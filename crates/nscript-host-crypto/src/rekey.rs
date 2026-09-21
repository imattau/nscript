//! CORD-06 rekey delivery: pairwise-encrypted blobs in kind-3303 events.
//!
//! The sending side builds the events for a base rotation (a Refounding's key
//! roll) or a single Private Channel rekey. The receiving side finds its
//! locator, checks continuity and authority, decrypts its blob and adopts the
//! key. Deciding *who* to remove, and republishing the compacted Control Plane,
//! are the caller's job.

use nscript_runtime::edition::Vac;
use nscript_runtime::rekey::{
    AcceptedKey, Continuity, MAX_BLOBS_PER_EVENT, RekeyOutcome, RekeyTags, Rotation, Scope,
    accept_blob, check_continuity, epoch_key_commitment, locator, parse_blob_list,
    parse_rekey_tags, pick_winner,
};
use serde_json::{Value, json};

use crate::group_key::{CryptoError, GroupKey, group_key, hex, xonly_pubkey};
use crate::nip44::{self, Nip44Error, conversation_key};
use crate::stream::{SealForm, StreamError, build_seal, build_wrap, open_stream_event, rumor};

const KIND_REKEY: u64 = 3303;

#[derive(Debug, Eq, PartialEq)]
pub enum RekeyBuildError {
    Crypto(CryptoError),
    Nip44(Nip44Error),
    Stream(StreamError),
    /// A recipient or id is not 32-byte lowercase hex.
    InvalidRecipient,
    NoRecipients,
}

impl From<CryptoError> for RekeyBuildError {
    fn from(error: CryptoError) -> Self {
        Self::Crypto(error)
    }
}
impl From<Nip44Error> for RekeyBuildError {
    fn from(error: Nip44Error) -> Self {
        Self::Nip44(error)
    }
}
impl From<StreamError> for RekeyBuildError {
    fn from(error: StreamError) -> Self {
        Self::Stream(error)
    }
}

/// Someone who should receive the new keys. Staff also receive the
/// `control_root` (a 136-byte blob); everyone else a 104-byte one.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Recipient {
    pub pubkey: String,
    pub staff: bool,
}

fn unhex32(text: &str) -> Option<[u8; 32]> {
    if text.len() != 64 || !text.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f')) {
        return None;
    }
    let mut out = [0_u8; 32];
    for (slot, pair) in out.iter_mut().zip(text.as_bytes().chunks(2)) {
        *slot = u8::from_str_radix(std::str::from_utf8(pair).ok()?, 16).ok()?;
    }
    Some(out)
}

/// Where a rotation is published: derived from the *prior* secret, so only a
/// holder of the old key can find it.
fn rekey_address(
    scope: &Scope,
    community_id: &[u8; 32],
    prior_root: &[u8; 32],
    new_epoch: u64,
) -> Option<GroupKey> {
    match scope {
        Scope::Community => Some(group_key(
            "concord/base-rekey-pseudonym",
            prior_root,
            community_id,
            Some(new_epoch),
        )),
        Scope::Channel(id) => Some(group_key(
            "concord/rekey-pseudonym",
            prior_root,
            &unhex32(id)?,
            Some(new_epoch),
        )),
    }
}

/// One rotation to send.
pub struct Rotation3303<'a> {
    pub rotator_secret: &'a [u8; 32],
    pub community_id: [u8; 32],
    pub scope: Scope,
    /// The prior `community_root`: the address derives from it and, for a base
    /// rotation, so does the continuity commitment.
    pub prior_root: [u8; 32],
    /// For a channel rekey, the prior *channel* key the commitment covers.
    pub prior_scope_key: [u8; 32],
    pub prior_epoch: u64,
    pub new_epoch: u64,
    pub new_key: [u8; 32],
    /// Base rotations only: the fresh `control_root`.
    pub new_control_root: Option<[u8; 32]>,
    pub vac: Option<Vac>,
    pub created_at: u64,
}

fn blob_plaintext(plan: &Rotation3303<'_>, staff: bool) -> Result<Vec<u8>, RekeyBuildError> {
    let mut bytes = unhex32(&plan.scope.id32())
        .ok_or(RekeyBuildError::InvalidRecipient)?
        .to_vec();
    bytes.extend_from_slice(&plan.new_epoch.to_be_bytes());
    bytes.extend_from_slice(&plan.new_key);
    if let (Scope::Community, Some(control_root)) = (&plan.scope, plan.new_control_root) {
        let control_pk = group_key(
            "concord/control-signer",
            &control_root,
            &plan.community_id,
            Some(plan.new_epoch),
        )
        .xonly_pubkey();
        bytes.extend_from_slice(&control_pk);
        if staff {
            bytes.extend_from_slice(&control_root);
        }
    }
    Ok(bytes)
}

/// Builds the wrap events (as JSON) for one rotation.
///
/// CORD-06 allows up to [`MAX_BLOBS_PER_EVENT`] blobs per event, but every
/// event is NIP-44 encrypted twice (seal, then wrap) and the wrap layer caps
/// its plaintext at 65,535 bytes. By NIP-44's padding rules the larger base
/// blobs (104 and 136 bytes) overflow that well before 120 per event, so the
/// chunk size shrinks until the whole rotation fits. Receivers accept any chunk
/// count, so this is invisible to them.
///
/// # Errors
///
/// Returns [`RekeyBuildError`] for malformed recipients or key failures.
pub fn build_rekey_events(
    plan: &Rotation3303<'_>,
    recipients: &[Recipient],
) -> Result<Vec<String>, RekeyBuildError> {
    if recipients.is_empty() {
        return Err(RekeyBuildError::NoRecipients);
    }
    let mut size = MAX_BLOBS_PER_EVENT;
    loop {
        match build_chunked(plan, recipients, size) {
            Err(RekeyBuildError::Stream(StreamError::Nip44(
                Nip44Error::InvalidPlaintextLength,
            ))) if size > 1 => {
                size = (size * 3 / 4).max(1);
            }
            other => return other,
        }
    }
}

fn build_chunked(
    plan: &Rotation3303<'_>,
    recipients: &[Recipient],
    size: usize,
) -> Result<Vec<String>, RekeyBuildError> {
    let rotator = hex(&xonly_pubkey(plan.rotator_secret)?);
    let address = rekey_address(
        &plan.scope,
        &plan.community_id,
        &plan.prior_root,
        plan.new_epoch,
    )
    .ok_or(RekeyBuildError::InvalidRecipient)?;
    let commit = epoch_key_commitment(plan.prior_epoch, &plan.prior_scope_key);
    let chunks: Vec<&[Recipient]> = recipients.chunks(size).collect();
    let mut events = Vec::new();
    for (index, chunk) in chunks.iter().enumerate() {
        let mut blobs = Vec::new();
        for recipient in *chunk {
            let their = unhex32(&recipient.pubkey).ok_or(RekeyBuildError::InvalidRecipient)?;
            let pairwise = conversation_key(plan.rotator_secret, &their)?;
            let wrapped = nip44::encrypt(&pairwise, &blob_plaintext(plan, recipient.staff)?)?;
            let locator = locator(&rotator, &recipient.pubkey, &plan.scope, plan.new_epoch)
                .ok_or(RekeyBuildError::InvalidRecipient)?;
            blobs.push(json!({"locator": locator, "wrapped": wrapped}));
        }
        let mut tags = vec![
            json!(["scope", plan.scope.id32()]),
            json!(["newepoch", plan.new_epoch.to_string()]),
            json!(["prevepoch", plan.prior_epoch.to_string()]),
            json!(["prevcommit", commit]),
            json!(["chunk", index.to_string(), chunks.len().to_string()]),
        ];
        if let Some(vac) = &plan.vac {
            tags.push(json!([
                "vac",
                vac.grant_eid,
                vac.version.to_string(),
                vac.hash
            ]));
        }
        let rumor = rumor(
            plan.rotator_secret,
            KIND_REKEY,
            &Value::Array(tags),
            &Value::Array(blobs).to_string(),
            plan.created_at,
        )?;
        let seal = build_seal(
            &address.conversation_key(),
            SealForm::Encrypted,
            plan.rotator_secret,
            &rumor.to_string(),
            plan.created_at,
        )?;
        events.push(build_wrap(
            &address.secret_bytes(),
            &address.conversation_key(),
            &seal,
            &[],
            plan.created_at,
        )?);
    }
    Ok(events)
}

/// What a receiver holds and expects.
pub struct Receiver<'a> {
    pub secret: &'a [u8; 32],
    pub community_id: [u8; 32],
    pub scope: Scope,
    /// The `community_root` the rekey address derives from.
    pub prior_root: [u8; 32],
    pub held_epoch: u64,
    /// The key the continuity commitment covers (root, or the channel key).
    pub held_key: [u8; 32],
}

#[derive(Debug, Eq, PartialEq)]
pub enum ReceiveOutcome {
    /// A key this receiver may adopt. A base rotation adopts root and control keys.
    Adopted(AcceptedKey),
    /// Every chunk was seen and none was addressed to this receiver.
    Removed,
    /// A chunk is missing: refetch these before concluding anything.
    Incomplete { missing: Vec<u64> },
    /// The rotation skips epochs this receiver never saw: fetch the gap first.
    MissedRotation,
    /// No acceptable rotation was found.
    Nothing,
}

struct Candidate {
    rotation: Rotation,
    blobs: Vec<(String, String)>,
    vac: Option<Vac>,
}

fn vac_from(rumor: &Value) -> Option<Vac> {
    let tag = rumor.get("tags")?.as_array()?.iter().find_map(|t| {
        let t = t.as_array()?;
        (t.first()?.as_str()? == "vac").then_some(t)
    })?;
    Some(Vac {
        grant_eid: tag.get(1)?.as_str()?.to_owned(),
        version: tag.get(2)?.as_str()?.parse().ok()?,
        hash: tag.get(3)?.as_str()?.to_owned(),
    })
}

/// Processes every rekey wrap found at the next epoch's address.
///
/// `authorize` decides whether the rotator may perform this rotation (the
/// caller's `authorize_rotation` over its folded Roster). Rotations that fail
/// continuity, authority or completeness are never adopted; among authorized
/// rivals the lowest new base key wins.
#[must_use]
pub fn receive_rekey(
    receiver: &Receiver<'_>,
    wraps: &[String],
    authorize: impl Fn(&str, Option<&Vac>, &Scope) -> bool,
) -> ReceiveOutcome {
    let Ok(me) = xonly_pubkey(receiver.secret).map(|k| hex(&k)) else {
        return ReceiveOutcome::Nothing;
    };
    let new_epoch = receiver.held_epoch + 1;
    let Some(address) = rekey_address(
        &receiver.scope,
        &receiver.community_id,
        &receiver.prior_root,
        new_epoch,
    ) else {
        return ReceiveOutcome::Nothing;
    };
    let (candidates, missed) = collect_candidates(receiver, wraps, &address, new_epoch);
    let mut adopted: Vec<([u8; 32], AcceptedKey)> = Vec::new();
    let (mut removed, mut incomplete) = (false, None);
    for candidate in &candidates {
        if !authorize(
            &candidate.rotation.rotator,
            candidate.vac.as_ref(),
            &receiver.scope,
        ) {
            continue;
        }
        let Some(mine) = locator(&candidate.rotation.rotator, &me, &receiver.scope, new_epoch)
        else {
            continue;
        };
        match candidate.rotation.outcome(&mine) {
            RekeyOutcome::Removed => removed = true,
            RekeyOutcome::Incomplete { missing } => incomplete = Some(missing),
            RekeyOutcome::Included { .. } => {
                if let Some((root, key)) = decrypt_blob(receiver, candidate, &mine, new_epoch) {
                    adopted.push((root, key));
                }
            }
        }
    }
    if let Some(roots) = adopted.iter().map(|(root, _)| *root).min() {
        // Lowest new base key wins the race; every client picks the same one.
        let winner = pick_winner(&[roots]).copied().unwrap_or(roots);
        if let Some((_, key)) = adopted.into_iter().find(|(root, _)| *root == winner) {
            return ReceiveOutcome::Adopted(key);
        }
    }
    if let Some(missing) = incomplete {
        return ReceiveOutcome::Incomplete { missing };
    }
    if removed {
        return ReceiveOutcome::Removed;
    }
    if missed {
        return ReceiveOutcome::MissedRotation;
    }
    ReceiveOutcome::Nothing
}

/// Opens every wrap at the rekey address and groups chunks into rotations,
/// keeping only those that extend the key this receiver holds.
fn collect_candidates(
    receiver: &Receiver<'_>,
    wraps: &[String],
    address: &GroupKey,
    new_epoch: u64,
) -> (Vec<Candidate>, bool) {
    let mut candidates: Vec<Candidate> = Vec::new();
    let mut missed = false;
    for wrap in wraps {
        let Ok(opened) = open_stream_event(
            &address.xonly_pubkey(),
            &address.conversation_key(),
            SealForm::Encrypted,
            wrap,
        ) else {
            continue;
        };
        let Ok(rumor) = serde_json::from_str::<Value>(&opened.rumor_json) else {
            continue;
        };
        if rumor.get("kind").and_then(Value::as_u64) != Some(KIND_REKEY) {
            continue;
        }
        let Some(tag_list) = rumor.get("tags").and_then(Value::as_array) else {
            continue;
        };
        let Ok(tags) = parse_rekey_tags(tag_list) else {
            continue;
        };
        let Some(content) = rumor.get("content").and_then(Value::as_str) else {
            continue;
        };
        let Ok(blobs) = parse_blob_list(content) else {
            continue;
        };
        if tags.scope != receiver.scope {
            continue;
        }
        match check_continuity(receiver.held_epoch, &receiver.held_key, &tags) {
            Continuity::Extends if tags.new_epoch == new_epoch => {}
            Continuity::MissedRotation => {
                missed = true;
                continue;
            }
            _ => continue,
        }
        let locators = blobs.iter().map(|(l, _)| l.clone()).collect();
        let vac = vac_from(&rumor);
        if let Some(existing) = candidates.iter_mut().find(|c| {
            c.rotation.rotator == opened.author && same_rotation(c.rotation.tags(), &tags)
        }) {
            if existing.rotation.add_chunk(&tags, locators).is_ok() {
                existing.blobs.extend(blobs);
            }
        } else {
            candidates.push(Candidate {
                rotation: Rotation::new(&opened.author, &tags, locators),
                blobs,
                vac,
            });
        }
    }
    (candidates, missed)
}

fn same_rotation(a: &RekeyTags, b: &RekeyTags) -> bool {
    a.scope == b.scope
        && a.new_epoch == b.new_epoch
        && a.prev_epoch == b.prev_epoch
        && a.prev_commit == b.prev_commit
}

/// Decrypts this receiver's blob and validates it against the event's tags.
fn decrypt_blob(
    receiver: &Receiver<'_>,
    candidate: &Candidate,
    mine: &str,
    new_epoch: u64,
) -> Option<([u8; 32], AcceptedKey)> {
    let wrapped = candidate
        .blobs
        .iter()
        .find(|(l, _)| l == mine)
        .map(|(_, w)| w)?;
    let rotator = unhex32(&candidate.rotation.rotator)?;
    let pairwise = conversation_key(receiver.secret, &rotator).ok()?;
    let plaintext = nip44::decrypt(&pairwise, wrapped).ok()?;
    let community_id = receiver.community_id;
    let derive = |control_root: &[u8; 32]| {
        Some(
            group_key(
                "concord/control-signer",
                control_root,
                &community_id,
                Some(new_epoch),
            )
            .xonly_pubkey(),
        )
    };
    let key = accept_blob(&plaintext, candidate.rotation.tags(), derive).ok()?;
    let root = match &key {
        AcceptedKey::Channel { key } | AcceptedKey::LegacyBase { root: key } => *key,
        AcceptedKey::Base { root, .. } => *root,
    };
    Some((root, key))
}
