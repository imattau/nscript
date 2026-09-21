//! CORD-06 §3 Refounding: roll the community keys, compact the Control Plane,
//! rekey private channels and seed the new Guestbook.
//!
//! A Refounding is resumable, not atomic: every step is idempotent, so a crash
//! simply resumes. The state being rotated is fully acquired before the first
//! publish, so a mid-flight failure never leaves half a rotation as the only
//! copy. The compacted Control Plane is republished only after the root roll is
//! confirmed published.

use std::collections::BTreeMap;

use nscript_runtime::authority::{AuthorityFold, Verdict};
use nscript_runtime::edition::{
    Edition, VSK_BANLIST, VSK_CHANNEL_METADATA, VSK_COMMUNITY_METADATA, VSK_GRANT, VSK_ROLE, Vac,
};
use nscript_runtime::rekey::{Scope, authorize_rotation};
use nscript_runtime::wire::parse_edition_rumor;
use nscript_runtime::{RelayHost, RuntimeError};
use serde_json::json;

use crate::group_key::{group_key, hex, random32_hex, xonly_pubkey};
use crate::host::signed_event_from_wire;
use crate::moderation::CommunityKeys;
use crate::rekey::{Recipient, RekeyBuildError, Rotation3303, build_rekey_events};
use crate::stream::{SealForm, StreamError, build_seal, build_wrap, open_seal, open_wrap, rumor};

const SNAPSHOT_CHUNK: usize = 400;
const KIND_SNAPSHOT: u64 = 3312;

#[derive(Debug, Eq, PartialEq)]
pub enum RefoundError {
    /// The rotator may not refound (needs BAN and to outrank every target, and
    /// a synced citation).
    Unauthorized(Verdict),
    /// A current head has no archived seal, so it cannot be re-wrapped
    /// verbatim. The Refounding must abort rather than drop authority.
    CannotCompact {
        entity_id: String,
    },
    Rekey(RekeyBuildError),
    Stream(StreamError),
    /// The root roll was not accepted by any relay: nothing further was sent.
    RootRollNotConfirmed,
    Relay(RuntimeError),
}

impl From<RekeyBuildError> for RefoundError {
    fn from(error: RekeyBuildError) -> Self {
        Self::Rekey(error)
    }
}
impl From<StreamError> for RefoundError {
    fn from(error: StreamError) -> Self {
        Self::Stream(error)
    }
}

/// The original seals of Control editions, kept verbatim. Plaintext seals are
/// what let a compaction re-wrap a signed edition into a new epoch with the
/// author's signature intact.
#[derive(Clone, Debug, Default)]
pub struct ControlArchive {
    seals: BTreeMap<String, String>,
}

impl ControlArchive {
    /// Opens a Control Plane wrap, archives its seal and returns the edition.
    ///
    /// # Errors
    ///
    /// Returns [`StreamError`] if the wrap does not verify, or
    /// [`StreamError::NotJson`] if it is not an edition.
    pub fn ingest(
        &mut self,
        control_pk: &[u8; 32],
        read_key: &[u8; 32],
        wrap: &str,
    ) -> Result<Edition, StreamError> {
        let seal = open_wrap(control_pk, read_key, wrap)?;
        let opened = open_seal(read_key, SealForm::Plaintext, &seal)?;
        let edition = parse_edition_rumor(&opened.author, &opened.rumor_json)
            .map_err(|_| StreamError::NotJson)?;
        self.seals.insert(edition.rumor_id.clone(), seal);
        Ok(edition)
    }

    #[must_use]
    pub fn len(&self) -> usize {
        self.seals.len()
    }

    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.seals.is_empty()
    }
}

/// Fresh keys for the new epoch. Callers use [`RefoundingKeys::random`]; the
/// fields are public so tests can pin them.
pub struct RefoundingKeys {
    pub community_root: [u8; 32],
    pub control_root: [u8; 32],
}

impl RefoundingKeys {
    /// # Errors
    ///
    /// Returns [`StreamError::Crypto`] if the OS random source fails.
    pub fn random() -> Result<Self, StreamError> {
        Ok(Self {
            community_root: crate::random32()?,
            control_root: crate::random32()?,
        })
    }
}

/// A private Channel to rekey alongside the base.
pub struct ChannelRekey {
    pub channel_id: String,
    pub prior_key: [u8; 32],
    pub prior_epoch: u64,
    pub new_key: [u8; 32],
    /// Members who keep access.
    pub recipients: Vec<Recipient>,
}

pub struct RefoundingRequest<'a> {
    pub rotator_secret: &'a [u8; 32],
    pub current: &'a CommunityKeys,
    pub authority: &'a AuthorityFold,
    pub archive: &'a ControlArchive,
    pub new_keys: RefoundingKeys,
    /// Everyone who keeps access to the base, excluding the removed.
    pub remaining: Vec<Recipient>,
    pub removed: Vec<String>,
    pub channels: Vec<ChannelRekey>,
    /// The rotator's citation; `None` only when the owner rotates.
    pub vac: Option<Vac>,
    pub created_at: u64,
}

/// Every event of a Refounding, in the order it must be published.
#[derive(Debug)]
pub struct Refounding {
    /// The keys the community moves to.
    pub epoch: u64,
    pub community_root: [u8; 32],
    pub control_root: [u8; 32],
    /// 1. The base root roll.
    pub root_roll: Vec<String>,
    /// 2. The compacted Control Plane at the new epoch's address.
    pub compaction: Vec<String>,
    /// 3. Rekeys for private Channels, addressed under the prior root.
    pub channel_rekeys: Vec<String>,
    /// 4. Best effort: the new Guestbook seeded with surviving members.
    pub snapshot: Vec<String>,
}

const COMPACTED_ENTITY_TYPES: [u8; 5] = [
    VSK_COMMUNITY_METADATA,
    VSK_ROLE,
    VSK_CHANNEL_METADATA,
    VSK_GRANT,
    VSK_BANLIST,
];

/// Plans a Refounding: authorizes, compacts and builds every event without
/// publishing anything.
///
/// # Errors
///
/// Returns [`RefoundError`] if the rotator is not authorized, a head cannot
/// be compacted, or an event cannot be built.
pub fn plan_refounding(request: &RefoundingRequest<'_>) -> Result<Refounding, RefoundError> {
    let rotator = hex(&xonly_pubkey(request.rotator_secret).map_err(StreamError::from)?);
    let roster = request.authority.roster();
    let verdict = authorize_rotation(
        request.authority,
        &roster,
        &rotator,
        request.vac.as_ref(),
        &Scope::Community,
        &request.removed,
    );
    if verdict != Verdict::Honored {
        return Err(RefoundError::Unauthorized(verdict));
    }
    let cid = request.current.community_id;
    let new_epoch = request.current.epoch + 1;
    let new_root = request.new_keys.community_root;
    let new_control = request.new_keys.control_root;

    // Acquire everything to be re-wrapped *before* building any event.
    let mut seals = Vec::new();
    for vsk in COMPACTED_ENTITY_TYPES {
        for head in request.authority.heads(vsk) {
            let seal = request.archive.seals.get(&head.rumor_id).ok_or_else(|| {
                RefoundError::CannotCompact {
                    entity_id: head.entity_id.clone(),
                }
            })?;
            seals.push(seal.clone());
        }
    }

    let root_roll = build_rekey_events(
        &Rotation3303 {
            rotator_secret: request.rotator_secret,
            community_id: cid,
            scope: Scope::Community,
            prior_root: request.current.community_root,
            prior_scope_key: request.current.community_root,
            prior_epoch: request.current.epoch,
            new_epoch,
            new_key: new_root,
            new_control_root: Some(new_control),
            vac: request.vac.clone(),
            created_at: request.created_at,
        },
        &request.remaining,
    )?;

    // Compaction: the original plaintext seals go verbatim into the new epoch.
    let signer = group_key(
        "concord/control-signer",
        &new_control,
        &cid,
        Some(new_epoch),
    );
    let read = group_key("concord/control", &new_root, &cid, Some(new_epoch));
    let compaction = seals
        .iter()
        .map(|seal| {
            build_wrap(
                &signer.secret_bytes(),
                &read.conversation_key(),
                seal,
                &[],
                request.created_at,
            )
        })
        .collect::<Result<Vec<_>, _>>()?;

    let mut channel_rekeys = Vec::new();
    for channel in &request.channels {
        channel_rekeys.extend(build_rekey_events(
            &Rotation3303 {
                rotator_secret: request.rotator_secret,
                community_id: cid,
                scope: Scope::Channel(channel.channel_id.clone()),
                // Sealed under the PRIOR community_root so a base-fork loser
                // can still open it on either branch.
                prior_root: request.current.community_root,
                prior_scope_key: channel.prior_key,
                prior_epoch: channel.prior_epoch,
                new_epoch: channel.prior_epoch + 1,
                new_key: channel.new_key,
                new_control_root: None,
                vac: request.vac.clone(),
                created_at: request.created_at,
            },
            &channel.recipients,
        )?);
    }

    let snapshot = build_snapshot(request, &cid, new_epoch, &new_root)?;
    Ok(Refounding {
        epoch: new_epoch,
        community_root: new_root,
        control_root: new_control,
        root_roll,
        compaction,
        channel_rekeys,
        snapshot,
    })
}

/// Seeds the new epoch's Guestbook with the surviving members (CORD-02 §5),
/// chunked at 400 per event under one snapshot id and timestamp.
fn build_snapshot(
    request: &RefoundingRequest<'_>,
    cid: &[u8; 32],
    epoch: u64,
    root: &[u8; 32],
) -> Result<Vec<String>, StreamError> {
    let book = group_key("concord/guestbook", root, cid, Some(epoch));
    let members: Vec<&str> = request
        .remaining
        .iter()
        .map(|r| r.pubkey.as_str())
        .collect();
    let id = random32_hex()?;
    let chunks: Vec<&[&str]> = members.chunks(SNAPSHOT_CHUNK).collect();
    let mut out = Vec::new();
    for (index, chunk) in chunks.iter().enumerate() {
        let tags = json!([
            ["ms", "0"],
            ["snap", id, index.to_string(), chunks.len().to_string()]
        ]);
        let rumor = rumor(
            request.rotator_secret,
            KIND_SNAPSHOT,
            &tags,
            &json!(chunk).to_string(),
            request.created_at,
        )?;
        let seal = build_seal(
            &book.conversation_key(),
            SealForm::Encrypted,
            request.rotator_secret,
            &rumor.to_string(),
            request.created_at,
        )?;
        out.push(build_wrap(
            &book.secret_bytes(),
            &book.conversation_key(),
            &seal,
            &[],
            request.created_at,
        )?);
    }
    Ok(out)
}

fn publish_all(
    relays: &mut dyn RelayHost,
    relayset: &str,
    wraps: &[String],
) -> Result<bool, RefoundError> {
    let mut all_accepted = true;
    for wrap in wraps {
        let event =
            signed_event_from_wire(wrap).ok_or(RefoundError::Stream(StreamError::NotJson))?;
        let report = relays
            .publish(1, &event, relayset)
            .map_err(RefoundError::Relay)?;
        all_accepted &= report.accepted();
    }
    Ok(all_accepted)
}

impl Refounding {
    /// Publishes in the mandated order. The root roll must be confirmed before
    /// the compaction goes out; the snapshot is best effort ("a Refounding
    /// succeeds with or without it"). Every step is idempotent, so a failed run
    /// can simply be executed again.
    ///
    /// # Errors
    ///
    /// Returns [`RefoundError::RootRollNotConfirmed`] if the root roll was
    /// refused, in which case nothing after it was published.
    pub fn execute(&self, relays: &mut dyn RelayHost, relayset: &str) -> Result<(), RefoundError> {
        if !publish_all(relays, relayset, &self.root_roll)? {
            return Err(RefoundError::RootRollNotConfirmed);
        }
        publish_all(relays, relayset, &self.compaction)?;
        publish_all(relays, relayset, &self.channel_rekeys)?;
        let _ = publish_all(relays, relayset, &self.snapshot);
        Ok(())
    }
}
