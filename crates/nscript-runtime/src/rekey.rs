//! CORD-06 rekeys and refoundings: the receive-side rules as pure logic.
//!
//! NIP-44 pairwise decryption of a blob is a host concern; this module owns
//! everything after it: blob shapes, locators, continuity, chunk assembly,
//! race resolution and rotator authority.

use std::collections::BTreeMap;

use serde_json::Value;
use sha2::{Digest, Sha256};

use crate::authority::{
    AuthorityFold, Roster, Verdict, bytes_to_hex, hex_to_bytes32, hkdf32, perm,
};
use crate::edition::Vac;
use crate::stream::is_hex32;
use crate::wire::{decimal_u64, tag_values};

pub const KIND_REKEY: u64 = 3303;
/// Most blobs one rekey event may carry.
pub const MAX_BLOBS_PER_EVENT: usize = 120;
const CHANNEL_BLOB: usize = 72;
const MEMBER_BASE_BLOB: usize = 104;
const STAFF_BASE_BLOB: usize = 136;

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum RekeyError {
    Malformed(&'static str),
    /// Blob scope or epoch disagrees with the event's tags: unspliceable.
    ScopeMismatch,
    EpochMismatch,
    /// `new_control_root` does not derive to `new_control_pk`.
    ControlKeyMismatch,
    /// Chunks of one rotation disagree on continuity fields.
    InconsistentChunks,
}

/// What a rotation replaces: one Private Channel's key, or the base root.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum Scope {
    Community,
    Channel(String),
}

impl Scope {
    /// The 32-byte scope id as hex; all zeroes means the `community_root`.
    #[must_use]
    pub fn id32(&self) -> String {
        match self {
            Self::Community => "00".repeat(32),
            Self::Channel(id) => id.clone(),
        }
    }

    fn from_hex(id: &str) -> Option<Self> {
        if !is_hex32(id) {
            None
        } else if id == "00".repeat(32) {
            Some(Self::Community)
        } else {
            Some(Self::Channel(id.to_owned()))
        }
    }
}

/// The tags of a kind-3303 rumor.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RekeyTags {
    pub scope: Scope,
    pub new_epoch: u64,
    pub prev_epoch: u64,
    pub prev_commit: String,
    pub chunk: u64,
    pub chunks: u64,
}

fn one<'a>(tags: &'a [Value], name: &'static str) -> Result<&'a str, RekeyError> {
    match tag_values(tags, name).as_deref() {
        Some([value]) => Ok(value),
        _ => Err(RekeyError::Malformed(name)),
    }
}

/// Parses a rekey rumor's tags (CORD-01 Encoding: decimal numbers, lowercase hex).
///
/// # Errors
///
/// Returns [`RekeyError::Malformed`] naming the offending tag.
pub fn parse_rekey_tags(tags: &[Value]) -> Result<RekeyTags, RekeyError> {
    let number =
        |name: &'static str| decimal_u64(one(tags, name)?).ok_or(RekeyError::Malformed(name));
    let scope = Scope::from_hex(one(tags, "scope")?).ok_or(RekeyError::Malformed("scope"))?;
    let prev_commit = one(tags, "prevcommit")?;
    if !is_hex32(prev_commit) {
        return Err(RekeyError::Malformed("prevcommit"));
    }
    let (chunk, chunks) = match tag_values(tags, "chunk").as_deref() {
        Some([i, n]) => (
            decimal_u64(i).ok_or(RekeyError::Malformed("chunk"))?,
            decimal_u64(n).ok_or(RekeyError::Malformed("chunk"))?,
        ),
        _ => return Err(RekeyError::Malformed("chunk")),
    };
    if chunks == 0 || chunk >= chunks {
        return Err(RekeyError::Malformed("chunk"));
    }
    let parsed = RekeyTags {
        scope,
        new_epoch: number("newepoch")?,
        prev_epoch: number("prevepoch")?,
        prev_commit: prev_commit.to_owned(),
        chunk,
        chunks,
    };
    // A rotation moves strictly forward.
    if parsed.new_epoch <= parsed.prev_epoch {
        return Err(RekeyError::Malformed("newepoch"));
    }
    Ok(parsed)
}

/// Parses the rumor content: a bounded list of `{locator, wrapped}` blobs.
///
/// # Errors
///
/// Returns [`RekeyError::Malformed`] for a bad list, locator, or oversize event.
pub fn parse_blob_list(content: &str) -> Result<Vec<(String, String)>, RekeyError> {
    let list: Vec<Value> =
        serde_json::from_str(content).map_err(|_| RekeyError::Malformed("content"))?;
    if list.len() > MAX_BLOBS_PER_EVENT {
        return Err(RekeyError::Malformed("content"));
    }
    list.iter()
        .map(|blob| {
            let locator = blob.get("locator").and_then(Value::as_str);
            let wrapped = blob.get("wrapped").and_then(Value::as_str);
            match (locator, wrapped) {
                (Some(l), Some(w)) if is_hex32(l) => Ok((l.to_owned(), w.to_owned())),
                _ => Err(RekeyError::Malformed("content")),
            }
        })
        .collect()
}

/// A key recovered from a decrypted blob.
#[derive(Clone, Eq, PartialEq)]
pub enum AcceptedKey {
    Channel {
        key: [u8; 32],
    },
    Base {
        root: [u8; 32],
        control_pk: [u8; 32],
        /// Present only in a staff recipient's 136-byte blob.
        control_root: Option<[u8; 32]>,
    },
    /// A 72-byte base blob: a pre-split rotation, honoured only when reading
    /// old epochs and never minted anew.
    LegacyBase {
        root: [u8; 32],
    },
}

impl std::fmt::Debug for AcceptedKey {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Key material never appears in debug output.
        let kind = match self {
            Self::Channel { .. } => "Channel",
            Self::Base { .. } => "Base",
            Self::LegacyBase { .. } => "LegacyBase",
        };
        formatter
            .debug_struct("AcceptedKey")
            .field("kind", &kind)
            .finish()
    }
}

fn take32(bytes: &[u8], at: usize) -> [u8; 32] {
    let mut out = [0_u8; 32];
    out.copy_from_slice(&bytes[at..at + 32]);
    out
}

/// Validates a decrypted blob plaintext against its event's tags.
///
/// The width declares the form. Scope and epoch live inside the ciphertext and
/// must equal the tags, so a blob cannot be spliced into another rotation.
/// `derive_control_pk` maps a `control_root` to its `control_pk` (a host
/// derivation, CORD-02 §5).
///
/// # Errors
///
/// Returns [`RekeyError`] for a wrong width, a scope/epoch mismatch, or a
/// staff blob whose `control_root` does not derive to `new_control_pk`.
pub fn accept_blob(
    plaintext: &[u8],
    tags: &RekeyTags,
    derive_control_pk: impl Fn(&[u8; 32]) -> Option<[u8; 32]>,
) -> Result<AcceptedKey, RekeyError> {
    if !matches!(
        plaintext.len(),
        CHANNEL_BLOB | MEMBER_BASE_BLOB | STAFF_BASE_BLOB
    ) {
        return Err(RekeyError::Malformed("blob width"));
    }
    if bytes_to_hex(&plaintext[..32]) != tags.scope.id32() {
        return Err(RekeyError::ScopeMismatch);
    }
    let Ok(epoch_bytes) = <[u8; 8]>::try_from(&plaintext[32..40]) else {
        return Err(RekeyError::Malformed("blob width"));
    };
    let epoch = u64::from_be_bytes(epoch_bytes);
    if epoch != tags.new_epoch {
        return Err(RekeyError::EpochMismatch);
    }
    match (&tags.scope, plaintext.len()) {
        (Scope::Channel(_), CHANNEL_BLOB) => Ok(AcceptedKey::Channel {
            key: take32(plaintext, 40),
        }),
        (Scope::Community, CHANNEL_BLOB) => Ok(AcceptedKey::LegacyBase {
            root: take32(plaintext, 40),
        }),
        (Scope::Community, MEMBER_BASE_BLOB) => Ok(AcceptedKey::Base {
            root: take32(plaintext, 40),
            control_pk: take32(plaintext, 72),
            control_root: None,
        }),
        (Scope::Community, STAFF_BASE_BLOB) => {
            let control_pk = take32(plaintext, 72);
            let control_root = take32(plaintext, 104);
            // Refuse a mismatched pair rather than adopt a plane split from
            // its readers.
            if derive_control_pk(&control_root) != Some(control_pk) {
                return Err(RekeyError::ControlKeyMismatch);
            }
            Ok(AcceptedKey::Base {
                root: take32(plaintext, 40),
                control_pk,
                control_root: Some(control_root),
            })
        }
        // Channel scopes never use the base widths.
        (Scope::Channel(_), _) => Err(RekeyError::Malformed("blob width")),
        (Scope::Community, _) => unreachable!("width checked above"),
    }
}

/// `hkdf(rotator_xonly || recipient_xonly, "concord/recipient-pseudonym",
/// scope_id, epoch)`: where a recipient finds their blob. Derived from public
/// inputs only, so a bunker account can find it without a raw key.
#[must_use]
pub fn locator(rotator: &str, recipient: &str, scope: &Scope, epoch: u64) -> Option<String> {
    let mut ikm = hex_to_bytes32(rotator)?.to_vec();
    ikm.extend_from_slice(&hex_to_bytes32(recipient)?);
    let mut info = b"concord/recipient-pseudonym".to_vec();
    info.push(0);
    info.extend_from_slice(&hex_to_bytes32(&scope.id32())?);
    info.extend_from_slice(&epoch.to_be_bytes());
    Some(bytes_to_hex(&hkdf32(&ikm, &info)))
}

/// `prevcommit = sha256("concord/epoch-key-commitment" || prev_epoch_be ||
/// prev_key)` (CORD-02 A.5).
#[must_use]
pub fn epoch_key_commitment(prev_epoch: u64, prev_key: &[u8; 32]) -> String {
    let mut digest = Sha256::new();
    digest.update(b"concord/epoch-key-commitment");
    digest.update(prev_epoch.to_be_bytes());
    digest.update(prev_key);
    bytes_to_hex(&digest.finalize())
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Continuity {
    /// The rotation extends the very key this client holds.
    Extends,
    /// A higher `prevepoch` than held: a rotation was missed; fetch the gap.
    MissedRotation,
    /// A fork or garbage: reject.
    Reject,
}

/// Checks a rotation against the epoch and key the client currently holds.
/// `prevcommit` is a convergence check, not a secrecy mechanism.
#[must_use]
pub fn check_continuity(held_epoch: u64, held_key: &[u8; 32], tags: &RekeyTags) -> Continuity {
    if tags.prev_epoch == held_epoch
        && epoch_key_commitment(held_epoch, held_key) == tags.prev_commit
    {
        Continuity::Extends
    } else if tags.prev_epoch > held_epoch {
        Continuity::MissedRotation
    } else {
        Continuity::Reject
    }
}

/// What a receiver may conclude about its own membership in a rotation.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum RekeyOutcome {
    /// Some chunk carries the receiver's locator.
    Included { chunk: u64 },
    /// All chunks are held and none carries the locator: removed.
    Removed,
    /// A missing chunk is never a removal: refetch these chunk indices.
    Incomplete { missing: Vec<u64> },
}

/// The chunks of one rotation by one Rotator. Chunks correlate on the Rotator
/// and identical continuity fields, so two Rotators racing the same epoch never
/// merge into one set.
#[derive(Clone, Debug)]
pub struct Rotation {
    pub rotator: String,
    head: RekeyTags,
    chunks: BTreeMap<u64, Vec<String>>,
}

impl Rotation {
    #[must_use]
    pub fn new(rotator: &str, first: &RekeyTags, locators: Vec<String>) -> Self {
        Self {
            rotator: rotator.to_owned(),
            head: first.clone(),
            chunks: BTreeMap::from([(first.chunk, locators)]),
        }
    }

    /// Adds another chunk of the same rotation.
    ///
    /// # Errors
    ///
    /// Returns [`RekeyError::InconsistentChunks`] if any continuity field
    /// differs from the first chunk's.
    pub fn add_chunk(&mut self, tags: &RekeyTags, locators: Vec<String>) -> Result<(), RekeyError> {
        let same = tags.scope == self.head.scope
            && tags.new_epoch == self.head.new_epoch
            && tags.prev_epoch == self.head.prev_epoch
            && tags.prev_commit == self.head.prev_commit
            && tags.chunks == self.head.chunks;
        if !same {
            return Err(RekeyError::InconsistentChunks);
        }
        self.chunks.insert(tags.chunk, locators);
        Ok(())
    }

    #[must_use]
    pub fn tags(&self) -> &RekeyTags {
        &self.head
    }

    #[must_use]
    pub fn outcome(&self, my_locator: &str) -> RekeyOutcome {
        if let Some((chunk, _)) = self
            .chunks
            .iter()
            .find(|(_, locators)| locators.iter().any(|l| l == my_locator))
        {
            return RekeyOutcome::Included { chunk: *chunk };
        }
        let missing: Vec<u64> = (0..self.head.chunks)
            .filter(|i| !self.chunks.contains_key(i))
            .collect();
        if missing.is_empty() {
            RekeyOutcome::Removed
        } else {
            RekeyOutcome::Incomplete { missing }
        }
    }
}

/// Authorizes a rotation (CORD-06 §3): a single-channel Rekey needs
/// `MANAGE_CHANNELS`, a Refounding needs `BAN`, the Rotator must strictly
/// outrank every removed target, and the cited Grant must be synced. Holding a
/// key is never authority.
#[must_use]
pub fn authorize_rotation(
    authority: &AuthorityFold,
    roster: &Roster,
    rotator: &str,
    vac: Option<&Vac>,
    scope: &Scope,
    removed: &[String],
) -> Verdict {
    let cited = authority.check_citation(rotator, vac);
    if cited != Verdict::Honored {
        return cited;
    }
    let bit = match scope {
        Scope::Community => perm::BAN,
        Scope::Channel(_) => perm::MANAGE_CHANNELS,
    };
    let allowed = if removed.is_empty() {
        roster.can(rotator, bit, None)
    } else {
        removed.iter().all(|t| roster.can(rotator, bit, Some(t)))
    };
    if allowed {
        Verdict::Honored
    } else {
        Verdict::Dropped
    }
}

/// Among authorized candidates at one continuity point the lexicographically
/// lowest new base key wins; every client computes the same winner.
#[must_use]
pub fn pick_winner(candidates: &[[u8; 32]]) -> Option<&[u8; 32]> {
    candidates.iter().min()
}

/// The same-epoch heal is down-only: a held epoch re-converges solely to a
/// strictly lower sibling, so a flaky fetch returning only the higher sibling
/// can never re-fork a settled epoch.
#[must_use]
pub fn should_heal_to(held: &[u8; 32], sibling: &[u8; 32]) -> bool {
    sibling < held
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::authority::{community_id, grant_locator};
    use crate::edition::{Edition, FoldMode, VSK_GRANT, VSK_ROLE};
    use serde_json::json;

    const OWNER: &str = "0101010101010101010101010101010101010101010101010101010101010101";
    const SALT: &str = "0202020202020202020202020202020202020202020202020202020202020202";
    const ADMIN: &str = "aa00000000000000000000000000000000000000000000000000000000000001";
    const BOB: &str = "bb00000000000000000000000000000000000000000000000000000000000002";
    const ROLE: &str = "1100000000000000000000000000000000000000000000000000000000000000";
    const CHANNEL: &str = "cc00000000000000000000000000000000000000000000000000000000000003";

    fn tags(scope: &Scope, new: u64, prev: u64, commit: &str, chunk: (u64, u64)) -> Vec<Value> {
        json!([
            ["scope", scope.id32()],
            ["newepoch", new.to_string()],
            ["prevepoch", prev.to_string()],
            ["prevcommit", commit],
            ["chunk", chunk.0.to_string(), chunk.1.to_string()]
        ])
        .as_array()
        .unwrap()
        .clone()
    }

    fn parsed(scope: &Scope, new: u64, prev: u64, chunk: (u64, u64)) -> RekeyTags {
        parse_rekey_tags(&tags(
            scope,
            new,
            prev,
            &epoch_key_commitment(prev, &[7; 32]),
            chunk,
        ))
        .unwrap()
    }

    fn blob(scope: &Scope, epoch: u64, extra: &[[u8; 32]]) -> Vec<u8> {
        let mut out = hex_to_bytes32(&scope.id32()).unwrap().to_vec();
        out.extend_from_slice(&epoch.to_be_bytes());
        for part in extra {
            out.extend_from_slice(part);
        }
        out
    }

    #[test]
    fn tags_follow_the_encoding_rules() {
        let ok = parsed(&Scope::Community, 5, 4, (0, 1));
        assert_eq!((ok.new_epoch, ok.prev_epoch, ok.chunks), (5, 4, 1));
        assert_eq!(ok.scope, Scope::Community);
        let commit = epoch_key_commitment(4, &[7; 32]);
        let bad = |t: Vec<Value>| parse_rekey_tags(&t);
        assert!(
            bad(tags(&Scope::Community, 4, 4, &commit, (0, 1))).is_err(),
            "must advance"
        );
        assert!(
            bad(tags(&Scope::Community, 5, 4, &commit, (1, 1))).is_err(),
            "chunk < n"
        );
        assert!(bad(tags(&Scope::Community, 5, 4, "zz", (0, 1))).is_err());
        let mut leading_zero = tags(&Scope::Community, 5, 4, &commit, (0, 1));
        leading_zero[1] = json!(["newepoch", "05"]);
        assert_eq!(bad(leading_zero), Err(RekeyError::Malformed("newepoch")));
        assert_eq!(
            parse_rekey_tags(&tags(
                &Scope::Channel(CHANNEL.into()),
                2,
                1,
                &commit,
                (0, 2)
            ))
            .unwrap()
            .scope,
            Scope::Channel(CHANNEL.to_owned())
        );
    }

    #[test]
    fn blob_widths_declare_the_form_and_scope_epoch_are_bound() {
        let key = [9_u8; 32];
        let (pk, sk) = ([3_u8; 32], [4_u8; 32]);
        let derive = |root: &[u8; 32]| (root == &sk).then_some(pk);

        let channel = Scope::Channel(CHANNEL.into());
        let tags_c = parsed(&channel, 2, 1, (0, 1));
        assert!(matches!(
            accept_blob(&blob(&channel, 2, &[key]), &tags_c, derive),
            Ok(AcceptedKey::Channel { key: k }) if k == key
        ));
        // A channel blob replayed against another channel or epoch is refused.
        let other = Scope::Channel(format!("dd{}", &CHANNEL[2..]));
        assert_eq!(
            accept_blob(&blob(&other, 2, &[key]), &tags_c, derive),
            Err(RekeyError::ScopeMismatch)
        );
        assert_eq!(
            accept_blob(&blob(&channel, 3, &[key]), &tags_c, derive),
            Err(RekeyError::EpochMismatch)
        );

        let tags_b = parsed(&Scope::Community, 5, 4, (0, 1));
        let member = accept_blob(&blob(&Scope::Community, 5, &[key, pk]), &tags_b, derive);
        assert!(matches!(
            member,
            Ok(AcceptedKey::Base {
                control_root: None,
                ..
            })
        ));
        let staff = accept_blob(&blob(&Scope::Community, 5, &[key, pk, sk]), &tags_b, derive);
        assert!(matches!(staff, Ok(AcceptedKey::Base { control_root: Some(r), .. }) if r == sk));
        // A staff blob whose secret does not derive to the delivered pk is refused.
        assert_eq!(
            accept_blob(
                &blob(&Scope::Community, 5, &[key, pk, [5; 32]]),
                &tags_b,
                derive
            ),
            Err(RekeyError::ControlKeyMismatch)
        );
        // 72-byte base blob is the legacy pre-split form.
        assert!(matches!(
            accept_blob(&blob(&Scope::Community, 5, &[key]), &tags_b, derive),
            Ok(AcceptedKey::LegacyBase { .. })
        ));
        // Any other width is malformed; base widths never carry a channel scope.
        assert!(accept_blob(&[0; 71], &tags_b, derive).is_err());
        assert!(accept_blob(&blob(&channel, 2, &[key, pk]), &tags_c, derive).is_err());
        // Debug output never shows key material.
        assert!(!format!("{member:?}").contains("9, 9"));
    }

    #[test]
    fn locators_are_deterministic_and_bound_to_every_input() {
        let a = locator(ADMIN, BOB, &Scope::Community, 5).unwrap();
        assert_eq!(a, locator(ADMIN, BOB, &Scope::Community, 5).unwrap());
        assert_ne!(a, locator(BOB, ADMIN, &Scope::Community, 5).unwrap());
        assert_ne!(a, locator(ADMIN, BOB, &Scope::Community, 6).unwrap());
        assert_ne!(
            a,
            locator(ADMIN, BOB, &Scope::Channel(CHANNEL.into()), 5).unwrap()
        );
        assert!(locator("nothex", BOB, &Scope::Community, 5).is_none());
    }

    #[test]
    fn continuity_distinguishes_extension_gap_and_fork() {
        let held = [7_u8; 32];
        let t = |prev: u64, key: &[u8; 32]| {
            let commit = epoch_key_commitment(prev, key);
            parse_rekey_tags(&tags(&Scope::Community, prev + 1, prev, &commit, (0, 1))).unwrap()
        };
        assert_eq!(
            check_continuity(4, &held, &t(4, &held)),
            Continuity::Extends
        );
        assert_eq!(
            check_continuity(4, &held, &t(4, &[8; 32])),
            Continuity::Reject,
            "fork"
        );
        assert_eq!(
            check_continuity(4, &held, &t(6, &[8; 32])),
            Continuity::MissedRotation
        );
        assert_eq!(
            check_continuity(4, &held, &t(2, &held)),
            Continuity::Reject,
            "stale"
        );
    }

    #[test]
    fn removal_is_concluded_only_from_a_complete_chunk_set() {
        let t0 = parsed(&Scope::Community, 5, 4, (0, 3));
        let t1 = parsed(&Scope::Community, 5, 4, (1, 3));
        let t2 = parsed(&Scope::Community, 5, 4, (2, 3));
        let mut rotation = Rotation::new(ADMIN, &t0, vec!["a".into()]);
        rotation.add_chunk(&t2, vec!["c".into()]).unwrap();
        assert_eq!(
            rotation.outcome("me"),
            RekeyOutcome::Incomplete { missing: vec![1] },
            "a missing chunk is never a removal"
        );
        assert_eq!(rotation.outcome("c"), RekeyOutcome::Included { chunk: 2 });
        rotation.add_chunk(&t1, vec!["b".into()]).unwrap();
        assert_eq!(rotation.outcome("me"), RekeyOutcome::Removed);
        // Chunks that disagree on continuity never merge.
        let forged = parsed(&Scope::Community, 6, 4, (1, 3));
        assert_eq!(
            rotation.add_chunk(&forged, vec![]),
            Err(RekeyError::InconsistentChunks)
        );
    }

    #[test]
    fn races_converge_on_the_lowest_key_and_healing_is_down_only() {
        let keys = [[9_u8; 32], [2; 32], [5; 32]];
        assert_eq!(pick_winner(&keys), Some(&[2; 32]));
        assert_eq!(pick_winner(&[]), None);
        assert!(should_heal_to(&[5; 32], &[2; 32]));
        assert!(!should_heal_to(&[2; 32], &[5; 32]), "never re-fork upward");
        assert!(!should_heal_to(&[2; 32], &[2; 32]));
    }

    #[test]
    fn rotation_authority_needs_the_bit_outrank_and_a_synced_citation() {
        let cid = community_id(OWNER, SALT).unwrap();
        let mut authority = AuthorityFold::new(OWNER, SALT, &cid, FoldMode::Tracking, 32).unwrap();
        let owner_edition = |vsk, eid: &str, content: String, id: &str| Edition {
            vsk,
            entity_id: eid.to_owned(),
            version: 1,
            prev: None,
            content,
            actor: OWNER.to_owned(),
            rumor_id: id.to_owned(),
            vac: None,
        };
        let role = owner_edition(
            VSK_ROLE,
            ROLE,
            format!(
                r#"{{"role_id":"{ROLE}","name":"a","position":1,"permissions":"{}","scope":{{"kind":"server"}}}}"#,
                perm::BAN | perm::MANAGE_CHANNELS
            ),
            "r",
        );
        let grant = owner_edition(
            VSK_GRANT,
            &grant_locator(&cid, ADMIN).unwrap(),
            format!(r#"{{"member":"{ADMIN}","role_ids":["{ROLE}"]}}"#),
            "g",
        );
        assert!(authority.insert(role) && authority.insert(grant.clone()));
        let roster = authority.roster();
        let vac = Vac {
            grant_eid: grant.entity_id.clone(),
            version: 1,
            hash: grant.hash().unwrap(),
        };
        let go = |rotator: &str, vac: Option<&Vac>, scope: &Scope, removed: &[String]| {
            authorize_rotation(&authority, &roster, rotator, vac, scope, removed)
        };
        let bob = vec![BOB.to_owned()];
        assert_eq!(
            go(ADMIN, Some(&vac), &Scope::Community, &bob),
            Verdict::Honored
        );
        assert_eq!(
            go(ADMIN, Some(&vac), &Scope::Channel(CHANNEL.into()), &bob),
            Verdict::Honored
        );
        // Cannot remove the owner, and a rotator without a citation is dropped.
        assert_eq!(
            go(ADMIN, Some(&vac), &Scope::Community, &[OWNER.to_owned()]),
            Verdict::Dropped
        );
        assert_eq!(go(ADMIN, None, &Scope::Community, &bob), Verdict::Dropped);
        // A rotator holding a key but no rank is dropped: keys are not authority.
        assert_eq!(
            go(BOB, Some(&vac), &Scope::Community, &bob),
            Verdict::Dropped
        );
        // An unsynced citation parks rather than drops.
        let mut unsynced = vac.clone();
        unsynced.hash = "00".repeat(32);
        assert_eq!(
            go(ADMIN, Some(&unsynced), &Scope::Community, &bob),
            Verdict::Parked
        );
    }

    #[test]
    fn blob_lists_are_bounded_and_locators_validated() {
        let l = "ab".repeat(32);
        let ok = format!(r#"[{{"locator":"{l}","wrapped":"AAAA"}}]"#);
        assert_eq!(parse_blob_list(&ok).unwrap().len(), 1);
        assert!(parse_blob_list(r#"[{"locator":"short","wrapped":"x"}]"#).is_err());
        let many = vec![json!({"locator": l, "wrapped": "x"}); MAX_BLOBS_PER_EVENT + 1];
        assert!(parse_blob_list(&serde_json::to_string(&many).unwrap()).is_err());
    }
}
