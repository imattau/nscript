//! CORD-04 §1 versioned editions and their per-entity fold.
//!
//! An edition is a signed Control Plane rumor (kind 3308) that replaces the
//! state of one entity. Each entity forms a hash chain; the fold picks the
//! head deterministically so every client lands on the same state.

use std::collections::BTreeMap;

use sha2::{Digest, Sha256};

/// Domain-separation label for the edition hash preimage.
const EDITION_HASH_LABEL: &[u8] = b"vector-community/v1/edition";

/// Entity types (`vsk`, CORD-02 Appendix B) this runtime folds.
pub const VSK_COMMUNITY_METADATA: u8 = 0;
pub const VSK_ROLE: u8 = 1;
pub const VSK_CHANNEL_METADATA: u8 = 2;
pub const VSK_GRANT: u8 = 3;
pub const VSK_BANLIST: u8 = 4;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Edition {
    /// Entity type (`vsk` tag).
    pub vsk: u8,
    /// Stable entity coordinate: 64 lowercase hex characters (`eid` tag).
    pub entity_id: String,
    /// Per-entity counter starting at 1 (`ev` tag).
    pub version: u64,
    /// Hash of the superseded edition (`ep` tag); absent on the first.
    pub prev: Option<String>,
    /// The rumor's content bytes, verbatim. Never re-serialised.
    pub content: String,
    /// Real author of the seal.
    pub actor: String,
    /// The rumor id, used only as the deterministic tie-break.
    pub rumor_id: String,
    /// Authority citation (`vac` tag). Absent when the owner acts.
    pub vac: Option<Vac>,
}

/// The exact Grant edition an actor claims their rank under, pinned by
/// coordinate, version and content hash (CORD-04 §1, §5).
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Vac {
    pub grant_eid: String,
    pub version: u64,
    pub hash: String,
}

impl Edition {
    /// Returns the identity the next edition's `prev` must cite.
    ///
    /// Returns `None` if `entity_id` or `prev` is not 32-byte lowercase hex.
    #[must_use]
    pub fn hash(&self) -> Option<String> {
        let entity = decode_hex32(&self.entity_id)?;
        let mut digest = Sha256::new();
        digest.update((EDITION_HASH_LABEL.len() as u64).to_be_bytes());
        digest.update(EDITION_HASH_LABEL);
        digest.update(entity);
        digest.update(self.version.to_be_bytes());
        if let Some(prev) = &self.prev {
            digest.update([0x01]);
            digest.update(decode_hex32(prev)?);
        } else {
            digest.update([0x00]);
            digest.update([0_u8; 32]);
        }
        digest.update((self.content.len() as u64).to_be_bytes());
        digest.update(self.content.as_bytes());
        Some(encode_hex(&digest.finalize()))
    }
}

fn decode_hex32(value: &str) -> Option<[u8; 32]> {
    if value.len() != 64
        || !value
            .bytes()
            .all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f'))
    {
        return None;
    }
    let mut out = [0_u8; 32];
    for (slot, pair) in out.iter_mut().zip(value.as_bytes().chunks(2)) {
        *slot = u8::from_str_radix(std::str::from_utf8(pair).ok()?, 16).ok()?;
    }
    Some(out)
}

fn encode_hex(bytes: &[u8]) -> String {
    use std::fmt::Write as _;
    bytes.iter().fold(String::new(), |mut out, byte| {
        let _ = write!(out, "{byte:02x}");
        out
    })
}

/// Judges whether an edition's actor holds authority for it. The fold treats
/// this as the sole verdict; holding the Control Plane write key is only a
/// spam gate (CORD-04 §5).
pub trait EditionAuthority {
    fn is_authorized(&self, edition: &Edition) -> bool;
}

/// Authorises every edition. Test and bootstrap use only.
pub struct AllowAll;

impl EditionAuthority for AllowAll {
    fn is_authorized(&self, _edition: &Edition) -> bool {
        true
    }
}

/// How a client treats a chain whose ancestors it does not hold.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum FoldMode {
    /// Steady state: the chain must be intact from version 1.
    Tracking,
    /// A fresh joiner (or a post-Refounding baseline) accepts the highest
    /// authority-verified head despite a dangling `prev`.
    FreshJoiner,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum EditionError {
    CapacityExceeded {
        capacity: usize,
    },
    /// `entity_id` or `prev` is not 32-byte lowercase hex, or `version` is 0,
    /// or `prev` presence disagrees with the version.
    Malformed,
}

/// Folded view of one entity.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct EntityHead<'a> {
    pub head: &'a Edition,
    /// A higher authorised edition exists that the chain cannot reach. Fail
    /// closed for this entity: the client should refetch the gap.
    pub suspended: bool,
}

/// Bounded store of editions folded per entity.
pub struct EditionFold<A: EditionAuthority> {
    authority: A,
    mode: FoldMode,
    capacity: usize,
    count: usize,
    /// entity id -> version -> editions at that version, keyed by rumor id.
    entities: BTreeMap<String, BTreeMap<u64, BTreeMap<String, Edition>>>,
}

impl<A: EditionAuthority> EditionFold<A> {
    #[must_use]
    pub fn new(authority: A, mode: FoldMode, capacity: usize) -> Self {
        Self {
            authority,
            mode,
            capacity,
            count: 0,
            entities: BTreeMap::new(),
        }
    }

    /// Stores an edition. Re-inserting a known rumor id is a no-op.
    ///
    /// # Errors
    ///
    /// Returns [`EditionError::Malformed`] for structurally invalid editions
    /// and [`EditionError::CapacityExceeded`] when the store is full.
    pub fn insert(&mut self, edition: Edition) -> Result<(), EditionError> {
        if edition.version == 0
            || edition.hash().is_none()
            || edition.prev.is_some() == (edition.version == 1)
        {
            return Err(EditionError::Malformed);
        }
        let slot = self
            .entities
            .entry(edition.entity_id.clone())
            .or_default()
            .entry(edition.version)
            .or_default();
        if slot.contains_key(&edition.rumor_id) {
            return Ok(());
        }
        if self.count >= self.capacity {
            return Err(EditionError::CapacityExceeded {
                capacity: self.capacity,
            });
        }
        slot.insert(edition.rumor_id.clone(), edition);
        self.count += 1;
        Ok(())
    }

    /// Folds one entity to its current head.
    #[must_use]
    pub fn head(&self, entity_id: &str) -> Option<EntityHead<'_>> {
        let versions = self.entities.get(entity_id)?;
        // Authorised candidates at a version, lowest rumor id first. Judging
        // is by authority first, never by the author-settable timestamp.
        let winner = |version: u64, prev: Option<&str>, any_prev: bool| {
            versions
                .get(&version)?
                .values()
                .filter(|e| any_prev || e.prev.as_deref() == prev)
                .find(|e| self.authority.is_authorized(e))
        };
        let highest_authorised = versions
            .iter()
            .rev()
            .find_map(|(v, _)| winner(*v, None, true).map(|e| (*v, e)));
        let (top_version, top) = highest_authorised?;

        let head = match self.mode {
            FoldMode::FreshJoiner => top,
            FoldMode::Tracking => {
                let mut head = winner(1, None, false)?;
                let mut hash = head.hash()?;
                while let Some(next) = winner(head.version + 1, Some(&hash), false) {
                    hash = next.hash()?;
                    head = next;
                }
                head
            }
        };
        Some(EntityHead {
            head,
            suspended: top_version > head.version,
        })
    }

    /// Entity ids currently held, in deterministic order.
    pub fn entity_ids(&self) -> impl Iterator<Item = &str> {
        self.entities.keys().map(String::as_str)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hex(n: u8) -> String {
        format!("{n:02x}").repeat(32)
    }

    fn edition(version: u64, prev: Option<&Edition>, content: &str, id: &str) -> Edition {
        Edition {
            vsk: VSK_CHANNEL_METADATA,
            entity_id: hex(1),
            version,
            prev: prev.map(|p| p.hash().unwrap()),
            content: content.to_owned(),
            actor: "owner".to_owned(),
            rumor_id: id.to_owned(),
            vac: None,
        }
    }

    #[test]
    fn hash_covers_content_bytes_verbatim() {
        let a = edition(1, None, r#"{"a":1}"#, "x");
        let b = edition(1, None, r#"{ "a": 1 }"#, "x");
        assert_ne!(a.hash(), b.hash());
        assert_eq!(a.hash(), a.clone().hash());
        assert_eq!(a.hash().unwrap().len(), 64);
    }

    #[test]
    fn chain_folds_to_highest_intact_version() {
        let v1 = edition(1, None, "one", "a");
        let v2 = edition(2, Some(&v1), "two", "b");
        let v3 = edition(3, Some(&v2), "three", "c");
        let mut fold = EditionFold::new(AllowAll, FoldMode::Tracking, 16);
        for e in [v3.clone(), v1, v2] {
            fold.insert(e).unwrap();
        }
        let head = fold.head(&hex(1)).unwrap();
        assert_eq!(head.head, &v3);
        assert!(!head.suspended);
    }

    #[test]
    fn stale_version_never_downgrades() {
        let v1 = edition(1, None, "one", "a");
        let v2 = edition(2, Some(&v1), "two", "b");
        let mut fold = EditionFold::new(AllowAll, FoldMode::Tracking, 16);
        fold.insert(v2.clone()).unwrap();
        fold.insert(v1).unwrap();
        assert_eq!(fold.head(&hex(1)).unwrap().head, &v2);
    }

    #[test]
    fn same_version_tie_breaks_on_lowest_rumor_id() {
        let v1 = edition(1, None, "one", "a");
        let high = edition(2, Some(&v1), "high", "zz");
        let low = edition(2, Some(&v1), "low", "bb");
        let mut fold = EditionFold::new(AllowAll, FoldMode::Tracking, 16);
        for e in [v1, high, low.clone()] {
            fold.insert(e).unwrap();
        }
        assert_eq!(fold.head(&hex(1)).unwrap().head, &low);
    }

    #[test]
    fn unauthorised_editions_are_dropped_before_the_tie_break() {
        struct OnlyOwner;
        impl EditionAuthority for OnlyOwner {
            fn is_authorized(&self, e: &Edition) -> bool {
                e.actor == "owner"
            }
        }
        let v1 = edition(1, None, "one", "a");
        let mut forged = edition(2, Some(&v1), "forged", "0000");
        "mallory".clone_into(&mut forged.actor);
        let real = edition(2, Some(&v1), "real", "ffff");
        let mut fold = EditionFold::new(OnlyOwner, FoldMode::Tracking, 16);
        for e in [v1, forged, real.clone()] {
            fold.insert(e).unwrap();
        }
        assert_eq!(fold.head(&hex(1)).unwrap().head, &real);
    }

    #[test]
    fn tracking_client_suspends_on_a_gap_but_fresh_joiner_baselines() {
        let v1 = edition(1, None, "one", "a");
        let v2 = edition(2, Some(&v1), "two", "b");
        let v3 = edition(3, Some(&v2), "three", "c");

        let mut tracking = EditionFold::new(AllowAll, FoldMode::Tracking, 16);
        tracking.insert(v1.clone()).unwrap();
        tracking.insert(v3.clone()).unwrap();
        let head = tracking.head(&hex(1)).unwrap();
        assert_eq!(head.head, &v1);
        assert!(head.suspended);

        let mut joiner = EditionFold::new(AllowAll, FoldMode::FreshJoiner, 16);
        joiner.insert(v3.clone()).unwrap();
        let head = joiner.head(&hex(1)).unwrap();
        assert_eq!(head.head, &v3);
        assert!(!head.suspended);
    }

    #[test]
    fn malformed_and_over_capacity_editions_are_refused() {
        let mut fold = EditionFold::new(AllowAll, FoldMode::Tracking, 1);
        let mut bad = edition(1, None, "x", "a");
        bad.entity_id = "NOT-HEX".to_owned();
        assert_eq!(fold.insert(bad), Err(EditionError::Malformed));
        let v1 = edition(1, None, "x", "a");
        let orphan = Edition {
            prev: Some(hex(9)),
            ..edition(1, None, "y", "b")
        };
        assert_eq!(fold.insert(orphan), Err(EditionError::Malformed));
        fold.insert(v1.clone()).unwrap();
        fold.insert(v1.clone()).unwrap();
        let v2 = edition(2, Some(&v1), "z", "c");
        assert_eq!(
            fold.insert(v2),
            Err(EditionError::CapacityExceeded { capacity: 1 })
        );
    }
}
