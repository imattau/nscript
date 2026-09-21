//! CORD-08 disappearing messages: tagging, enforcement and timer notices.
//!
//! The timer is Community state (a metadata field). It governs Chat planes
//! only and is never retroactive: the `expiration` tag inside the signed rumor
//! is what every reader enforces, whatever the fold now prescribes.

use std::collections::BTreeMap;

use crate::authority::{Roster, perm};
use crate::wire::{decimal_u64, tag_values};

pub const KIND_DELETE: u64 = 5;
pub const KIND_TIMER_NOTICE: u64 = 1740;
/// Ephemeral kinds (typing, voice presence) carry no expiration.
const EPHEMERAL_KINDS: [u64; 2] = [23311, 23313];

/// The NIP-40 tag for a rumor created at `created_at`, or `None` when the
/// timer is off or the kind is exempt. Deletes are exempt (an expiring
/// tombstone would let the erased message return) and so are timer notices
/// (the policy must not erase its own documentation).
#[must_use]
pub fn expiration_tag(kind: u64, created_at: u64, timer: Option<u64>) -> Option<Vec<String>> {
    if kind == KIND_DELETE || kind == KIND_TIMER_NOTICE || EPHEMERAL_KINDS.contains(&kind) {
        return None;
    }
    let seconds = timer.filter(|seconds| *seconds > 0)?;
    Some(vec![
        "expiration".to_owned(),
        created_at.saturating_add(seconds).to_string(),
    ])
}

/// Reads a rumor's own `expiration` tag. A missing or malformed tag means the
/// rumor does not expire (a reader judges by the signed copy alone).
#[must_use]
pub fn rumor_expiration(tags: &[serde_json::Value]) -> Option<u64> {
    match tag_values(tags, "expiration")?.as_slice() {
        [value] => decimal_u64(value),
        _ => None,
    }
}

/// NIP-40: a rumor is expired once `now` reaches its expiration.
#[must_use]
pub fn is_expired(expiration: Option<u64>, now: u64) -> bool {
    expiration.is_some_and(|at| now >= at)
}

/// Interprets a kind-1740 timer notice. Returns the announced timer
/// (`Some(None)` = turned off) only if the author holds `MANAGE_METADATA`:
/// anyone can spell a tag, only staff are believed about policy. The metadata
/// fold stays the authority; a notice is informational.
#[must_use]
pub fn accept_timer_notice(
    author: &str,
    tags: &[serde_json::Value],
    roster: &Roster,
) -> Option<Option<u64>> {
    let allowed = author == roster.owner
        || (!roster.banned.contains(author)
            && roster.permissions(author) & perm::MANAGE_METADATA != 0);
    if !allowed {
        return None;
    }
    match tag_values(tags, "timer")?.as_slice() {
        [seconds] => decimal_u64(seconds).map(|s| (s > 0).then_some(s)),
        _ => None,
    }
}

/// A local store that refuses, hides and purges expired rumors.
#[derive(Clone, Debug, Default)]
pub struct ExpiringStore<T> {
    entries: BTreeMap<String, (Option<u64>, T)>,
}

impl<T> ExpiringStore<T> {
    #[must_use]
    pub fn new() -> Self {
        Self {
            entries: BTreeMap::new(),
        }
    }

    /// Stores a rumor unless it is already expired. Returns whether it was kept.
    pub fn ingest(&mut self, id: &str, expiration: Option<u64>, value: T, now: u64) -> bool {
        if is_expired(expiration, now) {
            return false;
        }
        self.entries.insert(id.to_owned(), (expiration, value));
        true
    }

    /// Rumors still visible at `now`, including any stored before their expiry
    /// passed but not yet swept.
    pub fn visible(&self, now: u64) -> impl Iterator<Item = (&str, &T)> {
        self.entries
            .iter()
            .filter(move |(_, (expiration, _))| !is_expired(*expiration, now))
            .map(|(id, (_, value))| (id.as_str(), value))
    }

    /// Physically removes expired rumors, returning how many were purged.
    pub fn sweep(&mut self, now: u64) -> usize {
        let before = self.entries.len();
        self.entries
            .retain(|_, (expiration, _)| !is_expired(*expiration, now));
        before - self.entries.len()
    }

    #[must_use]
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::authority::Role;
    use crate::community::parse_community_metadata;
    use serde_json::json;

    fn tags(value: &serde_json::Value) -> Vec<serde_json::Value> {
        value.as_array().unwrap().clone()
    }

    #[test]
    fn timer_is_off_for_absent_zero_or_malformed_values() {
        let meta = |field: &str| {
            parse_community_metadata(&format!(r#"{{"name":"n"{field}}}"#))
                .unwrap()
                .message_expiration
        };
        assert_eq!(meta(""), None);
        assert_eq!(meta(r#","message_expiration":0"#), None);
        assert_eq!(meta(r#","message_expiration":"3600""#), None);
        assert_eq!(meta(r#","message_expiration":-5"#), None);
        assert_eq!(meta(r#","message_expiration":1.5"#), None);
        assert_eq!(meta(r#","message_expiration":2592000"#), Some(2_592_000));
    }

    #[test]
    fn tags_are_computed_from_created_at_and_exempt_kinds_get_none() {
        assert_eq!(
            expiration_tag(9, 1_000, Some(60)),
            Some(vec!["expiration".to_owned(), "1060".to_owned()])
        );
        assert_eq!(expiration_tag(9, 1_000, None), None);
        assert_eq!(expiration_tag(9, 1_000, Some(0)), None);
        for exempt in [KIND_DELETE, KIND_TIMER_NOTICE, 23311, 23313] {
            assert_eq!(expiration_tag(exempt, 1_000, Some(60)), None, "{exempt}");
        }
    }

    #[test]
    fn readers_judge_by_the_signed_rumor_tag() {
        let with = tags(&json!([["expiration", "1060"]]));
        assert_eq!(rumor_expiration(&with), Some(1060));
        assert!(!is_expired(Some(1060), 1059));
        assert!(is_expired(Some(1060), 1060));
        assert!(!is_expired(None, u64::MAX));
        // Malformed spellings do not become an expiry.
        for bad in [json!("01060"), json!("-1"), json!("1e3"), json!("")] {
            assert_eq!(rumor_expiration(&tags(&json!([["expiration", bad]]))), None);
        }
        assert_eq!(rumor_expiration(&[]), None);
    }

    #[test]
    fn store_refuses_hides_and_purges() {
        let mut store = ExpiringStore::new();
        assert!(
            !store.ingest("old", Some(100), "x", 100),
            "refused at ingest"
        );
        assert!(store.ingest("soon", Some(200), "y", 100));
        assert!(store.ingest("forever", None, "z", 100));
        assert_eq!(store.visible(150).count(), 2);
        // Stored before expiry, now past it: hidden even before the sweep.
        assert_eq!(
            store.visible(200).map(|(id, _)| id).collect::<Vec<_>>(),
            ["forever"]
        );
        assert_eq!(store.len(), 2);
        assert_eq!(store.sweep(200), 1);
        assert_eq!(store.len(), 1);
    }

    #[test]
    fn timer_notices_are_believed_only_from_metadata_staff() {
        let mut roster = Roster::new("owner");
        roster.roles.insert(
            "staff".into(),
            Role {
                role_id: "staff".into(),
                position: 2,
                permissions: perm::MANAGE_METADATA,
                server_scope: true,
            },
        );
        roster.grants.insert("editor".into(), vec!["staff".into()]);
        let notice = tags(&json!([
            ["channel", "c"],
            ["epoch", "1"],
            ["timer", "2592000"]
        ]));
        assert_eq!(
            accept_timer_notice("owner", &notice, &roster),
            Some(Some(2_592_000))
        );
        assert_eq!(
            accept_timer_notice("editor", &notice, &roster),
            Some(Some(2_592_000))
        );
        assert_eq!(accept_timer_notice("rando", &notice, &roster), None);
        let off = tags(&json!([["timer", "0"]]));
        assert_eq!(accept_timer_notice("owner", &off, &roster), Some(None));
        let bad = tags(&json!([["timer", "07"]]));
        assert_eq!(accept_timer_notice("owner", &bad, &roster), None);
        roster.banned.insert("editor".into());
        assert_eq!(accept_timer_notice("editor", &notice, &roster), None);
    }
}
