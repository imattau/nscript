//! CORD-02 §5 Guestbook: membership motion folded flat, one state per npub.
//!
//! The Guestbook is off-consensus: nothing in Control or Chat depends on it.
//! Joins and Leaves are each member's own word; Kicks need `KICK` plus strict
//! outrank; Snapshots are a refounder's secondhand seed and lose to any newer
//! first-hand entry.

use std::collections::{BTreeMap, BTreeSet};
use std::ops::RangeInclusive;

use serde_json::Value;

use crate::authority::{AuthorityFold, Roster, Verdict, perm};
use crate::edition::Vac;
use crate::stream::is_hex32;
use crate::wire::{decimal_u64, tag_values};

pub const KIND_JOIN_LEAVE: u64 = 3306;
pub const KIND_KICK: u64 = 3309;
pub const KIND_SNAPSHOT: u64 = 3312;
/// Entries dated further than this ahead of the receiver's clock are dropped.
pub const MAX_FUTURE_MS: u64 = 3_600_000;
/// Members per snapshot chunk.
pub const SNAPSHOT_CHUNK_MAX: usize = 400;
const MS_RANGE: RangeInclusive<u64> = 0..=999;

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum GuestbookError {
    NotJson,
    WrongKind,
    AuthorMismatch,
    /// Includes an `ms` tag outside `0..=999`: dropped, never interpreted.
    Malformed(&'static str),
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum EntryBody {
    Join,
    Leave,
    Kick { target: String, vac: Option<Vac> },
    Snapshot { members: Vec<String> },
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct GuestbookEntry {
    pub author: String,
    /// `created_at * 1000 + ms` (CORD-02 §4).
    pub time_ms: u64,
    /// Inner rumor id; the tie-break, never the wrap's.
    pub rumor_id: String,
    pub body: EntryBody,
}

/// Decodes a Guestbook rumor. `seal_pubkey` is the proven author.
///
/// # Errors
///
/// Returns [`GuestbookError`] for a rumor the fold must drop.
pub fn parse_guestbook_rumor(
    seal_pubkey: &str,
    rumor_json: &str,
) -> Result<GuestbookEntry, GuestbookError> {
    let rumor: Value = serde_json::from_str(rumor_json).map_err(|_| GuestbookError::NotJson)?;
    if rumor.get("pubkey").and_then(Value::as_str) != Some(seal_pubkey) {
        return Err(GuestbookError::AuthorMismatch);
    }
    let kind = rumor.get("kind").and_then(Value::as_u64);
    let content = rumor
        .get("content")
        .and_then(Value::as_str)
        .ok_or(GuestbookError::Malformed("content"))?;
    let tags = rumor
        .get("tags")
        .and_then(Value::as_array)
        .ok_or(GuestbookError::Malformed("tags"))?;
    let created_at = rumor
        .get("created_at")
        .and_then(Value::as_u64)
        .ok_or(GuestbookError::Malformed("created_at"))?;
    let ms = match tag_values(tags, "ms").as_deref() {
        None => 0,
        Some([ms]) => decimal_u64(ms)
            .filter(|ms| MS_RANGE.contains(ms))
            .ok_or(GuestbookError::Malformed("ms"))?,
        Some(_) => return Err(GuestbookError::Malformed("ms")),
    };
    let body = match kind {
        Some(KIND_JOIN_LEAVE) => match content {
            "join" => EntryBody::Join,
            "leave" => EntryBody::Leave,
            _ => return Err(GuestbookError::Malformed("content")),
        },
        Some(KIND_KICK) => {
            let target = match tag_values(tags, "p").as_deref() {
                Some([target]) if is_hex32(target) => (*target).to_owned(),
                _ => return Err(GuestbookError::Malformed("p")),
            };
            let vac = match tag_values(tags, "vac").as_deref() {
                None => None,
                Some([eid, version, hash]) if is_hex32(eid) && is_hex32(hash) => Some(Vac {
                    grant_eid: (*eid).to_owned(),
                    version: decimal_u64(version).ok_or(GuestbookError::Malformed("vac"))?,
                    hash: (*hash).to_owned(),
                }),
                Some(_) => return Err(GuestbookError::Malformed("vac")),
            };
            EntryBody::Kick { target, vac }
        }
        Some(KIND_SNAPSHOT) => {
            let members: Vec<String> =
                serde_json::from_str(content).map_err(|_| GuestbookError::Malformed("content"))?;
            if members.len() > SNAPSHOT_CHUNK_MAX || !members.iter().all(|m| is_hex32(m)) {
                return Err(GuestbookError::Malformed("content"));
            }
            EntryBody::Snapshot { members }
        }
        _ => return Err(GuestbookError::WrongKind),
    };
    let rumor_id = crate::wire::rumor_id(rumor_json).ok_or(GuestbookError::NotJson)?;
    Ok(GuestbookEntry {
        author: seal_pubkey.to_owned(),
        time_ms: created_at * 1000 + ms,
        rumor_id,
        body,
    })
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum MemberState {
    Present,
    Left,
    Kicked,
}

/// The coalesced Guestbook: one final state per npub.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct Guestbook {
    states: BTreeMap<String, (MemberState, u64, String)>,
}

impl Guestbook {
    /// Coalesces `entries`: the latest by `(time_ms, lowest rumor id)` wins per
    /// npub. `refounder` is the npub whose Refounding minted this epoch, the
    /// only author whose snapshots are honoured.
    #[must_use]
    pub fn fold(
        entries: &[GuestbookEntry],
        authority: &AuthorityFold,
        roster: &Roster,
        refounder: Option<&str>,
        now_ms: u64,
    ) -> Self {
        let mut book = Self::default();
        for entry in entries {
            if entry.time_ms > now_ms.saturating_add(MAX_FUTURE_MS) {
                continue;
            }
            // A banned npub vanishes entirely: none of their words count.
            if entry.author != roster.owner && roster.banned.contains(&entry.author) {
                continue;
            }
            match &entry.body {
                EntryBody::Join => book.offer(&entry.author, MemberState::Present, entry),
                EntryBody::Leave => book.offer(&entry.author, MemberState::Left, entry),
                EntryBody::Kick { target, vac } => {
                    let cited = authority.check_citation(&entry.author, vac.as_ref());
                    if cited == Verdict::Honored
                        && roster.can(&entry.author, perm::KICK, Some(target))
                    {
                        book.offer(target, MemberState::Kicked, entry);
                    }
                }
                EntryBody::Snapshot { members } => {
                    if refounder == Some(entry.author.as_str()) {
                        for member in members {
                            book.offer(member, MemberState::Present, entry);
                        }
                    }
                }
            }
        }
        book
    }

    fn offer(&mut self, npub: &str, state: MemberState, entry: &GuestbookEntry) {
        let wins = self.states.get(npub).is_none_or(|(_, time, id)| {
            (entry.time_ms, std::cmp::Reverse(&entry.rumor_id)) > (*time, std::cmp::Reverse(id))
        });
        if wins {
            self.states.insert(
                npub.to_owned(),
                (state, entry.time_ms, entry.rumor_id.clone()),
            );
        }
    }

    #[must_use]
    pub fn state(&self, npub: &str) -> Option<MemberState> {
        self.states.get(npub).map(|(state, _, _)| *state)
    }

    /// The Complete Memberlist: coalesced present members, plus authors
    /// observed publishing after their latest Leave or Kick, minus the
    /// Banlist. `observed` is `(author, time_ms)` of every valid event seen.
    #[must_use]
    pub fn members(
        &self,
        observed: &[(String, u64)],
        banned: &BTreeSet<String>,
    ) -> BTreeSet<String> {
        let mut list: BTreeSet<String> = self
            .states
            .iter()
            .filter(|(_, (state, _, _))| *state == MemberState::Present)
            .map(|(npub, _)| npub.clone())
            .collect();
        for (author, time_ms) in observed {
            // Observation only counts forward: old activity never resurrects.
            let departed_at = match self.states.get(author) {
                Some((MemberState::Left | MemberState::Kicked, at, _)) => Some(*at),
                _ => None,
            };
            if departed_at.is_none_or(|at| *time_ms > at) {
                list.insert(author.clone());
            }
        }
        list.retain(|npub| !banned.contains(npub));
        list
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::authority::{community_id, grant_locator};
    use crate::edition::{Edition, FoldMode, VSK_GRANT, VSK_ROLE};

    const OWNER: &str = "0101010101010101010101010101010101010101010101010101010101010101";
    const SALT: &str = "0202020202020202020202020202020202020202020202020202020202020202";
    const MODR: &str = "aa00000000000000000000000000000000000000000000000000000000000001";
    const BOB: &str = "bb00000000000000000000000000000000000000000000000000000000000002";
    const CAROL: &str = "cc00000000000000000000000000000000000000000000000000000000000003";
    const ROLE: &str = "1100000000000000000000000000000000000000000000000000000000000000";

    struct Setup {
        authority: AuthorityFold,
        grant: Edition,
    }

    fn setup(sync_grant: bool) -> Setup {
        let cid = community_id(OWNER, SALT).unwrap();
        let mut authority = AuthorityFold::new(OWNER, SALT, &cid, FoldMode::Tracking, 32).unwrap();
        let edition = |vsk, eid: &str, content: String, id: &str| Edition {
            vsk,
            entity_id: eid.to_owned(),
            version: 1,
            prev: None,
            content,
            actor: OWNER.to_owned(),
            rumor_id: id.to_owned(),
            vac: None,
        };
        let role = edition(
            VSK_ROLE,
            ROLE,
            format!(
                r#"{{"role_id":"{ROLE}","name":"mod","position":5,"permissions":"{}","scope":{{"kind":"server"}}}}"#,
                perm::KICK
            ),
            "r1",
        );
        let grant = edition(
            VSK_GRANT,
            &grant_locator(&cid, MODR).unwrap(),
            format!(r#"{{"member":"{MODR}","role_ids":["{ROLE}"]}}"#),
            "g1",
        );
        assert!(authority.insert(role));
        if sync_grant {
            assert!(authority.insert(grant.clone()));
        }
        Setup { authority, grant }
    }

    fn vac(grant: &Edition) -> Vac {
        Vac {
            grant_eid: grant.entity_id.clone(),
            version: grant.version,
            hash: grant.hash().unwrap(),
        }
    }

    fn entry(author: &str, time_ms: u64, id: &str, body: EntryBody) -> GuestbookEntry {
        GuestbookEntry {
            author: author.to_owned(),
            time_ms,
            rumor_id: id.to_owned(),
            body,
        }
    }

    fn fold(setup: &Setup, entries: &[GuestbookEntry], refounder: Option<&str>) -> Guestbook {
        let roster = setup.authority.roster();
        Guestbook::fold(entries, &setup.authority, &roster, refounder, 10_000_000)
    }

    #[test]
    fn latest_entry_wins_and_ties_break_on_the_lower_rumor_id() {
        let s = setup(true);
        let book = fold(
            &s,
            &[
                entry(BOB, 1000, "a", EntryBody::Join),
                entry(BOB, 2000, "b", EntryBody::Leave),
                entry(CAROL, 3000, "zz", EntryBody::Join),
                entry(CAROL, 3000, "aa", EntryBody::Leave),
            ],
            None,
        );
        assert_eq!(book.state(BOB), Some(MemberState::Left));
        assert_eq!(
            book.state(CAROL),
            Some(MemberState::Left),
            "lower id wins the tie"
        );
    }

    #[test]
    fn entries_more_than_an_hour_ahead_are_dropped() {
        let s = setup(true);
        let now = 10_000_000;
        let book = fold(
            &s,
            &[
                entry(BOB, now + MAX_FUTURE_MS, "a", EntryBody::Join),
                entry(CAROL, now + MAX_FUTURE_MS + 1, "b", EntryBody::Join),
            ],
            None,
        );
        assert_eq!(book.state(BOB), Some(MemberState::Present));
        assert_eq!(book.state(CAROL), None);
    }

    #[test]
    fn kicks_need_the_bit_a_synced_citation_and_outrank() {
        let s = setup(true);
        let kick = |author: &str, target: &str, vac: Option<Vac>, id: &str| {
            entry(
                author,
                5000,
                id,
                EntryBody::Kick {
                    target: target.to_owned(),
                    vac,
                },
            )
        };
        let book = fold(
            &s,
            &[
                entry(BOB, 1000, "j", EntryBody::Join),
                kick(MODR, BOB, Some(vac(&s.grant)), "k1"),
                kick(MODR, OWNER, Some(vac(&s.grant)), "k2"),
                kick(BOB, CAROL, None, "k3"),
                kick(MODR, CAROL, None, "k4"),
            ],
            None,
        );
        assert_eq!(book.state(BOB), Some(MemberState::Kicked));
        assert_eq!(book.state(OWNER), None, "cannot outrank the owner");
        assert_eq!(book.state(CAROL), None, "no KICK bit, or no citation");
        // A kicked member may rejoin with a newer Join.
        let rejoined = fold(
            &s,
            &[
                kick(MODR, BOB, Some(vac(&s.grant)), "k1"),
                entry(BOB, 9000, "j2", EntryBody::Join),
            ],
            None,
        );
        assert_eq!(rejoined.state(BOB), Some(MemberState::Present));
        // Owner kicks need no citation.
        let by_owner = fold(&s, &[kick(OWNER, BOB, None, "k5")], None);
        assert_eq!(by_owner.state(BOB), Some(MemberState::Kicked));
        // Unsynced citation parks: not honoured yet.
        let unsynced = setup(false);
        let parked = fold(
            &unsynced,
            &[kick(MODR, BOB, Some(vac(&unsynced.grant)), "k1")],
            None,
        );
        assert_eq!(parked.state(BOB), None);
    }

    #[test]
    fn snapshots_seed_only_from_the_refounder_and_lose_to_newer_words() {
        let s = setup(true);
        let snap = |author: &str, time, id: &str| {
            entry(
                author,
                time,
                id,
                EntryBody::Snapshot {
                    members: vec![BOB.to_owned(), CAROL.to_owned()],
                },
            )
        };
        let honoured = fold(&s, &[snap(MODR, 4000, "s1")], Some(MODR));
        assert_eq!(honoured.state(BOB), Some(MemberState::Present));
        let ignored = fold(&s, &[snap(MODR, 4000, "s1")], Some(OWNER));
        assert_eq!(ignored.state(BOB), None);
        let superseded = fold(
            &s,
            &[
                snap(MODR, 4000, "s1"),
                entry(BOB, 5000, "l", EntryBody::Leave),
            ],
            Some(MODR),
        );
        assert_eq!(superseded.state(BOB), Some(MemberState::Left));
        assert_eq!(superseded.state(CAROL), Some(MemberState::Present));
        // An older self-signed Leave does not beat a newer snapshot seed.
        let seeded = fold(
            &s,
            &[
                entry(BOB, 1000, "l", EntryBody::Leave),
                snap(MODR, 4000, "s1"),
            ],
            Some(MODR),
        );
        assert_eq!(seeded.state(BOB), Some(MemberState::Present));
    }

    #[test]
    fn memberlist_merges_observation_forward_only_and_removes_the_banned() {
        let s = setup(true);
        let book = fold(
            &s,
            &[
                entry(BOB, 1000, "j", EntryBody::Join),
                entry(CAROL, 2000, "l", EntryBody::Leave),
            ],
            None,
        );
        let observed = vec![
            (MODR.to_owned(), 500),   // never joined, but seen: included
            (CAROL.to_owned(), 1500), // activity before their Leave: ignored
        ];
        let list = book.members(&observed, &BTreeSet::new());
        assert!(list.contains(MODR) && list.contains(BOB) && !list.contains(CAROL));
        let later = vec![(CAROL.to_owned(), 2500)];
        assert!(book.members(&later, &BTreeSet::new()).contains(CAROL));
        let banned = BTreeSet::from([BOB.to_owned()]);
        assert!(!book.members(&observed, &banned).contains(BOB));
    }

    #[test]
    fn banned_authors_are_dropped_entirely() {
        let s = setup(true);
        let mut roster = s.authority.roster();
        roster.banned.insert(BOB.to_owned());
        let book = Guestbook::fold(
            &[entry(BOB, 1000, "j", EntryBody::Join)],
            &s.authority,
            &roster,
            None,
            10_000_000,
        );
        assert_eq!(book.state(BOB), None);
    }

    fn rumor(author: &str, kind: u64, content: &str, tags: &str) -> String {
        format!(
            r#"{{"kind":{kind},"pubkey":"{author}","content":{},"tags":{tags},"created_at":1700000000}}"#,
            serde_json::to_string(content).unwrap()
        )
    }

    #[test]
    fn rumors_decode_with_ms_and_reject_malformed_entries() {
        let join =
            parse_guestbook_rumor(BOB, &rumor(BOB, 3306, "join", r#"[["ms","250"]]"#)).unwrap();
        assert_eq!(join.time_ms, 1_700_000_000_250);
        assert_eq!(join.body, EntryBody::Join);
        for bad_ms in [r#"[["ms","1000"]]"#, r#"[["ms","-1"]]"#, r#"[["ms","07"]]"#] {
            assert_eq!(
                parse_guestbook_rumor(BOB, &rumor(BOB, 3306, "join", bad_ms)),
                Err(GuestbookError::Malformed("ms")),
                "{bad_ms}"
            );
        }
        assert_eq!(
            parse_guestbook_rumor(CAROL, &rumor(BOB, 3306, "join", "[]")),
            Err(GuestbookError::AuthorMismatch)
        );
        assert_eq!(
            parse_guestbook_rumor(BOB, &rumor(BOB, 3306, "hello", "[]")),
            Err(GuestbookError::Malformed("content"))
        );
        let kick = rumor(MODR, 3309, "", &format!(r#"[["p","{BOB}"]]"#));
        let kick = parse_guestbook_rumor(MODR, &kick).unwrap();
        assert_eq!(
            kick.body,
            EntryBody::Kick {
                target: BOB.to_owned(),
                vac: None
            }
        );
        let too_many = serde_json::to_string(&vec![BOB; SNAPSHOT_CHUNK_MAX + 1]).unwrap();
        assert_eq!(
            parse_guestbook_rumor(
                MODR,
                &rumor(MODR, 3312, &too_many, r#"[["snap","x","1","1"]]"#)
            ),
            Err(GuestbookError::Malformed("content"))
        );
    }
}
