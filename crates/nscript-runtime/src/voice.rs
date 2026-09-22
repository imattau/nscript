//! CORD-07 Audio/Video: the pure protocol vocabulary a broker or client needs
//! beyond the Chat-plane keying it already has (CORD-03 §1).
//!
//! The spec treats calls as host/service integration (`docs/CONCORD.md` §9):
//! there is no scripted "join a call" operation here. What lives in this
//! module is the deterministic, testable half of the protocol — the presence
//! rumor (kind 23313, §4), the broker request's non-cryptographic checks
//! (§2), and the rendezvous tie-break (§5) — so a broker or client built on
//! `nscript-host-crypto`'s real signing has a shared, spec-verified
//! foundation rather than reimplementing these rules itself.

use serde_json::Value;

use crate::stream::{BindingError, check_channel_binding};
use crate::wire::{decimal_u64, tag_values};

/// Voice presence (§4): ephemeral, never stored.
pub const KIND_PRESENCE: u64 = 23_313;
/// A blind broker's token request (§2), signed with `voice_key.sk`.
pub const KIND_BROKER_AUTH: u64 = 27_235;

/// A `joined` repeats at least this often (§4).
pub const PRESENCE_HEARTBEAT_SECS: u64 = 30;
/// A `joined` older than this (three missed heartbeats) is stale (§4).
pub const PRESENCE_STALE_MS: u64 = 90_000;
/// A broker auth grant's `created_at` must fall within this many seconds of
/// the broker's clock, either direction (§2).
pub const AUTH_FRESHNESS_SECS: u64 = 60;
/// How long a broker must retain seen auth-event ids: twice the freshness
/// window (§2).
pub const AUTH_REPLAY_RETENTION_SECS: u64 = 2 * AUTH_FRESHNESS_SECS;
/// The broker-assigned SFU identity must carry at least this many bits of
/// entropy (§2); expressed in bytes for [`identity_has_enough_entropy`].
pub const IDENTITY_MIN_ENTROPY_BYTES: usize = 16;

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum PresenceError {
    NotJson,
    AuthorMismatch,
    Binding(BindingError),
    Malformed(&'static str),
}

impl From<BindingError> for PresenceError {
    fn from(error: BindingError) -> Self {
        Self::Binding(error)
    }
}

/// What a presence heartbeat announces (§4). `Left` is best-effort and omits
/// the identity/broker a `Joined` carries.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum PresenceVerb {
    Joined { identity: String, broker: String },
    Left,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Presence {
    pub author: String,
    /// `created_at * 1000 + ms` (CORD-02 §4 basis), for the latest-wins rule.
    pub time_ms: u64,
    pub verb: PresenceVerb,
}

const MS_MAX: u64 = 999;

/// Decodes a presence rumor (kind 23313). `seal_pubkey` is the proven author,
/// and `channel_id`/`epoch` the coordinate the rumor must bind to (CORD-03
/// §3), exactly as any Chat-plane rumor.
///
/// # Errors
///
/// Returns [`PresenceError`] for anything a reader must drop rather than
/// display: wrong shape, an author mismatch, or a binding failure.
pub fn parse_presence_rumor(
    seal_pubkey: &str,
    rumor_json: &str,
    channel_id: &str,
    epoch: u64,
) -> Result<Presence, PresenceError> {
    let rumor: Value = serde_json::from_str(rumor_json).map_err(|_| PresenceError::NotJson)?;
    if rumor.get("pubkey").and_then(Value::as_str) != Some(seal_pubkey) {
        return Err(PresenceError::AuthorMismatch);
    }
    if rumor.get("kind").and_then(Value::as_u64) != Some(KIND_PRESENCE) {
        return Err(PresenceError::Malformed("kind"));
    }
    let content = rumor
        .get("content")
        .and_then(Value::as_str)
        .ok_or(PresenceError::Malformed("content"))?;
    let tags = rumor
        .get("tags")
        .and_then(Value::as_array)
        .ok_or(PresenceError::Malformed("tags"))?;
    let created_at = rumor
        .get("created_at")
        .and_then(Value::as_u64)
        .ok_or(PresenceError::Malformed("created_at"))?;
    check_channel_binding(
        &tags
            .iter()
            .filter_map(|tag| {
                tag.as_array().map(|tag| {
                    tag.iter()
                        .filter_map(|value| value.as_str().map(str::to_owned))
                        .collect::<Vec<_>>()
                })
            })
            .collect::<Vec<_>>(),
        channel_id,
        epoch,
    )?;
    let ms = match tag_values(tags, "ms").as_deref() {
        None => 0,
        Some([ms]) => decimal_u64(ms)
            .filter(|ms| *ms <= MS_MAX)
            .ok_or(PresenceError::Malformed("ms"))?,
        Some(_) => return Err(PresenceError::Malformed("ms")),
    };
    let verb = match content {
        "joined" => {
            let identity = match tag_values(tags, "identity").as_deref() {
                Some([identity]) => (*identity).to_owned(),
                _ => return Err(PresenceError::Malformed("identity")),
            };
            let broker = match tag_values(tags, "broker").as_deref() {
                Some([broker]) => (*broker).to_owned(),
                _ => return Err(PresenceError::Malformed("broker")),
            };
            PresenceVerb::Joined { identity, broker }
        }
        "left" => PresenceVerb::Left,
        _ => return Err(PresenceError::Malformed("content")),
    };
    Ok(Presence {
        author: seal_pubkey.to_owned(),
        time_ms: created_at.saturating_mul(1000).saturating_add(ms),
        verb,
    })
}

/// Whether a `joined` at `time_ms` (the presence basis, not wall time) is
/// stale at `now_ms`: older than three missed heartbeats (§4).
#[must_use]
pub fn is_stale(now_ms: u64, time_ms: u64) -> bool {
    now_ms.saturating_sub(time_ms) > PRESENCE_STALE_MS
}

/// Folds a set of presence heartbeats to the latest per author (CORD-02 §4:
/// greatest `time_ms` wins; a tie is vanishingly unlikely and left to
/// insertion order, since presence carries no id to break it by).
#[must_use]
pub fn latest_per_author(presences: &[Presence]) -> std::collections::BTreeMap<String, &Presence> {
    let mut latest: std::collections::BTreeMap<String, &Presence> = std::collections::BTreeMap::new();
    for presence in presences {
        match latest.get(&presence.author) {
            Some(current) if current.time_ms > presence.time_ms => {}
            _ => {
                latest.insert(presence.author.clone(), presence);
            }
        }
    }
    latest
}

/// How a call participant should render, from the identity-conflict rule
/// (§4): a fresh, uniquely-claimed identity is verified; a contested or
/// unclaimed one is not.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ParticipantView<'a> {
    Verified { identity: &'a str, author: &'a str },
    Unverified { identity: &'a str },
}

/// Renders live participants from the latest fresh presence per author (as
/// [`latest_per_author`] filtered by [`is_stale`]): an SFU identity claimed by
/// exactly one author's fresh, signed `joined` renders as that member;
/// claimed by more than one renders every claimant as unverified (§4, a
/// malicious member can copy a victim's identity into their own `joined`, so
/// a contest proves nothing about either author).
#[must_use]
pub fn render_participants<'a>(
    fresh_joined: impl IntoIterator<Item = (&'a str, &'a str)>,
) -> Vec<ParticipantView<'a>> {
    let mut by_identity: std::collections::BTreeMap<&'a str, Vec<&'a str>> =
        std::collections::BTreeMap::new();
    for (author, identity) in fresh_joined {
        by_identity.entry(identity).or_default().push(author);
    }
    by_identity
        .into_iter()
        .flat_map(|(identity, authors)| match authors.as_slice() {
            [author] => vec![ParticipantView::Verified { identity, author }],
            _ => authors
                .into_iter()
                .map(|_| ParticipantView::Unverified { identity })
                .collect(),
        })
        .collect()
}

/// Whether a broker-assigned SFU identity carries the minimum entropy §2
/// requires, judged the only way a pure check can: its encoded length. A
/// hex or base64 identity shorter than this cannot possibly carry 128 bits;
/// meeting the length is necessary, not sufficient (the broker must still
/// draw from a real RNG).
#[must_use]
pub fn identity_has_enough_entropy(identity: &str) -> bool {
    // Hex is the densest common encoding at 2 chars/byte; anything shorter
    // than that bound cannot reach `IDENTITY_MIN_ENTROPY_BYTES` of entropy.
    identity.len() >= IDENTITY_MIN_ENTROPY_BYTES * 2
}

/// A broker auth grant (kind 27235, §2), decoded enough to check without a
/// signature: the caller verifies `sig` separately (a pure crate does not do
/// cryptography), then calls [`check_broker_request`].
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BrokerRequest<'a> {
    pub pubkey: &'a str,
    pub created_at: u64,
    pub id: &'a str,
    /// The `u` tag: the exact request URL.
    pub url: &'a str,
    /// The `method` tag.
    pub method: &'a str,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum BrokerRequestError {
    /// `event.pubkey` is not the room this request names.
    WrongRoom,
    /// The `u` or `method` tag does not match this exact request.
    WrongTarget,
    /// `created_at` is outside the ±60s freshness window.
    Stale,
    /// This event id has already been used (anti-replay, §2).
    Replayed,
}

/// The non-cryptographic half of a broker's admission checks (§2): the
/// signature itself, and that the event actually verifies to `request.id`,
/// are the caller's job (real Schnorr verification lives in
/// `nscript-host-crypto`).
///
/// # Errors
///
/// Returns the first check the request fails.
pub fn check_broker_request(
    request: &BrokerRequest<'_>,
    room: &str,
    expected_url: &str,
    expected_method: &str,
    now: u64,
    seen_before: impl FnOnce(&str) -> bool,
) -> Result<(), BrokerRequestError> {
    if request.pubkey != room {
        return Err(BrokerRequestError::WrongRoom);
    }
    if request.url != expected_url || request.method != expected_method {
        return Err(BrokerRequestError::WrongTarget);
    }
    let age = now.abs_diff(request.created_at);
    if age > AUTH_FRESHNESS_SECS {
        return Err(BrokerRequestError::Stale);
    }
    if seen_before(request.id) {
        return Err(BrokerRequestError::Replayed);
    }
    Ok(())
}

/// RFC 6454 origin serialization for the rendezvous tie-break (§5): lowercase
/// scheme and host, default port omitted, no path or trailing slash. Returns
/// `None` for anything not a `http`/`https` URL with a host, since those are
/// the only broker origins the spec addresses.
#[must_use]
pub fn canonical_origin(url: &str) -> Option<String> {
    let (scheme, rest) = url.split_once("://")?;
    let scheme = scheme.to_ascii_lowercase();
    let default_port = match scheme.as_str() {
        "http" => 80,
        "https" => 443,
        _ => return None,
    };
    let authority = rest.split(['/', '?', '#']).next().unwrap_or(rest);
    if authority.is_empty() {
        return None;
    }
    let (host, port) = authority
        .rsplit_once(':')
        .filter(|(_, port)| port.bytes().all(|b| b.is_ascii_digit()) && !port.is_empty())
        .map_or((authority, default_port), |(host, port)| {
            (host, port.parse().unwrap_or(default_port))
        });
    if host.is_empty() {
        return None;
    }
    let host = host.to_ascii_lowercase();
    Some(if port == default_port {
        format!("{scheme}://{host}")
    } else {
        format!("{scheme}://{host}:{port}")
    })
}

/// The rendezvous tie-break (§5): among brokers with live presence, the
/// origin whose `sha256(voice_room[32] || utf8(origin))` sorts lowest wins.
/// `origin` MUST already be [`canonical_origin`]-formed, or two clients
/// hashing different spellings of one broker never converge.
#[must_use]
pub fn tie_break_origin<'a>(voice_room: &[u8; 32], origins: &[&'a str]) -> Option<&'a str> {
    origins.iter().copied().min_by_key(|origin| {
        use sha2::{Digest, Sha256};
        let mut hasher = Sha256::new();
        hasher.update(voice_room);
        hasher.update(origin.as_bytes());
        <[u8; 32]>::from(hasher.finalize())
    })
}

/// Chooses which broker to join (§5): the tie-broken winner among origins
/// with live presence, or `own_broker` when the room looks empty. Only a
/// hint from a fellow member, never an authorization (§5): a malicious
/// member can steer the call, but never decrypt it.
#[must_use]
pub fn choose_broker<'a>(
    voice_room: &[u8; 32],
    live_broker_origins: &[&'a str],
    own_broker: &'a str,
) -> &'a str {
    tie_break_origin(voice_room, live_broker_origins).unwrap_or(own_broker)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn joined_rumor(channel: &str, epoch: u64, ms: &str, identity: &str, broker: &str) -> String {
        serde_json::json!({
            "pubkey": "member",
            "kind": KIND_PRESENCE,
            "content": "joined",
            "created_at": 1_700_000_000_u64,
            "tags": [
                ["channel", channel], ["epoch", epoch.to_string()],
                ["identity", identity], ["broker", broker], ["ms", ms],
            ],
        })
        .to_string()
    }

    #[test]
    fn a_joined_rumor_binds_and_carries_identity_and_broker() {
        let rumor = joined_rumor("c1", 4, "417", "sfu-id", "https://broker.example");
        let presence = parse_presence_rumor("member", &rumor, "c1", 4).unwrap();
        assert_eq!(presence.author, "member");
        assert_eq!(presence.time_ms, 1_700_000_000_417);
        assert_eq!(
            presence.verb,
            PresenceVerb::Joined {
                identity: "sfu-id".to_owned(),
                broker: "https://broker.example".to_owned(),
            }
        );
    }

    #[test]
    fn wrong_channel_or_epoch_is_dropped_not_displayed() {
        let rumor = joined_rumor("c1", 4, "0", "id", "https://b");
        assert_eq!(
            parse_presence_rumor("member", &rumor, "c2", 4),
            Err(PresenceError::Binding(BindingError::Mismatch("channel")))
        );
        assert_eq!(
            parse_presence_rumor("member", &rumor, "c1", 5),
            Err(PresenceError::Binding(BindingError::Mismatch("epoch")))
        );
    }

    #[test]
    fn a_left_rumor_omits_identity_and_broker() {
        let rumor = serde_json::json!({
            "pubkey": "member", "kind": KIND_PRESENCE, "content": "left",
            "created_at": 1_700_000_100_u64,
            "tags": [["channel", "c1"], ["epoch", "4"]],
        })
        .to_string();
        let presence = parse_presence_rumor("member", &rumor, "c1", 4).unwrap();
        assert_eq!(presence.verb, PresenceVerb::Left);
    }

    #[test]
    fn an_impersonated_author_is_rejected() {
        let rumor = joined_rumor("c1", 4, "0", "id", "https://b");
        assert_eq!(
            parse_presence_rumor("mallory", &rumor, "c1", 4),
            Err(PresenceError::AuthorMismatch)
        );
    }

    #[test]
    fn staleness_is_three_missed_heartbeats() {
        let time_ms = 1_700_000_000_000;
        assert!(!is_stale(time_ms + PRESENCE_STALE_MS, time_ms));
        assert!(is_stale(time_ms + PRESENCE_STALE_MS + 1, time_ms));
    }

    #[test]
    fn latest_per_author_keeps_the_greatest_time() {
        let old = Presence {
            author: "a".to_owned(),
            time_ms: 1,
            verb: PresenceVerb::Left,
        };
        let new = Presence {
            author: "a".to_owned(),
            time_ms: 2,
            verb: PresenceVerb::Joined {
                identity: "x".to_owned(),
                broker: "b".to_owned(),
            },
        };
        let forward = [old.clone(), new.clone()];
        let latest = latest_per_author(&forward);
        assert_eq!(latest[&"a".to_owned()], &new);
        let reversed = [new, old];
        let latest = latest_per_author(&reversed);
        assert_eq!(latest[&"a".to_owned()].time_ms, 2);
    }

    #[test]
    fn an_uncontested_identity_renders_verified() {
        let views = render_participants([("alice", "sfu-1"), ("bob", "sfu-2")]);
        assert_eq!(
            views,
            vec![
                ParticipantView::Verified {
                    identity: "sfu-1",
                    author: "alice"
                },
                ParticipantView::Verified {
                    identity: "sfu-2",
                    author: "bob"
                },
            ]
        );
    }

    #[test]
    fn a_contested_identity_renders_every_claimant_unverified() {
        let views = render_participants([("alice", "sfu-1"), ("mallory", "sfu-1")]);
        assert_eq!(
            views,
            vec![
                ParticipantView::Unverified { identity: "sfu-1" },
                ParticipantView::Unverified { identity: "sfu-1" },
            ]
        );
    }

    #[test]
    fn identity_entropy_floor_is_length_based() {
        assert!(identity_has_enough_entropy(&"a".repeat(32)));
        assert!(!identity_has_enough_entropy(&"a".repeat(31)));
    }

    fn request<'a>(pubkey: &'a str, url: &'a str, created_at: u64, id: &'a str) -> BrokerRequest<'a> {
        BrokerRequest {
            pubkey,
            created_at,
            id,
            url,
            method: "GET",
        }
    }

    #[test]
    fn a_broker_request_must_match_room_target_freshness_and_be_unseen() {
        let room = "room1";
        let url = "https://broker.example/.well-known/concord/av/room1";
        let now = 1_700_000_000;
        let good = request(room, url, now, "id1");
        assert_eq!(
            check_broker_request(&good, room, url, "GET", now, |_| false),
            Ok(())
        );
        assert_eq!(
            check_broker_request(&request("other", url, now, "id2"), room, url, "GET", now, |_| false),
            Err(BrokerRequestError::WrongRoom)
        );
        assert_eq!(
            check_broker_request(
                &request(room, "https://broker.example/wrong", now, "id3"),
                room,
                url,
                "GET",
                now,
                |_| false
            ),
            Err(BrokerRequestError::WrongTarget)
        );
        assert_eq!(
            check_broker_request(
                &request(room, url, now - AUTH_FRESHNESS_SECS - 1, "id4"),
                room,
                url,
                "GET",
                now,
                |_| false
            ),
            Err(BrokerRequestError::Stale)
        );
        assert_eq!(
            check_broker_request(&good, room, url, "GET", now, |id| id == "id1"),
            Err(BrokerRequestError::Replayed)
        );
    }

    #[test]
    fn origin_canonicalization_drops_default_ports_and_lowercases() {
        assert_eq!(
            canonical_origin("HTTPS://Broker.Example:443/foo/bar"),
            Some("https://broker.example".to_owned())
        );
        assert_eq!(
            canonical_origin("http://broker.example:8080/"),
            Some("http://broker.example:8080".to_owned())
        );
        assert_eq!(canonical_origin("not-a-url"), None);
        assert_eq!(canonical_origin("ftp://broker.example"), None);
    }

    #[test]
    fn tie_break_is_deterministic_and_symmetric_across_clients() {
        let room = [7_u8; 32];
        let a = "https://a.example";
        let b = "https://b.example";
        let winner = tie_break_origin(&room, &[a, b]);
        // Whichever wins, every client computing the same hash agrees, and
        // the order the candidates are given in never matters.
        assert_eq!(winner, tie_break_origin(&room, &[b, a]));
        assert!(winner == Some(a) || winner == Some(b));
    }

    #[test]
    fn choose_broker_prefers_the_live_winner_and_falls_back_when_empty() {
        let room = [1_u8; 32];
        let own = "https://mine.example";
        assert_eq!(choose_broker(&room, &[], own), own);
        let winner = tie_break_origin(&room, &["https://a.example", "https://b.example"]).unwrap();
        assert_eq!(
            choose_broker(&room, &["https://a.example", "https://b.example"], own),
            winner
        );
    }
}
