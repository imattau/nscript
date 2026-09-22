//! CORD-07 Audio/Video: real key derivation, the broker auth grant (kind
//! 27235), and voice presence (kind 23313), sealed and wrapped like any other
//! Chat-plane rumor but under the ephemeral wrap (CORD-01 §1.3).
//!
//! The pure rules — staleness, the identity-conflict rule, the rendezvous
//! tie-break, and a broker request's non-cryptographic checks — live in
//! [`nscript_runtime::voice`]; this module supplies the real cryptography
//! they need (signing, sealing) and is what an actual broker or client links
//! against. The SFU connection and media pipeline themselves are host/service
//! integration, outside this crate (`docs/CONCORD.md` §9).

use base64::{Engine as _, engine::general_purpose::STANDARD};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};

use nscript_runtime::voice::{
    BrokerRequest, BrokerRequestError, KIND_BROKER_AUTH, KIND_PRESENCE, PresenceError,
    check_broker_request, parse_presence_rumor,
};

use crate::group_key::{CryptoError, GroupKey, coordinate, group_key, hex};
use crate::stream::{
    SealForm, StreamError, build_ephemeral_stream_event_with_tags, open_ephemeral_stream_event,
    rumor, signed_event, verify_event,
};

/// `voice_key = group_key("concord/voice-signer", channel_secret, channel_id,
/// epoch)` (§1): the SFU room's signing keypair. `voice_key.pk` is the room
/// name; `voice_key.sk` signs broker token grants (§2).
///
/// `(channel_secret, epoch)` is `(community_root, root_epoch)` for a Public
/// Channel or `(channel_key, channel_epoch)` for a Private one, exactly as
/// the Chat plane (CORD-03 §1): both ride the Channel's epoch, so a Rekey or
/// Refounding (CORD-06) rolls the room name along with everything else.
#[must_use]
pub fn voice_key(channel_secret: &[u8; 32], channel_id: &[u8; 32], epoch: u64) -> GroupKey {
    group_key("concord/voice-signer", channel_secret, channel_id, Some(epoch))
}

/// `voice_media_key = hkdf(channel_secret, "concord/voice-media", channel_id,
/// epoch)` (§1): the raw 32-byte root of media encryption. A plain
/// coordinate, not a `group_key` — this key never becomes a signing pair.
#[must_use]
pub fn voice_media_key(channel_secret: &[u8; 32], channel_id: &[u8; 32], epoch: u64) -> [u8; 32] {
    coordinate(channel_secret, "concord/voice-media", channel_id, Some(epoch))
}

/// `sender_key = hkdf(voice_media_key, "concord/voice-sender",
/// sha256(identity))` (§3): a publisher's per-sender frame key. No epoch
/// field — `voice_media_key` already carries it.
#[must_use]
pub fn sender_key(voice_media_key: &[u8; 32], identity: &str) -> [u8; 32] {
    let id_hash: [u8; 32] = Sha256::digest(identity.as_bytes()).into();
    coordinate(voice_media_key, "concord/voice-sender", &id_hash, None)
}

/// Builds a broker token request (kind 27235, §2), signed with
/// `voice_key_secret` so `event.pubkey` equals the room name. The caller
/// base64-encodes the result into the `Authorization: Concord <...>` header;
/// it never touches a relay.
///
/// # Errors
///
/// Returns [`StreamError`] for an invalid key.
pub fn build_broker_auth(
    voice_key_secret: &[u8; 32],
    url: &str,
    created_at: u64,
) -> Result<String, StreamError> {
    let tags = json!([["u", url], ["method", "GET"]]);
    let event = signed_event(voice_key_secret, KIND_BROKER_AUTH, &tags, "", created_at)?;
    Ok(event.to_string())
}

#[derive(Debug, Eq, PartialEq)]
pub enum AuthError {
    Stream(StreamError),
    NotJson,
    WrongKind,
    Request(BrokerRequestError),
}

impl From<StreamError> for AuthError {
    fn from(error: StreamError) -> Self {
        Self::Stream(error)
    }
}

/// Verifies a broker token request end to end (§2): the event's own
/// signature and id, that it really is a kind-27235 grant, and (via
/// [`check_broker_request`]) that it targets this exact room and request, is
/// fresh, and is unseen. What a broker runs on every incoming request.
///
/// # Errors
///
/// Returns [`AuthError`] describing the first failed check.
pub fn verify_broker_auth(
    event_json: &str,
    room: &str,
    expected_url: &str,
    now: u64,
    seen_before: impl FnOnce(&str) -> bool,
) -> Result<(), AuthError> {
    let event: Value = serde_json::from_str(event_json).map_err(|_| AuthError::NotJson)?;
    verify_event(&event)?;
    if event.get("kind").and_then(Value::as_u64) != Some(KIND_BROKER_AUTH) {
        return Err(AuthError::WrongKind);
    }
    let field = |name: &str| event.get(name).and_then(Value::as_str).ok_or(AuthError::NotJson);
    let pubkey = field("pubkey")?;
    let id = field("id")?;
    let created_at = event
        .get("created_at")
        .and_then(Value::as_u64)
        .ok_or(AuthError::NotJson)?;
    let tags = event
        .get("tags")
        .and_then(Value::as_array)
        .ok_or(AuthError::NotJson)?;
    let find_tag = |name: &str| -> Option<&str> {
        tags.iter().find_map(|tag| {
            let tag = tag.as_array()?;
            (tag.first()?.as_str()? == name)
                .then(|| tag.get(1)?.as_str())
                .flatten()
        })
    };
    let url = find_tag("u").ok_or(AuthError::NotJson)?;
    let method = find_tag("method").ok_or(AuthError::NotJson)?;
    check_broker_request(
        &BrokerRequest {
            pubkey,
            created_at,
            id,
            url,
            method,
        },
        room,
        expected_url,
        "GET",
        now,
        seen_before,
    )
    .map_err(AuthError::Request)
}

/// The header value a client sends: `Concord <base64(event)>` (§2), split so
/// the caller adds the header name itself.
#[must_use]
pub fn authorization_header_value(event_json: &str) -> String {
    format!("Concord {}", STANDARD.encode(event_json.as_bytes()))
}

/// Decodes the `Authorization: Concord <base64>` header's payload back to the
/// event JSON a broker verifies with [`verify_broker_auth`].
///
/// # Errors
///
/// Returns `None` for a header that is not `Concord <base64>` or whose
/// payload is not valid UTF-8.
#[must_use]
pub fn decode_authorization_header(header: &str) -> Option<String> {
    let encoded = header.strip_prefix("Concord ")?;
    let bytes = STANDARD.decode(encoded).ok()?;
    String::from_utf8(bytes).ok()
}

/// Builds a presence heartbeat (kind 23313, §4) at the Channel's own Chat
/// address, sealed and wrapped exactly like a chat message (CORD-02 §5) but
/// under the ephemeral wrap, so relays never store it.
///
/// `read_key`/`wrap_signer` are the Channel's Chat-plane keys (CORD-03 §1);
/// `identity_and_broker` is `Some((identity, broker_origin))` for a `joined`
/// heartbeat, `None` for a best-effort `left`.
///
/// # Errors
///
/// Returns [`StreamError`] for invalid keys.
#[allow(clippy::too_many_arguments)]
pub fn build_presence(
    wrap_signer: &[u8; 32],
    read_key: &[u8; 32],
    author_secret: &[u8; 32],
    channel_id: &str,
    epoch: u64,
    identity_and_broker: Option<(&str, &str)>,
    ms: u64,
    created_at: u64,
) -> Result<String, StreamError> {
    let mut tags = vec![
        json!(["channel", channel_id]),
        json!(["epoch", epoch.to_string()]),
    ];
    let content = match identity_and_broker {
        Some((identity, broker)) => {
            tags.push(json!(["identity", identity]));
            tags.push(json!(["broker", broker]));
            "joined"
        }
        None => "left",
    };
    tags.push(json!(["ms", ms.to_string()]));
    let rumor = rumor(
        author_secret,
        KIND_PRESENCE,
        &Value::Array(tags),
        content,
        created_at,
    )?;
    build_ephemeral_stream_event_with_tags(
        wrap_signer,
        read_key,
        SealForm::Encrypted,
        author_secret,
        &rumor,
        &[],
        created_at,
    )
}

#[derive(Debug, Eq, PartialEq)]
pub enum OpenPresenceError {
    Stream(StreamError),
    Presence(PresenceError),
}

impl From<StreamError> for OpenPresenceError {
    fn from(error: StreamError) -> Self {
        Self::Stream(error)
    }
}

impl From<PresenceError> for OpenPresenceError {
    fn from(error: PresenceError) -> Self {
        Self::Presence(error)
    }
}

/// Opens a presence wrap end to end: stream signature, decryption, seal
/// signature, and the CORD-03 §3 binding check, returning the decoded
/// [`nscript_runtime::voice::Presence`].
///
/// # Errors
///
/// Returns [`OpenPresenceError`] describing the first failed check.
pub fn open_presence(
    stream_pubkey: &[u8; 32],
    read_key: &[u8; 32],
    channel_id: &str,
    epoch: u64,
    wrap_json: &str,
) -> Result<nscript_runtime::voice::Presence, OpenPresenceError> {
    let opened = open_ephemeral_stream_event(stream_pubkey, read_key, SealForm::Encrypted, wrap_json)?;
    Ok(parse_presence_rumor(
        &opened.author,
        &opened.rumor_json,
        channel_id,
        epoch,
    )?)
}

/// Fresh 128+ bits of entropy for a broker-assigned SFU identity (§2), as
/// lowercase hex — meeting
/// [`nscript_runtime::voice::identity_has_enough_entropy`] by construction.
///
/// # Errors
///
/// Returns [`CryptoError::RandomUnavailable`] if the OS RNG fails.
pub fn random_identity() -> Result<String, CryptoError> {
    Ok(hex(&crate::random32()?))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::group_key::xonly_pubkey;
    use nscript_runtime::voice::PresenceVerb;

    const CHANNEL_SECRET: [u8; 32] = [3; 32];
    const CHANNEL_ID: [u8; 32] = [9; 32];
    const AUTHOR: [u8; 32] = [5; 32];

    fn channel_id_hex() -> String {
        hex(&CHANNEL_ID)
    }

    #[test]
    fn voice_and_media_keys_are_deterministic_and_distinct() {
        let key_a = voice_key(&CHANNEL_SECRET, &CHANNEL_ID, 1);
        let key_b = voice_key(&CHANNEL_SECRET, &CHANNEL_ID, 1);
        assert_eq!(key_a.xonly_pubkey(), key_b.xonly_pubkey());
        let media = voice_media_key(&CHANNEL_SECRET, &CHANNEL_ID, 1);
        assert_eq!(media, voice_media_key(&CHANNEL_SECRET, &CHANNEL_ID, 1));
        assert_ne!(media.to_vec(), key_a.secret_bytes().to_vec());
    }

    #[test]
    fn rotation_rolls_the_room_and_the_media_key() {
        let key1 = voice_key(&CHANNEL_SECRET, &CHANNEL_ID, 1);
        let key2 = voice_key(&CHANNEL_SECRET, &CHANNEL_ID, 2);
        assert_ne!(key1.xonly_pubkey(), key2.xonly_pubkey());
        assert_ne!(
            voice_media_key(&CHANNEL_SECRET, &CHANNEL_ID, 1),
            voice_media_key(&CHANNEL_SECRET, &CHANNEL_ID, 2)
        );
    }

    #[test]
    fn distinct_senders_never_share_a_frame_key() {
        let media = voice_media_key(&CHANNEL_SECRET, &CHANNEL_ID, 1);
        let alice = sender_key(&media, "alice-identity");
        let bob = sender_key(&media, "bob-identity");
        assert_ne!(alice, bob);
        assert_eq!(alice, sender_key(&media, "alice-identity"));
    }

    #[test]
    fn a_broker_auth_grant_round_trips_and_is_scoped_to_its_request() {
        let key = voice_key(&CHANNEL_SECRET, &CHANNEL_ID, 1);
        let secret = key.secret_bytes();
        let room = hex(&key.xonly_pubkey());
        let url = format!("https://broker.example/.well-known/concord/av/{room}");
        let event = build_broker_auth(&secret, &url, 1_700_000_000).unwrap();
        assert!(verify_broker_auth(&event, &room, &url, 1_700_000_000, |_| false).is_ok());
        // The wrong room, a different request, and a stale or replayed grant
        // are all refused.
        assert_eq!(
            verify_broker_auth(&event, "not-the-room", &url, 1_700_000_000, |_| false),
            Err(AuthError::Request(BrokerRequestError::WrongRoom))
        );
        assert_eq!(
            verify_broker_auth(
                &event,
                &room,
                "https://broker.example/other",
                1_700_000_000,
                |_| false
            ),
            Err(AuthError::Request(BrokerRequestError::WrongTarget))
        );
        assert_eq!(
            verify_broker_auth(&event, &room, &url, 1_700_000_100, |_| false),
            Err(AuthError::Request(BrokerRequestError::Stale))
        );
        assert_eq!(
            verify_broker_auth(&event, &room, &url, 1_700_000_000, |_| true),
            Err(AuthError::Request(BrokerRequestError::Replayed))
        );
    }

    #[test]
    fn a_forged_broker_auth_grant_fails_verification() {
        let key = voice_key(&CHANNEL_SECRET, &CHANNEL_ID, 1);
        let room = hex(&key.xonly_pubkey());
        let url = format!("https://broker.example/.well-known/concord/av/{room}");
        // Signed by a different key entirely: never proves possession of
        // this room's channel key.
        let forged = build_broker_auth(&[9; 32], &url, 1_700_000_000).unwrap();
        assert_eq!(
            verify_broker_auth(&forged, &room, &url, 1_700_000_000, |_| false),
            Err(AuthError::Request(BrokerRequestError::WrongRoom))
        );
    }

    #[test]
    fn the_authorization_header_round_trips() {
        let event = r#"{"kind":27235}"#;
        let header = authorization_header_value(event);
        assert!(header.starts_with("Concord "));
        assert_eq!(decode_authorization_header(&header).as_deref(), Some(event));
        assert_eq!(decode_authorization_header("Bearer xyz"), None);
    }

    #[test]
    fn a_presence_heartbeat_round_trips_through_the_ephemeral_wrap() {
        let wrap_signer = [4_u8; 32]; // the Chat plane's key, per CORD-03 §1.
        let read_key = [6_u8; 32];
        let channel_id = channel_id_hex();
        let wire = build_presence(
            &wrap_signer,
            &read_key,
            &AUTHOR,
            &channel_id,
            2,
            Some(("sfu-identity", "https://broker.example")),
            417,
            1_700_000_000,
        )
        .unwrap();
        let stream_pubkey = xonly_pubkey(&wrap_signer).unwrap();
        let presence = open_presence(&stream_pubkey, &read_key, &channel_id, 2, &wire).unwrap();
        assert_eq!(presence.author, hex(&xonly_pubkey(&AUTHOR).unwrap()));
        assert_eq!(presence.time_ms, 1_700_000_000_417);
        assert_eq!(
            presence.verb,
            PresenceVerb::Joined {
                identity: "sfu-identity".to_owned(),
                broker: "https://broker.example".to_owned(),
            }
        );

        // A relay-visible wrap is a real Nostr event: it must actually carry
        // the ephemeral wrap kind, not the persistent one messages use.
        let wire_value: Value = serde_json::from_str(&wire).unwrap();
        assert_eq!(
            wire_value.get("kind").and_then(Value::as_u64),
            Some(21_059)
        );
    }

    #[test]
    fn a_left_heartbeat_omits_identity_and_broker() {
        let wrap_signer = [4_u8; 32];
        let read_key = [6_u8; 32];
        let channel_id = channel_id_hex();
        let wire = build_presence(
            &wrap_signer,
            &read_key,
            &AUTHOR,
            &channel_id,
            2,
            None,
            0,
            1_700_000_100,
        )
        .unwrap();
        let stream_pubkey = xonly_pubkey(&wrap_signer).unwrap();
        let presence = open_presence(&stream_pubkey, &read_key, &channel_id, 2, &wire).unwrap();
        assert_eq!(presence.verb, PresenceVerb::Left);
    }

    #[test]
    fn presence_at_the_wrong_channel_or_epoch_is_refused() {
        let wrap_signer = [4_u8; 32];
        let read_key = [6_u8; 32];
        let channel_id = channel_id_hex();
        let wire = build_presence(
            &wrap_signer,
            &read_key,
            &AUTHOR,
            &channel_id,
            2,
            None,
            0,
            1_700_000_100,
        )
        .unwrap();
        let stream_pubkey = xonly_pubkey(&wrap_signer).unwrap();
        assert!(matches!(
            open_presence(&stream_pubkey, &read_key, &channel_id, 3, &wire),
            Err(OpenPresenceError::Presence(_))
        ));
    }

    #[test]
    fn random_identities_are_unique_and_meet_the_entropy_floor() {
        let a = random_identity().unwrap();
        let b = random_identity().unwrap();
        assert_ne!(a, b);
        assert!(nscript_runtime::voice::identity_has_enough_entropy(&a));
    }

}
