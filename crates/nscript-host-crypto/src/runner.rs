//! Real relay I/O and community loading for a controlled Concord bot runner.
//!
//! This module lifts the relay plumbing and community-loading logic that
//! used to live only in `examples/common/mod.rs` and
//! `examples/concord_interop.rs` into the library, as `Result`-returning
//! functions rather than `.expect(...)`-panicking ones, so a host binary
//! (such as `nscript-cli`'s `concord-run` subcommand) can use them without
//! linking an example.
//!
//! Gated behind the `real-hosts` feature, which is on by default and pulls
//! in `tungstenite`/`rustls` for a real WebSocket relay connection.

use std::net::TcpStream;
use std::time::{Duration, Instant};

use serde_json::{Value, json};
use tungstenite::{Message, WebSocket, stream::MaybeTlsStream};

use crate::group_key::{GroupKey, group_key};
use crate::nip44;
use crate::stream::{SealForm, open_stream_event};
use nscript_runtime::authority::AuthorityFold;
use nscript_runtime::community::{parse_channel_metadata, parse_community_metadata};
use nscript_runtime::edition::{FoldMode, VSK_CHANNEL_METADATA, VSK_COMMUNITY_METADATA};
use nscript_runtime::invite::{CommunityInvite, bundle_key, decode_fragment, parse_invite};
use nscript_runtime::wire::parse_edition_rumor;

/// tungstenite's `rustls` feature selects no crypto provider by default;
/// this installs `ring` as the default one. Idempotent: call it once before
/// the first [`connect`].
pub fn init_tls() {
    let _ = rustls::crypto::ring::default_provider().install_default();
}

fn set_timeout(socket: &mut WebSocket<MaybeTlsStream<TcpStream>>, timeout: Duration) {
    match socket.get_mut() {
        MaybeTlsStream::Plain(stream) => {
            let _ = stream.set_read_timeout(Some(timeout));
        }
        MaybeTlsStream::Rustls(stream) => {
            let _ = stream.get_mut().set_read_timeout(Some(timeout));
        }
        _ => {}
    }
}

/// Opens a WebSocket connection to a relay URL (e.g. `wss://relay.example`).
///
/// # Errors
///
/// Returns an error string if the connection cannot be established.
pub fn connect(relay: &str) -> Result<WebSocket<MaybeTlsStream<TcpStream>>, String> {
    let (mut socket, _) = tungstenite::connect(relay).map_err(|e| format!("connect: {e}"))?;
    set_timeout(&mut socket, Duration::from_secs(5));
    Ok(socket)
}

/// Runs one Nostr `REQ` and returns every `EVENT` received before `EOSE`.
///
/// # Errors
///
/// Returns an error string if the connection fails, the relay closes the
/// query, or no `EOSE` arrives before the internal timeout.
pub fn query(relay: &str, filter: &Value) -> Result<Vec<Value>, String> {
    let mut socket = connect(relay)?;
    socket
        .send(Message::text(json!(["REQ", "q", filter]).to_string()))
        .map_err(|e| format!("send: {e}"))?;
    let deadline = Instant::now() + Duration::from_secs(15);
    let mut events = Vec::new();
    while Instant::now() < deadline {
        let message = socket
            .read()
            .map_err(|error| format!("read before EOSE: {error}"))?;
        let Message::Text(text) = message else {
            continue;
        };
        let Ok(Value::Array(frame)) = serde_json::from_str::<Value>(&text) else {
            continue;
        };
        match frame.first().and_then(Value::as_str) {
            Some("EVENT") => events.extend(frame.get(2).cloned()),
            Some("EOSE") => {
                let _ = socket.close(None);
                return Ok(events);
            }
            Some("CLOSED") => {
                return Err(format!("relay closed query: {frame:?}"));
            }
            _ => {}
        }
    }
    let _ = socket.close(None);
    Err("query timed out before EOSE".to_owned())
}

/// Publishes one event, returning the relay's `OK` verdict and message.
///
/// # Errors
///
/// Returns an error string if the connection fails or no `OK` arrives
/// before the internal timeout.
pub fn publish(relay: &str, event: &Value) -> Result<(bool, String), String> {
    let mut socket = connect(relay)?;
    socket
        .send(Message::text(json!(["EVENT", event]).to_string()))
        .map_err(|e| format!("send: {e}"))?;
    let deadline = Instant::now() + Duration::from_secs(10);
    while Instant::now() < deadline {
        let Ok(Message::Text(text)) = socket.read() else {
            break;
        };
        if let Ok(Value::Array(frame)) = serde_json::from_str::<Value>(&text)
            && frame.first().and_then(Value::as_str) == Some("OK")
        {
            let accepted = frame.get(2).and_then(Value::as_bool).unwrap_or(false);
            let message = frame
                .get(3)
                .and_then(Value::as_str)
                .unwrap_or("")
                .to_owned();
            let _ = socket.close(None);
            return Ok((accepted, message));
        }
    }
    Err("no OK from relay".to_owned())
}

/// Lower-case hex encoding. Never use this on secret key material.
#[must_use]
pub fn hex(bytes: &[u8]) -> String {
    use std::fmt::Write as _;
    bytes.iter().fold(String::new(), |mut out, b| {
        let _ = write!(out, "{b:02x}");
        out
    })
}

/// Decodes 64 hex characters into 32 bytes.
///
/// # Panics
///
/// Panics if `text` is not valid 32-byte hex. Callers that read
/// operator-supplied identifiers (event ids, pubkeys, channel ids) should
/// validate the input's shape before calling this.
#[must_use]
pub fn unhex32(text: &str) -> [u8; 32] {
    let bytes: Vec<u8> = (0..text.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&text[i..i + 2], 16).expect("hex"))
        .collect();
    bytes.try_into().expect("32 bytes")
}

/// A community loaded and verified from an invite fragment: the invite
/// itself, the folded Control Plane authority, and the community's message
/// expiration timer, if one is set.
pub struct LoadedCommunity {
    pub invite: CommunityInvite,
    pub authority: AuthorityFold,
    pub timer: Option<u64>,
}

/// Fetches the invite bundle, decrypts it, and folds the community's
/// Control Plane into a verified [`AuthorityFold`].
///
/// `signer_hex` is the community's link-signer public key (hex,
/// x-only), as printed by the invite link. `fragment` is the invite
/// link's fragment (after `#`), which carries the bundle token and the
/// relays to query. `relays` are additional operator-supplied relays to
/// also query for the bundle event, alongside the fragment's own relays
/// (requirement: relay configuration is an explicit input to the bot
/// runner, even though the invite fragment already names its own relay
/// set).
///
/// # Errors
///
/// Returns an error string if the fragment cannot be decoded, no relay
/// answers with the bundle event, the bundle does not decrypt, or the
/// decrypted bundle does not parse as a valid invite.
pub fn load_community(
    signer_hex: &str,
    fragment: &str,
    relays: &[String],
) -> Result<LoadedCommunity, String> {
    let fragment = decode_fragment(fragment).map_err(|error| format!("fragment: {error:?}"))?;
    let candidate_relays: Vec<&String> = fragment.relays.iter().chain(relays.iter()).collect();
    let bundle = candidate_relays
        .iter()
        .find_map(|relay| {
            query(
                relay,
                &json!({"kinds": [33301], "authors": [signer_hex], "#d": [""]}),
            )
            .ok()?
            .into_iter()
            .next()
        })
        .ok_or_else(|| "no relay returned the invite bundle".to_owned())?;
    let content = bundle["content"]
        .as_str()
        .ok_or_else(|| "bundle event has no content".to_owned())?;
    let plaintext = nip44::decrypt(&bundle_key(&fragment.token), content)
        .map_err(|error| format!("bundle does not decrypt: {error:?}"))?;
    let text =
        String::from_utf8(plaintext).map_err(|error| format!("bundle is not utf-8: {error}"))?;
    let invite =
        parse_invite(&text).map_err(|error| format!("bundle does not validate: {error:?}"))?;
    let root = unhex32(invite.community_root());
    let cid = unhex32(&invite.community_id);
    let control_pk = invite
        .control_pk
        .as_ref()
        .ok_or_else(|| "invite is not for a split community (no control_pk)".to_owned())?;
    let control_pk = unhex32(control_pk);
    let read = group_key("concord/control", &root, &cid, Some(invite.root_epoch));

    let mut wraps = Vec::new();
    for relay in invite.relays.iter().chain(relays.iter()) {
        if let Ok(found) = query(
            relay,
            &json!({"kinds": [1059], "authors": [hex(&control_pk)]}),
        ) {
            wraps.extend(found);
        }
    }
    let mut authority = AuthorityFold::new(
        &invite.owner,
        &invite.owner_salt,
        &invite.community_id,
        FoldMode::FreshJoiner,
        4096,
    )
    .ok_or_else(|| "owner does not verify".to_owned())?;
    let mut seen = std::collections::BTreeSet::new();
    for wrap in wraps {
        if !seen.insert(wrap["id"].as_str().unwrap_or("").to_owned()) {
            continue;
        }
        if let Ok(event) = open_stream_event(
            &control_pk,
            &read.conversation_key(),
            SealForm::Plaintext,
            &wrap.to_string(),
        ) && let Ok(edition) = parse_edition_rumor(&event.author, &event.rumor_json)
        {
            authority.insert(edition);
        }
    }
    let timer = authority
        .heads(VSK_COMMUNITY_METADATA)
        .iter()
        .find_map(|head| parse_community_metadata(&head.content))
        .and_then(|meta| meta.message_expiration);
    Ok(LoadedCommunity {
        invite,
        authority,
        timer,
    })
}

/// Resolves a public, non-deleted channel's id by name from the loaded
/// community's Control Plane.
///
/// # Errors
///
/// Returns an error string if no such channel exists.
pub fn public_channel(loaded: &LoadedCommunity, name: &str) -> Result<String, String> {
    loaded
        .authority
        .heads(VSK_CHANNEL_METADATA)
        .iter()
        .find_map(|head| {
            let (channel, deleted) = parse_channel_metadata(&head.entity_id, &head.content)?;
            (channel.name == name && !channel.private && !deleted).then_some(channel.channel_id)
        })
        .ok_or_else(|| format!("no public channel named {name:?}"))
}

/// Derives a Public Channel's symmetric key from the community root
/// (CORD-03 §1).
#[must_use]
pub fn channel_key(loaded: &LoadedCommunity, channel_id: &str) -> GroupKey {
    group_key(
        "concord/channel",
        &unhex32(loaded.invite.community_root()),
        &unhex32(channel_id),
        Some(loaded.invite.root_epoch),
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use nscript_runtime::authority::community_id;
    use nscript_runtime::edition::VSK_CHANNEL_METADATA;
    use nscript_runtime::wire::build_edition;

    const OWNER: &str = "0101010101010101010101010101010101010101010101010101010101010101";
    const SALT: &str = "0202020202020202020202020202020202020202020202020202020202020202";
    const ROOT: &str = "0909090909090909090909090909090909090909090909090909090909090909";
    const CHANNEL: &str = "cc00000000000000000000000000000000000000000000000000000000000003";

    /// Builds a [`LoadedCommunity`] straight from fixture data, without a
    /// relay: exercises [`public_channel`] and [`channel_key`], the parts of
    /// this module that hold no relay I/O of their own. [`load_community`]
    /// itself needs a live relay and is exercised only by the
    /// `concord_interop` example and, indirectly, `nscript-cli`'s
    /// `concord-run` subcommand, per this milestone's scope.
    fn fixture_community(channel_private: bool, channel_deleted: bool) -> LoadedCommunity {
        let cid = community_id(OWNER, SALT).unwrap();
        let bundle = serde_json::json!({
            "community_id": cid,
            "owner": OWNER, "owner_salt": SALT,
            "community_root": ROOT, "root_epoch": 3,
            "control_pk": "0303030303030303030303030303030303030303030303030303030303030303",
            "channels": [],
            "relays": ["wss://a"],
            "name": "Fixture",
        })
        .to_string();
        let invite = parse_invite(&bundle).expect("fixture invite validates");

        let mut authority = AuthorityFold::new(OWNER, SALT, &cid, FoldMode::FreshJoiner, 64)
            .expect("owner verifies");
        let content = serde_json::json!({
            "name": "general",
            "private": channel_private,
            "deleted": channel_deleted,
        })
        .to_string();
        let (edition, _) = build_edition(
            VSK_CHANNEL_METADATA,
            CHANNEL,
            None,
            &content,
            OWNER,
            None,
            0,
        )
        .expect("edition builds");
        assert!(authority.insert(edition));

        LoadedCommunity {
            invite,
            authority,
            timer: None,
        }
    }

    #[test]
    fn hex_and_unhex32_round_trip() {
        let bytes = [7_u8; 32];
        assert_eq!(unhex32(&hex(&bytes)), bytes);
    }

    #[test]
    fn public_channel_resolves_a_public_undeleted_channel_by_name() {
        let loaded = fixture_community(false, false);
        assert_eq!(public_channel(&loaded, "general").unwrap(), CHANNEL);
        assert!(public_channel(&loaded, "nope").is_err());
    }

    #[test]
    fn public_channel_refuses_private_or_deleted_channels() {
        assert!(public_channel(&fixture_community(true, false), "general").is_err());
        assert!(public_channel(&fixture_community(false, true), "general").is_err());
    }

    #[test]
    fn channel_key_derives_from_the_community_root_and_epoch() {
        let loaded = fixture_community(false, false);
        let key = channel_key(&loaded, CHANNEL);
        let expected = group_key(
            "concord/channel",
            &unhex32(ROOT),
            &unhex32(CHANNEL),
            Some(3),
        );
        assert_eq!(key.secret_bytes(), expected.secret_bytes());
    }
}
