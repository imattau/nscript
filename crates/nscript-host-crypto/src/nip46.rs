//! NIP-46: a real remote-signer ("bunker") client, built on
//! [`nscript_runtime::RealRelayHost`] (the real websocket relay client) and
//! this crate's own NIP-44 encryption and Schnorr signing. This is what
//! [`nscript_runtime::Nip46SignerHost`] delegates to when a script's
//! `signer account = nip46()` should really talk to a remote signer — which
//! may be a browser extension (e.g. nsec.app) running in bunker mode, a
//! phone app, or any other NIP-46-compliant service.
//!
//! Scoped to the common case, honestly:
//!
//! - Only the `bunker://<remote-signer-pubkey>?relay=...&secret=...` URI —
//!   the flow where the caller already has a connection string. The reverse
//!   `nostrconnect://` flow (the *client* mints the URI and the signer, e.g.
//!   a browser extension the user scans/pastes it into, replies to it) is
//!   not implemented.
//! - Only `connect` and `sign_event`, the two methods
//!   [`nscript_runtime::Nip46Transport`] needs. `get_public_key` is called
//!   once during `connect` because the spec requires it ("a client MUST
//!   NOT assume `user-pubkey` equals `remote-signer-pubkey`"), but is not
//!   exposed as its own operation. `ping`, `nip04_encrypt`/`decrypt`,
//!   `nip44_encrypt`/`decrypt`, `switch_relays`, `logout`, and the
//!   `auth_url` challenge flow are not implemented.
//! - Only the first relay in the URI's list that actually connects. NIP-46
//!   recommends using every listed relay for redundancy; this does not.
//! - Discovery (a remote signer's NIP-05 `nip46` block or its NIP-89
//!   `kind:31990` advertisement) is not implemented — a `bunker://` URI is
//!   the only way in.

use std::time::{Duration, Instant};

use serde_json::{Value, json};

use nscript_runtime::{
    Nip46Transport, RealRelayHost, RelayHost, RuntimeError, SignedEvent, SignerSession,
    SubscriptionHost, SubscriptionRequest, UnsignedEvent,
};

use crate::group_key::{hex, xonly_pubkey};
use crate::nip44;
use crate::stream::{signed_event, verify_event};

/// Both the request and the response ride this one kind (NIP-46 §"Kind
/// 24133").
pub const KIND_NIP46: u64 = 24_133;

/// How long, in total, [`RealNip46Transport`] waits for one reply before
/// giving up. Each read within that budget is itself bounded by the relay
/// socket's own read timeout (ten seconds by default).
const REPLY_BUDGET: Duration = Duration::from_secs(30);

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

fn denied(provider: &str, reason: impl std::fmt::Display) -> RuntimeError {
    RuntimeError::SignerDenied {
        signer: format!("{provider}: {reason}"),
    }
}

fn now_unix() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |elapsed| elapsed.as_secs())
}

/// A parsed `bunker://<remote-signer-pubkey>?relay=...&secret=...` URI.
struct BunkerUri {
    remote_signer_pubkey: [u8; 32],
    relays: Vec<String>,
    secret: Option<String>,
}

fn parse_bunker_uri(uri: &str) -> Option<BunkerUri> {
    let rest = uri.strip_prefix("bunker://")?;
    let (pubkey_part, query) = rest.split_once('?').unwrap_or((rest, ""));
    let remote_signer_pubkey = unhex32(pubkey_part)?;
    let mut relays = Vec::new();
    let mut secret = None;
    for pair in query.split('&').filter(|pair| !pair.is_empty()) {
        let (key, value) = pair.split_once('=')?;
        let value = percent_decode(value);
        match key {
            "relay" => relays.push(value),
            "secret" => secret = Some(value),
            _ => {}
        }
    }
    if relays.is_empty() {
        return None;
    }
    Some(BunkerUri {
        remote_signer_pubkey,
        relays,
        secret,
    })
}

/// Decodes `%XX` escapes (relay URLs and secrets travel through a URI query
/// string, e.g. `wss%3A%2F%2Frelay.example` for `wss://relay.example`).
fn percent_decode(value: &str) -> String {
    let bytes = value.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut index = 0;
    while index < bytes.len() {
        if bytes[index] == b'%'
            && index + 2 < bytes.len()
            && let Ok(byte) = u8::from_str_radix(&value[index + 1..index + 3], 16)
        {
            out.push(byte);
            index += 3;
            continue;
        }
        out.push(bytes[index]);
        index += 1;
    }
    String::from_utf8_lossy(&out).into_owned()
}

/// One established remote-signer session: the client's own disposable
/// keypair, the two pubkeys the spec is careful to keep distinct, the
/// shared NIP-44 key (symmetric, so it also decrypts the signer's replies),
/// and the live relay connection and subscription used to reach it.
struct Session {
    client_secret: [u8; 32],
    client_pubkey_hex: String,
    remote_signer_pubkey_hex: String,
    /// Learned via `get_public_key` right after `connect`, per the spec —
    /// never assumed to equal `remote_signer_pubkey_hex`.
    #[allow(dead_code)]
    user_pubkey_hex: String,
    conversation_key: [u8; 32],
    relay: RealRelayHost,
    subscription: nscript_runtime::SubscriptionHandle,
}

/// A real [`Nip46Transport`]: everything above the relay/crypto primitives —
/// the request/response envelope, the `connect` handshake, and `sign_event` —
/// implemented against the actual protocol, not simulated.
#[derive(Default)]
pub struct RealNip46Transport {
    sessions: std::collections::BTreeMap<String, Session>,
}

impl RealNip46Transport {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Sends one NIP-46 request and waits for the matching reply, decrypting
    /// and parsing it. `params` are the method's positional string
    /// arguments, already whatever shape the method expects (a
    /// JSON-stringified object for `sign_event`, for instance).
    fn call(
        session: &mut Session,
        provider: &str,
        method: &str,
        params: &[String],
    ) -> Result<Value, RuntimeError> {
        let request_id = hex(&crate::random32().map_err(|_| denied(provider, "no randomness"))?);
        let plaintext = json!({
            "id": request_id,
            "method": method,
            "params": params,
        })
        .to_string();
        let ciphertext = nip44::encrypt(&session.conversation_key, plaintext.as_bytes())
            .map_err(|error| denied(provider, format!("encrypt failed: {error:?}")))?;
        let tags = json!([["p", session.remote_signer_pubkey_hex]]);
        let event = signed_event(
            &session.client_secret,
            KIND_NIP46,
            &tags,
            &ciphertext,
            now_unix(),
        )
        .map_err(|error| denied(provider, format!("could not sign request: {error:?}")))?;
        let wire = SignedEvent {
            unsigned: UnsignedEvent {
                event_type: "Nip46Request".to_owned(),
                kind: u16::try_from(KIND_NIP46).expect("24133 fits in u16"),
                content: ciphertext,
                tags: vec![("p".to_owned(), session.remote_signer_pubkey_hex.clone())],
                created_at: now_unix(),
            },
            signer: session.client_pubkey_hex.clone(),
            id: event
                .get("id")
                .and_then(Value::as_str)
                .unwrap_or_default()
                .to_owned(),
            signature: event
                .get("sig")
                .and_then(Value::as_str)
                .unwrap_or_default()
                .to_owned(),
        };
        session.relay.publish(0, &wire, "")?;

        let deadline = Instant::now() + REPLY_BUDGET;
        while Instant::now() < deadline {
            let Some(reply) = session.relay.recv_event(&session.subscription)? else {
                continue;
            };
            let Ok(plaintext) = nip44::decrypt(&session.conversation_key, &reply.unsigned.content)
            else {
                continue;
            };
            let Ok(body) = serde_json::from_slice::<Value>(&plaintext) else {
                continue;
            };
            if body.get("id").and_then(Value::as_str) != Some(request_id.as_str()) {
                // A reply to some other request (or a stale/replayed one);
                // keep waiting for ours within the same budget.
                continue;
            }
            if let Some(error) = body.get("error").and_then(Value::as_str) {
                return Err(denied(provider, error));
            }
            return body
                .get("result")
                .cloned()
                .ok_or_else(|| denied(provider, "reply had neither a result nor an error"));
        }
        Err(RuntimeError::RelayUnavailable {
            relayset: provider.to_owned(),
        })
    }
}

impl Nip46Transport for RealNip46Transport {
    fn provision(&mut self, provider: &str) -> Result<SignerSession, RuntimeError> {
        let bunker =
            parse_bunker_uri(provider).ok_or_else(|| denied(provider, "not a bunker:// URI"))?;
        let mut last_error = None;
        let mut relay = None;
        for candidate in &bunker.relays {
            match RealRelayHost::connect(candidate.clone()) {
                Ok(host) => {
                    relay = Some(host);
                    break;
                }
                Err(error) => last_error = Some(error),
            }
        }
        let mut relay = relay.ok_or_else(|| {
            last_error.unwrap_or(RuntimeError::RelayUnavailable {
                relayset: provider.to_owned(),
            })
        })?;

        let client_secret = crate::random32().map_err(|_| denied(provider, "no randomness"))?;
        let client_pubkey = xonly_pubkey(&client_secret).map_err(|_| denied(provider, "bad key"))?;
        let client_pubkey_hex = hex(&client_pubkey);
        let remote_signer_pubkey_hex = hex(&bunker.remote_signer_pubkey);
        let conversation_key = nip44::conversation_key(&client_secret, &bunker.remote_signer_pubkey)
            .map_err(|_| denied(provider, "could not derive a shared key"))?;

        let subscription = relay
            .subscribe(
                0,
                &SubscriptionRequest {
                    event_type: "Nip46Response".to_owned(),
                    relayset: None,
                    kinds: vec![u16::try_from(KIND_NIP46).expect("24133 fits in u16")],
                    tag_equals: vec![("p".to_owned(), client_pubkey_hex.clone())],
                    cursor: None,
                    author: Some(remote_signer_pubkey_hex.clone()),
                    since: None,
                    limit: None,
                },
            )?;

        let mut session = Session {
            client_secret,
            client_pubkey_hex,
            remote_signer_pubkey_hex: remote_signer_pubkey_hex.clone(),
            user_pubkey_hex: String::new(),
            conversation_key,
            relay,
            subscription,
        };

        let mut connect_params = vec![remote_signer_pubkey_hex];
        if let Some(secret) = bunker.secret {
            connect_params.push(secret);
        }
        let connect_result = Self::call(&mut session, provider, "connect", &connect_params)?;
        // The spec's success shape is `"ack"` or, for the `nostrconnect://`
        // flow only, the pre-agreed secret — either way, anything but an
        // `error` field (already handled by `call`) is success here.
        let _ = connect_result;

        // "a client MUST NOT assume `user-pubkey` is equal to
        // `remote-signer-pubkey`" — `get_public_key` is the one way to learn
        // it, so `connect` always finishes the handshake with it rather than
        // leaving it to a script to ask for separately (there is no script-
        // facing `get_public_key` operation).
        let user_pubkey = Self::call(&mut session, provider, "get_public_key", &[])?;
        user_pubkey
            .as_str()
            .ok_or_else(|| denied(provider, "get_public_key did not return a pubkey"))?
            .clone_into(&mut session.user_pubkey_hex);

        self.sessions.insert(provider.to_owned(), session);
        Ok(SignerSession {
            provider: provider.to_owned(),
        })
    }

    fn sign(
        &mut self,
        session: &SignerSession,
        event: UnsignedEvent,
    ) -> Result<SignedEvent, RuntimeError> {
        let provider = session.provider.clone();
        let state = self
            .sessions
            .get_mut(&provider)
            .ok_or_else(|| denied(&provider, "not connected (call provision first)"))?;
        let template = json!({
            "kind": event.kind,
            "content": event.content,
            "tags": event.wire_tags(),
            "created_at": event.created_at,
        })
        .to_string();
        let result = Self::call(state, &provider, "sign_event", &[template])?;
        let signed: Value = match result {
            Value::String(text) => serde_json::from_str(&text)
                .map_err(|_| denied(&provider, "sign_event result was not a signed event"))?,
            other => other,
        };
        verify_event(&signed)
            .map_err(|_| denied(&provider, "signer returned a badly signed event"))?;
        let tags = signed
            .get("tags")
            .and_then(Value::as_array)
            .map(|tags| {
                tags.iter()
                    .filter_map(|tag| {
                        let values = tag.as_array()?;
                        Some((
                            values.first()?.as_str()?.to_owned(),
                            values.get(1).and_then(Value::as_str).unwrap_or("").to_owned(),
                        ))
                    })
                    .collect()
            })
            .unwrap_or_default();
        Ok(SignedEvent {
            unsigned: UnsignedEvent {
                event_type: event.event_type,
                kind: signed
                    .get("kind")
                    .and_then(Value::as_u64)
                    .and_then(|kind| u16::try_from(kind).ok())
                    .unwrap_or(event.kind),
                content: signed
                    .get("content")
                    .and_then(Value::as_str)
                    .unwrap_or_default()
                    .to_owned(),
                tags,
                created_at: signed
                    .get("created_at")
                    .and_then(Value::as_u64)
                    .unwrap_or(event.created_at),
            },
            signer: signed
                .get("pubkey")
                .and_then(Value::as_str)
                .unwrap_or_default()
                .to_owned(),
            id: signed
                .get("id")
                .and_then(Value::as_str)
                .unwrap_or_default()
                .to_owned(),
            signature: signed
                .get("sig")
                .and_then(Value::as_str)
                .unwrap_or_default()
                .to_owned(),
        })
    }
}

#[cfg(test)]
mod tests {
    use std::net::{TcpListener, TcpStream};
    use std::thread;

    use tungstenite::{Message, WebSocket};

    use super::*;

    #[test]
    fn parses_a_bunker_uri_with_multiple_relays_and_a_secret() {
        let pubkey = "1".repeat(64);
        let uri = format!(
            "bunker://{pubkey}?relay=wss%3A%2F%2Frelay1.example&relay=wss%3A%2F%2Frelay2.example&secret=abc123"
        );
        let parsed = parse_bunker_uri(&uri).expect("parses");
        assert_eq!(parsed.remote_signer_pubkey, unhex32(&pubkey).unwrap());
        assert_eq!(
            parsed.relays,
            vec!["wss://relay1.example".to_owned(), "wss://relay2.example".to_owned()]
        );
        assert_eq!(parsed.secret.as_deref(), Some("abc123"));
    }

    #[test]
    fn a_bunker_uri_needs_no_secret_and_the_relay_param_alone_is_enough() {
        let pubkey = "2".repeat(64);
        let uri = format!("bunker://{pubkey}?relay=ws%3A%2F%2Flocalhost%3A1234");
        let parsed = parse_bunker_uri(&uri).expect("parses");
        assert_eq!(parsed.relays, vec!["ws://localhost:1234".to_owned()]);
        assert_eq!(parsed.secret, None);
    }

    #[test]
    fn rejects_a_non_bunker_uri_or_one_with_no_relay() {
        assert!(parse_bunker_uri("nostrconnect://abc?relay=ws%3A%2F%2Fx").is_none());
        assert!(parse_bunker_uri(&format!("bunker://{}", "3".repeat(64))).is_none());
        assert!(parse_bunker_uri("bunker://not-hex?relay=ws%3A%2F%2Fx").is_none());
    }

    /// A minimal in-process bunker: accepts one client, answers exactly the
    /// `connect` / `get_public_key` / `sign_event` sequence
    /// [`RealNip46Transport::provision`] and [`Nip46Transport::sign`] send,
    /// using the same real NIP-44 encryption and Schnorr signing the client
    /// does — this proves the two sides actually agree on the wire format,
    /// not just that the client's own code runs.
    fn fake_bunker(bunker_secret: [u8; 32], user_secret: [u8; 32], expect_secret: Option<&'static str>) -> String {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
        let url = format!("ws://{}", listener.local_addr().expect("addr"));
        thread::spawn(move || {
            let (stream, _) = listener.accept().expect("accept");
            let mut socket = tungstenite::accept(stream).expect("handshake");
            let user_pubkey = xonly_pubkey(&user_secret).expect("user pubkey");

            // REQ: acknowledge with an immediate EOSE, same as a real relay
            // with no matching history for a brand-new subscription.
            let Message::Text(req) = socket.read().expect("REQ frame") else {
                panic!("expected REQ");
            };
            let req: Value = serde_json::from_str(&req).expect("REQ json");
            let sub_id = req.get(1).and_then(Value::as_str).unwrap().to_owned();
            send(&mut socket, &json!(["EOSE", sub_id]));

            let mut conversation_key = None;
            for expected_method in ["connect", "get_public_key", "sign_event"] {
                let Message::Text(text) = socket.read().expect("EVENT frame") else {
                    panic!("expected EVENT");
                };
                let frame: Value = serde_json::from_str(&text).expect("EVENT json");
                assert_eq!(frame.get(0).and_then(Value::as_str), Some("EVENT"));
                let event = frame.get(1).cloned().expect("event body");
                send(&mut socket, &json!(["OK", event["id"], true, ""]));

                let client_pubkey_hex = event["pubkey"].as_str().unwrap().to_owned();
                let client_pubkey = unhex32(&client_pubkey_hex).unwrap();
                let key = *conversation_key.get_or_insert_with(|| {
                    nip44::conversation_key(&bunker_secret, &client_pubkey).unwrap()
                });
                let plaintext =
                    nip44::decrypt(&key, event["content"].as_str().unwrap()).expect("decrypts");
                let request: Value = serde_json::from_slice(&plaintext).expect("request json");
                assert_eq!(
                    request.get("method").and_then(Value::as_str),
                    Some(expected_method)
                );

                if expected_method == "connect"
                    && let Some(secret) = expect_secret
                {
                    let params = request["params"].as_array().unwrap();
                    assert_eq!(params.get(1).and_then(Value::as_str), Some(secret));
                }

                let result = match expected_method {
                    "connect" => json!("ack"),
                    "get_public_key" => json!(hex(&user_pubkey)),
                    "sign_event" => {
                        let template: Value = serde_json::from_str(
                            request["params"][0].as_str().expect("sign_event param"),
                        )
                        .expect("template json");
                        let tags = template.get("tags").cloned().unwrap_or(json!([]));
                        let signed = signed_event(
                            &user_secret,
                            template["kind"].as_u64().unwrap(),
                            &tags,
                            template["content"].as_str().unwrap(),
                            template["created_at"].as_u64().unwrap(),
                        )
                        .expect("signs the delegated event");
                        json!(signed.to_string())
                    }
                    _ => unreachable!(),
                };
                let response = json!({"id": request["id"], "result": result}).to_string();
                let ciphertext = nip44::encrypt(&key, response.as_bytes()).expect("encrypts");
                let response_event = signed_event(
                    &bunker_secret,
                    KIND_NIP46,
                    &json!([["p", client_pubkey_hex]]),
                    &ciphertext,
                    0,
                )
                .expect("signs response");
                send(&mut socket, &json!(["EVENT", sub_id, response_event]));
            }
        });
        url
    }

    fn send(socket: &mut WebSocket<TcpStream>, value: &Value) {
        socket
            .send(Message::Text(value.to_string().into()))
            .expect("relay send");
    }

    #[test]
    fn provisions_and_signs_against_a_real_bunker_over_a_real_relay() {
        let bunker_secret = [7_u8; 32];
        let user_secret = [9_u8; 32];
        let url = fake_bunker(bunker_secret, user_secret, None);
        let bunker_pubkey_hex = hex(&xonly_pubkey(&bunker_secret).unwrap());
        let provider = format!("bunker://{bunker_pubkey_hex}?relay={url}");

        let mut transport = RealNip46Transport::new();
        let session = transport.provision(&provider).expect("provisions");
        assert_eq!(session.provider, provider);

        let signed = transport
            .sign(
                &session,
                UnsignedEvent {
                    event_type: "Note".to_owned(),
                    kind: 1,
                    content: "hello from a real bunker round trip".to_owned(),
                    tags: Vec::new(),
                    created_at: 1_700_000_000,
                },
            )
            .expect("signs");
        assert_eq!(signed.unsigned.content, "hello from a real bunker round trip");
        assert_eq!(signed.signer, hex(&xonly_pubkey(&user_secret).unwrap()));
        assert_eq!(signed.id.len(), 64);
        assert_eq!(signed.signature.len(), 128);
    }

    #[test]
    fn a_bunker_urls_secret_reaches_the_connect_request() {
        let bunker_secret = [11_u8; 32];
        let user_secret = [13_u8; 32];
        let url = fake_bunker(bunker_secret, user_secret, Some("s3cr3t"));
        let bunker_pubkey_hex = hex(&xonly_pubkey(&bunker_secret).unwrap());
        let provider = format!("bunker://{bunker_pubkey_hex}?relay={url}&secret=s3cr3t");

        let mut transport = RealNip46Transport::new();
        transport.provision(&provider).expect("provisions");
    }

    #[test]
    fn an_unreachable_relay_fails_with_relay_unavailable() {
        let provider = format!("bunker://{}?relay=ws%3A%2F%2F127.0.0.1%3A1", "4".repeat(64));
        let mut transport = RealNip46Transport::new();
        assert!(matches!(
            transport.provision(&provider),
            Err(RuntimeError::RelayUnavailable { .. })
        ));
    }

    #[test]
    fn a_non_bunker_provider_is_denied_without_touching_the_network() {
        let mut transport = RealNip46Transport::new();
        assert!(matches!(
            transport.provision("nostrconnect://not-supported"),
            Err(RuntimeError::SignerDenied { .. })
        ));
    }
}
