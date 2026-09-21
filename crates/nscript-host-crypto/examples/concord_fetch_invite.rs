//! Read-only interop step: resolve a Concord invite link, fetch its bundle from
//! the bootstrap relays, decrypt it with the link's token, and print a preview.
//! Publishes nothing and never prints key material.
//!
//! Usage: `concord_fetch_invite <link_signer_hex> <fragment>`

use std::net::TcpStream;
use std::time::{Duration, Instant};

use nscript_host_crypto::nip44;
use nscript_runtime::invite::{bundle_key, decode_fragment, parse_invite};
use serde_json::{Value, json};
use tungstenite::{Message, WebSocket, stream::MaybeTlsStream};

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

fn fetch(relay: &str, signer: &str) -> Result<Option<Value>, String> {
    let (mut socket, _) = tungstenite::connect(relay).map_err(|e| format!("connect: {e}"))?;
    set_timeout(&mut socket, Duration::from_secs(5));
    let filter = json!({"kinds": [33301], "authors": [signer], "#d": [""]});
    socket
        .send(Message::text(json!(["REQ", "inv", filter]).to_string()))
        .map_err(|e| format!("send: {e}"))?;
    let deadline = Instant::now() + Duration::from_secs(10);
    let mut found = None;
    while Instant::now() < deadline {
        let Ok(Message::Text(text)) = socket.read() else {
            break;
        };
        let Ok(Value::Array(frame)) = serde_json::from_str::<Value>(&text) else {
            continue;
        };
        match frame.first().and_then(Value::as_str) {
            Some("EVENT") => found = frame.get(2).cloned(),
            Some("EOSE" | "CLOSED") => break,
            _ => {}
        }
    }
    let _ = socket.close(None);
    Ok(found)
}

fn main() {
    // tungstenite's rustls feature selects no crypto provider; pick ring.
    let _ = rustls::crypto::ring::default_provider().install_default();
    let args: Vec<String> = std::env::args().collect();
    let (signer, fragment) = (&args[1], &args[2]);
    let fragment = decode_fragment(fragment).expect("fragment decodes");
    println!("bootstrap relays: {:?}", fragment.relays);

    let mut event = None;
    for relay in &fragment.relays {
        match fetch(relay, signer) {
            Ok(Some(found)) => {
                println!("bundle event found on {relay}");
                event = Some(found);
                break;
            }
            Ok(None) => println!("{relay}: no bundle"),
            Err(error) => println!("{relay}: {error}"),
        }
    }
    let event = event.expect("no relay returned the bundle");
    let tags = event["tags"].to_string();
    println!("tags: {tags}");
    if tags.contains(r#"["vsk","9"]"#) {
        println!("this link has been REVOKED (tombstone)");
        return;
    }
    let content = event["content"].as_str().expect("content");
    let plaintext = nip44::decrypt(&bundle_key(&fragment.token), content).expect("bundle decrypts");
    let bundle = String::from_utf8(plaintext).expect("utf8");
    let invite = parse_invite(&bundle).expect("bundle validates (owner self-certifies)");
    println!("community: {} ({})", invite.name, invite.community_id);
    println!("owner: {}", invite.owner);
    println!(
        "root_epoch: {} | control_pk: {}",
        invite.root_epoch,
        invite.control_pk.is_some()
    );
    println!("relays: {:?}", invite.relays);
    println!(
        "expires_at: {:?} | label: {:?}",
        invite.expires_at, invite.label
    );
    for channel in &invite.channels {
        println!(
            "channel {} ({}) epoch {}",
            channel.name, channel.id, channel.epoch
        );
    }
}
