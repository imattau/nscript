//! Shared relay plumbing for the interop examples.

use std::net::TcpStream;
use std::time::{Duration, Instant};

use serde_json::{Value, json};
use tungstenite::{Message, WebSocket, stream::MaybeTlsStream};

pub fn init_tls() {
    // tungstenite's rustls feature selects no crypto provider; pick ring.
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

pub fn connect(relay: &str) -> Result<WebSocket<MaybeTlsStream<TcpStream>>, String> {
    let (mut socket, _) = tungstenite::connect(relay).map_err(|e| format!("connect: {e}"))?;
    set_timeout(&mut socket, Duration::from_secs(5));
    Ok(socket)
}

/// Runs one REQ and returns every EVENT received before EOSE.
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

pub fn hex(bytes: &[u8]) -> String {
    use std::fmt::Write as _;
    bytes.iter().fold(String::new(), |mut out, b| {
        let _ = write!(out, "{b:02x}");
        out
    })
}

pub fn unhex32(text: &str) -> [u8; 32] {
    let bytes: Vec<u8> = (0..text.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&text[i..i + 2], 16).expect("hex"))
        .collect();
    bytes.try_into().expect("32 bytes")
}
