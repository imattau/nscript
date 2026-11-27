//! Shared signing and relay publishing for the repository-facing CLI commands.
//!
//! `nscript ncc` and `nscript git` publish with a local key read from an
//! environment variable and report per-relay outcomes. Keeping one copy here
//! means both commands sign, publish, and fail the same way.

use std::env;
use std::fmt::Write as _;
use std::process::ExitCode;
use std::time::{SystemTime, UNIX_EPOCH};

use nscript_host_crypto::group_key::xonly_pubkey;
use nscript_host_crypto::schnorr::{sign_random, verify};
use nscript_runtime::{RealRelayPool, RelayHost, SignedEvent, UnsignedEvent, compute_event_id};
use serde_json::json;

#[derive(Debug)]
pub(crate) enum Failure {
    Usage(String),
    Runtime(String),
}

impl Failure {
    pub(crate) fn message(&self) -> &str {
        match self {
            Self::Usage(message) | Self::Runtime(message) => message,
        }
    }

    pub(crate) fn exit_code(&self) -> u8 {
        match self {
            Self::Usage(_) => 2,
            Self::Runtime(_) => 1,
        }
    }
}

pub(crate) fn finish(result: Result<(), Failure>) -> ExitCode {
    match result {
        Ok(()) => ExitCode::SUCCESS,
        Err(failure) => {
            eprintln!("error: {}", failure.message());
            ExitCode::from(failure.exit_code())
        }
    }
}

pub(crate) struct EventToPublish {
    pub(crate) label: String,
    pub(crate) event: UnsignedEvent,
}

pub(crate) struct RelayResult {
    pub(crate) relay: String,
    pub(crate) accepted: bool,
    pub(crate) detail: String,
}

pub(crate) struct PublishedEvent {
    pub(crate) label: String,
    pub(crate) kind: u16,
    pub(crate) event_id: String,
    pub(crate) accepted: usize,
    pub(crate) total: usize,
    pub(crate) relays: Vec<RelayResult>,
}

pub(crate) struct LocalSigner {
    pub(crate) secret: [u8; 32],
    pub(crate) public_key: [u8; 32],
    pub(crate) public_key_hex: String,
}

pub(crate) fn load_signer(key_env: Option<&str>) -> Result<LocalSigner, Failure> {
    let Some(key_name) = key_env else {
        return Err(Failure::Usage(
            "publishing needs --signer-key-env <environment-variable>".to_owned(),
        ));
    };
    let raw_key = env::var(key_name).map_err(|_| {
        Failure::Usage(format!(
            "environment variable `{key_name}` is not set; pass --signer-key-env with the variable that holds the key"
        ))
    })?;
    if raw_key.trim().is_empty() {
        return Err(Failure::Usage(format!(
            "environment variable `{key_name}` is empty"
        )));
    }
    let secret = parse_secret_key(&raw_key).map_err(Failure::Runtime)?;
    let public_key = xonly_pubkey(&secret)
        .map_err(|error| Failure::Runtime(format!("invalid key: {error:?}")))?;
    let public_key_hex = hex_encode(&public_key);
    Ok(LocalSigner {
        secret,
        public_key,
        public_key_hex,
    })
}

pub(crate) fn connect_relays(relays: &[String]) -> Result<RealRelayPool, Failure> {
    let mut pool = RealRelayPool::new();
    let mut connected = 0_usize;
    for relay in relays {
        match pool.add_relay(relay.clone()) {
            Ok(()) => {
                connected += 1;
                eprintln!("connected: {relay}");
            }
            Err(error) => eprintln!("warning: could not connect to {relay}: {error:?}"),
        }
    }
    if connected == 0 {
        return Err(Failure::Runtime(
            "could not connect to any relay; no event was attempted".to_owned(),
        ));
    }
    Ok(pool)
}

pub(crate) fn publish_event_list<R: RelayHost>(
    events: &[EventToPublish],
    pool: &mut R,
    signer: &LocalSigner,
    json_output: bool,
) -> Result<Vec<PublishedEvent>, Failure> {
    events
        .iter()
        .map(|event| publish_one(event, pool, signer, json_output))
        .collect()
}

pub(crate) fn publish_one<R: RelayHost>(
    event: &EventToPublish,
    pool: &mut R,
    signer: &LocalSigner,
    json_output: bool,
) -> Result<PublishedEvent, Failure> {
    let signed_event = sign_event(
        &event.event,
        &signer.secret,
        &signer.public_key,
        &signer.public_key_hex,
    )
    .map_err(Failure::Runtime)?;
    let report = pool.publish(0, &signed_event, "public").map_err(|error| {
        Failure::Runtime(format!("publishing {} failed: {error:?}", event.label))
    })?;
    let accepted = report
        .outcomes
        .iter()
        .filter(|outcome| outcome.accepted)
        .count();
    let total = report.outcomes.len();
    if !json_output {
        println!(
            "{}: event {} accepted {accepted}/{total} relays",
            event.label, signed_event.id
        );
        for outcome in &report.outcomes {
            if !outcome.accepted {
                eprintln!("  {}: {}", outcome.relay, outcome.detail);
            }
        }
    }
    Ok(PublishedEvent {
        label: event.label.clone(),
        kind: event.event.kind,
        event_id: signed_event.id,
        accepted,
        total,
        relays: report
            .outcomes
            .into_iter()
            .map(|outcome| RelayResult {
                relay: outcome.relay,
                accepted: outcome.accepted,
                detail: outcome.detail,
            })
            .collect(),
    })
}

pub(crate) fn count_failures(results: &[PublishedEvent], require: usize) -> usize {
    results
        .iter()
        .filter(|result| result.accepted < require)
        .count()
}

pub(crate) fn finish_publish(
    results: &[PublishedEvent],
    require: usize,
    json_output: bool,
) -> Result<(), Failure> {
    if json_output {
        let published = results
            .iter()
            .map(|result| {
                json!({
                    "label": &result.label,
                    "kind": result.kind,
                    "event_id": &result.event_id,
                    "accepted": result.accepted,
                    "total": result.total,
                    "relays": result.relays.iter().map(|relay| json!({
                        "relay": &relay.relay,
                        "accepted": relay.accepted,
                        "detail": &relay.detail,
                    })).collect::<Vec<_>>(),
                })
            })
            .collect::<Vec<_>>();
        println!(
            "{}",
            serde_json::to_string_pretty(&json!({ "published": published }))
                .expect("serializing a JSON value cannot fail")
        );
    }
    let failures = count_failures(results, require);
    if failures > 0 {
        return Err(Failure::Runtime(format!(
            "{failures} event(s) were accepted by fewer than {require} relay(s)"
        )));
    }
    Ok(())
}

pub(crate) fn sign_event(
    unsigned: &UnsignedEvent,
    secret: &[u8; 32],
    public_key: &[u8; 32],
    public_key_hex: &str,
) -> Result<SignedEvent, String> {
    let id = compute_event_id(public_key_hex, unsigned);
    let id_bytes = decode_hex_32(&id)?;
    let signature = sign_random(secret, &id_bytes)
        .map_err(|error| format!("could not sign {}: {error:?}", unsigned.event_type))?;
    if !verify(public_key, &id_bytes, &signature) {
        return Err("the local signer produced a signature that does not verify".to_owned());
    }
    Ok(SignedEvent {
        unsigned: unsigned.clone(),
        signer: public_key_hex.to_owned(),
        id,
        signature: hex_encode(&signature),
    })
}

pub(crate) fn parse_secret_key(raw: &str) -> Result<[u8; 32], String> {
    let raw = raw.trim();
    if raw.len() == 64 && raw.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return decode_hex_32(raw);
    }
    if raw.starts_with("nsec1") {
        let (hrp, data) = bech32::decode(raw).map_err(|error| format!("invalid nsec: {error}"))?;
        if hrp.to_string() != "nsec" {
            return Err("the provided key is not an nsec".to_owned());
        }
        if data.len() != 32 {
            return Err(format!(
                "an nsec must decode to 32 bytes, found {}",
                data.len()
            ));
        }
        let mut key = [0_u8; 32];
        key.copy_from_slice(&data);
        return Ok(key);
    }
    Err("signing key must be 64 hexadecimal characters or an nsec1... string".to_owned())
}

pub(crate) fn decode_hex_32(text: &str) -> Result<[u8; 32], String> {
    decode_hex::<32>(text)
}

pub(crate) fn decode_hex<const N: usize>(text: &str) -> Result<[u8; N], String> {
    if text.len() != N * 2 {
        return Err(format!(
            "expected {} hexadecimal characters, found {}",
            N * 2,
            text.len()
        ));
    }
    let mut bytes = [0_u8; N];
    let (chunks, remainder) = text.as_bytes().as_chunks::<2>();
    if !remainder.is_empty() {
        return Err("the hexadecimal value has an odd number of characters".to_owned());
    }
    for (index, chunk) in chunks.iter().enumerate() {
        let pair = std::str::from_utf8(chunk)
            .map_err(|_| "the hexadecimal value contains non-UTF-8 bytes".to_owned())?;
        bytes[index] = u8::from_str_radix(pair, 16)
            .map_err(|_| format!("invalid hexadecimal byte `{pair}`"))?;
    }
    Ok(bytes)
}

pub(crate) fn hex_encode(bytes: &[u8]) -> String {
    let mut output = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        write!(output, "{byte:02x}").expect("writing to a String cannot fail");
    }
    output
}

pub(crate) fn normalize_pubkey(value: &str) -> Result<String, Failure> {
    let value = value.trim();
    let bare = value.strip_prefix("pubkey:").unwrap_or(value);
    if bare.len() == 64 && bare.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return Ok(bare.to_ascii_lowercase());
    }
    let npub = value.strip_prefix("npub:").unwrap_or(value);
    if npub.starts_with("npub1") {
        let (hrp, data) = bech32::decode(npub)
            .map_err(|error| Failure::Usage(format!("invalid npub: {error}")))?;
        if hrp.to_string() != "npub" {
            return Err(Failure::Usage("the value is not an npub".to_owned()));
        }
        if data.len() != 32 {
            return Err(Failure::Usage(format!(
                "an npub must decode to 32 bytes, found {}",
                data.len()
            )));
        }
        return Ok(hex_encode(&data));
    }
    Err(Failure::Usage(
        "public key must be a 64-character pubkey or npub1...".to_owned(),
    ))
}

pub(crate) fn now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |duration| duration.as_secs())
}

pub(crate) fn option_value(
    arguments: &[String],
    index: &mut usize,
    flag: &str,
) -> Result<String, Failure> {
    let Some(value) = arguments.get(*index + 1) else {
        return Err(Failure::Usage(format!("{flag} needs a value")));
    };
    *index += 2;
    Ok(value.clone())
}

pub(crate) fn parse_u64(value: &str, flag: &str) -> Result<u64, Failure> {
    value.parse().map_err(|_| {
        Failure::Usage(format!(
            "{flag} expects a non-negative integer, found `{value}`"
        ))
    })
}

pub(crate) fn parse_usize(value: &str, flag: &str) -> Result<usize, Failure> {
    value.parse().map_err(|_| {
        Failure::Usage(format!(
            "{flag} expects a non-negative integer, found `{value}`"
        ))
    })
}
