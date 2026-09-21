//! CORD-01 stream events: building and opening real wraps and seals.
//!
//! A wrap is a kind-1059 event signed by the plane's stream key, tagged with an
//! ephemeral `p`, whose content is NIP-44 encrypted under the plane's read key.
//! Inside is a seal (kind 20013 encrypted or 20014 plaintext) signed by the
//! author's real key, carrying the rumor.

use serde_json::{Value, json};
use sha2::{Digest, Sha256};

use crate::group_key::{CryptoError, hex, xonly_pubkey};
use crate::nip44::{self, Nip44Error};
use crate::schnorr;

pub const KIND_WRAP: u64 = 1059;
pub const KIND_SEAL_ENCRYPTED: u64 = 20013;
pub const KIND_SEAL_PLAINTEXT: u64 = 20014;

#[derive(Debug, Eq, PartialEq)]
pub enum StreamError {
    Crypto(CryptoError),
    Nip44(Nip44Error),
    NotJson,
    /// The wrap is not a kind-1059 event.
    NotAWrap,
    /// The wrap's author is not the plane's stream key.
    WrongStream,
    /// An event id or signature failed verification.
    BadSignature,
    /// The seal kind differs from what the plane requires.
    WrongSealKind,
    /// The rumor's author differs from the seal's (impersonation).
    AuthorMismatch,
}

impl From<CryptoError> for StreamError {
    fn from(error: CryptoError) -> Self {
        Self::Crypto(error)
    }
}

impl From<Nip44Error> for StreamError {
    fn from(error: Nip44Error) -> Self {
        Self::Nip44(error)
    }
}

/// Whether a seal carries an encrypted (20013) or plaintext (20014) rumor.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SealForm {
    Encrypted,
    Plaintext,
}

impl SealForm {
    fn kind(self) -> u64 {
        match self {
            Self::Encrypted => KIND_SEAL_ENCRYPTED,
            Self::Plaintext => KIND_SEAL_PLAINTEXT,
        }
    }
}

/// NIP-01 event id: sha256 of `[0, pubkey, created_at, kind, tags, content]`.
fn event_id(pubkey: &str, created_at: u64, kind: u64, tags: &Value, content: &str) -> String {
    let preimage = json!([0, pubkey, created_at, kind, tags, content]).to_string();
    hex(&Sha256::digest(preimage.as_bytes()))
}

fn unhex32(text: &str) -> Option<[u8; 32]> {
    if text.len() != 64 {
        return None;
    }
    let mut out = [0_u8; 32];
    for (slot, pair) in out.iter_mut().zip(text.as_bytes().chunks(2)) {
        *slot = u8::from_str_radix(std::str::from_utf8(pair).ok()?, 16).ok()?;
    }
    Some(out)
}

fn unhex64(text: &str) -> Option<[u8; 64]> {
    let bytes: Vec<u8> = (0..text.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(text.get(i..i + 2)?, 16).ok())
        .collect::<Option<_>>()?;
    bytes.try_into().ok()
}

/// A signed Nostr event as JSON.
fn signed_event(
    secret: &[u8; 32],
    kind: u64,
    tags: &Value,
    content: &str,
    created_at: u64,
) -> Result<Value, StreamError> {
    let pubkey = hex(&xonly_pubkey(secret)?);
    let id = event_id(&pubkey, created_at, kind, tags, content);
    let id_bytes = unhex32(&id).ok_or(StreamError::BadSignature)?;
    let sig = schnorr::sign_random(secret, &id_bytes)?;
    Ok(json!({
        "id": id, "pubkey": pubkey, "created_at": created_at,
        "kind": kind, "tags": tags, "content": content, "sig": hex(&sig)
    }))
}

/// Verifies an event's id and signature, returning its fields.
fn verify_event(event: &Value) -> Result<(), StreamError> {
    let field = |name: &str| event.get(name).ok_or(StreamError::NotJson);
    let pubkey = field("pubkey")?.as_str().ok_or(StreamError::NotJson)?;
    let created_at = field("created_at")?.as_u64().ok_or(StreamError::NotJson)?;
    let kind = field("kind")?.as_u64().ok_or(StreamError::NotJson)?;
    let content = field("content")?.as_str().ok_or(StreamError::NotJson)?;
    let id = event_id(pubkey, created_at, kind, field("tags")?, content);
    if field("id")?.as_str() != Some(id.as_str()) {
        return Err(StreamError::BadSignature);
    }
    let sig = event.get("sig").and_then(Value::as_str).and_then(unhex64);
    match (sig, unhex32(pubkey), unhex32(&id)) {
        (Some(sig), Some(key), Some(id)) if schnorr::verify(&key, &id, &sig) => Ok(()),
        _ => Err(StreamError::BadSignature),
    }
}

/// Builds a wrap around a rumor. `wrap_signer` is the plane's stream secret,
/// `read_key` the conversation key that encrypts the wrap and (for encrypted
/// seals) the rumor. Returns the wrap event as JSON.
///
/// # Errors
///
/// Returns [`StreamError`] for invalid keys or an oversize rumor.
pub fn build_stream_event(
    wrap_signer: &[u8; 32],
    read_key: &[u8; 32],
    form: SealForm,
    author_secret: &[u8; 32],
    rumor: &Value,
    created_at: u64,
) -> Result<String, StreamError> {
    build_stream_event_with_tags(
        wrap_signer,
        read_key,
        form,
        author_secret,
        rumor,
        &[],
        created_at,
    )
}

/// Like [`build_stream_event`], adding relay-visible tags to the outer wrap
/// after the ephemeral `p`. CORD-08 uses this for the NIP-40 `expiration` tag,
/// which a chat wrap must carry with the same value as its rumor.
///
/// # Errors
///
/// Returns [`StreamError`] for invalid keys or an oversize rumor.
pub fn build_stream_event_with_tags(
    wrap_signer: &[u8; 32],
    read_key: &[u8; 32],
    form: SealForm,
    author_secret: &[u8; 32],
    rumor: &Value,
    outer_tags: &[Vec<String>],
    created_at: u64,
) -> Result<String, StreamError> {
    let rumor_json = rumor.to_string();
    let seal_content = match form {
        SealForm::Encrypted => nip44::encrypt(read_key, rumor_json.as_bytes())?,
        SealForm::Plaintext => rumor_json,
    };
    let seal = signed_event(
        author_secret,
        form.kind(),
        &json!([]),
        &seal_content,
        created_at,
    )?;
    let wrap_content = nip44::encrypt(read_key, seal.to_string().as_bytes())?;
    // Streams reverse NIP-59: fixed author, ephemeral `p` tag.
    let ephemeral = hex(&xonly_pubkey(&crate::random32()?)?);
    let mut tags = vec![json!(["p", ephemeral])];
    tags.extend(outer_tags.iter().map(|tag| json!(tag)));
    let wrap = signed_event(
        wrap_signer,
        KIND_WRAP,
        &Value::Array(tags),
        &wrap_content,
        created_at,
    )?;
    Ok(wrap.to_string())
}

/// What a valid wrap contained.
#[derive(Debug, Eq, PartialEq)]
pub struct Opened {
    /// The seal's real author.
    pub author: String,
    pub form: SealForm,
    /// The rumor, byte-verbatim for plaintext seals.
    pub rumor_json: String,
}

/// Opens a wrap: verifies the stream signature, decrypts, verifies the seal's
/// signature, checks the seal kind against the plane, and enforces that the
/// rumor's author equals the seal's.
///
/// # Errors
///
/// Returns [`StreamError`] describing the first failed check.
pub fn open_stream_event(
    stream_pubkey: &[u8; 32],
    read_key: &[u8; 32],
    expected: SealForm,
    wrap_json: &str,
) -> Result<Opened, StreamError> {
    let wrap: Value = serde_json::from_str(wrap_json).map_err(|_| StreamError::NotJson)?;
    if wrap.get("kind").and_then(Value::as_u64) != Some(KIND_WRAP) {
        return Err(StreamError::NotAWrap);
    }
    if wrap.get("pubkey").and_then(Value::as_str) != Some(hex(stream_pubkey).as_str()) {
        return Err(StreamError::WrongStream);
    }
    verify_event(&wrap)?;
    let payload = wrap
        .get("content")
        .and_then(Value::as_str)
        .ok_or(StreamError::NotJson)?;
    let seal_json =
        String::from_utf8(nip44::decrypt(read_key, payload)?).map_err(|_| StreamError::NotJson)?;
    let seal: Value = serde_json::from_str(&seal_json).map_err(|_| StreamError::NotJson)?;
    verify_event(&seal)?;
    if seal.get("kind").and_then(Value::as_u64) != Some(expected.kind()) {
        return Err(StreamError::WrongSealKind);
    }
    let author = seal
        .get("pubkey")
        .and_then(Value::as_str)
        .ok_or(StreamError::NotJson)?;
    let seal_content = seal
        .get("content")
        .and_then(Value::as_str)
        .ok_or(StreamError::NotJson)?;
    let rumor_json = match expected {
        SealForm::Plaintext => seal_content.to_owned(),
        SealForm::Encrypted => String::from_utf8(nip44::decrypt(read_key, seal_content)?)
            .map_err(|_| StreamError::NotJson)?,
    };
    let rumor: Value = serde_json::from_str(&rumor_json).map_err(|_| StreamError::NotJson)?;
    // NIP-59 impersonation check: renderers display rumor fields.
    if rumor.get("pubkey").and_then(Value::as_str) != Some(author) {
        return Err(StreamError::AuthorMismatch);
    }
    Ok(Opened {
        author: author.to_owned(),
        form: expected,
        rumor_json,
    })
}

/// Builds a rumor with its NIP-01 id computed (an embedded id is never trusted
/// by readers, but rumors carry one).
///
/// # Errors
///
/// Returns [`StreamError::Crypto`] for an invalid author secret.
pub fn rumor(
    author_secret: &[u8; 32],
    kind: u64,
    tags: &Value,
    content: &str,
    created_at: u64,
) -> Result<Value, StreamError> {
    let pubkey = hex(&xonly_pubkey(author_secret)?);
    let id = event_id(&pubkey, created_at, kind, tags, content);
    Ok(json!({
        "id": id, "pubkey": pubkey, "created_at": created_at,
        "kind": kind, "tags": tags, "content": content
    }))
}
