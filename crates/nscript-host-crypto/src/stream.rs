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
/// The ephemeral wrap (CORD-01 §1.3): same shape as [`KIND_WRAP`], but in
/// Nostr's ephemeral range so relays never store any layer of it. Typing
/// indicators and voice presence (CORD-07 §4) use this kind.
pub const KIND_WRAP_EPHEMERAL: u64 = 21059;
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
pub(crate) fn signed_event(
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
pub(crate) fn verify_event(event: &Value) -> Result<(), StreamError> {
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

/// Builds a seal (kind 20013 or 20014) signed by the author's real key. The
/// rumor is carried byte-for-byte: encrypted under `read_key` for an encrypted
/// seal, or verbatim as the seal content for a plaintext one.
///
/// # Errors
///
/// Returns [`StreamError`] for invalid keys or an oversize rumor.
pub fn build_seal(
    read_key: &[u8; 32],
    form: SealForm,
    author_secret: &[u8; 32],
    rumor_json: &str,
    created_at: u64,
) -> Result<String, StreamError> {
    let content = match form {
        SealForm::Encrypted => nip44::encrypt(read_key, rumor_json.as_bytes())?,
        SealForm::Plaintext => rumor_json.to_owned(),
    };
    let seal = signed_event(author_secret, form.kind(), &json!([]), &content, created_at)?;
    Ok(seal.to_string())
}

/// Wraps a seal: a kind-1059 event signed by the plane's stream key, tagged
/// with an ephemeral `p` (streams reverse NIP-59: fixed author, ephemeral
/// `p`), plus any relay-visible `outer_tags`. CORD-08 uses those for the NIP-40
/// `expiration` tag, which a chat wrap carries with its rumor's value.
///
/// # Errors
///
/// Returns [`StreamError`] for invalid keys or an oversize seal.
pub fn build_wrap(
    wrap_signer: &[u8; 32],
    read_key: &[u8; 32],
    seal_json: &str,
    outer_tags: &[Vec<String>],
    created_at: u64,
) -> Result<String, StreamError> {
    build_wrap_as(
        KIND_WRAP,
        wrap_signer,
        read_key,
        seal_json,
        outer_tags,
        created_at,
    )
}

/// Like [`build_wrap`], as [`KIND_WRAP_EPHEMERAL`]: a wrap relays never store.
///
/// # Errors
///
/// Returns [`StreamError`] for invalid keys or an oversize seal.
pub fn build_ephemeral_wrap(
    wrap_signer: &[u8; 32],
    read_key: &[u8; 32],
    seal_json: &str,
    outer_tags: &[Vec<String>],
    created_at: u64,
) -> Result<String, StreamError> {
    build_wrap_as(
        KIND_WRAP_EPHEMERAL,
        wrap_signer,
        read_key,
        seal_json,
        outer_tags,
        created_at,
    )
}

fn build_wrap_as(
    wrap_kind: u64,
    wrap_signer: &[u8; 32],
    read_key: &[u8; 32],
    seal_json: &str,
    outer_tags: &[Vec<String>],
    created_at: u64,
) -> Result<String, StreamError> {
    let content = nip44::encrypt(read_key, seal_json.as_bytes())?;
    let ephemeral = hex(&xonly_pubkey(&crate::random32()?)?);
    let mut tags = vec![json!(["p", ephemeral])];
    tags.extend(outer_tags.iter().map(|tag| json!(tag)));
    let wrap = signed_event(
        wrap_signer,
        wrap_kind,
        &Value::Array(tags),
        &content,
        created_at,
    )?;
    Ok(wrap.to_string())
}

/// Builds a wrap around a rumor in one step.
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

/// Like [`build_stream_event`], adding relay-visible outer tags.
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
    let seal = build_seal(
        read_key,
        form,
        author_secret,
        &rumor.to_string(),
        created_at,
    )?;
    build_wrap(wrap_signer, read_key, &seal, outer_tags, created_at)
}

/// Like [`build_stream_event_with_tags`], wrapped as [`KIND_WRAP_EPHEMERAL`]
/// (a typing indicator or voice presence, CORD-01 §1.3).
///
/// # Errors
///
/// Returns [`StreamError`] for invalid keys or an oversize rumor.
pub fn build_ephemeral_stream_event_with_tags(
    wrap_signer: &[u8; 32],
    read_key: &[u8; 32],
    form: SealForm,
    author_secret: &[u8; 32],
    rumor: &Value,
    outer_tags: &[Vec<String>],
    created_at: u64,
) -> Result<String, StreamError> {
    let seal = build_seal(
        read_key,
        form,
        author_secret,
        &rumor.to_string(),
        created_at,
    )?;
    build_ephemeral_wrap(wrap_signer, read_key, &seal, outer_tags, created_at)
}

/// Verifies a wrap (kind 1059, signed by the stream key) and decrypts it to
/// the seal event JSON it carries.
///
/// # Errors
///
/// Returns [`StreamError`] describing the first failed check.
pub fn open_wrap(
    stream_pubkey: &[u8; 32],
    read_key: &[u8; 32],
    wrap_json: &str,
) -> Result<String, StreamError> {
    open_wrap_as(KIND_WRAP, stream_pubkey, read_key, wrap_json)
}

/// Like [`open_wrap`], for a [`KIND_WRAP_EPHEMERAL`] wrap.
///
/// # Errors
///
/// Returns [`StreamError`] describing the first failed check.
pub fn open_ephemeral_wrap(
    stream_pubkey: &[u8; 32],
    read_key: &[u8; 32],
    wrap_json: &str,
) -> Result<String, StreamError> {
    open_wrap_as(KIND_WRAP_EPHEMERAL, stream_pubkey, read_key, wrap_json)
}

fn open_wrap_as(
    wrap_kind: u64,
    stream_pubkey: &[u8; 32],
    read_key: &[u8; 32],
    wrap_json: &str,
) -> Result<String, StreamError> {
    let wrap: Value = serde_json::from_str(wrap_json).map_err(|_| StreamError::NotJson)?;
    if wrap.get("kind").and_then(Value::as_u64) != Some(wrap_kind) {
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
    String::from_utf8(nip44::decrypt(read_key, payload)?).map_err(|_| StreamError::NotJson)
}

/// The seal form declared by a seal event's kind.
///
/// # Errors
///
/// Returns [`StreamError::WrongSealKind`] for any other kind.
pub fn seal_form(seal_json: &str) -> Result<SealForm, StreamError> {
    let seal: Value = serde_json::from_str(seal_json).map_err(|_| StreamError::NotJson)?;
    match seal.get("kind").and_then(Value::as_u64) {
        Some(KIND_SEAL_ENCRYPTED) => Ok(SealForm::Encrypted),
        Some(KIND_SEAL_PLAINTEXT) => Ok(SealForm::Plaintext),
        _ => Err(StreamError::WrongSealKind),
    }
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

/// Opens a seal: verifies its signature, checks its kind against the plane,
/// recovers the rumor, and enforces that the rumor's author equals the seal's.
///
/// # Errors
///
/// Returns [`StreamError`] describing the first failed check.
pub fn open_seal(
    read_key: &[u8; 32],
    expected: SealForm,
    seal_json: &str,
) -> Result<Opened, StreamError> {
    let seal: Value = serde_json::from_str(seal_json).map_err(|_| StreamError::NotJson)?;
    verify_event(&seal)?;
    if seal.get("kind").and_then(Value::as_u64) != Some(expected.kind()) {
        return Err(StreamError::WrongSealKind);
    }
    let author = seal
        .get("pubkey")
        .and_then(Value::as_str)
        .ok_or(StreamError::NotJson)?;
    let content = seal
        .get("content")
        .and_then(Value::as_str)
        .ok_or(StreamError::NotJson)?;
    let rumor_json = match expected {
        SealForm::Plaintext => content.to_owned(),
        SealForm::Encrypted => String::from_utf8(nip44::decrypt(read_key, content)?)
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

/// Opens a wrap end to end: stream signature, decryption, seal signature and
/// kind, and the rumor author check.
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
    open_seal(
        read_key,
        expected,
        &open_wrap(stream_pubkey, read_key, wrap_json)?,
    )
}

/// Like [`open_stream_event`], for a [`KIND_WRAP_EPHEMERAL`] wrap.
///
/// # Errors
///
/// Returns [`StreamError`] describing the first failed check.
pub fn open_ephemeral_stream_event(
    stream_pubkey: &[u8; 32],
    read_key: &[u8; 32],
    expected: SealForm,
    wrap_json: &str,
) -> Result<Opened, StreamError> {
    open_seal(
        read_key,
        expected,
        &open_ephemeral_wrap(stream_pubkey, read_key, wrap_json)?,
    )
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
