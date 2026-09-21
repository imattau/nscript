//! NIP-44 v2: authenticated encryption under a conversation key.

use base64::{Engine as _, engine::general_purpose::STANDARD};
use chacha20::{
    ChaCha20,
    cipher::{KeyIvInit, StreamCipher},
};
use hkdf::Hkdf;
use hmac::{Hmac, Mac};
use sha2::Sha256;
use subtle::ConstantTimeEq;

use crate::group_key::{CryptoError, shared_x};

const VERSION: u8 = 2;
const MIN_PLAINTEXT: usize = 1;
const MAX_PLAINTEXT: usize = 65_535;

#[derive(Debug, Eq, PartialEq)]
pub enum Nip44Error {
    Key(CryptoError),
    /// Plaintext length outside 1..=65535.
    InvalidPlaintextLength,
    /// Unknown version, bad base64, bad length, or a `#` future-version marker.
    InvalidPayload,
    InvalidMac,
    InvalidPadding,
}

impl From<CryptoError> for Nip44Error {
    fn from(error: CryptoError) -> Self {
        Self::Key(error)
    }
}

/// The per-message keys derived from a conversation key and nonce.
pub struct MessageKeys {
    pub chacha_key: [u8; 32],
    pub chacha_nonce: [u8; 12],
    pub hmac_key: [u8; 32],
}

/// `conversation_key = hkdf_extract(salt = "nip44-v2", ikm = ecdh_x)`.
///
/// # Errors
///
/// Returns [`CryptoError::InvalidKey`] for an invalid secret or public key.
pub fn conversation_key(secret: &[u8; 32], public: &[u8; 32]) -> Result<[u8; 32], CryptoError> {
    let shared = shared_x(secret, public)?;
    let (prk, _) = Hkdf::<Sha256>::extract(Some(b"nip44-v2"), &shared);
    Ok(prk.into())
}

/// Expands the 76 bytes of per-message key material (`hkdf_expand(conv_key,
/// nonce, 76)`). Disclosing this exposes one message and nothing else.
///
/// # Panics
///
/// Never in practice: the conversation key is a valid 32-byte PRK.
#[must_use]
pub fn message_keys(conversation_key: &[u8; 32], nonce: &[u8; 32]) -> MessageKeys {
    let mut okm = [0_u8; 76];
    Hkdf::<Sha256>::from_prk(conversation_key)
        .expect("32 bytes is a valid PRK")
        .expand(nonce, &mut okm)
        .expect("76 bytes is a valid HKDF-SHA256 output length");
    let mut keys = MessageKeys {
        chacha_key: [0; 32],
        chacha_nonce: [0; 12],
        hmac_key: [0; 32],
    };
    keys.chacha_key.copy_from_slice(&okm[..32]);
    keys.chacha_nonce.copy_from_slice(&okm[32..44]);
    keys.hmac_key.copy_from_slice(&okm[44..]);
    keys
}

/// Padded plaintext length: 32 up to 32, then chunked by a power-of-two rule.
#[must_use]
pub fn calc_padded_len(len: usize) -> usize {
    if len <= 32 {
        return 32;
    }
    let next_power = 1_usize << (usize::BITS - (len - 1).leading_zeros());
    let chunk = if next_power <= 256 {
        32
    } else {
        next_power / 8
    };
    chunk * ((len - 1) / chunk + 1)
}

fn pad(plaintext: &[u8]) -> Result<Vec<u8>, Nip44Error> {
    let len = plaintext.len();
    if !(MIN_PLAINTEXT..=MAX_PLAINTEXT).contains(&len) {
        return Err(Nip44Error::InvalidPlaintextLength);
    }
    let prefix = u16::try_from(len).map_err(|_| Nip44Error::InvalidPlaintextLength)?;
    let mut out = prefix.to_be_bytes().to_vec();
    out.extend_from_slice(plaintext);
    out.resize(2 + calc_padded_len(len), 0);
    Ok(out)
}

fn unpad(padded: &[u8]) -> Result<Vec<u8>, Nip44Error> {
    let (prefix, rest) = padded
        .split_at_checked(2)
        .ok_or(Nip44Error::InvalidPadding)?;
    let len = usize::from(u16::from_be_bytes([prefix[0], prefix[1]]));
    if len < MIN_PLAINTEXT || rest.len() != calc_padded_len(len) || len > rest.len() {
        return Err(Nip44Error::InvalidPadding);
    }
    Ok(rest[..len].to_vec())
}

fn mac(hmac_key: &[u8; 32], nonce: &[u8; 32], ciphertext: &[u8]) -> [u8; 32] {
    let mut mac =
        <Hmac<Sha256> as Mac>::new_from_slice(hmac_key).expect("HMAC accepts any key length");
    mac.update(nonce);
    mac.update(ciphertext);
    mac.finalize().into_bytes().into()
}

/// Encrypts with a caller-supplied nonce. Production callers pass 32 fresh
/// random bytes; the parameter exists so the official vectors are checkable.
///
/// # Errors
///
/// Returns [`Nip44Error::InvalidPlaintextLength`] outside 1..=65535 bytes.
pub fn encrypt_with_nonce(
    conversation_key: &[u8; 32],
    nonce: &[u8; 32],
    plaintext: &[u8],
) -> Result<String, Nip44Error> {
    let keys = message_keys(conversation_key, nonce);
    let mut buffer = pad(plaintext)?;
    ChaCha20::new(&keys.chacha_key.into(), &keys.chacha_nonce.into()).apply_keystream(&mut buffer);
    let tag = mac(&keys.hmac_key, nonce, &buffer);
    let mut payload = vec![VERSION];
    payload.extend_from_slice(nonce);
    payload.extend_from_slice(&buffer);
    payload.extend_from_slice(&tag);
    Ok(STANDARD.encode(payload))
}

/// Decrypts a payload, verifying the MAC in constant time before decrypting.
///
/// # Errors
///
/// Returns [`Nip44Error`] for a malformed payload, bad MAC, or bad padding.
pub fn decrypt(conversation_key: &[u8; 32], payload: &str) -> Result<Vec<u8>, Nip44Error> {
    // A leading '#' marks a non-base64 future version.
    if payload.is_empty() || payload.starts_with('#') || !(132..=87_472).contains(&payload.len()) {
        return Err(Nip44Error::InvalidPayload);
    }
    let data = STANDARD
        .decode(payload)
        .map_err(|_| Nip44Error::InvalidPayload)?;
    if !(99..=65_603).contains(&data.len()) || data[0] != VERSION {
        return Err(Nip44Error::InvalidPayload);
    }
    let nonce: [u8; 32] = data[1..33]
        .try_into()
        .map_err(|_| Nip44Error::InvalidPayload)?;
    let (ciphertext, tag) = data[33..].split_at(data.len() - 33 - 32);
    let keys = message_keys(conversation_key, &nonce);
    if !bool::from(mac(&keys.hmac_key, &nonce, ciphertext).ct_eq(tag)) {
        return Err(Nip44Error::InvalidMac);
    }
    let mut buffer = ciphertext.to_vec();
    ChaCha20::new(&keys.chacha_key.into(), &keys.chacha_nonce.into()).apply_keystream(&mut buffer);
    unpad(&buffer)
}
