//! CORD-02 Appendix A key derivation: HKDF, `scalar_normalize`, x-only keys.

use hkdf::Hkdf;
use k256::{
    NonZeroScalar, PublicKey, SecretKey, ecdh::diffie_hellman, elliptic_curve::sec1::ToEncodedPoint,
};
use sha2::Sha256;

#[derive(Debug, Eq, PartialEq)]
pub enum CryptoError {
    /// Not a valid secp256k1 secret key or x-only public key.
    InvalidKey,
    InvalidLength,
    /// The operating system's random number generator failed.
    RandomUnavailable,
}

/// A Stream/plane keypair from `group_key` (CORD-02 A.2). The secret never
/// leaves this type except through the explicit accessors.
pub struct GroupKey {
    secret: SecretKey,
}

impl std::fmt::Debug for GroupKey {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("GroupKey")
            .field("pk", &hex(&self.xonly_pubkey()))
            .finish()
    }
}

/// `hkdf(secret, label, id, epoch)`: HKDF-SHA256, empty salt, `info = utf8(label)
/// || 0x00 || id[32] || epoch_be[8]` (epoch omitted when `None`), 32 bytes.
/// `counter` is the `scalar_normalize` retry byte appended after every field.
fn hkdf32(
    secret: &[u8],
    label: &str,
    id: &[u8; 32],
    epoch: Option<u64>,
    counter: Option<u8>,
) -> [u8; 32] {
    let mut info = label.as_bytes().to_vec();
    info.push(0);
    info.extend_from_slice(id);
    if let Some(epoch) = epoch {
        info.extend_from_slice(&epoch.to_be_bytes());
    }
    if let Some(counter) = counter {
        info.push(counter);
    }
    let mut okm = [0_u8; 32];
    Hkdf::<Sha256>::new(None, secret)
        .expand(&info, &mut okm)
        .expect("32 bytes is a valid HKDF-SHA256 output length");
    okm
}

/// A keyless coordinate: plain `hkdf(secret, label, id, epoch)` with no
/// `scalar_normalize` (CORD-02 A.1, A.6), e.g. `concord/grant`.
#[must_use]
pub fn coordinate(secret: &[u8], label: &str, id: &[u8; 32], epoch: Option<u64>) -> [u8; 32] {
    hkdf32(secret, label, id, epoch, None)
}

/// `group_key(label, secret, id, epoch)` with CORD-02 A.3 `scalar_normalize`:
/// if the seed is not a valid scalar, append an incrementing counter byte
/// (starting at 0) to the HKDF `info` and retry.
#[must_use]
pub fn group_key(label: &str, secret: &[u8], id: &[u8; 32], epoch: Option<u64>) -> GroupKey {
    for counter in std::iter::once(None).chain((0..=u8::MAX).map(Some)) {
        let seed = hkdf32(secret, label, id, epoch, counter);
        if let Ok(secret) = SecretKey::from_slice(&seed) {
            return GroupKey { secret };
        }
    }
    // The reject branch is ~2^-128 rare; 257 consecutive rejects cannot occur.
    unreachable!("scalar_normalize exhausted its retry counter")
}

impl GroupKey {
    /// The 32-byte x-only public key: the plane's on-wire address.
    #[must_use]
    pub fn xonly_pubkey(&self) -> [u8; 32] {
        xonly(&self.secret.public_key())
    }

    /// The secret scalar bytes. Handle as key material.
    #[must_use]
    pub fn secret_bytes(&self) -> [u8; 32] {
        self.secret.to_bytes().into()
    }

    /// NIP-44 self-ECDH conversation key: encrypts the wrap.
    ///
    /// # Panics
    ///
    /// Never: a key's own public key is always a valid point.
    #[must_use]
    pub fn conversation_key(&self) -> [u8; 32] {
        crate::nip44::conversation_key(&self.secret_bytes(), &self.xonly_pubkey())
            .expect("a key's own public key is valid")
    }
}

fn xonly(key: &PublicKey) -> [u8; 32] {
    let point = key.to_encoded_point(true);
    let mut out = [0_u8; 32];
    out.copy_from_slice(&point.as_bytes()[1..33]);
    out
}

/// Lifts an x-only key to the even-Y point BIP-340 and NIP-44 both use.
pub(crate) fn lift_xonly(x: &[u8; 32]) -> Result<PublicKey, CryptoError> {
    let mut compressed = [0_u8; 33];
    compressed[0] = 0x02;
    compressed[1..].copy_from_slice(x);
    PublicKey::from_sec1_bytes(&compressed).map_err(|_| CryptoError::InvalidKey)
}

/// The ECDH shared x-coordinate between `secret` and an x-only `public` key.
pub(crate) fn shared_x(secret: &[u8; 32], public: &[u8; 32]) -> Result<[u8; 32], CryptoError> {
    let scalar = SecretKey::from_slice(secret).map_err(|_| CryptoError::InvalidKey)?;
    let scalar = NonZeroScalar::from(&scalar);
    let point = lift_xonly(public)?;
    let shared = diffie_hellman(scalar, point.as_affine());
    let mut out = [0_u8; 32];
    out.copy_from_slice(shared.raw_secret_bytes());
    Ok(out)
}

/// x-only public key of a secret key.
///
/// # Errors
///
/// Returns [`CryptoError::InvalidKey`] for an invalid scalar.
pub fn xonly_pubkey(secret: &[u8; 32]) -> Result<[u8; 32], CryptoError> {
    let key = SecretKey::from_slice(secret).map_err(|_| CryptoError::InvalidKey)?;
    Ok(xonly(&key.public_key()))
}

/// 32 fresh random bytes as lowercase hex (ids such as a snapshot id).
pub(crate) fn random32_hex() -> Result<String, CryptoError> {
    Ok(hex(&crate::random32()?))
}

pub(crate) fn hex(bytes: &[u8]) -> String {
    use std::fmt::Write as _;
    bytes.iter().fold(String::new(), |mut out, byte| {
        let _ = write!(out, "{byte:02x}");
        out
    })
}
