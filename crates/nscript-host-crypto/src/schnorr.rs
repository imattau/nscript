//! BIP-340 Schnorr signatures over secp256k1, as Nostr uses for event ids.

use k256::schnorr::{Signature, SigningKey, VerifyingKey};

use crate::group_key::CryptoError;

/// Signs `message` with BIP-340. `aux_rand` is 32 fresh random bytes in
/// production ([`sign_random`]); it is a parameter so the official vectors
/// are checkable.
///
/// # Errors
///
/// Returns [`CryptoError::InvalidKey`] for an invalid secret key.
pub fn sign(
    secret: &[u8; 32],
    message: &[u8],
    aux_rand: &[u8; 32],
) -> Result<[u8; 64], CryptoError> {
    let key = SigningKey::from_bytes(secret).map_err(|_| CryptoError::InvalidKey)?;
    let signature = key
        .sign_raw(message, aux_rand)
        .map_err(|_| CryptoError::InvalidKey)?;
    Ok(signature.to_bytes())
}

/// Signs with fresh OS randomness as auxiliary data.
///
/// # Errors
///
/// Returns [`CryptoError::InvalidKey`] for an invalid secret key, or
/// [`CryptoError::RandomUnavailable`] if the OS RNG fails.
pub fn sign_random(secret: &[u8; 32], message: &[u8]) -> Result<[u8; 64], CryptoError> {
    sign(secret, message, &crate::random32()?)
}

/// Verifies a BIP-340 signature against an x-only public key. Any invalid
/// key or signature simply fails verification.
#[must_use]
pub fn verify(pubkey: &[u8; 32], message: &[u8], signature: &[u8; 64]) -> bool {
    let Ok(key) = VerifyingKey::from_bytes(pubkey) else {
        return false;
    };
    let Ok(signature) = Signature::try_from(signature.as_slice()) else {
        return false;
    };
    key.verify_raw(message, &signature).is_ok()
}
