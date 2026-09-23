//! Production cryptography behind the `NScript` Concord host contracts.
//!
//! Kept out of `nscript-runtime` so the core stays dependency-light: only a
//! host that wants real keys pulls these crates in.

pub mod group_key;
pub mod host;
pub mod moderation;
pub mod nip44;
pub mod nip46;
pub mod reader;
pub mod refound;
pub mod rekey;
pub mod schnorr;
pub mod stream;
pub mod voice;

/// 32 bytes from the operating system's random number generator.
///
/// # Errors
///
/// Returns [`group_key::CryptoError::RandomUnavailable`] if the RNG fails.
pub fn random32() -> Result<[u8; 32], group_key::CryptoError> {
    let mut bytes = [0_u8; 32];
    getrandom::fill(&mut bytes).map_err(|_| group_key::CryptoError::RandomUnavailable)?;
    Ok(bytes)
}
