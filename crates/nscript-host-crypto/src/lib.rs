//! Production cryptography behind the `NScript` Concord host contracts.
//!
//! Kept out of `nscript-runtime` so the core stays dependency-light: only a
//! host that wants real keys pulls these crates in.

pub mod group_key;
pub mod host;
pub mod nip44;
