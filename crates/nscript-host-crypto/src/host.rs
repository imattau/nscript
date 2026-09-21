//! Real [`ConcordKeyHost`]: `group_key` derivation behind the capability gate.

use nscript_runtime::stream::GroupKeyLabel;
use nscript_runtime::{ConcordKeyHost, DerivedKey, InvocationId, RuntimeError, SharedSecret};

use crate::group_key::group_key;

/// Derives plane keys with the protocol's approved algorithm.
///
/// The derived key's secret scalar is held in an opaque, debug-redacted
/// [`DerivedKey`]; scripts never see it.
#[derive(Clone, Debug, Default)]
pub struct Nip44KeyHost {
    pub denied: bool,
    pub derivations: usize,
}

fn unhex32(text: &str) -> Option<[u8; 32]> {
    if text.len() != 64 || !text.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f')) {
        return None;
    }
    let mut out = [0_u8; 32];
    for (slot, pair) in out.iter_mut().zip(text.as_bytes().chunks(2)) {
        *slot = u8::from_str_radix(std::str::from_utf8(pair).ok()?, 16).ok()?;
    }
    Some(out)
}

impl ConcordKeyHost for Nip44KeyHost {
    /// CORD-01/02 define no bare "stream key from a secret" derivation: every
    /// plane key comes from [`ConcordKeyHost::derive_group_key`], which binds a
    /// label, id and epoch. The fake host keeps this operation for tests only.
    fn derive_stream_key(
        &mut self,
        _invocation: InvocationId,
        _secret: &SharedSecret,
    ) -> Result<DerivedKey, RuntimeError> {
        Err(RuntimeError::OperationUnavailable {
            module: "concord01".to_owned(),
            operation: "derive_stream_key".to_owned(),
        })
    }

    fn derive_group_key(
        &mut self,
        _invocation: InvocationId,
        label: GroupKeyLabel,
        secret: &SharedSecret,
        id: &str,
        epoch: u64,
    ) -> Result<DerivedKey, RuntimeError> {
        if self.denied {
            return Err(RuntimeError::CapabilityDenied {
                capability: "concord_key_derivation".to_owned(),
            });
        }
        let id = unhex32(id).ok_or_else(|| RuntimeError::InvalidOperationArguments {
            operation: "derive_group_key".to_owned(),
        })?;
        let key = group_key(label.as_str(), secret.as_bytes(), &id, Some(epoch));
        self.derivations += 1;
        DerivedKey::new(key.secret_bytes().to_vec())
    }
}
