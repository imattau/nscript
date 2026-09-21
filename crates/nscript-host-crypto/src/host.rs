//! Real [`ConcordKeyHost`]: `group_key` derivation behind the capability gate.

use std::time::{SystemTime, UNIX_EPOCH};

use nscript_runtime::expiry::rumor_expiration;
use nscript_runtime::stream::GroupKeyLabel;
use nscript_runtime::{
    ConcordKeyHost, DerivedKey, InvocationId, OperationHost, OperationValue, RuntimeError,
    SealedEvent, SharedSecret, SignedBytes, StreamWrap,
};

use crate::group_key::{group_key, xonly_pubkey};
use crate::nip44::conversation_key;
use crate::stream::{SealForm, build_seal, build_wrap, open_seal, open_wrap, seal_form};

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

/// Real `concord01` seal, wrap and open operations.
///
/// A [`DerivedKey`] here is a plane's secret key from
/// [`ConcordKeyHost::derive_group_key`]. The author's real key stays inside
/// the host: scripts hold only opaque values, never key material. In
/// production the author signature would come from a NIP-46 signer; a local
/// key stands in for it here.
///
/// Planes whose signer and read key differ (the Control Plane's write-restricted
/// split) need two keys and are not yet expressible through one [`DerivedKey`].
pub struct Nip44OperationHost {
    author_secret: [u8; 32],
    /// Fixed clock for tests; the system clock when `None`.
    pub fixed_time: Option<u64>,
}

impl std::fmt::Debug for Nip44OperationHost {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("Nip44OperationHost")
            .finish_non_exhaustive()
    }
}

impl Nip44OperationHost {
    #[must_use]
    pub fn new(author_secret: [u8; 32]) -> Self {
        Self {
            author_secret,
            fixed_time: None,
        }
    }

    fn now(&self) -> u64 {
        self.fixed_time.unwrap_or_else(|| {
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .map_or(0, |elapsed| elapsed.as_secs())
        })
    }
}

/// A plane's secret, x-only public key and NIP-44 conversation key.
struct Plane {
    secret: [u8; 32],
    pubkey: [u8; 32],
    conv: [u8; 32],
}

fn plane(key: &DerivedKey) -> Option<Plane> {
    let secret: [u8; 32] = key.as_bytes().try_into().ok()?;
    let pubkey = xonly_pubkey(&secret).ok()?;
    let conv = conversation_key(&secret, &pubkey).ok()?;
    Some(Plane {
        secret,
        pubkey,
        conv,
    })
}

impl Nip44OperationHost {
    fn seal(&self, plane: &Plane, rumor: &SignedBytes, form: SealForm) -> Option<SealedEvent> {
        let rumor = std::str::from_utf8(rumor.as_bytes()).ok()?;
        let seal = build_seal(&plane.conv, form, &self.author_secret, rumor, self.now()).ok()?;
        match form {
            SealForm::Encrypted => SealedEvent::new(seal.into_bytes()),
            SealForm::Plaintext => SealedEvent::plaintext(seal.into_bytes()),
        }
        .ok()
    }

    fn open(plane: &Plane, sealed: &SealedEvent) -> Option<SignedBytes> {
        let seal = std::str::from_utf8(sealed.as_bytes()).ok()?;
        let opened = open_seal(&plane.conv, seal_form(seal).ok()?, seal).ok()?;
        SignedBytes::new(opened.rumor_json.into_bytes()).ok()
    }

    fn wrap(&self, plane: &Plane, sealed: &SealedEvent) -> Option<StreamWrap> {
        let seal = std::str::from_utf8(sealed.as_bytes()).ok()?;
        // CORD-08: a chat wrap carries its rumor's expiration too, so relays
        // can delete the ciphertext. Only encrypted seals are chat; the host
        // can read the rumor because it holds the plane key.
        let mut outer = Vec::new();
        if seal_form(seal).ok()? == SealForm::Encrypted {
            let rumor = open_seal(&plane.conv, SealForm::Encrypted, seal).ok()?;
            let value: serde_json::Value = serde_json::from_str(&rumor.rumor_json).ok()?;
            let expiration = value
                .get("tags")
                .and_then(serde_json::Value::as_array)
                .and_then(|tags| rumor_expiration(tags));
            if let Some(at) = expiration {
                outer.push(vec!["expiration".to_owned(), at.to_string()]);
            }
        }
        let wire = build_wrap(&plane.secret, &plane.conv, seal, &outer, self.now()).ok()?;
        let mut wrap = StreamWrap::from_wire(&wire).ok()?;
        wrap.sealed = Some(sealed.clone());
        Some(wrap)
    }

    fn unwrap_event(plane: &Plane, wrap: &StreamWrap) -> Option<SealedEvent> {
        let seal = open_wrap(&plane.pubkey, &plane.conv, wrap.wire.as_deref()?).ok()?;
        let form = seal_form(&seal).ok()?;
        match form {
            SealForm::Encrypted => SealedEvent::new(seal.into_bytes()),
            SealForm::Plaintext => SealedEvent::plaintext(seal.into_bytes()),
        }
        .ok()
    }
}

impl OperationHost for Nip44OperationHost {
    fn call(
        &mut self,
        _invocation: InvocationId,
        module: &str,
        operation: &str,
        arguments: &[OperationValue],
    ) -> Result<OperationValue, RuntimeError> {
        let invalid = || RuntimeError::InvalidOperationArguments {
            operation: operation.to_owned(),
        };
        if module != "concord01" {
            return Err(RuntimeError::OperationUnavailable {
                module: module.to_owned(),
                operation: operation.to_owned(),
            });
        }
        let result = match (operation, arguments) {
            (
                "seal_message",
                [
                    OperationValue::DerivedKey(k),
                    OperationValue::SignedBytes(r),
                ],
            ) => plane(k)
                .and_then(|p| self.seal(&p, r, SealForm::Encrypted))
                .map(OperationValue::SealedEvent),
            (
                "seal_control_message",
                [
                    OperationValue::DerivedKey(k),
                    OperationValue::SignedBytes(r),
                ],
            ) => plane(k)
                .and_then(|p| self.seal(&p, r, SealForm::Plaintext))
                .map(OperationValue::SealedEvent),
            (
                "open_message",
                [
                    OperationValue::DerivedKey(k),
                    OperationValue::SealedEvent(s),
                ],
            ) => plane(k)
                .and_then(|p| Self::open(&p, s))
                .map(OperationValue::SignedBytes),
            (
                "wrap_stream",
                [
                    OperationValue::DerivedKey(k),
                    OperationValue::SealedEvent(s),
                ],
            ) => plane(k)
                .and_then(|p| self.wrap(&p, s))
                .map(OperationValue::StreamWrap),
            ("unwrap_stream", [OperationValue::DerivedKey(k), OperationValue::StreamWrap(w)]) => {
                plane(k)
                    .and_then(|p| Self::unwrap_event(&p, w))
                    .map(OperationValue::SealedEvent)
            }
            // Deriving keys is the key host's job; publishing needs a relay
            // host and policy, which the fake operation host models.
            _ => {
                return Err(RuntimeError::OperationUnavailable {
                    module: module.to_owned(),
                    operation: operation.to_owned(),
                });
            }
        };
        result.ok_or_else(invalid)
    }
}
