//! Real [`ConcordKeyHost`]: `group_key` derivation behind the capability gate.

use std::time::{SystemTime, UNIX_EPOCH};

use nscript_runtime::expiry::{expiration_tag, rumor_expiration};
use nscript_runtime::stream::GroupKeyLabel;
use nscript_runtime::{
    ConcordKeyHost, DerivedKey, InvocationId, OperationHost, OperationValue, PublishReport,
    RelayHost, RuntimeError, SealedEvent, SharedSecret, SignedBytes, SignedEvent, StreamHandle,
    StreamWrap, UnsignedEvent,
};

use crate::group_key::{group_key, hex, xonly_pubkey};
use crate::nip44::conversation_key;
use crate::stream::{SealForm, build_seal, build_wrap, open_seal, open_wrap, rumor, seal_form};

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
    publisher: Option<(PublishTarget, Box<dyn RelayHost>)>,
}

/// Where `publish_message` sends: one Channel of one Community.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PublishTarget {
    /// 64-hex Channel id, committed in the rumor's `channel` tag (CORD-03 §3).
    pub channel_id: String,
    /// The key epoch the Channel's key was derived at (the `epoch` tag).
    pub epoch: u64,
    /// The Community's `message_expiration` in seconds; `None` = off (CORD-08).
    pub timer: Option<u64>,
    /// Relay set name reported to the relay host.
    pub relayset: String,
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
            publisher: None,
        }
    }

    /// Enables `publish_message`, sending to `target` through `relays`. The
    /// relay host is the runtime's own (`RealRelayPool` in production).
    #[must_use]
    pub fn with_publisher(mut self, target: PublishTarget, relays: Box<dyn RelayHost>) -> Self {
        self.publisher = Some((target, relays));
        self
    }

    fn now_millis_part(&self) -> u64 {
        if self.fixed_time.is_some() {
            return 0;
        }
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_or(0, |elapsed| u64::from(elapsed.subsec_millis()))
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

/// Converts a serialised kind-1059 event into the runtime's [`SignedEvent`].
pub(crate) fn signed_event_from_wire(wire: &str) -> Option<SignedEvent> {
    let event: serde_json::Value = serde_json::from_str(wire).ok()?;
    let text = |name: &str| event.get(name)?.as_str().map(str::to_owned);
    let tags = event
        .get("tags")?
        .as_array()?
        .iter()
        .map(|tag| {
            let tag = tag.as_array()?;
            match tag.as_slice() {
                [name, value] => Some((name.as_str()?.to_owned(), value.as_str()?.to_owned())),
                _ => None,
            }
        })
        .collect::<Option<Vec<_>>>()?;
    Some(SignedEvent {
        unsigned: UnsignedEvent {
            event_type: "StreamWrap".to_owned(),
            kind: u16::try_from(event.get("kind")?.as_u64()?).ok()?,
            content: text("content")?,
            tags,
            created_at: event.get("created_at")?.as_u64()?,
        },
        signer: text("pubkey")?,
        id: text("id")?,
        signature: text("sig")?,
    })
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

    /// Builds and publishes a kind-9 message. The author must be the host's
    /// own identity: a script cannot publish as anyone else.
    fn publish_message(
        &mut self,
        plane: &Plane,
        message: &nscript_runtime::StreamMessage,
    ) -> Option<PublishReport> {
        let me = hex(&xonly_pubkey(&self.author_secret).ok()?);
        if message.author != me || message.content.is_empty() {
            return None;
        }
        let created_at = self.now();
        let outer: Vec<Vec<String>> = {
            let (target, _) = self.publisher.as_ref()?;
            expiration_tag(9, created_at, target.timer)
                .into_iter()
                .collect()
        };
        let (target, _) = self.publisher.as_ref()?;
        // CORD-03 §3 binding plus the sub-second `ms` tag (CORD-02 §4).
        let mut tags = vec![
            serde_json::json!(["channel", target.channel_id]),
            serde_json::json!(["epoch", target.epoch.to_string()]),
            serde_json::json!(["ms", self.now_millis_part().to_string()]),
        ];
        tags.extend(outer.iter().map(|tag| serde_json::json!(tag)));
        let rumor = rumor(
            &self.author_secret,
            9,
            &serde_json::Value::Array(tags),
            &message.content,
            created_at,
        )
        .ok()?;
        let seal = build_seal(
            &plane.conv,
            SealForm::Encrypted,
            &self.author_secret,
            &rumor.to_string(),
            created_at,
        )
        .ok()?;
        let wire = build_wrap(&plane.secret, &plane.conv, &seal, &outer, created_at).ok()?;
        let event = signed_event_from_wire(&wire)?;
        let relayset = self.publisher.as_ref()?.0.relayset.clone();
        let (_, relays) = self.publisher.as_mut()?;
        relays.publish(1, &event, &relayset).ok()
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
            ("stream", [OperationValue::DerivedKey(k)]) => plane(k).map(|p| {
                // The handle is the plane's public address only: safe to print
                // or pass around, and it carries no key material.
                OperationValue::StreamHandle(StreamHandle {
                    address: hex(&p.pubkey),
                })
            }),
            ("unwrap_stream", [OperationValue::DerivedKey(k), OperationValue::StreamWrap(w)]) => {
                plane(k)
                    .and_then(|p| Self::unwrap_event(&p, w))
                    .map(OperationValue::SealedEvent)
            }
            (
                "publish_message",
                [
                    OperationValue::DerivedKey(k),
                    OperationValue::StreamMessage(m),
                ],
            ) if self.publisher.is_some() => plane(k)
                .and_then(|p| self.publish_message(&p, m))
                .map(OperationValue::PublishReport),
            // An operation this host implements, called with the wrong
            // arguments, is a mistake in the call and says so.
            (
                "seal_message"
                | "seal_control_message"
                | "open_message"
                | "wrap_stream"
                | "unwrap_stream"
                | "stream",
                _,
            ) => return Err(invalid()),
            ("publish_message", _) if self.publisher.is_some() => return Err(invalid()),
            // Deriving keys is the key host's job; without a configured
            // publisher there is nowhere to send.
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
