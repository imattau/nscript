//! Deterministic reference runtime and host capability contracts.

use std::collections::{BTreeMap, BTreeSet};

use nscript_semantics::{CheckedProgram, CheckedPublication};
use nscript_syntax::Program;

pub type InvocationId = u64;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct UnsignedEvent {
    pub event_type: String,
    pub kind: u16,
    pub content: String,
    pub created_at: u64,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SignedEvent {
    pub unsigned: UnsignedEvent,
    pub signer: String,
    pub id: String,
    pub signature: String,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RelayOutcome {
    pub relay: String,
    pub accepted: bool,
    pub detail: String,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PublishReport {
    pub outcomes: Vec<RelayOutcome>,
}

impl PublishReport {
    #[must_use]
    pub fn accepted(&self) -> bool {
        self.outcomes.iter().any(|outcome| outcome.accepted)
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum RuntimeError {
    CapabilityDenied { capability: String },
    SignerDenied { signer: String },
    RelayUnavailable { relayset: String },
    PublicationRejected,
    StoreConflict,
    Cancelled,
    ResourceLimit { resource: String },
    OperationUnavailable { module: String, operation: String },
    InvalidOperationArguments { operation: String },
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PrivateMessage {
    pub content: String,
    pub recipient: String,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum OperationValue {
    Text(String),
    PubKey(String),
    EncryptedText(String),
    GiftWrap(String),
    PrivateMessage(PrivateMessage),
    PublishReport(PublishReport),
}

pub trait OperationHost {
    /// Invoke a declared NIP module operation with typed values.
    ///
    /// # Errors
    ///
    /// Returns a capability, operation availability, or argument validation error.
    fn call(
        &mut self,
        invocation: InvocationId,
        module: &str,
        operation: &str,
        arguments: &[OperationValue],
    ) -> Result<OperationValue, RuntimeError>;
}

pub trait RelayHost {
    /// Publish a signed event through a named relay set.
    ///
    /// # Errors
    ///
    /// Returns a capability or relay availability error when publication cannot be attempted.
    fn publish(
        &mut self,
        invocation: InvocationId,
        event: &SignedEvent,
        relayset: &str,
    ) -> Result<PublishReport, RuntimeError>;
}

pub trait SignerHost {
    /// Sign an unsigned event using a named signer capability.
    ///
    /// # Errors
    ///
    /// Returns a capability or signer policy error when signing is denied.
    fn sign(
        &mut self,
        invocation: InvocationId,
        event: UnsignedEvent,
        signer: &str,
    ) -> Result<SignedEvent, RuntimeError>;
}

pub trait ClockHost {
    fn now(&self) -> u64;
}

pub trait AuditHost {
    fn record(&mut self, entry: AuditEntry);
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AuditEntry {
    pub invocation: InvocationId,
    pub operation: String,
    pub target: String,
    pub result: String,
}

pub trait StorageHost {
    fn begin(&mut self, invocation: InvocationId) -> StorageTransaction;
}

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct InMemoryStorage {
    pub values: BTreeMap<String, String>,
}

impl StorageHost for InMemoryStorage {
    fn begin(&mut self, _invocation: InvocationId) -> StorageTransaction {
        StorageTransaction::default()
    }
}

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct StorageTransaction {
    writes: BTreeMap<String, String>,
    committed: bool,
}

impl StorageTransaction {
    pub fn put(&mut self, key: impl Into<String>, value: impl Into<String>) {
        self.writes.insert(key.into(), value.into());
    }

    #[must_use]
    pub fn get(&self, key: &str) -> Option<&str> {
        self.writes.get(key).map(String::as_str)
    }

    pub fn commit(mut self) {
        self.committed = true;
    }

    /// Commit this transaction into an in-memory host.
    pub fn commit_to(mut self, storage: &mut InMemoryStorage) {
        storage.values.extend(self.writes);
        self.committed = true;
    }

    #[must_use]
    pub fn is_committed(&self) -> bool {
        self.committed
    }
}

pub struct Runtime<R, S, C, A> {
    pub relay: R,
    pub signer: S,
    pub clock: C,
    pub audit: A,
    next_invocation: InvocationId,
}

impl<R, S, C, A> Runtime<R, S, C, A>
where
    R: RelayHost,
    S: SignerHost,
    C: ClockHost,
    A: AuditHost,
{
    pub fn new(relay: R, signer: S, clock: C, audit: A) -> Self {
        Self {
            relay,
            signer,
            clock,
            audit,
            next_invocation: 1,
        }
    }

    /// Execute the checked program's effectful publication operations.
    ///
    /// # Errors
    ///
    /// Returns the first signer, relay, cancellation, or resource failure.
    pub fn run(
        &mut self,
        _program: &Program,
        checked: &CheckedProgram,
    ) -> Result<Vec<PublishReport>, RuntimeError> {
        let invocation = self.next_invocation;
        self.next_invocation += 1;
        let mut reports = Vec::new();
        for publication in &checked.publications {
            reports.push(self.execute_publication(invocation, publication)?);
        }
        Ok(reports)
    }

    /// Invoke a module operation through an approved host capability.
    ///
    /// # Errors
    ///
    /// Returns the host's typed operation failure.
    pub fn invoke_operation<H: OperationHost>(
        &mut self,
        host: &mut H,
        module: &str,
        operation: &str,
        arguments: &[OperationValue],
    ) -> Result<OperationValue, RuntimeError> {
        let invocation = self.next_invocation;
        self.next_invocation += 1;
        let result = host.call(invocation, module, operation, arguments);
        self.audit.record(AuditEntry {
            invocation,
            operation: format!("{module}.{operation}"),
            target: module.to_owned(),
            result: if result.is_ok() { "ok" } else { "error" }.to_owned(),
        });
        result
    }

    fn execute_publication(
        &mut self,
        invocation: InvocationId,
        publication: &CheckedPublication,
    ) -> Result<PublishReport, RuntimeError> {
        let unsigned = UnsignedEvent {
            event_type: publication.event.clone(),
            kind: match publication.event.as_str() {
                "Note" => 1,
                _ => 0,
            },
            content: publication.content.clone().unwrap_or_default(),
            created_at: self.clock.now(),
        };
        self.audit.record(AuditEntry {
            invocation,
            operation: "create_event".to_owned(),
            target: publication.event.clone(),
            result: "ok".to_owned(),
        });
        let signed = self
            .signer
            .sign(invocation, unsigned, &publication.signer)?;
        self.audit.record(AuditEntry {
            invocation,
            operation: "sign_event".to_owned(),
            target: publication.signer.clone(),
            result: "ok".to_owned(),
        });
        let report = self
            .relay
            .publish(invocation, &signed, &publication.relayset)?;
        self.audit.record(AuditEntry {
            invocation,
            operation: "publish_event".to_owned(),
            target: publication.relayset.clone(),
            result: if report.accepted() {
                "accepted"
            } else {
                "rejected"
            }
            .to_owned(),
        });
        if !report.accepted() {
            return Err(RuntimeError::PublicationRejected);
        }
        Ok(report)
    }
}

#[derive(Clone, Debug, Default)]
pub struct FakeRelayHost {
    pub relays: BTreeMap<String, bool>,
    pub published: Vec<SignedEvent>,
}

impl RelayHost for FakeRelayHost {
    fn publish(
        &mut self,
        _invocation: InvocationId,
        event: &SignedEvent,
        relayset: &str,
    ) -> Result<PublishReport, RuntimeError> {
        if self.relays.is_empty() {
            return Err(RuntimeError::RelayUnavailable {
                relayset: relayset.to_owned(),
            });
        }
        let outcomes = self
            .relays
            .iter()
            .map(|(relay, accepts)| RelayOutcome {
                relay: relay.clone(),
                accepted: *accepts,
                detail: if *accepts { "ok" } else { "rejected" }.to_owned(),
            })
            .collect::<Vec<_>>();
        if outcomes.iter().any(|outcome| outcome.accepted) {
            self.published.push(event.clone());
        }
        Ok(PublishReport { outcomes })
    }
}

#[derive(Clone, Debug, Default)]
pub struct FakeSignerHost {
    pub denied: BTreeSet<String>,
    pub signed: Vec<SignedEvent>,
}

impl SignerHost for FakeSignerHost {
    fn sign(
        &mut self,
        _invocation: InvocationId,
        event: UnsignedEvent,
        signer: &str,
    ) -> Result<SignedEvent, RuntimeError> {
        if self.denied.contains(signer) {
            return Err(RuntimeError::SignerDenied {
                signer: signer.to_owned(),
            });
        }
        let id = format!("fake:{}:{}", signer, self.signed.len());
        let signed_event = SignedEvent {
            unsigned: event,
            signer: signer.to_owned(),
            id: id.clone(),
            signature: format!("sig:{id}"),
        };
        self.signed.push(signed_event.clone());
        Ok(signed_event)
    }
}

#[derive(Clone, Copy, Debug, Default)]
pub struct FakeClock {
    pub now: u64,
}

impl ClockHost for FakeClock {
    fn now(&self) -> u64 {
        self.now
    }
}

#[derive(Clone, Debug, Default)]
pub struct RecordingAudit {
    pub entries: Vec<AuditEntry>,
}

#[derive(Clone, Debug, Default)]
pub struct FakeOperationHost {
    encrypted: BTreeMap<String, String>,
    wrapped: BTreeMap<String, String>,
    next_value: u64,
}

impl OperationHost for FakeOperationHost {
    fn call(
        &mut self,
        _invocation: InvocationId,
        module: &str,
        operation: &str,
        arguments: &[OperationValue],
    ) -> Result<OperationValue, RuntimeError> {
        match (module, operation) {
            ("nip44", "encrypt_text") => {
                let [
                    OperationValue::Text(text),
                    OperationValue::PubKey(recipient),
                ] = arguments
                else {
                    return Err(RuntimeError::InvalidOperationArguments {
                        operation: operation.to_owned(),
                    });
                };
                self.next_value += 1;
                let payload = format!("encrypted-{}", self.next_value);
                self.encrypted
                    .insert(payload.clone(), format!("{recipient}:{text}"));
                Ok(OperationValue::EncryptedText(payload))
            }
            ("nip44", "decrypt_text") => {
                let [
                    OperationValue::EncryptedText(payload),
                    OperationValue::PubKey(_sender),
                ] = arguments
                else {
                    return Err(RuntimeError::InvalidOperationArguments {
                        operation: operation.to_owned(),
                    });
                };
                let Some(value) = self.encrypted.get(payload) else {
                    return Err(RuntimeError::OperationUnavailable {
                        module: module.to_owned(),
                        operation: operation.to_owned(),
                    });
                };
                let (_, text) = value.split_once(':').unwrap_or(("", value));
                Ok(OperationValue::Text(text.to_owned()))
            }
            ("nip59", "gift_wrap") => {
                let [
                    OperationValue::EncryptedText(payload),
                    OperationValue::PubKey(recipient),
                ] = arguments
                else {
                    return Err(RuntimeError::InvalidOperationArguments {
                        operation: operation.to_owned(),
                    });
                };
                self.next_value += 1;
                let wrapped = format!("gift-wrap-{}", self.next_value);
                self.wrapped
                    .insert(wrapped.clone(), format!("{recipient}:{payload}"));
                Ok(OperationValue::GiftWrap(wrapped))
            }
            ("nip59", "open_gift_wrap") => {
                let [OperationValue::GiftWrap(wrapped)] = arguments else {
                    return Err(RuntimeError::InvalidOperationArguments {
                        operation: operation.to_owned(),
                    });
                };
                let Some(value) = self.wrapped.get(wrapped) else {
                    return Err(RuntimeError::OperationUnavailable {
                        module: module.to_owned(),
                        operation: operation.to_owned(),
                    });
                };
                let (_, payload) = value.split_once(':').unwrap_or(("", value));
                Ok(OperationValue::EncryptedText(payload.to_owned()))
            }
            ("nip17", "send_private") => {
                let [OperationValue::PrivateMessage(_message)] = arguments else {
                    return Err(RuntimeError::InvalidOperationArguments {
                        operation: operation.to_owned(),
                    });
                };
                Ok(OperationValue::PublishReport(PublishReport {
                    outcomes: vec![RelayOutcome {
                        relay: "fake://private".to_owned(),
                        accepted: true,
                        detail: "ok".to_owned(),
                    }],
                }))
            }
            _ => Err(RuntimeError::OperationUnavailable {
                module: module.to_owned(),
                operation: operation.to_owned(),
            }),
        }
    }
}

impl AuditHost for RecordingAudit {
    fn record(&mut self, entry: AuditEntry) {
        self.entries.push(entry);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use nscript_semantics::CheckedPublication;
    use nscript_syntax::Span;

    #[test]
    fn partial_publication_is_accepted_and_audited() {
        let checked = CheckedProgram {
            publications: vec![CheckedPublication {
                event: "Note".to_owned(),
                content: Some("hello".to_owned()),
                signer: "account".to_owned(),
                relayset: "public".to_owned(),
                span: Span::default(),
            }],
            ..CheckedProgram::default()
        };
        let mut relay = FakeRelayHost::default();
        relay.relays.insert("good".to_owned(), true);
        relay.relays.insert("bad".to_owned(), false);
        let mut runtime = Runtime::new(
            relay,
            FakeSignerHost::default(),
            FakeClock { now: 42 },
            RecordingAudit::default(),
        );
        let program = nscript_syntax::parse_program(
            "publish Note { content: \"hello\" } to public with account",
        )
        .0;
        let reports = runtime.run(&program, &checked).expect("one relay accepted");
        assert_eq!(reports[0].outcomes.len(), 2);
        assert_eq!(runtime.audit.entries.len(), 3);
    }

    #[test]
    fn signer_denial_prevents_publication() {
        let checked = CheckedProgram {
            publications: vec![CheckedPublication {
                event: "Note".to_owned(),
                content: Some("hello".to_owned()),
                signer: "account".to_owned(),
                relayset: "public".to_owned(),
                span: Span::default(),
            }],
            ..CheckedProgram::default()
        };
        let mut signer = FakeSignerHost::default();
        signer.denied.insert("account".to_owned());
        let mut relay = FakeRelayHost::default();
        relay.relays.insert("good".to_owned(), true);
        let mut runtime = Runtime::new(
            relay,
            signer,
            FakeClock::default(),
            RecordingAudit::default(),
        );
        let program = nscript_syntax::parse_program(
            "publish Note { content: \"hello\" } to public with account",
        )
        .0;
        assert!(matches!(
            runtime.run(&program, &checked),
            Err(RuntimeError::SignerDenied { .. })
        ));
        assert!(runtime.relay.published.is_empty());
    }

    #[test]
    fn storage_mutations_commit_or_roll_back_as_a_unit() {
        let mut storage = InMemoryStorage::default();
        let mut committed = storage.begin(1);
        committed.put("seen", "event-1");
        committed.commit_to(&mut storage);
        assert_eq!(
            storage.values.get("seen").map(String::as_str),
            Some("event-1")
        );

        let mut rolled_back = storage.begin(2);
        rolled_back.put("seen", "event-2");
        drop(rolled_back);
        assert_eq!(
            storage.values.get("seen").map(String::as_str),
            Some("event-1")
        );
    }

    #[test]
    fn nip_operations_preserve_typed_boundaries() {
        let mut runtime = Runtime::new(
            FakeRelayHost::default(),
            FakeSignerHost::default(),
            FakeClock::default(),
            RecordingAudit::default(),
        );
        let mut host = FakeOperationHost::default();
        let encrypted = runtime
            .invoke_operation(
                &mut host,
                "nip44",
                "encrypt_text",
                &[
                    OperationValue::Text("secret".to_owned()),
                    OperationValue::PubKey("alice".to_owned()),
                ],
            )
            .expect("encryption host available");
        assert!(matches!(encrypted, OperationValue::EncryptedText(_)));
        let wrapped = runtime
            .invoke_operation(
                &mut host,
                "nip59",
                "gift_wrap",
                &[encrypted, OperationValue::PubKey("alice".to_owned())],
            )
            .expect("gift-wrap host available");
        assert!(matches!(wrapped, OperationValue::GiftWrap(_)));
        let message = runtime
            .invoke_operation(
                &mut host,
                "nip17",
                "send_private",
                &[OperationValue::PrivateMessage(PrivateMessage {
                    content: "hello".to_owned(),
                    recipient: "alice".to_owned(),
                })],
            )
            .expect("private-message host available");
        assert!(matches!(message, OperationValue::PublishReport(report) if report.accepted()));
        assert_eq!(runtime.audit.entries.len(), 3);
    }
}
