//! Deterministic reference runtime and host capability contracts.

use std::collections::{BTreeMap, BTreeSet};

use nscript_semantics::{CheckedArgument, CheckedProgram, CheckedPublication};
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

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum FunctionValue {
    Text(String),
    Npub(String),
    PubKey(String),
}

pub trait PureFunctionHost {
    /// Evaluate a declared pure module function without host side effects.
    ///
    /// # Errors
    ///
    /// Returns an invalid-input or unavailable-function error.
    fn call_function(
        &mut self,
        module: &str,
        function: &str,
        arguments: &[FunctionValue],
    ) -> Result<FunctionValue, RuntimeError>;
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

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct OperationPolicy {
    allowed: BTreeSet<(String, String)>,
}

impl OperationPolicy {
    #[must_use]
    pub fn allow(mut self, module: impl Into<String>, operation: impl Into<String>) -> Self {
        self.allowed.insert((module.into(), operation.into()));
        self
    }

    #[must_use]
    pub fn permits(&self, module: &str, operation: &str) -> bool {
        self.allowed
            .contains(&(module.to_owned(), operation.to_owned()))
    }
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

    /// Invoke a module operation after checking the program capability policy.
    ///
    /// # Errors
    ///
    /// Returns `CapabilityDenied` when the operation was not approved, or the
    /// typed host failure for an approved operation.
    pub fn invoke_authorized_operation<H: OperationHost>(
        &mut self,
        policy: &OperationPolicy,
        host: &mut H,
        module: &str,
        operation: &str,
        arguments: &[OperationValue],
    ) -> Result<OperationValue, RuntimeError> {
        if !policy.permits(module, operation) {
            return Err(RuntimeError::CapabilityDenied {
                capability: format!("{module}.{operation}"),
            });
        }
        self.invoke_operation(host, module, operation, arguments)
    }

    /// Execute operation calls collected by static checking.
    ///
    /// # Errors
    ///
    /// Returns the first capability, argument, or host operation failure.
    pub fn run_operations<H: OperationHost>(
        &mut self,
        checked: &CheckedProgram,
        policy: &OperationPolicy,
        host: &mut H,
    ) -> Result<Vec<OperationValue>, RuntimeError> {
        checked
            .operation_calls
            .iter()
            .map(|call| {
                let arguments = call
                    .arguments
                    .iter()
                    .map(|argument| match argument {
                        CheckedArgument::Text(value) => OperationValue::Text(value.clone()),
                        CheckedArgument::PubKey(value) => OperationValue::PubKey(value.clone()),
                        CheckedArgument::PrivateMessage { content, recipient } => {
                            OperationValue::PrivateMessage(PrivateMessage {
                                content: content.clone(),
                                recipient: recipient.clone(),
                            })
                        }
                    })
                    .collect::<Vec<_>>();
                self.invoke_authorized_operation(
                    policy,
                    host,
                    &call.module,
                    &call.operation,
                    &arguments,
                )
            })
            .collect()
    }

    /// Invoke a pure module function through its typed host implementation.
    ///
    /// # Errors
    ///
    /// Returns the function host's validation or availability failure.
    pub fn invoke_function<H: PureFunctionHost>(
        &mut self,
        host: &mut H,
        module: &str,
        function: &str,
        arguments: &[FunctionValue],
    ) -> Result<FunctionValue, RuntimeError> {
        let result = host.call_function(module, function, arguments);
        self.audit.record(AuditEntry {
            invocation: self.next_invocation,
            operation: format!("{module}.{function}"),
            target: module.to_owned(),
            result: if result.is_ok() { "ok" } else { "error" }.to_owned(),
        });
        self.next_invocation += 1;
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

#[derive(Clone, Debug, Default)]
pub struct Nip19FunctionHost;

impl PureFunctionHost for Nip19FunctionHost {
    fn call_function(
        &mut self,
        module: &str,
        function: &str,
        arguments: &[FunctionValue],
    ) -> Result<FunctionValue, RuntimeError> {
        match (module, function, arguments) {
            ("nip19", "npub", [FunctionValue::Text(value)]) => {
                decode_npub(value).map(|_| FunctionValue::Npub(value.clone()))
            }
            ("nip19", "pubkey", [FunctionValue::Npub(value)]) => {
                decode_npub(value).map(FunctionValue::PubKey)
            }
            _ => Err(RuntimeError::OperationUnavailable {
                module: module.to_owned(),
                operation: function.to_owned(),
            }),
        }
    }
}

#[allow(clippy::format_collect)]
fn decode_npub(value: &str) -> Result<String, RuntimeError> {
    let (hrp, data) =
        bech32_decode(value).ok_or_else(|| RuntimeError::InvalidOperationArguments {
            operation: "nip19.npub".to_owned(),
        })?;
    if hrp != "npub" {
        return Err(RuntimeError::InvalidOperationArguments {
            operation: "nip19.npub".to_owned(),
        });
    }
    let bytes = convert_bits(&data, 5, 8, false).ok_or_else(|| {
        RuntimeError::InvalidOperationArguments {
            operation: "nip19.npub".to_owned(),
        }
    })?;
    if bytes.len() != 32 {
        return Err(RuntimeError::InvalidOperationArguments {
            operation: "nip19.npub".to_owned(),
        });
    }
    Ok(bytes.iter().map(|byte| format!("{byte:02x}")).collect())
}

fn bech32_decode(value: &str) -> Option<(String, Vec<u8>)> {
    if value.len() < 8
        || value
            .chars()
            .any(|character| character.is_ascii_uppercase())
    {
        return None;
    }
    let separator = value.rfind('1')?;
    let (hrp, encoded) = value.split_at(separator);
    let encoded = encoded.as_bytes().get(1..)?;
    let charset = "qpzry9x8gf2tvdw0s3jn54khce6mua7l";
    let values = encoded
        .iter()
        .map(|byte| {
            charset
                .as_bytes()
                .iter()
                .position(|item| item == byte)
                .and_then(|item| u8::try_from(item).ok())
        })
        .collect::<Option<Vec<_>>>()?;
    if values.len() < 6 || !bech32_verify(hrp.as_bytes(), &values) {
        return None;
    }
    Some((hrp.to_owned(), values[..values.len() - 6].to_vec()))
}

fn bech32_verify(hrp: &[u8], values: &[u8]) -> bool {
    let mut expanded = hrp.iter().map(|byte| byte >> 5).collect::<Vec<_>>();
    expanded.push(0);
    expanded.extend(hrp.iter().map(|byte| byte & 31));
    expanded.extend(values);
    bech32_polymod(&expanded) == 1
}

fn bech32_polymod(values: &[u8]) -> u32 {
    let generators = [
        0x3b6a_57b2_u32,
        0x2650_8e6d,
        0x1ea1_19fa,
        0x3d42_33dd,
        0x2a14_62b3,
    ];
    values.iter().fold(1_u32, |checksum, value| {
        let top = checksum >> 25;
        let mut next = (checksum & 0x1ff_ffff) << 5 ^ u32::from(*value);
        for (index, generator) in generators.iter().enumerate() {
            if (top >> index) & 1 == 1 {
                next ^= generator;
            }
        }
        next
    })
}

#[allow(clippy::cast_possible_truncation)]
fn convert_bits(data: &[u8], from: u8, to: u8, pad: bool) -> Option<Vec<u8>> {
    let mut accumulator = 0_u32;
    let mut bits = 0_u8;
    let max_value = (1_u32 << to) - 1;
    let max_accumulator = (1_u32 << (from + to - 1)) - 1;
    let mut output = Vec::new();
    for value in data {
        if (*value >> from) != 0 {
            return None;
        }
        accumulator = ((accumulator << from) | u32::from(*value)) & max_accumulator;
        bits += from;
        while bits >= to {
            bits -= to;
            output.push(((accumulator >> bits) & max_value) as u8);
        }
    }
    if pad {
        if bits > 0 {
            output.push(((accumulator << (to - bits)) & max_value) as u8);
        }
    } else if bits >= from || ((accumulator << (to - bits)) & max_value) != 0 {
        return None;
    }
    Some(output)
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

    #[test]
    fn undeclared_operation_is_denied_before_host_call() {
        let mut runtime = Runtime::new(
            FakeRelayHost::default(),
            FakeSignerHost::default(),
            FakeClock::default(),
            RecordingAudit::default(),
        );
        let mut host = FakeOperationHost::default();
        let policy = OperationPolicy::default().allow("nip44", "encrypt_text");
        let error = runtime
            .invoke_authorized_operation(&policy, &mut host, "nip44", "decrypt_text", &[])
            .expect_err("undeclared decrypt must be denied");
        assert_eq!(
            error,
            RuntimeError::CapabilityDenied {
                capability: "nip44.decrypt_text".to_owned()
            }
        );
        assert!(runtime.audit.entries.is_empty());
    }

    #[test]
    fn checked_source_calls_execute_through_operation_host() {
        let source = "let result = nip44.encrypt_text(\"secret\", alice)\n";
        let (program, parse_diagnostics) = nscript_syntax::parse_program(source);
        assert!(parse_diagnostics.is_empty());
        let (checked, diagnostics) = nscript_semantics::check(&program);
        assert!(diagnostics.is_empty());
        let checked = checked.expect("source is statically valid");
        assert_eq!(checked.operation_calls.len(), 1);

        let mut runtime = Runtime::new(
            FakeRelayHost::default(),
            FakeSignerHost::default(),
            FakeClock::default(),
            RecordingAudit::default(),
        );
        let mut host = FakeOperationHost::default();
        let values = runtime
            .run_operations(
                &checked,
                &OperationPolicy::default().allow("nip44", "encrypt_text"),
                &mut host,
            )
            .expect("authorized source call succeeds");
        assert!(matches!(
            values.first(),
            Some(OperationValue::EncryptedText(_))
        ));
    }

    #[test]
    fn nip19_decodes_npub_to_nominal_pubkey() {
        let mut runtime = Runtime::new(
            FakeRelayHost::default(),
            FakeSignerHost::default(),
            FakeClock::default(),
            RecordingAudit::default(),
        );
        let mut host = Nip19FunctionHost;
        let encoded = "npub1qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqzqujme";
        let npub = runtime
            .invoke_function(
                &mut host,
                "nip19",
                "npub",
                &[FunctionValue::Text(encoded.to_owned())],
            )
            .expect("valid npub");
        assert_eq!(npub, FunctionValue::Npub(encoded.to_owned()));
        let pubkey = runtime
            .invoke_function(&mut host, "nip19", "pubkey", &[npub])
            .expect("npub converts to pubkey");
        assert_eq!(pubkey, FunctionValue::PubKey("00".repeat(32)));
    }

    #[test]
    fn nip19_rejects_wrong_prefix_and_bad_checksum() {
        let mut host = Nip19FunctionHost;
        let wrong_prefix = host.call_function(
            "nip19",
            "npub",
            &[FunctionValue::Text(
                "nsec1qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqql5j8p".to_owned(),
            )],
        );
        assert!(wrong_prefix.is_err());
        let bad_checksum = host.call_function(
            "nip19",
            "npub",
            &[FunctionValue::Text(
                "npub1qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqzqujmx".to_owned(),
            )],
        );
        assert!(bad_checksum.is_err());
    }
}
