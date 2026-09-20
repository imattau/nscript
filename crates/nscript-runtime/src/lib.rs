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
pub struct ThreadReply {
    pub target: String,
    pub root: String,
    pub content: String,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Repost {
    pub target: String,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Comment {
    pub target: String,
    pub content: String,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Article {
    pub identifier: String,
    pub title: String,
    pub content: String,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct GroupMessage {
    pub group: String,
    pub content: String,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Label {
    pub target: String,
    pub namespace: String,
    pub value: String,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RelayList {
    pub read: Vec<String>,
    pub write: Vec<String>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AppData {
    pub identifier: String,
    pub content: String,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct FollowList {
    pub people: Vec<String>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Reaction {
    pub target: String,
    pub content: String,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DeletionRequest {
    pub target: String,
    pub reason: String,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct UserList {
    pub identifier: String,
    pub members: Vec<String>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ZapRequest {
    pub recipient: String,
    pub amount: i64,
    pub message: String,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PaymentIntent {
    pub recipient: String,
    pub amount: i64,
    pub invoice: String,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CalendarEvent {
    pub title: String,
    pub start: u64,
    pub end: u64,
    pub location: String,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RelayStatus {
    pub relay: String,
    pub uptime_percent: u8,
    pub latency_ms: i64,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SiteDeployment {
    pub domain: String,
    pub source: String,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum OperationValue {
    Text(String),
    Integer(i64),
    PubKey(String),
    Record {
        name: String,
        fields: Vec<(String, OperationValue)>,
    },
    EncryptedText(String),
    GiftWrap(String),
    PrivateMessage(PrivateMessage),
    ThreadReply(ThreadReply),
    Repost(Repost),
    Comment(Comment),
    Article(Article),
    GroupMessage(GroupMessage),
    Label(Label),
    RelayList(RelayList),
    AppData(AppData),
    FollowList(FollowList),
    Reaction(Reaction),
    DeletionRequest(DeletionRequest),
    UserList(UserList),
    ZapRequest(ZapRequest),
    PaymentIntent(PaymentIntent),
    CalendarEvent(CalendarEvent),
    RelayStatus(RelayStatus),
    SiteDeployment(SiteDeployment),
    PublishReport(PublishReport),
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum FunctionValue {
    Text(String),
    Npub(String),
    Nprofile(String),
    Nevent(String),
    Naddr(String),
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
                    .map(checked_to_operation)
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

fn checked_to_operation(argument: &CheckedArgument) -> OperationValue {
    match argument {
        CheckedArgument::Text(value) => OperationValue::Text(value.clone()),
        CheckedArgument::Integer(value) => OperationValue::Integer(*value),
        CheckedArgument::PubKey(value) => OperationValue::PubKey(value.clone()),
        CheckedArgument::Record { name, fields } => OperationValue::Record {
            name: name.clone(),
            fields: fields
                .iter()
                .map(|(field, value)| (field.clone(), checked_to_operation(value)))
                .collect(),
        },
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
            ("nip19", "nprofile", [FunctionValue::Text(value)]) => {
                validate_hrp(value, "nprofile").map(|_| FunctionValue::Nprofile(value.clone()))
            }
            ("nip19", "nevent", [FunctionValue::Text(value)]) => {
                validate_hrp(value, "nevent").map(|_| FunctionValue::Nevent(value.clone()))
            }
            ("nip19", "naddr", [FunctionValue::Text(value)]) => {
                validate_hrp(value, "naddr").map(|_| FunctionValue::Naddr(value.clone()))
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
    let bytes = validate_hrp(value, "npub")?;
    if bytes.len() != 32 {
        return Err(RuntimeError::InvalidOperationArguments {
            operation: "nip19.npub".to_owned(),
        });
    }
    Ok(bytes.iter().map(|byte| format!("{byte:02x}")).collect())
}

fn validate_hrp(value: &str, expected: &str) -> Result<Vec<u8>, RuntimeError> {
    let (hrp, data) =
        bech32_decode(value).ok_or_else(|| RuntimeError::InvalidOperationArguments {
            operation: format!("nip19.{expected}"),
        })?;
    if hrp != expected {
        return Err(RuntimeError::InvalidOperationArguments {
            operation: format!("nip19.{expected}"),
        });
    }
    convert_bits(&data, 5, 8, false).ok_or_else(|| RuntimeError::InvalidOperationArguments {
        operation: format!("nip19.{expected}"),
    })
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
    #[allow(clippy::too_many_lines)]
    fn call(
        &mut self,
        _invocation: InvocationId,
        module: &str,
        operation: &str,
        arguments: &[OperationValue],
    ) -> Result<OperationValue, RuntimeError> {
        let normalized = arguments.iter().map(normalize_record).collect::<Vec<_>>();
        let arguments = normalized.as_slice();
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
                let valid = match arguments {
                    [OperationValue::PrivateMessage(_)] => true,
                    [OperationValue::Record { name, fields }] if name == "PrivateMessage" => {
                        matches!(
                            fields.as_slice(),
                            [(content, OperationValue::Text(_)), (recipient, OperationValue::PubKey(_))]
                                if content == "content" && recipient == "recipient"
                        )
                    }
                    _ => false,
                };
                if !valid {
                    return Err(RuntimeError::InvalidOperationArguments {
                        operation: operation.to_owned(),
                    });
                }
                Ok(OperationValue::PublishReport(PublishReport {
                    outcomes: vec![RelayOutcome {
                        relay: "fake://private".to_owned(),
                        accepted: true,
                        detail: "ok".to_owned(),
                    }],
                }))
            }
            ("nip10", "publish_reply") => {
                let [OperationValue::ThreadReply(reply)] = arguments else {
                    return Err(RuntimeError::InvalidOperationArguments {
                        operation: operation.to_owned(),
                    });
                };
                if reply.target.is_empty() || reply.root.is_empty() || reply.content.is_empty() {
                    return Err(RuntimeError::InvalidOperationArguments {
                        operation: operation.to_owned(),
                    });
                }
                Ok(OperationValue::PublishReport(PublishReport {
                    outcomes: vec![RelayOutcome {
                        relay: "fake://replies".to_owned(),
                        accepted: true,
                        detail: "reply tags lowered".to_owned(),
                    }],
                }))
            }
            ("nip18", "publish_repost") => {
                let [OperationValue::Repost(repost)] = arguments else {
                    return Err(RuntimeError::InvalidOperationArguments {
                        operation: operation.to_owned(),
                    });
                };
                if repost.target.is_empty() {
                    return Err(RuntimeError::InvalidOperationArguments {
                        operation: operation.to_owned(),
                    });
                }
                Ok(OperationValue::PublishReport(PublishReport {
                    outcomes: vec![RelayOutcome {
                        relay: "fake://reposts".to_owned(),
                        accepted: true,
                        detail: "repost tag lowered".to_owned(),
                    }],
                }))
            }
            ("nip22", "publish_comment") => {
                let [OperationValue::Comment(comment)] = arguments else {
                    return Err(RuntimeError::InvalidOperationArguments {
                        operation: operation.to_owned(),
                    });
                };
                if comment.target.is_empty() || comment.content.is_empty() {
                    return Err(RuntimeError::InvalidOperationArguments {
                        operation: operation.to_owned(),
                    });
                }
                Ok(OperationValue::PublishReport(PublishReport {
                    outcomes: vec![RelayOutcome {
                        relay: "fake://comments".to_owned(),
                        accepted: true,
                        detail: "comment target lowered".to_owned(),
                    }],
                }))
            }
            ("nip23", "publish_article") => {
                let [OperationValue::Article(article)] = arguments else {
                    return Err(RuntimeError::InvalidOperationArguments {
                        operation: operation.to_owned(),
                    });
                };
                if article.identifier.is_empty()
                    || article.title.is_empty()
                    || article.content.is_empty()
                {
                    return Err(RuntimeError::InvalidOperationArguments {
                        operation: operation.to_owned(),
                    });
                }
                Ok(OperationValue::PublishReport(PublishReport {
                    outcomes: vec![RelayOutcome {
                        relay: "fake://articles".to_owned(),
                        accepted: true,
                        detail: "addressable article lowered".to_owned(),
                    }],
                }))
            }
            ("nip29", "publish_group_message") => {
                let [OperationValue::GroupMessage(message)] = arguments else {
                    return Err(RuntimeError::InvalidOperationArguments {
                        operation: operation.to_owned(),
                    });
                };
                if message.group.is_empty() || message.content.is_empty() {
                    return Err(RuntimeError::InvalidOperationArguments {
                        operation: operation.to_owned(),
                    });
                }
                Ok(OperationValue::PublishReport(PublishReport {
                    outcomes: vec![RelayOutcome {
                        relay: "fake://groups".to_owned(),
                        accepted: true,
                        detail: "group scope lowered".to_owned(),
                    }],
                }))
            }
            ("nip32", "publish_label") => {
                let [OperationValue::Label(label)] = arguments else {
                    return Err(RuntimeError::InvalidOperationArguments {
                        operation: operation.to_owned(),
                    });
                };
                if label.target.is_empty() || label.namespace.is_empty() || label.value.is_empty() {
                    return Err(RuntimeError::InvalidOperationArguments {
                        operation: operation.to_owned(),
                    });
                }
                Ok(OperationValue::PublishReport(PublishReport {
                    outcomes: vec![RelayOutcome {
                        relay: "fake://labels".to_owned(),
                        accepted: true,
                        detail: "label namespace/value lowered".to_owned(),
                    }],
                }))
            }
            ("nip65", "publish_relay_list") => {
                let [OperationValue::RelayList(_list)] = arguments else {
                    return Err(RuntimeError::InvalidOperationArguments {
                        operation: operation.to_owned(),
                    });
                };
                Ok(OperationValue::PublishReport(PublishReport {
                    outcomes: vec![RelayOutcome {
                        relay: "fake://relay-list".to_owned(),
                        accepted: true,
                        detail: "ok".to_owned(),
                    }],
                }))
            }
            ("nip78", "publish_app_data") => {
                let [OperationValue::AppData(_data)] = arguments else {
                    return Err(RuntimeError::InvalidOperationArguments {
                        operation: operation.to_owned(),
                    });
                };
                Ok(OperationValue::PublishReport(PublishReport {
                    outcomes: vec![RelayOutcome {
                        relay: "fake://app-data".to_owned(),
                        accepted: true,
                        detail: "ok".to_owned(),
                    }],
                }))
            }
            ("nip02", "publish_follow_list") => {
                let [OperationValue::FollowList(_list)] = arguments else {
                    return Err(RuntimeError::InvalidOperationArguments {
                        operation: operation.to_owned(),
                    });
                };
                Ok(OperationValue::PublishReport(PublishReport {
                    outcomes: vec![RelayOutcome {
                        relay: "fake://follows".to_owned(),
                        accepted: true,
                        detail: "ok".to_owned(),
                    }],
                }))
            }
            ("nip25", "publish_reaction") => {
                let [OperationValue::Reaction(_reaction)] = arguments else {
                    return Err(RuntimeError::InvalidOperationArguments {
                        operation: operation.to_owned(),
                    });
                };
                Ok(OperationValue::PublishReport(PublishReport {
                    outcomes: vec![RelayOutcome {
                        relay: "fake://reactions".to_owned(),
                        accepted: true,
                        detail: "ok".to_owned(),
                    }],
                }))
            }
            ("nip09", "request_deletion") => {
                let [OperationValue::DeletionRequest(_request)] = arguments else {
                    return Err(RuntimeError::InvalidOperationArguments {
                        operation: operation.to_owned(),
                    });
                };
                Ok(OperationValue::PublishReport(PublishReport {
                    outcomes: vec![RelayOutcome {
                        relay: "fake://deletion-requests".to_owned(),
                        accepted: true,
                        detail: "ok".to_owned(),
                    }],
                }))
            }
            ("nip51", "publish_user_list") => {
                let [OperationValue::UserList(_list)] = arguments else {
                    return Err(RuntimeError::InvalidOperationArguments {
                        operation: operation.to_owned(),
                    });
                };
                Ok(OperationValue::PublishReport(PublishReport {
                    outcomes: vec![RelayOutcome {
                        relay: "fake://lists".to_owned(),
                        accepted: true,
                        detail: "ok".to_owned(),
                    }],
                }))
            }
            ("nip57", "create_zap_request") => {
                let [OperationValue::ZapRequest(request)] = arguments else {
                    return Err(RuntimeError::InvalidOperationArguments {
                        operation: operation.to_owned(),
                    });
                };
                if request.amount <= 0 {
                    return Err(RuntimeError::InvalidOperationArguments {
                        operation: operation.to_owned(),
                    });
                }
                Ok(OperationValue::PaymentIntent(PaymentIntent {
                    recipient: request.recipient.clone(),
                    amount: request.amount,
                    invoice: format!("fake-invoice-{}", request.amount),
                }))
            }
            ("nip52", "publish_calendar_event") => {
                let [OperationValue::CalendarEvent(event)] = arguments else {
                    return Err(RuntimeError::InvalidOperationArguments {
                        operation: operation.to_owned(),
                    });
                };
                if event.end <= event.start {
                    return Err(RuntimeError::InvalidOperationArguments {
                        operation: operation.to_owned(),
                    });
                }
                Ok(OperationValue::PublishReport(PublishReport {
                    outcomes: vec![RelayOutcome {
                        relay: "fake://calendar".to_owned(),
                        accepted: true,
                        detail: "ok".to_owned(),
                    }],
                }))
            }
            ("nip66", "publish_relay_status") => {
                let [OperationValue::RelayStatus(status)] = arguments else {
                    return Err(RuntimeError::InvalidOperationArguments {
                        operation: operation.to_owned(),
                    });
                };
                if status.uptime_percent > 100 || status.latency_ms < 0 {
                    return Err(RuntimeError::InvalidOperationArguments {
                        operation: operation.to_owned(),
                    });
                }
                Ok(OperationValue::PublishReport(PublishReport {
                    outcomes: vec![RelayOutcome {
                        relay: "fake://relay-monitor".to_owned(),
                        accepted: true,
                        detail: "ok".to_owned(),
                    }],
                }))
            }
            ("nip5a", "publish_site") => {
                let [OperationValue::SiteDeployment(deployment)] = arguments else {
                    return Err(RuntimeError::InvalidOperationArguments {
                        operation: operation.to_owned(),
                    });
                };
                if deployment.domain.is_empty() || deployment.source.is_empty() {
                    return Err(RuntimeError::InvalidOperationArguments {
                        operation: operation.to_owned(),
                    });
                }
                Ok(OperationValue::PublishReport(PublishReport {
                    outcomes: vec![RelayOutcome {
                        relay: "fake://site-deployment".to_owned(),
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

#[allow(clippy::too_many_lines)]
fn normalize_record(value: &OperationValue) -> OperationValue {
    let OperationValue::Record { name, fields } = value else {
        return value.clone();
    };
    let text = |key: &str| record_text(fields, key);
    let integer = |key: &str| record_integer(fields, key);
    let pubkey = |key: &str| record_pubkey(fields, key);
    match name.as_str() {
        "PrivateMessage" => match (text("content"), pubkey("recipient")) {
            (Some(content), Some(recipient)) => {
                OperationValue::PrivateMessage(PrivateMessage { content, recipient })
            }
            _ => value.clone(),
        },
        "Reply" => match (text("target"), text("root"), text("content")) {
            (Some(target), Some(root), Some(content)) => OperationValue::ThreadReply(ThreadReply {
                target,
                root,
                content,
            }),
            _ => value.clone(),
        },
        "Repost" => match text("target") {
            Some(target) => OperationValue::Repost(Repost { target }),
            _ => value.clone(),
        },
        "Comment" => match (text("target"), text("content")) {
            (Some(target), Some(content)) => OperationValue::Comment(Comment { target, content }),
            _ => value.clone(),
        },
        "Article" => match (text("identifier"), text("title"), text("content")) {
            (Some(identifier), Some(title), Some(content)) => OperationValue::Article(Article {
                identifier,
                title,
                content,
            }),
            _ => value.clone(),
        },
        "GroupMessage" => match (text("group"), text("content")) {
            (Some(group), Some(content)) => {
                OperationValue::GroupMessage(GroupMessage { group, content })
            }
            _ => value.clone(),
        },
        "Label" => match (text("target"), text("namespace"), text("value")) {
            (Some(target), Some(namespace), Some(value)) => OperationValue::Label(Label {
                target,
                namespace,
                value,
            }),
            _ => value.clone(),
        },
        "AppData" => match (text("identifier"), text("content")) {
            (Some(identifier), Some(content)) => OperationValue::AppData(AppData {
                identifier,
                content,
            }),
            _ => value.clone(),
        },
        "Reaction" => match (text("content"), text("target")) {
            (Some(content), Some(target)) => OperationValue::Reaction(Reaction { target, content }),
            _ => value.clone(),
        },
        "DeletionRequest" => match (text("target"), text("reason")) {
            (Some(target), Some(reason)) => {
                OperationValue::DeletionRequest(DeletionRequest { target, reason })
            }
            _ => value.clone(),
        },
        "ZapRequest" => match (pubkey("recipient"), integer("amount"), text("message")) {
            (Some(recipient), Some(amount), Some(message)) => {
                OperationValue::ZapRequest(ZapRequest {
                    recipient,
                    amount,
                    message,
                })
            }
            _ => value.clone(),
        },
        "CalendarEvent" => match (
            text("title"),
            integer("start"),
            integer("end"),
            text("location"),
        ) {
            (Some(title), Some(start), Some(end), Some(location))
                if let (Ok(start), Ok(end)) = (u64::try_from(start), u64::try_from(end)) =>
            {
                OperationValue::CalendarEvent(CalendarEvent {
                    title,
                    start,
                    end,
                    location,
                })
            }
            _ => value.clone(),
        },
        "RelayStatus" => match (
            text("relay"),
            integer("uptime_percent"),
            integer("latency_ms"),
        ) {
            (Some(relay), Some(uptime_percent), Some(latency_ms))
                if let Ok(uptime_percent) = u8::try_from(uptime_percent) =>
            {
                OperationValue::RelayStatus(RelayStatus {
                    relay,
                    uptime_percent,
                    latency_ms,
                })
            }
            _ => value.clone(),
        },
        "SiteDeployment" => match (text("domain"), text("source")) {
            (Some(domain), Some(source)) => {
                OperationValue::SiteDeployment(SiteDeployment { domain, source })
            }
            _ => value.clone(),
        },
        _ => value.clone(),
    }
}

fn record_text(fields: &[(String, OperationValue)], key: &str) -> Option<String> {
    fields.iter().find_map(|(field, value)| {
        (field == key).then_some(match value {
            OperationValue::Text(value) => Some(value.clone()),
            _ => None,
        })?
    })
}

fn record_integer(fields: &[(String, OperationValue)], key: &str) -> Option<i64> {
    fields.iter().find_map(|(field, value)| {
        (field == key).then_some(match value {
            OperationValue::Integer(value) => Some(*value),
            _ => None,
        })?
    })
}

fn record_pubkey(fields: &[(String, OperationValue)], key: &str) -> Option<String> {
    fields.iter().find_map(|(field, value)| {
        (field == key).then_some(match value {
            OperationValue::PubKey(value) => Some(value.clone()),
            _ => None,
        })?
    })
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
        let record_message = runtime
            .invoke_operation(
                &mut host,
                "nip17",
                "send_private",
                &[OperationValue::Record {
                    name: "PrivateMessage".to_owned(),
                    fields: vec![
                        (
                            "content".to_owned(),
                            OperationValue::Text("hello".to_owned()),
                        ),
                        (
                            "recipient".to_owned(),
                            OperationValue::PubKey("alice".to_owned()),
                        ),
                    ],
                }],
            )
            .expect("generic private-message record host available");
        assert!(
            matches!(record_message, OperationValue::PublishReport(report) if report.accepted())
        );
        assert_eq!(runtime.audit.entries.len(), 4);
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

    #[test]
    fn nip19_validates_profile_event_and_address_hrps() {
        let mut host = Nip19FunctionHost;
        for (function, value) in [
            (
                "nprofile",
                "nprofile1qqsqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqq8uzqt",
            ),
            (
                "nevent",
                "nevent1qqsqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqradspk",
            ),
            ("naddr", "naddr1qypqxkrtttv"),
        ] {
            let result =
                host.call_function("nip19", function, &[FunctionValue::Text(value.to_owned())]);
            assert!(result.is_ok());
        }
    }

    #[test]
    fn nip10_lowers_replies_to_root_and_target_references() {
        let mut runtime = Runtime::new(
            FakeRelayHost::default(),
            FakeSignerHost::default(),
            FakeClock::default(),
            RecordingAudit::default(),
        );
        let mut host = FakeOperationHost::default();
        let result = runtime
            .invoke_authorized_operation(
                &OperationPolicy::default().allow("nip10", "publish_reply"),
                &mut host,
                "nip10",
                "publish_reply",
                &[OperationValue::Record {
                    name: "Reply".to_owned(),
                    fields: vec![
                        (
                            "target".to_owned(),
                            OperationValue::Text("event-target".to_owned()),
                        ),
                        (
                            "root".to_owned(),
                            OperationValue::Text("event-root".to_owned()),
                        ),
                        (
                            "content".to_owned(),
                            OperationValue::Text("Agreed".to_owned()),
                        ),
                    ],
                }],
            )
            .expect("reply host available");
        assert!(matches!(result, OperationValue::PublishReport(report) if report.accepted()));
    }

    #[test]
    fn nip18_lowers_reposts_to_event_references() {
        let mut runtime = Runtime::new(
            FakeRelayHost::default(),
            FakeSignerHost::default(),
            FakeClock::default(),
            RecordingAudit::default(),
        );
        let mut host = FakeOperationHost::default();
        let result = runtime
            .invoke_authorized_operation(
                &OperationPolicy::default().allow("nip18", "publish_repost"),
                &mut host,
                "nip18",
                "publish_repost",
                &[OperationValue::Record {
                    name: "Repost".to_owned(),
                    fields: vec![(
                        "target".to_owned(),
                        OperationValue::Text("event-to-repost".to_owned()),
                    )],
                }],
            )
            .expect("repost host available");
        assert!(matches!(result, OperationValue::PublishReport(report) if report.accepted()));
    }

    #[test]
    fn nip22_lowers_comments_for_arbitrary_event_targets() {
        let mut runtime = Runtime::new(
            FakeRelayHost::default(),
            FakeSignerHost::default(),
            FakeClock::default(),
            RecordingAudit::default(),
        );
        let mut host = FakeOperationHost::default();
        let result = runtime
            .invoke_authorized_operation(
                &OperationPolicy::default().allow("nip22", "publish_comment"),
                &mut host,
                "nip22",
                "publish_comment",
                &[OperationValue::Record {
                    name: "Comment".to_owned(),
                    fields: vec![
                        (
                            "target".to_owned(),
                            OperationValue::Text("event-to-comment-on".to_owned()),
                        ),
                        (
                            "content".to_owned(),
                            OperationValue::Text("A useful comment".to_owned()),
                        ),
                    ],
                }],
            )
            .expect("comment host available");
        assert!(matches!(result, OperationValue::PublishReport(report) if report.accepted()));
    }

    #[test]
    fn nip23_lowers_addressable_articles() {
        let mut runtime = Runtime::new(
            FakeRelayHost::default(),
            FakeSignerHost::default(),
            FakeClock::default(),
            RecordingAudit::default(),
        );
        let mut host = FakeOperationHost::default();
        let result = runtime
            .invoke_authorized_operation(
                &OperationPolicy::default().allow("nip23", "publish_article"),
                &mut host,
                "nip23",
                "publish_article",
                &[OperationValue::Record {
                    name: "Article".to_owned(),
                    fields: vec![
                        (
                            "identifier".to_owned(),
                            OperationValue::Text("first-post".to_owned()),
                        ),
                        (
                            "title".to_owned(),
                            OperationValue::Text("Hello Nostr".to_owned()),
                        ),
                        (
                            "content".to_owned(),
                            OperationValue::Text("Long-form content belongs here.".to_owned()),
                        ),
                    ],
                }],
            )
            .expect("article host available");
        assert!(matches!(result, OperationValue::PublishReport(report) if report.accepted()));
    }

    #[test]
    fn nip29_lowers_group_scoped_messages() {
        let mut runtime = Runtime::new(
            FakeRelayHost::default(),
            FakeSignerHost::default(),
            FakeClock::default(),
            RecordingAudit::default(),
        );
        let mut host = FakeOperationHost::default();
        let result = runtime
            .invoke_authorized_operation(
                &OperationPolicy::default().allow("nip29", "publish_group_message"),
                &mut host,
                "nip29",
                "publish_group_message",
                &[OperationValue::Record {
                    name: "GroupMessage".to_owned(),
                    fields: vec![
                        (
                            "group".to_owned(),
                            OperationValue::Text("nostr-dev".to_owned()),
                        ),
                        (
                            "content".to_owned(),
                            OperationValue::Text("Release discussion".to_owned()),
                        ),
                    ],
                }],
            )
            .expect("group message host available");
        assert!(matches!(result, OperationValue::PublishReport(report) if report.accepted()));
    }

    #[test]
    fn nip32_lowers_namespaced_labels() {
        let mut runtime = Runtime::new(
            FakeRelayHost::default(),
            FakeSignerHost::default(),
            FakeClock::default(),
            RecordingAudit::default(),
        );
        let mut host = FakeOperationHost::default();
        let result = runtime
            .invoke_authorized_operation(
                &OperationPolicy::default().allow("nip32", "publish_label"),
                &mut host,
                "nip32",
                "publish_label",
                &[OperationValue::Record {
                    name: "Label".to_owned(),
                    fields: vec![
                        (
                            "target".to_owned(),
                            OperationValue::Text("event-to-label".to_owned()),
                        ),
                        (
                            "namespace".to_owned(),
                            OperationValue::Text("moderation".to_owned()),
                        ),
                        ("value".to_owned(), OperationValue::Text("spam".to_owned())),
                    ],
                }],
            )
            .expect("label host available");
        assert!(matches!(result, OperationValue::PublishReport(report) if report.accepted()));
    }

    #[test]
    fn nip65_publishes_typed_relay_preferences() {
        let mut runtime = Runtime::new(
            FakeRelayHost::default(),
            FakeSignerHost::default(),
            FakeClock::default(),
            RecordingAudit::default(),
        );
        let mut host = FakeOperationHost::default();
        let result = runtime
            .invoke_authorized_operation(
                &OperationPolicy::default().allow("nip65", "publish_relay_list"),
                &mut host,
                "nip65",
                "publish_relay_list",
                &[OperationValue::RelayList(RelayList {
                    read: vec!["wss://read.example".to_owned()],
                    write: vec!["wss://write.example".to_owned()],
                })],
            )
            .expect("relay-list operation is authorized");
        assert!(matches!(result, OperationValue::PublishReport(report) if report.accepted()));
    }

    #[test]
    fn nip78_publishes_addressable_application_data() {
        let mut runtime = Runtime::new(
            FakeRelayHost::default(),
            FakeSignerHost::default(),
            FakeClock::default(),
            RecordingAudit::default(),
        );
        let mut host = FakeOperationHost::default();
        let result = runtime
            .invoke_authorized_operation(
                &OperationPolicy::default().allow("nip78", "publish_app_data"),
                &mut host,
                "nip78",
                "publish_app_data",
                &[OperationValue::AppData(AppData {
                    identifier: "app/settings".to_owned(),
                    content: "{\"theme\":\"dark\"}".to_owned(),
                })],
            )
            .expect("application-data operation is authorized");
        assert!(matches!(result, OperationValue::PublishReport(report) if report.accepted()));
    }

    #[test]
    fn nip02_publishes_typed_follow_lists() {
        let mut runtime = Runtime::new(
            FakeRelayHost::default(),
            FakeSignerHost::default(),
            FakeClock::default(),
            RecordingAudit::default(),
        );
        let mut host = FakeOperationHost::default();
        let result = runtime
            .invoke_authorized_operation(
                &OperationPolicy::default().allow("nip02", "publish_follow_list"),
                &mut host,
                "nip02",
                "publish_follow_list",
                &[OperationValue::FollowList(FollowList {
                    people: vec!["00".repeat(32)],
                })],
            )
            .expect("follow-list operation is authorized");
        assert!(matches!(result, OperationValue::PublishReport(report) if report.accepted()));
    }

    #[test]
    fn nip25_publishes_typed_reactions() {
        let mut runtime = Runtime::new(
            FakeRelayHost::default(),
            FakeSignerHost::default(),
            FakeClock::default(),
            RecordingAudit::default(),
        );
        let mut host = FakeOperationHost::default();
        let result = runtime
            .invoke_authorized_operation(
                &OperationPolicy::default().allow("nip25", "publish_reaction"),
                &mut host,
                "nip25",
                "publish_reaction",
                &[OperationValue::Reaction(Reaction {
                    target: "11".repeat(32),
                    content: "+".to_owned(),
                })],
            )
            .expect("reaction operation is authorized");
        assert!(matches!(result, OperationValue::PublishReport(report) if report.accepted()));
    }

    #[test]
    fn nip09_publishes_deletion_requests_not_guarantees() {
        let mut runtime = Runtime::new(
            FakeRelayHost::default(),
            FakeSignerHost::default(),
            FakeClock::default(),
            RecordingAudit::default(),
        );
        let mut host = FakeOperationHost::default();
        let result = runtime
            .invoke_authorized_operation(
                &OperationPolicy::default().allow("nip09", "request_deletion"),
                &mut host,
                "nip09",
                "request_deletion",
                &[OperationValue::DeletionRequest(DeletionRequest {
                    target: "22".repeat(32),
                    reason: "posted by mistake".to_owned(),
                })],
            )
            .expect("deletion request operation is authorized");
        assert!(matches!(result, OperationValue::PublishReport(report) if report.accepted()));
    }

    #[test]
    fn nip51_publishes_typed_user_lists() {
        let mut runtime = Runtime::new(
            FakeRelayHost::default(),
            FakeSignerHost::default(),
            FakeClock::default(),
            RecordingAudit::default(),
        );
        let mut host = FakeOperationHost::default();
        let result = runtime
            .invoke_authorized_operation(
                &OperationPolicy::default().allow("nip51", "publish_user_list"),
                &mut host,
                "nip51",
                "publish_user_list",
                &[OperationValue::UserList(UserList {
                    identifier: "muted".to_owned(),
                    members: vec!["33".repeat(32)],
                })],
            )
            .expect("user-list operation is authorized");
        assert!(matches!(result, OperationValue::PublishReport(report) if report.accepted()));
    }

    #[test]
    fn nip57_creates_payment_intent_without_authorizing_payment() {
        let mut runtime = Runtime::new(
            FakeRelayHost::default(),
            FakeSignerHost::default(),
            FakeClock::default(),
            RecordingAudit::default(),
        );
        let mut host = FakeOperationHost::default();
        let result = runtime
            .invoke_authorized_operation(
                &OperationPolicy::default().allow("nip57", "create_zap_request"),
                &mut host,
                "nip57",
                "create_zap_request",
                &[OperationValue::ZapRequest(ZapRequest {
                    recipient: "44".repeat(32),
                    amount: 1_000,
                    message: "thanks".to_owned(),
                })],
            )
            .expect("zap request operation is authorized");
        assert!(matches!(result, OperationValue::PaymentIntent(intent) if intent.amount == 1_000));
    }

    #[test]
    fn nip57_rejects_non_positive_amounts() {
        let mut host = FakeOperationHost::default();
        let result = host.call(
            1,
            "nip57",
            "create_zap_request",
            &[OperationValue::ZapRequest(ZapRequest {
                recipient: "44".repeat(32),
                amount: 0,
                message: String::new(),
            })],
        );
        assert!(result.is_err());
    }

    #[test]
    fn nip52_publishes_ordered_calendar_events() {
        let mut runtime = Runtime::new(
            FakeRelayHost::default(),
            FakeSignerHost::default(),
            FakeClock::default(),
            RecordingAudit::default(),
        );
        let mut host = FakeOperationHost::default();
        let result = runtime
            .invoke_authorized_operation(
                &OperationPolicy::default().allow("nip52", "publish_calendar_event"),
                &mut host,
                "nip52",
                "publish_calendar_event",
                &[OperationValue::CalendarEvent(CalendarEvent {
                    title: "Nostr Meetup".to_owned(),
                    start: 1_760_000_000,
                    end: 1_760_003_600,
                    location: "Melbourne".to_owned(),
                })],
            )
            .expect("calendar operation is authorized");
        assert!(matches!(result, OperationValue::PublishReport(report) if report.accepted()));
    }

    #[test]
    fn nip52_rejects_inverted_event_times() {
        let mut host = FakeOperationHost::default();
        let result = host.call(
            1,
            "nip52",
            "publish_calendar_event",
            &[OperationValue::CalendarEvent(CalendarEvent {
                title: "invalid".to_owned(),
                start: 10,
                end: 9,
                location: String::new(),
            })],
        );
        assert!(result.is_err());
    }

    #[test]
    fn nip66_publishes_valid_relay_status() {
        let mut runtime = Runtime::new(
            FakeRelayHost::default(),
            FakeSignerHost::default(),
            FakeClock::default(),
            RecordingAudit::default(),
        );
        let mut host = FakeOperationHost::default();
        let result = runtime
            .invoke_authorized_operation(
                &OperationPolicy::default().allow("nip66", "publish_relay_status"),
                &mut host,
                "nip66",
                "publish_relay_status",
                &[OperationValue::RelayStatus(RelayStatus {
                    relay: "wss://relay.example".to_owned(),
                    uptime_percent: 99,
                    latency_ms: 120,
                })],
            )
            .expect("relay-status operation is authorized");
        assert!(matches!(result, OperationValue::PublishReport(report) if report.accepted()));
    }

    #[test]
    fn nip66_rejects_invalid_monitoring_values() {
        let mut host = FakeOperationHost::default();
        let result = host.call(
            1,
            "nip66",
            "publish_relay_status",
            &[OperationValue::RelayStatus(RelayStatus {
                relay: "wss://relay.example".to_owned(),
                uptime_percent: 101,
                latency_ms: -1,
            })],
        );
        assert!(result.is_err());
    }

    #[test]
    fn nip5a_publishes_scoped_site_deployment() {
        let mut runtime = Runtime::new(
            FakeRelayHost::default(),
            FakeSignerHost::default(),
            FakeClock::default(),
            RecordingAudit::default(),
        );
        let mut host = FakeOperationHost::default();
        let result = runtime
            .invoke_authorized_operation(
                &OperationPolicy::default().allow("nip5a", "publish_site"),
                &mut host,
                "nip5a",
                "publish_site",
                &[OperationValue::SiteDeployment(SiteDeployment {
                    domain: "example.com".to_owned(),
                    source: "blossom://site-manifest".to_owned(),
                })],
            )
            .expect("site deployment operation is authorized");
        assert!(matches!(result, OperationValue::PublishReport(report) if report.accepted()));
    }
}
