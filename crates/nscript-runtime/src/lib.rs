//! Deterministic reference runtime and host capability contracts.

pub mod authority;
pub mod community;
pub mod edition;
pub mod eval;
pub mod expiry;
pub mod fold;
pub mod guestbook;
pub mod invite;
pub mod moderation;
pub mod rekey;
pub mod stream;
pub mod voice;
pub mod wire;

use std::collections::{BTreeMap, BTreeSet};
use std::fmt::Write as _;
use std::{fs, path::PathBuf};

#[cfg(feature = "real-hosts")]
use std::{net::TcpStream, thread, time::Duration};

use nscript_semantics::{
    CheckedArgument, CheckedHandler, CheckedProgram, CheckedPublication, CheckedScheduleKind,
};
use nscript_syntax::{
    Program,
    ast::{ExprKind, Item, StatementKind},
};
use serde_json::Value;
#[cfg(feature = "real-hosts")]
use serde_json::json;
use sha2::{Digest, Sha256};
#[cfg(feature = "real-hosts")]
use tungstenite::stream::MaybeTlsStream;
#[cfg(feature = "real-hosts")]
use tungstenite::{Message, WebSocket, client::connect};

pub type InvocationId = u64;
pub const MAX_WASM_DISPATCH_BYTES: usize = 1 << 20;
pub const MAX_WASM_OPERATIONS: usize = 1024;
const CONCORD_TEST_SEAL_PREFIX: &[u8] = b"nscript/concord01/test-seal\0";

#[cfg(feature = "wasm-engine")]
pub mod wasmi_engine {
    use std::collections::BTreeSet;

    use super::{MAX_WASM_DISPATCH_BYTES, RuntimeError};
    use serde_json::Value;
    use wasmi::{
        Caller, Config, Engine, Error, Extern, Linker, Module, Store, StoreLimits,
        StoreLimitsBuilder,
    };

    pub const DEFAULT_WASM_MEMORY_BYTES: usize = 16 * 1024 * 1024;

    /// Wasmi-backed validator with deterministic fuel configuration.
    pub struct WasmiEngine {
        engine: Engine,
        fuel: u64,
        memory_limit: usize,
        instance_limit: usize,
        table_limit: usize,
    }

    impl WasmiEngine {
        #[must_use]
        pub fn new(fuel: u64) -> Self {
            Self::with_limits(fuel, DEFAULT_WASM_MEMORY_BYTES, 1, 1)
        }

        /// Creates an engine with explicit store resource limits.
        #[must_use]
        pub fn with_limits(
            fuel: u64,
            memory_limit: usize,
            instance_limit: usize,
            table_limit: usize,
        ) -> Self {
            let mut config = Config::default();
            config.consume_fuel(true);
            Self {
                engine: Engine::new(&config),
                fuel,
                memory_limit,
                instance_limit,
                table_limit,
            }
        }

        /// Validates a module before instantiation or host binding.
        ///
        /// # Errors
        ///
        /// Returns [`RuntimeError::InvalidWasmPayload`] when Wasmi rejects the
        /// module or when the artifact exceeds the dispatch size budget.
        pub fn validate(&self, module: &[u8]) -> Result<(), RuntimeError> {
            if module.len() > MAX_WASM_DISPATCH_BYTES {
                return Err(RuntimeError::ResourceLimit {
                    resource: "wasm_module_bytes".to_owned(),
                });
            }
            Module::new(&self.engine, module)
                .map(|_| ())
                .map_err(|_| RuntimeError::InvalidWasmPayload)
        }

        /// Instantiates and calls `nscript_main` with explicitly supplied
        /// import signatures. The caller still owns capability dispatch.
        ///
        /// # Errors
        ///
        /// Returns [`RuntimeError::InvalidWasmPayload`] when imports or the
        /// entrypoint cannot be instantiated or executed.
        pub fn run_with_imports(
            &self,
            module: &[u8],
            imports: &[(String, bool)],
        ) -> Result<(), RuntimeError> {
            self.validate(module)?;
            let module =
                Module::new(&self.engine, module).map_err(|_| RuntimeError::InvalidWasmPayload)?;
            let limits = StoreLimitsBuilder::new()
                .memory_size(self.memory_limit)
                .instances(self.instance_limit)
                .tables(self.table_limit)
                .build();
            let mut store = Store::new(&self.engine, ((), limits));
            store.limiter(|data| &mut data.1);
            store
                .set_fuel(self.fuel)
                .map_err(|_| RuntimeError::InvalidWasmPayload)?;
            let mut linker = Linker::new(&self.engine);
            let mut operation_indices = BTreeSet::new();
            for (name, takes_payload) in imports {
                if *takes_payload {
                    let Some(operation_index) = operation_index(name) else {
                        return Err(RuntimeError::InvalidWasmPayload);
                    };
                    if !operation_indices.insert(operation_index) {
                        return Err(RuntimeError::InvalidWasmPayload);
                    }
                    linker
                        .func_wrap("nscript", name, |_: i32, _: i32| {})
                        .map_err(|_| RuntimeError::InvalidWasmPayload)?;
                } else {
                    linker
                        .func_wrap("nscript", name, || {})
                        .map_err(|_| RuntimeError::InvalidWasmPayload)?;
                }
            }
            let instance = linker
                .instantiate(&mut store, &module)
                .map_err(|_| RuntimeError::InvalidWasmPayload)?
                .start(&mut store)
                .map_err(|_| RuntimeError::InvalidWasmPayload)?;
            instance
                .get_typed_func::<(), ()>(&store, "nscript_main")
                .map_err(|_| RuntimeError::InvalidWasmPayload)?
                .call(&mut store, ())
                .map_err(|_| RuntimeError::InvalidWasmPayload)
        }

        /// Runs `nscript_main` and routes payload imports to a dispatch host.
        ///
        /// # Errors
        ///
        /// Returns a runtime error when instantiation, memory decoding, fuel,
        /// or host dispatch fails.
        pub fn run_with_dispatch_host<H: super::WasmDispatchHost>(
            &self,
            module: &[u8],
            imports: &[(String, bool)],
            host: H,
            invocation: super::InvocationId,
        ) -> Result<H, RuntimeError> {
            self.validate(module)?;
            let dispatch_records = super::extract_wasm_dispatch(module)?;
            let module =
                Module::new(&self.engine, module).map_err(|_| RuntimeError::InvalidWasmPayload)?;
            let limits = StoreLimitsBuilder::new()
                .memory_size(self.memory_limit)
                .instances(self.instance_limit)
                .tables(self.table_limit)
                .build();
            let mut store = Store::new(&self.engine, (host, invocation, limits));
            store.limiter(|data| &mut data.2);
            store
                .set_fuel(self.fuel)
                .map_err(|_| RuntimeError::InvalidWasmPayload)?;
            let mut linker = Linker::new(&self.engine);
            let mut operation_indices = BTreeSet::new();
            for (name, takes_payload) in imports {
                if *takes_payload {
                    let Some((operation_index, operation_name)) = operation_descriptor(name) else {
                        return Err(RuntimeError::InvalidWasmPayload);
                    };
                    if !operation_indices.insert(operation_index) {
                        return Err(RuntimeError::InvalidWasmPayload);
                    }
                    let Some(record_name) = dispatch_records
                        .get(operation_index)
                        .and_then(Value::as_object)
                        .and_then(|record| record.get("op"))
                        .and_then(Value::as_str)
                    else {
                        return Err(RuntimeError::InvalidWasmPayload);
                    };
                    if record_name != operation_name {
                        return Err(RuntimeError::InvalidWasmPayload);
                    }
                    linker
                        .func_wrap(
                            "nscript",
                            name,
                            move |mut caller: Caller<'_, (H, super::InvocationId, StoreLimits)>,
                                  ptr: i32,
                                  len: i32| {
                                let memory = caller
                                    .get_export("memory")
                                    .and_then(Extern::into_memory)
                                    .ok_or_else(|| Error::new("missing exported memory"))?;
                                let bytes = memory.data(&caller);
                                let pointer = u32::try_from(ptr)
                                    .map_err(|_| Error::new("invalid pointer"))?;
                                let length =
                                    u32::try_from(len).map_err(|_| Error::new("invalid length"))?;
                                let records =
                                    super::decode_wasm_dispatch(bytes, pointer, length)
                                        .map_err(|_| Error::new("invalid dispatch payload"))?;
                                let index = operation_index;
                                let record = records
                                    .get(index)
                                    .ok_or_else(|| Error::new("operation index out of bounds"))?;
                                let invocation = caller.data().1;
                                super::dispatch_wasm_operations(
                                    &mut caller.data_mut().0,
                                    invocation,
                                    std::slice::from_ref(record),
                                )
                                .map_err(|_| Error::new("dispatch denied"))?;
                                Ok::<(), Error>(())
                            },
                        )
                        .map_err(|_| RuntimeError::InvalidWasmPayload)?;
                } else {
                    linker
                        .func_wrap("nscript", name, || {})
                        .map_err(|_| RuntimeError::InvalidWasmPayload)?;
                }
            }
            let instance = linker
                .instantiate(&mut store, &module)
                .map_err(|_| RuntimeError::InvalidWasmPayload)?
                .start(&mut store)
                .map_err(|_| RuntimeError::InvalidWasmPayload)?;
            instance
                .get_typed_func::<(), ()>(&store, "nscript_main")
                .map_err(|_| RuntimeError::InvalidWasmPayload)?
                .call(&mut store, ())
                .map_err(|_| RuntimeError::InvalidWasmPayload)?;
            Ok(store.into_data().0)
        }

        #[must_use]
        pub fn fuel(&self) -> u64 {
            self.fuel
        }
    }

    fn operation_index(name: &str) -> Option<usize> {
        name.strip_prefix("op:")
            .and_then(|value| value.split(':').next())
            .and_then(|value| value.parse::<usize>().ok())
    }

    fn operation_descriptor(name: &str) -> Option<(usize, &str)> {
        let value = name.strip_prefix("op:")?;
        let (index, operation) = value.split_once(':')?;
        Some((index.parse().ok()?, operation))
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct UnsignedEvent {
    pub event_type: String,
    pub kind: u16,
    pub content: String,
    pub tags: Vec<(String, String)>,
    pub created_at: u64,
}

impl UnsignedEvent {
    /// Serialize typed two-column tags into ordinary Nostr tag arrays.
    #[must_use]
    pub fn wire_tags(&self) -> Vec<Vec<String>> {
        self.tags
            .iter()
            .map(|(name, value)| vec![name.clone(), value.clone()])
            .collect()
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SignedEvent {
    pub unsigned: UnsignedEvent,
    pub signer: String,
    pub id: String,
    pub signature: String,
}

/// Returns whether `candidate` should replace `current` for one replaceable
/// event address. NIP-01 selects the greatest `created_at`; equal timestamps
/// are resolved by the lexicographically lowest event id.
#[must_use]
pub fn replaceable_event_wins(candidate: &SignedEvent, current: &SignedEvent) -> bool {
    candidate.unsigned.created_at > current.unsigned.created_at
        || (candidate.unsigned.created_at == current.unsigned.created_at
            && candidate.id < current.id)
}

/// Selects the canonical event from an already-grouped replaceable address.
#[must_use]
pub fn select_replaceable_event<'a>(
    events: impl IntoIterator<Item = &'a SignedEvent>,
) -> Option<&'a SignedEvent> {
    events.into_iter().reduce(|current, candidate| {
        if replaceable_event_wins(candidate, current) {
            candidate
        } else {
            current
        }
    })
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

/// Opaque shared key material used by Concord protocol modules.
///
/// The bytes are deliberately private; callers can only borrow them for a
/// host operation and cannot accidentally treat them as ordinary text.
#[derive(Clone, Eq, PartialEq)]
pub struct SharedSecret(Vec<u8>);

impl SharedSecret {
    /// Creates shared secret material, rejecting empty values.
    ///
    /// # Errors
    ///
    /// Returns [`RuntimeError::InvalidConcordBytes`] for an empty value.
    pub fn new(bytes: Vec<u8>) -> Result<Self, RuntimeError> {
        if bytes.is_empty() {
            return Err(RuntimeError::InvalidConcordBytes {
                type_name: "SharedSecret",
            });
        }
        Ok(Self(bytes))
    }

    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }
}

impl std::fmt::Debug for SharedSecret {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("SharedSecret")
            .field("length", &self.0.len())
            .finish()
    }
}

/// Opaque key material derived from a Concord shared secret.
#[derive(Clone, Eq, PartialEq)]
pub struct DerivedKey(Vec<u8>);

impl DerivedKey {
    /// Creates derived key material, rejecting empty values.
    ///
    /// # Errors
    ///
    /// Returns [`RuntimeError::InvalidConcordBytes`] for an empty value.
    pub fn new(bytes: Vec<u8>) -> Result<Self, RuntimeError> {
        if bytes.is_empty() {
            return Err(RuntimeError::InvalidConcordBytes {
                type_name: "DerivedKey",
            });
        }
        Ok(Self(bytes))
    }

    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }
}

impl std::fmt::Debug for DerivedKey {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("DerivedKey")
            .field("length", &self.0.len())
            .finish()
    }
}

/// Immutable bytes whose exact representation must survive Concord wrapping.
#[derive(Clone, Eq, PartialEq)]
pub struct SignedBytes(Vec<u8>);

impl SignedBytes {
    /// Creates immutable signed bytes, rejecting empty values.
    ///
    /// # Errors
    ///
    /// Returns [`RuntimeError::InvalidConcordBytes`] for an empty value.
    pub fn new(bytes: Vec<u8>) -> Result<Self, RuntimeError> {
        if bytes.is_empty() {
            return Err(RuntimeError::InvalidConcordBytes {
                type_name: "SignedBytes",
            });
        }
        Ok(Self(bytes))
    }

    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }
}

impl std::fmt::Debug for SignedBytes {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("SignedBytes")
            .field("length", &self.0.len())
            .finish()
    }
}

impl PublishReport {
    #[must_use]
    pub fn accepted(&self) -> bool {
        self.outcomes.iter().any(|outcome| outcome.accepted)
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum RuntimeError {
    CapabilityDenied {
        capability: String,
    },
    SignerDenied {
        signer: String,
    },
    RelayUnavailable {
        relayset: String,
    },
    PublicationRejected,
    StoreConflict,
    Cancelled,
    ResourceLimit {
        resource: String,
    },
    OperationUnavailable {
        module: String,
        operation: String,
    },
    InvalidOperationArguments {
        operation: String,
    },
    PaymentLimitExceeded {
        amount: i64,
        limit: i64,
    },
    InvalidWasmPayload,
    InvalidConcordBytes {
        type_name: &'static str,
    },
    /// The acting identity lacks the rank or permission bit for the action.
    AuthorityDenied {
        actor: String,
        action: String,
    },
    /// A handler body failed to evaluate: a type mismatch, an unknown name,
    /// division by zero and the like.
    EvaluationError {
        message: String,
    },
    /// A handler ended by returning an error result, either by `?` on an error
    /// or by returning one. The handler's transaction is rolled back.
    HandlerError {
        message: String,
    },
}

/// Decodes a dispatch payload supplied by a WASM operation import.
///
/// The host owns the memory slice and remains responsible for mapping the
/// returned JSON records to typed capability calls.
///
/// # Errors
///
/// Returns [`RuntimeError::InvalidWasmPayload`] when the slice is out of
/// bounds, invalid UTF-8/JSON, or does not contain an array.
pub fn decode_wasm_dispatch(
    memory: &[u8],
    pointer: u32,
    length: u32,
) -> Result<Vec<Value>, RuntimeError> {
    let start = usize::try_from(pointer).map_err(|_| RuntimeError::InvalidWasmPayload)?;
    let size = usize::try_from(length).map_err(|_| RuntimeError::InvalidWasmPayload)?;
    let end = start
        .checked_add(size)
        .ok_or(RuntimeError::InvalidWasmPayload)?;
    let payload = memory
        .get(start..end)
        .ok_or(RuntimeError::InvalidWasmPayload)?;
    if payload.len() > MAX_WASM_DISPATCH_BYTES {
        return Err(RuntimeError::ResourceLimit {
            resource: "wasm_dispatch_bytes".to_owned(),
        });
    }
    serde_json::from_slice(payload).map_err(|_| RuntimeError::InvalidWasmPayload)
}

/// Host boundary for executing one decoded WASM operation record.
pub trait WasmDispatchHost {
    /// Dispatches a single typed operation record.
    ///
    /// # Errors
    ///
    /// Returns a capability or validation error when the operation is denied.
    fn dispatch(&mut self, invocation: InvocationId, operation: &Value)
    -> Result<(), RuntimeError>;
}

/// Executes decoded records with stable invocation identifiers.
///
/// # Errors
///
/// Returns [`RuntimeError::InvalidWasmPayload`] for non-object records or
/// invocation overflow, or propagates a host dispatch denial.
pub fn dispatch_wasm_operations<H: WasmDispatchHost>(
    host: &mut H,
    invocation: InvocationId,
    records: &[Value],
) -> Result<usize, RuntimeError> {
    for (offset, operation) in records.iter().enumerate() {
        if offset >= MAX_WASM_OPERATIONS {
            return Err(RuntimeError::ResourceLimit {
                resource: "wasm_operations".to_owned(),
            });
        }
        if !operation.is_object() {
            return Err(RuntimeError::InvalidWasmPayload);
        }
        host.dispatch(
            invocation
                .checked_add(u64::try_from(offset).map_err(|_| RuntimeError::InvalidWasmPayload)?)
                .ok_or(RuntimeError::InvalidWasmPayload)?,
            operation,
        )?;
    }
    Ok(records.len())
}

/// Executes the publication subset of WASM records through runtime hosts.
///
/// # Errors
///
/// Returns [`RuntimeError::InvalidWasmPayload`] for malformed records or
/// propagates signer and relay host failures.
pub fn execute_wasm_publications<R: RelayHost, S: SignerHost>(
    relay: &mut R,
    signer: &mut S,
    invocation: InvocationId,
    records: &[Value],
) -> Result<Vec<PublishReport>, RuntimeError> {
    let mut unsigned = BTreeMap::<String, UnsignedEvent>::new();
    let mut signed_events = BTreeMap::<String, SignedEvent>::new();
    let mut reports = Vec::new();
    for record in records {
        let object = record.as_object().ok_or(RuntimeError::InvalidWasmPayload)?;
        match object.get("op").and_then(Value::as_str) {
            Some("create_event") => {
                let result = object
                    .get("result")
                    .and_then(Value::as_str)
                    .ok_or(RuntimeError::InvalidWasmPayload)?;
                let event = UnsignedEvent {
                    event_type: object
                        .get("event")
                        .and_then(Value::as_str)
                        .ok_or(RuntimeError::InvalidWasmPayload)?
                        .to_owned(),
                    kind: object
                        .get("kind")
                        .and_then(Value::as_u64)
                        .and_then(|value| u16::try_from(value).ok())
                        .ok_or(RuntimeError::InvalidWasmPayload)?,
                    content: object
                        .get("content")
                        .and_then(Value::as_str)
                        .unwrap_or_default()
                        .to_owned(),
                    tags: Vec::new(),
                    created_at: 0,
                };
                unsigned.insert(result.to_owned(), event);
            }
            Some("sign_event") => {
                let result = object
                    .get("result")
                    .and_then(Value::as_str)
                    .ok_or(RuntimeError::InvalidWasmPayload)?;
                let event_key = object
                    .get("event")
                    .and_then(Value::as_str)
                    .ok_or(RuntimeError::InvalidWasmPayload)?;
                let signer_name = object
                    .get("signer")
                    .and_then(Value::as_str)
                    .ok_or(RuntimeError::InvalidWasmPayload)?;
                let event = unsigned
                    .remove(event_key)
                    .ok_or(RuntimeError::InvalidWasmPayload)?;
                let signed_event = signer.sign(invocation, event, signer_name)?;
                signed_events.insert(result.to_owned(), signed_event);
            }
            Some("publish_event") => {
                let event_key = object
                    .get("event")
                    .and_then(Value::as_str)
                    .ok_or(RuntimeError::InvalidWasmPayload)?;
                let relayset = object
                    .get("relayset")
                    .and_then(Value::as_str)
                    .ok_or(RuntimeError::InvalidWasmPayload)?;
                let event = signed_events
                    .get(event_key)
                    .ok_or(RuntimeError::InvalidWasmPayload)?;
                reports.push(relay.publish(invocation, event, relayset)?);
            }
            Some(_) | None => return Err(RuntimeError::InvalidWasmPayload),
        }
    }
    Ok(reports)
}

/// Executes the `NScript` dispatch section embedded in a compiled WASM artifact.
///
/// This is the deterministic reference path used when no general WASM engine
/// is available; an engine-backed adapter can reuse the same host functions.
///
/// # Errors
///
/// Returns [`RuntimeError::InvalidWasmPayload`] for malformed modules or
/// propagates signer and relay host failures.
pub fn execute_nscript_wasm<R: RelayHost, S: SignerHost>(
    module: &[u8],
    relay: &mut R,
    signer: &mut S,
    invocation: InvocationId,
) -> Result<Vec<PublishReport>, RuntimeError> {
    let records = extract_wasm_dispatch(module)?;
    execute_wasm_publications(relay, signer, invocation, &records)
}

fn extract_wasm_dispatch(module: &[u8]) -> Result<Vec<Value>, RuntimeError> {
    if module.get(..8) != Some(b"\0asm\x01\0\0\0") {
        return Err(RuntimeError::InvalidWasmPayload);
    }
    let mut cursor = 8;
    while cursor < module.len() {
        let section_id = *module.get(cursor).ok_or(RuntimeError::InvalidWasmPayload)?;
        cursor += 1;
        let (section_len, consumed) = read_leb_u32(&module[cursor..])?;
        cursor += consumed;
        let end = cursor
            .checked_add(
                usize::try_from(section_len).map_err(|_| RuntimeError::InvalidWasmPayload)?,
            )
            .ok_or(RuntimeError::InvalidWasmPayload)?;
        let payload = module
            .get(cursor..end)
            .ok_or(RuntimeError::InvalidWasmPayload)?;
        cursor = end;
        if section_id != 0 {
            continue;
        }
        let (name_len, name_bytes) = read_name(payload)?;
        if name_bytes != b"nscript.dispatch" {
            continue;
        }
        let data_start = name_len;
        let records = decode_wasm_dispatch(
            &payload[data_start..],
            0,
            u32::try_from(payload.len() - data_start)
                .map_err(|_| RuntimeError::InvalidWasmPayload)?,
        )?;
        return Ok(records);
    }
    Err(RuntimeError::InvalidWasmPayload)
}

fn read_leb_u32(bytes: &[u8]) -> Result<(u32, usize), RuntimeError> {
    let mut value = 0u32;
    for (index, byte) in bytes.iter().copied().enumerate().take(5) {
        value |= u32::from(byte & 0x7f) << (index * 7);
        if byte & 0x80 == 0 {
            return Ok((value, index + 1));
        }
    }
    Err(RuntimeError::InvalidWasmPayload)
}

fn read_name(bytes: &[u8]) -> Result<(usize, &[u8]), RuntimeError> {
    let (length, consumed) = read_leb_u32(bytes)?;
    let length = usize::try_from(length).map_err(|_| RuntimeError::InvalidWasmPayload)?;
    let end = consumed
        .checked_add(length)
        .ok_or(RuntimeError::InvalidWasmPayload)?;
    Ok((
        end,
        bytes
            .get(consumed..end)
            .ok_or(RuntimeError::InvalidWasmPayload)?,
    ))
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
pub struct Draft {
    pub identifier: String,
    pub content: String,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct UserStatus {
    pub status: String,
    pub content: String,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct StreamMessage {
    pub author: String,
    pub content: String,
}

#[derive(Clone, Eq, PartialEq)]
pub struct SealedEvent {
    bytes: Vec<u8>,
    kind: stream::SealKind,
}

impl SealedEvent {
    /// Creates an opaque encrypted (kind 20013) seal, rejecting empty values.
    ///
    /// # Errors
    ///
    /// Returns [`RuntimeError::InvalidConcordBytes`] for an empty value.
    pub fn new(bytes: Vec<u8>) -> Result<Self, RuntimeError> {
        Self::with_kind(bytes, stream::SealKind::Encrypted)
    }

    /// Creates a plaintext (kind 20014) seal whose bytes are the rumor JSON,
    /// carried verbatim.
    ///
    /// # Errors
    ///
    /// Returns [`RuntimeError::InvalidConcordBytes`] for an empty value.
    pub fn plaintext(bytes: Vec<u8>) -> Result<Self, RuntimeError> {
        Self::with_kind(bytes, stream::SealKind::Plaintext)
    }

    fn with_kind(bytes: Vec<u8>, kind: stream::SealKind) -> Result<Self, RuntimeError> {
        if bytes.is_empty() {
            return Err(RuntimeError::InvalidConcordBytes {
                type_name: "SealedEvent",
            });
        }
        Ok(Self { bytes, kind })
    }

    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes
    }

    #[must_use]
    pub fn kind(&self) -> stream::SealKind {
        self.kind
    }
}

impl std::fmt::Debug for SealedEvent {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("SealedEvent")
            .field("kind", &self.kind.wire_kind())
            .field("length", &self.bytes.len())
            .finish()
    }
}

/// A readable Concord stream, as a script sees it: the plane's public address
/// (the `authors` a subscription filters on). It carries no key material, so it
/// is safe to print and to pass around; reading needs the host that holds the
/// plane key.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct StreamHandle {
    /// 64-hex x-only public key of the plane (its stream address).
    pub address: String,
}

/// CORD-01 private-stream envelope: a kind-1059 wrap signed by the stream
/// key (fixed author), tagged with an ephemeral `p` key, carrying a seal.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct StreamWrap {
    pub kind: u16,
    pub stream_pubkey: String,
    /// Ephemeral `p` tag; never the key the wrap is encrypted to.
    pub ephemeral_p: String,
    /// The carried seal. `None` for a wrap received off the wire: its seal is
    /// encrypted and only recoverable by a host that holds the plane key.
    pub sealed: Option<SealedEvent>,
    /// The serialised kind-1059 event as published or received, when a real
    /// host produced or parsed it. Fake hosts leave this `None`.
    pub wire: Option<String>,
}

/// Why a received wrap was refused.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum WrapError {
    NotAGiftWrap,
    WrongStream,
    MalformedEphemeralKey,
    /// The seal kind does not match what the plane requires.
    WrongSealKind,
}

impl StreamWrap {
    /// Reads the public fields of a received kind-1059 event. The seal stays
    /// sealed until a host opens it with the plane key.
    ///
    /// # Errors
    ///
    /// Returns [`WrapError`] for a non-wrap or malformed event.
    pub fn from_wire(wire: &str) -> Result<Self, WrapError> {
        let event: Value = serde_json::from_str(wire).map_err(|_| WrapError::NotAGiftWrap)?;
        let kind = event
            .get("kind")
            .and_then(Value::as_u64)
            .and_then(|kind| u16::try_from(kind).ok())
            .ok_or(WrapError::NotAGiftWrap)?;
        let stream_pubkey = event
            .get("pubkey")
            .and_then(Value::as_str)
            .ok_or(WrapError::WrongStream)?;
        let ephemeral_p = event
            .get("tags")
            .and_then(Value::as_array)
            .and_then(|tags| {
                tags.iter().find_map(|tag| {
                    let tag = tag.as_array()?;
                    (tag.first()?.as_str()? == "p").then(|| tag.get(1)?.as_str())?
                })
            })
            .ok_or(WrapError::MalformedEphemeralKey)?;
        Ok(Self {
            kind,
            stream_pubkey: stream_pubkey.to_owned(),
            ephemeral_p: ephemeral_p.to_owned(),
            sealed: None,
            wire: Some(wire.to_owned()),
        })
    }

    /// Validates the envelope against the plane it was read from.
    ///
    /// # Errors
    ///
    /// Returns [`WrapError`] describing the first failed check.
    pub fn validate(&self, expected_pubkey: &str, plane: stream::Plane) -> Result<(), WrapError> {
        if self.kind != 1059 {
            return Err(WrapError::NotAGiftWrap);
        }
        if self.stream_pubkey != expected_pubkey {
            return Err(WrapError::WrongStream);
        }
        if !stream::is_hex32(&self.ephemeral_p) {
            return Err(WrapError::MalformedEphemeralKey);
        }
        // A wire wrap's seal kind is only knowable after opening it.
        if self
            .sealed
            .as_ref()
            .is_some_and(|sealed| sealed.kind() != plane.seal_kind())
        {
            return Err(WrapError::WrongSealKind);
        }
        Ok(())
    }
}

fn concord_test_stream_pubkey(stream: &DerivedKey) -> String {
    let mut digest = Sha256::new();
    digest.update(b"nscript/concord01/test-stream-pubkey\0");
    digest.update(stream.as_bytes());
    digest
        .finalize()
        .iter()
        .fold(String::new(), |mut out, byte| {
            use std::fmt::Write as _;
            let _ = write!(out, "{byte:02x}");
            out
        })
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AuthenticatedRelay {
    pub relay: String,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SubscriptionRequest {
    pub event_type: String,
    pub relayset: Option<String>,
    pub kinds: Vec<u16>,
    pub tag_equals: Vec<(String, String)>,
    pub cursor: Option<String>,
    pub author: Option<String>,
    pub since: Option<u64>,
    pub limit: Option<u32>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SubscriptionHandle {
    pub id: u64,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SubscriptionBatch {
    pub events: Vec<SignedEvent>,
    pub complete: bool,
    pub cursor: Option<String>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct LogRecord {
    pub level: String,
    pub message: String,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ScheduleRequest {
    pub name: String,
    pub next_at: u64,
    pub interval: Option<u64>,
    pub catch_up: bool,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TimerHandle {
    pub id: u64,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SearchRequest {
    pub query: String,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SearchResults {
    pub query: String,
    pub count: i64,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct LiveEvent {
    pub identifier: String,
    pub title: String,
    pub summary: String,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Report {
    pub target: String,
    pub category: String,
    pub content: String,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Badge {
    pub identifier: String,
    pub name: String,
    pub description: String,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ImageEvent {
    pub url: String,
    pub caption: String,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct VideoEvent {
    pub url: String,
    pub caption: String,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SyncRequest {
    pub relay: String,
    pub cursor: String,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SyncResult {
    pub relay: String,
    pub added: i64,
    pub removed: i64,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Highlight {
    pub source: String,
    pub content: String,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Assertion {
    pub subject: String,
    pub kind: String,
    pub value: String,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RelayAdminRequest {
    pub relay: String,
    pub action: String,
    pub subject: String,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AppHandler {
    pub kind: String,
    pub app: String,
    pub endpoint: String,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct FileMetadata {
    pub url: String,
    pub mime: String,
    pub hash: String,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BlobUpload {
    pub url: String,
    pub hash: String,
    pub size: i64,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BlobStored {
    pub url: String,
    pub hash: String,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct HttpAuthRequest {
    pub url: String,
    pub method: String,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AuthenticatedRequest {
    pub url: String,
    pub method: String,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct HttpResponse {
    pub status: u16,
    pub body: String,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SignerSession {
    pub provider: String,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct WalletPayment {
    pub invoice: String,
    pub amount: i64,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PaymentResult {
    pub invoice: String,
    pub amount: i64,
    pub settled: bool,
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
pub struct PollOption {
    pub id: String,
    pub label: String,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Poll {
    pub question: String,
    pub options: Vec<PollOption>,
    pub multiple_choice: bool,
    pub ends_at: i64,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PollResponse {
    pub poll: String,
    pub option: String,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MediaAttachment {
    pub url: String,
    pub mime: String,
    pub hash: String,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct NoteWithMedia {
    pub content: String,
    pub media: Vec<MediaAttachment>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct NoteWithWarning {
    pub content: String,
    pub reason: String,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ExpiringNote {
    pub content: String,
    pub expires_at: i64,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct NoteWithMentions {
    pub content: String,
    pub mentions: Vec<String>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CustomEmoji {
    pub shortcode: String,
    pub url: String,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct NoteWithEmoji {
    pub content: String,
    pub emoji: Vec<CustomEmoji>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ExternalIdentity {
    pub platform: String,
    pub proof: String,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct IdentityClaims {
    pub claims: Vec<ExternalIdentity>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ExternalComment {
    pub content: String,
    pub target_id: String,
    pub target_kind: String,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TorrentFile {
    pub path: String,
    pub bytes: i64,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Torrent {
    pub title: String,
    pub description: String,
    pub info_hash: String,
    pub files: Vec<TorrentFile>,
    pub trackers: Vec<String>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Listing {
    pub title: String,
    pub summary: String,
    pub content: String,
    pub location: String,
    pub price_amount: String,
    pub price_currency: String,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Bookmark {
    pub uri: String,
    pub title: String,
    pub description: String,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CodeSnippet {
    pub code: String,
    pub language: String,
    pub name: String,
    pub description: String,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Repository {
    pub identifier: String,
    pub name: String,
    pub description: String,
    pub clone_url: String,
    pub web_url: String,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct WikiArticle {
    pub identifier: String,
    pub title: String,
    pub summary: String,
    pub content: String,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Community {
    pub identifier: String,
    pub name: String,
    pub description: String,
    pub moderators: Vec<String>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PostApproval {
    pub community: String,
    pub post: String,
    pub author: String,
    pub kind: i64,
    pub post_json: String,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ChatMessage {
    pub content: String,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ChatReply {
    pub content: String,
    pub target: String,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ChessGame {
    pub pgn: String,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ForumThread {
    pub title: String,
    pub content: String,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PodcastShow {
    pub title: String,
    pub description: String,
    pub image: String,
    pub website: String,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PodcastEpisode {
    pub title: String,
    pub description: String,
    pub content: String,
    pub audio_url: String,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct GeocacheListing {
    pub identifier: String,
    pub name: String,
    pub geohash: String,
    pub difficulty: i64,
    pub terrain: i64,
    pub size: String,
    pub description: String,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct FoundLog {
    pub cache: String,
    pub message: String,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Channel {
    pub name: String,
    pub about: String,
    pub picture: String,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ChannelMessage {
    pub channel: String,
    pub content: String,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct HideMessage {
    pub message: String,
    pub reason: String,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MuteUser {
    pub target: String,
    pub reason: String,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct VanishRequest {
    pub relays: Vec<String>,
    pub reason: String,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ZapGoal {
    pub description: String,
    pub amount_msats: i64,
    pub relays: Vec<String>,
    pub closed_at: i64,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PublicMessage {
    pub content: String,
    pub recipients: Vec<String>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TimestampAttestation {
    pub target: String,
    pub target_kind: i64,
    pub ots_proof: String,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ProtectedNote {
    pub content: String,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct JobRequest {
    pub job_kind: i64,
    pub input: String,
    pub input_type: String,
    pub output: String,
    pub bid_msats: i64,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct JobResult {
    pub job_kind: i64,
    pub request: String,
    pub payload: String,
    pub amount_msats: i64,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct VoiceMessage {
    pub audio_url: String,
    pub duration: i64,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct VoiceReply {
    pub audio_url: String,
    pub duration: i64,
    pub target: String,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct NoteWithSubject {
    pub content: String,
    pub subject: String,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DelegatedNote {
    pub content: String,
    pub delegator: String,
    pub conditions: String,
    pub token: String,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BridgedNote {
    pub content: String,
    pub source_id: String,
    pub protocol: String,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct FileServerPreferences {
    pub servers: Vec<String>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MintAnnouncement {
    pub mint_pubkey: String,
    pub url: String,
    pub nuts: String,
    pub network: String,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MintRecommendation {
    pub mint: String,
    pub review: String,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PaymentTarget {
    pub payment_type: String,
    pub address: String,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PaymentTargets {
    pub targets: Vec<PaymentTarget>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct P2POrder {
    pub identifier: String,
    pub order_type: String,
    pub currency: String,
    pub status: String,
    pub amount_sats: i64,
    pub fiat_amount: String,
    pub payment_method: String,
    pub premium: i64,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum OperationValue {
    Text(String),
    Integer(i64),
    Bool(bool),
    PubKey(String),
    List(Vec<OperationValue>),
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
    Draft(Draft),
    UserStatus(UserStatus),
    SharedSecret(SharedSecret),
    DerivedKey(DerivedKey),
    SignedBytes(SignedBytes),
    SealedEvent(SealedEvent),
    StreamWrap(StreamWrap),
    StreamHandle(StreamHandle),
    StreamMessage(StreamMessage),
    AuthenticatedRelay(AuthenticatedRelay),
    SearchRequest(SearchRequest),
    SearchResults(SearchResults),
    LiveEvent(LiveEvent),
    Report(Report),
    Badge(Badge),
    ImageEvent(ImageEvent),
    VideoEvent(VideoEvent),
    SyncRequest(SyncRequest),
    SyncResult(SyncResult),
    Highlight(Highlight),
    Assertion(Assertion),
    RelayAdminRequest(RelayAdminRequest),
    AppHandler(AppHandler),
    FileMetadata(FileMetadata),
    BlobUpload(BlobUpload),
    BlobStored(BlobStored),
    HttpAuthRequest(HttpAuthRequest),
    AuthenticatedRequest(AuthenticatedRequest),
    SignerSession(SignerSession),
    WalletPayment(WalletPayment),
    PaymentResult(PaymentResult),
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
    Poll(Poll),
    PollResponse(PollResponse),
    NoteWithMedia(NoteWithMedia),
    NoteWithWarning(NoteWithWarning),
    ExpiringNote(ExpiringNote),
    NoteWithMentions(NoteWithMentions),
    NoteWithEmoji(NoteWithEmoji),
    IdentityClaims(IdentityClaims),
    ExternalComment(ExternalComment),
    Torrent(Torrent),
    // Boxed: `Listing` has six `String` fields (144 bytes), which alone would
    // make this the largest `OperationValue` variant and trip
    // `clippy::result_large_err` on every `Result<OperationValue, _>` in the
    // crate.
    Listing(Box<Listing>),
    Bookmark(Bookmark),
    CodeSnippet(CodeSnippet),
    // Boxed for the same reason as `Listing`: five `String` fields (120
    // bytes) push this variant to exactly the `result_large_err` threshold.
    Repository(Box<Repository>),
    WikiArticle(WikiArticle),
    Community(Community),
    PostApproval(PostApproval),
    ChatMessage(ChatMessage),
    ChatReply(ChatReply),
    ChessGame(ChessGame),
    ForumThread(ForumThread),
    PodcastShow(PodcastShow),
    PodcastEpisode(PodcastEpisode),
    // Boxed like `Listing`/`Repository`: five `Text` fields plus two `Int`s
    // (136 bytes) would make this the largest `OperationValue` variant.
    GeocacheListing(Box<GeocacheListing>),
    FoundLog(FoundLog),
    Channel(Channel),
    ChannelMessage(ChannelMessage),
    HideMessage(HideMessage),
    MuteUser(MuteUser),
    VanishRequest(VanishRequest),
    ZapGoal(ZapGoal),
    PublicMessage(PublicMessage),
    TimestampAttestation(TimestampAttestation),
    ProtectedNote(ProtectedNote),
    JobRequest(JobRequest),
    JobResult(JobResult),
    VoiceMessage(VoiceMessage),
    VoiceReply(VoiceReply),
    NoteWithSubject(NoteWithSubject),
    DelegatedNote(DelegatedNote),
    BridgedNote(BridgedNote),
    // Boxed like `Listing`/`Repository`/`GeocacheListing`: six `Text` fields
    // plus two `Int`s (160 bytes) would make this the largest
    // `OperationValue` variant.
    P2POrder(Box<P2POrder>),
    FileServerPreferences(FileServerPreferences),
    MintAnnouncement(MintAnnouncement),
    MintRecommendation(MintRecommendation),
    PaymentTargets(PaymentTargets),
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
    /// The key the host holds under `label`, for a script's `key name =
    /// host("label")`. The script receives an opaque handle, never the bytes as
    /// text. The default provisions nothing.
    ///
    /// # Errors
    ///
    /// Returns [`RuntimeError::OperationUnavailable`] when no such key is held.
    fn host_key(&mut self, label: &str) -> Result<DerivedKey, RuntimeError> {
        let _ = label;
        Err(RuntimeError::OperationUnavailable {
            module: "host".to_owned(),
            operation: "key".to_owned(),
        })
    }

    /// Whether `module.function` is a pure, effect-free protocol query — a
    /// module `function` declaration (RFC 0002 §3), never a gated
    /// `operation`. A host never overrides this: every fold query the
    /// language knows is answered below, by [`Self::call_pure_function`],
    /// from protocol logic already in this crate.
    fn is_pure_function(&self, module: &str, function: &str) -> bool {
        pure_function(module, function).is_some()
    }

    /// Evaluates a pure protocol query (RFC 0002 §3: `concord05`/`concord06`
    /// fold-derived reads such as `invite_is_valid` and
    /// `commitment_matches`). Unlike [`Self::call`], this runs with no
    /// permission gate, no declared effect, and no operation-call audit
    /// trail — the result depends only on the arguments, so every host
    /// answers it the same way.
    ///
    /// # Errors
    ///
    /// Returns [`RuntimeError::InvalidOperationArguments`] for a wrong
    /// argument shape, or [`RuntimeError::OperationUnavailable`] for a
    /// `module`/`function` pair this is not one of.
    fn call_pure_function(
        &mut self,
        module: &str,
        function: &str,
        arguments: &[OperationValue],
    ) -> Result<OperationValue, RuntimeError> {
        pure_function(module, function).ok_or_else(|| RuntimeError::OperationUnavailable {
            module: module.to_owned(),
            operation: function.to_owned(),
        })?(arguments)
    }

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

    /// The declared return type of an operation (for example
    /// `Result<PublishReport,ModerationError>`), if this host knows it. The
    /// handler evaluator uses it to hand a script `Ok`/`Err` values for
    /// operations declared to return a `Result`. Hosts that do not know their
    /// operations' signatures leave the default, and their operations return
    /// plain values.
    fn declared_return(&self, _module: &str, _operation: &str) -> Option<String> {
        None
    }
}

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct OperationPolicy {
    allowed: BTreeSet<(String, String)>,
    max_payment: Option<i64>,
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

    #[must_use]
    pub fn allow_payment_up_to(mut self, limit: i64) -> Self {
        self.max_payment = Some(limit);
        self
    }

    #[must_use]
    pub fn payment_limit(&self) -> Option<i64> {
        self.max_payment
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

pub trait RelaySessionHost {
    /// Authenticate a relay session without exposing signer secrets.
    ///
    /// # Errors
    ///
    /// Returns a relay availability or authentication failure.
    fn authenticate(
        &mut self,
        invocation: InvocationId,
        relay: &str,
    ) -> Result<AuthenticatedRelay, RuntimeError>;
}

pub trait SubscriptionHost {
    /// Open a typed event subscription through the host relay implementation.
    ///
    /// # Errors
    ///
    /// Returns a capability, relay, or malformed-filter error.
    fn subscribe(
        &mut self,
        invocation: InvocationId,
        request: &SubscriptionRequest,
    ) -> Result<SubscriptionHandle, RuntimeError>;

    /// Close an existing event subscription.
    ///
    /// # Errors
    ///
    /// Returns a stable runtime error when the handle is unknown or cleanup fails.
    fn unsubscribe(
        &mut self,
        invocation: InvocationId,
        handle: &SubscriptionHandle,
    ) -> Result<(), RuntimeError>;

    /// Drain the next batch of events for a subscription.
    ///
    /// # Errors
    ///
    /// Returns a stable runtime error when the handle is unknown or delivery fails.
    fn poll(
        &mut self,
        invocation: InvocationId,
        handle: &SubscriptionHandle,
    ) -> Result<SubscriptionBatch, RuntimeError>;
}

pub trait LogHost {
    /// Emit a bounded structured log record.
    ///
    /// # Errors
    ///
    /// Returns a capability or resource-limit error when logging is denied.
    fn log(&mut self, invocation: InvocationId, record: &LogRecord) -> Result<(), RuntimeError>;
}

pub trait HttpHost {
    /// Execute an authenticated HTTP request through an allowlisted host.
    ///
    /// # Errors
    ///
    /// Returns an HTTP policy, transport, or response error.
    fn request(
        &mut self,
        invocation: InvocationId,
        request: &AuthenticatedRequest,
    ) -> Result<HttpResponse, RuntimeError>;
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

/// Capability boundary for Concord shared-secret derivation.
///
/// Implementations own ECDH/HKDF and must not expose intermediate key
/// material to scripts or audit records. The reference fake host below is
/// deterministic for tests; production hosts must provide the protocol's
/// approved derivation algorithm.
pub trait ConcordKeyHost {
    /// Derive a stream key from opaque shared-secret material.
    ///
    /// # Errors
    ///
    /// Returns a capability or key-material validation error when derivation
    /// is denied or the secret is invalid.
    fn derive_stream_key(
        &mut self,
        invocation: InvocationId,
        secret: &SharedSecret,
    ) -> Result<DerivedKey, RuntimeError>;

    /// Derive a plane key with CORD-02 §4 `group_key(label, secret, id,
    /// epoch)`. `id` is a 32-byte lowercase-hex coordinate.
    ///
    /// # Errors
    ///
    /// Returns a capability error when denied, or
    /// [`RuntimeError::InvalidOperationArguments`] for a malformed `id`.
    fn derive_group_key(
        &mut self,
        invocation: InvocationId,
        label: stream::GroupKeyLabel,
        secret: &SharedSecret,
        id: &str,
        epoch: u64,
    ) -> Result<DerivedKey, RuntimeError>;
}

pub trait SignerProvisionHost {
    /// Provision a remote signer without exposing private key material.
    ///
    /// # Errors
    ///
    /// Returns `SignerDenied` when the provider is unavailable or disallowed.
    fn provision(
        &mut self,
        invocation: InvocationId,
        provider: &str,
    ) -> Result<SignerSession, RuntimeError>;
}

/// Transport boundary for a NIP-46 remote signer. Implementations own the
/// relay/encryption details; the runtime only ever receives signed events.
pub trait Nip46Transport {
    /// Establishes a remote signing session.
    ///
    /// # Errors
    ///
    /// Returns a signer error when the remote provider rejects the session.
    fn provision(&mut self, provider: &str) -> Result<SignerSession, RuntimeError>;
    /// Requests a signature without exposing key material to the host.
    ///
    /// # Errors
    ///
    /// Returns a signer error when the remote provider rejects the request.
    fn sign(
        &mut self,
        session: &SignerSession,
        event: UnsignedEvent,
    ) -> Result<SignedEvent, RuntimeError>;
}

/// NIP-46 signer host that enforces bunker URI validation and session binding.
pub struct Nip46SignerHost<T> {
    pub transport: T,
    sessions: BTreeMap<String, SignerSession>,
}

impl<T> Nip46SignerHost<T> {
    #[must_use]
    pub fn new(transport: T) -> Self {
        Self {
            transport,
            sessions: BTreeMap::new(),
        }
    }
}

impl<T: Nip46Transport> SignerProvisionHost for Nip46SignerHost<T> {
    fn provision(
        &mut self,
        _invocation: InvocationId,
        provider: &str,
    ) -> Result<SignerSession, RuntimeError> {
        if !(provider.starts_with("bunker://") || provider.starts_with("nostrconnect://")) {
            return Err(RuntimeError::SignerDenied {
                signer: provider.to_owned(),
            });
        }
        let session = self.transport.provision(provider)?;
        self.sessions
            .insert(session.provider.clone(), session.clone());
        Ok(session)
    }
}

impl<T: Nip46Transport> SignerHost for Nip46SignerHost<T> {
    fn sign(
        &mut self,
        _invocation: InvocationId,
        event: UnsignedEvent,
        signer: &str,
    ) -> Result<SignedEvent, RuntimeError> {
        let Some(session) = self.sessions.get(signer).cloned() else {
            return Err(RuntimeError::SignerDenied {
                signer: signer.to_owned(),
            });
        };
        self.transport.sign(&session, event)
    }
}

pub trait ClockHost {
    fn now(&self) -> u64;
}

pub trait TimerHost {
    /// Register a schedule with the host.
    ///
    /// # Errors
    ///
    /// Returns a stable runtime error when scheduling is denied or unavailable.
    fn schedule(
        &mut self,
        invocation: InvocationId,
        request: &ScheduleRequest,
    ) -> Result<TimerHandle, RuntimeError>;
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

pub trait TransactionalStorageHost: StorageHost {
    fn commit(&mut self, transaction: StorageTransaction);
}

pub trait IdempotencyHost {
    /// Atomically claim a key for one delivery.
    ///
    /// # Errors
    ///
    /// Returns a stable runtime error when the idempotency store is unavailable.
    fn claim_once(&mut self, invocation: InvocationId, key: &str) -> Result<bool, RuntimeError>;
}

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct InMemoryStorage {
    pub values: BTreeMap<String, String>,
    pub claimed: BTreeSet<String>,
}

impl StorageHost for InMemoryStorage {
    fn begin(&mut self, _invocation: InvocationId) -> StorageTransaction {
        StorageTransaction {
            reads: self.values.clone(),
            ..StorageTransaction::default()
        }
    }
}

impl TransactionalStorageHost for InMemoryStorage {
    fn commit(&mut self, transaction: StorageTransaction) {
        self.values.extend(transaction.writes);
    }
}

impl IdempotencyHost for InMemoryStorage {
    fn claim_once(&mut self, _invocation: InvocationId, key: &str) -> Result<bool, RuntimeError> {
        Ok(self.claimed.insert(key.to_owned()))
    }
}

/// Durable key/value storage host for local deployments.
///
/// The format is intentionally small and deterministic: one tab-separated
/// record per line, with `v` records for values and `c` records for claims.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct FileStorage {
    pub path: PathBuf,
    pub values: BTreeMap<String, String>,
    pub claimed: BTreeSet<String>,
}

impl FileStorage {
    /// Opens an existing store or creates an empty one in memory.
    ///
    /// # Errors
    ///
    /// Returns [`RuntimeError::StoreConflict`] when the file cannot be read or
    /// contains malformed records.
    pub fn open(path: impl Into<PathBuf>) -> Result<Self, RuntimeError> {
        let path = path.into();
        let mut storage = Self {
            path,
            values: BTreeMap::new(),
            claimed: BTreeSet::new(),
        };
        if storage.path.exists() {
            let contents =
                fs::read_to_string(&storage.path).map_err(|_| RuntimeError::StoreConflict)?;
            for line in contents.lines() {
                let mut fields = line.splitn(3, '\t');
                match (fields.next(), fields.next(), fields.next()) {
                    (Some("v"), Some(key), Some(value)) => {
                        storage.values.insert(key.to_owned(), value.to_owned());
                    }
                    (Some("c"), Some(key), None) => {
                        storage.claimed.insert(key.to_owned());
                    }
                    _ => return Err(RuntimeError::StoreConflict),
                }
            }
        }
        Ok(storage)
    }

    fn persist(&self) -> Result<(), RuntimeError> {
        let mut output = String::new();
        for (key, value) in &self.values {
            let _ = writeln!(output, "v\t{key}\t{value}");
        }
        for key in &self.claimed {
            let _ = writeln!(output, "c\t{key}");
        }
        let temp = self.path.with_extension("tmp");
        fs::write(&temp, output).map_err(|_| RuntimeError::StoreConflict)?;
        fs::rename(temp, &self.path).map_err(|_| RuntimeError::StoreConflict)
    }
}

impl StorageHost for FileStorage {
    fn begin(&mut self, _invocation: InvocationId) -> StorageTransaction {
        StorageTransaction {
            reads: self.values.clone(),
            ..StorageTransaction::default()
        }
    }
}

impl TransactionalStorageHost for FileStorage {
    fn commit(&mut self, transaction: StorageTransaction) {
        self.values.extend(transaction.writes);
        let _ = self.persist();
    }
}

impl IdempotencyHost for FileStorage {
    fn claim_once(&mut self, _invocation: InvocationId, key: &str) -> Result<bool, RuntimeError> {
        if !self.claimed.insert(key.to_owned()) {
            return Ok(false);
        }
        self.persist()?;
        Ok(true)
    }
}

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct StorageTransaction {
    reads: BTreeMap<String, String>,
    writes: BTreeMap<String, String>,
    committed: bool,
}

impl StorageTransaction {
    pub fn put(&mut self, key: impl Into<String>, value: impl Into<String>) {
        self.writes.insert(key.into(), value.into());
    }

    #[must_use]
    pub fn get(&self, key: &str) -> Option<&str> {
        self.writes
            .get(key)
            .or_else(|| self.reads.get(key))
            .map(String::as_str)
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
    seen_event_ids: BTreeSet<String>,
    max_subscription_batch: usize,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum HandlerFlow {
    Continue,
    Return,
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
            seen_event_ids: BTreeSet::new(),
            max_subscription_batch: 1024,
        }
    }

    /// Execute the checked program's effectful publication operations.
    ///
    /// # Errors
    ///
    /// Returns the first signer, relay, cancellation, or resource failure.
    pub fn run(
        &mut self,
        program: &Program,
        checked: &CheckedProgram,
    ) -> Result<Vec<PublishReport>, RuntimeError> {
        let invocation = self.next_invocation;
        self.next_invocation += 1;
        let mut reports = Vec::new();
        // Only a top-level `publish`: the checker collects one wherever it
        // appears (so a handler's own `publish` still gets its permission and
        // effect checks), but one written inside a handler body must wait for
        // that handler to actually run, not fire once here regardless of
        // whether any event ever reaches it. See `eval::top_level_publications`.
        for publication in eval::top_level_publications(Some(program), checked) {
            reports.push(self.execute_publication(invocation, publication)?);
        }
        Ok(reports)
    }

    /// Creates, signs and publishes an event right now, for a `publish`/`send`
    /// expression evaluated live from inside a handler body (as opposed to
    /// [`Runtime::run`]'s startup pass over the program's top-level
    /// publications). Same event construction as a top-level `publish`: only
    /// `content` is carried, and `kind` is inferred from `event_type` the same
    /// small way (`"Note"` is kind 1, anything else kind 0) — a handler gets
    /// the same publish capability top-level code already has, not more.
    ///
    /// # Errors
    ///
    /// Returns the signer's or the relay's failure, or
    /// [`RuntimeError::PublicationRejected`] if no relay accepted it.
    pub fn publish_now(
        &mut self,
        event_type: &str,
        content: Option<String>,
        relayset: &str,
        signer: &str,
    ) -> Result<PublishReport, RuntimeError> {
        let invocation = self.next_invocation;
        self.next_invocation += 1;
        let publication = CheckedPublication {
            event: event_type.to_owned(),
            content,
            signer: signer.to_owned(),
            relayset: relayset.to_owned(),
            span: nscript_syntax::Span::default(),
        };
        self.execute_publication(invocation, &publication)
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

    /// Provision a remote signer through a dedicated host adapter.
    ///
    /// # Errors
    ///
    /// Returns the host's signer provisioning failure.
    pub fn provision_signer<H: SignerProvisionHost>(
        &mut self,
        host: &mut H,
        provider: &str,
    ) -> Result<SignerSession, RuntimeError> {
        let invocation = self.next_invocation;
        self.next_invocation += 1;
        let result = host.provision(invocation, provider);
        self.audit.record(AuditEntry {
            invocation,
            operation: "provision_signer".to_owned(),
            target: provider.to_owned(),
            result: if result.is_ok() { "ok" } else { "error" }.to_owned(),
        });
        result
    }

    /// Authenticate a relay through a dedicated session host adapter.
    ///
    /// # Errors
    ///
    /// Returns the host's relay authentication failure.
    pub fn authenticate_relay<H: RelaySessionHost>(
        &mut self,
        host: &mut H,
        relay: &str,
    ) -> Result<AuthenticatedRelay, RuntimeError> {
        let invocation = self.next_invocation;
        self.next_invocation += 1;
        let result = host.authenticate(invocation, relay);
        self.audit.record(AuditEntry {
            invocation,
            operation: "authenticate_relay".to_owned(),
            target: relay.to_owned(),
            result: if result.is_ok() { "ok" } else { "error" }.to_owned(),
        });
        result
    }

    /// Open an audited typed event subscription.
    ///
    /// # Errors
    ///
    /// Returns the host's subscription failure.
    pub fn subscribe<H: SubscriptionHost>(
        &mut self,
        host: &mut H,
        request: &SubscriptionRequest,
    ) -> Result<SubscriptionHandle, RuntimeError> {
        let invocation = self.next_invocation;
        self.next_invocation += 1;
        let result = host.subscribe(invocation, request);
        self.audit.record(AuditEntry {
            invocation,
            operation: "subscribe".to_owned(),
            target: request.event_type.clone(),
            result: if result.is_ok() { "ok" } else { "error" }.to_owned(),
        });
        result
    }

    /// Close an audited typed event subscription.
    ///
    /// # Errors
    ///
    /// Returns the host's cleanup failure.
    pub fn unsubscribe<H: SubscriptionHost>(
        &mut self,
        host: &mut H,
        handle: &SubscriptionHandle,
    ) -> Result<(), RuntimeError> {
        let invocation = self.next_invocation;
        self.next_invocation += 1;
        let result = host.unsubscribe(invocation, handle);
        self.audit.record(AuditEntry {
            invocation,
            operation: "unsubscribe".to_owned(),
            target: handle.id.to_string(),
            result: if result.is_ok() { "ok" } else { "error" }.to_owned(),
        });
        result
    }

    /// Poll an audited event batch from a typed subscription.
    ///
    /// # Errors
    ///
    /// Returns the host's delivery failure.
    pub fn poll_subscription<H: SubscriptionHost>(
        &mut self,
        host: &mut H,
        handle: &SubscriptionHandle,
    ) -> Result<SubscriptionBatch, RuntimeError> {
        let invocation = self.next_invocation;
        self.next_invocation += 1;
        let result = host.poll(invocation, handle).and_then(|mut batch| {
            if batch.events.len() > self.max_subscription_batch {
                return Err(RuntimeError::ResourceLimit {
                    resource: "subscription_batch".to_owned(),
                });
            }
            // Drop an event that reached this subscription more than once (from
            // several relays, say). The key includes the subscription: a second
            // handler's subscription must still see an event the first has.
            batch.events.retain(|event| {
                self.seen_event_ids
                    .insert(format!("{}/{}", handle.id, event.id))
            });
            Ok(batch)
        });
        self.audit.record(AuditEntry {
            invocation,
            operation: "poll_subscription".to_owned(),
            target: handle.id.to_string(),
            result: match &result {
                Ok(batch) if batch.complete => "complete",
                Ok(_) => "ok",
                Err(_) => "error",
            }
            .to_owned(),
        });
        result
    }

    /// Poll a batch and atomically claim each event before handler delivery.
    ///
    /// # Errors
    ///
    /// Returns the subscription or idempotency-host failure.
    pub fn poll_and_claim<H: SubscriptionHost, I: IdempotencyHost>(
        &mut self,
        subscription_host: &mut H,
        idempotency_host: &mut I,
        handle: &SubscriptionHandle,
    ) -> Result<SubscriptionBatch, RuntimeError> {
        let mut batch = self.poll_subscription(subscription_host, handle)?;
        let mut claimed = Vec::with_capacity(batch.events.len());
        for event in batch.events {
            if self.claim_once(idempotency_host, &event.id)? {
                claimed.push(event);
            }
        }
        batch.events = claimed;
        Ok(batch)
    }

    /// Set the maximum number of events accepted from one subscription batch.
    pub fn set_max_subscription_batch(&mut self, limit: usize) {
        self.max_subscription_batch = limit;
    }

    /// Emit a structured log record through the host.
    ///
    /// # Errors
    ///
    /// Returns the host's logging failure.
    pub fn log<H: LogHost>(
        &mut self,
        host: &mut H,
        record: &LogRecord,
    ) -> Result<(), RuntimeError> {
        let invocation = self.next_invocation;
        self.next_invocation += 1;
        let result = host.log(invocation, record);
        self.audit.record(AuditEntry {
            invocation,
            operation: "log".to_owned(),
            target: record.level.clone(),
            result: if result.is_ok() { "ok" } else { "error" }.to_owned(),
        });
        result
    }

    /// Execute an authenticated request through a dedicated HTTP adapter.
    ///
    /// # Errors
    ///
    /// Returns the host's HTTP execution failure.
    pub fn execute_http<H: HttpHost>(
        &mut self,
        host: &mut H,
        request: &AuthenticatedRequest,
    ) -> Result<HttpResponse, RuntimeError> {
        let invocation = self.next_invocation;
        self.next_invocation += 1;
        let result = host.request(invocation, request);
        self.audit.record(AuditEntry {
            invocation,
            operation: "http_request".to_owned(),
            target: request.url.clone(),
            result: if result.is_ok() { "ok" } else { "error" }.to_owned(),
        });
        result
    }

    /// Register a host-controlled timer for an `every` or `at` declaration.
    ///
    /// # Errors
    ///
    /// Returns the host's scheduling failure.
    pub fn schedule_timer<H: TimerHost>(
        &mut self,
        host: &mut H,
        request: &ScheduleRequest,
    ) -> Result<TimerHandle, RuntimeError> {
        let invocation = self.next_invocation;
        self.next_invocation += 1;
        let result = host.schedule(invocation, request);
        self.audit.record(AuditEntry {
            invocation,
            operation: "schedule_timer".to_owned(),
            target: request.name.clone(),
            result: if result.is_ok() { "ok" } else { "error" }.to_owned(),
        });
        result
    }

    /// Schedule all statically checked `every` and `at` declarations.
    ///
    /// # Errors
    ///
    /// Returns the first host scheduling failure.
    pub fn schedule_program<H: TimerHost>(
        &mut self,
        host: &mut H,
        checked: &CheckedProgram,
    ) -> Result<Vec<TimerHandle>, RuntimeError> {
        let now = self.clock.now();
        checked
            .schedules
            .iter()
            .enumerate()
            .map(|(index, schedule)| {
                let request = ScheduleRequest {
                    name: format!("schedule-{index}"),
                    next_at: match schedule.kind {
                        CheckedScheduleKind::Every => now.saturating_add(schedule.value),
                        CheckedScheduleKind::At => schedule.value,
                    },
                    interval: match schedule.kind {
                        CheckedScheduleKind::Every => Some(schedule.value),
                        CheckedScheduleKind::At => None,
                    },
                    catch_up: false,
                };
                self.schedule_timer(host, &request)
            })
            .collect()
    }

    /// Lower checked `on` handlers into typed subscription requests.
    #[must_use]
    pub fn handler_subscriptions(
        checked: &CheckedProgram,
        relayset: Option<&str>,
    ) -> Vec<SubscriptionRequest> {
        checked
            .handlers
            .iter()
            .map(|handler| SubscriptionRequest {
                event_type: handler.event_type.clone(),
                relayset: relayset.map(str::to_owned),
                kinds: Vec::new(),
                tag_equals: handler.tag_equals.clone(),
                cursor: None,
                author: handler.author.clone(),
                since: None,
                limit: None,
            })
            .collect()
    }

    /// Check the locally available event fields against a typed subscription.
    /// Tag predicates remain host-side filter responsibilities until event tags
    /// are represented in the signed-event value.
    #[must_use]
    pub fn matches_subscription(request: &SubscriptionRequest, event: &SignedEvent) -> bool {
        if request.event_type != event.unsigned.event_type {
            return false;
        }
        if !request.kinds.is_empty() && !request.kinds.contains(&event.unsigned.kind) {
            return false;
        }
        if let Some(since) = request.since
            && event.unsigned.created_at < since
        {
            return false;
        }
        if let Some(author) = &request.author
            && author != &event.signer
        {
            return false;
        }
        if request.tag_equals.iter().any(|(name, value)| {
            !event
                .unsigned
                .tags
                .iter()
                .any(|tag| tag == &(name.clone(), value.clone()))
        }) {
            return false;
        }
        true
    }

    /// Dispatch one matched event through an idempotent handler callback.
    ///
    /// Returns `Ok(false)` when the filter does not match or the event was
    /// already claimed. The callback runs only for a newly claimed event.
    ///
    /// # Errors
    ///
    /// Returns idempotency or handler-body failures.
    pub fn dispatch_event<I, F>(
        &mut self,
        request: &SubscriptionRequest,
        event: &SignedEvent,
        idempotency_host: &mut I,
        key: &str,
        body: F,
    ) -> Result<bool, RuntimeError>
    where
        I: IdempotencyHost,
        F: FnOnce(&SignedEvent) -> Result<(), RuntimeError>,
    {
        if !Self::matches_subscription(request, event) {
            return Ok(false);
        }
        if !self.claim_once(idempotency_host, key)? {
            return Ok(false);
        }
        let result = body(event);
        self.audit.record(AuditEntry {
            invocation: self.next_invocation,
            operation: "handler".to_owned(),
            target: event.id.clone(),
            result: if result.is_ok() { "ok" } else { "error" }.to_owned(),
        });
        self.next_invocation += 1;
        result.map(|()| true)
    }

    /// Dispatch a matched event with an atomic storage transaction.
    ///
    /// # Errors
    ///
    /// Returns idempotency, storage, or handler-body failures. Failed bodies
    /// leave staged writes uncommitted.
    pub fn dispatch_event_transactional<I, T, F>(
        &mut self,
        request: &SubscriptionRequest,
        event: &SignedEvent,
        idempotency_host: &mut I,
        storage_host: &mut T,
        key: &str,
        body: F,
    ) -> Result<bool, RuntimeError>
    where
        I: IdempotencyHost,
        T: TransactionalStorageHost,
        F: FnOnce(&SignedEvent, &mut StorageTransaction) -> Result<(), RuntimeError>,
    {
        if !Self::matches_subscription(request, event) {
            return Ok(false);
        }
        if !self.claim_once(idempotency_host, key)? {
            return Ok(false);
        }
        let invocation = self.next_invocation;
        self.next_invocation += 1;
        let mut transaction = storage_host.begin(invocation);
        let result = body(event, &mut transaction);
        if result.is_ok() {
            storage_host.commit(transaction);
        }
        self.audit.record(AuditEntry {
            invocation,
            operation: "handler_transaction".to_owned(),
            target: event.id.clone(),
            result: if result.is_ok() {
                "committed"
            } else {
                "rolled_back"
            }
            .to_owned(),
        });
        result.map(|()| true)
    }

    /// Dispatch an event through the built-in checked handler interpreter.
    ///
    /// # Errors
    ///
    /// Returns idempotency, storage, logging, or handler-body failures.
    pub fn dispatch_checked_handler_transactional<I, T, L>(
        &mut self,
        request: &SubscriptionRequest,
        event: &SignedEvent,
        handler: &CheckedHandler,
        idempotency_host: &mut I,
        storage_host: &mut T,
        log_host: &mut L,
    ) -> Result<bool, RuntimeError>
    where
        I: IdempotencyHost,
        T: TransactionalStorageHost,
        L: LogHost,
    {
        if !Self::matches_subscription(request, event) {
            return Ok(false);
        }
        // Claimed per handler and event: a second handler on the same event
        // must still run.
        let claim = format!("{}/{}", handler.span.start, event.id);
        if !self.claim_once(idempotency_host, &claim)? {
            return Ok(false);
        }
        let invocation = self.next_invocation;
        self.next_invocation += 1;
        let transaction = storage_host.begin(invocation);
        let result = self.execute_handler_body_for_event(handler, event, log_host);
        if result.is_ok() {
            storage_host.commit(transaction);
        }
        self.audit.record(AuditEntry {
            invocation,
            operation: "handler_transaction".to_owned(),
            target: event.id.clone(),
            result: if result.is_ok() {
                "committed"
            } else {
                "rolled_back"
            }
            .to_owned(),
        });
        result.map(|()| true)
    }

    /// Run one polling cycle for every checked handler.
    ///
    /// This composes handler lowering, subscription lifecycle, bounded polling,
    /// idempotency, and transactional body execution. The callback is the
    /// interpreter seam for handler statements.
    ///
    /// # Errors
    ///
    /// Returns the first subscription, polling, idempotency, storage, or body
    /// failure.
    pub fn run_handler_cycle<H, I, T, F>(
        &mut self,
        checked: &CheckedProgram,
        relayset: Option<&str>,
        subscription_host: &mut H,
        idempotency_host: &mut I,
        storage_host: &mut T,
        mut body: F,
    ) -> Result<usize, RuntimeError>
    where
        H: SubscriptionHost,
        I: IdempotencyHost,
        T: TransactionalStorageHost,
        F: FnMut(
            &CheckedHandler,
            &SignedEvent,
            &mut StorageTransaction,
        ) -> Result<(), RuntimeError>,
    {
        let subscriptions = Self::handler_subscriptions(checked, relayset);
        let mut dispatched = 0;
        for (handler, request) in checked.handlers.iter().zip(subscriptions.iter()) {
            let handle = self.subscribe(subscription_host, request)?;
            let batch = match self.poll_subscription(subscription_host, &handle) {
                Ok(batch) => batch,
                Err(error) => {
                    let _ = self.unsubscribe(subscription_host, &handle);
                    return Err(error);
                }
            };
            for event in batch.events {
                let key = event.id.clone();
                let result = self.dispatch_event_transactional(
                    request,
                    &event,
                    idempotency_host,
                    storage_host,
                    &key,
                    |event, transaction| body(handler, event, transaction),
                );
                match result {
                    Ok(true) => dispatched += 1,
                    Ok(false) => {}
                    Err(error) => {
                        let _ = self.unsubscribe(subscription_host, &handle);
                        return Err(error);
                    }
                }
            }
            self.unsubscribe(subscription_host, &handle)?;
        }
        Ok(dispatched)
    }

    /// Run one polling cycle using each checked handler's executable body.
    ///
    /// # Errors
    ///
    /// Returns the first subscription, polling, idempotency, storage, logging,
    /// or handler-body failure.
    pub fn run_handler_cycle_with_event_body<H, I, T, L>(
        &mut self,
        checked: &CheckedProgram,
        relayset: Option<&str>,
        subscription_host: &mut H,
        idempotency_host: &mut I,
        storage_host: &mut T,
        log_host: &mut L,
    ) -> Result<usize, RuntimeError>
    where
        H: SubscriptionHost,
        I: IdempotencyHost,
        T: TransactionalStorageHost,
        L: LogHost,
    {
        let subscriptions = Self::handler_subscriptions(checked, relayset);
        let mut dispatched = 0;
        for (handler, request) in checked.handlers.iter().zip(subscriptions.iter()) {
            let handle = self.subscribe(subscription_host, request)?;
            let batch = match self.poll_subscription(subscription_host, &handle) {
                Ok(batch) => batch,
                Err(error) => {
                    let _ = self.unsubscribe(subscription_host, &handle);
                    return Err(error);
                }
            };
            for event in batch.events {
                match self.dispatch_checked_handler_transactional(
                    request,
                    &event,
                    handler,
                    idempotency_host,
                    storage_host,
                    log_host,
                ) {
                    Ok(true) => dispatched += 1,
                    Ok(false) => {}
                    Err(error) => {
                        let _ = self.unsubscribe(subscription_host, &handle);
                        return Err(error);
                    }
                }
            }
            self.unsubscribe(subscription_host, &handle)?;
        }
        Ok(dispatched)
    }

    /// Execute the currently supported handler body subset through host effects.
    ///
    /// The interpreter supports direct `print(...)` statements, boolean `if`
    /// branches, and bounded iteration over delivered event tags; unsupported
    /// statements return a stable runtime error instead of being silently
    /// skipped.
    ///
    /// # Errors
    ///
    /// Returns logging or unsupported-body failures.
    pub fn execute_handler_body<H: LogHost>(
        &mut self,
        handler: &CheckedHandler,
        log_host: &mut H,
    ) -> Result<(), RuntimeError> {
        self.execute_handler_items(&handler.body, None, &mut BTreeMap::new(), log_host)
            .map(|_| ())
    }

    /// Execute a handler body with the delivered event available to conditions.
    ///
    /// The event binding currently exposes `event.id`, `event.author`, and
    /// `event.content` in boolean comparisons and `contains` expressions.
    ///
    /// # Errors
    ///
    /// Returns logging or unsupported-body failures.
    pub fn execute_handler_body_for_event<H: LogHost>(
        &mut self,
        handler: &CheckedHandler,
        event: &SignedEvent,
        log_host: &mut H,
    ) -> Result<(), RuntimeError> {
        self.execute_handler_items(&handler.body, Some(event), &mut BTreeMap::new(), log_host)
            .map(|_| ())
    }

    fn execute_handler_items<H: LogHost>(
        &mut self,
        items: &[Item],
        event: Option<&SignedEvent>,
        bindings: &mut BTreeMap<String, String>,
        log_host: &mut H,
    ) -> Result<HandlerFlow, RuntimeError> {
        for item in items {
            if let Item::Let(declaration) = item {
                let Some(value) = Self::handler_text(&declaration.value, event, bindings) else {
                    return Err(RuntimeError::InvalidOperationArguments {
                        operation: "handler_let".to_owned(),
                    });
                };
                bindings.insert(declaration.name.value.clone(), value);
                continue;
            }
            let Item::Statement(statement) = item else {
                continue;
            };
            match &statement.value {
                StatementKind::Return(Some(_)) => {
                    return Err(RuntimeError::OperationUnavailable {
                        module: "handler".to_owned(),
                        operation: "return_value".to_owned(),
                    });
                }
                StatementKind::Return(None) => return Ok(HandlerFlow::Return),
                StatementKind::Expression(expression) => {
                    let ExprKind::Call { callee, arguments } = &expression.value else {
                        return Err(RuntimeError::OperationUnavailable {
                            module: "handler".to_owned(),
                            operation: "body_expression".to_owned(),
                        });
                    };
                    if !matches!(&callee.value, ExprKind::Identifier(name) if name == "print")
                        || arguments.len() != 1
                    {
                        return Err(RuntimeError::OperationUnavailable {
                            module: "handler".to_owned(),
                            operation: "body_call".to_owned(),
                        });
                    }
                    let Some(message) = Self::handler_text(&arguments[0], event, bindings) else {
                        return Err(RuntimeError::InvalidOperationArguments {
                            operation: "print".to_owned(),
                        });
                    };
                    self.log(
                        log_host,
                        &LogRecord {
                            level: "info".to_owned(),
                            message,
                        },
                    )?;
                }
                StatementKind::If {
                    condition,
                    then_body,
                    else_body,
                } => {
                    if Self::evaluate_handler_condition(condition, event, bindings)? {
                        if self.execute_handler_items(then_body, event, bindings, log_host)?
                            == HandlerFlow::Return
                        {
                            return Ok(HandlerFlow::Return);
                        }
                    } else if self.execute_handler_items(else_body, event, bindings, log_host)?
                        == HandlerFlow::Return
                    {
                        return Ok(HandlerFlow::Return);
                    }
                }
                StatementKind::For {
                    binding,
                    value,
                    body,
                } if Self::is_event_tags(value) && event.is_some() => {
                    let event = event.expect("guarded event binding");
                    for (name, value) in &event.unsigned.tags {
                        let previous =
                            bindings.insert(binding.value.clone(), format!("{name}={value}"));
                        if self.execute_handler_items(body, Some(event), bindings, log_host)?
                            == HandlerFlow::Return
                        {
                            return Ok(HandlerFlow::Return);
                        }
                        if let Some(previous) = previous {
                            bindings.insert(binding.value.clone(), previous);
                        } else {
                            bindings.remove(&binding.value);
                        }
                    }
                }
                _ => {
                    return Err(RuntimeError::OperationUnavailable {
                        module: "handler".to_owned(),
                        operation: "body_statement".to_owned(),
                    });
                }
            }
        }
        Ok(HandlerFlow::Continue)
    }

    fn evaluate_handler_condition(
        expression: &nscript_syntax::ast::Expr,
        event: Option<&SignedEvent>,
        bindings: &BTreeMap<String, String>,
    ) -> Result<bool, RuntimeError> {
        match &expression.value {
            ExprKind::Bool(value) => Ok(*value),
            ExprKind::Unary { operator, value } if operator == "!" => {
                Ok(!Self::evaluate_handler_condition(value, event, bindings)?)
            }
            ExprKind::Binary {
                operator,
                left,
                right,
            } if operator == "&&" || operator == "||" => {
                let left = Self::evaluate_handler_condition(left, event, bindings)?;
                if operator == "&&" {
                    Ok(left && Self::evaluate_handler_condition(right, event, bindings)?)
                } else {
                    Ok(left || Self::evaluate_handler_condition(right, event, bindings)?)
                }
            }
            ExprKind::Binary {
                operator,
                left,
                right,
            } if matches!(operator.as_str(), "==" | "!=" | "contains") => {
                if operator == "contains" {
                    if let Some(tag_name) = Self::handler_tag_name(left) {
                        let Some(needle) = Self::handler_text(right, event, bindings) else {
                            return Err(RuntimeError::InvalidOperationArguments {
                                operation: "handler_condition".to_owned(),
                            });
                        };
                        let event =
                            event.ok_or_else(|| RuntimeError::InvalidOperationArguments {
                                operation: "handler_condition".to_owned(),
                            })?;
                        return Ok(event
                            .unsigned
                            .tags
                            .iter()
                            .any(|(name, value)| name == &tag_name && value == &needle));
                    }
                    let (Some(haystack), Some(needle)) = (
                        Self::handler_text(left, event, bindings),
                        Self::handler_text(right, event, bindings),
                    ) else {
                        return Err(RuntimeError::InvalidOperationArguments {
                            operation: "handler_condition".to_owned(),
                        });
                    };
                    return Ok(haystack.contains(&needle));
                }
                let equal = match (&left.value, &right.value) {
                    (ExprKind::Bool(a), ExprKind::Bool(b)) => a == b,
                    (ExprKind::Integer(a), ExprKind::Integer(b)) => a == b,
                    (ExprKind::Text(a), ExprKind::Text(b)) => a == b,
                    (ExprKind::Member { .. }, ExprKind::Integer(value)) => {
                        Self::handler_integer(left, event)? == *value
                    }
                    (ExprKind::Integer(value), ExprKind::Member { .. }) => {
                        *value == Self::handler_integer(right, event)?
                    }
                    _ => match (
                        Self::handler_text(left, event, bindings),
                        Self::handler_text(right, event, bindings),
                    ) {
                        (Some(a), Some(b)) => a == b,
                        _ => {
                            return Err(RuntimeError::InvalidOperationArguments {
                                operation: "handler_condition".to_owned(),
                            });
                        }
                    },
                };
                Ok(if operator == "==" { equal } else { !equal })
            }
            _ => Err(RuntimeError::InvalidOperationArguments {
                operation: "handler_condition".to_owned(),
            }),
        }
    }

    fn handler_text(
        expression: &nscript_syntax::ast::Expr,
        event: Option<&SignedEvent>,
        bindings: &BTreeMap<String, String>,
    ) -> Option<String> {
        match &expression.value {
            ExprKind::Text(value) => Some(value.clone()),
            ExprKind::Identifier(name) => bindings.get(name).cloned(),
            ExprKind::Member { value, name } if matches!(&value.value, ExprKind::Identifier(base) if base == "event") =>
            {
                let event = event?;
                match name.value.as_str() {
                    "id" => Some(event.id.clone()),
                    "author" => Some(event.signer.clone()),
                    "content" => Some(event.unsigned.content.clone()),
                    _ => None,
                }
            }
            _ => None,
        }
    }

    fn handler_integer(
        expression: &nscript_syntax::ast::Expr,
        event: Option<&SignedEvent>,
    ) -> Result<i64, RuntimeError> {
        match &expression.value {
            ExprKind::Integer(value) => Ok(*value),
            ExprKind::Member { value, name }
                if matches!(&value.value, ExprKind::Identifier(base) if base == "event")
                    && name.value == "kind" =>
            {
                let event = event.ok_or_else(|| RuntimeError::InvalidOperationArguments {
                    operation: "handler_condition".to_owned(),
                })?;
                Ok(i64::from(event.unsigned.kind))
            }
            _ => Err(RuntimeError::InvalidOperationArguments {
                operation: "handler_condition".to_owned(),
            }),
        }
    }

    fn handler_tag_name(expression: &nscript_syntax::ast::Expr) -> Option<String> {
        let ExprKind::Member { value, name } = &expression.value else {
            return None;
        };
        let ExprKind::Member {
            value: tags,
            name: tag_name,
        } = &value.value
        else {
            return None;
        };
        if matches!(&tags.value, ExprKind::Identifier(base) if base == "event")
            && tag_name.value == "tags"
        {
            Some(name.value.clone())
        } else {
            None
        }
    }

    fn is_event_tags(expression: &nscript_syntax::ast::Expr) -> bool {
        matches!(
            &expression.value,
            ExprKind::Member { value, name }
                if matches!(&value.value, ExprKind::Identifier(base) if base == "event")
                    && name.value == "tags"
        )
    }

    /// Run a staged storage transaction and commit it only when the closure succeeds.
    ///
    /// # Errors
    ///
    /// Returns the closure's error; failed transactions are discarded.
    pub fn storage_transaction<H, F>(
        &mut self,
        host: &mut H,
        operation: &str,
        f: F,
    ) -> Result<(), RuntimeError>
    where
        H: TransactionalStorageHost,
        F: FnOnce(&mut StorageTransaction) -> Result<(), RuntimeError>,
    {
        let invocation = self.next_invocation;
        self.next_invocation += 1;
        let mut transaction = host.begin(invocation);
        let result = f(&mut transaction);
        if result.is_ok() {
            host.commit(transaction);
        }
        self.audit.record(AuditEntry {
            invocation,
            operation: operation.to_owned(),
            target: "storage".to_owned(),
            result: if result.is_ok() {
                "committed"
            } else {
                "rolled_back"
            }
            .to_owned(),
        });
        result
    }

    /// Atomically claim an idempotency key for a delivered event.
    ///
    /// # Errors
    ///
    /// Returns the host's idempotency-store failure.
    pub fn claim_once<H: IdempotencyHost + ?Sized>(
        &mut self,
        host: &mut H,
        key: &str,
    ) -> Result<bool, RuntimeError> {
        let invocation = self.next_invocation;
        self.next_invocation += 1;
        let result = host.claim_once(invocation, key);
        self.audit.record(AuditEntry {
            invocation,
            operation: "claim_once".to_owned(),
            target: key.to_owned(),
            result: match result {
                Ok(true) => "claimed",
                Ok(false) => "already_claimed",
                Err(_) => "error",
            }
            .to_owned(),
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
        if module == "nip47"
            && operation == "pay_invoice"
            && let Some(amount) = payment_amount(arguments)
            && let Some(limit) = policy.payment_limit()
            && amount > limit
        {
            return Err(RuntimeError::PaymentLimitExceeded { amount, limit });
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
        // Calls inside a handler run when an event arrives, not at startup.
        eval::top_level_operation_calls(None, checked)
            .into_iter()
            .map(|call| {
                let arguments = call
                    .arguments
                    .iter()
                    .map(|argument| match argument {
                        CheckedArgument::PubKey(name) if checked.keys.contains_key(name) => host
                            .host_key(&checked.keys[name])
                            .map(OperationValue::DerivedKey),
                        other => Ok(checked_to_operation(other)),
                    })
                    .collect::<Result<Vec<_>, _>>()?;
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
            tags: Vec::new(),
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

/// A pure protocol query's implementation, dispatched by
/// [`OperationHost::call_pure_function`].
type PureFunction = fn(&[OperationValue]) -> Result<OperationValue, RuntimeError>;

/// The fold queries RFC 0002 §3 proposes, resolved by `(module, function)`.
/// Adding one here is the whole implementation: every [`OperationHost`]
/// answers it identically, with no per-host wiring.
fn pure_function(module: &str, function: &str) -> Option<PureFunction> {
    match (module, function) {
        ("concord05", "invite_is_valid") => Some(invite_is_valid as PureFunction),
        ("concord06", "commitment_matches") => Some(commitment_matches as PureFunction),
        ("nip05", "identifier_matches") => Some(nip05_identifier_matches as PureFunction),
        _ => None,
    }
}

fn invalid(function: &'static str) -> RuntimeError {
    RuntimeError::InvalidOperationArguments {
        operation: function.to_owned(),
    }
}

/// CORD-05 §6/§7: whether a bundle's own structure is well-formed, its
/// owner self-certification reproduces its `community_id`, and (given the
/// caller's clock) it has not expired. Never touches a relay or a key: the
/// bundle is data the script already holds, and no secret is exposed, only a
/// yes/no.
fn invite_is_valid(arguments: &[OperationValue]) -> Result<OperationValue, RuntimeError> {
    let [
        OperationValue::Text(bundle_json),
        OperationValue::Integer(now_ms),
    ] = arguments
    else {
        return Err(invalid("invite_is_valid"));
    };
    let now_ms = u64::try_from(*now_ms).map_err(|_| invalid("invite_is_valid"))?;
    let valid = match crate::invite::parse_invite(bundle_json) {
        Ok(invite) => invite
            .expires_at
            .is_none_or(|expires_at| now_ms < expires_at),
        Err(_) => false,
    };
    Ok(OperationValue::Bool(valid))
}

/// NIP-05: whether a fetched `/.well-known/nostr.json` response's `names`
/// mapping for `local_part` matches `pubkey`. This is the verification the
/// spec actually asks for — the DNS fetch itself is ordinary host I/O
/// (`fetch text from ...`), not something this function does; it only
/// compares data the script already holds. Hex pubkeys are compared
/// case-insensitively, matching how relays and clients already normalize
/// them elsewhere in this crate.
fn nip05_identifier_matches(arguments: &[OperationValue]) -> Result<OperationValue, RuntimeError> {
    let [
        OperationValue::Text(local_part),
        OperationValue::Text(response_json),
        OperationValue::PubKey(pubkey),
    ] = arguments
    else {
        return Err(invalid("identifier_matches"));
    };
    let matches = serde_json::from_str::<serde_json::Value>(response_json)
        .ok()
        .and_then(|response| {
            response
                .get("names")?
                .get(local_part)?
                .as_str()
                .map(str::to_owned)
        })
        .is_some_and(|found| found.eq_ignore_ascii_case(pubkey));
    Ok(OperationValue::Bool(matches))
}

/// CORD-06 §4 continuity: whether a key the caller already holds, compared at
/// `held_epoch`, reproduces a rotation's committed `epoch_key_commitment`
/// tag. A script uses this to decide whether a rekey notice actually extends
/// what it holds before spending effort trying to apply it — the key itself
/// never leaves the opaque [`DerivedKey`] handle, only the comparison's
/// result does.
fn commitment_matches(arguments: &[OperationValue]) -> Result<OperationValue, RuntimeError> {
    let [
        OperationValue::DerivedKey(held_key),
        OperationValue::Integer(held_epoch),
        OperationValue::Text(commitment),
    ] = arguments
    else {
        return Err(invalid("commitment_matches"));
    };
    let held_epoch = u64::try_from(*held_epoch).map_err(|_| invalid("commitment_matches"))?;
    let key_bytes: [u8; 32] = held_key
        .as_bytes()
        .try_into()
        .map_err(|_| invalid("commitment_matches"))?;
    let expected = crate::rekey::epoch_key_commitment(held_epoch, &key_bytes);
    Ok(OperationValue::Bool(expected == *commitment))
}

fn checked_to_operation(argument: &CheckedArgument) -> OperationValue {
    match argument {
        CheckedArgument::Text(value) => OperationValue::Text(value.clone()),
        CheckedArgument::Integer(value) => OperationValue::Integer(*value),
        CheckedArgument::Bool(value) => OperationValue::Bool(*value),
        CheckedArgument::PubKey(value) => OperationValue::PubKey(value.clone()),
        CheckedArgument::Record { name, fields } => OperationValue::Record {
            name: name.clone(),
            fields: fields
                .iter()
                .map(|(field, value)| (field.clone(), checked_to_operation(value)))
                .collect(),
        },
        CheckedArgument::List(items) => {
            OperationValue::List(items.iter().map(checked_to_operation).collect())
        }
    }
}

fn payment_amount(arguments: &[OperationValue]) -> Option<i64> {
    match arguments {
        [OperationValue::WalletPayment(payment)] => Some(payment.amount),
        [OperationValue::Record { name, fields }] if name == "WalletPayment" => {
            fields.iter().find_map(|(field, value)| {
                (field == "amount").then_some(match value {
                    OperationValue::Integer(amount) => Some(*amount),
                    _ => None,
                })?
            })
        }
        _ => None,
    }
}

#[cfg(feature = "real-hosts")]
#[derive(Debug)]
/// Minimal production relay adapter for `ws://` and `wss://` Nostr relays.
///
/// The adapter keeps one WebSocket session, translates typed subscription
/// requests into NIP-01 filters, drains `EVENT` frames through `EOSE`, and
/// publishes signed events while preserving relay outcomes.
pub struct RealRelayHost {
    relay: String,
    socket: WebSocket<MaybeTlsStream<TcpStream>>,
    next_subscription: u64,
    subscriptions: BTreeMap<u64, String>,
}

/// How long a relay read may block before the relay counts as unavailable.
#[cfg(feature = "real-hosts")]
const RELAY_IO_TIMEOUT: Duration = Duration::from_secs(10);
/// Frames skipped while waiting for the `OK` that answers a publish.
#[cfg(feature = "real-hosts")]
const MAX_FRAMES_BEFORE_OK: usize = 64;

#[cfg(feature = "real-hosts")]
fn set_read_timeout(socket: &mut WebSocket<MaybeTlsStream<TcpStream>>, timeout: Duration) {
    match socket.get_mut() {
        MaybeTlsStream::Plain(stream) => {
            let _ = stream.set_read_timeout(Some(timeout));
        }
        MaybeTlsStream::Rustls(stream) => {
            let _ = stream.get_mut().set_read_timeout(Some(timeout));
        }
        _ => {}
    }
}

/// Opens a relay WebSocket, first making sure TLS has a crypto provider.
///
/// tungstenite's `rustls-tls-native-roots` feature selects no provider, so a
/// `wss://` connect panics until one is installed. A provider the host
/// application already installed is left untouched.
#[cfg(feature = "real-hosts")]
fn open_socket(relay: &str) -> Result<WebSocket<MaybeTlsStream<TcpStream>>, RuntimeError> {
    if rustls::crypto::CryptoProvider::get_default().is_none() {
        // A concurrent installer winning the race is equally fine.
        let _ = rustls::crypto::ring::default_provider().install_default();
    }
    let (mut socket, _) = connect(relay).map_err(|_| RuntimeError::RelayUnavailable {
        relayset: relay.to_owned(),
    })?;
    // A silent relay must not hang the program.
    set_read_timeout(&mut socket, RELAY_IO_TIMEOUT);
    Ok(socket)
}

#[cfg(feature = "real-hosts")]
impl RealRelayHost {
    /// Bounds how long a read may block before the relay counts as
    /// unavailable (default ten seconds).
    pub fn set_read_timeout(&mut self, timeout: Duration) {
        set_read_timeout(&mut self.socket, timeout);
    }

    /// Connect to a relay URL.
    ///
    /// # Errors
    ///
    /// Returns `RelayUnavailable` when the URL cannot be opened.
    pub fn connect(relay: impl Into<String>) -> Result<Self, RuntimeError> {
        let relay = relay.into();
        let socket = open_socket(&relay)?;
        Ok(Self {
            relay,
            socket,
            next_subscription: 1,
            subscriptions: BTreeMap::new(),
        })
    }

    /// Reconnect the relay socket and discard stale subscription handles.
    ///
    /// Callers should rebuild subscriptions after reconnecting because relay
    /// servers do not retain a previous WebSocket session's `REQ` state.
    ///
    /// # Errors
    ///
    /// Returns `RelayUnavailable` when the socket cannot be re-established.
    pub fn reconnect(&mut self) -> Result<(), RuntimeError> {
        self.socket = Self::connect_socket(&self.relay)?;
        self.subscriptions.clear();
        Ok(())
    }

    /// Reconnect with bounded exponential backoff.
    ///
    /// Attempts are capped at eight and each delay at five seconds.
    ///
    /// # Errors
    ///
    /// Returns `RelayUnavailable` after all attempts fail.
    pub fn reconnect_with_backoff(
        &mut self,
        attempts: u8,
        initial_delay: Duration,
    ) -> Result<(), RuntimeError> {
        let attempts = attempts.clamp(1, 8);
        let mut delay = initial_delay.min(Duration::from_secs(5));
        let mut last_error = None;
        for attempt in 0..attempts {
            match Self::connect_socket(&self.relay) {
                Ok(socket) => {
                    self.socket = socket;
                    self.subscriptions.clear();
                    return Ok(());
                }
                Err(error) => last_error = Some(error),
            }
            if attempt + 1 < attempts {
                thread::sleep(delay);
                delay = (delay * 2).min(Duration::from_secs(5));
            }
        }
        Err(
            last_error.unwrap_or_else(|| RuntimeError::RelayUnavailable {
                relayset: self.relay.clone(),
            }),
        )
    }

    fn connect_socket(relay: &str) -> Result<WebSocket<MaybeTlsStream<TcpStream>>, RuntimeError> {
        open_socket(relay)
    }

    fn send_json(&mut self, value: &Value) -> Result<(), RuntimeError> {
        self.socket
            .send(Message::Text(value.to_string().into()))
            .map_err(|_| RuntimeError::RelayUnavailable {
                relayset: self.relay.clone(),
            })
    }

    fn receive_json(&mut self) -> Result<Value, RuntimeError> {
        loop {
            let message = self
                .socket
                .read()
                .map_err(|_| RuntimeError::RelayUnavailable {
                    relayset: self.relay.clone(),
                })?;
            if let Message::Text(text) = message {
                return serde_json::from_str(&text).map_err(|_| RuntimeError::RelayUnavailable {
                    relayset: self.relay.clone(),
                });
            }
        }
    }

    fn parse_event(value: &Value) -> Option<SignedEvent> {
        let object = value.as_object()?;
        let tags = object
            .get("tags")?
            .as_array()?
            .iter()
            .filter_map(|tag| {
                let values = tag.as_array()?;
                Some((
                    values.first()?.as_str()?.to_owned(),
                    values.get(1)?.as_str()?.to_owned(),
                ))
            })
            .collect();
        Some(SignedEvent {
            unsigned: UnsignedEvent {
                event_type: "Event".to_owned(),
                kind: u16::try_from(object.get("kind")?.as_u64()?).ok()?,
                content: object.get("content")?.as_str()?.to_owned(),
                tags,
                created_at: object.get("created_at")?.as_u64()?,
            },
            signer: object.get("pubkey")?.as_str()?.to_owned(),
            id: object.get("id")?.as_str()?.to_owned(),
            signature: object.get("sig")?.as_str()?.to_owned(),
        })
    }
}

#[cfg(feature = "real-hosts")]
impl RelayHost for RealRelayHost {
    fn publish(
        &mut self,
        _invocation: InvocationId,
        event: &SignedEvent,
        _relayset: &str,
    ) -> Result<PublishReport, RuntimeError> {
        self.send_json(&json!([
            "EVENT",
            {
                "id": event.id,
                "pubkey": event.signer,
                "created_at": event.unsigned.created_at,
                "kind": event.unsigned.kind,
                "tags": event.unsigned.wire_tags(),
                "content": event.unsigned.content,
                "sig": event.signature,
            }
        ]))?;
        // NIP-01: the relay answers with ["OK", <event id>, <accepted>, <message>].
        // NOTICE, EVENT and EOSE frames may interleave and are not the answer.
        for _ in 0..MAX_FRAMES_BEFORE_OK {
            let response = self.receive_json()?;
            let is_answer = response.get(0).and_then(Value::as_str) == Some("OK")
                && response.get(1).and_then(Value::as_str) == Some(event.id.as_str());
            if !is_answer {
                continue;
            }
            return Ok(PublishReport {
                outcomes: vec![RelayOutcome {
                    relay: self.relay.clone(),
                    accepted: response.get(2).and_then(Value::as_bool).unwrap_or(false),
                    detail: response
                        .get(3)
                        .and_then(Value::as_str)
                        .unwrap_or_default()
                        .to_owned(),
                }],
            });
        }
        Err(RuntimeError::RelayUnavailable {
            relayset: self.relay.clone(),
        })
    }
}

#[cfg(feature = "real-hosts")]
impl SubscriptionHost for RealRelayHost {
    fn subscribe(
        &mut self,
        _invocation: InvocationId,
        request: &SubscriptionRequest,
    ) -> Result<SubscriptionHandle, RuntimeError> {
        let id = self.next_subscription;
        self.next_subscription += 1;
        let mut filter = serde_json::Map::new();
        if !request.kinds.is_empty() {
            filter.insert("kinds".to_owned(), json!(request.kinds));
        }
        if let Some(author) = &request.author {
            filter.insert("authors".to_owned(), json!([author]));
        }
        if let Some(since) = request.since {
            filter.insert("since".to_owned(), json!(since));
        }
        if let Some(limit) = request.limit {
            filter.insert("limit".to_owned(), json!(limit));
        }
        for (name, value) in &request.tag_equals {
            filter.insert(format!("#{name}"), json!([value]));
        }
        self.send_json(&json!(["REQ", id.to_string(), Value::Object(filter)]))?;
        self.subscriptions.insert(id, id.to_string());
        Ok(SubscriptionHandle { id })
    }

    fn unsubscribe(
        &mut self,
        _invocation: InvocationId,
        handle: &SubscriptionHandle,
    ) -> Result<(), RuntimeError> {
        self.send_json(&json!(["CLOSE", handle.id.to_string()]))?;
        self.subscriptions.remove(&handle.id);
        Ok(())
    }

    fn poll(
        &mut self,
        _invocation: InvocationId,
        handle: &SubscriptionHandle,
    ) -> Result<SubscriptionBatch, RuntimeError> {
        let subscription = self.subscriptions.get(&handle.id).cloned().ok_or_else(|| {
            RuntimeError::RelayUnavailable {
                relayset: self.relay.clone(),
            }
        })?;
        let mut events = Vec::new();
        loop {
            let frame = self.receive_json()?;
            match frame.get(0).and_then(Value::as_str) {
                Some("EVENT") if frame.get(1).and_then(Value::as_str) == Some(&subscription) => {
                    if let Some(event) = frame.get(2).and_then(Self::parse_event) {
                        events.push(event);
                    }
                }
                Some("EOSE") if frame.get(1).and_then(Value::as_str) == Some(&subscription) => {
                    return Ok(SubscriptionBatch {
                        events,
                        complete: true,
                        cursor: None,
                    });
                }
                _ => {}
            }
        }
    }
}

/// Reusable connection pool for multiple Nostr relays.
#[derive(Debug, Default)]
#[cfg(feature = "real-hosts")]
pub struct RealRelayPool {
    relays: BTreeMap<String, RealRelayHost>,
    handles: BTreeMap<u64, (String, SubscriptionHandle)>,
    next_handle: u64,
}

#[cfg(feature = "real-hosts")]
impl RealRelayPool {
    #[must_use]
    pub fn new() -> Self {
        Self {
            relays: BTreeMap::new(),
            handles: BTreeMap::new(),
            next_handle: 1,
        }
    }

    /// Connect and add a relay to the pool.
    ///
    /// # Errors
    ///
    /// Returns `RelayUnavailable` when the relay cannot be connected.
    pub fn add_relay(&mut self, relay: impl Into<String>) -> Result<(), RuntimeError> {
        let relay = relay.into();
        let host = RealRelayHost::connect(relay.clone())?;
        self.relays.insert(relay, host);
        Ok(())
    }

    /// Reconnect every pooled relay and invalidate subscription handles.
    ///
    /// # Errors
    ///
    /// Returns the first relay connection failure.
    pub fn reconnect_all(&mut self) -> Result<(), RuntimeError> {
        self.handles.clear();
        for relay in self.relays.values_mut() {
            relay.reconnect()?;
        }
        Ok(())
    }

    #[must_use]
    pub fn relay_urls(&self) -> Vec<String> {
        self.relays.keys().cloned().collect()
    }

    fn select_relay(&self, relayset: Option<&str>) -> Option<String> {
        relayset
            .and_then(|name| self.relays.contains_key(name).then(|| name.to_owned()))
            .or_else(|| self.relays.keys().next().cloned())
    }
}

#[cfg(feature = "real-hosts")]
impl RelayHost for RealRelayPool {
    fn publish(
        &mut self,
        invocation: InvocationId,
        event: &SignedEvent,
        relayset: &str,
    ) -> Result<PublishReport, RuntimeError> {
        if let Some(relay) = self.relays.get_mut(relayset) {
            return relay.publish(invocation, event, relayset);
        }
        // Partial publication: one failing relay is an outcome, never a reason
        // to drop the others' results.
        let mut outcomes = Vec::new();
        for (name, relay) in &mut self.relays {
            match relay.publish(invocation, event, name) {
                Ok(report) => outcomes.extend(report.outcomes),
                Err(_) => outcomes.push(RelayOutcome {
                    relay: name.clone(),
                    accepted: false,
                    detail: "relay unavailable".to_owned(),
                }),
            }
        }
        if outcomes.is_empty() {
            return Err(RuntimeError::RelayUnavailable {
                relayset: relayset.to_owned(),
            });
        }
        Ok(PublishReport { outcomes })
    }
}

#[cfg(feature = "real-hosts")]
impl SubscriptionHost for RealRelayPool {
    fn subscribe(
        &mut self,
        invocation: InvocationId,
        request: &SubscriptionRequest,
    ) -> Result<SubscriptionHandle, RuntimeError> {
        let relay_name = self
            .select_relay(request.relayset.as_deref())
            .ok_or_else(|| RuntimeError::RelayUnavailable {
                relayset: request.relayset.clone().unwrap_or_default(),
            })?;
        let relay =
            self.relays
                .get_mut(&relay_name)
                .ok_or_else(|| RuntimeError::RelayUnavailable {
                    relayset: relay_name.clone(),
                })?;
        let local = relay.subscribe(invocation, request)?;
        let handle = SubscriptionHandle {
            id: self.next_handle,
        };
        self.next_handle += 1;
        self.handles.insert(handle.id, (relay_name, local));
        Ok(handle)
    }

    fn unsubscribe(
        &mut self,
        invocation: InvocationId,
        handle: &SubscriptionHandle,
    ) -> Result<(), RuntimeError> {
        let Some((relay_name, local)) = self.handles.remove(&handle.id) else {
            return Err(RuntimeError::RelayUnavailable {
                relayset: handle.id.to_string(),
            });
        };
        self.relays
            .get_mut(&relay_name)
            .ok_or_else(|| RuntimeError::RelayUnavailable {
                relayset: relay_name.clone(),
            })?
            .unsubscribe(invocation, &local)
    }

    fn poll(
        &mut self,
        invocation: InvocationId,
        handle: &SubscriptionHandle,
    ) -> Result<SubscriptionBatch, RuntimeError> {
        let (relay_name, local) = self.handles.get(&handle.id).cloned().ok_or_else(|| {
            RuntimeError::RelayUnavailable {
                relayset: handle.id.to_string(),
            }
        })?;
        self.relays
            .get_mut(&relay_name)
            .ok_or_else(|| RuntimeError::RelayUnavailable {
                relayset: relay_name.clone(),
            })?
            .poll(invocation, &local)
    }
}

#[derive(Clone, Debug, Default)]
pub struct FakeRelayHost {
    pub relays: BTreeMap<String, bool>,
    pub published: Vec<SignedEvent>,
    pub subscriptions: Vec<SubscriptionRequest>,
    pub next_subscription: u64,
    pub closed_subscriptions: BTreeSet<u64>,
    pub queued_events: BTreeMap<u64, Vec<SignedEvent>>,
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

impl RelaySessionHost for FakeRelayHost {
    fn authenticate(
        &mut self,
        _invocation: InvocationId,
        relay: &str,
    ) -> Result<AuthenticatedRelay, RuntimeError> {
        if !relay.starts_with("wss://") || relay.len() <= 7 {
            return Err(RuntimeError::RelayUnavailable {
                relayset: relay.to_owned(),
            });
        }
        Ok(AuthenticatedRelay {
            relay: relay.to_owned(),
        })
    }
}

impl SubscriptionHost for FakeRelayHost {
    fn subscribe(
        &mut self,
        _invocation: InvocationId,
        request: &SubscriptionRequest,
    ) -> Result<SubscriptionHandle, RuntimeError> {
        if request.event_type.is_empty()
            || request.relayset.as_deref() == Some("")
            || request.cursor.as_deref() == Some("")
            || request.tag_equals.iter().any(|(name, value)| {
                name.is_empty()
                    || value.is_empty()
                    || !name.starts_with(|c: char| c.is_ascii_alphabetic())
            })
            || request.limit == Some(0)
        {
            return Err(RuntimeError::InvalidOperationArguments {
                operation: "subscribe".to_owned(),
            });
        }
        self.subscriptions.push(request.clone());
        self.next_subscription += 1;
        Ok(SubscriptionHandle {
            id: self.next_subscription,
        })
    }

    fn unsubscribe(
        &mut self,
        _invocation: InvocationId,
        handle: &SubscriptionHandle,
    ) -> Result<(), RuntimeError> {
        if handle.id == 0 || handle.id > self.next_subscription {
            return Err(RuntimeError::InvalidOperationArguments {
                operation: "unsubscribe".to_owned(),
            });
        }
        self.closed_subscriptions.insert(handle.id);
        Ok(())
    }

    fn poll(
        &mut self,
        _invocation: InvocationId,
        handle: &SubscriptionHandle,
    ) -> Result<SubscriptionBatch, RuntimeError> {
        if handle.id == 0 || handle.id > self.next_subscription {
            return Err(RuntimeError::InvalidOperationArguments {
                operation: "poll_subscription".to_owned(),
            });
        }
        if self.closed_subscriptions.contains(&handle.id) {
            return Err(RuntimeError::Cancelled);
        }
        Ok(SubscriptionBatch {
            events: self.queued_events.remove(&handle.id).unwrap_or_default(),
            complete: true,
            cursor: Some(format!("cursor-{}", handle.id)),
        })
    }
}

#[derive(Clone, Debug, Default)]
pub struct FakeHttpHost {
    pub allowlisted_hosts: BTreeSet<String>,
    pub requests: Vec<AuthenticatedRequest>,
    pub redirects: BTreeMap<String, String>,
}

impl HttpHost for FakeHttpHost {
    fn request(
        &mut self,
        _invocation: InvocationId,
        request: &AuthenticatedRequest,
    ) -> Result<HttpResponse, RuntimeError> {
        let Some(host) = request.url.split('/').nth(2) else {
            return Err(RuntimeError::OperationUnavailable {
                module: "http".to_owned(),
                operation: "request".to_owned(),
            });
        };
        if !self.allowlisted_hosts.is_empty() && !self.allowlisted_hosts.contains(host) {
            return Err(RuntimeError::CapabilityDenied {
                capability: format!("http:{host}"),
            });
        }
        if let Some(target) = self.redirects.get(&request.url) {
            let target_host = target.split('/').nth(2).unwrap_or_default();
            if !self.allowlisted_hosts.contains(target_host) {
                return Err(RuntimeError::CapabilityDenied {
                    capability: format!("http:{target_host}"),
                });
            }
        }
        self.requests.push(request.clone());
        Ok(HttpResponse {
            status: 200,
            body: "fake response".to_owned(),
        })
    }
}

#[derive(Clone, Debug, Default)]
pub struct FakeSignerHost {
    pub denied: BTreeSet<String>,
    pub signed: Vec<SignedEvent>,
}

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct FakeConcordKeyHost {
    pub denied: bool,
    pub derivations: usize,
}

impl ConcordKeyHost for FakeConcordKeyHost {
    fn derive_stream_key(
        &mut self,
        _invocation: InvocationId,
        secret: &SharedSecret,
    ) -> Result<DerivedKey, RuntimeError> {
        if self.denied {
            return Err(RuntimeError::CapabilityDenied {
                capability: "concord_key_derivation".to_owned(),
            });
        }
        let mut digest = Sha256::new();
        digest.update(b"nscript/concord01/test-derivation\0");
        digest.update(secret.as_bytes());
        self.derivations += 1;
        DerivedKey::new(digest.finalize().to_vec())
    }

    fn derive_group_key(
        &mut self,
        _invocation: InvocationId,
        label: stream::GroupKeyLabel,
        secret: &SharedSecret,
        id: &str,
        epoch: u64,
    ) -> Result<DerivedKey, RuntimeError> {
        if self.denied {
            return Err(RuntimeError::CapabilityDenied {
                capability: "concord_key_derivation".to_owned(),
            });
        }
        if !stream::is_hex32(id) {
            return Err(RuntimeError::InvalidOperationArguments {
                operation: "derive_group_key".to_owned(),
            });
        }
        let mut digest = Sha256::new();
        digest.update(b"nscript/concord01/test-group-key\0");
        digest.update(label.as_str().as_bytes());
        digest.update([0]);
        digest.update(secret.as_bytes());
        digest.update(id.as_bytes());
        digest.update(epoch.to_be_bytes());
        self.derivations += 1;
        DerivedKey::new(digest.finalize().to_vec())
    }
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

impl SignerProvisionHost for FakeSignerHost {
    fn provision(
        &mut self,
        _invocation: InvocationId,
        provider: &str,
    ) -> Result<SignerSession, RuntimeError> {
        if provider.is_empty() || self.denied.contains(provider) {
            return Err(RuntimeError::SignerDenied {
                signer: provider.to_owned(),
            });
        }
        Ok(SignerSession {
            provider: provider.to_owned(),
        })
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
pub struct FakeTimerHost {
    pub schedules: Vec<ScheduleRequest>,
    pub next_id: u64,
    pub reject: bool,
    pub active_names: BTreeSet<String>,
}

impl TimerHost for FakeTimerHost {
    fn schedule(
        &mut self,
        _invocation: InvocationId,
        request: &ScheduleRequest,
    ) -> Result<TimerHandle, RuntimeError> {
        if self.reject || request.name.is_empty() || request.next_at == 0 {
            return Err(RuntimeError::ResourceLimit {
                resource: "timer".to_owned(),
            });
        }
        if request.interval == Some(0) {
            return Err(RuntimeError::InvalidOperationArguments {
                operation: "schedule_timer".to_owned(),
            });
        }
        if !self.active_names.insert(request.name.clone()) {
            return Err(RuntimeError::ResourceLimit {
                resource: "timer_overlap".to_owned(),
            });
        }
        self.schedules.push(request.clone());
        self.next_id += 1;
        Ok(TimerHandle { id: self.next_id })
    }
}

#[derive(Clone, Debug, Default)]
pub struct FakeLogHost {
    pub records: Vec<LogRecord>,
    pub max_message_bytes: usize,
}

impl LogHost for FakeLogHost {
    fn log(&mut self, _invocation: InvocationId, record: &LogRecord) -> Result<(), RuntimeError> {
        if record.level.is_empty()
            || (self.max_message_bytes > 0 && record.message.len() > self.max_message_bytes)
        {
            return Err(RuntimeError::ResourceLimit {
                resource: "log_message".to_owned(),
            });
        }
        self.records.push(record.clone());
        Ok(())
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
            ("nip19", "npub_encode", [FunctionValue::PubKey(value)]) => {
                encode_npub(value).map(FunctionValue::Npub)
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

fn encode_npub(value: &str) -> Result<String, RuntimeError> {
    const CHARSET: &[u8] = b"qpzry9x8gf2tvdw0s3jn54khce6mua7l";
    if value.len() != 64 || !value.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return Err(RuntimeError::InvalidOperationArguments {
            operation: "nip19.npub_encode".to_owned(),
        });
    }
    let bytes = (0..32)
        .map(|index| u8::from_str_radix(&value[index * 2..index * 2 + 2], 16))
        .collect::<Result<Vec<_>, _>>()
        .map_err(|_| RuntimeError::InvalidOperationArguments {
            operation: "nip19.npub_encode".to_owned(),
        })?;
    let data = convert_bits(&bytes, 8, 5, true).ok_or_else(|| {
        RuntimeError::InvalidOperationArguments {
            operation: "nip19.npub_encode".to_owned(),
        }
    })?;
    let checksum = bech32_checksum("npub", &data);
    let mut output = String::from("npub1");
    for value in data.into_iter().chain(checksum) {
        output.push(CHARSET[usize::from(value)] as char);
    }
    Ok(output)
}

fn bech32_checksum(hrp: &str, data: &[u8]) -> Vec<u8> {
    let mut values = hrp.bytes().map(|byte| byte >> 5).collect::<Vec<_>>();
    values.push(0);
    values.extend(hrp.bytes().map(|byte| byte & 31));
    values.extend(data.iter().copied());
    values.extend([0; 6]);
    let polymod = bech32_checksum_polymod(&values) ^ 1;
    (0..6)
        .rev()
        .map(|index| ((polymod >> (index * 5)) & 31) as u8)
        .collect()
}

fn bech32_checksum_polymod(values: &[u8]) -> u64 {
    let generators: [u64; 5] = [
        0x3b6a_57b2,
        0x2650_8e6d,
        0x1ea1_19fa,
        0x3d42_33dd,
        0x2a14_62b3,
    ];
    let mut checksum = 1u64;
    for value in values {
        let top = checksum >> 25;
        checksum = ((checksum & 0x01ff_ffff) << 5) ^ u64::from(*value);
        for (index, generator) in generators.iter().enumerate() {
            if (top >> index) & 1 == 1 {
                checksum ^= *generator;
            }
        }
    }
    checksum
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
        if (u32::from(*value) >> from) != 0 {
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
    /// A deterministic stand-in: the same label always yields the same key, and
    /// it is not secret. For simulation and tests only.
    fn host_key(&mut self, label: &str) -> Result<DerivedKey, RuntimeError> {
        let mut digest = Sha256::new();
        digest.update(b"nscript/simulated-host-key/");
        digest.update(label.as_bytes());
        DerivedKey::new(digest.finalize().to_vec())
    }

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
            ("nip46", "nip46") => {
                if !arguments.is_empty() {
                    return Err(RuntimeError::InvalidOperationArguments {
                        operation: operation.to_owned(),
                    });
                }
                Ok(OperationValue::SignerSession(SignerSession {
                    provider: "nip46://remote-signer".to_owned(),
                }))
            }
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
            ("concord01", "derive_stream_key") => {
                let [OperationValue::SharedSecret(secret)] = arguments else {
                    return Err(RuntimeError::InvalidOperationArguments {
                        operation: operation.to_owned(),
                    });
                };
                let mut digest = Sha256::new();
                digest.update(b"nscript/concord01/test-derivation\0");
                digest.update(secret.as_bytes());
                DerivedKey::new(digest.finalize().to_vec()).map(OperationValue::DerivedKey)
            }
            ("concord01", "seal_message") => {
                let [
                    OperationValue::DerivedKey(stream),
                    OperationValue::SignedBytes(payload),
                ] = arguments
                else {
                    return Err(RuntimeError::InvalidOperationArguments {
                        operation: operation.to_owned(),
                    });
                };
                if stream.as_bytes().is_empty() || payload.as_bytes().is_empty() {
                    return Err(RuntimeError::InvalidOperationArguments {
                        operation: operation.to_owned(),
                    });
                }
                let mut sealed = CONCORD_TEST_SEAL_PREFIX.to_vec();
                sealed.extend_from_slice(payload.as_bytes());
                SealedEvent::new(sealed).map(OperationValue::SealedEvent)
            }
            ("concord01", "seal_control_message") => {
                let [
                    OperationValue::DerivedKey(stream),
                    OperationValue::SignedBytes(payload),
                ] = arguments
                else {
                    return Err(RuntimeError::InvalidOperationArguments {
                        operation: operation.to_owned(),
                    });
                };
                if stream.as_bytes().is_empty() {
                    return Err(RuntimeError::InvalidOperationArguments {
                        operation: operation.to_owned(),
                    });
                }
                // Plaintext seal: the rumor bytes ride verbatim, so a
                // compaction re-wrap keeps the author's signature valid.
                SealedEvent::plaintext(payload.as_bytes().to_vec()).map(OperationValue::SealedEvent)
            }
            ("concord01", "open_message") => {
                let [
                    OperationValue::DerivedKey(stream),
                    OperationValue::SealedEvent(payload),
                ] = arguments
                else {
                    return Err(RuntimeError::InvalidOperationArguments {
                        operation: operation.to_owned(),
                    });
                };
                if payload.kind() == stream::SealKind::Plaintext {
                    return SignedBytes::new(payload.as_bytes().to_vec())
                        .map(OperationValue::SignedBytes);
                }
                let prefix = CONCORD_TEST_SEAL_PREFIX;
                if stream.as_bytes().is_empty() || !payload.as_bytes().starts_with(prefix) {
                    return Err(RuntimeError::InvalidOperationArguments {
                        operation: operation.to_owned(),
                    });
                }
                SignedBytes::new(payload.as_bytes()[prefix.len()..].to_vec())
                    .map(OperationValue::SignedBytes)
            }
            ("concord01", "stream") => {
                let [OperationValue::DerivedKey(stream)] = arguments else {
                    return Err(RuntimeError::InvalidOperationArguments {
                        operation: operation.to_owned(),
                    });
                };
                Ok(OperationValue::StreamHandle(StreamHandle {
                    address: concord_test_stream_pubkey(stream),
                }))
            }
            ("concord01", "wrap_stream") => {
                let [
                    OperationValue::DerivedKey(stream),
                    OperationValue::SealedEvent(sealed),
                ] = arguments
                else {
                    return Err(RuntimeError::InvalidOperationArguments {
                        operation: operation.to_owned(),
                    });
                };
                self.next_value += 1;
                let mut digest = Sha256::new();
                digest.update(b"nscript/concord01/test-ephemeral\0");
                digest.update(self.next_value.to_be_bytes());
                digest.update(sealed.as_bytes());
                let ephemeral_p = digest
                    .finalize()
                    .iter()
                    .fold(String::new(), |mut out, byte| {
                        let _ = write!(out, "{byte:02x}");
                        out
                    });
                Ok(OperationValue::StreamWrap(StreamWrap {
                    kind: 1059,
                    stream_pubkey: concord_test_stream_pubkey(stream),
                    ephemeral_p,
                    sealed: Some(sealed.clone()),
                    wire: None,
                }))
            }
            ("concord01", "unwrap_stream") => {
                let [
                    OperationValue::DerivedKey(stream),
                    OperationValue::StreamWrap(wrap),
                ] = arguments
                else {
                    return Err(RuntimeError::InvalidOperationArguments {
                        operation: operation.to_owned(),
                    });
                };
                let Some(sealed) = &wrap.sealed else {
                    return Err(RuntimeError::InvalidOperationArguments {
                        operation: operation.to_owned(),
                    });
                };
                let plane = if sealed.kind() == stream::SealKind::Plaintext {
                    stream::Plane::Control
                } else {
                    stream::Plane::Chat
                };
                if wrap
                    .validate(&concord_test_stream_pubkey(stream), plane)
                    .is_err()
                {
                    return Err(RuntimeError::InvalidOperationArguments {
                        operation: operation.to_owned(),
                    });
                }
                Ok(OperationValue::SealedEvent(sealed.clone()))
            }
            ("concord01", "publish_message") => {
                let [
                    OperationValue::DerivedKey(stream),
                    OperationValue::StreamMessage(message),
                ] = arguments
                else {
                    return Err(RuntimeError::InvalidOperationArguments {
                        operation: operation.to_owned(),
                    });
                };
                if stream.as_bytes().is_empty()
                    || message.author.is_empty()
                    || message.content.is_empty()
                {
                    return Err(RuntimeError::InvalidOperationArguments {
                        operation: operation.to_owned(),
                    });
                }
                Ok(OperationValue::PublishReport(PublishReport {
                    outcomes: vec![RelayOutcome {
                        relay: "fake://concord01".to_owned(),
                        accepted: true,
                        detail: "stream message accepted by fake host".to_owned(),
                    }],
                }))
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
            ("nip37", "save_draft") => {
                let [OperationValue::Draft(draft)] = arguments else {
                    return Err(RuntimeError::InvalidOperationArguments {
                        operation: operation.to_owned(),
                    });
                };
                if draft.identifier.is_empty() || draft.content.is_empty() {
                    return Err(RuntimeError::InvalidOperationArguments {
                        operation: operation.to_owned(),
                    });
                }
                Ok(OperationValue::PublishReport(PublishReport {
                    outcomes: vec![RelayOutcome {
                        relay: "fake://drafts".to_owned(),
                        accepted: true,
                        detail: "draft stored and publication staged".to_owned(),
                    }],
                }))
            }
            ("nip38", "publish_status") => {
                let [OperationValue::UserStatus(status)] = arguments else {
                    return Err(RuntimeError::InvalidOperationArguments {
                        operation: operation.to_owned(),
                    });
                };
                if status.status.is_empty() || status.content.is_empty() {
                    return Err(RuntimeError::InvalidOperationArguments {
                        operation: operation.to_owned(),
                    });
                }
                Ok(OperationValue::PublishReport(PublishReport {
                    outcomes: vec![RelayOutcome {
                        relay: "fake://status".to_owned(),
                        accepted: true,
                        detail: "user status lowered".to_owned(),
                    }],
                }))
            }
            ("nip42", "authenticate") => {
                let [OperationValue::Text(relay)] = arguments else {
                    return Err(RuntimeError::InvalidOperationArguments {
                        operation: operation.to_owned(),
                    });
                };
                if !relay.starts_with("wss://") || relay.len() <= 7 {
                    return Err(RuntimeError::InvalidOperationArguments {
                        operation: operation.to_owned(),
                    });
                }
                Ok(OperationValue::AuthenticatedRelay(AuthenticatedRelay {
                    relay: relay.clone(),
                }))
            }
            ("nip45", "count_events") => {
                let [OperationValue::Text(filter)] = arguments else {
                    return Err(RuntimeError::InvalidOperationArguments {
                        operation: operation.to_owned(),
                    });
                };
                if filter.trim().is_empty() {
                    return Err(RuntimeError::InvalidOperationArguments {
                        operation: operation.to_owned(),
                    });
                }
                Ok(OperationValue::Integer(0))
            }
            ("nip50", "search_events") => {
                let [OperationValue::SearchRequest(request)] = arguments else {
                    return Err(RuntimeError::InvalidOperationArguments {
                        operation: operation.to_owned(),
                    });
                };
                if request.query.trim().is_empty() {
                    return Err(RuntimeError::InvalidOperationArguments {
                        operation: operation.to_owned(),
                    });
                }
                Ok(OperationValue::SearchResults(SearchResults {
                    query: request.query.clone(),
                    count: 0,
                }))
            }
            ("nip53", "publish_live_event") => {
                let [OperationValue::LiveEvent(event)] = arguments else {
                    return Err(RuntimeError::InvalidOperationArguments {
                        operation: operation.to_owned(),
                    });
                };
                if event.identifier.is_empty() || event.title.is_empty() || event.summary.is_empty()
                {
                    return Err(RuntimeError::InvalidOperationArguments {
                        operation: operation.to_owned(),
                    });
                }
                Ok(OperationValue::PublishReport(PublishReport {
                    outcomes: vec![RelayOutcome {
                        relay: "fake://live-events".to_owned(),
                        accepted: true,
                        detail: "live event lowered".to_owned(),
                    }],
                }))
            }
            ("nip56", "publish_report") => {
                let [OperationValue::Report(report)] = arguments else {
                    return Err(RuntimeError::InvalidOperationArguments {
                        operation: operation.to_owned(),
                    });
                };
                if report.target.is_empty()
                    || report.category.is_empty()
                    || report.content.is_empty()
                {
                    return Err(RuntimeError::InvalidOperationArguments {
                        operation: operation.to_owned(),
                    });
                }
                Ok(OperationValue::PublishReport(PublishReport {
                    outcomes: vec![RelayOutcome {
                        relay: "fake://reports".to_owned(),
                        accepted: true,
                        detail: "moderation report lowered".to_owned(),
                    }],
                }))
            }
            ("nip58", "publish_badge") => {
                let [OperationValue::Badge(badge)] = arguments else {
                    return Err(RuntimeError::InvalidOperationArguments {
                        operation: operation.to_owned(),
                    });
                };
                if badge.identifier.is_empty()
                    || badge.name.is_empty()
                    || badge.description.is_empty()
                {
                    return Err(RuntimeError::InvalidOperationArguments {
                        operation: operation.to_owned(),
                    });
                }
                Ok(OperationValue::PublishReport(PublishReport {
                    outcomes: vec![RelayOutcome {
                        relay: "fake://badges".to_owned(),
                        accepted: true,
                        detail: "badge definition lowered".to_owned(),
                    }],
                }))
            }
            ("nip68", "publish_image") => {
                let [OperationValue::ImageEvent(event)] = arguments else {
                    return Err(RuntimeError::InvalidOperationArguments {
                        operation: operation.to_owned(),
                    });
                };
                if event.url.is_empty() || event.caption.is_empty() {
                    return Err(RuntimeError::InvalidOperationArguments {
                        operation: operation.to_owned(),
                    });
                }
                Ok(OperationValue::PublishReport(PublishReport {
                    outcomes: vec![RelayOutcome {
                        relay: "fake://images".to_owned(),
                        accepted: true,
                        detail: "image event lowered".to_owned(),
                    }],
                }))
            }
            ("nip71", "publish_video") => {
                let [OperationValue::VideoEvent(event)] = arguments else {
                    return Err(RuntimeError::InvalidOperationArguments {
                        operation: operation.to_owned(),
                    });
                };
                if event.url.is_empty() || event.caption.is_empty() {
                    return Err(RuntimeError::InvalidOperationArguments {
                        operation: operation.to_owned(),
                    });
                }
                Ok(OperationValue::PublishReport(PublishReport {
                    outcomes: vec![RelayOutcome {
                        relay: "fake://videos".to_owned(),
                        accepted: true,
                        detail: "video event lowered".to_owned(),
                    }],
                }))
            }
            ("nip77", "synchronize") => {
                let [OperationValue::SyncRequest(request)] = arguments else {
                    return Err(RuntimeError::InvalidOperationArguments {
                        operation: operation.to_owned(),
                    });
                };
                if !request.relay.starts_with("wss://") || request.cursor.is_empty() {
                    return Err(RuntimeError::InvalidOperationArguments {
                        operation: operation.to_owned(),
                    });
                }
                Ok(OperationValue::SyncResult(SyncResult {
                    relay: request.relay.clone(),
                    added: 0,
                    removed: 0,
                }))
            }
            ("nip84", "publish_highlight") => {
                let [OperationValue::Highlight(highlight)] = arguments else {
                    return Err(RuntimeError::InvalidOperationArguments {
                        operation: operation.to_owned(),
                    });
                };
                if highlight.source.is_empty() || highlight.content.is_empty() {
                    return Err(RuntimeError::InvalidOperationArguments {
                        operation: operation.to_owned(),
                    });
                }
                Ok(OperationValue::PublishReport(PublishReport {
                    outcomes: vec![RelayOutcome {
                        relay: "fake://highlights".to_owned(),
                        accepted: true,
                        detail: "highlight source/content lowered".to_owned(),
                    }],
                }))
            }
            ("nip85", "publish_assertion") => {
                let [OperationValue::Assertion(assertion)] = arguments else {
                    return Err(RuntimeError::InvalidOperationArguments {
                        operation: operation.to_owned(),
                    });
                };
                if assertion.subject.is_empty()
                    || assertion.kind.is_empty()
                    || assertion.value.is_empty()
                {
                    return Err(RuntimeError::InvalidOperationArguments {
                        operation: operation.to_owned(),
                    });
                }
                Ok(OperationValue::PublishReport(PublishReport {
                    outcomes: vec![RelayOutcome {
                        relay: "fake://assertions".to_owned(),
                        accepted: true,
                        detail: "trusted assertion lowered".to_owned(),
                    }],
                }))
            }
            ("nip86", "manage_relay") => {
                let [OperationValue::RelayAdminRequest(request)] = arguments else {
                    return Err(RuntimeError::InvalidOperationArguments {
                        operation: operation.to_owned(),
                    });
                };
                if !request.relay.starts_with("wss://")
                    || request.action.is_empty()
                    || request.subject.is_empty()
                {
                    return Err(RuntimeError::InvalidOperationArguments {
                        operation: operation.to_owned(),
                    });
                }
                Ok(OperationValue::PublishReport(PublishReport {
                    outcomes: vec![RelayOutcome {
                        relay: request.relay.clone(),
                        accepted: true,
                        detail: format!("relay admin action: {}", request.action),
                    }],
                }))
            }
            ("nip89", "publish_handler") => {
                let [OperationValue::AppHandler(handler)] = arguments else {
                    return Err(RuntimeError::InvalidOperationArguments {
                        operation: operation.to_owned(),
                    });
                };
                if handler.kind.is_empty() || handler.app.is_empty() || handler.endpoint.is_empty()
                {
                    return Err(RuntimeError::InvalidOperationArguments {
                        operation: operation.to_owned(),
                    });
                }
                Ok(OperationValue::PublishReport(PublishReport {
                    outcomes: vec![RelayOutcome {
                        relay: "fake://app-handlers".to_owned(),
                        accepted: true,
                        detail: "application handler lowered".to_owned(),
                    }],
                }))
            }
            ("nip94", "publish_file_metadata") => {
                let [OperationValue::FileMetadata(file)] = arguments else {
                    return Err(RuntimeError::InvalidOperationArguments {
                        operation: operation.to_owned(),
                    });
                };
                if file.url.is_empty() || file.mime.is_empty() || file.hash.is_empty() {
                    return Err(RuntimeError::InvalidOperationArguments {
                        operation: operation.to_owned(),
                    });
                }
                Ok(OperationValue::PublishReport(PublishReport {
                    outcomes: vec![RelayOutcome {
                        relay: "fake://file-metadata".to_owned(),
                        accepted: true,
                        detail: "file metadata lowered".to_owned(),
                    }],
                }))
            }
            ("nipb7", "upload_blob") => {
                let [OperationValue::BlobUpload(upload)] = arguments else {
                    return Err(RuntimeError::InvalidOperationArguments {
                        operation: operation.to_owned(),
                    });
                };
                if upload.url.is_empty() || upload.hash.is_empty() || upload.size < 0 {
                    return Err(RuntimeError::InvalidOperationArguments {
                        operation: operation.to_owned(),
                    });
                }
                Ok(OperationValue::BlobStored(BlobStored {
                    url: upload.url.clone(),
                    hash: upload.hash.clone(),
                }))
            }
            ("nip98", "authenticate_http") => {
                let [OperationValue::HttpAuthRequest(request)] = arguments else {
                    return Err(RuntimeError::InvalidOperationArguments {
                        operation: operation.to_owned(),
                    });
                };
                if !request.url.starts_with("https://") || request.method.is_empty() {
                    return Err(RuntimeError::InvalidOperationArguments {
                        operation: operation.to_owned(),
                    });
                }
                Ok(OperationValue::AuthenticatedRequest(AuthenticatedRequest {
                    url: request.url.clone(),
                    method: request.method.clone(),
                }))
            }
            ("nip47", "pay_invoice") => {
                let [OperationValue::WalletPayment(payment)] = arguments else {
                    return Err(RuntimeError::InvalidOperationArguments {
                        operation: operation.to_owned(),
                    });
                };
                if payment.invoice.is_empty() || payment.amount <= 0 {
                    return Err(RuntimeError::InvalidOperationArguments {
                        operation: operation.to_owned(),
                    });
                }
                Ok(OperationValue::PaymentResult(PaymentResult {
                    invoice: payment.invoice.clone(),
                    amount: payment.amount,
                    settled: true,
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
            ("nip88", "publish_poll") => {
                let [OperationValue::Poll(poll)] = arguments else {
                    return Err(RuntimeError::InvalidOperationArguments {
                        operation: operation.to_owned(),
                    });
                };
                if poll.question.is_empty()
                    || poll.options.len() < 2
                    || poll
                        .options
                        .iter()
                        .any(|option| option.id.is_empty() || option.label.is_empty())
                {
                    return Err(RuntimeError::InvalidOperationArguments {
                        operation: operation.to_owned(),
                    });
                }
                Ok(OperationValue::PublishReport(PublishReport {
                    outcomes: vec![RelayOutcome {
                        relay: "fake://poll".to_owned(),
                        accepted: true,
                        detail: "poll lowered".to_owned(),
                    }],
                }))
            }
            ("nip88", "respond_to_poll") => {
                let [OperationValue::PollResponse(response)] = arguments else {
                    return Err(RuntimeError::InvalidOperationArguments {
                        operation: operation.to_owned(),
                    });
                };
                if response.poll.is_empty() || response.option.is_empty() {
                    return Err(RuntimeError::InvalidOperationArguments {
                        operation: operation.to_owned(),
                    });
                }
                Ok(OperationValue::PublishReport(PublishReport {
                    outcomes: vec![RelayOutcome {
                        relay: "fake://poll-response".to_owned(),
                        accepted: true,
                        detail: "poll response lowered".to_owned(),
                    }],
                }))
            }
            ("nip92", "publish_note_with_media") => {
                let [OperationValue::NoteWithMedia(note)] = arguments else {
                    return Err(RuntimeError::InvalidOperationArguments {
                        operation: operation.to_owned(),
                    });
                };
                if note.content.is_empty()
                    || note.media.is_empty()
                    || note
                        .media
                        .iter()
                        .any(|item| item.url.is_empty() || item.mime.is_empty())
                {
                    return Err(RuntimeError::InvalidOperationArguments {
                        operation: operation.to_owned(),
                    });
                }
                Ok(OperationValue::PublishReport(PublishReport {
                    outcomes: vec![RelayOutcome {
                        relay: "fake://note-with-media".to_owned(),
                        accepted: true,
                        detail: "imeta note lowered".to_owned(),
                    }],
                }))
            }
            ("nip36", "publish_note_with_warning") => {
                let [OperationValue::NoteWithWarning(note)] = arguments else {
                    return Err(RuntimeError::InvalidOperationArguments {
                        operation: operation.to_owned(),
                    });
                };
                if note.content.is_empty() || note.reason.is_empty() {
                    return Err(RuntimeError::InvalidOperationArguments {
                        operation: operation.to_owned(),
                    });
                }
                Ok(OperationValue::PublishReport(PublishReport {
                    outcomes: vec![RelayOutcome {
                        relay: "fake://content-warning".to_owned(),
                        accepted: true,
                        detail: "sensitive-content note lowered".to_owned(),
                    }],
                }))
            }
            ("nip40", "publish_expiring_note") => {
                let [OperationValue::ExpiringNote(note)] = arguments else {
                    return Err(RuntimeError::InvalidOperationArguments {
                        operation: operation.to_owned(),
                    });
                };
                if note.content.is_empty() || note.expires_at <= 0 {
                    return Err(RuntimeError::InvalidOperationArguments {
                        operation: operation.to_owned(),
                    });
                }
                Ok(OperationValue::PublishReport(PublishReport {
                    outcomes: vec![RelayOutcome {
                        relay: "fake://expiring-note".to_owned(),
                        accepted: true,
                        detail: "expiring note lowered".to_owned(),
                    }],
                }))
            }
            ("nip27", "publish_note_with_mentions") => {
                let [OperationValue::NoteWithMentions(note)] = arguments else {
                    return Err(RuntimeError::InvalidOperationArguments {
                        operation: operation.to_owned(),
                    });
                };
                if note.content.is_empty() || note.mentions.is_empty() {
                    return Err(RuntimeError::InvalidOperationArguments {
                        operation: operation.to_owned(),
                    });
                }
                Ok(OperationValue::PublishReport(PublishReport {
                    outcomes: vec![RelayOutcome {
                        relay: "fake://note-with-mentions".to_owned(),
                        accepted: true,
                        detail: "mention note lowered".to_owned(),
                    }],
                }))
            }
            ("nip30", "publish_note_with_emoji") => {
                let [OperationValue::NoteWithEmoji(note)] = arguments else {
                    return Err(RuntimeError::InvalidOperationArguments {
                        operation: operation.to_owned(),
                    });
                };
                if note.content.is_empty()
                    || note.emoji.is_empty()
                    || note
                        .emoji
                        .iter()
                        .any(|item| item.shortcode.is_empty() || item.url.is_empty())
                {
                    return Err(RuntimeError::InvalidOperationArguments {
                        operation: operation.to_owned(),
                    });
                }
                Ok(OperationValue::PublishReport(PublishReport {
                    outcomes: vec![RelayOutcome {
                        relay: "fake://note-with-emoji".to_owned(),
                        accepted: true,
                        detail: "emoji note lowered".to_owned(),
                    }],
                }))
            }
            ("nip39", "publish_identity_claims") => {
                let [OperationValue::IdentityClaims(claims)] = arguments else {
                    return Err(RuntimeError::InvalidOperationArguments {
                        operation: operation.to_owned(),
                    });
                };
                if claims.claims.is_empty()
                    || claims
                        .claims
                        .iter()
                        .any(|claim| claim.platform.is_empty() || claim.proof.is_empty())
                {
                    return Err(RuntimeError::InvalidOperationArguments {
                        operation: operation.to_owned(),
                    });
                }
                Ok(OperationValue::PublishReport(PublishReport {
                    outcomes: vec![RelayOutcome {
                        relay: "fake://identity-claims".to_owned(),
                        accepted: true,
                        detail: "identity claims lowered".to_owned(),
                    }],
                }))
            }
            ("nip73", "publish_external_comment") => {
                let [OperationValue::ExternalComment(comment)] = arguments else {
                    return Err(RuntimeError::InvalidOperationArguments {
                        operation: operation.to_owned(),
                    });
                };
                if comment.content.is_empty()
                    || comment.target_id.is_empty()
                    || comment.target_kind.is_empty()
                {
                    return Err(RuntimeError::InvalidOperationArguments {
                        operation: operation.to_owned(),
                    });
                }
                Ok(OperationValue::PublishReport(PublishReport {
                    outcomes: vec![RelayOutcome {
                        relay: "fake://external-comment".to_owned(),
                        accepted: true,
                        detail: "external comment lowered".to_owned(),
                    }],
                }))
            }
            ("nip35", "publish_torrent") => {
                let [OperationValue::Torrent(torrent)] = arguments else {
                    return Err(RuntimeError::InvalidOperationArguments {
                        operation: operation.to_owned(),
                    });
                };
                if torrent.title.is_empty()
                    || torrent.info_hash.is_empty()
                    || torrent.files.is_empty()
                    || torrent
                        .files
                        .iter()
                        .any(|file| file.path.is_empty() || file.bytes <= 0)
                {
                    return Err(RuntimeError::InvalidOperationArguments {
                        operation: operation.to_owned(),
                    });
                }
                Ok(OperationValue::PublishReport(PublishReport {
                    outcomes: vec![RelayOutcome {
                        relay: "fake://torrent".to_owned(),
                        accepted: true,
                        detail: "torrent lowered".to_owned(),
                    }],
                }))
            }
            ("nip99", "publish_listing") => {
                let [OperationValue::Listing(listing)] = arguments else {
                    return Err(RuntimeError::InvalidOperationArguments {
                        operation: operation.to_owned(),
                    });
                };
                if listing.title.is_empty()
                    || listing.price_amount.is_empty()
                    || listing.price_currency.is_empty()
                {
                    return Err(RuntimeError::InvalidOperationArguments {
                        operation: operation.to_owned(),
                    });
                }
                Ok(OperationValue::PublishReport(PublishReport {
                    outcomes: vec![RelayOutcome {
                        relay: "fake://listing".to_owned(),
                        accepted: true,
                        detail: "listing lowered".to_owned(),
                    }],
                }))
            }
            ("nipb0", "publish_bookmark") => {
                let [OperationValue::Bookmark(bookmark)] = arguments else {
                    return Err(RuntimeError::InvalidOperationArguments {
                        operation: operation.to_owned(),
                    });
                };
                if bookmark.uri.is_empty() {
                    return Err(RuntimeError::InvalidOperationArguments {
                        operation: operation.to_owned(),
                    });
                }
                Ok(OperationValue::PublishReport(PublishReport {
                    outcomes: vec![RelayOutcome {
                        relay: "fake://bookmark".to_owned(),
                        accepted: true,
                        detail: "bookmark lowered".to_owned(),
                    }],
                }))
            }
            ("nipc0", "publish_snippet") => {
                let [OperationValue::CodeSnippet(snippet)] = arguments else {
                    return Err(RuntimeError::InvalidOperationArguments {
                        operation: operation.to_owned(),
                    });
                };
                if snippet.code.is_empty() {
                    return Err(RuntimeError::InvalidOperationArguments {
                        operation: operation.to_owned(),
                    });
                }
                Ok(OperationValue::PublishReport(PublishReport {
                    outcomes: vec![RelayOutcome {
                        relay: "fake://snippet".to_owned(),
                        accepted: true,
                        detail: "snippet lowered".to_owned(),
                    }],
                }))
            }
            ("nip34", "publish_repository") => {
                let [OperationValue::Repository(repository)] = arguments else {
                    return Err(RuntimeError::InvalidOperationArguments {
                        operation: operation.to_owned(),
                    });
                };
                if repository.identifier.is_empty() {
                    return Err(RuntimeError::InvalidOperationArguments {
                        operation: operation.to_owned(),
                    });
                }
                Ok(OperationValue::PublishReport(PublishReport {
                    outcomes: vec![RelayOutcome {
                        relay: "fake://repository".to_owned(),
                        accepted: true,
                        detail: "repository announcement lowered".to_owned(),
                    }],
                }))
            }
            ("nip54", "publish_wiki_article") => {
                let [OperationValue::WikiArticle(article)] = arguments else {
                    return Err(RuntimeError::InvalidOperationArguments {
                        operation: operation.to_owned(),
                    });
                };
                if article.identifier.is_empty() || article.content.is_empty() {
                    return Err(RuntimeError::InvalidOperationArguments {
                        operation: operation.to_owned(),
                    });
                }
                Ok(OperationValue::PublishReport(PublishReport {
                    outcomes: vec![RelayOutcome {
                        relay: "fake://wiki".to_owned(),
                        accepted: true,
                        detail: "wiki article lowered".to_owned(),
                    }],
                }))
            }
            ("nip72", "publish_community") => {
                let [OperationValue::Community(community)] = arguments else {
                    return Err(RuntimeError::InvalidOperationArguments {
                        operation: operation.to_owned(),
                    });
                };
                if community.identifier.is_empty() || community.moderators.is_empty() {
                    return Err(RuntimeError::InvalidOperationArguments {
                        operation: operation.to_owned(),
                    });
                }
                Ok(OperationValue::PublishReport(PublishReport {
                    outcomes: vec![RelayOutcome {
                        relay: "fake://community".to_owned(),
                        accepted: true,
                        detail: "community definition lowered".to_owned(),
                    }],
                }))
            }
            ("nip72", "approve_post") => {
                let [OperationValue::PostApproval(approval)] = arguments else {
                    return Err(RuntimeError::InvalidOperationArguments {
                        operation: operation.to_owned(),
                    });
                };
                if approval.community.is_empty()
                    || approval.post.is_empty()
                    || approval.post_json.is_empty()
                    || approval.kind < 0
                {
                    return Err(RuntimeError::InvalidOperationArguments {
                        operation: operation.to_owned(),
                    });
                }
                Ok(OperationValue::PublishReport(PublishReport {
                    outcomes: vec![RelayOutcome {
                        relay: "fake://community-approval".to_owned(),
                        accepted: true,
                        detail: "post approval lowered".to_owned(),
                    }],
                }))
            }
            ("nipc7", "send_chat_message") => {
                let [OperationValue::ChatMessage(message)] = arguments else {
                    return Err(RuntimeError::InvalidOperationArguments {
                        operation: operation.to_owned(),
                    });
                };
                if message.content.is_empty() {
                    return Err(RuntimeError::InvalidOperationArguments {
                        operation: operation.to_owned(),
                    });
                }
                Ok(OperationValue::PublishReport(PublishReport {
                    outcomes: vec![RelayOutcome {
                        relay: "fake://chat".to_owned(),
                        accepted: true,
                        detail: "chat message lowered".to_owned(),
                    }],
                }))
            }
            ("nipc7", "reply_to_chat_message") => {
                let [OperationValue::ChatReply(reply)] = arguments else {
                    return Err(RuntimeError::InvalidOperationArguments {
                        operation: operation.to_owned(),
                    });
                };
                if reply.content.is_empty() || reply.target.is_empty() {
                    return Err(RuntimeError::InvalidOperationArguments {
                        operation: operation.to_owned(),
                    });
                }
                Ok(OperationValue::PublishReport(PublishReport {
                    outcomes: vec![RelayOutcome {
                        relay: "fake://chat-reply".to_owned(),
                        accepted: true,
                        detail: "chat reply lowered".to_owned(),
                    }],
                }))
            }
            ("nip64", "publish_chess_game") => {
                let [OperationValue::ChessGame(game)] = arguments else {
                    return Err(RuntimeError::InvalidOperationArguments {
                        operation: operation.to_owned(),
                    });
                };
                if game.pgn.is_empty() {
                    return Err(RuntimeError::InvalidOperationArguments {
                        operation: operation.to_owned(),
                    });
                }
                Ok(OperationValue::PublishReport(PublishReport {
                    outcomes: vec![RelayOutcome {
                        relay: "fake://chess".to_owned(),
                        accepted: true,
                        detail: "chess game lowered".to_owned(),
                    }],
                }))
            }
            ("nip7d", "publish_thread") => {
                let [OperationValue::ForumThread(thread)] = arguments else {
                    return Err(RuntimeError::InvalidOperationArguments {
                        operation: operation.to_owned(),
                    });
                };
                if thread.title.is_empty() || thread.content.is_empty() {
                    return Err(RuntimeError::InvalidOperationArguments {
                        operation: operation.to_owned(),
                    });
                }
                Ok(OperationValue::PublishReport(PublishReport {
                    outcomes: vec![RelayOutcome {
                        relay: "fake://forum".to_owned(),
                        accepted: true,
                        detail: "forum thread lowered".to_owned(),
                    }],
                }))
            }
            ("nipf4", "publish_podcast_show") => {
                let [OperationValue::PodcastShow(show)] = arguments else {
                    return Err(RuntimeError::InvalidOperationArguments {
                        operation: operation.to_owned(),
                    });
                };
                if show.title.is_empty() {
                    return Err(RuntimeError::InvalidOperationArguments {
                        operation: operation.to_owned(),
                    });
                }
                Ok(OperationValue::PublishReport(PublishReport {
                    outcomes: vec![RelayOutcome {
                        relay: "fake://podcast".to_owned(),
                        accepted: true,
                        detail: "podcast show lowered".to_owned(),
                    }],
                }))
            }
            ("nipf4", "publish_podcast_episode") => {
                let [OperationValue::PodcastEpisode(episode)] = arguments else {
                    return Err(RuntimeError::InvalidOperationArguments {
                        operation: operation.to_owned(),
                    });
                };
                if episode.title.is_empty() || episode.audio_url.is_empty() {
                    return Err(RuntimeError::InvalidOperationArguments {
                        operation: operation.to_owned(),
                    });
                }
                Ok(OperationValue::PublishReport(PublishReport {
                    outcomes: vec![RelayOutcome {
                        relay: "fake://podcast-episode".to_owned(),
                        accepted: true,
                        detail: "podcast episode lowered".to_owned(),
                    }],
                }))
            }
            ("nipcc", "publish_geocache") => {
                let [OperationValue::GeocacheListing(listing)] = arguments else {
                    return Err(RuntimeError::InvalidOperationArguments {
                        operation: operation.to_owned(),
                    });
                };
                if listing.identifier.is_empty()
                    || listing.geohash.is_empty()
                    || !(1..=5).contains(&listing.difficulty)
                    || !(1..=5).contains(&listing.terrain)
                {
                    return Err(RuntimeError::InvalidOperationArguments {
                        operation: operation.to_owned(),
                    });
                }
                Ok(OperationValue::PublishReport(PublishReport {
                    outcomes: vec![RelayOutcome {
                        relay: "fake://geocache".to_owned(),
                        accepted: true,
                        detail: "geocache listing lowered".to_owned(),
                    }],
                }))
            }
            ("nipcc", "publish_found_log") => {
                let [OperationValue::FoundLog(log)] = arguments else {
                    return Err(RuntimeError::InvalidOperationArguments {
                        operation: operation.to_owned(),
                    });
                };
                if log.cache.is_empty() || log.message.is_empty() {
                    return Err(RuntimeError::InvalidOperationArguments {
                        operation: operation.to_owned(),
                    });
                }
                Ok(OperationValue::PublishReport(PublishReport {
                    outcomes: vec![RelayOutcome {
                        relay: "fake://geocache-log".to_owned(),
                        accepted: true,
                        detail: "found log lowered".to_owned(),
                    }],
                }))
            }
            ("nip28", "create_channel") => {
                let [OperationValue::Channel(channel)] = arguments else {
                    return Err(RuntimeError::InvalidOperationArguments {
                        operation: operation.to_owned(),
                    });
                };
                if channel.name.is_empty() {
                    return Err(RuntimeError::InvalidOperationArguments {
                        operation: operation.to_owned(),
                    });
                }
                Ok(OperationValue::PublishReport(PublishReport {
                    outcomes: vec![RelayOutcome {
                        relay: "fake://channel".to_owned(),
                        accepted: true,
                        detail: "channel created".to_owned(),
                    }],
                }))
            }
            ("nip28", "send_channel_message") => {
                let [OperationValue::ChannelMessage(message)] = arguments else {
                    return Err(RuntimeError::InvalidOperationArguments {
                        operation: operation.to_owned(),
                    });
                };
                if message.channel.is_empty() || message.content.is_empty() {
                    return Err(RuntimeError::InvalidOperationArguments {
                        operation: operation.to_owned(),
                    });
                }
                Ok(OperationValue::PublishReport(PublishReport {
                    outcomes: vec![RelayOutcome {
                        relay: "fake://channel-message".to_owned(),
                        accepted: true,
                        detail: "channel message lowered".to_owned(),
                    }],
                }))
            }
            ("nip28", "hide_message") => {
                let [OperationValue::HideMessage(hide)] = arguments else {
                    return Err(RuntimeError::InvalidOperationArguments {
                        operation: operation.to_owned(),
                    });
                };
                if hide.message.is_empty() {
                    return Err(RuntimeError::InvalidOperationArguments {
                        operation: operation.to_owned(),
                    });
                }
                Ok(OperationValue::PublishReport(PublishReport {
                    outcomes: vec![RelayOutcome {
                        relay: "fake://hide-message".to_owned(),
                        accepted: true,
                        detail: "hide request lowered".to_owned(),
                    }],
                }))
            }
            ("nip28", "mute_user") => {
                let [OperationValue::MuteUser(mute)] = arguments else {
                    return Err(RuntimeError::InvalidOperationArguments {
                        operation: operation.to_owned(),
                    });
                };
                if mute.target.is_empty() {
                    return Err(RuntimeError::InvalidOperationArguments {
                        operation: operation.to_owned(),
                    });
                }
                Ok(OperationValue::PublishReport(PublishReport {
                    outcomes: vec![RelayOutcome {
                        relay: "fake://mute-user".to_owned(),
                        accepted: true,
                        detail: "mute request lowered".to_owned(),
                    }],
                }))
            }
            ("nip62", "request_to_vanish") => {
                let [OperationValue::VanishRequest(request)] = arguments else {
                    return Err(RuntimeError::InvalidOperationArguments {
                        operation: operation.to_owned(),
                    });
                };
                if request.relays.is_empty() || request.relays.iter().any(String::is_empty) {
                    return Err(RuntimeError::InvalidOperationArguments {
                        operation: operation.to_owned(),
                    });
                }
                Ok(OperationValue::PublishReport(PublishReport {
                    outcomes: vec![RelayOutcome {
                        relay: "fake://vanish".to_owned(),
                        accepted: true,
                        detail: "vanish request lowered".to_owned(),
                    }],
                }))
            }
            ("nip75", "publish_zap_goal") => {
                let [OperationValue::ZapGoal(goal)] = arguments else {
                    return Err(RuntimeError::InvalidOperationArguments {
                        operation: operation.to_owned(),
                    });
                };
                if goal.description.is_empty()
                    || goal.amount_msats <= 0
                    || goal.relays.is_empty()
                {
                    return Err(RuntimeError::InvalidOperationArguments {
                        operation: operation.to_owned(),
                    });
                }
                Ok(OperationValue::PublishReport(PublishReport {
                    outcomes: vec![RelayOutcome {
                        relay: "fake://zap-goal".to_owned(),
                        accepted: true,
                        detail: "zap goal lowered".to_owned(),
                    }],
                }))
            }
            ("nipa4", "publish_public_message") => {
                let [OperationValue::PublicMessage(message)] = arguments else {
                    return Err(RuntimeError::InvalidOperationArguments {
                        operation: operation.to_owned(),
                    });
                };
                if message.content.is_empty() || message.recipients.is_empty() {
                    return Err(RuntimeError::InvalidOperationArguments {
                        operation: operation.to_owned(),
                    });
                }
                Ok(OperationValue::PublishReport(PublishReport {
                    outcomes: vec![RelayOutcome {
                        relay: "fake://public-message".to_owned(),
                        accepted: true,
                        detail: "public message lowered".to_owned(),
                    }],
                }))
            }
            ("nip03", "publish_timestamp") => {
                let [OperationValue::TimestampAttestation(attestation)] = arguments else {
                    return Err(RuntimeError::InvalidOperationArguments {
                        operation: operation.to_owned(),
                    });
                };
                if attestation.target.is_empty() || attestation.ots_proof.is_empty() {
                    return Err(RuntimeError::InvalidOperationArguments {
                        operation: operation.to_owned(),
                    });
                }
                Ok(OperationValue::PublishReport(PublishReport {
                    outcomes: vec![RelayOutcome {
                        relay: "fake://timestamp".to_owned(),
                        accepted: true,
                        detail: "timestamp attestation lowered".to_owned(),
                    }],
                }))
            }
            ("nip70", "publish_protected_note") => {
                let [OperationValue::ProtectedNote(note)] = arguments else {
                    return Err(RuntimeError::InvalidOperationArguments {
                        operation: operation.to_owned(),
                    });
                };
                if note.content.is_empty() {
                    return Err(RuntimeError::InvalidOperationArguments {
                        operation: operation.to_owned(),
                    });
                }
                Ok(OperationValue::PublishReport(PublishReport {
                    outcomes: vec![RelayOutcome {
                        relay: "fake://protected-note".to_owned(),
                        accepted: true,
                        detail: "protected note lowered".to_owned(),
                    }],
                }))
            }
            ("nip90", "publish_job_request") => {
                let [OperationValue::JobRequest(request)] = arguments else {
                    return Err(RuntimeError::InvalidOperationArguments {
                        operation: operation.to_owned(),
                    });
                };
                if !(5000..6000).contains(&request.job_kind)
                    || request.input.is_empty()
                    || request.bid_msats < 0
                {
                    return Err(RuntimeError::InvalidOperationArguments {
                        operation: operation.to_owned(),
                    });
                }
                Ok(OperationValue::PublishReport(PublishReport {
                    outcomes: vec![RelayOutcome {
                        relay: "fake://job-request".to_owned(),
                        accepted: true,
                        detail: "job request lowered".to_owned(),
                    }],
                }))
            }
            ("nip90", "publish_job_result") => {
                let [OperationValue::JobResult(result)] = arguments else {
                    return Err(RuntimeError::InvalidOperationArguments {
                        operation: operation.to_owned(),
                    });
                };
                if !(6000..7000).contains(&result.job_kind)
                    || result.request.is_empty()
                    || result.amount_msats < 0
                {
                    return Err(RuntimeError::InvalidOperationArguments {
                        operation: operation.to_owned(),
                    });
                }
                Ok(OperationValue::PublishReport(PublishReport {
                    outcomes: vec![RelayOutcome {
                        relay: "fake://job-result".to_owned(),
                        accepted: true,
                        detail: "job result lowered".to_owned(),
                    }],
                }))
            }
            ("nipa0", "publish_voice_message") => {
                let [OperationValue::VoiceMessage(message)] = arguments else {
                    return Err(RuntimeError::InvalidOperationArguments {
                        operation: operation.to_owned(),
                    });
                };
                if message.audio_url.is_empty()
                    || message.duration <= 0
                    || message.duration > 60
                {
                    return Err(RuntimeError::InvalidOperationArguments {
                        operation: operation.to_owned(),
                    });
                }
                Ok(OperationValue::PublishReport(PublishReport {
                    outcomes: vec![RelayOutcome {
                        relay: "fake://voice-message".to_owned(),
                        accepted: true,
                        detail: "voice message lowered".to_owned(),
                    }],
                }))
            }
            ("nipa0", "reply_with_voice_message") => {
                let [OperationValue::VoiceReply(reply)] = arguments else {
                    return Err(RuntimeError::InvalidOperationArguments {
                        operation: operation.to_owned(),
                    });
                };
                if reply.audio_url.is_empty()
                    || reply.duration <= 0
                    || reply.duration > 60
                    || reply.target.is_empty()
                {
                    return Err(RuntimeError::InvalidOperationArguments {
                        operation: operation.to_owned(),
                    });
                }
                Ok(OperationValue::PublishReport(PublishReport {
                    outcomes: vec![RelayOutcome {
                        relay: "fake://voice-reply".to_owned(),
                        accepted: true,
                        detail: "voice reply lowered".to_owned(),
                    }],
                }))
            }
            ("nip14", "publish_note_with_subject") => {
                let [OperationValue::NoteWithSubject(note)] = arguments else {
                    return Err(RuntimeError::InvalidOperationArguments {
                        operation: operation.to_owned(),
                    });
                };
                if note.content.is_empty() || note.subject.is_empty() {
                    return Err(RuntimeError::InvalidOperationArguments {
                        operation: operation.to_owned(),
                    });
                }
                Ok(OperationValue::PublishReport(PublishReport {
                    outcomes: vec![RelayOutcome {
                        relay: "fake://note-with-subject".to_owned(),
                        accepted: true,
                        detail: "subject note lowered".to_owned(),
                    }],
                }))
            }
            ("nip26", "publish_delegated_note") => {
                let [OperationValue::DelegatedNote(note)] = arguments else {
                    return Err(RuntimeError::InvalidOperationArguments {
                        operation: operation.to_owned(),
                    });
                };
                if note.content.is_empty()
                    || note.delegator.is_empty()
                    || note.conditions.is_empty()
                    || note.token.is_empty()
                {
                    return Err(RuntimeError::InvalidOperationArguments {
                        operation: operation.to_owned(),
                    });
                }
                Ok(OperationValue::PublishReport(PublishReport {
                    outcomes: vec![RelayOutcome {
                        relay: "fake://delegated-note".to_owned(),
                        accepted: true,
                        detail: "delegated note lowered".to_owned(),
                    }],
                }))
            }
            ("nip48", "publish_bridged_note") => {
                let [OperationValue::BridgedNote(note)] = arguments else {
                    return Err(RuntimeError::InvalidOperationArguments {
                        operation: operation.to_owned(),
                    });
                };
                if note.source_id.is_empty() || note.protocol.is_empty() {
                    return Err(RuntimeError::InvalidOperationArguments {
                        operation: operation.to_owned(),
                    });
                }
                Ok(OperationValue::PublishReport(PublishReport {
                    outcomes: vec![RelayOutcome {
                        relay: "fake://bridged-note".to_owned(),
                        accepted: true,
                        detail: "bridged note lowered".to_owned(),
                    }],
                }))
            }
            ("nip69", "publish_order") => {
                let [OperationValue::P2POrder(order)] = arguments else {
                    return Err(RuntimeError::InvalidOperationArguments {
                        operation: operation.to_owned(),
                    });
                };
                if order.identifier.is_empty()
                    || !matches!(order.order_type.as_str(), "sell" | "buy")
                    || order.currency.is_empty()
                    || order.amount_sats < 0
                {
                    return Err(RuntimeError::InvalidOperationArguments {
                        operation: operation.to_owned(),
                    });
                }
                Ok(OperationValue::PublishReport(PublishReport {
                    outcomes: vec![RelayOutcome {
                        relay: "fake://p2p-order".to_owned(),
                        accepted: true,
                        detail: "p2p order lowered".to_owned(),
                    }],
                }))
            }
            ("nip96", "publish_file_server_preferences") => {
                let [OperationValue::FileServerPreferences(preferences)] = arguments else {
                    return Err(RuntimeError::InvalidOperationArguments {
                        operation: operation.to_owned(),
                    });
                };
                if preferences.servers.is_empty()
                    || preferences.servers.iter().any(String::is_empty)
                {
                    return Err(RuntimeError::InvalidOperationArguments {
                        operation: operation.to_owned(),
                    });
                }
                Ok(OperationValue::PublishReport(PublishReport {
                    outcomes: vec![RelayOutcome {
                        relay: "fake://file-server-preferences".to_owned(),
                        accepted: true,
                        detail: "file server preferences lowered".to_owned(),
                    }],
                }))
            }
            ("nip87", "publish_mint_announcement") => {
                let [OperationValue::MintAnnouncement(announcement)] = arguments else {
                    return Err(RuntimeError::InvalidOperationArguments {
                        operation: operation.to_owned(),
                    });
                };
                if announcement.mint_pubkey.is_empty() || announcement.url.is_empty() {
                    return Err(RuntimeError::InvalidOperationArguments {
                        operation: operation.to_owned(),
                    });
                }
                Ok(OperationValue::PublishReport(PublishReport {
                    outcomes: vec![RelayOutcome {
                        relay: "fake://mint-announcement".to_owned(),
                        accepted: true,
                        detail: "mint announcement lowered".to_owned(),
                    }],
                }))
            }
            ("nip87", "publish_mint_recommendation") => {
                let [OperationValue::MintRecommendation(recommendation)] = arguments else {
                    return Err(RuntimeError::InvalidOperationArguments {
                        operation: operation.to_owned(),
                    });
                };
                if recommendation.mint.is_empty() {
                    return Err(RuntimeError::InvalidOperationArguments {
                        operation: operation.to_owned(),
                    });
                }
                Ok(OperationValue::PublishReport(PublishReport {
                    outcomes: vec![RelayOutcome {
                        relay: "fake://mint-recommendation".to_owned(),
                        accepted: true,
                        detail: "mint recommendation lowered".to_owned(),
                    }],
                }))
            }
            ("nipa3", "publish_payment_targets") => {
                let [OperationValue::PaymentTargets(targets)] = arguments else {
                    return Err(RuntimeError::InvalidOperationArguments {
                        operation: operation.to_owned(),
                    });
                };
                if targets.targets.is_empty()
                    || targets
                        .targets
                        .iter()
                        .any(|target| target.payment_type.is_empty() || target.address.is_empty())
                {
                    return Err(RuntimeError::InvalidOperationArguments {
                        operation: operation.to_owned(),
                    });
                }
                Ok(OperationValue::PublishReport(PublishReport {
                    outcomes: vec![RelayOutcome {
                        relay: "fake://payment-targets".to_owned(),
                        accepted: true,
                        detail: "payment targets lowered".to_owned(),
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
        "Draft" => match (text("identifier"), text("content")) {
            (Some(identifier), Some(content)) => OperationValue::Draft(Draft {
                identifier,
                content,
            }),
            _ => value.clone(),
        },
        "UserStatus" => match (text("status"), text("content")) {
            (Some(status), Some(content)) => {
                OperationValue::UserStatus(UserStatus { status, content })
            }
            _ => value.clone(),
        },
        "StreamMessage" => match (pubkey("author"), text("content")) {
            (Some(author), Some(content)) => {
                OperationValue::StreamMessage(StreamMessage { author, content })
            }
            _ => value.clone(),
        },
        "SearchRequest" => match text("query") {
            Some(query) => OperationValue::SearchRequest(SearchRequest { query }),
            _ => value.clone(),
        },
        "LiveEvent" => match (text("identifier"), text("title"), text("summary")) {
            (Some(identifier), Some(title), Some(summary)) => {
                OperationValue::LiveEvent(LiveEvent {
                    identifier,
                    title,
                    summary,
                })
            }
            _ => value.clone(),
        },
        "Report" => match (text("target"), text("category"), text("content")) {
            (Some(target), Some(category), Some(content)) => OperationValue::Report(Report {
                target,
                category,
                content,
            }),
            _ => value.clone(),
        },
        "Badge" => match (text("identifier"), text("name"), text("description")) {
            (Some(identifier), Some(name), Some(description)) => OperationValue::Badge(Badge {
                identifier,
                name,
                description,
            }),
            _ => value.clone(),
        },
        "ImageEvent" => match (text("url"), text("caption")) {
            (Some(url), Some(caption)) => OperationValue::ImageEvent(ImageEvent { url, caption }),
            _ => value.clone(),
        },
        "VideoEvent" => match (text("url"), text("caption")) {
            (Some(url), Some(caption)) => OperationValue::VideoEvent(VideoEvent { url, caption }),
            _ => value.clone(),
        },
        "SyncRequest" => match (text("relay"), text("cursor")) {
            (Some(relay), Some(cursor)) => {
                OperationValue::SyncRequest(SyncRequest { relay, cursor })
            }
            _ => value.clone(),
        },
        "Highlight" => match (text("source"), text("content")) {
            (Some(source), Some(content)) => {
                OperationValue::Highlight(Highlight { source, content })
            }
            _ => value.clone(),
        },
        "Assertion" => match (text("subject"), text("kind"), text("value")) {
            (Some(subject), Some(kind), Some(value)) => OperationValue::Assertion(Assertion {
                subject,
                kind,
                value,
            }),
            _ => value.clone(),
        },
        "RelayAdminRequest" => match (text("relay"), text("action"), text("subject")) {
            (Some(relay), Some(action), Some(subject)) => {
                OperationValue::RelayAdminRequest(RelayAdminRequest {
                    relay,
                    action,
                    subject,
                })
            }
            _ => value.clone(),
        },
        "AppHandler" => match (text("kind"), text("app"), text("endpoint")) {
            (Some(kind), Some(app), Some(endpoint)) => OperationValue::AppHandler(AppHandler {
                kind,
                app,
                endpoint,
            }),
            _ => value.clone(),
        },
        "FileMetadata" => match (text("url"), text("mime"), text("hash")) {
            (Some(url), Some(mime), Some(hash)) => {
                OperationValue::FileMetadata(FileMetadata { url, mime, hash })
            }
            _ => value.clone(),
        },
        "BlobUpload" => match (text("url"), text("hash"), integer("size")) {
            (Some(url), Some(hash), Some(size)) => {
                OperationValue::BlobUpload(BlobUpload { url, hash, size })
            }
            _ => value.clone(),
        },
        "HttpAuthRequest" => match (text("url"), text("method")) {
            (Some(url), Some(method)) => {
                OperationValue::HttpAuthRequest(HttpAuthRequest { url, method })
            }
            _ => value.clone(),
        },
        "WalletPayment" => match (text("invoice"), integer("amount")) {
            (Some(invoice), Some(amount)) => {
                OperationValue::WalletPayment(WalletPayment { invoice, amount })
            }
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
        "FollowList" => match record_strings(fields, "people") {
            Some(people) => OperationValue::FollowList(FollowList { people }),
            None => value.clone(),
        },
        "RelayList" => match (record_strings(fields, "read"), record_strings(fields, "write")) {
            (Some(read), Some(write)) => OperationValue::RelayList(RelayList { read, write }),
            _ => value.clone(),
        },
        "Poll" => match (
            text("question"),
            record_poll_options(fields, "options"),
            record_bool(fields, "multiple_choice"),
            integer("ends_at"),
        ) {
            (Some(question), Some(options), Some(multiple_choice), Some(ends_at)) => {
                OperationValue::Poll(Poll {
                    question,
                    options,
                    multiple_choice,
                    ends_at,
                })
            }
            _ => value.clone(),
        },
        "PollResponse" => match (text("poll"), text("option")) {
            (Some(poll), Some(option)) => {
                OperationValue::PollResponse(PollResponse { poll, option })
            }
            _ => value.clone(),
        },
        "NoteWithMedia" => match (text("content"), record_media(fields, "media")) {
            (Some(content), Some(media)) => {
                OperationValue::NoteWithMedia(NoteWithMedia { content, media })
            }
            _ => value.clone(),
        },
        "NoteWithWarning" => match (text("content"), text("reason")) {
            (Some(content), Some(reason)) => {
                OperationValue::NoteWithWarning(NoteWithWarning { content, reason })
            }
            _ => value.clone(),
        },
        "ExpiringNote" => match (text("content"), integer("expires_at")) {
            (Some(content), Some(expires_at)) => {
                OperationValue::ExpiringNote(ExpiringNote {
                    content,
                    expires_at,
                })
            }
            _ => value.clone(),
        },
        "NoteWithMentions" => match (text("content"), record_strings(fields, "mentions")) {
            (Some(content), Some(mentions)) => {
                OperationValue::NoteWithMentions(NoteWithMentions { content, mentions })
            }
            _ => value.clone(),
        },
        "NoteWithEmoji" => match (text("content"), record_emoji(fields, "emoji")) {
            (Some(content), Some(emoji)) => {
                OperationValue::NoteWithEmoji(NoteWithEmoji { content, emoji })
            }
            _ => value.clone(),
        },
        "IdentityClaims" => match record_identities(fields, "claims") {
            Some(claims) => OperationValue::IdentityClaims(IdentityClaims { claims }),
            None => value.clone(),
        },
        "ExternalComment" => match (text("content"), text("target_id"), text("target_kind")) {
            (Some(content), Some(target_id), Some(target_kind)) => {
                OperationValue::ExternalComment(ExternalComment {
                    content,
                    target_id,
                    target_kind,
                })
            }
            _ => value.clone(),
        },
        "Torrent" => match (
            text("title"),
            text("description"),
            text("info_hash"),
            record_torrent_files(fields, "files"),
            record_strings(fields, "trackers"),
        ) {
            (Some(title), Some(description), Some(info_hash), Some(files), Some(trackers)) => {
                OperationValue::Torrent(Torrent {
                    title,
                    description,
                    info_hash,
                    files,
                    trackers,
                })
            }
            _ => value.clone(),
        },
        "Listing" => match (
            text("title"),
            text("summary"),
            text("content"),
            text("location"),
            text("price_amount"),
            text("price_currency"),
        ) {
            (
                Some(title),
                Some(summary),
                Some(content),
                Some(location),
                Some(price_amount),
                Some(price_currency),
            ) => OperationValue::Listing(Box::new(Listing {
                title,
                summary,
                content,
                location,
                price_amount,
                price_currency,
            })),
            _ => value.clone(),
        },
        "Bookmark" => match (text("uri"), text("title"), text("description")) {
            (Some(uri), Some(title), Some(description)) => {
                OperationValue::Bookmark(Bookmark {
                    uri,
                    title,
                    description,
                })
            }
            _ => value.clone(),
        },
        "CodeSnippet" => match (
            text("code"),
            text("language"),
            text("name"),
            text("description"),
        ) {
            (Some(code), Some(language), Some(name), Some(description)) => {
                OperationValue::CodeSnippet(CodeSnippet {
                    code,
                    language,
                    name,
                    description,
                })
            }
            _ => value.clone(),
        },
        "Repository" => match (
            text("identifier"),
            text("name"),
            text("description"),
            text("clone_url"),
            text("web_url"),
        ) {
            (Some(identifier), Some(name), Some(description), Some(clone_url), Some(web_url)) => {
                OperationValue::Repository(Box::new(Repository {
                    identifier,
                    name,
                    description,
                    clone_url,
                    web_url,
                }))
            }
            _ => value.clone(),
        },
        "WikiArticle" => match (
            text("identifier"),
            text("title"),
            text("summary"),
            text("content"),
        ) {
            (Some(identifier), Some(title), Some(summary), Some(content)) => {
                OperationValue::WikiArticle(WikiArticle {
                    identifier,
                    title,
                    summary,
                    content,
                })
            }
            _ => value.clone(),
        },
        "Community" => match (
            text("identifier"),
            text("name"),
            text("description"),
            record_strings(fields, "moderators"),
        ) {
            (Some(identifier), Some(name), Some(description), Some(moderators)) => {
                OperationValue::Community(Community {
                    identifier,
                    name,
                    description,
                    moderators,
                })
            }
            _ => value.clone(),
        },
        "PostApproval" => match (
            text("community"),
            text("post"),
            pubkey("author"),
            integer("kind"),
            text("post_json"),
        ) {
            (Some(community), Some(post), Some(author), Some(kind), Some(post_json)) => {
                OperationValue::PostApproval(PostApproval {
                    community,
                    post,
                    author,
                    kind,
                    post_json,
                })
            }
            _ => value.clone(),
        },
        "ChatMessage" => match text("content") {
            Some(content) => OperationValue::ChatMessage(ChatMessage { content }),
            None => value.clone(),
        },
        "ChatReply" => match (text("content"), text("target")) {
            (Some(content), Some(target)) => {
                OperationValue::ChatReply(ChatReply { content, target })
            }
            _ => value.clone(),
        },
        "ChessGame" => match text("pgn") {
            Some(pgn) => OperationValue::ChessGame(ChessGame { pgn }),
            None => value.clone(),
        },
        "ForumThread" => match (text("title"), text("content")) {
            (Some(title), Some(content)) => {
                OperationValue::ForumThread(ForumThread { title, content })
            }
            _ => value.clone(),
        },
        "PodcastShow" => match (
            text("title"),
            text("description"),
            text("image"),
            text("website"),
        ) {
            (Some(title), Some(description), Some(image), Some(website)) => {
                OperationValue::PodcastShow(PodcastShow {
                    title,
                    description,
                    image,
                    website,
                })
            }
            _ => value.clone(),
        },
        "PodcastEpisode" => match (
            text("title"),
            text("description"),
            text("content"),
            text("audio_url"),
        ) {
            (Some(title), Some(description), Some(content), Some(audio_url)) => {
                OperationValue::PodcastEpisode(PodcastEpisode {
                    title,
                    description,
                    content,
                    audio_url,
                })
            }
            _ => value.clone(),
        },
        "GeocacheListing" => match (
            text("identifier"),
            text("name"),
            text("geohash"),
            integer("difficulty"),
            integer("terrain"),
            text("size"),
            text("description"),
        ) {
            (
                Some(identifier),
                Some(name),
                Some(geohash),
                Some(difficulty),
                Some(terrain),
                Some(size),
                Some(description),
            ) => OperationValue::GeocacheListing(Box::new(GeocacheListing {
                identifier,
                name,
                geohash,
                difficulty,
                terrain,
                size,
                description,
            })),
            _ => value.clone(),
        },
        "FoundLog" => match (text("cache"), text("message")) {
            (Some(cache), Some(message)) => OperationValue::FoundLog(FoundLog { cache, message }),
            _ => value.clone(),
        },
        "Channel" => match (text("name"), text("about"), text("picture")) {
            (Some(name), Some(about), Some(picture)) => OperationValue::Channel(Channel {
                name,
                about,
                picture,
            }),
            _ => value.clone(),
        },
        "ChannelMessage" => match (text("channel"), text("content")) {
            (Some(channel), Some(content)) => {
                OperationValue::ChannelMessage(ChannelMessage { channel, content })
            }
            _ => value.clone(),
        },
        "HideMessage" => match (text("message"), text("reason")) {
            (Some(message), Some(reason)) => {
                OperationValue::HideMessage(HideMessage { message, reason })
            }
            _ => value.clone(),
        },
        "MuteUser" => match (pubkey("target"), text("reason")) {
            (Some(target), Some(reason)) => OperationValue::MuteUser(MuteUser { target, reason }),
            _ => value.clone(),
        },
        "VanishRequest" => match (record_strings(fields, "relays"), text("reason")) {
            (Some(relays), Some(reason)) => {
                OperationValue::VanishRequest(VanishRequest { relays, reason })
            }
            _ => value.clone(),
        },
        "ZapGoal" => match (
            text("description"),
            integer("amount_msats"),
            record_strings(fields, "relays"),
            integer("closed_at"),
        ) {
            (Some(description), Some(amount_msats), Some(relays), Some(closed_at)) => {
                OperationValue::ZapGoal(ZapGoal {
                    description,
                    amount_msats,
                    relays,
                    closed_at,
                })
            }
            _ => value.clone(),
        },
        "PublicMessage" => match (text("content"), record_strings(fields, "recipients")) {
            (Some(content), Some(recipients)) => {
                OperationValue::PublicMessage(PublicMessage { content, recipients })
            }
            _ => value.clone(),
        },
        "TimestampAttestation" => match (
            text("target"),
            integer("target_kind"),
            text("ots_proof"),
        ) {
            (Some(target), Some(target_kind), Some(ots_proof)) => {
                OperationValue::TimestampAttestation(TimestampAttestation {
                    target,
                    target_kind,
                    ots_proof,
                })
            }
            _ => value.clone(),
        },
        "ProtectedNote" => match text("content") {
            Some(content) => OperationValue::ProtectedNote(ProtectedNote { content }),
            None => value.clone(),
        },
        "JobRequest" => match (
            integer("job_kind"),
            text("input"),
            text("input_type"),
            text("output"),
            integer("bid_msats"),
        ) {
            (Some(job_kind), Some(input), Some(input_type), Some(output), Some(bid_msats)) => {
                OperationValue::JobRequest(JobRequest {
                    job_kind,
                    input,
                    input_type,
                    output,
                    bid_msats,
                })
            }
            _ => value.clone(),
        },
        "JobResult" => match (
            integer("job_kind"),
            text("request"),
            text("payload"),
            integer("amount_msats"),
        ) {
            (Some(job_kind), Some(request), Some(payload), Some(amount_msats)) => {
                OperationValue::JobResult(JobResult {
                    job_kind,
                    request,
                    payload,
                    amount_msats,
                })
            }
            _ => value.clone(),
        },
        "VoiceMessage" => match (text("audio_url"), integer("duration")) {
            (Some(audio_url), Some(duration)) => {
                OperationValue::VoiceMessage(VoiceMessage {
                    audio_url,
                    duration,
                })
            }
            _ => value.clone(),
        },
        "VoiceReply" => match (text("audio_url"), integer("duration"), text("target")) {
            (Some(audio_url), Some(duration), Some(target)) => {
                OperationValue::VoiceReply(VoiceReply {
                    audio_url,
                    duration,
                    target,
                })
            }
            _ => value.clone(),
        },
        "NoteWithSubject" => match (text("content"), text("subject")) {
            (Some(content), Some(subject)) => {
                OperationValue::NoteWithSubject(NoteWithSubject { content, subject })
            }
            _ => value.clone(),
        },
        "DelegatedNote" => match (
            text("content"),
            pubkey("delegator"),
            text("conditions"),
            text("token"),
        ) {
            (Some(content), Some(delegator), Some(conditions), Some(token)) => {
                OperationValue::DelegatedNote(DelegatedNote {
                    content,
                    delegator,
                    conditions,
                    token,
                })
            }
            _ => value.clone(),
        },
        "BridgedNote" => match (text("content"), text("source_id"), text("protocol")) {
            (Some(content), Some(source_id), Some(protocol)) => {
                OperationValue::BridgedNote(BridgedNote {
                    content,
                    source_id,
                    protocol,
                })
            }
            _ => value.clone(),
        },
        "P2POrder" => match (
            text("identifier"),
            text("order_type"),
            text("currency"),
            text("status"),
            integer("amount_sats"),
            text("fiat_amount"),
            text("payment_method"),
            integer("premium"),
        ) {
            (
                Some(identifier),
                Some(order_type),
                Some(currency),
                Some(status),
                Some(amount_sats),
                Some(fiat_amount),
                Some(payment_method),
                Some(premium),
            ) => OperationValue::P2POrder(Box::new(P2POrder {
                identifier,
                order_type,
                currency,
                status,
                amount_sats,
                fiat_amount,
                payment_method,
                premium,
            })),
            _ => value.clone(),
        },
        "FileServerPreferences" => match record_strings(fields, "servers") {
            Some(servers) => {
                OperationValue::FileServerPreferences(FileServerPreferences { servers })
            }
            None => value.clone(),
        },
        "MintAnnouncement" => match (
            text("mint_pubkey"),
            text("url"),
            text("nuts"),
            text("network"),
        ) {
            (Some(mint_pubkey), Some(url), Some(nuts), Some(network)) => {
                OperationValue::MintAnnouncement(MintAnnouncement {
                    mint_pubkey,
                    url,
                    nuts,
                    network,
                })
            }
            _ => value.clone(),
        },
        "MintRecommendation" => match (text("mint"), text("review")) {
            (Some(mint), Some(review)) => {
                OperationValue::MintRecommendation(MintRecommendation { mint, review })
            }
            _ => value.clone(),
        },
        "PaymentTargets" => match record_payment_targets(fields, "targets") {
            Some(targets) => OperationValue::PaymentTargets(PaymentTargets { targets }),
            None => value.clone(),
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

fn record_bool(fields: &[(String, OperationValue)], key: &str) -> Option<bool> {
    fields.iter().find_map(|(field, value)| {
        (field == key).then_some(match value {
            OperationValue::Bool(value) => Some(*value),
            _ => None,
        })?
    })
}

/// A `List<PollOption>` field: each element is still a generic, un-normalized
/// `OperationValue::Record` (only the top-level argument passes through
/// `normalize_record`), so this reads its `id`/`label` fields directly.
fn record_poll_options(
    fields: &[(String, OperationValue)],
    key: &str,
) -> Option<Vec<PollOption>> {
    fields.iter().find_map(|(field, value)| {
        (field == key).then_some(match value {
            OperationValue::List(items) => items
                .iter()
                .map(|item| match item {
                    OperationValue::Record { name, fields } if name == "PollOption" => {
                        match (record_text(fields, "id"), record_text(fields, "label")) {
                            (Some(id), Some(label)) => Some(PollOption { id, label }),
                            _ => None,
                        }
                    }
                    _ => None,
                })
                .collect(),
            _ => None,
        })?
    })
}

/// A `List<MediaAttachment>` field; see [`record_poll_options`] for why each
/// element is read directly rather than through `normalize_record`.
fn record_media(
    fields: &[(String, OperationValue)],
    key: &str,
) -> Option<Vec<MediaAttachment>> {
    fields.iter().find_map(|(field, value)| {
        (field == key).then_some(match value {
            OperationValue::List(items) => items
                .iter()
                .map(|item| match item {
                    OperationValue::Record { name, fields } if name == "MediaAttachment" => {
                        match (
                            record_text(fields, "url"),
                            record_text(fields, "mime"),
                            record_text(fields, "hash"),
                        ) {
                            (Some(url), Some(mime), Some(hash)) => {
                                Some(MediaAttachment { url, mime, hash })
                            }
                            _ => None,
                        }
                    }
                    _ => None,
                })
                .collect(),
            _ => None,
        })?
    })
}

/// A `List<CustomEmoji>` field; see [`record_poll_options`] for why each
/// element is read directly rather than through `normalize_record`.
fn record_emoji(fields: &[(String, OperationValue)], key: &str) -> Option<Vec<CustomEmoji>> {
    fields.iter().find_map(|(field, value)| {
        (field == key).then_some(match value {
            OperationValue::List(items) => items
                .iter()
                .map(|item| match item {
                    OperationValue::Record { name, fields } if name == "CustomEmoji" => {
                        match (record_text(fields, "shortcode"), record_text(fields, "url")) {
                            (Some(shortcode), Some(url)) => {
                                Some(CustomEmoji { shortcode, url })
                            }
                            _ => None,
                        }
                    }
                    _ => None,
                })
                .collect(),
            _ => None,
        })?
    })
}

/// A `List<TorrentFile>` field; see [`record_poll_options`] for why each
/// element is read directly rather than through `normalize_record`.
fn record_torrent_files(
    fields: &[(String, OperationValue)],
    key: &str,
) -> Option<Vec<TorrentFile>> {
    fields.iter().find_map(|(field, value)| {
        (field == key).then_some(match value {
            OperationValue::List(items) => items
                .iter()
                .map(|item| match item {
                    OperationValue::Record { name, fields } if name == "TorrentFile" => {
                        match (record_text(fields, "path"), record_integer(fields, "bytes")) {
                            (Some(path), Some(bytes)) => Some(TorrentFile { path, bytes }),
                            _ => None,
                        }
                    }
                    _ => None,
                })
                .collect(),
            _ => None,
        })?
    })
}

/// A `List<ExternalIdentity>` field; see [`record_poll_options`] for why each
/// element is read directly rather than through `normalize_record`.
fn record_identities(
    fields: &[(String, OperationValue)],
    key: &str,
) -> Option<Vec<ExternalIdentity>> {
    fields.iter().find_map(|(field, value)| {
        (field == key).then_some(match value {
            OperationValue::List(items) => items
                .iter()
                .map(|item| match item {
                    OperationValue::Record { name, fields } if name == "ExternalIdentity" => {
                        match (record_text(fields, "platform"), record_text(fields, "proof")) {
                            (Some(platform), Some(proof)) => {
                                Some(ExternalIdentity { platform, proof })
                            }
                            _ => None,
                        }
                    }
                    _ => None,
                })
                .collect(),
            _ => None,
        })?
    })
}

/// A `List<PaymentTarget>` field; see [`record_poll_options`] for why each
/// element is read directly rather than through `normalize_record`.
fn record_payment_targets(
    fields: &[(String, OperationValue)],
    key: &str,
) -> Option<Vec<PaymentTarget>> {
    fields.iter().find_map(|(field, value)| {
        (field == key).then_some(match value {
            OperationValue::List(items) => items
                .iter()
                .map(|item| match item {
                    OperationValue::Record { name, fields } if name == "PaymentTarget" => {
                        match (
                            record_text(fields, "payment_type"),
                            record_text(fields, "address"),
                        ) {
                            (Some(payment_type), Some(address)) => {
                                Some(PaymentTarget { payment_type, address })
                            }
                            _ => None,
                        }
                    }
                    _ => None,
                })
                .collect(),
            _ => None,
        })?
    })
}

/// A `List<PubKey>` or `List<Text>` field: either scalar unwraps the same way,
/// since a follow list or a relay list is just strings by the time it is
/// here.
fn record_strings(fields: &[(String, OperationValue)], key: &str) -> Option<Vec<String>> {
    fields.iter().find_map(|(field, value)| {
        (field == key).then_some(match value {
            OperationValue::List(items) => items
                .iter()
                .map(|item| match item {
                    OperationValue::Text(text) | OperationValue::PubKey(text) => {
                        Some(text.clone())
                    }
                    _ => None,
                })
                .collect(),
            _ => None,
        })?
    })
}

impl AuditHost for RecordingAudit {
    fn record(&mut self, entry: AuditEntry) {
        self.entries.push(entry);
    }
}

/// The result of running one handler cycle against a synthetic event.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SimulationReport {
    /// How many handlers dispatched the event (after type/kind/author matching).
    pub dispatched: usize,
    /// The lowered subscription event types, in handler order.
    pub subscriptions: Vec<String>,
    /// Structured log records produced by executing handler bodies.
    pub logs: Vec<LogRecord>,
    /// The module operations the handlers called during this event. Those no
    /// host implements are answered from their declared return type and marked
    /// simulated.
    pub operations: Vec<eval::SimulatedCall>,
    /// Handlers that ran and failed. A failed body is rolled back and reported
    /// here, and does not stop the other handlers.
    pub failures: Vec<eval::HandlerFailure>,
}

impl Runtime<FakeRelayHost, FakeSignerHost, FakeClock, RecordingAudit> {
    /// Runs one handler cycle with a synthetic signed event queued on every
    /// lowered subscription, returning the deterministic preview a Studio
    /// "Test Event" uses. No relay, signer, or other external host is
    /// contacted; handler bodies run against the same transactional,
    /// idempotency, and logging fakes the conformance suite uses.
    ///
    /// # Errors
    ///
    /// Returns the first subscription, polling, idempotency, storage, logging,
    /// or handler-body failure.
    #[allow(clippy::too_many_arguments)]
    pub fn simulate_event(
        program: &nscript_syntax::Program,
        checked: &CheckedProgram,
        relay: &mut FakeRelayHost,
        storage: &mut InMemoryStorage,
        log: &mut FakeLogHost,
        operations: &mut eval::SimulatedOperations,
        principal: Option<&str>,
        event: &SignedEvent,
    ) -> Result<SimulationReport, RuntimeError> {
        let mut runtime = Self::new(
            FakeRelayHost::default(),
            FakeSignerHost::default(),
            FakeClock { now: 1_700_000_000 },
            RecordingAudit::default(),
        );
        let subscriptions = Self::handler_subscriptions(checked, Some("public"));
        for handle in 1..=subscriptions.len() {
            relay
                .queued_events
                .insert(handle as u64, vec![event.clone()]);
        }
        let mut claims = InMemoryStorage::default();
        let calls_before = operations.calls.len();
        let cycle = runtime.run_evaluated_cycle(
            program,
            checked,
            Some("public"),
            relay,
            &mut claims,
            storage,
            log,
            operations,
            principal,
            eval::EvalLimits::default(),
        )?;
        Ok(SimulationReport {
            dispatched: cycle.dispatched,
            subscriptions: subscriptions
                .into_iter()
                .map(|request| request.event_type)
                .collect(),
            logs: log.records.clone(),
            operations: operations.calls[calls_before..].to_vec(),
            failures: cycle.failures,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_list_valued_field_normalizes_a_follow_or_relay_list() {
        let follow = OperationValue::Record {
            name: "FollowList".to_owned(),
            fields: vec![(
                "people".to_owned(),
                OperationValue::List(vec![
                    OperationValue::PubKey("alice".to_owned()),
                    OperationValue::PubKey("bob".to_owned()),
                ]),
            )],
        };
        assert_eq!(
            normalize_record(&follow),
            OperationValue::FollowList(FollowList {
                people: vec!["alice".to_owned(), "bob".to_owned()]
            })
        );

        let relays = OperationValue::Record {
            name: "RelayList".to_owned(),
            fields: vec![
                (
                    "read".to_owned(),
                    OperationValue::List(vec![OperationValue::Text("wss://a".to_owned())]),
                ),
                (
                    "write".to_owned(),
                    OperationValue::List(vec![OperationValue::Text("wss://b".to_owned())]),
                ),
            ],
        };
        assert_eq!(
            normalize_record(&relays),
            OperationValue::RelayList(RelayList {
                read: vec!["wss://a".to_owned()],
                write: vec!["wss://b".to_owned()],
            })
        );

        // A field that isn't a list at all falls through unnormalized rather
        // than panicking.
        let malformed = OperationValue::Record {
            name: "FollowList".to_owned(),
            fields: vec![("people".to_owned(), OperationValue::Text("x".to_owned()))],
        };
        assert_eq!(normalize_record(&malformed), malformed);
    }

    #[test]
    fn a_list_of_records_normalizes_a_poll_or_a_note_with_media() {
        let option = |id: &str, label: &str| OperationValue::Record {
            name: "PollOption".to_owned(),
            fields: vec![
                ("id".to_owned(), OperationValue::Text(id.to_owned())),
                ("label".to_owned(), OperationValue::Text(label.to_owned())),
            ],
        };
        let poll = OperationValue::Record {
            name: "Poll".to_owned(),
            fields: vec![
                (
                    "question".to_owned(),
                    OperationValue::Text("Best relay?".to_owned()),
                ),
                (
                    "options".to_owned(),
                    OperationValue::List(vec![option("a", "relay.damus.io"), option("b", "nos.lol")]),
                ),
                ("multiple_choice".to_owned(), OperationValue::Bool(false)),
                ("ends_at".to_owned(), OperationValue::Integer(1_700_000_000)),
            ],
        };
        assert_eq!(
            normalize_record(&poll),
            OperationValue::Poll(Poll {
                question: "Best relay?".to_owned(),
                options: vec![
                    PollOption {
                        id: "a".to_owned(),
                        label: "relay.damus.io".to_owned(),
                    },
                    PollOption {
                        id: "b".to_owned(),
                        label: "nos.lol".to_owned(),
                    },
                ],
                multiple_choice: false,
                ends_at: 1_700_000_000,
            })
        );

        let media = OperationValue::Record {
            name: "NoteWithMedia".to_owned(),
            fields: vec![
                (
                    "content".to_owned(),
                    OperationValue::Text("look".to_owned()),
                ),
                (
                    "media".to_owned(),
                    OperationValue::List(vec![OperationValue::Record {
                        name: "MediaAttachment".to_owned(),
                        fields: vec![
                            (
                                "url".to_owned(),
                                OperationValue::Text("https://cdn.example/a.jpg".to_owned()),
                            ),
                            (
                                "mime".to_owned(),
                                OperationValue::Text("image/jpeg".to_owned()),
                            ),
                            (
                                "hash".to_owned(),
                                OperationValue::Text("sha256:abc".to_owned()),
                            ),
                        ],
                    }]),
                ),
            ],
        };
        assert_eq!(
            normalize_record(&media),
            OperationValue::NoteWithMedia(NoteWithMedia {
                content: "look".to_owned(),
                media: vec![MediaAttachment {
                    url: "https://cdn.example/a.jpg".to_owned(),
                    mime: "image/jpeg".to_owned(),
                    hash: "sha256:abc".to_owned(),
                }],
            })
        );
    }

    #[test]
    fn a_list_of_records_normalizes_emoji_and_identity_claims() {
        let emoji = OperationValue::Record {
            name: "NoteWithEmoji".to_owned(),
            fields: vec![
                ("content".to_owned(), OperationValue::Text("gm".to_owned())),
                (
                    "emoji".to_owned(),
                    OperationValue::List(vec![OperationValue::Record {
                        name: "CustomEmoji".to_owned(),
                        fields: vec![
                            (
                                "shortcode".to_owned(),
                                OperationValue::Text("wave".to_owned()),
                            ),
                            (
                                "url".to_owned(),
                                OperationValue::Text("https://cdn.example/wave.png".to_owned()),
                            ),
                        ],
                    }]),
                ),
            ],
        };
        assert_eq!(
            normalize_record(&emoji),
            OperationValue::NoteWithEmoji(NoteWithEmoji {
                content: "gm".to_owned(),
                emoji: vec![CustomEmoji {
                    shortcode: "wave".to_owned(),
                    url: "https://cdn.example/wave.png".to_owned(),
                }],
            })
        );

        let claims = OperationValue::Record {
            name: "IdentityClaims".to_owned(),
            fields: vec![(
                "claims".to_owned(),
                OperationValue::List(vec![OperationValue::Record {
                    name: "ExternalIdentity".to_owned(),
                    fields: vec![
                        (
                            "platform".to_owned(),
                            OperationValue::Text("github:example".to_owned()),
                        ),
                        (
                            "proof".to_owned(),
                            OperationValue::Text("https://gist.example/abc".to_owned()),
                        ),
                    ],
                }]),
            )],
        };
        assert_eq!(
            normalize_record(&claims),
            OperationValue::IdentityClaims(IdentityClaims {
                claims: vec![ExternalIdentity {
                    platform: "github:example".to_owned(),
                    proof: "https://gist.example/abc".to_owned(),
                }],
            })
        );
    }

    #[test]
    fn a_list_of_records_normalizes_a_torrents_file_list() {
        let torrent = OperationValue::Record {
            name: "Torrent".to_owned(),
            fields: vec![
                (
                    "title".to_owned(),
                    OperationValue::Text("A film".to_owned()),
                ),
                (
                    "description".to_owned(),
                    OperationValue::Text("desc".to_owned()),
                ),
                (
                    "info_hash".to_owned(),
                    OperationValue::Text("abc123".to_owned()),
                ),
                (
                    "files".to_owned(),
                    OperationValue::List(vec![OperationValue::Record {
                        name: "TorrentFile".to_owned(),
                        fields: vec![
                            (
                                "path".to_owned(),
                                OperationValue::Text("film.mkv".to_owned()),
                            ),
                            ("bytes".to_owned(), OperationValue::Integer(4_700_000_000)),
                        ],
                    }]),
                ),
                (
                    "trackers".to_owned(),
                    OperationValue::List(vec![OperationValue::Text(
                        "udp://tracker.example/announce".to_owned(),
                    )]),
                ),
            ],
        };
        assert_eq!(
            normalize_record(&torrent),
            OperationValue::Torrent(Torrent {
                title: "A film".to_owned(),
                description: "desc".to_owned(),
                info_hash: "abc123".to_owned(),
                files: vec![TorrentFile {
                    path: "film.mkv".to_owned(),
                    bytes: 4_700_000_000,
                }],
                trackers: vec!["udp://tracker.example/announce".to_owned()],
            })
        );
    }

    #[test]
    fn a_list_valued_field_normalizes_a_community_moderator_list() {
        let community = OperationValue::Record {
            name: "Community".to_owned(),
            fields: vec![
                (
                    "identifier".to_owned(),
                    OperationValue::Text("devs".to_owned()),
                ),
                ("name".to_owned(), OperationValue::Text("Devs".to_owned())),
                (
                    "description".to_owned(),
                    OperationValue::Text("desc".to_owned()),
                ),
                (
                    "moderators".to_owned(),
                    OperationValue::List(vec![OperationValue::PubKey("alice".to_owned())]),
                ),
            ],
        };
        assert_eq!(
            normalize_record(&community),
            OperationValue::Community(Community {
                identifier: "devs".to_owned(),
                name: "Devs".to_owned(),
                description: "desc".to_owned(),
                moderators: vec!["alice".to_owned()],
            })
        );
    }

    #[test]
    fn a_geocache_listing_normalizes_its_integer_and_text_fields() {
        let listing = OperationValue::Record {
            name: "GeocacheListing".to_owned(),
            fields: vec![
                (
                    "identifier".to_owned(),
                    OperationValue::Text("park-1".to_owned()),
                ),
                (
                    "name".to_owned(),
                    OperationValue::Text("Park Bench Cache".to_owned()),
                ),
                (
                    "geohash".to_owned(),
                    OperationValue::Text("r1r0fs".to_owned()),
                ),
                ("difficulty".to_owned(), OperationValue::Integer(2)),
                ("terrain".to_owned(), OperationValue::Integer(1)),
                ("size".to_owned(), OperationValue::Text("small".to_owned())),
                (
                    "description".to_owned(),
                    OperationValue::Text("near the bench".to_owned()),
                ),
            ],
        };
        assert_eq!(
            normalize_record(&listing),
            OperationValue::GeocacheListing(Box::new(GeocacheListing {
                identifier: "park-1".to_owned(),
                name: "Park Bench Cache".to_owned(),
                geohash: "r1r0fs".to_owned(),
                difficulty: 2,
                terrain: 1,
                size: "small".to_owned(),
                description: "near the bench".to_owned(),
            }))
        );
    }

    #[test]
    fn a_list_valued_field_normalizes_a_zap_goals_relay_list() {
        let goal = OperationValue::Record {
            name: "ZapGoal".to_owned(),
            fields: vec![
                (
                    "description".to_owned(),
                    OperationValue::Text("Fund it".to_owned()),
                ),
                (
                    "amount_msats".to_owned(),
                    OperationValue::Integer(100_000_000),
                ),
                (
                    "relays".to_owned(),
                    OperationValue::List(vec![OperationValue::Text(
                        "wss://relay.example".to_owned(),
                    )]),
                ),
                ("closed_at".to_owned(), OperationValue::Integer(1_700_003_600)),
            ],
        };
        assert_eq!(
            normalize_record(&goal),
            OperationValue::ZapGoal(ZapGoal {
                description: "Fund it".to_owned(),
                amount_msats: 100_000_000,
                relays: vec!["wss://relay.example".to_owned()],
                closed_at: 1_700_003_600,
            })
        );

        let message = OperationValue::Record {
            name: "PublicMessage".to_owned(),
            fields: vec![
                (
                    "content".to_owned(),
                    OperationValue::Text("hi".to_owned()),
                ),
                (
                    "recipients".to_owned(),
                    OperationValue::List(vec![OperationValue::PubKey("alice".to_owned())]),
                ),
            ],
        };
        assert_eq!(
            normalize_record(&message),
            OperationValue::PublicMessage(PublicMessage {
                content: "hi".to_owned(),
                recipients: vec!["alice".to_owned()],
            })
        );
    }

    #[test]
    fn a_job_request_normalizes_its_mixed_integer_and_text_fields() {
        let request = OperationValue::Record {
            name: "JobRequest".to_owned(),
            fields: vec![
                ("job_kind".to_owned(), OperationValue::Integer(5002)),
                (
                    "input".to_owned(),
                    OperationValue::Text("translate".to_owned()),
                ),
                (
                    "input_type".to_owned(),
                    OperationValue::Text("text".to_owned()),
                ),
                (
                    "output".to_owned(),
                    OperationValue::Text("text/plain".to_owned()),
                ),
                ("bid_msats".to_owned(), OperationValue::Integer(5_000_000)),
            ],
        };
        assert_eq!(
            normalize_record(&request),
            OperationValue::JobRequest(JobRequest {
                job_kind: 5002,
                input: "translate".to_owned(),
                input_type: "text".to_owned(),
                output: "text/plain".to_owned(),
                bid_msats: 5_000_000,
            })
        );
    }

    #[test]
    fn a_p2p_order_normalizes_its_eight_mixed_fields_and_is_boxed() {
        let order = OperationValue::Record {
            name: "P2POrder".to_owned(),
            fields: vec![
                (
                    "identifier".to_owned(),
                    OperationValue::Text("order-1".to_owned()),
                ),
                (
                    "order_type".to_owned(),
                    OperationValue::Text("sell".to_owned()),
                ),
                (
                    "currency".to_owned(),
                    OperationValue::Text("USD".to_owned()),
                ),
                (
                    "status".to_owned(),
                    OperationValue::Text("pending".to_owned()),
                ),
                ("amount_sats".to_owned(), OperationValue::Integer(100_000)),
                (
                    "fiat_amount".to_owned(),
                    OperationValue::Text("50".to_owned()),
                ),
                (
                    "payment_method".to_owned(),
                    OperationValue::Text("bank transfer".to_owned()),
                ),
                ("premium".to_owned(), OperationValue::Integer(2)),
            ],
        };
        assert_eq!(
            normalize_record(&order),
            OperationValue::P2POrder(Box::new(P2POrder {
                identifier: "order-1".to_owned(),
                order_type: "sell".to_owned(),
                currency: "USD".to_owned(),
                status: "pending".to_owned(),
                amount_sats: 100_000,
                fiat_amount: "50".to_owned(),
                payment_method: "bank transfer".to_owned(),
                premium: 2,
            }))
        );
    }

    #[test]
    fn a_list_of_records_normalizes_payment_targets() {
        let targets = OperationValue::Record {
            name: "PaymentTargets".to_owned(),
            fields: vec![(
                "targets".to_owned(),
                OperationValue::List(vec![OperationValue::Record {
                    name: "PaymentTarget".to_owned(),
                    fields: vec![
                        (
                            "payment_type".to_owned(),
                            OperationValue::Text("bitcoin".to_owned()),
                        ),
                        (
                            "address".to_owned(),
                            OperationValue::Text("bc1qexample".to_owned()),
                        ),
                    ],
                }]),
            )],
        };
        assert_eq!(
            normalize_record(&targets),
            OperationValue::PaymentTargets(PaymentTargets {
                targets: vec![PaymentTarget {
                    payment_type: "bitcoin".to_owned(),
                    address: "bc1qexample".to_owned(),
                }],
            })
        );
    }

    #[test]
    fn nip05_identifier_matches_only_the_hex_pubkey_the_json_names() {
        let response = OperationValue::Text(
            r#"{"names":{"bob":"0000000000000000000000000000000000000000000000000000000000000001"}}"#
                .to_owned(),
        );
        let matching = [
            OperationValue::Text("bob".to_owned()),
            response.clone(),
            OperationValue::PubKey(
                "0000000000000000000000000000000000000000000000000000000000000001".to_owned(),
            ),
        ];
        assert_eq!(
            nip05_identifier_matches(&matching),
            Ok(OperationValue::Bool(true))
        );

        let wrong_pubkey = [
            OperationValue::Text("bob".to_owned()),
            response.clone(),
            OperationValue::PubKey(
                "0000000000000000000000000000000000000000000000000000000000000002".to_owned(),
            ),
        ];
        assert_eq!(
            nip05_identifier_matches(&wrong_pubkey),
            Ok(OperationValue::Bool(false))
        );

        let unknown_name = [
            OperationValue::Text("carol".to_owned()),
            response,
            OperationValue::PubKey(
                "0000000000000000000000000000000000000000000000000000000000000001".to_owned(),
            ),
        ];
        assert_eq!(
            nip05_identifier_matches(&unknown_name),
            Ok(OperationValue::Bool(false))
        );

        let malformed_json = [
            OperationValue::Text("bob".to_owned()),
            OperationValue::Text("not json".to_owned()),
            OperationValue::PubKey("1".repeat(64)),
        ];
        assert_eq!(
            nip05_identifier_matches(&malformed_json),
            Ok(OperationValue::Bool(false))
        );
    }

    // RFC 0002 §3: fold queries as pure functions. Every `OperationHost`
    // answers these identically (they are default trait methods), so a
    // bare `FakeOperationHost` exercises the same logic a real host would.

    #[test]
    fn a_valid_unexpired_invite_bundle_is_valid() {
        let owner = "1".repeat(64);
        let owner_salt = "2".repeat(64);
        let community_id = crate::authority::community_id(&owner, &owner_salt).unwrap();
        let bundle = serde_json::json!({
            "community_id": community_id,
            "owner": owner,
            "owner_salt": owner_salt,
            "community_root": "3".repeat(64),
            "root_epoch": 1,
            "channels": [],
            "name": "lounge",
            "expires_at": 2_000,
        })
        .to_string();
        let mut host = FakeOperationHost::default();
        assert_eq!(
            host.call_pure_function(
                "concord05",
                "invite_is_valid",
                &[
                    OperationValue::Text(bundle.clone()),
                    OperationValue::Integer(1_000)
                ]
            ),
            Ok(OperationValue::Bool(true))
        );
        // Past its own `expires_at`: still well-formed, but no longer valid.
        assert_eq!(
            host.call_pure_function(
                "concord05",
                "invite_is_valid",
                &[OperationValue::Text(bundle), OperationValue::Integer(3_000)]
            ),
            Ok(OperationValue::Bool(false))
        );
    }

    #[test]
    fn a_forged_or_malformed_invite_bundle_is_never_valid() {
        let mut host = FakeOperationHost::default();
        for bundle in [
            "not json".to_owned(),
            serde_json::json!({"community_id": "1".repeat(64), "owner": "1".repeat(64), "owner_salt": "2".repeat(64), "community_root": "3".repeat(64), "root_epoch": 1, "channels": [], "name": "x"}).to_string(),
        ] {
            assert_eq!(
                host.call_pure_function(
                    "concord05",
                    "invite_is_valid",
                    &[OperationValue::Text(bundle), OperationValue::Integer(0)]
                ),
                Ok(OperationValue::Bool(false))
            );
        }
    }

    #[test]
    fn commitment_matches_only_the_key_and_epoch_that_produced_it() {
        let key = DerivedKey::new(vec![9; 32]).unwrap();
        let expected = crate::rekey::epoch_key_commitment(4, &[9; 32]);
        let mut host = FakeOperationHost::default();
        assert_eq!(
            host.call_pure_function(
                "concord06",
                "commitment_matches",
                &[
                    OperationValue::DerivedKey(key.clone()),
                    OperationValue::Integer(4),
                    OperationValue::Text(expected.clone()),
                ]
            ),
            Ok(OperationValue::Bool(true))
        );
        // A different epoch derives a different commitment: no match.
        assert_eq!(
            host.call_pure_function(
                "concord06",
                "commitment_matches",
                &[
                    OperationValue::DerivedKey(key),
                    OperationValue::Integer(5),
                    OperationValue::Text(expected),
                ]
            ),
            Ok(OperationValue::Bool(false))
        );
    }

    #[test]
    fn pure_functions_reject_the_wrong_argument_shape_and_unknown_names() {
        let mut host = FakeOperationHost::default();
        assert!(matches!(
            host.call_pure_function("concord05", "invite_is_valid", &[]),
            Err(RuntimeError::InvalidOperationArguments { .. })
        ));
        assert!(matches!(
            host.call_pure_function("concord09", "nope", &[]),
            Err(RuntimeError::OperationUnavailable { .. })
        ));
        assert!(host.is_pure_function("concord05", "invite_is_valid"));
        assert!(!host.is_pure_function("concord01", "stream"));
    }

    #[test]
    fn concord_protocol_bytes_are_non_empty_and_debug_redacted() {
        assert!(SharedSecret::new(Vec::new()).is_err());
        assert!(DerivedKey::new(Vec::new()).is_err());
        assert!(SignedBytes::new(Vec::new()).is_err());

        let secret = SharedSecret::new(vec![1, 2, 3]).expect("secret accepted");
        let key = DerivedKey::new(vec![4, 5, 6]).expect("key accepted");
        let signed = SignedBytes::new(vec![7, 8, 9]).expect("signed bytes accepted");
        assert_eq!(secret.as_bytes(), &[1, 2, 3]);
        assert_eq!(key.as_bytes(), &[4, 5, 6]);
        assert_eq!(signed.as_bytes(), &[7, 8, 9]);
        assert!(!format!("{secret:?}").contains('1'));
        assert!(!format!("{key:?}").contains('4'));
        assert!(!format!("{signed:?}").contains('7'));
    }

    #[test]
    fn concord_key_host_is_capability_gated_and_deterministic_for_tests() {
        let secret = SharedSecret::new(vec![1, 2, 3]).expect("secret accepted");
        let mut host = FakeConcordKeyHost::default();
        let first = host
            .derive_stream_key(7, &secret)
            .expect("derivation permitted");
        let second = host
            .derive_stream_key(8, &secret)
            .expect("derivation permitted");
        assert_eq!(first, second);
        assert_eq!(first.as_bytes().len(), 32);
        assert_eq!(host.derivations, 2);

        host.denied = true;
        assert!(matches!(
            host.derive_stream_key(9, &secret),
            Err(RuntimeError::CapabilityDenied { .. })
        ));
    }

    #[test]
    fn concord01_operations_preserve_typed_stream_boundaries() {
        let secret = SharedSecret::new(vec![9, 8, 7]).expect("secret accepted");
        let mut host = FakeOperationHost::default();
        let key = host
            .call(
                1,
                "concord01",
                "derive_stream_key",
                &[OperationValue::SharedSecret(secret)],
            )
            .expect("stream key derivation available");
        let OperationValue::DerivedKey(key) = key else {
            panic!("expected derived key");
        };
        let message = OperationValue::StreamMessage(StreamMessage {
            author: "npub1author".to_owned(),
            content: "hello concord".to_owned(),
        });
        let result = host
            .call(
                2,
                "concord01",
                "publish_message",
                &[OperationValue::DerivedKey(key), message],
            )
            .expect("stream publication available");
        assert!(matches!(result, OperationValue::PublishReport(report) if report.accepted()));
    }

    #[test]
    fn concord01_seal_round_trip_preserves_exact_signed_bytes() {
        let key = DerivedKey::new(vec![1, 2, 3]).expect("key accepted");
        let payload = SignedBytes::new(vec![0, 1, 255, 2]).expect("payload accepted");
        let mut host = FakeOperationHost::default();
        let sealed = host
            .call(
                1,
                "concord01",
                "seal_message",
                &[
                    OperationValue::DerivedKey(key.clone()),
                    OperationValue::SignedBytes(payload.clone()),
                ],
            )
            .expect("seal available");
        let OperationValue::SealedEvent(sealed) = sealed else {
            panic!("expected sealed event");
        };
        let opened = host
            .call(
                2,
                "concord01",
                "open_message",
                &[
                    OperationValue::DerivedKey(key),
                    OperationValue::SealedEvent(sealed),
                ],
            )
            .expect("open available");
        assert_eq!(opened, OperationValue::SignedBytes(payload));
    }

    #[test]
    fn concord01_stream_wrap_round_trips_and_rejects_wrong_stream() {
        let key = DerivedKey::new(vec![1, 2, 3]).expect("key accepted");
        let other = DerivedKey::new(vec![9, 9]).expect("key accepted");
        let sealed = SealedEvent::new(vec![7, 0, 255]).expect("sealed accepted");
        let mut host = FakeOperationHost::default();
        let wrap = host
            .call(
                1,
                "concord01",
                "wrap_stream",
                &[
                    OperationValue::DerivedKey(key.clone()),
                    OperationValue::SealedEvent(sealed.clone()),
                ],
            )
            .expect("wrap available");
        let OperationValue::StreamWrap(inner) = &wrap else {
            panic!("expected stream wrap");
        };
        assert_eq!(inner.kind, 1059);
        let opened = host
            .call(
                2,
                "concord01",
                "unwrap_stream",
                &[OperationValue::DerivedKey(key), wrap.clone()],
            )
            .expect("unwrap available");
        assert_eq!(opened, OperationValue::SealedEvent(sealed));
        assert!(
            host.call(
                3,
                "concord01",
                "unwrap_stream",
                &[OperationValue::DerivedKey(other), wrap],
            )
            .is_err()
        );
    }

    #[test]
    fn concord01_control_seal_is_plaintext_and_verbatim() {
        let key = DerivedKey::new(vec![4, 4]).expect("key accepted");
        let rumor = SignedBytes::new(br#"{"kind":3308, "content":"x"}"#.to_vec()).expect("bytes");
        let mut host = FakeOperationHost::default();
        let sealed = host
            .call(
                1,
                "concord01",
                "seal_control_message",
                &[
                    OperationValue::DerivedKey(key.clone()),
                    OperationValue::SignedBytes(rumor.clone()),
                ],
            )
            .expect("control seal available");
        let OperationValue::SealedEvent(seal) = &sealed else {
            panic!("expected sealed event");
        };
        assert_eq!(seal.kind().wire_kind(), 20014);
        assert_eq!(seal.as_bytes(), rumor.as_bytes());
        let opened = host
            .call(
                2,
                "concord01",
                "open_message",
                &[OperationValue::DerivedKey(key), sealed],
            )
            .expect("open available");
        assert_eq!(opened, OperationValue::SignedBytes(rumor));
    }

    #[test]
    fn stream_wrap_validation_checks_kind_pubkey_ephemeral_and_seal_kind() {
        let sealed = SealedEvent::new(vec![1]).expect("sealed");
        let wrap = StreamWrap {
            kind: 1059,
            stream_pubkey: "aa".repeat(32),
            ephemeral_p: "bb".repeat(32),
            sealed: Some(sealed.clone()),
            wire: None,
        };
        assert_eq!(wrap.validate(&"aa".repeat(32), stream::Plane::Chat), Ok(()));
        assert_eq!(
            wrap.validate(&"cc".repeat(32), stream::Plane::Chat),
            Err(WrapError::WrongStream)
        );
        assert_eq!(
            wrap.validate(&"aa".repeat(32), stream::Plane::Control),
            Err(WrapError::WrongSealKind)
        );
        let bad_p = StreamWrap {
            ephemeral_p: "BB".repeat(32),
            ..wrap.clone()
        };
        assert_eq!(
            bad_p.validate(&"aa".repeat(32), stream::Plane::Chat),
            Err(WrapError::MalformedEphemeralKey)
        );
        let not_wrap = StreamWrap { kind: 4, ..wrap };
        assert_eq!(
            not_wrap.validate(&"aa".repeat(32), stream::Plane::Chat),
            Err(WrapError::NotAGiftWrap)
        );
    }

    #[test]
    fn wire_wraps_expose_public_fields_and_keep_the_seal_sealed() {
        let event = serde_json::json!({
            "kind": 1059, "pubkey": "aa".repeat(32),
            "tags": [["expiration", "9"], ["p", "bb".repeat(32)]],
        })
        .to_string();
        let wrap = StreamWrap::from_wire(&event).expect("wrap parses");
        assert_eq!(wrap.ephemeral_p, "bb".repeat(32));
        assert!(wrap.sealed.is_none() && wrap.wire.as_deref() == Some(event.as_str()));
        assert_eq!(wrap.validate(&"aa".repeat(32), stream::Plane::Chat), Ok(()));
        let no_p = serde_json::json!({"kind": 1059, "pubkey": "aa", "tags": []}).to_string();
        assert_eq!(
            StreamWrap::from_wire(&no_p),
            Err(WrapError::MalformedEphemeralKey)
        );
        assert_eq!(StreamWrap::from_wire("nope"), Err(WrapError::NotAGiftWrap));
    }

    #[test]
    fn group_keys_are_domain_separated_by_label_id_and_epoch() {
        use stream::GroupKeyLabel::{Channel, Guestbook};
        let secret = SharedSecret::new(vec![7; 32]).expect("secret");
        let mut host = FakeConcordKeyHost::default();
        let id = "ab".repeat(32);
        let mut derive = |label, id: &str, epoch| {
            host.derive_group_key(1, label, &secret, id, epoch)
                .expect("derived")
        };
        let base = derive(Channel, &id, 1);
        assert_eq!(base, derive(Channel, &id, 1));
        assert_ne!(base, derive(Guestbook, &id, 1));
        assert_ne!(base, derive(Channel, &id, 2));
        assert_ne!(base, derive(Channel, &"cd".repeat(32), 1));
        assert!(
            host.derive_group_key(2, Channel, &secret, "short", 1)
                .is_err()
        );
    }

    #[test]
    fn replaceable_events_use_timestamp_then_lowest_id() {
        let make = |created_at: u64, id: &str| SignedEvent {
            unsigned: UnsignedEvent {
                event_type: "Profile".to_owned(),
                kind: 0,
                content: id.to_owned(),
                tags: Vec::new(),
                created_at,
            },
            signer: "alice".to_owned(),
            id: id.to_owned(),
            signature: "sig".to_owned(),
        };
        let older = make(10, "ffff");
        let newer = make(11, "zzzz");
        let tie_high = make(11, "bbbb");
        let tie_low = make(11, "aaaa");
        assert_eq!(select_replaceable_event([&older, &newer]), Some(&newer));
        assert_eq!(
            select_replaceable_event([&newer, &tie_high]),
            Some(&tie_high)
        );
        assert_eq!(
            select_replaceable_event([&tie_high, &tie_low]),
            Some(&tie_low)
        );
    }

    #[test]
    fn wasm_dispatch_decoder_bounds_and_parses_payload() {
        let memory = br#"[{"op":"create_event","kind":1}]"#;
        let length = u32::try_from(memory.len()).expect("test payload fits");
        let records = decode_wasm_dispatch(memory, 0, length).expect("decodes payload");
        assert_eq!(records[0]["op"], "create_event");
        assert!(decode_wasm_dispatch(memory, 1, length).is_err());
    }

    #[test]
    fn wasm_dispatch_assigns_stable_invocations() {
        struct Host(Vec<InvocationId>);
        impl WasmDispatchHost for Host {
            fn dispatch(
                &mut self,
                invocation: InvocationId,
                _: &Value,
            ) -> Result<(), RuntimeError> {
                self.0.push(invocation);
                Ok(())
            }
        }
        let mut host = Host(Vec::new());
        let records = vec![json!({"op":"create_event"}), json!({"op":"publish_event"})];
        assert_eq!(
            dispatch_wasm_operations(&mut host, 40, &records).unwrap(),
            2
        );
        assert_eq!(host.0, vec![40, 41]);
    }

    #[test]
    fn wasm_publications_route_through_signer_and_relay_hosts() {
        let records = vec![
            json!({"op":"create_event","result":"%0","event":"Note","kind":1,"content":"hello"}),
            json!({"op":"sign_event","result":"%1","event":"%0","signer":"account"}),
            json!({"op":"publish_event","result":"%2","event":"%1","relayset":"public"}),
        ];
        let mut relay = FakeRelayHost {
            relays: [("public".to_owned(), true)].into_iter().collect(),
            ..FakeRelayHost::default()
        };
        let mut signer = FakeSignerHost::default();
        let reports = execute_wasm_publications(&mut relay, &mut signer, 1, &records)
            .expect("routes publication");
        assert_eq!(reports.len(), 1);
        assert_eq!(signer.signed.len(), 1);
        assert_eq!(relay.published.len(), 1);
    }

    #[test]
    fn reference_wasm_executor_reads_dispatch_section() {
        let dispatch = br#"[{"op":"create_event","result":"%0","event":"Note","kind":1,"content":"hello"},{"op":"sign_event","result":"%1","event":"%0","signer":"account"},{"op":"publish_event","event":"%1","relayset":"public"}]"#;
        let name = b"nscript.dispatch";
        let mut payload = vec![u8::try_from(name.len()).expect("test name fits")];
        payload.extend_from_slice(name);
        payload.extend_from_slice(dispatch);
        let mut module = b"\0asm\x01\0\0\0".to_vec();
        module.push(0);
        let payload_len = u32::try_from(payload.len()).expect("test payload fits");
        module.push(u8::try_from(payload_len & 0x7f).expect("length byte fits") | 0x80);
        module.push(u8::try_from(payload_len >> 7).expect("length continuation fits"));
        module.extend_from_slice(&payload);
        let mut relay = FakeRelayHost {
            relays: [("public".to_owned(), true)].into_iter().collect(),
            ..FakeRelayHost::default()
        };
        let mut signer = FakeSignerHost::default();
        let reports =
            execute_nscript_wasm(&module, &mut relay, &mut signer, 1).expect("executes dispatch");
        assert_eq!(reports.len(), 1);
    }

    #[test]
    fn nip46_host_binds_signing_to_provisioned_session() {
        #[derive(Default)]
        struct Transport;
        impl Nip46Transport for Transport {
            fn provision(&mut self, provider: &str) -> Result<SignerSession, RuntimeError> {
                Ok(SignerSession {
                    provider: provider.to_owned(),
                })
            }
            fn sign(
                &mut self,
                session: &SignerSession,
                event: UnsignedEvent,
            ) -> Result<SignedEvent, RuntimeError> {
                Ok(SignedEvent {
                    unsigned: event,
                    signer: session.provider.clone(),
                    id: "remote-id".to_owned(),
                    signature: "remote-sig".to_owned(),
                })
            }
        }
        let mut host = Nip46SignerHost::new(Transport);
        assert!(host.provision(1, "https://not-a-bunker").is_err());
        let session = host
            .provision(2, "bunker://remote")
            .expect("provisions session");
        let event = UnsignedEvent {
            event_type: "Note".to_owned(),
            kind: 1,
            content: "hello".to_owned(),
            tags: Vec::new(),
            created_at: 1,
        };
        assert!(host.sign(3, event.clone(), "other").is_err());
        assert_eq!(
            host.sign(4, event, &session.provider)
                .expect("signs remotely")
                .signer,
            "bunker://remote"
        );
    }

    #[test]
    fn file_storage_persists_transactions_and_claims() {
        let path = std::env::temp_dir().join(format!("nscript-storage-{}.db", std::process::id()));
        let _ = std::fs::remove_file(&path);
        let mut storage = FileStorage::open(&path).expect("opens file storage");
        let mut transaction = storage.begin(1);
        transaction.put("answer", "42");
        storage.commit(transaction);
        assert!(storage.claim_once(1, "event-1").expect("claims once"));
        drop(storage);
        let mut reopened = FileStorage::open(&path).expect("reopens file storage");
        assert_eq!(reopened.begin(2).get("answer"), Some("42"));
        assert!(
            !reopened
                .claim_once(2, "event-1")
                .expect("deduplicates claim")
        );
        let _ = std::fs::remove_file(path);
    }
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
    fn a_publish_written_inside_a_handler_does_not_fire_at_startup() {
        // The checker collects a `publish` wherever it appears (so a
        // handler's own permission/effect checks still apply), so without
        // `eval::top_level_publications` filtering by handler span, `run`
        // would fire this one immediately even though no event was ever
        // delivered to the handler it is written inside.
        let source = "use nip01\nuse nip46\n\nsigner account = nip46()\nrelayset public = configured\n\npermissions {\n    read Note from public\n    publish Note to public\n    sign Note with account\n    relay public\n}\n\non Note where tags.t contains \"trigger\" {\n    publish Note {\n        content: \"should wait for the handler\",\n    } to public with account\n}\n";
        let program = nscript_syntax::parse_program(source).0;
        let (checked, diagnostics) = nscript_semantics::check(&program);
        assert!(diagnostics.is_empty(), "{diagnostics:?}");
        let checked = checked.expect("checks");
        // The checker really did collect it — this is the regression this
        // test guards against, not an absence of the publication entirely.
        assert_eq!(checked.publications.len(), 1);

        let mut relay = FakeRelayHost::default();
        relay.relays.insert("fake://public".to_owned(), true);
        let mut runtime = Runtime::new(
            relay,
            FakeSignerHost::default(),
            FakeClock::default(),
            RecordingAudit::default(),
        );
        let reports = runtime.run(&program, &checked).expect("startup succeeds");
        assert!(
            reports.is_empty(),
            "a handler-nested publish must not fire at startup: {reports:?}"
        );
        assert!(runtime.relay.published.is_empty());
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
        assert_eq!(rolled_back.get("seen"), Some("event-1"));
        rolled_back.put("seen", "event-2");
        assert_eq!(rolled_back.get("seen"), Some("event-2"));
        drop(rolled_back);
        assert_eq!(
            storage.values.get("seen").map(String::as_str),
            Some("event-1")
        );
    }

    #[test]
    fn runtime_storage_transaction_commits_only_successful_work() {
        let mut runtime = Runtime::new(
            FakeRelayHost::default(),
            FakeSignerHost::default(),
            FakeClock::default(),
            RecordingAudit::default(),
        );
        let mut storage = InMemoryStorage::default();

        runtime
            .storage_transaction(&mut storage, "save_state", |transaction| {
                transaction.put("seen", "event-1");
                Ok(())
            })
            .expect("successful transaction commits");

        let result = runtime.storage_transaction(&mut storage, "fail_state", |transaction| {
            transaction.put("seen", "event-2");
            Err(RuntimeError::Cancelled)
        });
        assert_eq!(result, Err(RuntimeError::Cancelled));
        assert_eq!(
            storage.values.get("seen").map(String::as_str),
            Some("event-1")
        );
        assert_eq!(runtime.audit.entries.len(), 2);
        assert_eq!(runtime.audit.entries[0].result, "committed");
        assert_eq!(runtime.audit.entries[1].result, "rolled_back");
    }

    #[test]
    fn once_claims_are_atomic_and_audited() {
        let mut runtime = Runtime::new(
            FakeRelayHost::default(),
            FakeSignerHost::default(),
            FakeClock::default(),
            RecordingAudit::default(),
        );
        let mut storage = InMemoryStorage::default();
        assert_eq!(runtime.claim_once(&mut storage, "event-1"), Ok(true));
        assert_eq!(runtime.claim_once(&mut storage, "event-1"), Ok(false));
        assert_eq!(runtime.claim_once(&mut storage, "event-2"), Ok(true));
        assert_eq!(storage.claimed.len(), 2);
        assert_eq!(runtime.audit.entries[0].result, "claimed");
        assert_eq!(runtime.audit.entries[1].result, "already_claimed");
    }

    #[test]
    fn timer_scheduling_is_host_controlled_and_audited() {
        let mut runtime = Runtime::new(
            FakeRelayHost::default(),
            FakeSignerHost::default(),
            FakeClock { now: 100 },
            RecordingAudit::default(),
        );
        let mut timers = FakeTimerHost::default();
        let request = ScheduleRequest {
            name: "heartbeat".to_owned(),
            next_at: 200,
            interval: Some(60),
            catch_up: false,
        };
        let handle = runtime
            .schedule_timer(&mut timers, &request)
            .expect("valid timer is scheduled");
        assert_eq!(handle, TimerHandle { id: 1 });
        assert_eq!(timers.schedules, vec![request]);
        assert_eq!(runtime.audit.entries[0].operation, "schedule_timer");

        let invalid = ScheduleRequest {
            name: "bad".to_owned(),
            next_at: 0,
            interval: None,
            catch_up: false,
        };
        assert!(matches!(
            runtime.schedule_timer(&mut timers, &invalid),
            Err(RuntimeError::ResourceLimit { resource }) if resource == "timer"
        ));
        assert_eq!(runtime.audit.entries[1].result, "error");
    }

    #[test]
    fn timer_host_rejects_overlapping_schedule_names() {
        let mut host = FakeTimerHost::default();
        let request = ScheduleRequest {
            name: "heartbeat".to_owned(),
            next_at: 100,
            interval: Some(60),
            catch_up: false,
        };
        host.schedule(1, &request).expect("first timer");
        assert!(matches!(
            host.schedule(2, &request),
            Err(RuntimeError::ResourceLimit { resource }) if resource == "timer_overlap"
        ));
    }

    #[test]
    fn typed_subscriptions_are_host_controlled_and_audited() {
        let mut runtime = Runtime::new(
            FakeRelayHost::default(),
            FakeSignerHost::default(),
            FakeClock::default(),
            RecordingAudit::default(),
        );
        let mut relay = FakeRelayHost::default();
        let request = SubscriptionRequest {
            event_type: "Note".to_owned(),
            relayset: Some("public".to_owned()),
            kinds: vec![1],
            tag_equals: vec![("p".to_owned(), "alice".to_owned())],
            cursor: None,
            author: Some("alice".to_owned()),
            since: Some(100),
            limit: Some(20),
        };
        let handle = runtime
            .subscribe(&mut relay, &request)
            .expect("valid subscription");
        assert_eq!(handle, SubscriptionHandle { id: 1 });
        assert_eq!(relay.subscriptions, vec![request.clone()]);
        assert_eq!(runtime.audit.entries[0].operation, "subscribe");
        let event = SignedEvent {
            unsigned: UnsignedEvent {
                event_type: "Note".to_owned(),
                kind: 1,
                content: "hello".to_owned(),
                tags: Vec::new(),
                created_at: 100,
            },
            signer: "alice".to_owned(),
            id: "event-1".to_owned(),
            signature: "sig".to_owned(),
        };
        relay.queued_events.insert(1, vec![event.clone(), event]);
        let batch = runtime
            .poll_subscription(&mut relay, &handle)
            .expect("subscription polls");
        assert_eq!(batch.events.len(), 1);
        assert!(batch.complete);
        assert_eq!(batch.cursor.as_deref(), Some("cursor-1"));
        assert_eq!(runtime.audit.entries[1].result, "complete");
        runtime
            .unsubscribe(&mut relay, &handle)
            .expect("subscription closes");
        assert!(relay.closed_subscriptions.contains(&1));
        assert_eq!(runtime.audit.entries[2].operation, "unsubscribe");

        let invalid = SubscriptionRequest {
            event_type: "Note".to_owned(),
            relayset: None,
            kinds: Vec::new(),
            tag_equals: vec![("p".to_owned(), "alice".to_owned())],
            cursor: None,
            author: None,
            since: None,
            limit: Some(0),
        };
        assert!(matches!(
            runtime.subscribe(&mut relay, &invalid),
            Err(RuntimeError::InvalidOperationArguments { operation })
                if operation == "subscribe"
        ));
        assert_eq!(runtime.audit.entries[3].result, "error");
        assert!(matches!(
            runtime.unsubscribe(&mut relay, &SubscriptionHandle { id: 9 }),
            Err(RuntimeError::InvalidOperationArguments { operation })
                if operation == "unsubscribe"
        ));
        assert_eq!(runtime.audit.entries[4].result, "error");

        runtime.set_max_subscription_batch(0);
        let limited = runtime
            .subscribe(&mut relay, &request)
            .expect("second subscription");
        relay.queued_events.insert(
            limited.id,
            vec![SignedEvent {
                unsigned: UnsignedEvent {
                    event_type: "Note".to_owned(),
                    kind: 1,
                    content: "limited".to_owned(),
                    tags: Vec::new(),
                    created_at: 101,
                },
                signer: "alice".to_owned(),
                id: "event-2".to_owned(),
                signature: "sig-2".to_owned(),
            }],
        );
        assert!(matches!(
            runtime.poll_subscription(&mut relay, &limited),
            Err(RuntimeError::ResourceLimit { resource }) if resource == "subscription_batch"
        ));
    }

    #[test]
    fn polling_and_claiming_filters_persisted_duplicates() {
        let mut runtime = Runtime::new(
            FakeRelayHost::default(),
            FakeSignerHost::default(),
            FakeClock::default(),
            RecordingAudit::default(),
        );
        let mut relay = FakeRelayHost::default();
        let request = SubscriptionRequest {
            event_type: "Note".to_owned(),
            relayset: None,
            kinds: vec![1],
            tag_equals: vec![("p".to_owned(), "alice".to_owned())],
            cursor: Some("resume-1".to_owned()),
            author: None,
            since: None,
            limit: Some(10),
        };
        let handle = runtime.subscribe(&mut relay, &request).expect("subscribe");
        relay.queued_events.insert(
            handle.id,
            vec![SignedEvent {
                unsigned: UnsignedEvent {
                    event_type: "Note".to_owned(),
                    kind: 1,
                    content: "hello".to_owned(),
                    tags: Vec::new(),
                    created_at: 100,
                },
                signer: "alice".to_owned(),
                id: "event-claim".to_owned(),
                signature: "sig".to_owned(),
            }],
        );
        let mut storage = InMemoryStorage::default();
        let batch = runtime
            .poll_and_claim(&mut relay, &mut storage, &handle)
            .expect("claim batch");
        assert_eq!(batch.events.len(), 1);
        assert!(storage.claimed.contains("event-claim"));
    }

    #[test]
    fn logging_is_bounded_and_audited() {
        let mut runtime = Runtime::new(
            FakeRelayHost::default(),
            FakeSignerHost::default(),
            FakeClock::default(),
            RecordingAudit::default(),
        );
        let mut logs = FakeLogHost {
            max_message_bytes: 8,
            ..Default::default()
        };
        runtime
            .log(
                &mut logs,
                &LogRecord {
                    level: "info".to_owned(),
                    message: "ready".to_owned(),
                },
            )
            .expect("short log is accepted");
        assert_eq!(logs.records.len(), 1);
        assert!(matches!(
            runtime.log(
                &mut logs,
                &LogRecord {
                    level: "info".to_owned(),
                    message: "too long!".to_owned(),
                },
            ),
            Err(RuntimeError::ResourceLimit { resource }) if resource == "log_message"
        ));
        assert_eq!(runtime.audit.entries[0].operation, "log");
        assert_eq!(runtime.audit.entries[1].result, "error");
    }

    #[test]
    fn checked_program_schedules_every_and_at_declarations() {
        let source = "permissions {\n    clock\n    log\n}\nevery 5m { print(\"tick\") }\nat 200 { print(\"once\") }";
        let program = nscript_syntax::parse_program(source).0;
        let (checked, diagnostics) = nscript_semantics::check(&program);
        assert!(diagnostics.is_empty(), "{diagnostics:?}");
        let checked = checked.expect("program checks");

        let mut runtime = Runtime::new(
            FakeRelayHost::default(),
            FakeSignerHost::default(),
            FakeClock { now: 100 },
            RecordingAudit::default(),
        );
        let mut timers = FakeTimerHost::default();
        let handles = runtime
            .schedule_program(&mut timers, &checked)
            .expect("schedules are accepted");
        assert_eq!(handles, vec![TimerHandle { id: 1 }, TimerHandle { id: 2 }]);
        assert_eq!(timers.schedules[0].next_at, 400);
        assert_eq!(timers.schedules[0].interval, Some(300));
        assert_eq!(timers.schedules[1].next_at, 200);
    }

    #[test]
    fn checked_handlers_lower_to_typed_subscriptions() {
        let source = "permissions {\n    read Note from public\n    relay public\n    log\n}\non Note where tags.t contains \"nostrhost\" {\n    print(\"seen\")\n}";
        let program = nscript_syntax::parse_program(source).0;
        let (checked, diagnostics) = nscript_semantics::check(&program);
        assert!(diagnostics.is_empty(), "{diagnostics:?}");
        let checked = checked.expect("program checks");
        assert_eq!(checked.handlers.len(), 1);
        assert!(checked.handlers[0].has_predicate);
        let subscriptions = Runtime::<FakeRelayHost, FakeSignerHost, FakeClock, RecordingAudit>::handler_subscriptions(
            &checked,
            Some("public"),
        );
        assert_eq!(subscriptions.len(), 1);
        assert_eq!(subscriptions[0].event_type, "Note");
        assert_eq!(subscriptions[0].relayset.as_deref(), Some("public"));
        assert_eq!(
            subscriptions[0].tag_equals,
            vec![("t".to_owned(), "nostrhost".to_owned())]
        );
    }

    #[test]
    fn handler_body_executes_print_through_log_host() {
        let source = "permissions {\n    read Note from public\n    relay public\n    log\n}\non Note { print(\"hello\") }";
        let program = nscript_syntax::parse_program(source).0;
        let (checked, diagnostics) = nscript_semantics::check(&program);
        assert!(diagnostics.is_empty(), "{diagnostics:?}");
        let checked = checked.expect("program checks");
        let mut runtime = Runtime::new(
            FakeRelayHost::default(),
            FakeSignerHost::default(),
            FakeClock::default(),
            RecordingAudit::default(),
        );
        let mut logs = FakeLogHost {
            max_message_bytes: 16,
            ..Default::default()
        };
        runtime
            .execute_handler_body(&checked.handlers[0], &mut logs)
            .expect("print statement executes");
        assert_eq!(logs.records.len(), 1);
        assert_eq!(logs.records[0].message, "hello");
    }

    #[test]
    fn handler_body_evaluates_boolean_branches() {
        let source = "permissions {\n    read Note from public\n    relay public\n    log\n}\non Note { if true { print(\"then\") } else { print(\"else\") } }";
        let program = nscript_syntax::parse_program(source).0;
        let (checked, diagnostics) = nscript_semantics::check(&program);
        assert!(diagnostics.is_empty(), "{diagnostics:?}");
        let checked = checked.expect("program checks");
        let mut runtime = Runtime::new(
            FakeRelayHost::default(),
            FakeSignerHost::default(),
            FakeClock::default(),
            RecordingAudit::default(),
        );
        let mut logs = FakeLogHost::default();
        runtime
            .execute_handler_body(&checked.handlers[0], &mut logs)
            .expect("conditional body executes");
        assert_eq!(
            logs.records
                .iter()
                .map(|record| record.message.as_str())
                .collect::<Vec<_>>(),
            vec!["then"]
        );
    }

    #[test]
    fn handler_body_can_match_delivered_event_fields() {
        let source = "permissions {\n    read Note from public\n    relay public\n    log\n}\non Note {\n    if event.author == \"alice\" && event.kind == 1 && event.tags.t contains \"nostrhost\" && event.content contains \"nostr\" {\n        print(\"matched\")\n    }\n}";
        let program = nscript_syntax::parse_program(source).0;
        let (checked, diagnostics) = nscript_semantics::check(&program);
        assert!(diagnostics.is_empty(), "{diagnostics:?}");
        let checked = checked.expect("program checks");
        let event = SignedEvent {
            unsigned: UnsignedEvent {
                event_type: "Note".to_owned(),
                kind: 1,
                content: "hello nostr".to_owned(),
                tags: vec![("t".to_owned(), "nostrhost".to_owned())],
                created_at: 100,
            },
            signer: "alice".to_owned(),
            id: "event-fields".to_owned(),
            signature: "sig".to_owned(),
        };
        let mut runtime = Runtime::new(
            FakeRelayHost::default(),
            FakeSignerHost::default(),
            FakeClock::default(),
            RecordingAudit::default(),
        );
        let mut logs = FakeLogHost::default();
        runtime
            .execute_handler_body_for_event(&checked.handlers[0], &event, &mut logs)
            .expect("event-bound condition executes");
        assert_eq!(logs.records[0].message, "matched");
    }

    #[test]
    fn handler_body_binds_event_values_with_let() {
        let source = "permissions {\n    read Note from public\n    relay public\n    log\n}\non Note {\n    let message = event.content\n    print(message)\n}";
        let program = nscript_syntax::parse_program(source).0;
        let (checked, diagnostics) = nscript_semantics::check(&program);
        assert!(diagnostics.is_empty(), "{diagnostics:?}");
        let checked = checked.expect("program checks");
        let event = SignedEvent {
            unsigned: UnsignedEvent {
                event_type: "Note".to_owned(),
                kind: 1,
                content: "captured".to_owned(),
                tags: Vec::new(),
                created_at: 100,
            },
            signer: "alice".to_owned(),
            id: "event-let".to_owned(),
            signature: "sig".to_owned(),
        };
        let mut runtime = Runtime::new(
            FakeRelayHost::default(),
            FakeSignerHost::default(),
            FakeClock::default(),
            RecordingAudit::default(),
        );
        let mut logs = FakeLogHost::default();
        runtime
            .execute_handler_body_for_event(&checked.handlers[0], &event, &mut logs)
            .expect("let binding executes");
        assert_eq!(logs.records[0].message, "captured");
    }

    #[test]
    fn handler_body_return_stops_remaining_statements() {
        let source = "permissions {\n    read Note from public\n    relay public\n    log\n}\non Note {\n    print(\"before\")\n    return\n    print(\"after\")\n}";
        let program = nscript_syntax::parse_program(source).0;
        let (checked, diagnostics) = nscript_semantics::check(&program);
        assert!(diagnostics.is_empty(), "{diagnostics:?}");
        let checked = checked.expect("program checks");
        let mut runtime = Runtime::new(
            FakeRelayHost::default(),
            FakeSignerHost::default(),
            FakeClock::default(),
            RecordingAudit::default(),
        );
        let mut logs = FakeLogHost::default();
        runtime
            .execute_handler_body(&checked.handlers[0], &mut logs)
            .expect("return executes");
        assert_eq!(logs.records.len(), 1);
        assert_eq!(logs.records[0].message, "before");
    }

    #[test]
    fn handler_body_rejects_value_return() {
        let source = "permissions {\n    read Note from public\n    relay public\n}\non Note {\n    return \"value\"\n}";
        let program = nscript_syntax::parse_program(source).0;
        let (checked, diagnostics) = nscript_semantics::check(&program);
        assert!(diagnostics.is_empty(), "{diagnostics:?}");
        let checked = checked.expect("program checks");
        let mut runtime = Runtime::new(
            FakeRelayHost::default(),
            FakeSignerHost::default(),
            FakeClock::default(),
            RecordingAudit::default(),
        );
        let mut logs = FakeLogHost::default();
        assert!(
            runtime
                .execute_handler_body(&checked.handlers[0], &mut logs)
                .is_err()
        );
    }

    #[test]
    fn handler_cycle_executes_event_aware_body() {
        let source = "permissions {\n    read Note from public\n    relay public\n    log\n}\non Note {\n    if event.author == \"alice\" {\n        print(event.content)\n    }\n}";
        let program = nscript_syntax::parse_program(source).0;
        let (checked, diagnostics) = nscript_semantics::check(&program);
        assert!(diagnostics.is_empty(), "{diagnostics:?}");
        let checked = checked.expect("program checks");
        let mut runtime = Runtime::new(
            FakeRelayHost::default(),
            FakeSignerHost::default(),
            FakeClock::default(),
            RecordingAudit::default(),
        );
        let mut relay = FakeRelayHost::default();
        relay.queued_events.insert(
            1,
            vec![SignedEvent {
                unsigned: UnsignedEvent {
                    event_type: "Note".to_owned(),
                    kind: 1,
                    content: "hello".to_owned(),
                    tags: Vec::new(),
                    created_at: 100,
                },
                signer: "alice".to_owned(),
                id: "event-handler-body".to_owned(),
                signature: "sig".to_owned(),
            }],
        );
        let mut claims = InMemoryStorage::default();
        let mut storage = InMemoryStorage::default();
        let mut logs = FakeLogHost::default();
        let dispatched = runtime
            .run_handler_cycle_with_event_body(
                &checked,
                Some("public"),
                &mut relay,
                &mut claims,
                &mut storage,
                &mut logs,
            )
            .expect("handler cycle executes body");
        assert_eq!(dispatched, 1);
        assert_eq!(logs.records[0].message, "hello");
        assert!(relay.closed_subscriptions.contains(&1));
    }

    #[test]
    fn simulate_event_previews_a_synthetic_event_without_hosts() {
        let source = "permissions {\n    read Note from public\n    relay public\n    log\n}\non Note {\n    print(event.content)\n}";
        let program = nscript_syntax::parse_program(source).0;
        let (checked, diagnostics) = nscript_semantics::check(&program);
        assert!(diagnostics.is_empty(), "{diagnostics:?}");
        let checked = checked.expect("program checks");
        let event = SignedEvent {
            unsigned: UnsignedEvent {
                event_type: "Note".to_owned(),
                kind: 1,
                content: "hello preview".to_owned(),
                tags: Vec::new(),
                created_at: 100,
            },
            signer: "alice".to_owned(),
            id: "preview-1".to_owned(),
            signature: "sig".to_owned(),
        };
        let mut relay = FakeRelayHost::default();
        let mut storage = InMemoryStorage::default();
        let mut logs = FakeLogHost::default();
        let mut operations = eval::SimulatedOperations::default();
        let report =
            Runtime::<FakeRelayHost, FakeSignerHost, FakeClock, RecordingAudit>::simulate_event(
                &program,
                &checked,
                &mut relay,
                &mut storage,
                &mut logs,
                &mut operations,
                None,
                &event,
            )
            .expect("preview executes");
        assert_eq!(report.dispatched, 1);
        assert_eq!(report.subscriptions, ["Note"]);
        assert_eq!(report.logs.len(), 1);
        assert_eq!(report.logs[0].message, "hello preview");
    }

    fn simulate(
        source: &str,
        event: &SignedEvent,
        principal: Option<&str>,
    ) -> (SimulationReport, InMemoryStorage) {
        let (program, _) = nscript_syntax::parse_program(source);
        let (checked, diagnostics) = nscript_semantics::check(&program);
        assert!(diagnostics.is_empty(), "{diagnostics:?}");
        let checked = checked.expect("program checks");
        let mut relay = FakeRelayHost::default();
        let mut storage = InMemoryStorage::default();
        let mut logs = FakeLogHost::default();
        let mut operations = eval::SimulatedOperations::default();
        let report =
            Runtime::<FakeRelayHost, FakeSignerHost, FakeClock, RecordingAudit>::simulate_event(
                &program,
                &checked,
                &mut relay,
                &mut storage,
                &mut logs,
                &mut operations,
                principal,
                event,
            )
            .expect("preview executes");
        (report, storage)
    }

    fn preview_event(content: &str) -> SignedEvent {
        SignedEvent {
            unsigned: UnsignedEvent {
                event_type: "Note".to_owned(),
                kind: 1,
                content: content.to_owned(),
                tags: Vec::new(),
                created_at: 100,
            },
            signer: "mallory".to_owned(),
            id: "preview".to_owned(),
            signature: "sig".to_owned(),
        }
    }

    #[test]
    fn simulate_event_lets_a_handler_call_module_operations() {
        let source = "use concord04\npermissions {\n    concord_kick\n    log\n}\non Note {\n    if event.content contains \"spam\" {\n        kick event.author\n    }\n}";
        let (report, _) = simulate(source, &preview_event("buy spam"), None);
        assert_eq!(report.dispatched, 1);
        assert_eq!(report.operations.len(), 1);
        assert_eq!(report.operations[0].operation, "kick_member");
        assert_eq!(
            report.operations[0].arguments,
            vec![OperationValue::PubKey("mallory".to_owned())]
        );
        assert!(report.operations[0].simulated);
        let (quiet, _) = simulate(source, &preview_event("hello"), None);
        assert!(quiet.operations.is_empty());
    }

    #[test]
    fn simulate_event_reports_a_failing_handler_without_hiding_the_others() {
        let source = "permissions {\n    log\n}\non Note {\n    print(me)\n}\non Note {\n    print(\"second\")\n}";
        let (report, _) = simulate(source, &preview_event("x"), None);
        assert_eq!(report.dispatched, 2, "both handlers ran");
        assert_eq!(report.failures.len(), 1);
        assert_eq!(report.logs.len(), 1, "the second handler's log survived");
        // With a principal the same program has no failure.
        let (fine, _) = simulate(source, &preview_event("x"), Some("my-key"));
        assert!(fine.failures.is_empty());
        assert_eq!(fine.logs.len(), 2);
    }

    #[test]
    fn handler_body_iterates_event_tags() {
        let source = "permissions {\n    read Note from public\n    relay public\n    log\n}\non Note {\n    for tag in event.tags {\n        print(tag)\n    }\n}";
        let program = nscript_syntax::parse_program(source).0;
        let (checked, diagnostics) = nscript_semantics::check(&program);
        assert!(diagnostics.is_empty(), "{diagnostics:?}");
        let checked = checked.expect("program checks");
        let event = SignedEvent {
            unsigned: UnsignedEvent {
                event_type: "Note".to_owned(),
                kind: 1,
                content: "hello".to_owned(),
                tags: vec![
                    ("t".to_owned(), "one".to_owned()),
                    ("t".to_owned(), "two".to_owned()),
                ],
                created_at: 100,
            },
            signer: "alice".to_owned(),
            id: "event-tags".to_owned(),
            signature: "sig".to_owned(),
        };
        let mut runtime = Runtime::new(
            FakeRelayHost::default(),
            FakeSignerHost::default(),
            FakeClock::default(),
            RecordingAudit::default(),
        );
        let mut logs = FakeLogHost::default();
        runtime
            .execute_handler_body_for_event(&checked.handlers[0], &event, &mut logs)
            .expect("tag loop executes");
        assert_eq!(logs.records.len(), 2);
        assert_eq!(logs.records[0].message, "t=one");
        assert_eq!(logs.records[1].message, "t=two");
    }

    #[test]
    #[cfg(feature = "real-hosts")]
    fn real_relay_adapter_decodes_nip01_event_frames() {
        let frame = serde_json::json!({
            "id": "event-1",
            "pubkey": "alice",
            "created_at": 100,
            "kind": 1,
            "tags": [["t", "nostr"]],
            "content": "hello",
            "sig": "signature"
        });
        let event = RealRelayHost::parse_event(&frame).expect("valid NIP-01 event");
        assert_eq!(event.id, "event-1");
        assert_eq!(event.signer, "alice");
        assert_eq!(event.unsigned.kind, 1);
        assert_eq!(
            event.unsigned.tags,
            vec![("t".to_owned(), "nostr".to_owned())]
        );
    }

    #[test]
    #[cfg(feature = "real-hosts")]
    fn real_relay_adapter_reports_connection_failures() {
        assert!(matches!(
            RealRelayHost::connect("ws://127.0.0.1:1"),
            Err(RuntimeError::RelayUnavailable { relayset })
                if relayset == "ws://127.0.0.1:1"
        ));
    }

    #[test]
    #[cfg(feature = "real-hosts")]
    fn real_relay_adapter_accepts_secure_relay_urls() {
        assert!(matches!(
            RealRelayHost::connect("wss://127.0.0.1:1"),
            Err(RuntimeError::RelayUnavailable { relayset })
                if relayset == "wss://127.0.0.1:1"
        ));
    }

    /// A minimal local relay: accepts one WebSocket client and runs `script`
    /// against it, returning the `ws://` URL to connect to.
    #[cfg(feature = "real-hosts")]
    fn local_relay(script: impl FnOnce(&mut WebSocket<TcpStream>) + Send + 'static) -> String {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("bind");
        let url = format!("ws://{}", listener.local_addr().expect("addr"));
        thread::spawn(move || {
            let (stream, _) = listener.accept().expect("accept");
            let mut socket = tungstenite::accept(stream).expect("handshake");
            script(&mut socket);
        });
        url
    }

    #[cfg(feature = "real-hosts")]
    fn sample_event(id: &str) -> SignedEvent {
        SignedEvent {
            unsigned: UnsignedEvent {
                event_type: "Note".to_owned(),
                kind: 1,
                content: "hi".to_owned(),
                tags: Vec::new(),
                created_at: 1,
            },
            signer: "alice".to_owned(),
            id: id.to_owned(),
            signature: "sig".to_owned(),
        }
    }

    #[cfg(feature = "real-hosts")]
    fn send_text(socket: &mut WebSocket<TcpStream>, value: &serde_json::Value) {
        socket
            .send(Message::Text(value.to_string().into()))
            .expect("relay send");
    }

    #[test]
    #[cfg(feature = "real-hosts")]
    fn publish_waits_for_the_ok_that_names_its_event() {
        let url = local_relay(|socket| {
            let _ = socket.read().expect("EVENT frame");
            // Unrelated frames and another event's OK arrive first.
            send_text(socket, &serde_json::json!(["NOTICE", "slow down"]));
            send_text(socket, &serde_json::json!(["OK", "someone-else", true, ""]));
            send_text(
                socket,
                &serde_json::json!(["OK", "evt-1", false, "blocked: spam"]),
            );
        });
        let mut host = RealRelayHost::connect(url).expect("connect");
        let report = host
            .publish(1, &sample_event("evt-1"), "r")
            .expect("report");
        assert_eq!(report.outcomes.len(), 1);
        assert!(!report.outcomes[0].accepted, "the matching OK said no");
        assert_eq!(report.outcomes[0].detail, "blocked: spam");
    }

    #[test]
    #[cfg(feature = "real-hosts")]
    fn a_silent_relay_times_out_instead_of_hanging() {
        let url = local_relay(|socket| {
            let _ = socket.read();
            thread::sleep(Duration::from_secs(2));
        });
        let mut host = RealRelayHost::connect(url).expect("connect");
        host.set_read_timeout(Duration::from_millis(200));
        let started = std::time::Instant::now();
        let result = host.publish(1, &sample_event("evt-2"), "r");
        assert!(matches!(result, Err(RuntimeError::RelayUnavailable { .. })));
        assert!(started.elapsed() < Duration::from_secs(2));
    }

    #[test]
    #[cfg(feature = "real-hosts")]
    fn pool_publication_survives_a_failing_relay() {
        let good = local_relay(|socket| {
            let _ = socket.read().expect("EVENT frame");
            send_text(socket, &serde_json::json!(["OK", "evt-3", true, ""]));
        });
        let dead = local_relay(|socket| {
            let _ = socket.read();
            let _ = socket.close(None);
        });
        let mut pool = RealRelayPool::new();
        pool.add_relay(good.clone()).expect("good relay");
        pool.add_relay(dead.clone()).expect("dead relay");
        let report = pool
            .publish(1, &sample_event("evt-3"), "community")
            .expect("partial publication is a report, not an error");
        assert_eq!(report.outcomes.len(), 2);
        let accepted: Vec<_> = report.outcomes.iter().filter(|o| o.accepted).collect();
        assert_eq!(accepted.len(), 1);
        assert_eq!(accepted[0].relay, good);
        assert!(
            report
                .outcomes
                .iter()
                .any(|o| o.relay == dead && !o.accepted)
        );
    }

    /// Regression: a `wss://` connect used to panic for want of a rustls
    /// crypto provider. Runs against a real relay, so it is opt-in:
    /// `cargo test -p nscript-runtime -- --ignored real_relay_tls`.
    #[test]
    #[ignore = "needs network access"]
    #[cfg(feature = "real-hosts")]
    fn real_relay_tls_handshake_succeeds_against_a_public_relay() {
        let mut host = RealRelayHost::connect("wss://relay.ditto.pub")
            .expect("TLS handshake and WebSocket upgrade succeed");
        // The session is live: a request round-trips through the socket.
        host.send_json(&serde_json::json!(["REQ", "t", {"kinds": [1], "limit": 1}]))
            .expect("frame sent over TLS");
    }

    #[test]
    #[cfg(feature = "real-hosts")]
    fn opening_a_secure_socket_installs_a_tls_provider_without_panicking() {
        // Refused before any handshake, but the provider must already be set.
        assert!(RealRelayHost::connect("wss://127.0.0.1:1").is_err());
        assert!(rustls::crypto::CryptoProvider::get_default().is_some());
    }

    #[test]
    #[cfg(feature = "real-hosts")]
    fn real_relay_pool_routes_empty_pool_as_unavailable() {
        let mut pool = RealRelayPool::new();
        let request = SubscriptionRequest {
            event_type: "Note".to_owned(),
            relayset: Some("public".to_owned()),
            kinds: vec![1],
            tag_equals: Vec::new(),
            cursor: None,
            author: None,
            since: None,
            limit: None,
        };
        assert!(matches!(
            pool.subscribe(1, &request),
            Err(RuntimeError::RelayUnavailable { relayset }) if relayset == "public"
        ));
    }

    #[test]
    fn subscription_matching_checks_event_type_kind_and_author() {
        let request = SubscriptionRequest {
            event_type: "Note".to_owned(),
            relayset: None,
            kinds: vec![1],
            tag_equals: vec![("p".to_owned(), "alice".to_owned())],
            cursor: None,
            author: Some("alice".to_owned()),
            since: Some(100),
            limit: None,
        };
        let event = SignedEvent {
            unsigned: UnsignedEvent {
                event_type: "Note".to_owned(),
                kind: 1,
                content: "hello".to_owned(),
                tags: vec![("p".to_owned(), "alice".to_owned())],
                created_at: 100,
            },
            signer: "alice".to_owned(),
            id: "event-1".to_owned(),
            signature: "sig".to_owned(),
        };
        assert!(Runtime::<
            FakeRelayHost,
            FakeSignerHost,
            FakeClock,
            RecordingAudit,
        >::matches_subscription(&request, &event));
        assert_eq!(
            event.unsigned.wire_tags(),
            vec![vec!["p".to_owned(), "alice".to_owned()]]
        );
        let mut wrong_author = event.clone();
        wrong_author.signer = "bob".to_owned();
        assert!(!Runtime::<
            FakeRelayHost,
            FakeSignerHost,
            FakeClock,
            RecordingAudit,
        >::matches_subscription(&request, &wrong_author));
        let mut stale = event;
        stale.unsigned.created_at = 99;
        assert!(!Runtime::<
            FakeRelayHost,
            FakeSignerHost,
            FakeClock,
            RecordingAudit,
        >::matches_subscription(&request, &stale));
    }

    #[test]
    fn dispatch_event_claims_before_running_handler_body() {
        let request = SubscriptionRequest {
            event_type: "Note".to_owned(),
            relayset: None,
            kinds: vec![1],
            tag_equals: Vec::new(),
            cursor: None,
            author: Some("alice".to_owned()),
            since: None,
            limit: None,
        };
        let event = SignedEvent {
            unsigned: UnsignedEvent {
                event_type: "Note".to_owned(),
                kind: 1,
                content: "hello".to_owned(),
                tags: Vec::new(),
                created_at: 100,
            },
            signer: "alice".to_owned(),
            id: "event-dispatch".to_owned(),
            signature: "sig".to_owned(),
        };
        let mut runtime = Runtime::new(
            FakeRelayHost::default(),
            FakeSignerHost::default(),
            FakeClock::default(),
            RecordingAudit::default(),
        );
        let mut storage = InMemoryStorage::default();
        let mut calls = 0;
        assert_eq!(
            runtime.dispatch_event(&request, &event, &mut storage, "event-dispatch", |_| {
                calls += 1;
                Ok(())
            },),
            Ok(true)
        );
        assert_eq!(
            runtime.dispatch_event(&request, &event, &mut storage, "event-dispatch", |_| {
                calls += 1;
                Ok(())
            },),
            Ok(false)
        );
        assert_eq!(calls, 1);
    }

    #[test]
    fn transactional_handler_dispatch_commits_or_rolls_back() {
        let request = SubscriptionRequest {
            event_type: "Note".to_owned(),
            relayset: None,
            kinds: vec![1],
            tag_equals: Vec::new(),
            cursor: None,
            author: None,
            since: None,
            limit: None,
        };
        let event = SignedEvent {
            unsigned: UnsignedEvent {
                event_type: "Note".to_owned(),
                kind: 1,
                content: "hello".to_owned(),
                tags: Vec::new(),
                created_at: 100,
            },
            signer: "alice".to_owned(),
            id: "event-transaction".to_owned(),
            signature: "sig".to_owned(),
        };
        let mut runtime = Runtime::new(
            FakeRelayHost::default(),
            FakeSignerHost::default(),
            FakeClock::default(),
            RecordingAudit::default(),
        );
        let mut claims = InMemoryStorage::default();
        let mut storage = InMemoryStorage::default();
        assert_eq!(
            runtime.dispatch_event_transactional(
                &request,
                &event,
                &mut claims,
                &mut storage,
                "event-transaction",
                |_, transaction| {
                    transaction.put("seen", "yes");
                    Ok(())
                },
            ),
            Ok(true)
        );
        assert_eq!(storage.values.get("seen").map(String::as_str), Some("yes"));

        let second = SignedEvent {
            id: "event-transaction-2".to_owned(),
            ..event
        };
        assert_eq!(
            runtime.dispatch_event_transactional(
                &request,
                &second,
                &mut claims,
                &mut storage,
                "event-transaction-2",
                |_, transaction| {
                    transaction.put("seen", "no");
                    Err(RuntimeError::Cancelled)
                },
            ),
            Err(RuntimeError::Cancelled)
        );
        assert_eq!(storage.values.get("seen").map(String::as_str), Some("yes"));
    }

    #[test]
    fn handler_cycle_composes_subscription_and_transaction_boundaries() {
        let source = "permissions {\n    read Note from public\n    relay public\n}\non Note { }";
        let program = nscript_syntax::parse_program(source).0;
        let (checked, diagnostics) = nscript_semantics::check(&program);
        assert!(diagnostics.is_empty(), "{diagnostics:?}");
        let checked = checked.expect("program checks");
        let mut runtime = Runtime::new(
            FakeRelayHost::default(),
            FakeSignerHost::default(),
            FakeClock::default(),
            RecordingAudit::default(),
        );
        let mut relay = FakeRelayHost::default();
        relay.queued_events.insert(
            1,
            vec![SignedEvent {
                unsigned: UnsignedEvent {
                    event_type: "Note".to_owned(),
                    kind: 1,
                    content: "hello".to_owned(),
                    tags: Vec::new(),
                    created_at: 100,
                },
                signer: "alice".to_owned(),
                id: "event-cycle".to_owned(),
                signature: "sig".to_owned(),
            }],
        );
        let mut claims = InMemoryStorage::default();
        let mut storage = InMemoryStorage::default();
        let dispatched = runtime
            .run_handler_cycle(
                &checked,
                Some("public"),
                &mut relay,
                &mut claims,
                &mut storage,
                |_, _, transaction| {
                    transaction.put("last", "event-cycle");
                    Ok(())
                },
            )
            .expect("empty cycle succeeds");
        assert_eq!(dispatched, 1);
        assert_eq!(
            storage.values.get("last").map(String::as_str),
            Some("event-cycle")
        );
        assert_eq!(relay.subscriptions.len(), 1);
        assert_eq!(relay.closed_subscriptions.len(), 1);

        relay.queued_events.insert(
            2,
            vec![SignedEvent {
                unsigned: UnsignedEvent {
                    event_type: "Note".to_owned(),
                    kind: 1,
                    content: "failure".to_owned(),
                    tags: Vec::new(),
                    created_at: 101,
                },
                signer: "alice".to_owned(),
                id: "event-cycle-failure".to_owned(),
                signature: "sig-failure".to_owned(),
            }],
        );
        let error = runtime.run_handler_cycle(
            &checked,
            Some("public"),
            &mut relay,
            &mut claims,
            &mut storage,
            |_, _, _| Err(RuntimeError::Cancelled),
        );
        assert_eq!(error, Err(RuntimeError::Cancelled));
        assert!(relay.closed_subscriptions.contains(&2));
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
    fn nip19_npub_round_trips_through_pubkey() {
        let mut host = Nip19FunctionHost;
        let encoded = "npub1qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqzqujme";
        let pubkey = host
            .call_function(
                "nip19",
                "pubkey",
                &[FunctionValue::Npub(encoded.to_owned())],
            )
            .expect("decode npub");
        let round_trip = host
            .call_function("nip19", "npub_encode", &[pubkey])
            .expect("encode npub");
        assert_eq!(round_trip, FunctionValue::Npub(encoded.to_owned()));
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
    fn nip37_lowers_stored_drafts() {
        let mut runtime = Runtime::new(
            FakeRelayHost::default(),
            FakeSignerHost::default(),
            FakeClock::default(),
            RecordingAudit::default(),
        );
        let mut host = FakeOperationHost::default();
        let result = runtime
            .invoke_authorized_operation(
                &OperationPolicy::default().allow("nip37", "save_draft"),
                &mut host,
                "nip37",
                "save_draft",
                &[OperationValue::Record {
                    name: "Draft".to_owned(),
                    fields: vec![
                        (
                            "identifier".to_owned(),
                            OperationValue::Text("release-notes".to_owned()),
                        ),
                        (
                            "content".to_owned(),
                            OperationValue::Text("Work in progress".to_owned()),
                        ),
                    ],
                }],
            )
            .expect("draft host available");
        assert!(matches!(result, OperationValue::PublishReport(report) if report.accepted()));
    }

    #[test]
    fn nip38_lowers_user_status_updates() {
        let mut runtime = Runtime::new(
            FakeRelayHost::default(),
            FakeSignerHost::default(),
            FakeClock::default(),
            RecordingAudit::default(),
        );
        let mut host = FakeOperationHost::default();
        let result = runtime
            .invoke_authorized_operation(
                &OperationPolicy::default().allow("nip38", "publish_status"),
                &mut host,
                "nip38",
                "publish_status",
                &[OperationValue::Record {
                    name: "UserStatus".to_owned(),
                    fields: vec![
                        (
                            "status".to_owned(),
                            OperationValue::Text("music".to_owned()),
                        ),
                        (
                            "content".to_owned(),
                            OperationValue::Text("Listening to Nostr".to_owned()),
                        ),
                    ],
                }],
            )
            .expect("status host available");
        assert!(matches!(result, OperationValue::PublishReport(report) if report.accepted()));
    }

    #[test]
    fn nip42_authenticates_secure_relays() {
        let mut runtime = Runtime::new(
            FakeRelayHost::default(),
            FakeSignerHost::default(),
            FakeClock::default(),
            RecordingAudit::default(),
        );
        let mut host = FakeOperationHost::default();
        let result = runtime
            .invoke_authorized_operation(
                &OperationPolicy::default().allow("nip42", "authenticate"),
                &mut host,
                "nip42",
                "authenticate",
                &[OperationValue::Text("wss://relay.example".to_owned())],
            )
            .expect("relay auth host available");
        assert!(matches!(
            result,
            OperationValue::AuthenticatedRelay(AuthenticatedRelay { relay })
                if relay == "wss://relay.example"
        ));
    }

    #[test]
    fn nip45_returns_event_counts_without_materializing_events() {
        let mut runtime = Runtime::new(
            FakeRelayHost::default(),
            FakeSignerHost::default(),
            FakeClock::default(),
            RecordingAudit::default(),
        );
        let mut host = FakeOperationHost::default();
        let result = runtime
            .invoke_authorized_operation(
                &OperationPolicy::default().allow("nip45", "count_events"),
                &mut host,
                "nip45",
                "count_events",
                &[OperationValue::Text("kind:1 since:24h".to_owned())],
            )
            .expect("count host available");
        assert_eq!(result, OperationValue::Integer(0));
    }

    #[test]
    fn nip50_lowers_search_queries_to_relay_requests() {
        let mut runtime = Runtime::new(
            FakeRelayHost::default(),
            FakeSignerHost::default(),
            FakeClock::default(),
            RecordingAudit::default(),
        );
        let mut host = FakeOperationHost::default();
        let result = runtime
            .invoke_authorized_operation(
                &OperationPolicy::default().allow("nip50", "search_events"),
                &mut host,
                "nip50",
                "search_events",
                &[OperationValue::Record {
                    name: "SearchRequest".to_owned(),
                    fields: vec![(
                        "query".to_owned(),
                        OperationValue::Text("nostr scripting".to_owned()),
                    )],
                }],
            )
            .expect("search host available");
        assert_eq!(
            result,
            OperationValue::SearchResults(SearchResults {
                query: "nostr scripting".to_owned(),
                count: 0,
            })
        );
    }

    #[test]
    fn nip53_lowers_addressable_live_events() {
        let mut runtime = Runtime::new(
            FakeRelayHost::default(),
            FakeSignerHost::default(),
            FakeClock::default(),
            RecordingAudit::default(),
        );
        let mut host = FakeOperationHost::default();
        let result = runtime
            .invoke_authorized_operation(
                &OperationPolicy::default().allow("nip53", "publish_live_event"),
                &mut host,
                "nip53",
                "publish_live_event",
                &[OperationValue::Record {
                    name: "LiveEvent".to_owned(),
                    fields: vec![
                        (
                            "identifier".to_owned(),
                            OperationValue::Text("weekly-space".to_owned()),
                        ),
                        (
                            "title".to_owned(),
                            OperationValue::Text("Nostr Builders".to_owned()),
                        ),
                        (
                            "summary".to_owned(),
                            OperationValue::Text("A live discussion".to_owned()),
                        ),
                    ],
                }],
            )
            .expect("live event host available");
        assert!(matches!(result, OperationValue::PublishReport(report) if report.accepted()));
    }

    #[test]
    fn nip56_lowers_structured_reports() {
        let mut runtime = Runtime::new(
            FakeRelayHost::default(),
            FakeSignerHost::default(),
            FakeClock::default(),
            RecordingAudit::default(),
        );
        let mut host = FakeOperationHost::default();
        let result = runtime
            .invoke_authorized_operation(
                &OperationPolicy::default().allow("nip56", "publish_report"),
                &mut host,
                "nip56",
                "publish_report",
                &[OperationValue::Record {
                    name: "Report".to_owned(),
                    fields: vec![
                        (
                            "target".to_owned(),
                            OperationValue::Text("event-to-report".to_owned()),
                        ),
                        (
                            "category".to_owned(),
                            OperationValue::Text("spam".to_owned()),
                        ),
                        (
                            "content".to_owned(),
                            OperationValue::Text("Promotional flood".to_owned()),
                        ),
                    ],
                }],
            )
            .expect("report host available");
        assert!(matches!(result, OperationValue::PublishReport(report) if report.accepted()));
    }

    #[test]
    fn nip58_lowers_badge_definitions() {
        let mut runtime = Runtime::new(
            FakeRelayHost::default(),
            FakeSignerHost::default(),
            FakeClock::default(),
            RecordingAudit::default(),
        );
        let mut host = FakeOperationHost::default();
        let result = runtime
            .invoke_authorized_operation(
                &OperationPolicy::default().allow("nip58", "publish_badge"),
                &mut host,
                "nip58",
                "publish_badge",
                &[OperationValue::Record {
                    name: "Badge".to_owned(),
                    fields: vec![
                        (
                            "identifier".to_owned(),
                            OperationValue::Text("contributor".to_owned()),
                        ),
                        (
                            "name".to_owned(),
                            OperationValue::Text("Contributor".to_owned()),
                        ),
                        (
                            "description".to_owned(),
                            OperationValue::Text("Participated in the project".to_owned()),
                        ),
                    ],
                }],
            )
            .expect("badge host available");
        assert!(matches!(result, OperationValue::PublishReport(report) if report.accepted()));
    }

    #[test]
    fn nip68_lowers_image_events() {
        let mut runtime = Runtime::new(
            FakeRelayHost::default(),
            FakeSignerHost::default(),
            FakeClock::default(),
            RecordingAudit::default(),
        );
        let mut host = FakeOperationHost::default();
        let result = runtime
            .invoke_authorized_operation(
                &OperationPolicy::default().allow("nip68", "publish_image"),
                &mut host,
                "nip68",
                "publish_image",
                &[OperationValue::Record {
                    name: "ImageEvent".to_owned(),
                    fields: vec![
                        (
                            "url".to_owned(),
                            OperationValue::Text("https://cdn.example/image.jpg".to_owned()),
                        ),
                        (
                            "caption".to_owned(),
                            OperationValue::Text("A Nostr image".to_owned()),
                        ),
                    ],
                }],
            )
            .expect("image host available");
        assert!(matches!(result, OperationValue::PublishReport(report) if report.accepted()));
    }

    #[test]
    fn nip71_lowers_video_events() {
        let mut runtime = Runtime::new(
            FakeRelayHost::default(),
            FakeSignerHost::default(),
            FakeClock::default(),
            RecordingAudit::default(),
        );
        let mut host = FakeOperationHost::default();
        let result = runtime
            .invoke_authorized_operation(
                &OperationPolicy::default().allow("nip71", "publish_video"),
                &mut host,
                "nip71",
                "publish_video",
                &[OperationValue::Record {
                    name: "VideoEvent".to_owned(),
                    fields: vec![
                        (
                            "url".to_owned(),
                            OperationValue::Text("https://cdn.example/video.mp4".to_owned()),
                        ),
                        (
                            "caption".to_owned(),
                            OperationValue::Text("A Nostr video".to_owned()),
                        ),
                    ],
                }],
            )
            .expect("video host available");
        assert!(matches!(result, OperationValue::PublishReport(report) if report.accepted()));
    }

    #[test]
    fn nip77_lowers_negentropy_sync_requests() {
        let mut runtime = Runtime::new(
            FakeRelayHost::default(),
            FakeSignerHost::default(),
            FakeClock::default(),
            RecordingAudit::default(),
        );
        let mut host = FakeOperationHost::default();
        let result = runtime
            .invoke_authorized_operation(
                &OperationPolicy::default().allow("nip77", "synchronize"),
                &mut host,
                "nip77",
                "synchronize",
                &[OperationValue::Record {
                    name: "SyncRequest".to_owned(),
                    fields: vec![
                        (
                            "relay".to_owned(),
                            OperationValue::Text("wss://relay.example".to_owned()),
                        ),
                        (
                            "cursor".to_owned(),
                            OperationValue::Text("local-cursor-1".to_owned()),
                        ),
                    ],
                }],
            )
            .expect("sync host available");
        assert_eq!(
            result,
            OperationValue::SyncResult(SyncResult {
                relay: "wss://relay.example".to_owned(),
                added: 0,
                removed: 0,
            })
        );
    }

    #[test]
    fn nip84_lowers_highlights_with_sources() {
        let mut runtime = Runtime::new(
            FakeRelayHost::default(),
            FakeSignerHost::default(),
            FakeClock::default(),
            RecordingAudit::default(),
        );
        let mut host = FakeOperationHost::default();
        let result = runtime
            .invoke_authorized_operation(
                &OperationPolicy::default().allow("nip84", "publish_highlight"),
                &mut host,
                "nip84",
                "publish_highlight",
                &[OperationValue::Record {
                    name: "Highlight".to_owned(),
                    fields: vec![
                        (
                            "source".to_owned(),
                            OperationValue::Text("https://example.com/article".to_owned()),
                        ),
                        (
                            "content".to_owned(),
                            OperationValue::Text("A useful passage".to_owned()),
                        ),
                    ],
                }],
            )
            .expect("highlight host available");
        assert!(matches!(result, OperationValue::PublishReport(report) if report.accepted()));
    }

    #[test]
    fn nip85_lowers_trusted_assertions() {
        let mut runtime = Runtime::new(
            FakeRelayHost::default(),
            FakeSignerHost::default(),
            FakeClock::default(),
            RecordingAudit::default(),
        );
        let mut host = FakeOperationHost::default();
        let result = runtime
            .invoke_authorized_operation(
                &OperationPolicy::default().allow("nip85", "publish_assertion"),
                &mut host,
                "nip85",
                "publish_assertion",
                &[OperationValue::Record {
                    name: "Assertion".to_owned(),
                    fields: vec![
                        (
                            "subject".to_owned(),
                            OperationValue::Text("npub1subject".to_owned()),
                        ),
                        (
                            "kind".to_owned(),
                            OperationValue::Text("reputation".to_owned()),
                        ),
                        (
                            "value".to_owned(),
                            OperationValue::Text("trusted".to_owned()),
                        ),
                    ],
                }],
            )
            .expect("assertion host available");
        assert!(matches!(result, OperationValue::PublishReport(report) if report.accepted()));
    }

    #[test]
    fn nip86_lowers_relay_admin_requests() {
        let mut runtime = Runtime::new(
            FakeRelayHost::default(),
            FakeSignerHost::default(),
            FakeClock::default(),
            RecordingAudit::default(),
        );
        let mut host = FakeOperationHost::default();
        let result = runtime
            .invoke_authorized_operation(
                &OperationPolicy::default().allow("nip86", "manage_relay"),
                &mut host,
                "nip86",
                "manage_relay",
                &[OperationValue::Record {
                    name: "RelayAdminRequest".to_owned(),
                    fields: vec![
                        (
                            "relay".to_owned(),
                            OperationValue::Text("wss://relay.example".to_owned()),
                        ),
                        (
                            "action".to_owned(),
                            OperationValue::Text("allow".to_owned()),
                        ),
                        (
                            "subject".to_owned(),
                            OperationValue::Text("npub1operator".to_owned()),
                        ),
                    ],
                }],
            )
            .expect("relay admin host available");
        assert!(matches!(result, OperationValue::PublishReport(report) if report.accepted()));
    }

    #[test]
    fn nip89_lowers_application_handlers() {
        let mut runtime = Runtime::new(
            FakeRelayHost::default(),
            FakeSignerHost::default(),
            FakeClock::default(),
            RecordingAudit::default(),
        );
        let mut host = FakeOperationHost::default();
        let result = runtime
            .invoke_authorized_operation(
                &OperationPolicy::default().allow("nip89", "publish_handler"),
                &mut host,
                "nip89",
                "publish_handler",
                &[OperationValue::Record {
                    name: "AppHandler".to_owned(),
                    fields: vec![
                        ("kind".to_owned(), OperationValue::Text("1".to_owned())),
                        (
                            "app".to_owned(),
                            OperationValue::Text("nscript-reader".to_owned()),
                        ),
                        (
                            "endpoint".to_owned(),
                            OperationValue::Text("https://apps.example/nostr".to_owned()),
                        ),
                    ],
                }],
            )
            .expect("handler host available");
        assert!(matches!(result, OperationValue::PublishReport(report) if report.accepted()));
    }

    #[test]
    fn nip94_lowers_file_metadata() {
        let mut runtime = Runtime::new(
            FakeRelayHost::default(),
            FakeSignerHost::default(),
            FakeClock::default(),
            RecordingAudit::default(),
        );
        let mut host = FakeOperationHost::default();
        let result = runtime
            .invoke_authorized_operation(
                &OperationPolicy::default().allow("nip94", "publish_file_metadata"),
                &mut host,
                "nip94",
                "publish_file_metadata",
                &[OperationValue::Record {
                    name: "FileMetadata".to_owned(),
                    fields: vec![
                        (
                            "url".to_owned(),
                            OperationValue::Text("https://cdn.example/file.jpg".to_owned()),
                        ),
                        (
                            "mime".to_owned(),
                            OperationValue::Text("image/jpeg".to_owned()),
                        ),
                        (
                            "hash".to_owned(),
                            OperationValue::Text("sha256:abc123".to_owned()),
                        ),
                    ],
                }],
            )
            .expect("file metadata host available");
        assert!(matches!(result, OperationValue::PublishReport(report) if report.accepted()));
    }

    #[test]
    fn nipb7_lowers_content_addressed_blob_uploads() {
        let mut runtime = Runtime::new(
            FakeRelayHost::default(),
            FakeSignerHost::default(),
            FakeClock::default(),
            RecordingAudit::default(),
        );
        let mut host = FakeOperationHost::default();
        let result = runtime
            .invoke_authorized_operation(
                &OperationPolicy::default().allow("nipb7", "upload_blob"),
                &mut host,
                "nipb7",
                "upload_blob",
                &[OperationValue::Record {
                    name: "BlobUpload".to_owned(),
                    fields: vec![
                        (
                            "url".to_owned(),
                            OperationValue::Text("https://blossom.example/upload".to_owned()),
                        ),
                        (
                            "hash".to_owned(),
                            OperationValue::Text("sha256:abc123".to_owned()),
                        ),
                        ("size".to_owned(), OperationValue::Integer(1024)),
                    ],
                }],
            )
            .expect("blob host available");
        assert_eq!(
            result,
            OperationValue::BlobStored(BlobStored {
                url: "https://blossom.example/upload".to_owned(),
                hash: "sha256:abc123".to_owned(),
            })
        );
    }

    #[test]
    fn nip98_lowers_authenticated_http_requests() {
        let mut runtime = Runtime::new(
            FakeRelayHost::default(),
            FakeSignerHost::default(),
            FakeClock::default(),
            RecordingAudit::default(),
        );
        let mut host = FakeOperationHost::default();
        let result = runtime
            .invoke_authorized_operation(
                &OperationPolicy::default().allow("nip98", "authenticate_http"),
                &mut host,
                "nip98",
                "authenticate_http",
                &[OperationValue::Record {
                    name: "HttpAuthRequest".to_owned(),
                    fields: vec![
                        (
                            "url".to_owned(),
                            OperationValue::Text("https://api.example/resource".to_owned()),
                        ),
                        ("method".to_owned(), OperationValue::Text("GET".to_owned())),
                    ],
                }],
            )
            .expect("HTTP auth host available");
        assert_eq!(
            result,
            OperationValue::AuthenticatedRequest(AuthenticatedRequest {
                url: "https://api.example/resource".to_owned(),
                method: "GET".to_owned(),
            })
        );
    }

    #[test]
    fn nip47_lowers_wallet_payments_with_positive_amounts() {
        let mut runtime = Runtime::new(
            FakeRelayHost::default(),
            FakeSignerHost::default(),
            FakeClock::default(),
            RecordingAudit::default(),
        );
        let mut host = FakeOperationHost::default();
        let result = runtime
            .invoke_authorized_operation(
                &OperationPolicy::default().allow("nip47", "pay_invoice"),
                &mut host,
                "nip47",
                "pay_invoice",
                &[OperationValue::Record {
                    name: "WalletPayment".to_owned(),
                    fields: vec![
                        (
                            "invoice".to_owned(),
                            OperationValue::Text("lnbc1example".to_owned()),
                        ),
                        ("amount".to_owned(), OperationValue::Integer(1000)),
                    ],
                }],
            )
            .expect("wallet host available");
        assert_eq!(
            result,
            OperationValue::PaymentResult(PaymentResult {
                invoice: "lnbc1example".to_owned(),
                amount: 1000,
                settled: true,
            })
        );
    }

    #[test]
    fn nip46_provisions_remote_signer_sessions_without_keys() {
        let mut runtime = Runtime::new(
            FakeRelayHost::default(),
            FakeSignerHost::default(),
            FakeClock::default(),
            RecordingAudit::default(),
        );
        let mut host = FakeOperationHost::default();
        let result = runtime
            .invoke_authorized_operation(
                &OperationPolicy::default().allow("nip46", "nip46"),
                &mut host,
                "nip46",
                "nip46",
                &[],
            )
            .expect("signer provisioning host available");
        assert_eq!(
            result,
            OperationValue::SignerSession(SignerSession {
                provider: "nip46://remote-signer".to_owned(),
            })
        );
    }

    #[test]
    fn dedicated_signer_provision_host_is_audited() {
        let mut runtime = Runtime::new(
            FakeRelayHost::default(),
            FakeSignerHost::default(),
            FakeClock::default(),
            RecordingAudit::default(),
        );
        let mut signer = FakeSignerHost::default();
        let session = runtime
            .provision_signer(&mut signer, "bunker://alice")
            .expect("provisioning should succeed");
        assert_eq!(
            session,
            SignerSession {
                provider: "bunker://alice".to_owned()
            }
        );
        assert_eq!(runtime.audit.entries[0].operation, "provision_signer");
    }

    #[test]
    fn dedicated_relay_session_host_is_audited() {
        let mut runtime = Runtime::new(
            FakeRelayHost::default(),
            FakeSignerHost::default(),
            FakeClock::default(),
            RecordingAudit::default(),
        );
        let mut relay = FakeRelayHost::default();
        let session = runtime
            .authenticate_relay(&mut relay, "wss://relay.example")
            .expect("relay authentication should succeed");
        assert_eq!(session.relay, "wss://relay.example");
        assert_eq!(runtime.audit.entries[0].operation, "authenticate_relay");
    }

    #[test]
    fn dedicated_http_host_enforces_allowlist_and_audits_requests() {
        let mut runtime = Runtime::new(
            FakeRelayHost::default(),
            FakeSignerHost::default(),
            FakeClock::default(),
            RecordingAudit::default(),
        );
        let mut http = FakeHttpHost {
            allowlisted_hosts: BTreeSet::from(["api.example".to_owned()]),
            requests: Vec::new(),
            redirects: BTreeMap::new(),
        };
        let response = runtime
            .execute_http(
                &mut http,
                &AuthenticatedRequest {
                    url: "https://api.example/resource".to_owned(),
                    method: "GET".to_owned(),
                },
            )
            .expect("allowlisted request should succeed");
        assert_eq!(response.status, 200);
        assert_eq!(http.requests.len(), 1);
        assert_eq!(runtime.audit.entries[0].operation, "http_request");

        http.redirects.insert(
            "https://api.example/redirect".to_owned(),
            "https://other.example/resource".to_owned(),
        );
        assert!(matches!(
            runtime.execute_http(
                &mut http,
                &AuthenticatedRequest {
                    url: "https://api.example/redirect".to_owned(),
                    method: "GET".to_owned(),
                },
            ),
            Err(RuntimeError::CapabilityDenied { capability })
                if capability == "http:other.example"
        ));
    }

    #[test]
    fn payment_policy_rejects_amounts_over_budget_before_host_call() {
        let mut runtime = Runtime::new(
            FakeRelayHost::default(),
            FakeSignerHost::default(),
            FakeClock::default(),
            RecordingAudit::default(),
        );
        let mut host = FakeOperationHost::default();
        let policy = OperationPolicy::default()
            .allow("nip47", "pay_invoice")
            .allow_payment_up_to(500);
        let result = runtime.invoke_authorized_operation(
            &policy,
            &mut host,
            "nip47",
            "pay_invoice",
            &[OperationValue::WalletPayment(WalletPayment {
                invoice: "lnbc1example".to_owned(),
                amount: 1000,
            })],
        );
        assert_eq!(
            result,
            Err(RuntimeError::PaymentLimitExceeded {
                amount: 1000,
                limit: 500,
            })
        );
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
