//! The `NScript` compiler front end compiled to WebAssembly.
//!
//! The crate exposes a small, dependency-free JSON-in/JSON-out ABI over linear
//! memory so a browser (or Node) host can drive the same compiler paths the
//! CLI exposes without a server. Built-in modules are embedded in the
//! `nscript-modules` resolver, so analysis works fully offline.
//!
//! ABI (all pointers are offsets into the exported `memory`):
//!
//! - `nscript_alloc(len) -> ptr`: allocate `len` zeroed bytes.
//! - `nscript_dealloc(ptr, len)`: release a buffer from `nscript_alloc`.
//! - `nscript_handle(ptr, len) -> ptr`: process a JSON request, returning a
//!   NUL-terminated UTF-8 response buffer (release with `nscript_free`).
//! - `nscript_free(ptr, len)`: release a response buffer; `len` is the byte
//!   length read by the caller including the trailing NUL.
//! - `nscript_abi() -> u32`: the ABI version.
//!
//! Requests and responses are JSON. A response is `{"ok":true,"result":…}` or
//! `{"ok":false,"error":{"message":…}}`. Supported operations: `version`,
//! `analyze`, `inspect`, `ir`, `compile`, and `run`.

use std::collections::BTreeMap;
use std::fmt::Write as _;

use nscript_runtime::{
    FakeClock, FakeLogHost, FakeOperationHost, FakeRelayHost, FakeSignerHost, FakeTimerHost,
    InMemoryStorage, OperationPolicy, RecordingAudit, Runtime, SignedEvent, UnsignedEvent, eval,
};
use nscript_semantics::{CheckedProgram, check, footprint, infer};
use nscript_syntax::{Diagnostic, Program};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};

const ABI_VERSION: u32 = 1;

/// Allocates `len` zeroed bytes and returns their address.
///
/// # Panics
///
/// Panics if a wasm pointer cannot be represented in 32 bits, which cannot
/// occur on the `wasm32` target this crate is built for.
#[unsafe(no_mangle)]
pub extern "C" fn nscript_alloc(len: u32) -> u32 {
    let boxed = vec![0_u8; len as usize].into_boxed_slice();
    let raw = Box::into_raw(boxed).cast::<u8>() as usize;
    u32::try_from(raw).expect("a wasm pointer fits u32")
}

/// Releases a request buffer.
///
/// # Safety
///
/// `ptr` must have come from [`nscript_alloc`] and `len` must match the value
/// passed there.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn nscript_dealloc(ptr: u32, len: u32) {
    if ptr == 0 {
        return;
    }
    // SAFETY: `ptr` and `len` come from a matching `nscript_alloc` call, so the
    // slice reconstructs the exact `Box<[u8]>` that call created.
    let boxed = unsafe {
        Box::from_raw(std::ptr::slice_from_raw_parts_mut(
            ptr as *mut u8,
            len as usize,
        ))
    };
    drop(boxed);
}

/// Processes one JSON request and returns a NUL-terminated JSON response.
///
/// # Panics
///
/// Panics if a wasm pointer cannot be represented in 32 bits, which cannot
/// occur on the `wasm32` target this crate is built for.
#[unsafe(no_mangle)]
pub extern "C" fn nscript_handle(ptr: u32, len: u32) -> u32 {
    let request = unsafe { read_request(ptr, len) };
    let response = process_request(&request);
    let mut bytes = response.into_bytes();
    bytes.push(0);
    let boxed = bytes.into_boxed_slice();
    let raw = Box::into_raw(boxed).cast::<u8>() as usize;
    u32::try_from(raw).expect("a wasm pointer fits u32")
}

/// Releases a response buffer.
///
/// # Safety
///
/// `ptr` must have come from [`nscript_handle`] and `len` must be the byte
/// length read by the caller including the trailing NUL.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn nscript_free(ptr: u32, len: u32) {
    if ptr == 0 {
        return;
    }
    // SAFETY: `ptr` and `len` come from a `nscript_handle` response whose byte
    // length (including the trailing NUL) is `len`.
    let boxed = unsafe {
        Box::from_raw(std::ptr::slice_from_raw_parts_mut(
            ptr as *mut u8,
            len as usize,
        ))
    };
    drop(boxed);
}

/// Returns the ABI version this artifact implements.
#[unsafe(no_mangle)]
pub extern "C" fn nscript_abi() -> u32 {
    ABI_VERSION
}

unsafe fn read_request(ptr: u32, len: u32) -> String {
    // SAFETY: `ptr` and `len` reference `len` readable bytes written by the
    // caller into a `nscript_alloc` buffer.
    let slice = unsafe { std::slice::from_raw_parts(ptr as *const u8, len as usize) };
    String::from_utf8_lossy(slice).into_owned()
}

struct ModuleSource {
    name: String,
    source: String,
}

#[must_use]
fn module_sources(request: &Value) -> Vec<ModuleSource> {
    request
        .get("modules")
        .and_then(Value::as_array)
        .map(|items| {
            items
                .iter()
                .filter_map(|item| {
                    let name = item.get("name").and_then(Value::as_str)?;
                    let source = item.get("source").and_then(Value::as_str)?;
                    Some(ModuleSource {
                        name: name.to_owned(),
                        source: source.to_owned(),
                    })
                })
                .collect()
        })
        .unwrap_or_default()
}

#[must_use]
fn process_request(request: &str) -> String {
    let Ok(value) = serde_json::from_str::<Value>(request) else {
        return error_response("invalid JSON request");
    };
    let Some(op) = value.get("op").and_then(Value::as_str) else {
        return error_response("request is missing `op`");
    };
    let source = value.get("source").and_then(Value::as_str).unwrap_or("");
    let modules = module_sources(&value);
    match op {
        "version" => ok(json!({ "abi": ABI_VERSION })),
        "analyze" => handle_analyze(source, &modules),
        "footprint" => handle_footprint(source, &modules),
        "inspect" => handle_inspect(source, &modules),
        "ir" => handle_ir(source, &modules),
        "compile" => handle_compile(source, &modules),
        "run" => handle_run(source, &modules),
        "symbols" => handle_symbols(source, &modules),
        "completions" => handle_completions(source, &modules, &value),
        "hover" => handle_hover(source, &modules, &value),
        "test_event" => handle_test_event(source, &modules, &value),
        "manifest" => handle_manifest(source, &modules, &value),
        "lock" => handle_lock(source, &modules),
        other => error_response(&format!("unknown operation `{other}`")),
    }
}

#[must_use]
#[allow(clippy::needless_pass_by_value)]
fn ok(result: Value) -> String {
    json!({ "ok": true, "result": result }).to_string()
}

#[must_use]
fn error_response(message: &str) -> String {
    json!({ "ok": false, "error": { "message": message } }).to_string()
}

struct Loaded {
    program: Program,
    graph: nscript_modules::ResolvedModuleGraph,
    diagnostics: Vec<Diagnostic>,
}

#[must_use]
fn load(source: &str, modules: &[ModuleSource]) -> Loaded {
    let module_refs = modules
        .iter()
        .map(|module| (module.name.as_str(), module.source.as_str()))
        .collect::<Vec<_>>();
    let analysis = nscript_lang::analyze(source, &module_refs);
    Loaded {
        program: analysis.program,
        graph: analysis.graph,
        diagnostics: analysis.diagnostics,
    }
}

#[must_use]
fn module_refs(modules: &[ModuleSource]) -> Vec<(&str, &str)> {
    modules
        .iter()
        .map(|module| (module.name.as_str(), module.source.as_str()))
        .collect()
}

#[must_use]
fn diagnostic_json(diagnostic: &Diagnostic) -> Value {
    json!({
        "code": diagnostic.code,
        "severity": "error",
        "message": diagnostic.message,
        "line": diagnostic.span.line,
        "column": diagnostic.span.column,
        "start": diagnostic.span.start,
        "end": diagnostic.span.end,
    })
}

#[must_use]
fn diagnostics_json(diagnostics: &[Diagnostic]) -> Vec<Value> {
    diagnostics.iter().map(diagnostic_json).collect()
}

#[must_use]
fn handle_analyze(source: &str, modules: &[ModuleSource]) -> String {
    let loaded = load(source, modules);
    ok(json!({ "diagnostics": diagnostics_json(&loaded.diagnostics) }))
}

/// The capability footprint, computed even when the program still has
/// permission errors, so the Studio panel can show `requested` live.
#[must_use]
fn handle_footprint(source: &str, modules: &[ModuleSource]) -> String {
    let loaded = load(source, modules);
    let (inferred, typed_diagnostics) = infer(&loaded.program);
    let mut diagnostics = loaded.diagnostics.clone();
    diagnostics.extend(typed_diagnostics);
    diagnostics.sort_by_key(|diagnostic| (diagnostic.span.start, diagnostic.code));
    let footprint = footprint(&loaded.program, &inferred, &loaded.graph, &diagnostics);
    ok(json!({
        "diagnostics": diagnostics_json(&diagnostics),
        "footprint": footprint,
    }))
}

fn checked_program(source: &str, modules: &[ModuleSource]) -> Result<CheckedProgram, Vec<Value>> {
    let loaded = load(source, modules);
    if !loaded.diagnostics.is_empty() {
        return Err(diagnostics_json(&loaded.diagnostics));
    }
    let (checked, typed_diagnostics) = check(&loaded.program);
    if !typed_diagnostics.is_empty() {
        return Err(diagnostics_json(&typed_diagnostics));
    }
    checked.ok_or_else(Vec::new)
}

#[must_use]
#[allow(clippy::too_many_lines)]
fn handle_inspect(source: &str, modules: &[ModuleSource]) -> String {
    let loaded = load(source, modules);
    let (inferred, typed_diagnostics) = infer(&loaded.program);
    let mut diagnostics = loaded.diagnostics.clone();
    diagnostics.extend(typed_diagnostics);
    diagnostics.sort_by_key(|diagnostic| (diagnostic.span.start, diagnostic.code));
    let checked = diagnostics.is_empty();
    let manifest = if checked {
        json!({
            "profile": format!("{:?}", loaded.program.profile).to_lowercase(),
            "effects": inferred.effects.iter().map(|effect| format!("{effect:?}").to_lowercase()).collect::<Vec<_>>(),
            "operations": inferred.operation_calls.iter().map(|call| format!("{}.{}", call.module, call.operation)).collect::<Vec<_>>(),
            "publications": inferred.publications.len(),
            "publication_trace": inferred.publications.iter().map(|publication| json!({
                "steps": [
                    {"op": "create_event", "event": publication.event},
                    {"op": "sign_event", "signer": publication.signer},
                    {"op": "publish_event", "relayset": publication.relayset}
                ]
            })).collect::<Vec<_>>(),
            "schedules": inferred.schedules.len(),
            "handlers": inferred.handlers.iter().map(|handler| json!({
                "event": handler.event_type,
                "author": handler.author,
                "tags": handler.tag_equals,
                "filter_trace": {
                    "event": handler.event_type,
                    "author": handler.author,
                    "tags": handler.tag_equals
                }
            })).collect::<Vec<_>>(),
        })
    } else {
        Value::Null
    };
    let footprint = footprint(&loaded.program, &inferred, &loaded.graph, &diagnostics);
    ok(json!({
        "diagnostics": diagnostics_json(&diagnostics),
        "checked": checked,
        "manifest": manifest,
        "footprint": footprint,
    }))
}

#[must_use]
fn handle_ir(source: &str, modules: &[ModuleSource]) -> String {
    let checked = match checked_program(source, modules) {
        Ok(checked) => checked,
        Err(diagnostics) => {
            return ok(json!({ "diagnostics": diagnostics, "checked": false, "ir": null }));
        }
    };
    let loaded = load(source, modules);
    let ir = nscript_ir::lower(&loaded.program, &checked, &loaded.graph);
    ok(json!({ "diagnostics": [], "checked": true, "ir": ir }))
}

#[must_use]
fn handle_compile(source: &str, modules: &[ModuleSource]) -> String {
    let checked = match checked_program(source, modules) {
        Ok(checked) => checked,
        Err(diagnostics) => {
            return ok(json!({ "diagnostics": diagnostics, "checked": false, "wasm": null }));
        }
    };
    let loaded = load(source, modules);
    let ir = nscript_ir::lower(&loaded.program, &checked, &loaded.graph);
    let wasm = nscript_ir::emit_wasm(&ir);
    ok(json!({
        "diagnostics": [],
        "checked": true,
        "wasm": base64(&wasm),
        "bytes": wasm.len(),
    }))
}

#[must_use]
#[allow(clippy::too_many_lines)]
fn handle_run(source: &str, modules: &[ModuleSource]) -> String {
    let loaded = load(source, modules);
    if !loaded.diagnostics.is_empty() {
        return ok(json!({
            "diagnostics": diagnostics_json(&loaded.diagnostics),
            "executed": false,
            "trace": null,
        }));
    }
    let (checked, typed_diagnostics) = check(&loaded.program);
    if !typed_diagnostics.is_empty() {
        return ok(json!({
            "diagnostics": diagnostics_json(&typed_diagnostics),
            "executed": false,
            "trace": null,
        }));
    }
    let Some(checked) = checked else {
        return error_response("program did not type-check");
    };
    let relay = FakeRelayHost {
        relays: [("fake://public".to_owned(), true)].into_iter().collect(),
        published: Vec::new(),
        ..Default::default()
    };
    let signer = FakeSignerHost::default();
    let clock = FakeClock { now: 1_700_000_000 };
    let audit = RecordingAudit::default();
    let mut runtime = Runtime::new(relay, signer, clock, audit);
    let mut timers = FakeTimerHost::default();
    let timer_error = match runtime.schedule_program(&mut timers, &checked) {
        Ok(_) => None,
        Err(error) => Some(format!("{error:?}")),
    };
    let subscriptions =
        Runtime::<FakeRelayHost, FakeSignerHost, FakeClock, RecordingAudit>::handler_subscriptions(
            &checked,
            Some("public"),
        );
    let operation_policy = checked
        .operation_calls
        .iter()
        .fold(OperationPolicy::default(), |policy, call| {
            policy.allow(&call.module, &call.operation)
        });
    let mut operation_host = FakeOperationHost::default();
    let operation_values =
        match runtime.run_operations(&checked, &operation_policy, &mut operation_host) {
            Ok(values) => values
                .iter()
                .map(|value| format!("{value:?}"))
                .collect::<Vec<_>>(),
            Err(error) => {
                return ok(json!({
                    "diagnostics": [{
                        "code": "R1002",
                        "severity": "error",
                        "message": format!("{error:?}"),
                        "line": 0,
                        "column": 0,
                        "start": 0,
                        "end": 0,
                    }],
                    "executed": false,
                    "trace": null,
                }));
            }
        };
    let reports = match runtime.run(&loaded.program, &checked) {
        Ok(reports) => reports,
        Err(error) => {
            return ok(json!({
                "diagnostics": [{
                    "code": "R1001",
                    "severity": "error",
                    "message": format!("{error:?}"),
                    "line": 0,
                    "column": 0,
                    "start": 0,
                    "end": 0,
                }],
                "executed": false,
                "trace": null,
            }));
        }
    };
    let publications = reports
        .iter()
        .map(|report| {
            let accepted = report
                .outcomes
                .iter()
                .filter(|outcome| outcome.accepted)
                .count();
            json!({
                "outcomes": report.outcomes.iter().map(|outcome| json!({
                    "relay": outcome.relay,
                    "accepted": outcome.accepted,
                    "detail": outcome.detail,
                })).collect::<Vec<_>>(),
                "accepted": accepted,
                "total": report.outcomes.len(),
            })
        })
        .collect::<Vec<_>>();
    ok(json!({
        "diagnostics": [],
        "executed": true,
        "trace": {
            "timers": timers.schedules.iter().map(|timer| json!({
                "name": timer.name,
                "next_at": timer.next_at,
            })).collect::<Vec<_>>(),
            "subscriptions": subscriptions.iter().map(|subscription| subscription.event_type.clone()).collect::<Vec<_>>(),
            "operations": operation_values,
            "publications": publications,
            "timer_error": timer_error,
        },
    }))
}

#[must_use]
fn handle_symbols(source: &str, modules: &[ModuleSource]) -> String {
    let analysis = nscript_lang::analyze(source, &module_refs(modules));
    ok(json!({ "symbols": nscript_lang::symbols(&analysis) }))
}

#[must_use]
fn handle_completions(source: &str, modules: &[ModuleSource], request: &Value) -> String {
    let offset = request
        .get("offset")
        .and_then(Value::as_u64)
        .and_then(|offset| usize::try_from(offset).ok())
        .unwrap_or(0)
        .min(source.len());
    let analysis = nscript_lang::analyze(source, &module_refs(modules));
    ok(json!({ "completions": nscript_lang::completions(&analysis, offset) }))
}

#[must_use]
fn handle_hover(source: &str, modules: &[ModuleSource], request: &Value) -> String {
    let offset = request
        .get("offset")
        .and_then(Value::as_u64)
        .and_then(|offset| usize::try_from(offset).ok())
        .unwrap_or(0)
        .min(source.len());
    let analysis = nscript_lang::analyze(source, &module_refs(modules));
    ok(json!({ "hover": nscript_lang::hover(&analysis, offset) }))
}

/// Simulates a synthetic event through the evaluator, mirroring the CLI's
/// `test-event`: no host, relay, or key is touched.
#[must_use]
#[allow(clippy::too_many_lines)]
fn handle_test_event(source: &str, modules: &[ModuleSource], request: &Value) -> String {
    let loaded = load(source, modules);
    if !loaded.diagnostics.is_empty() {
        return ok(json!({
            "diagnostics": diagnostics_json(&loaded.diagnostics),
            "executed": false,
            "report": null,
        }));
    }
    let (checked, typed_diagnostics) = check(&loaded.program);
    if !typed_diagnostics.is_empty() {
        return ok(json!({
            "diagnostics": diagnostics_json(&typed_diagnostics),
            "executed": false,
            "report": null,
        }));
    }
    let Some(checked) = checked else {
        return error_response("program did not type-check");
    };
    let Some(event) = parse_test_event(request.get("event")) else {
        return error_response("test_event requires an `event` object");
    };
    let principal = request
        .get("principal")
        .and_then(Value::as_str)
        .map(str::to_owned);
    let mut relay = FakeRelayHost::default();
    let mut storage = InMemoryStorage::default();
    let mut logs = FakeLogHost::default();
    let mut operations = simulated_operations(&loaded.graph);
    match Runtime::<FakeRelayHost, FakeSignerHost, FakeClock, RecordingAudit>::simulate_event(
        &loaded.program,
        &checked,
        &mut relay,
        &mut storage,
        &mut logs,
        &mut operations,
        principal.as_deref(),
        &event,
    ) {
        Ok(report) => ok(json!({
            "diagnostics": [],
            "executed": true,
            "report": {
                "dispatched": report.dispatched,
                "subscriptions": report.subscriptions,
                "logs": report.logs.iter().map(|record| json!({
                    "level": record.level,
                    "message": record.message,
                })).collect::<Vec<_>>(),
                "operations": report.operations.iter().map(|call| json!({
                    "module": call.module,
                    "operation": call.operation,
                    "arguments": call.arguments.iter().map(|value| format!("{value:?}")).collect::<Vec<_>>(),
                    "simulated": call.simulated,
                })).collect::<Vec<_>>(),
                "failures": report.failures.iter().map(|failure| json!({
                    "handler": failure.handler,
                    "error": format!("{:?}", failure.error),
                })).collect::<Vec<_>>(),
                "storage": storage.values,
            },
        })),
        Err(error) => error_response(&format!("{error:?}")),
    }
}

fn simulated_operations(graph: &nscript_modules::ResolvedModuleGraph) -> eval::SimulatedOperations {
    let returns = graph
        .modules
        .iter()
        .flat_map(|(module, registered)| {
            registered
                .descriptor
                .operations
                .iter()
                .map(move |operation| {
                    (
                        (module.clone(), operation.name.clone()),
                        operation.return_type.clone(),
                    )
                })
        })
        .collect::<BTreeMap<_, _>>();
    eval::SimulatedOperations::new(returns)
}

fn parse_test_event(value: Option<&Value>) -> Option<SignedEvent> {
    let value = value?;
    let as_text = |key: &str, default: &str| {
        value
            .get(key)
            .and_then(Value::as_str)
            .unwrap_or(default)
            .to_owned()
    };
    let kind = value.get("kind").and_then(Value::as_u64).unwrap_or(1);
    let kind = u16::try_from(kind).ok()?;
    let tags = value
        .get("tags")
        .and_then(Value::as_array)
        .map(|array| {
            array
                .iter()
                .filter_map(|tag| {
                    let array = tag.as_array()?;
                    let name = array.first()?.as_str()?;
                    let value = array.get(1).and_then(Value::as_str).unwrap_or("");
                    Some((name.to_owned(), value.to_owned()))
                })
                .collect::<Vec<_>>()
        })
        .unwrap_or_default();
    Some(SignedEvent {
        unsigned: UnsignedEvent {
            event_type: as_text("event_type", "Note"),
            kind,
            content: as_text("content", ""),
            tags,
            created_at: value.get("created_at").and_then(Value::as_u64).unwrap_or(0),
        },
        signer: as_text("signer", "alice"),
        id: as_text("id", "test-event"),
        signature: as_text("signature", "sig"),
    })
}

/// Builds an npack-compatible manifest for the compiled artifact, mirroring the
/// CLI's `package manifest` but with no file system: the wasm artifact is
/// compiled in memory and its SHA-256 becomes the manifest hash.
#[must_use]
#[allow(clippy::too_many_lines)]
fn handle_manifest(source: &str, modules: &[ModuleSource], request: &Value) -> String {
    let Some(publisher) = request.get("publisher").and_then(Value::as_str) else {
        return error_response("manifest requires a `publisher`");
    };
    let name = request
        .get("name")
        .and_then(Value::as_str)
        .unwrap_or("script");
    let version = request
        .get("version")
        .and_then(Value::as_str)
        .unwrap_or("0.1.0");
    let artifact = request
        .get("artifact")
        .and_then(Value::as_str)
        .unwrap_or("script.wasm");
    let checked = match checked_program(source, modules) {
        Ok(checked) => checked,
        Err(diagnostics) => {
            return ok(json!({
                "diagnostics": diagnostics,
                "checked": false,
                "manifest": null,
            }));
        }
    };
    let loaded = load(source, modules);
    let ir = nscript_ir::lower(&loaded.program, &checked, &loaded.graph);
    let wasm = nscript_ir::emit_wasm(&ir);
    let digest = Sha256::digest(&wasm);
    let mut sha256 = String::with_capacity(64);
    for byte in digest {
        write!(&mut sha256, "{byte:02x}").expect("writing to a String cannot fail");
    }
    let dependencies = loaded
        .program
        .imports
        .iter()
        .map(|import| {
            format!(
                "{} {}",
                import.path,
                import.requirement.as_deref().unwrap_or("*")
            )
        })
        .collect::<Vec<_>>();
    let resolved_modules = loaded
        .graph
        .modules
        .values()
        .map(|module| {
            json!({
                "name": module.descriptor.id.name,
                "version": module.descriptor.id.version.to_string(),
                "sha256": nscript_modules::hash_hex(&module.descriptor.canonical_hash),
            })
        })
        .collect::<Vec<_>>();
    let manifest = json!({
        "publisher": publisher,
        "name": name,
        "version": version,
        "artifact": artifact,
        "sha256": sha256,
        "dependencies": dependencies,
        "conflicts": [],
        "artifact_event": Value::Null,
        "os": "any",
        "arch": "any",
        "format": "npk",
        "runtime_requires": ["nscript-runtime >=0.1"],
        "provides": ["nscript-program"],
        "post_install": [],
        "nscript": {
            "source": "script.ns",
            "lockfile": Value::Null,
            "resolved_modules": resolved_modules,
            "effects": checked.effects.iter().map(|effect| format!("{effect:?}").to_lowercase()).collect::<Vec<_>>(),
            "permissions_reviewed": true
        }
    });
    ok(json!({
        "diagnostics": [],
        "checked": true,
        "manifest": manifest,
        "wasm": base64(&wasm),
        "bytes": wasm.len(),
        "sha256": sha256,
    }))
}

/// Emits the deterministic lockfile for a source, mirroring the CLI's
/// `package lock`.
#[must_use]
fn handle_lock(source: &str, modules: &[ModuleSource]) -> String {
    let loaded = load(source, modules);
    if !loaded.diagnostics.is_empty() {
        return ok(json!({
            "diagnostics": diagnostics_json(&loaded.diagnostics),
            "checked": false,
            "lockfile": null,
        }));
    }
    let lock_modules = loaded
        .graph
        .modules
        .values()
        .map(|module| {
            json!({
                "name": module.descriptor.id.name,
                "version": module.descriptor.id.version.to_string(),
                "sha256": nscript_modules::hash_hex(&module.descriptor.canonical_hash),
                "dependencies": module.descriptor.dependencies.iter().map(|dependency| {
                    json!({
                        "name": dependency.name,
                        "requirement": dependency.requirement.to_string(),
                    })
                }).collect::<Vec<_>>(),
            })
        })
        .collect::<Vec<_>>();
    let roots = loaded
        .program
        .imports
        .iter()
        .map(|import| {
            json!({
                "name": import.path,
                "requirement": import.requirement.as_deref().unwrap_or("*"),
            })
        })
        .collect::<Vec<_>>();
    let lockfile = json!({
        "lockfile_version": 1,
        "source": "script.ns",
        "roots": roots,
        "modules": lock_modules,
    });
    ok(json!({ "diagnostics": [], "checked": true, "lockfile": lockfile }))
}

#[must_use]
fn base64(bytes: &[u8]) -> String {
    const ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut output = String::with_capacity(bytes.len().div_ceil(3) * 4);
    for chunk in bytes.chunks(3) {
        let first = usize::from(chunk[0]) << 16;
        let second = chunk.get(1).map_or(0, |byte| usize::from(*byte) << 8);
        let third = chunk.get(2).map_or(0, |byte| usize::from(*byte));
        let combined = first | second | third;
        output.push(ALPHABET[(combined >> 18) & 63] as char);
        output.push(ALPHABET[(combined >> 12) & 63] as char);
        output.push(if chunk.len() > 1 {
            ALPHABET[(combined >> 6) & 63] as char
        } else {
            '='
        });
        output.push(if chunk.len() > 2 {
            ALPHABET[combined & 63] as char
        } else {
            '='
        });
    }
    output
}

#[cfg(test)]
mod tests {
    use super::process_request;

    fn result(request: &str) -> serde_json::Value {
        serde_json::from_str(&process_request(request)).expect("response is JSON")
    }

    #[test]
    fn reports_abi_version() {
        assert_eq!(result(r#"{"op":"version"}"#)["result"]["abi"], 1);
    }

    #[test]
    fn rejects_malformed_requests() {
        let response = serde_json::from_str::<serde_json::Value>(&process_request("not json"))
            .expect("still JSON");
        assert!(!response["ok"].as_bool().unwrap());
    }

    #[test]
    fn analyze_accepts_the_default_publish_fixture() {
        let source = include_str!("../../../conformance/valid/default-publish.ns");
        let response = result(&format!(
            r#"{{"op":"analyze","source":{} }}"#,
            serde_json::to_string(source).expect("source is a string")
        ));
        assert_eq!(
            response["result"]["diagnostics"].as_array().unwrap().len(),
            0
        );
    }

    #[test]
    fn analyze_reports_declared_invalid_codes() {
        let source = include_str!("../../../conformance/invalid/missing-default-signer.ns");
        let response = result(&format!(
            r#"{{"op":"analyze","source":{} }}"#,
            serde_json::to_string(source).expect("source is a string")
        ));
        let codes = response["result"]["diagnostics"]
            .as_array()
            .unwrap()
            .iter()
            .filter_map(|diagnostic| diagnostic["code"].as_str())
            .collect::<Vec<_>>();
        assert!(codes.contains(&"E2203"));
    }

    #[test]
    fn inspect_reports_the_checked_manifest() {
        let source = include_str!("../../../conformance/valid/hello-note.ns");
        let response = result(&format!(
            r#"{{"op":"inspect","source":{} }}"#,
            serde_json::to_string(source).expect("source is a string")
        ));
        assert!(response["result"]["checked"].as_bool().unwrap());
        assert_eq!(response["result"]["manifest"]["profile"], "standard");
    }

    #[test]
    fn compile_produces_a_wasm_artifact() {
        let source = include_str!("../../../conformance/valid/hello-note.ns");
        let response = result(&format!(
            r#"{{"op":"compile","source":{} }}"#,
            serde_json::to_string(source).expect("source is a string")
        ));
        assert!(response["result"]["checked"].as_bool().unwrap());
        let wasm = response["result"]["wasm"].as_str().unwrap();
        assert!(wasm.starts_with("AGFzbQ"), "wasm magic in base64");
    }

    #[test]
    fn run_executes_against_fake_hosts() {
        let source = include_str!("../../../conformance/valid/hello-note.ns");
        let response = result(&format!(
            r#"{{"op":"run","source":{} }}"#,
            serde_json::to_string(source).expect("source is a string")
        ));
        assert!(response["result"]["executed"].as_bool().unwrap());
        assert_eq!(
            response["result"]["trace"]["publications"]
                .as_array()
                .unwrap()
                .len(),
            1
        );
    }

    #[test]
    fn footprint_reports_a_requested_zap_live() {
        let source = "use nip57\nzap alice amount 1000\n";
        let response = result(&format!(
            r#"{{"op":"footprint","source":{} }}"#,
            serde_json::to_string(source).expect("source is a string")
        ));
        let payments = response["result"]["footprint"]["groups"]
            .as_array()
            .unwrap()
            .iter()
            .find(|group| group["name"] == "Payments")
            .expect("zap requests a payment capability");
        let item = payments["items"]
            .as_array()
            .unwrap()
            .iter()
            .find(|item| {
                item["label"]
                    .as_str()
                    .unwrap()
                    .contains("create_zap_request")
            })
            .expect("the zap call is listed");
        assert_eq!(item["status"], "requested");
        assert_eq!(item["permission"], "zap");
    }

    #[test]
    fn completions_offer_modules_and_members() {
        let source = "use nip\n";
        let response = result(&format!(
            r#"{{"op":"completions","source":{},"offset":7}}"#,
            serde_json::to_string(source).expect("source is a string")
        ));
        let labels = response["result"]["completions"]
            .as_array()
            .unwrap()
            .iter()
            .filter_map(|completion| completion["label"].as_str())
            .collect::<Vec<_>>();
        assert!(labels.contains(&"nip17"), "{labels:?}");
    }

    #[test]
    fn hover_types_the_handler_event_binding() {
        let source = "use nip01\non Note {\n    event\n}\n";
        let offset = source.find("event").unwrap() + 2;
        let response = result(&format!(
            r#"{{"op":"hover","source":{},"offset":{offset}}}"#,
            serde_json::to_string(source).expect("source is a string")
        ));
        assert_eq!(response["result"]["hover"]["label"], "event");
        assert!(
            response["result"]["hover"]["detail"]
                .as_str()
                .unwrap()
                .contains("Signed<")
        );
    }

    #[test]
    fn test_event_simulates_a_synthetic_handler_run() {
        let source = "use nip01\npermissions {\n    read Note from public\n    relay public\n    log\n}\non Note {\n    print(event.content)\n}\n";
        let event = serde_json::json!({ "kind": 1, "content": "hello" });
        let request = serde_json::json!({ "op": "test_event", "source": source, "event": event });
        let response = result(&request.to_string());
        assert!(response["result"]["executed"].as_bool().unwrap());
        assert_eq!(response["result"]["report"]["dispatched"], 1);
        assert_eq!(response["result"]["report"]["logs"][0]["message"], "hello");
    }

    #[test]
    fn manifest_builds_an_npack_compatible_package() {
        let source = include_str!("../../../conformance/valid/hello-note.ns");
        let request = serde_json::json!({
            "op": "manifest",
            "source": source,
            "publisher": "npub1author",
            "name": "hello-note",
            "version": "0.1.0",
        });
        let response = result(&request.to_string());
        assert!(response["result"]["checked"].as_bool().unwrap());
        let manifest = &response["result"]["manifest"];
        assert_eq!(manifest["publisher"], "npub1author");
        assert_eq!(manifest["format"], "npk");
        assert_eq!(manifest["sha256"].as_str().unwrap().len(), 64);
        assert_eq!(
            response["result"]["sha256"].as_str().unwrap(),
            manifest["sha256"].as_str().unwrap()
        );
        assert!(
            response["result"]["wasm"]
                .as_str()
                .unwrap()
                .starts_with("AGFzbQ")
        );
    }

    #[test]
    fn lock_emits_a_deterministic_lockfile() {
        let source = include_str!("../../../conformance/valid/nip17-send.ns");
        let response = result(&format!(
            r#"{{"op":"lock","source":{} }}"#,
            serde_json::to_string(source).expect("source is a string")
        ));
        let lockfile = &response["result"]["lockfile"];
        assert_eq!(lockfile["lockfile_version"], 1);
        let names = lockfile["modules"]
            .as_array()
            .unwrap()
            .iter()
            .filter_map(|module| module["name"].as_str())
            .collect::<Vec<_>>();
        assert!(names.contains(&"nip17"), "{names:?}");
        assert!(names.contains(&"nip44"), "{names:?}");
        assert!(names.contains(&"nip59"), "{names:?}");
    }
}
