use std::{
    env, fs,
    io::{self, BufRead, Read, Write},
    path::PathBuf,
    process::{Command, Stdio},
    sync::mpsc,
    sync::{
        Arc,
        atomic::{AtomicBool, AtomicU64, Ordering},
    },
    thread,
    time::{Duration, Instant},
};

use serde_json::{Value, json};
use wasmi::{Config, Engine, Linker, Module, Store, StoreLimitsBuilder};

mod sessions;

const PROTOCOL_VERSION: &str = "2025-03-26";
const MAX_SOURCE_BYTES: usize = 1_000_000;
const MAX_EVENT_BYTES: usize = 256_000;
const MAX_WASM_RESPONSE_BYTES: usize = 2_000_000;
const DEFAULT_WASM_FUEL: u64 = 250_000_000;
const MAX_WASM_FUEL: u64 = 1_000_000_000;
const WASM_MEMORY_LIMIT: usize = 16 * 1024 * 1024;
const DEFAULT_CLI_TIMEOUT: Duration = Duration::from_secs(30);
static NEXT_TEMP: AtomicU64 = AtomicU64::new(0);
static HTTP_MODE: AtomicBool = AtomicBool::new(false);

fn main() -> io::Result<()> {
    sessions::resume_all();
    if env::args().any(|argument| argument == "--http") {
        return serve_http();
    }
    let (input_tx, input_rx) = mpsc::channel::<io::Result<String>>();
    let (output_tx, output_rx) = mpsc::channel::<(String, Option<Value>)>();
    thread::spawn(move || {
        for line in io::stdin().lock().lines() {
            if input_tx.send(line).is_err() {
                break;
            }
        }
    });
    let mut stdout = io::BufWriter::new(io::stdout().lock());
    let mut active: std::collections::HashMap<String, Arc<AtomicBool>> =
        std::collections::HashMap::new();
    let mut input_closed = false;
    loop {
        match input_rx.try_recv() {
            Ok(Ok(line)) if !line.trim().is_empty() => {
                let request: Value = match serde_json::from_str(&line) {
                    Ok(request) => request,
                    Err(error) => {
                        write_message(
                            &mut stdout,
                            &json!({"jsonrpc":"2.0","id":null,"error":{"code":-32700,"message":format!("Parse error: {error}")}}),
                        )?;
                        continue;
                    }
                };
                if request.get("method").and_then(Value::as_str) == Some("notifications/cancelled")
                {
                    if let Some(key) = request.pointer("/params/requestId").map(id_key)
                        && let Some(cancel) = active.get(&key)
                    {
                        cancel.store(true, Ordering::Relaxed);
                    }
                    continue;
                }
                let Some(id) = request.get("id").cloned() else {
                    continue;
                };
                let key = id_key(&id);
                let cancelled = Arc::new(AtomicBool::new(false));
                active.insert(key.clone(), Arc::clone(&cancelled));
                let sender = output_tx.clone();
                thread::spawn(move || {
                    let response = handle(&request, &cancelled);
                    let _ = sender.send((key, response));
                });
            }
            Ok(Err(error)) => return Err(error),
            Err(mpsc::TryRecvError::Disconnected) => input_closed = true,
            Ok(Ok(_)) | Err(mpsc::TryRecvError::Empty) => {}
        }
        while let Ok((key, response)) = output_rx.try_recv() {
            active.remove(&key);
            if let Some(response) = response {
                write_message(&mut stdout, &response)?;
            }
        }
        if input_closed && active.is_empty() {
            break;
        }
        thread::sleep(Duration::from_millis(5));
    }
    Ok(())
}

fn id_key(id: &Value) -> String {
    serde_json::to_string(id).unwrap_or_else(|_| "null".to_owned())
}

fn write_message(output: &mut impl Write, value: &Value) -> io::Result<()> {
    serde_json::to_writer(&mut *output, value)?;
    output.write_all(b"\n")?;
    output.flush()
}

fn handle(request: &Value, cancelled: &Arc<AtomicBool>) -> Option<Value> {
    let id = request.get("id")?.clone();
    let method = request.get("method").and_then(Value::as_str).unwrap_or("");
    let params = request.get("params").cloned().unwrap_or_else(|| json!({}));
    let result = match method {
        "initialize" => Ok(json!({
            "protocolVersion": params.get("protocolVersion").and_then(Value::as_str)
                .filter(|version| *version == PROTOCOL_VERSION || *version == "2024-11-05")
                .unwrap_or(PROTOCOL_VERSION),
            "capabilities": {"tools": {"listChanged": false}},
            "serverInfo": {"name": "nscript", "version": env!("CARGO_PKG_VERSION")},
            "instructions": "Check, inspect, and simulate NScript source. nscript_execute runs inside a fuel- and memory-limited WASM sandbox and does not access live relays or signing keys. nscript_execute_live and nscript_session_start are available only when the server administrator enables live execution; they use native nscript deploy and may publish to configured relays."
        })),
        "ping" => Ok(json!({})),
        "tools/list" => Ok(json!({"tools": tool_definitions()})),
        "tools/call" => call_tool(&params, cancelled),
        _ => {
            return Some(json!({
                "jsonrpc": "2.0",
                "id": id,
                "error": {"code": -32601, "message": format!("Unknown method: {method}")}
            }));
        }
    };
    Some(match result {
        Ok(result) => json!({"jsonrpc": "2.0", "id": id, "result": result}),
        Err((code, message)) => json!({
            "jsonrpc": "2.0", "id": id,
            "error": {"code": code, "message": message}
        }),
    })
}

fn tool_definitions() -> Value {
    json!([
        {
            "name": "nscript_check",
            "title": "Check NScript source",
            "description": "Parse and statically check an NScript program. Returns compiler diagnostics and a success flag.",
            "annotations": {"readOnlyHint": true, "openWorldHint": false},
            "inputSchema": {"type": "object", "properties": {"source": {"type": "string", "description": "Complete NScript source code."}, "module_dirs": {"type": "array", "items": {"type": "string"}, "description": "Optional local directories containing custom .nsm modules; each is passed to the CLI with -M."}}, "required": ["source"], "additionalProperties": false}
        },
        {
            "name": "nscript_inspect",
            "title": "Inspect NScript permissions and effects",
            "description": "Check an NScript program and return its structured manifest, including effects, resolved modules, operations, and publication trace.",
            "annotations": {"readOnlyHint": true, "openWorldHint": false},
            "inputSchema": {"type": "object", "properties": {"source": {"type": "string", "description": "Complete NScript source code."}, "module_dirs": {"type": "array", "items": {"type": "string"}, "description": "Optional local directories containing custom .nsm modules; each is passed to the CLI with -M."}}, "required": ["source"], "additionalProperties": false}
        },
        {
            "name": "nscript_simulate_event",
            "title": "Simulate an NScript event handler",
            "description": "Deliver a JSON event to an NScript program using the CLI simulator. This is a dry simulation: it does not publish, connect to relays, or access signing keys. Module operations are simulated.",
            "annotations": {"readOnlyHint": true, "openWorldHint": false},
            "inputSchema": {"type": "object", "properties": {"source": {"type": "string", "description": "Complete NScript source code."}, "event": {"type": "object", "description": "JSON event value to deliver."}, "principal": {"type": "string", "description": "Optional value supplied as the program's me principal (--as)."}, "inputs": {"type": "object", "description": "Optional values for declared scalar inputs. Values may be strings, integers, or booleans.", "additionalProperties": {"type": ["string", "integer", "boolean"]}}, "module_dirs": {"type": "array", "items": {"type": "string"}, "description": "Optional local directories containing custom .nsm modules; each is passed to the CLI with -M."}}, "required": ["source", "event"], "additionalProperties": false}
        },
        {
            "name": "nscript_test_event",
            "title": "Diagnose NScript event filters",
            "description": "Simulate an event and report matched handler counts and per-handler event, author, and tag filter traces.",
            "annotations": {"readOnlyHint": true, "openWorldHint": false},
            "inputSchema": {"type": "object", "properties": {"source": {"type": "string"}, "event": {"type": "object"}, "principal": {"type": "string"}, "inputs": {"type": "object", "description": "Optional values for declared scalar inputs.", "additionalProperties": {"type": ["string", "integer", "boolean"]}}, "module_dirs": {"type": "array", "items": {"type": "string"}}}, "required": ["source", "event"], "additionalProperties": false}
        },
        {
            "name": "nscript_execute",
            "title": "Execute NScript in a WASM sandbox",
            "description": "Run NScript startup logic or deliver one event inside a fuel- and memory-limited WASM guest. This is sandbox simulation: it does not connect to relays, publish, access signing keys, or perform live module operations.",
            "annotations": {"readOnlyHint": true, "openWorldHint": false},
            "inputSchema": {"type": "object", "properties": {"source": {"type": "string", "description": "Complete NScript source code."}, "event": {"type": "object", "description": "Optional JSON event to deliver to handlers."}, "principal": {"type": "string", "description": "Optional principal value used for `me`."}, "inputs": {"type": "object", "description": "Optional values for declared scalar inputs.", "additionalProperties": {"type": ["string", "integer", "boolean"]}}, "module_dirs": {"type": "array", "items": {"type": "string", "description": "Local module directories the MCP process is allowed to read."}}}, "required": ["source"], "additionalProperties": false}
        },
        {
            "name": "nscript_execute_live",
            "title": "Execute NScript against live relays",
            "description": "Explicitly run nscript deploy for one relay polling cycle. This may sign and publish events using server-configured remote signers. Requires confirm_live=true and NSCRIPT_MCP_LIVE_ENABLED=true.",
            "annotations": {"readOnlyHint": false, "destructiveHint": true, "openWorldHint": true},
            "inputSchema": {"type":"object","properties":{"source":{"type":"string"},"confirm_live":{"type":"boolean","const":true},"relays":{"type":"array","items":{"type":"string"},"description":"Optional subset of server-allowed relay URLs."},"signer_refs":{"type":"array","items":{"type":"string"},"description":"Configured signer names; raw signer URIs are not accepted."},"principal":{"type":"string"},"inputs":{"type":"object","additionalProperties":{"type":["string","integer","boolean"]}},"module_dirs":{"type":"array","items":{"type":"string"}}},"required":["source","confirm_live"],"additionalProperties":false}
        },
        {
            "name": "nscript_session_start",
            "title": "Start a durable NScript bot session",
            "description": "Start a long-running nscript deploy process that polls configured relays. Session definitions and NScript storage persist across MCP server restarts. Requires confirm_live=true and server live execution policy.",
            "annotations": {"readOnlyHint": false, "destructiveHint": true, "openWorldHint": true},
            "inputSchema": {"type":"object","properties":{"source":{"type":"string"},"confirm_live":{"type":"boolean","const":true},"relays":{"type":"array","items":{"type":"string"}},"signer_refs":{"type":"array","items":{"type":"string"}},"principal":{"type":"string"},"inputs":{"type":"object","additionalProperties":{"type":["string","integer","boolean"]}},"module_dirs":{"type":"array","items":{"type":"string"}}},"required":["source","confirm_live"],"additionalProperties":false}
        },
        {
            "name": "nscript_session_status",
            "title": "Check NScript session status",
            "description": "Return a session's state, process ID, and recent log output.",
            "annotations": {"readOnlyHint": true, "openWorldHint": false},
            "inputSchema": {"type":"object","properties":{"session_id":{"type":"string"}},"required":["session_id"],"additionalProperties":false}
        },
        {
            "name": "nscript_session_stop",
            "title": "Stop an NScript session",
            "description": "Stop a running nscript deploy process and mark the durable session as stopped.",
            "annotations": {"readOnlyHint": false, "destructiveHint": true, "openWorldHint": false},
            "inputSchema": {"type":"object","properties":{"session_id":{"type":"string"}},"required":["session_id"],"additionalProperties":false}
        }
    ])
}

fn wasm_execute_tool(
    arguments: &Value,
    cancelled: &Arc<AtomicBool>,
) -> Result<Value, (i64, String)> {
    let source = arguments
        .get("source")
        .and_then(Value::as_str)
        .ok_or((-32602, "tool argument `source` must be a string".to_owned()))?;
    if source.len() > MAX_SOURCE_BYTES {
        return Err((
            -32602,
            format!("source exceeds the {MAX_SOURCE_BYTES}-byte limit"),
        ));
    }
    if cancelled.load(Ordering::Relaxed) {
        return Err((-32603, "request cancelled".to_owned()));
    }
    let directories = module_dirs(arguments)?;
    let modules = module_sources_from_dirs(&directories).map_err(|error| (-32602, error))?;
    let event = arguments.get("event");
    if let Some(event) = event {
        if !event.is_object() {
            return Err((-32602, "event must be a JSON object".to_owned()));
        }
        let bytes = serde_json::to_vec(event).map_err(|error| (-32602, error.to_string()))?;
        if bytes.len() > MAX_EVENT_BYTES {
            return Err((
                -32602,
                format!("event exceeds the {MAX_EVENT_BYTES}-byte limit"),
            ));
        }
    }
    let principal = arguments.get("principal");
    if principal.is_some_and(|value| !value.is_string()) {
        return Err((-32602, "principal must be a string".to_owned()));
    }
    let inputs = arguments.get("inputs");
    if let Some(inputs) = inputs {
        let Some(inputs) = inputs.as_object() else {
            return Err((
                -32602,
                "inputs must be an object of scalar values".to_owned(),
            ));
        };
        for (name, value) in inputs {
            if !(value.is_string() || value.as_i64().is_some() || value.is_boolean()) {
                return Err((
                    -32602,
                    format!("input `{name}` must be a string, integer, or boolean"),
                ));
            }
        }
        if event.is_none() && !inputs.is_empty() {
            return Err((
                -32602,
                "declared inputs are available during event-handler execution; supply an event"
                    .to_owned(),
            ));
        }
    }
    let mut request = json!({
        "op": if event.is_some() { "test_event" } else { "run" },
        "source": source,
        "modules": modules,
    });
    if let Some(event) = event {
        request["event"] = event.clone();
    }
    if let Some(principal) = principal {
        request["principal"] = principal.clone();
    }
    if let Some(inputs) = inputs {
        request["inputs"] = inputs.clone();
    }
    let response = match wasm_call(&request) {
        Ok(response) => response,
        Err(error) => {
            return Ok(json!({
                "content": [{"type":"text","text":error}],
                "isError": true,
            }));
        }
    };
    if cancelled.load(Ordering::Relaxed) {
        return Ok(json!({
            "content": [{"type":"text","text":"execution cancelled"}],
            "isError": true,
        }));
    }
    let payload = response
        .get("result")
        .cloned()
        .unwrap_or_else(|| response.clone());
    let failed = response.get("ok").and_then(Value::as_bool) != Some(true)
        || payload.get("executed").and_then(Value::as_bool) == Some(false);
    let text = serde_json::to_string_pretty(&payload).unwrap_or_else(|_| payload.to_string());
    Ok(json!({
        "content": [{"type":"text","text":text}],
        "structuredContent": payload,
        "isError": failed,
    }))
}

fn wasm_path() -> Result<PathBuf, String> {
    if let Some(path) = env::var_os("NSCRIPT_WASM_PATH") {
        return Ok(PathBuf::from(path));
    }
    let executable = env::current_exe().map_err(|error| error.to_string())?;
    let sibling = executable.with_file_name("nscript_wasm.wasm");
    if sibling.is_file() {
        return Ok(sibling);
    }
    Ok(PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../target/wasm32-unknown-unknown/release/nscript_wasm.wasm"))
}

#[allow(clippy::too_many_lines)]
fn wasm_call(request: &Value) -> Result<Value, String> {
    let path = wasm_path()?;
    let bytes = fs::read(&path).map_err(|error| {
        format!(
            "cannot read NScript WASM guest {}: {error}; build nscript-wasm for wasm32-unknown-unknown or set NSCRIPT_WASM_PATH",
            path.display()
        )
    })?;
    if bytes.len() > WASM_MEMORY_LIMIT {
        return Err("NScript WASM guest exceeds the module size limit".to_owned());
    }
    let mut config = Config::default();
    config.consume_fuel(true);
    let engine = Engine::new(&config);
    let module = Module::new(&engine, &bytes[..])
        .map_err(|error| format!("invalid NScript WASM guest: {error}"))?;
    if module.imports().next().is_some() {
        return Err("NScript WASM guest must not import host or WASI functions".to_owned());
    }
    let limits = StoreLimitsBuilder::new()
        .memory_size(WASM_MEMORY_LIMIT)
        .instances(1)
        .tables(1)
        .build();
    let mut store = Store::new(&engine, limits);
    store.limiter(|limits| limits);
    let fuel = env::var("NSCRIPT_MCP_WASM_FUEL")
        .ok()
        .and_then(|value| value.parse::<u64>().ok())
        .filter(|fuel| *fuel > 0 && *fuel <= MAX_WASM_FUEL)
        .unwrap_or(DEFAULT_WASM_FUEL);
    store
        .set_fuel(fuel)
        .map_err(|error| format!("cannot set WASM fuel: {error}"))?;
    let linker = Linker::<wasmi::StoreLimits>::new(&engine);
    let instance = linker
        .instantiate(&mut store, &module)
        .map_err(|error| format!("cannot instantiate NScript WASM guest: {error}"))?
        .start(&mut store)
        .map_err(|error| format!("cannot start NScript WASM guest: {error}"))?;
    let memory = instance
        .get_memory(&store, "memory")
        .ok_or_else(|| "NScript WASM guest does not export memory".to_owned())?;
    let alloc = instance
        .get_typed_func::<i32, i32>(&store, "nscript_alloc")
        .map_err(|error| format!("NScript WASM guest ABI is missing nscript_alloc: {error}"))?;
    let dealloc = instance
        .get_typed_func::<(i32, i32), ()>(&store, "nscript_dealloc")
        .map_err(|error| format!("NScript WASM guest ABI is missing nscript_dealloc: {error}"))?;
    let handle = instance
        .get_typed_func::<(i32, i32), i32>(&store, "nscript_handle")
        .map_err(|error| format!("NScript WASM guest ABI is missing nscript_handle: {error}"))?;
    let free = instance
        .get_typed_func::<(i32, i32), ()>(&store, "nscript_free")
        .map_err(|error| format!("NScript WASM guest ABI is missing nscript_free: {error}"))?;
    let abi = instance
        .get_typed_func::<(), i32>(&store, "nscript_abi")
        .map_err(|error| format!("NScript WASM guest ABI is missing nscript_abi: {error}"))?
        .call(&mut store, ())
        .map_err(|error| format!("cannot query NScript WASM ABI: {error}"))?;
    if abi != 1 {
        return Err(format!("unsupported NScript WASM ABI version {abi}"));
    }
    let request = serde_json::to_vec(request).map_err(|error| error.to_string())?;
    let request_len = i32::try_from(request.len()).map_err(|_| "request is too large")?;
    let request_ptr = alloc
        .call(&mut store, request_len)
        .map_err(|error| format!("WASM request allocation failed: {error}"))?;
    if request_ptr < 0 {
        return Err("WASM returned an invalid request pointer".to_owned());
    }
    let request_offset =
        usize::try_from(request_ptr).map_err(|_| "WASM returned an invalid request pointer")?;
    memory
        .write(&mut store, request_offset, &request)
        .map_err(|error| format!("WASM request write failed: {error}"))?;
    let response_ptr = handle
        .call(&mut store, (request_ptr, request_len))
        .map_err(|error| format!("WASM execution failed (fuel or memory limit): {error}"))?;
    dealloc
        .call(&mut store, (request_ptr, request_len))
        .map_err(|error| format!("WASM request cleanup failed: {error}"))?;
    if response_ptr < 0 {
        return Err("WASM returned an invalid response pointer".to_owned());
    }
    let response_ptr_i32 = response_ptr;
    let response_ptr =
        usize::try_from(response_ptr).map_err(|_| "WASM returned an invalid response pointer")?;
    let data = memory.data(&store);
    let response = data
        .get(response_ptr..)
        .ok_or_else(|| "WASM response pointer is out of bounds".to_owned())?;
    let response_len = response
        .iter()
        .take(MAX_WASM_RESPONSE_BYTES + 1)
        .position(|byte| *byte == 0)
        .ok_or_else(|| {
            "WASM response is missing a terminator or exceeds the size limit".to_owned()
        })?;
    let response_text = std::str::from_utf8(&response[..response_len])
        .map_err(|error| format!("WASM response is not UTF-8: {error}"))?;
    let result = serde_json::from_str::<Value>(response_text)
        .map_err(|error| format!("WASM response is not valid JSON: {error}"));
    let response_len = i32::try_from(response_len + 1).map_err(|_| "response is too large")?;
    free.call(&mut store, (response_ptr_i32, response_len))
        .map_err(|error| format!("WASM response cleanup failed: {error}"))?;
    result
}

fn module_sources_from_dirs(directories: &[String]) -> Result<Vec<Value>, String> {
    let mut sources = Vec::new();
    let mut pending = directories.iter().map(PathBuf::from).collect::<Vec<_>>();
    let mut total_bytes = 0_usize;
    while let Some(path) = pending.pop() {
        let entries = fs::read_dir(&path)
            .map_err(|error| format!("cannot read module directory {}: {error}", path.display()))?;
        for entry in entries {
            let entry = entry.map_err(|error| error.to_string())?;
            let entry_path = entry.path();
            let metadata = entry
                .file_type()
                .map_err(|error| format!("cannot inspect {}: {error}", entry_path.display()))?;
            if metadata.is_dir() {
                pending.push(entry_path);
                continue;
            }
            if !metadata.is_file()
                || entry_path.extension().and_then(|value| value.to_str()) != Some("nsm")
            {
                continue;
            }
            let source = fs::read_to_string(&entry_path)
                .map_err(|error| format!("cannot read module {}: {error}", entry_path.display()))?;
            total_bytes = total_bytes.saturating_add(source.len());
            if total_bytes > MAX_SOURCE_BYTES {
                return Err("custom module sources exceed the 1 MB total limit".to_owned());
            }
            let (descriptor, diagnostics) = nscript_modules::parse_module(&source);
            let descriptor = descriptor
                .filter(|_| diagnostics.is_empty())
                .ok_or_else(|| {
                    format!(
                        "invalid module {}: {}",
                        entry_path.display(),
                        diagnostics
                            .iter()
                            .map(|diagnostic| diagnostic.message.as_str())
                            .collect::<Vec<_>>()
                            .join("; ")
                    )
                })?;
            sources.push(json!({"name":descriptor.id.name,"source":source}));
            if sources.len() > 256 {
                return Err("module directory contains more than 256 .nsm files".to_owned());
            }
        }
    }
    Ok(sources)
}

#[allow(clippy::too_many_lines)]
fn call_tool(params: &Value, cancelled: &Arc<AtomicBool>) -> Result<Value, (i64, String)> {
    let name = params
        .get("name")
        .and_then(Value::as_str)
        .ok_or((-32602, "tools/call requires a tool name".to_owned()))?;
    if !matches!(
        name,
        "nscript_check"
            | "nscript_inspect"
            | "nscript_simulate_event"
            | "nscript_test_event"
            | "nscript_execute"
            | "nscript_execute_live"
            | "nscript_session_start"
            | "nscript_session_status"
            | "nscript_session_stop"
    ) {
        return Ok(json!({
            "content": [{"type": "text", "text": format!("Unknown tool: {name}")}],
            "isError": true
        }));
    }
    let arguments = params
        .get("arguments")
        .cloned()
        .unwrap_or_else(|| json!({}));
    if name == "nscript_session_status" || name == "nscript_session_stop" {
        let result = if name == "nscript_session_status" {
            sessions::status(&arguments)
        } else {
            sessions::stop(&arguments)
        };
        return Ok(match result {
            Ok(payload) => tool_result(&payload, false),
            Err(error) => tool_error(&error),
        });
    }
    if name == "nscript_execute_live" || name == "nscript_session_start" {
        if arguments.get("confirm_live").and_then(Value::as_bool) != Some(true) {
            return Err((
                -32602,
                "confirm_live must be true for live execution".to_owned(),
            ));
        }
        let source = arguments
            .get("source")
            .and_then(Value::as_str)
            .ok_or((-32602, "tool argument `source` must be a string".to_owned()))?;
        if source.len() > MAX_SOURCE_BYTES {
            return Err((
                -32602,
                format!("source exceeds the {MAX_SOURCE_BYTES}-byte limit"),
            ));
        }
        let directories = module_dirs(&arguments)?;
        if name == "nscript_session_start" {
            return Ok(match sessions::start(&arguments, &directories) {
                Ok(payload) => tool_result(&payload, false),
                Err(error) => tool_error(&error),
            });
        }
        return Ok(
            match sessions::execute_once(&arguments, &directories, cancelled) {
                Ok(payload) => {
                    let failed = payload.get("success").and_then(Value::as_bool) != Some(true);
                    tool_result(&payload, failed)
                }
                Err(error) => tool_error(&error),
            },
        );
    }
    let source = arguments
        .get("source")
        .and_then(Value::as_str)
        .ok_or((-32602, "tool argument `source` must be a string".to_owned()))?;
    if source.len() > MAX_SOURCE_BYTES {
        return Err((
            -32602,
            format!("source exceeds the {MAX_SOURCE_BYTES}-byte limit"),
        ));
    }

    if name == "nscript_execute" {
        return wasm_execute_tool(&arguments, cancelled);
    }

    let mut temp = TempSource::new(source).map_err(|error| (-32603, error))?;
    let module_dirs = module_dirs(&arguments)?;
    let (mut args, format_json) = match name {
        "nscript_check" => (vec!["check".to_owned()], false),
        "nscript_inspect" => (vec!["inspect".to_owned(), "--json".to_owned()], true),
        "nscript_simulate_event" | "nscript_test_event" => {
            let event = arguments
                .get("event")
                .ok_or((-32602, "tool argument `event` is required".to_owned()))?;
            if !event.is_object() {
                return Err((-32602, "event must be a JSON object".to_owned()));
            }
            let serialized =
                serde_json::to_string(event).map_err(|error| (-32602, error.to_string()))?;
            if serialized.len() > MAX_EVENT_BYTES {
                return Err((
                    -32602,
                    format!("event exceeds the {MAX_EVENT_BYTES}-byte limit"),
                ));
            }
            let mut run = if name == "nscript_test_event" {
                vec!["test-event".to_owned()]
            } else {
                vec!["run".to_owned()]
            };
            if let Some(principal) = arguments.get("principal") {
                let principal = principal.as_str().ok_or((
                    -32602,
                    "principal must be a string when supplied".to_owned(),
                ))?;
                run.extend(["--as".to_owned(), principal.to_owned()]);
            }
            if let Some(inputs) = arguments.get("inputs")
                && matches!(name, "nscript_simulate_event" | "nscript_test_event")
            {
                let inputs = inputs.as_object().ok_or((
                    -32602,
                    "inputs must be an object of scalar values".to_owned(),
                ))?;
                for (name, value) in inputs {
                    let raw = match value {
                        Value::String(value) => value.clone(),
                        Value::Number(value) if value.as_i64().is_some() => value.to_string(),
                        Value::Bool(value) => value.to_string(),
                        _ => {
                            return Err((
                                -32602,
                                format!("input `{name}` must be a string, integer, or boolean"),
                            ));
                        }
                    };
                    run.extend(["--input".to_owned(), format!("{name}={raw}")]);
                }
            }
            run.extend(["--event".to_owned(), serialized]);
            (run, false)
        }
        _ => unreachable!("tool name was validated"),
    };
    for directory in module_dirs {
        args.extend(["-M".to_owned(), directory]);
    }
    args.push(temp.path.display().to_string());
    let output = run_cli(&args, cancelled).map_err(|error| (-32603, error))?;
    let temp_path = temp.path.display().to_string();
    let stdout = String::from_utf8_lossy(&output.stdout).replace(&temp_path, "<source>");
    let stderr = String::from_utf8_lossy(&output.stderr).replace(&temp_path, "<source>");
    let is_error = !output.status.success();
    let payload = if format_json && !is_error {
        serde_json::from_str::<Value>(&stdout)
            .unwrap_or_else(|_| json!({"output": stdout, "stderr": stderr}))
    } else if name == "nscript_test_event" {
        let inspect_args = {
            let mut inspect = vec!["inspect".to_owned(), "--json".to_owned()];
            let mut index = 0;
            while index < args.len() {
                if args[index] == "-M" && index + 1 < args.len() {
                    inspect.extend(["-M".to_owned(), args[index + 1].clone()]);
                    index += 2;
                } else {
                    index += 1;
                }
            }
            inspect.push(temp_path.clone());
            inspect
        };
        let inspection = run_cli(&inspect_args, cancelled)
            .ok()
            .and_then(|result| serde_json::from_slice::<Value>(&result.stdout).ok())
            .unwrap_or_else(|| json!({"handlers": []}));
        let event: Value = serde_json::from_str(
            &args
                .windows(2)
                .find(|pair| pair[0] == "--event")
                .map(|pair| pair[1].clone())
                .unwrap_or_default(),
        )
        .unwrap_or(Value::Null);
        let dispatched = stdout
            .lines()
            .find_map(|line| line.strip_prefix("matched: "))
            .and_then(|line| line.split('/').next())
            .and_then(|count| count.parse::<usize>().ok())
            .unwrap_or(0);
        let handlers = inspection
            .get("handlers")
            .and_then(Value::as_array)
            .cloned()
            .unwrap_or_default();
        let traces = handlers.iter().enumerate().map(|(index, handler)| {
            let event_type = handler.get("event").and_then(Value::as_str).unwrap_or("");
            let actual_type = event.get("event_type").and_then(Value::as_str).unwrap_or("Note");
            let principal = args.windows(2).find(|pair| pair[0] == "--as").map_or("alice", |pair| pair[1].as_str());
            let principal = arguments.get("principal").and_then(Value::as_str).unwrap_or(principal);
            let expected_author = if handler.get("author_is_principal").and_then(Value::as_bool) == Some(true) { Some(principal) } else { handler.get("author").and_then(Value::as_str) };
            let actual_author = event.get("signer").and_then(Value::as_str).unwrap_or("alice");
            let mut predicates = handler.get("tags").and_then(Value::as_array).cloned().unwrap_or_default();
            if let Some(principal_tags) = handler.get("tag_equals_principal").and_then(Value::as_array) {
                predicates.extend(principal_tags.iter().map(|name| json!([name, principal])));
            }
            let tag_checks: Vec<Value> = predicates.iter().map(|predicate| {
                let name = predicate.get(0).and_then(Value::as_str).unwrap_or("");
                let expected = predicate.get(1).and_then(Value::as_str).unwrap_or("");
                let found = event.get("tags").and_then(Value::as_array).into_iter().flatten().any(|tag| tag.get(0).and_then(Value::as_str) == Some(name) && tag.get(1).and_then(Value::as_str) == Some(expected));
                json!({"tag":name,"expected":expected,"matched":found})
            }).collect();
            let type_match = event_type == actual_type;
            let author_match = expected_author.is_none_or(|author| author == actual_author);
            let tags_match = tag_checks.iter().all(|check| check["matched"] == true);
            json!({"handler_index":index,"event_type":{"expected":event_type,"actual":actual_type,"matched":type_match},"author":{"expected":expected_author,"actual":actual_author,"matched":author_match},"tags":tag_checks,"matched":type_match && author_match && tags_match})
        }).collect::<Vec<_>>();
        let filter_matches = traces
            .iter()
            .filter(|trace| trace["matched"] == true)
            .count();
        json!({"success":!is_error,"matched_handlers":dispatched,"handler_count":handlers.len(),"filter_matches":filter_matches,"filter_trace":traces,"output":stdout,"stderr":stderr})
    } else {
        json!({"success": !is_error, "exit_code": output.status.code(), "output": stdout.clone(), "stderr": stderr.clone()})
    };
    let text = serde_json::to_string_pretty(&payload).unwrap_or_else(|_| payload.to_string());
    // Drop the temporary source before returning the tool result.
    temp.remove();
    let structured = if name == "nscript_test_event" || (format_json && !is_error) {
        payload.clone()
    } else {
        json!({"success": !is_error, "exit_code": output.status.code(), "output": stdout, "stderr": stderr})
    };
    Ok(json!({
        "content": [{"type": "text", "text": text}],
        "structuredContent": structured,
        "isError": is_error
    }))
}

fn tool_result(payload: &Value, is_error: bool) -> Value {
    let text = serde_json::to_string_pretty(&payload).unwrap_or_else(|_| payload.to_string());
    json!({
        "content": [{"type":"text","text":text}],
        "structuredContent": payload.clone(),
        "isError": is_error,
    })
}

fn tool_error(message: &str) -> Value {
    json!({
        "content": [{"type":"text","text":message}],
        "isError": true,
    })
}

pub(crate) fn module_dirs(arguments: &Value) -> Result<Vec<String>, (i64, String)> {
    let Some(directories) = arguments.get("module_dirs") else {
        return Ok(Vec::new());
    };
    let directories = directories.as_array().ok_or((
        -32602,
        "module_dirs must be an array of directory paths".to_owned(),
    ))?;
    let paths: Vec<String> = directories
        .iter()
        .map(|directory| {
            directory
                .as_str()
                .map(str::to_owned)
                .ok_or((-32602, "each module_dirs entry must be a string".to_owned()))
        })
        .collect::<Result<_, _>>()?;
    if HTTP_MODE.load(Ordering::Relaxed) {
        let roots = env::var_os("NSCRIPT_MCP_ALLOWED_MODULE_ROOTS").ok_or((
            -32602,
            "HTTP module_dirs require NSCRIPT_MCP_ALLOWED_MODULE_ROOTS".to_owned(),
        ))?;
        let roots: Vec<PathBuf> = env::split_paths(&roots)
            .filter_map(|path| path.canonicalize().ok())
            .collect();
        for path in &paths {
            let canonical = PathBuf::from(path)
                .canonicalize()
                .map_err(|error| (-32602, format!("cannot resolve module directory: {error}")))?;
            if !canonical.is_dir() || !roots.iter().any(|root| canonical.starts_with(root)) {
                return Err((
                    -32602,
                    format!(
                        "module directory is outside NSCRIPT_MCP_ALLOWED_MODULE_ROOTS: {}",
                        canonical.display()
                    ),
                ));
            }
        }
    }
    Ok(paths)
}

pub(crate) fn cli_path() -> Result<PathBuf, io::Error> {
    if let Some(path) = env::var_os("NSCRIPT_CLI_PATH") {
        return Ok(PathBuf::from(path));
    }
    let current = env::current_exe()?;
    let sibling = current.with_file_name(if cfg!(windows) {
        "nscript.exe"
    } else {
        "nscript"
    });
    if sibling.is_file() {
        Ok(sibling)
    } else {
        Ok(PathBuf::from("nscript"))
    }
}

pub(crate) fn run_cli(
    arguments: &[String],
    cancelled: &Arc<AtomicBool>,
) -> Result<std::process::Output, String> {
    run_cli_with_env(arguments, cancelled, &[])
}

pub(crate) fn run_cli_with_env(
    arguments: &[String],
    cancelled: &Arc<AtomicBool>,
    extra_env: &[(String, String)],
) -> Result<std::process::Output, String> {
    let executable =
        cli_path().map_err(|error| format!("cannot locate nscript-mcp executable: {error}"))?;
    let mut child = Command::new(&executable)
        .args(arguments)
        .envs(extra_env.iter().map(|(key, value)| (key, value)))
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|error| {
            format!(
                "cannot run NScript CLI `{}`: {error}; set NSCRIPT_CLI_PATH if it is not on PATH",
                executable.display()
            )
        })?;
    let mut stdout_pipe = child
        .stdout
        .take()
        .ok_or_else(|| "failed to capture NScript CLI stdout".to_owned())?;
    let mut stderr_pipe = child
        .stderr
        .take()
        .ok_or_else(|| "failed to capture NScript CLI stderr".to_owned())?;
    let stdout_reader = thread::spawn(move || {
        let mut bytes = Vec::new();
        let _ = stdout_pipe.read_to_end(&mut bytes);
        bytes
    });
    let stderr_reader = thread::spawn(move || {
        let mut bytes = Vec::new();
        let _ = stderr_pipe.read_to_end(&mut bytes);
        bytes
    });
    let started = Instant::now();
    let status = loop {
        match child.try_wait() {
            Ok(Some(status)) => break status,
            Ok(None) => {}
            Err(error) => {
                let _ = child.kill();
                let _ = child.wait();
                let _ = stdout_reader.join();
                let _ = stderr_reader.join();
                return Err(format!("could not wait for NScript CLI: {error}"));
            }
        }
        if cancelled.load(Ordering::Relaxed) {
            let _ = child.kill();
            let _ = child.wait();
            let _ = stdout_reader.join();
            let _ = stderr_reader.join();
            return Err("request cancelled".to_owned());
        }
        let timeout = env::var("NSCRIPT_MCP_TIMEOUT_SECS")
            .ok()
            .and_then(|value| value.parse::<u64>().ok())
            .map_or(DEFAULT_CLI_TIMEOUT, Duration::from_secs);
        if started.elapsed() >= timeout {
            let _ = child.kill();
            let _ = child.wait();
            let _ = stdout_reader.join();
            let _ = stderr_reader.join();
            return Err(format!(
                "NScript CLI exceeded the {} second time limit",
                timeout.as_secs()
            ));
        }
        thread::sleep(Duration::from_millis(25));
    };
    let stdout = stdout_reader
        .join()
        .map_err(|_| "NScript CLI stdout reader failed".to_owned())?;
    let stderr = stderr_reader
        .join()
        .map_err(|_| "NScript CLI stderr reader failed".to_owned())?;
    Ok(std::process::Output {
        status,
        stdout,
        stderr,
    })
}

fn serve_http() -> io::Result<()> {
    use std::net::TcpListener;
    HTTP_MODE.store(true, Ordering::Relaxed);
    if env::var("NSCRIPT_MCP_BEARER_TOKEN")
        .ok()
        .as_ref()
        .is_none_or(String::is_empty)
    {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "NSCRIPT_MCP_BEARER_TOKEN is required for HTTP mode",
        ));
    }
    let bind = env::var("NSCRIPT_MCP_BIND").unwrap_or_else(|_| "127.0.0.1:8765".to_owned());
    let listener = TcpListener::bind(&bind)?;
    eprintln!("nscript-mcp Streamable HTTP listening on {bind}");
    for connection in listener.incoming() {
        match connection {
            Ok(stream) => {
                thread::spawn(move || {
                    let _ = serve_http_connection(stream);
                });
            }
            Err(error) => eprintln!("HTTP accept error: {error}"),
        }
    }
    Ok(())
}

#[allow(clippy::too_many_lines)]
fn serve_http_connection(mut stream: std::net::TcpStream) -> io::Result<()> {
    use std::net::Shutdown;
    stream.set_read_timeout(Some(Duration::from_secs(10)))?;
    let mut request_bytes = Vec::new();
    let mut buffer = [0_u8; 4096];
    let header_end = loop {
        let count = stream.read(&mut buffer)?;
        if count == 0 {
            return Ok(());
        }
        request_bytes.extend_from_slice(&buffer[..count]);
        if request_bytes.len() > 1_400_000 {
            return http_error(&mut stream, 413, "request too large");
        }
        if let Some(index) = request_bytes
            .windows(4)
            .position(|window| window == b"\r\n\r\n")
        {
            break index + 4;
        }
    };
    let header = String::from_utf8_lossy(&request_bytes[..header_end]);
    let mut lines = header.split("\r\n");
    let Some(request_line) = lines.next() else {
        return http_error(&mut stream, 400, "invalid request");
    };
    let mut request_parts = request_line.split_whitespace();
    let method = request_parts.next().unwrap_or("");
    let path = request_parts.next().unwrap_or("");
    if !matches!(method, "POST" | "OPTIONS") || path != "/mcp" {
        return http_error(&mut stream, 404, "use POST /mcp");
    }
    let mut headers = std::collections::HashMap::new();
    for line in lines {
        if let Some((name, value)) = line.split_once(':') {
            headers.insert(name.trim().to_ascii_lowercase(), value.trim().to_owned());
        }
    }
    if !host_allowed(headers.get("host").map_or("", String::as_str)) {
        return http_error(&mut stream, 403, "Host is not allowed");
    }
    if let Some(origin) = headers.get("origin") {
        let allowed = env::var("NSCRIPT_MCP_ALLOWED_ORIGINS").unwrap_or_default();
        if !allowed
            .split(',')
            .map(str::trim)
            .any(|candidate| candidate == origin)
        {
            return http_error(&mut stream, 403, "Origin is not allowed");
        }
    }
    if method == "OPTIONS" {
        let origin = headers.get("origin").map_or("", String::as_str);
        if origin.is_empty() {
            return http_error(&mut stream, 403, "Origin is required for preflight");
        }
        write!(
            stream,
            "HTTP/1.1 204 No Content\r\nAccess-Control-Allow-Origin: {origin}\r\nVary: Origin\r\nAccess-Control-Allow-Methods: POST, OPTIONS\r\nAccess-Control-Allow-Headers: Authorization, Content-Type, MCP-Protocol-Version\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
        )?;
        return Ok(());
    }
    let accept = headers.get("accept").map_or("", String::as_str);
    if !accept.contains("application/json") || !accept.contains("text/event-stream") {
        return http_error(
            &mut stream,
            406,
            "Accept must include application/json and text/event-stream",
        );
    }
    let expected = env::var("NSCRIPT_MCP_BEARER_TOKEN").unwrap_or_default();
    let auth = headers.get("authorization").map_or("", String::as_str);
    if auth.strip_prefix("Bearer ") != Some(expected.as_str()) {
        return http_error(&mut stream, 401, "invalid bearer token");
    }
    let content_type = headers.get("content-type").map_or("", String::as_str);
    if !content_type
        .to_ascii_lowercase()
        .starts_with("application/json")
    {
        return http_error(&mut stream, 415, "Content-Type must be application/json");
    }
    let content_length = headers
        .get("content-length")
        .and_then(|length| length.parse::<usize>().ok())
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "Content-Length is required"))?;
    if content_length > 1_300_000 {
        return http_error(&mut stream, 413, "request too large");
    }
    let already_read = request_bytes
        .len()
        .saturating_sub(header_end)
        .min(content_length);
    while request_bytes.len() - header_end < content_length {
        let count = stream.read(&mut buffer)?;
        if count == 0 {
            return http_error(&mut stream, 400, "incomplete request body");
        }
        request_bytes.extend_from_slice(&buffer[..count]);
    }
    let body = &request_bytes[header_end..header_end + content_length];
    let request: Value = match serde_json::from_slice(body) {
        Ok(request) => request,
        Err(error) => return http_error(&mut stream, 400, &format!("invalid JSON: {error}")),
    };
    let cancelled = Arc::new(AtomicBool::new(false));
    let done = Arc::new(AtomicBool::new(false));
    let peer = stream.try_clone()?;
    peer.set_nonblocking(true)?;
    let monitor_cancelled = Arc::clone(&cancelled);
    let monitor_done = Arc::clone(&done);
    let monitor = thread::spawn(move || {
        let mut probe = [0_u8; 1];
        while !monitor_done.load(Ordering::Relaxed) {
            match peer.peek(&mut probe) {
                Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                    thread::sleep(Duration::from_millis(25));
                }
                Ok(0 | _) | Err(_) => {
                    monitor_cancelled.store(true, Ordering::Relaxed);
                    break;
                }
            }
        }
    });
    let response = handle(&request, &cancelled);
    done.store(true, Ordering::Relaxed);
    let _ = monitor.join();
    if cancelled.load(Ordering::Relaxed) {
        let _ = stream.shutdown(Shutdown::Both);
        return Ok(());
    }
    if let Some(response) = response {
        let body = serde_json::to_vec(&response).unwrap_or_else(|_| b"{}".to_vec());
        let origin = headers.get("origin").map(String::as_str);
        if accept.contains("text/event-stream") {
            let event_body = format!(
                "event: message\ndata: {}\n\n",
                String::from_utf8_lossy(&body)
            );
            write!(
                stream,
                "HTTP/1.1 200 OK\r\nContent-Type: text/event-stream\r\nCache-Control: no-cache\r\nContent-Length: {}\r\nMCP-Protocol-Version: {}\r\nConnection: close\r\n",
                event_body.len(),
                PROTOCOL_VERSION
            )?;
            if let Some(origin) = origin {
                write!(
                    stream,
                    "Access-Control-Allow-Origin: {origin}\r\nVary: Origin\r\n"
                )?;
            }
            write!(stream, "\r\n{event_body}")?;
        } else {
            write!(
                stream,
                "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nMCP-Protocol-Version: {}\r\nConnection: close\r\n",
                body.len(),
                PROTOCOL_VERSION
            )?;
            if let Some(origin) = origin {
                write!(
                    stream,
                    "Access-Control-Allow-Origin: {origin}\r\nVary: Origin\r\n"
                )?;
            }
            write!(stream, "\r\n")?;
            stream.write_all(&body)?;
        }
    } else {
        write!(
            stream,
            "HTTP/1.1 202 Accepted\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
        )?;
    }
    let _ = already_read;
    Ok(())
}

fn host_allowed(host_header: &str) -> bool {
    let host = if host_header.starts_with('[') {
        host_header
            .split_once(']')
            .map_or("", |(host, _)| &host[1..])
    } else {
        host_header
            .rsplit_once(':')
            .map_or(host_header, |(host, _)| host)
    }
    .to_ascii_lowercase();
    if let Ok(allowlist) = env::var("NSCRIPT_MCP_ALLOWED_HOSTS") {
        return allowlist
            .split(',')
            .map(|item| item.trim().to_ascii_lowercase())
            .any(|item| item == host);
    }
    matches!(host.as_str(), "localhost" | "127.0.0.1" | "::1")
}

fn http_error(stream: &mut std::net::TcpStream, status: u16, message: &str) -> io::Result<()> {
    let phrase = match status {
        400 => "Bad Request",
        401 => "Unauthorized",
        403 => "Forbidden",
        404 => "Not Found",
        413 => "Payload Too Large",
        415 => "Unsupported Media Type",
        _ => "Error",
    };
    let body = format!("{message}\n");
    write!(
        stream,
        "HTTP/1.1 {status} {phrase}\r\nContent-Type: text/plain\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
        body.len()
    )
}

struct TempSource {
    path: PathBuf,
}

impl TempSource {
    fn new(source: &str) -> Result<Self, String> {
        let directory = env::temp_dir();
        for _ in 0..10 {
            let nonce = NEXT_TEMP.fetch_add(1, Ordering::Relaxed);
            let path = directory.join(format!("nscript-mcp-{}-{nonce}.ns", std::process::id()));
            let mut options = fs::OpenOptions::new();
            options.write(true).create_new(true);
            #[cfg(unix)]
            {
                use std::os::unix::fs::OpenOptionsExt as _;
                options.mode(0o600);
            }
            match options.open(&path) {
                Ok(mut file) => {
                    file.write_all(source.as_bytes())
                        .map_err(|error| format!("cannot write temporary source: {error}"))?;
                    return Ok(Self { path });
                }
                Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {}
                Err(error) => return Err(format!("cannot create temporary source: {error}")),
            }
        }
        Err("could not allocate a unique temporary source file".to_owned())
    }

    fn remove(&mut self) {
        let _ = fs::remove_file(&self.path);
    }
}

impl Drop for TempSource {
    fn drop(&mut self) {
        self.remove();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn wasm_execution_delivers_event_and_returns_handler_trace() {
        let request = json!({
            "op": "test_event",
            "source": include_str!("../../../conformance/valid/handler-print.ns"),
            "event": {"event_type":"Note", "content":"hello from wasm", "signer":"alice"},
        });
        let response = wasm_call(&request).expect("executes in wasm");
        assert_eq!(response["ok"], true);
        assert_eq!(response["result"]["executed"], true);
        assert_eq!(response["result"]["report"]["dispatched"], 1);
        assert_eq!(
            response["result"]["report"]["logs"][0]["message"],
            "hello from wasm"
        );
    }

    #[test]
    fn wasm_mcp_tool_supplies_declared_handler_inputs() {
        let cancelled = Arc::new(AtomicBool::new(false));
        let payload = call_tool(
            &json!({
                "name":"nscript_execute",
                "arguments":{
                    "source": include_str!("../../../conformance/valid/handler-input.ns"),
                    "event": {"event_type":"Note", "content":"hello", "signer":"alice"},
                    "inputs": {"reply_prefix":"reply: "},
                },
            }),
            &cancelled,
        )
        .expect("executes through MCP tool");
        assert_eq!(payload["isError"], false);
        assert_eq!(
            payload["structuredContent"]["report"]["logs"][0]["message"],
            "reply: hello"
        );
    }

    #[test]
    fn wasm_executor_rejects_invalid_guest_bytes() {
        let mut config = Config::default();
        config.consume_fuel(true);
        let engine = Engine::new(&config);
        assert!(Module::new(&engine, b"not wasm".as_slice()).is_err());
    }

    #[test]
    fn live_tools_require_an_explicit_confirmation_flag() {
        let cancelled = Arc::new(AtomicBool::new(false));
        let error = call_tool(
            &json!({
                "name":"nscript_execute_live",
                "arguments":{"source":"", "confirm_live":false},
            }),
            &cancelled,
        )
        .expect_err("live call without confirmation is rejected");
        assert_eq!(error.0, -32602);
    }

    #[test]
    fn tool_list_exposes_live_execution_and_session_controls() {
        let definitions = tool_definitions();
        let names = definitions
            .as_array()
            .expect("tool list is an array")
            .iter()
            .filter_map(|tool| tool.get("name").and_then(Value::as_str))
            .collect::<Vec<_>>();
        assert!(names.contains(&"nscript_execute"));
        assert!(names.contains(&"nscript_execute_live"));
        assert!(names.contains(&"nscript_session_start"));
        assert!(names.contains(&"nscript_session_status"));
        assert!(names.contains(&"nscript_session_stop"));
    }
}
