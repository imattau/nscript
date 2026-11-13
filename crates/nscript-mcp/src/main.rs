use std::{
    env, fs,
    io::{self, BufRead, Read, Write},
    path::PathBuf,
    process::{Command, Stdio},
    sync::atomic::{AtomicU64, Ordering},
    thread,
    time::{Duration, Instant},
};

use serde_json::{Value, json};

const PROTOCOL_VERSION: &str = "2025-03-26";
const MAX_SOURCE_BYTES: usize = 1_000_000;
const MAX_EVENT_BYTES: usize = 256_000;
const CLI_TIMEOUT: Duration = Duration::from_secs(30);
static NEXT_TEMP: AtomicU64 = AtomicU64::new(0);

fn main() -> io::Result<()> {
    let stdin = io::stdin();
    let mut stdout = io::BufWriter::new(io::stdout().lock());
    for line in stdin.lock().lines() {
        let line = line?;
        if line.trim().is_empty() {
            continue;
        }
        let request: Value = match serde_json::from_str(&line) {
            Ok(request) => request,
            Err(error) => {
                write_message(
                    &mut stdout,
                    json!({
                        "jsonrpc": "2.0",
                        "id": null,
                        "error": {"code": -32700, "message": format!("Parse error: {error}")}
                    }),
                )?;
                continue;
            }
        };
        if let Some(response) = handle(request) {
            write_message(&mut stdout, response)?;
        }
    }
    Ok(())
}

fn write_message(output: &mut impl Write, value: Value) -> io::Result<()> {
    serde_json::to_writer(&mut *output, &value)?;
    output.write_all(b"\n")?;
    output.flush()
}

fn handle(request: Value) -> Option<Value> {
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
            "instructions": "Check, inspect, and simulate NScript source. Simulation uses the NScript CLI simulator and does not publish to relays or access signing keys."
        })),
        "ping" => Ok(json!({})),
        "tools/list" => Ok(json!({"tools": tool_definitions()})),
        "tools/call" => call_tool(&params),
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
        }
    ])
}

fn call_tool(params: &Value) -> Result<Value, (i64, String)> {
    let name = params
        .get("name")
        .and_then(Value::as_str)
        .ok_or((-32602, "tools/call requires a tool name".to_owned()))?;
    if !matches!(
        name,
        "nscript_check" | "nscript_inspect" | "nscript_simulate_event"
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

    let mut temp = TempSource::new(source).map_err(|error| (-32603, error))?;
    let module_dirs = module_dirs(&arguments)?;
    let (mut args, format_json) = match name {
        "nscript_check" => (vec!["check".to_owned()], false),
        "nscript_inspect" => (vec!["inspect".to_owned(), "--json".to_owned()], true),
        "nscript_simulate_event" => {
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
            let mut run = vec!["run".to_owned()];
            if let Some(principal) = arguments.get("principal") {
                let principal = principal.as_str().ok_or((
                    -32602,
                    "principal must be a string when supplied".to_owned(),
                ))?;
                run.extend(["--as".to_owned(), principal.to_owned()]);
            }
            if let Some(inputs) = arguments.get("inputs") {
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
    let output = run_cli(&args).map_err(|error| (-32603, error))?;
    let temp_path = temp.path.display().to_string();
    let stdout = String::from_utf8_lossy(&output.stdout).replace(&temp_path, "<source>");
    let stderr = String::from_utf8_lossy(&output.stderr).replace(&temp_path, "<source>");
    let is_error = !output.status.success();
    let payload = if format_json && !is_error {
        serde_json::from_str::<Value>(&stdout)
            .unwrap_or_else(|_| json!({"output": stdout, "stderr": stderr}))
    } else {
        json!({"success": !is_error, "exit_code": output.status.code(), "output": stdout, "stderr": stderr})
    };
    let text = serde_json::to_string_pretty(&payload).unwrap_or_else(|_| payload.to_string());
    // Drop the temporary source before returning the tool result.
    temp.remove();
    Ok(json!({
        "content": [{"type": "text", "text": text}],
        "structuredContent": if format_json && !is_error { payload } else { json!({"success": !is_error, "exit_code": output.status.code(), "output": stdout, "stderr": stderr}) },
        "isError": is_error
    }))
}

fn module_dirs(arguments: &Value) -> Result<Vec<String>, (i64, String)> {
    let Some(directories) = arguments.get("module_dirs") else {
        return Ok(Vec::new());
    };
    let directories = directories.as_array().ok_or((
        -32602,
        "module_dirs must be an array of directory paths".to_owned(),
    ))?;
    directories
        .iter()
        .map(|directory| {
            directory
                .as_str()
                .map(str::to_owned)
                .ok_or((-32602, "each module_dirs entry must be a string".to_owned()))
        })
        .collect()
}

fn run_cli(arguments: &[String]) -> Result<std::process::Output, String> {
    let executable = if let Some(path) = env::var_os("NSCRIPT_CLI_PATH") {
        PathBuf::from(path)
    } else {
        let current = env::current_exe()
            .map_err(|error| format!("cannot locate nscript-mcp executable: {error}"))?;
        let sibling = current.with_file_name(if cfg!(windows) {
            "nscript.exe"
        } else {
            "nscript"
        });
        if sibling.is_file() {
            sibling
        } else {
            PathBuf::from("nscript")
        }
    };
    let mut child = Command::new(&executable)
        .args(arguments)
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
        if started.elapsed() >= CLI_TIMEOUT {
            let _ = child.kill();
            let _ = child.wait();
            let _ = stdout_reader.join();
            let _ = stderr_reader.join();
            return Err(format!(
                "NScript CLI exceeded the {} second time limit",
                CLI_TIMEOUT.as_secs()
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
                Err(error) if error.kind() == io::ErrorKind::AlreadyExists => continue,
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
