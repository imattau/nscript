use std::{
    env, fs,
    fs::OpenOptions,
    io::Write,
    path::{Path, PathBuf},
    process::{Command, Stdio},
    sync::{
        Arc,
        atomic::{AtomicBool, AtomicU64, Ordering},
    },
    thread,
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use serde_json::{Map, Value, json};

static NEXT_SESSION: AtomicU64 = AtomicU64::new(0);
const MAX_SESSIONS: usize = 32;

struct LiveConfig {
    relays: Vec<String>,
    allowed_relays: Vec<String>,
    signers: Map<String, Value>,
    inputs: Map<String, Value>,
    operation_command: Option<String>,
    event_webhook_url: Option<String>,
    event_webhook_token: Option<String>,
}

fn live_config() -> Result<LiveConfig, String> {
    if env::var("NSCRIPT_MCP_LIVE_ENABLED").as_deref() != Ok("true") {
        return Err("live execution is disabled; set NSCRIPT_MCP_LIVE_ENABLED=true".to_owned());
    }
    let relays = env_json::<Vec<String>>("NSCRIPT_MCP_RELAYS")?.unwrap_or_default();
    if relays.is_empty() {
        return Err("configure at least one relay in NSCRIPT_MCP_RELAYS".to_owned());
    }
    let allowed_relays =
        env_json::<Vec<String>>("NSCRIPT_MCP_ALLOWED_RELAYS")?.unwrap_or_else(|| relays.clone());
    let signers = env_json::<Map<String, Value>>("NSCRIPT_MCP_SIGNERS")?.unwrap_or_default();
    let inputs = env_json::<Map<String, Value>>("NSCRIPT_MCP_INPUTS")?.unwrap_or_default();
    let operation_command = env::var("NSCRIPT_MCP_OPERATION_COMMAND").ok();
    let event_webhook_url = env::var("NSCRIPT_MCP_EVENT_WEBHOOK_URL").ok();
    let event_webhook_token = env::var("NSCRIPT_MCP_EVENT_WEBHOOK_TOKEN").ok();
    if event_webhook_url.is_some() != event_webhook_token.is_some() {
        return Err(
            "configure both NSCRIPT_MCP_EVENT_WEBHOOK_URL and NSCRIPT_MCP_EVENT_WEBHOOK_TOKEN"
                .to_owned(),
        );
    }
    if let Some(url) = &event_webhook_url {
        let lower = url.to_ascii_lowercase();
        if url.contains('@')
            || !(lower.starts_with("http://127.0.0.1:")
                || lower.starts_with("http://localhost:")
                || lower.starts_with("http://[::1]:"))
        {
            return Err("NSCRIPT_MCP_EVENT_WEBHOOK_URL must use loopback HTTP".to_owned());
        }
    }
    Ok(LiveConfig {
        relays,
        allowed_relays,
        signers,
        inputs,
        operation_command,
        event_webhook_url,
        event_webhook_token,
    })
}

fn env_json<T: serde::de::DeserializeOwned>(name: &str) -> Result<Option<T>, String> {
    env::var(name)
        .ok()
        .map(|value| {
            serde_json::from_str(&value).map_err(|error| format!("invalid {name}: {error}"))
        })
        .transpose()
}

fn select_relays(arguments: &Value, config: &LiveConfig) -> Result<Vec<String>, String> {
    let requested = arguments
        .get("relays")
        .map(|value| {
            value
                .as_array()
                .ok_or_else(|| "relays must be an array of configured relay URLs".to_owned())?
                .iter()
                .map(|value| {
                    value
                        .as_str()
                        .map(str::to_owned)
                        .ok_or_else(|| "each relay must be a string".to_owned())
                })
                .collect::<Result<Vec<_>, _>>()
        })
        .transpose()?
        .unwrap_or_else(|| config.relays.clone());
    if requested.is_empty() {
        return Err("at least one relay must be selected".to_owned());
    }
    for relay in &requested {
        if !config.allowed_relays.contains(relay) {
            return Err(format!("relay is not permitted by server policy: {relay}"));
        }
    }
    Ok(requested)
}

fn selected_signers(
    arguments: &Value,
    config: &LiveConfig,
) -> Result<Vec<(String, String)>, String> {
    let Some(value) = arguments.get("signer_refs") else {
        return Ok(Vec::new());
    };
    let refs = value
        .as_array()
        .ok_or_else(|| "signer_refs must be an array of configured signer names".to_owned())?;
    refs.iter()
        .map(|value| {
            let name = value
                .as_str()
                .ok_or_else(|| "each signer reference must be a string".to_owned())?;
            let uri = config
                .signers
                .get(name)
                .and_then(Value::as_str)
                .ok_or_else(|| format!("signer `{name}` is not configured on the MCP server"))?;
            Ok((name.to_owned(), uri.to_owned()))
        })
        .collect()
}

#[allow(clippy::too_many_arguments)]
fn make_deploy_args(
    source_path: &Path,
    arguments: &Value,
    directories: &[String],
    relays: &[String],
    signers: &[(String, String)],
    config: &LiveConfig,
    state_dir: Option<&Path>,
    one_cycle: bool,
) -> Result<Vec<String>, String> {
    let mut args = vec!["deploy".to_owned()];
    for relay in relays {
        args.extend(["--relay".to_owned(), relay.clone()]);
    }
    for (name, _) in signers {
        args.extend([
            "--signer-env".to_owned(),
            format!("{name}={}", signer_environment_name(name)?),
        ]);
    }
    let principal = arguments.get("principal").filter(|value| !value.is_null());
    if principal.is_none() {
        let selected = arguments
            .get("principal_signer")
            .and_then(Value::as_str)
            .map(str::to_owned)
            .or_else(|| (signers.len() == 1).then(|| signers[0].0.clone()));
        if let Some(name) = selected {
            if !signers.iter().any(|(selected, _)| selected == &name) {
                return Err(format!(
                    "principal signer `{name}` must be included in signer_refs"
                ));
            }
            args.extend(["--as-signer".to_owned(), name]);
        }
    }
    if let Some(principal) = principal {
        let principal = principal
            .as_str()
            .ok_or_else(|| "principal must be a string".to_owned())?;
        args.extend(["--as".to_owned(), principal.to_owned()]);
    }
    if let Some(inputs) = arguments.get("inputs") {
        let inputs = inputs
            .as_object()
            .ok_or_else(|| "inputs must be an object of scalar values".to_owned())?;
        for (name, value) in inputs {
            let raw = scalar_input(name, value)?;
            args.extend(["--input".to_owned(), format!("{name}={raw}")]);
        }
    }
    if let Some(input_refs) = arguments.get("input_refs") {
        let input_refs = input_refs
            .as_object()
            .ok_or_else(|| "input_refs must map input names to configured references".to_owned())?;
        for (name, reference) in input_refs {
            let reference = reference
                .as_str()
                .ok_or_else(|| "input_refs values must be configured reference names".to_owned())?;
            let value = config
                .inputs
                .get(reference)
                .ok_or_else(|| format!("input reference `{reference}` is not configured"))?;
            scalar_input(name, value)?;
            args.extend([
                "--input-env".to_owned(),
                format!("{name}={}", input_environment_name(name)?),
            ]);
        }
    }
    if let Some(command) = &config.operation_command {
        args.extend(["--operation-command".to_owned(), command.clone()]);
    }
    if let Some(state_dir) = state_dir {
        args.extend(["--state-dir".to_owned(), state_dir.display().to_string()]);
    }
    if one_cycle {
        args.extend(["--cycles".to_owned(), "1".to_owned()]);
        args.extend(["--poll-interval".to_owned(), "1".to_owned()]);
    }
    for directory in directories {
        args.extend(["-M".to_owned(), directory.clone()]);
    }
    args.push(source_path.display().to_string());
    Ok(args)
}

fn signer_environment_name(name: &str) -> Result<String, String> {
    if name.is_empty()
        || !name
            .chars()
            .all(|ch| ch.is_ascii_alphanumeric() || ch == '_')
    {
        return Err(format!(
            "signer reference `{name}` cannot map to a safe environment name"
        ));
    }
    Ok(format!("NSCRIPT_MCP_SIGNER_{}", name.to_ascii_uppercase()))
}

fn input_environment_name(name: &str) -> Result<String, String> {
    if name.is_empty()
        || !name
            .chars()
            .all(|ch| ch.is_ascii_alphanumeric() || ch == '_')
    {
        return Err(format!(
            "input name `{name}` cannot map to a safe environment name"
        ));
    }
    Ok(format!("NSCRIPT_MCP_INPUT_{}", name.to_ascii_uppercase()))
}

fn signer_environment(signers: &[(String, String)]) -> Result<Vec<(String, String)>, String> {
    let mut output = Vec::with_capacity(signers.len());
    for (name, uri) in signers {
        let variable = signer_environment_name(name)?;
        if output.iter().any(|(existing, _)| existing == &variable) {
            return Err(format!(
                "signer references collide on environment variable `{variable}`"
            ));
        }
        output.push((variable, uri.clone()));
    }
    Ok(output)
}

fn input_environment(
    arguments: &Value,
    config: &LiveConfig,
) -> Result<Vec<(String, String)>, String> {
    let Some(refs) = arguments.get("input_refs") else {
        return Ok(Vec::new());
    };
    let refs = refs
        .as_object()
        .ok_or_else(|| "input_refs must map input names to configured references".to_owned())?;
    let mut output = Vec::with_capacity(refs.len());
    for (name, reference) in refs {
        let reference = reference
            .as_str()
            .ok_or_else(|| "input_refs values must be configured reference names".to_owned())?;
        let value = config
            .inputs
            .get(reference)
            .ok_or_else(|| format!("input reference `{reference}` is not configured"))?;
        let raw = scalar_input(name, value)?;
        let variable = input_environment_name(name)?;
        if output.iter().any(|(existing, _)| existing == &variable) {
            return Err(format!(
                "input names collide on environment variable `{variable}`"
            ));
        }
        output.push((variable, raw));
    }
    Ok(output)
}

fn scalar_input(name: &str, value: &Value) -> Result<String, String> {
    match value {
        Value::String(value) => Ok(value.clone()),
        Value::Number(value) if value.as_i64().is_some() => Ok(value.to_string()),
        Value::Bool(value) => Ok(value.to_string()),
        _ => Err(format!(
            "input `{name}` must be a string, integer, or boolean"
        )),
    }
}

pub(crate) fn execute_once(
    arguments: &Value,
    directories: &[String],
    cancelled: &Arc<AtomicBool>,
) -> Result<Value, String> {
    let config = live_config()?;
    let relays = select_relays(arguments, &config)?;
    let signers = selected_signers(arguments, &config)?;
    let source = arguments
        .get("source")
        .and_then(Value::as_str)
        .ok_or_else(|| "source must be a string".to_owned())?;
    if arguments.get("event").is_some() {
        return Err("live execution consumes relay events; omit the synthetic event".to_owned());
    }
    let source_path = unique_temp_source(source)?;
    let result = (|| {
        let args = make_deploy_args(
            &source_path,
            arguments,
            directories,
            &relays,
            &signers,
            &config,
            None,
            true,
        )?;
        let mut signer_env = signer_environment(&signers)?;
        signer_env.extend(input_environment(arguments, &config)?);
        crate::run_cli_with_env(&args, cancelled, &signer_env)
    })();
    let _ = fs::remove_file(source_path);
    let output = result?;
    Ok(json!({
        "exit_code": output.status.code(),
        "success": output.status.success(),
        "stdout": String::from_utf8_lossy(&output.stdout),
        "stderr": String::from_utf8_lossy(&output.stderr),
        "mode": "live",
    }))
}

fn unique_temp_source(source: &str) -> Result<PathBuf, String> {
    let path = env::temp_dir().join(format!(
        "nscript-mcp-live-{}-{}.ns",
        std::process::id(),
        NEXT_SESSION.fetch_add(1, Ordering::Relaxed)
    ));
    write_private_file(&path, source.as_bytes())?;
    Ok(path)
}

fn write_private_file(path: &Path, contents: &[u8]) -> Result<(), String> {
    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt as _;
        options.mode(0o600);
    }
    let mut file = options
        .open(path)
        .map_err(|error| format!("cannot create {}: {error}", path.display()))?;
    file.write_all(contents)
        .map_err(|error| format!("cannot write {}: {error}", path.display()))
}

fn state_root() -> Result<PathBuf, String> {
    if let Some(path) = env::var_os("NSCRIPT_MCP_STATE_DIR") {
        return Ok(PathBuf::from(path));
    }
    #[cfg(windows)]
    let base = env::var_os("LOCALAPPDATA").map(PathBuf::from);
    #[cfg(not(windows))]
    let base = env::var_os("XDG_STATE_HOME")
        .map(PathBuf::from)
        .or_else(|| env::var_os("HOME").map(|home| PathBuf::from(home).join(".local/state")));
    base.map(|path| path.join("nscript-mcp"))
        .ok_or_else(|| "set NSCRIPT_MCP_STATE_DIR to persist MCP sessions".to_owned())
}

fn session_root() -> Result<PathBuf, String> {
    let path = state_root()?.join("sessions");
    fs::create_dir_all(&path).map_err(|error| format!("cannot create session store: {error}"))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        fs::set_permissions(&path, fs::Permissions::from_mode(0o700))
            .map_err(|error| format!("cannot protect session store: {error}"))?;
    }
    Ok(path)
}

fn session_file(root: &Path, id: &str) -> Result<PathBuf, String> {
    if id.is_empty() || !id.chars().all(|ch| ch.is_ascii_alphanumeric() || ch == '-') {
        return Err("invalid session_id".to_owned());
    }
    Ok(root.join(format!("{id}.json")))
}

fn save_record(path: &Path, record: &Value) -> Result<(), String> {
    let bytes = serde_json::to_vec_pretty(record).map_err(|error| error.to_string())?;
    let temporary = path.with_extension(format!(
        "json.{}.{}.tmp",
        std::process::id(),
        NEXT_SESSION.fetch_add(1, Ordering::Relaxed)
    ));
    write_private_file(&temporary, &bytes)?;
    if let Err(error) = fs::rename(&temporary, path) {
        let _ = fs::remove_file(temporary);
        return Err(format!("cannot persist session: {error}"));
    }
    Ok(())
}

fn spawn_record(record: &Value, config: &LiveConfig) -> Result<u32, String> {
    let source_path = record
        .get("source_path")
        .and_then(Value::as_str)
        .ok_or_else(|| "session record has no source path".to_owned())?;
    let directories = record
        .get("module_dirs")
        .and_then(Value::as_array)
        .map(|values| {
            values
                .iter()
                .filter_map(Value::as_str)
                .map(str::to_owned)
                .collect::<Vec<_>>()
        })
        .unwrap_or_default();
    let relays = record
        .get("relays")
        .and_then(Value::as_array)
        .map(|values| {
            values
                .iter()
                .filter_map(Value::as_str)
                .map(str::to_owned)
                .collect::<Vec<_>>()
        })
        .unwrap_or_default();
    let signer_refs = record
        .get("signer_refs")
        .cloned()
        .unwrap_or_else(|| json!([]));
    let args_value = json!({
        "principal": record.get("principal"),
        "principal_signer": record.get("principal_signer"),
        "inputs": record.get("inputs"),
        "input_refs": record.get("input_refs"),
        "signer_refs": signer_refs,
    });
    let signers = selected_signers(&args_value, config)?;
    let mut signer_env = signer_environment(&signers)?;
    signer_env.extend(input_environment(&args_value, config)?);
    let state_dir = record
        .get("state_path")
        .and_then(Value::as_str)
        .map(PathBuf::from)
        .ok_or_else(|| "session record has no state path".to_owned())?;
    let args = make_deploy_args(
        Path::new(source_path),
        &args_value,
        &directories,
        &relays,
        &signers,
        config,
        Some(&state_dir),
        false,
    )?;
    let log_path = record
        .get("log_path")
        .and_then(Value::as_str)
        .ok_or_else(|| "session record has no log path".to_owned())?;
    let mut log_options = OpenOptions::new();
    log_options.create(true).append(true).write(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt as _;
        log_options.mode(0o600);
    }
    let log = log_options
        .open(log_path)
        .map_err(|error| format!("cannot open session log: {error}"))?;
    let stderr = log
        .try_clone()
        .map_err(|error| format!("cannot clone session log: {error}"))?;
    let cli = crate::cli_path().map_err(|error| error.to_string())?;
    let child = Command::new(cli)
        .args(args)
        .stdin(Stdio::null())
        .stdout(Stdio::from(log))
        .stderr(Stdio::from(stderr))
        .envs(signer_env)
        .envs(
            config
                .event_webhook_url
                .iter()
                .map(|url| ("NSCRIPT_MCP_EVENT_WEBHOOK_URL", url)),
        )
        .envs(
            config
                .event_webhook_token
                .iter()
                .map(|token| ("NSCRIPT_MCP_EVENT_WEBHOOK_TOKEN", token)),
        )
        .env(
            "NSCRIPT_MCP_SESSION_ID",
            record["id"].as_str().unwrap_or_default(),
        )
        .spawn()
        .map_err(|error| format!("cannot start nscript deploy: {error}"))?;
    Ok(child.id())
}

pub(crate) fn start(arguments: &Value, directories: &[String]) -> Result<Value, String> {
    let config = live_config()?;
    let relays = select_relays(arguments, &config)?;
    let signer_refs = arguments
        .get("signer_refs")
        .cloned()
        .unwrap_or_else(|| json!([]));
    let signers = selected_signers(&json!({"signer_refs":signer_refs}), &config)?;
    validate_durable_session_inputs(arguments, &config)?;
    let source = arguments
        .get("source")
        .and_then(Value::as_str)
        .ok_or_else(|| "source must be a string".to_owned())?;
    let root = session_root()?;
    let count = fs::read_dir(&root)
        .map_err(|error| error.to_string())?
        .filter_map(Result::ok)
        .filter(|entry| entry.path().extension().is_some_and(|ext| ext == "json"))
        .filter(|entry| {
            fs::read(entry.path())
                .ok()
                .and_then(|bytes| serde_json::from_slice::<Value>(&bytes).ok())
                .is_some_and(|record| record["desired_running"] == true)
        })
        .count();
    if count >= MAX_SESSIONS {
        return Err(format!("session limit reached ({MAX_SESSIONS})"));
    }
    let stamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis();
    let id = format!(
        "{}-{stamp}-{}",
        std::process::id(),
        NEXT_SESSION.fetch_add(1, Ordering::Relaxed)
    );
    let source_path = root.join(format!("{id}.ns"));
    write_private_file(&source_path, source.as_bytes())?;
    let state_path = root.join(&id);
    fs::create_dir_all(&state_path).map_err(|error| {
        let _ = fs::remove_file(&source_path);
        error.to_string()
    })?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        fs::set_permissions(&state_path, fs::Permissions::from_mode(0o700)).map_err(|error| {
            let _ = fs::remove_file(&source_path);
            let _ = fs::remove_dir_all(&state_path);
            format!("cannot protect session state: {error}")
        })?;
    }
    let log_path = root.join(format!("{id}.log"));
    let record_path = session_file(&root, &id)?;
    let record = json!({
        "id": id,
        "status": "starting",
        "desired_running": true,
        "pid": null,
        "source_path": source_path,
        "log_path": log_path,
        "state_path": state_path,
        "relays": relays,
        "signer_refs": signers.iter().map(|(name, _)| name).collect::<Vec<_>>(),
        "principal": arguments.get("principal"),
        "principal_signer": arguments.get("principal_signer"),
        "inputs": arguments.get("inputs").cloned().unwrap_or_else(|| json!({})),
        "input_refs": arguments.get("input_refs").cloned().unwrap_or_else(|| json!({})),
        "module_dirs": directories,
    });
    save_record(&record_path, &record)?;
    match spawn_record(&record, &config) {
        Ok(pid) => {
            let mut record = record;
            record["pid"] = json!(pid);
            record["status"] = json!("running");
            if let Err(error) = save_record(&record_path, &record) {
                let _ = terminate_process(pid);
                let _ = fs::remove_file(&record_path);
                let _ = fs::remove_file(source_path);
                return Err(error);
            }
            Ok(json!({"session_id":id,"status":"running","pid":pid}))
        }
        Err(error) => {
            let _ = fs::remove_file(&record_path);
            let _ = fs::remove_file(source_path);
            Err(error)
        }
    }
}

fn validate_durable_session_inputs(arguments: &Value, config: &LiveConfig) -> Result<(), String> {
    input_environment(arguments, config)?;
    let raw_inputs = arguments
        .get("inputs")
        .and_then(Value::as_object)
        .cloned()
        .unwrap_or_default();
    for name in raw_inputs.keys() {
        let lower = name.to_ascii_lowercase();
        if [
            "secret",
            "token",
            "password",
            "passwd",
            "credential",
            "api_key",
            "private_key",
        ]
        .iter()
        .any(|marker| lower.contains(marker))
        {
            return Err(format!(
                "durable session input `{name}` looks secret-bearing; configure it in NSCRIPT_MCP_INPUTS and pass its name through input_refs"
            ));
        }
    }
    if let Some(refs) = arguments.get("input_refs") {
        let refs = refs
            .as_object()
            .ok_or_else(|| "input_refs must map input names to configured references".to_owned())?;
        if refs.keys().any(|name| raw_inputs.contains_key(name)) {
            return Err("an input cannot have both a raw value and an input_ref".to_owned());
        }
    }
    Ok(())
}

fn process_alive(pid: u32) -> bool {
    #[cfg(unix)]
    {
        Command::new("kill")
            .args(["-0", &pid.to_string()])
            .status()
            .is_ok_and(|status| status.success())
    }
    #[cfg(windows)]
    {
        Command::new("tasklist")
            .args(["/FI", &format!("PID eq {pid}"), "/FO", "CSV", "/NH"])
            .output()
            .is_ok_and(|output| String::from_utf8_lossy(&output.stdout).contains(&pid.to_string()))
    }
}

fn process_matches_record(pid: u32, record: &Value) -> bool {
    let source_path = record["source_path"].as_str().unwrap_or_default();
    if source_path.is_empty() || !process_alive(pid) {
        return false;
    }
    #[cfg(unix)]
    {
        Command::new("ps")
            .args(["-p", &pid.to_string(), "-o", "command="])
            .output()
            .is_ok_and(|output| {
                let command = String::from_utf8_lossy(&output.stdout);
                command.contains("deploy") && command.contains(source_path)
            })
    }
    #[cfg(windows)]
    {
        let query =
            format!("(Get-CimInstance Win32_Process -Filter 'ProcessId = {pid}').CommandLine");
        Command::new("powershell")
            .args(["-NoProfile", "-NonInteractive", "-Command", &query])
            .output()
            .is_ok_and(|output| {
                let command = String::from_utf8_lossy(&output.stdout);
                command.contains("deploy") && command.contains(source_path)
            })
    }
}

pub(crate) fn status(arguments: &Value) -> Result<Value, String> {
    let id = arguments
        .get("session_id")
        .and_then(Value::as_str)
        .ok_or_else(|| "session_id must be a string".to_owned())?;
    let root = session_root()?;
    let path = session_file(&root, id)?;
    let mut record: Value = serde_json::from_slice(
        &fs::read(&path).map_err(|error| format!("cannot read session: {error}"))?,
    )
    .map_err(|error| format!("invalid session record: {error}"))?;
    if record["desired_running"] == true {
        let pid = record["pid"]
            .as_u64()
            .and_then(|value| u32::try_from(value).ok());
        if pid.is_some_and(|pid| process_matches_record(pid, &record)) {
            record["status"] = json!("running");
        } else {
            record["status"] = json!("exited");
        }
        save_record(&path, &record)?;
    }
    let log_path = record["log_path"].as_str().unwrap_or_default();
    let log = fs::read(log_path).unwrap_or_default();
    let tail = String::from_utf8_lossy(&log[log.len().saturating_sub(16_000)..]);
    Ok(json!({
        "session_id":id,
        "status":record["status"],
        "pid":record["pid"],
        "log_tail":tail,
    }))
}

pub(crate) fn stop(arguments: &Value) -> Result<Value, String> {
    let id = arguments
        .get("session_id")
        .and_then(Value::as_str)
        .ok_or_else(|| "session_id must be a string".to_owned())?;
    let root = session_root()?;
    let path = session_file(&root, id)?;
    let mut record: Value = serde_json::from_slice(
        &fs::read(&path).map_err(|error| format!("cannot read session: {error}"))?,
    )
    .map_err(|error| format!("invalid session record: {error}"))?;
    if let Some(pid) = record["pid"]
        .as_u64()
        .and_then(|value| u32::try_from(value).ok())
        && process_matches_record(pid, &record)
    {
        terminate_process(pid)?;
    }
    record["desired_running"] = json!(false);
    record["status"] = json!("stopped");
    save_record(&path, &record)?;
    Ok(json!({"session_id":id,"status":"stopped"}))
}

fn terminate_process(pid: u32) -> Result<(), String> {
    #[cfg(unix)]
    let status = Command::new("kill")
        .args(["-TERM", &pid.to_string()])
        .status();
    #[cfg(windows)]
    let status = Command::new("taskkill")
        .args(["/PID", &pid.to_string(), "/T", "/F"])
        .status();
    if !status.is_ok_and(|status| status.success()) {
        return Err(format!("could not stop session process {pid}"));
    }
    for _ in 0..40 {
        if !process_alive(pid) {
            return Ok(());
        }
        thread::sleep(Duration::from_millis(50));
    }
    Err(format!("session process {pid} did not stop in time"))
}

pub(crate) fn resume_all() {
    let Ok(root) = session_root() else {
        return;
    };
    let Ok(entries) = fs::read_dir(&root) else {
        return;
    };
    let config = live_config();
    for entry in entries.flatten() {
        if entry.path().extension().is_none_or(|ext| ext != "json") {
            continue;
        }
        let Ok(bytes) = fs::read(entry.path()) else {
            continue;
        };
        let Ok(mut record) = serde_json::from_slice::<Value>(&bytes) else {
            continue;
        };
        if record["desired_running"] != true {
            continue;
        }
        let pid = record["pid"]
            .as_u64()
            .and_then(|value| u32::try_from(value).ok());
        let alive = pid.is_some_and(|pid| process_matches_record(pid, &record));
        if config.is_err() {
            if let Some(pid) = pid.filter(|_| alive) {
                let _ = terminate_process(pid);
            }
            record["status"] = json!("blocked");
            record["last_error"] = json!(
                config
                    .as_ref()
                    .err()
                    .map_or("live host unavailable", String::as_str)
            );
            let _ = save_record(&entry.path(), &record);
            continue;
        }
        let config = config.as_ref().expect("checked configuration above");
        if alive {
            record["status"] = json!("running");
        } else {
            match spawn_record(&record, config) {
                Ok(pid) => {
                    record["pid"] = json!(pid);
                    record["status"] = json!("running");
                }
                Err(error) => {
                    record["status"] = json!("blocked");
                    record["last_error"] = json!(error);
                }
            }
        }
        let _ = save_record(&entry.path(), &record);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn configured_input_references_resolve_to_child_environment_values() {
        let config = LiveConfig {
            relays: vec!["wss://relay.example".to_owned()],
            allowed_relays: vec!["wss://relay.example".to_owned()],
            signers: Map::new(),
            inputs: Map::from_iter([("api-token".to_owned(), json!("secret-value"))]),
            operation_command: None,
            event_webhook_url: None,
            event_webhook_token: None,
        };
        let environment =
            input_environment(&json!({"input_refs":{"api_token":"api-token"}}), &config)
                .expect("configured reference resolves");
        assert_eq!(
            environment,
            vec![(
                "NSCRIPT_MCP_INPUT_API_TOKEN".to_owned(),
                "secret-value".to_owned()
            )]
        );
    }

    #[test]
    fn a_single_selected_signer_supplies_the_deploy_principal() {
        let config = LiveConfig {
            relays: vec!["wss://relay.example".to_owned()],
            allowed_relays: vec!["wss://relay.example".to_owned()],
            signers: Map::from_iter([("bot".to_owned(), json!("bunker://example"))]),
            inputs: Map::new(),
            operation_command: None,
            event_webhook_url: None,
            event_webhook_token: None,
        };
        let signers =
            selected_signers(&json!({"signer_refs":["bot"]}), &config).expect("signer resolves");
        let args = make_deploy_args(
            Path::new("bot.ns"),
            &json!({"signer_refs":["bot"]}),
            &[],
            &["wss://relay.example".to_owned()],
            &signers,
            &config,
            None,
            true,
        )
        .expect("deploy args build");
        assert!(
            args.windows(2).any(|pair| pair == ["--as-signer", "bot"]),
            "{args:?}"
        );
    }
}
