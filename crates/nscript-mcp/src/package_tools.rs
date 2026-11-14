use std::{
    env, fs,
    path::{Path, PathBuf},
    process::{Command, Stdio},
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
    thread,
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};

use serde_json::{Value, json};

use crate::{module_dirs, run_cli};

pub fn call(name: &str, args: &Value, cancelled: &Arc<AtomicBool>) -> Result<Value, (i64, String)> {
    if env::var("NSCRIPT_MCP_NPACK_ENABLED").as_deref() != Ok("true") {
        return Err((
            -32000,
            "npack tools are disabled by server policy (set NSCRIPT_MCP_NPACK_ENABLED=true)".into(),
        ));
    }
    let result = match name {
        "nscript_package_publish" => publish(args, cancelled),
        "nscript_package_search" => run_npack(
            vec![
                "search".into(),
                required(args, "query")?,
                "--provides".into(),
                "nscript-program".into(),
                "--json".into(),
            ],
            cancelled,
        ),
        "nscript_package_resolve" => {
            let mut command = vec![
                "resolve".into(),
                required(args, "package")?,
                "--recursive".into(),
            ];
            let package = command[1].clone();
            if let Some(req) = args.get("version_requirement").and_then(Value::as_str) {
                command.extend(["--requirement".into(), req.into()]);
            }
            let resolved = run_npack(command, cancelled)?;
            ensure_nscript_package(&resolved, &package)?;
            Ok(resolved)
        }
        "nscript_package_install" => {
            let package = required(args, "package")?;
            let resolved = run_npack(vec!["resolve".into(), package.clone()], cancelled)?;
            ensure_nscript_package(&resolved, &package)?;
            run_npack(vec!["install".into(), package, "--user".into()], cancelled)
        }
        "nscript_package_update" => {
            let package = required(args, "package")?;
            let installed = run_npack(
                vec![
                    "list".into(),
                    "--user".into(),
                    "--provides".into(),
                    "nscript-program".into(),
                    "--json".into(),
                ],
                cancelled,
            )?;
            ensure_nscript_installed(&installed, &package)?;
            let resolved = run_npack(vec!["resolve".into(), package.clone()], cancelled)?;
            ensure_nscript_package(&resolved, &package)?;
            run_npack(vec!["update".into(), package, "--user".into()], cancelled)
        }
        "nscript_package_list" => run_npack(
            vec![
                "list".into(),
                "--user".into(),
                "--provides".into(),
                "nscript-program".into(),
                "--json".into(),
            ],
            cancelled,
        ),
        "nscript_package_remove" => {
            let package = required(args, "package")?;
            let installed = run_npack(
                vec![
                    "list".into(),
                    "--user".into(),
                    "--provides".into(),
                    "nscript-program".into(),
                    "--json".into(),
                ],
                cancelled,
            )?;
            ensure_nscript_installed(&installed, &package)?;
            run_npack(vec!["remove".into(), package, "--user".into()], cancelled)
        }
        _ => Err((-32602, format!("unknown package tool: {name}"))),
    };
    result.map(|payload| {
        let error = payload.get("success").and_then(Value::as_bool) == Some(false);
        let body = serde_json::to_string_pretty(&payload).unwrap_or_else(|_| payload.to_string());
        json!({"content":[{"type":"text","text":body}],"structuredContent":payload,"isError":error})
    })
}

#[allow(clippy::too_many_lines)]
fn publish(args: &Value, cancelled: &Arc<AtomicBool>) -> Result<Value, (i64, String)> {
    let source = args
        .get("source")
        .and_then(Value::as_str)
        .ok_or((-32602, "source must be a string".into()))?;
    if source.len() > 1_000_000 {
        return Err((-32602, "source exceeds the 1 MB limit".into()));
    }
    let name = required(args, "name")?;
    if name.len() > 80
        || !name
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"-_.".contains(&b))
    {
        return Err((
            -32602,
            "name may contain only ASCII letters, digits, '.', '_' and '-'".into(),
        ));
    }
    let version = required(args, "version")?;
    if !valid_semver(&version) {
        return Err((-32602, "version must be explicit SemVer".into()));
    }
    let publisher = env::var("NSCRIPT_MCP_NPACK_PUBLISHER").map_err(|_| {
        (
            -32000,
            "NSCRIPT_MCP_NPACK_PUBLISHER must identify the registered npack publisher key".into(),
        )
    })?;
    let directories = module_dirs(args).map_err(|(_, e)| (-32602, e))?;
    let workspace = TempWorkspace::new().map_err(internal)?;
    let root = workspace.path.join("package");
    fs::create_dir_all(root.join(".npack")).map_err(internal)?;
    fs::create_dir_all(root.join("modules")).map_err(internal)?;
    let source_path = root.join("main.ns");
    fs::write(&source_path, source).map_err(internal)?;
    let mut inspect = vec![
        "inspect".into(),
        "--json".into(),
        source_path.display().to_string(),
    ];
    for dir in &directories {
        inspect.extend(["-M".into(), dir.clone()]);
    }
    let inspected = run_cli(&inspect, cancelled).map_err(internal)?;
    if !inspected.status.success() {
        return Err((
            -32602,
            String::from_utf8_lossy(&inspected.stderr).into_owned(),
        ));
    }
    let manifest: Value = serde_json::from_slice(&inspected.stdout)
        .map_err(|e| (-32603, format!("invalid inspect JSON: {e}")))?;
    let resolved = manifest
        .get("resolved_modules")
        .and_then(Value::as_array)
        .cloned()
        .unwrap_or_default();
    if !resolved.is_empty() && !directories.is_empty() {
        let wanted = resolved
            .iter()
            .filter(|v| v.get("origin").and_then(Value::as_str) != Some("builtin"))
            .filter_map(|v| v.get("name").and_then(Value::as_str))
            .collect::<std::collections::HashSet<_>>();
        for dir in &directories {
            copy_resolved_modules(Path::new(dir), &root.join("modules"), &wanted)
                .map_err(internal)?;
        }
    }
    let modules = root.join("modules");
    let lock = root.join("nscript.lock.json");
    let mut lock_args = vec![
        "package".into(),
        "lock".into(),
        source_path.display().to_string(),
        "--output".into(),
        lock.display().to_string(),
    ];
    if modules.exists() {
        lock_args.extend(["-M".into(), modules.display().to_string()]);
    }
    let locked = run_cli(&lock_args, cancelled).map_err(internal)?;
    if !locked.status.success() {
        return Err((-32602, String::from_utf8_lossy(&locked.stderr).into_owned()));
    }
    let verify = vec![
        "package".into(),
        "verify".into(),
        source_path.display().to_string(),
        "--lock".into(),
        lock.display().to_string(),
        "-M".into(),
        modules.display().to_string(),
    ];
    let verified = run_cli(&verify, cancelled).map_err(internal)?;
    if !verified.status.success() {
        return Err((
            -32602,
            String::from_utf8_lossy(&verified.stderr).into_owned(),
        ));
    }
    let artifact_name = format!("{name}-{version}.npk");
    let artifact = workspace.path.join(&artifact_name);
    let summary = args.get("summary").and_then(Value::as_str).unwrap_or("");
    if summary.len() > 500 {
        return Err((-32602, "summary exceeds 500 bytes".into()));
    }
    let embedded = json!({"publisher":publisher,"name":name,"version":version,"artifact":artifact_name,"sha256":"","dependencies":[],"conflicts":[],"artifact_event":null,"os":"any","arch":"any","format":"npk","runtime_requires":["nscript-runtime >=0.1"],"provides":["nscript-program"],"post_install":[],"app":{"summary":summary}});
    fs::write(
        root.join(".npack/manifest.json"),
        serde_json::to_vec_pretty(&embedded).map_err(internal)?,
    )
    .map_err(internal)?;
    let packed = run_npack(
        vec![
            "pack".into(),
            root.display().to_string(),
            "--output".into(),
            artifact.display().to_string(),
            "--strict".into(),
        ],
        cancelled,
    )?;
    if packed.get("success").and_then(Value::as_bool) != Some(true) {
        return Ok(packed);
    }
    let external = workspace.path.join("release.json");
    let manifest_args = vec![
        "package".into(),
        "manifest".into(),
        source_path.display().to_string(),
        "--publisher".into(),
        publisher.clone(),
        "--name".into(),
        name.clone(),
        "--version".into(),
        version.clone(),
        "--artifact".into(),
        artifact.display().to_string(),
        "--hash-artifact".into(),
        "--lock".into(),
        lock.display().to_string(),
        "--output".into(),
        external.display().to_string(),
        "-M".into(),
        modules.display().to_string(),
    ];
    let generated = run_cli(&manifest_args, cancelled).map_err(internal)?;
    if !generated.status.success() {
        return Err((
            -32602,
            String::from_utf8_lossy(&generated.stderr).into_owned(),
        ));
    }
    let mut external_manifest: Value =
        serde_json::from_slice(&fs::read(&external).map_err(internal)?)
            .map_err(|e| (-32603, format!("invalid generated package manifest: {e}")))?;
    external_manifest["artifact"] = json!(artifact_name);
    external_manifest["app"] = json!({"summary":summary});
    fs::write(
        &external,
        serde_json::to_vec_pretty(&external_manifest).map_err(internal)?,
    )
    .map_err(internal)?;
    let publish_result = run_npack(
        vec!["publish".into(), external.display().to_string()],
        cancelled,
    )?;
    if publish_result.get("success").and_then(Value::as_bool) == Some(true) {
        Ok(
            json!({"success":true,"package":name,"version":version,"artifact":artifact_name,"publisher":publisher,"publish":publish_result}),
        )
    } else {
        Ok(publish_result)
    }
}

fn copy_resolved_modules(
    from: &Path,
    to: &Path,
    wanted: &std::collections::HashSet<&str>,
) -> Result<(), String> {
    for entry in fs::read_dir(from)
        .map_err(|e| format!("cannot read module directory {}: {e}", from.display()))?
    {
        let entry = entry.map_err(|e| e.to_string())?;
        let path = entry.path();
        if entry.file_type().map_err(|e| e.to_string())?.is_dir() {
            copy_resolved_modules(&path, to, wanted)?;
            continue;
        }
        if path.extension().and_then(|x| x.to_str()) != Some("nsm") {
            continue;
        }
        let text = fs::read_to_string(&path).map_err(|e| e.to_string())?;
        let (module, diagnostics) = nscript_modules::parse_module(&text);
        let module = module
            .filter(|_| diagnostics.is_empty())
            .ok_or_else(|| format!("invalid module {}", path.display()))?;
        if wanted.contains(module.id.name.as_str()) {
            let target = to.join(format!("{}.nsm", module.id.name));
            fs::write(target, text).map_err(|e| e.to_string())?;
        }
    }
    Ok(())
}

fn ensure_nscript_package(value: &Value, package: &str) -> Result<(), (i64, String)> {
    let wanted = package.rsplit('/').next().unwrap_or(package);
    if value.get("success").and_then(Value::as_bool) != Some(true) {
        return Err((
            -32602,
            "npack could not resolve the package under the current trust policy".into(),
        ));
    }
    let result = value.get("result").unwrap_or(value);
    let entries = result
        .as_array()
        .cloned()
        .unwrap_or_else(|| vec![result.clone()]);
    if entries.iter().any(|entry| {
        entry.get("name").and_then(Value::as_str) == Some(wanted)
            && entry
                .get("provides")
                .and_then(Value::as_array)
                .is_some_and(|values| values.iter().any(|v| v.as_str() == Some("nscript-program")))
    }) {
        Ok(())
    } else {
        Err((
            -32602,
            "resolved package does not declare the nscript-program capability".into(),
        ))
    }
}

fn ensure_nscript_installed(value: &Value, package: &str) -> Result<(), (i64, String)> {
    if value.get("success").and_then(Value::as_bool) != Some(true) {
        return Err((
            -32603,
            "npack could not inspect the user package prefix".into(),
        ));
    }
    let result = value
        .get("result")
        .and_then(Value::as_array)
        .cloned()
        .unwrap_or_default();
    let (wanted_publisher, wanted_name) = package.split_once('/').unwrap_or(("", package));
    if result.iter().any(|item| {
        item.get("name").and_then(Value::as_str) == Some(wanted_name)
            && (wanted_publisher.is_empty()
                || item
                    .get("publisher")
                    .and_then(Value::as_str)
                    .is_some_and(|publisher| publisher == wanted_publisher))
            && item
                .get("provides")
                .and_then(Value::as_array)
                .is_some_and(|values| values.iter().any(|v| v.as_str() == Some("nscript-program")))
    }) {
        Ok(())
    } else {
        Err((
            -32602,
            "package is not an installed nscript-program in the current user's prefix".into(),
        ))
    }
}

fn required(args: &Value, field: &str) -> Result<String, (i64, String)> {
    let value = args
        .get(field)
        .and_then(Value::as_str)
        .ok_or((-32602, format!("{field} must be a string")))?;
    if value.is_empty() || value.len() > 256 {
        return Err((-32602, format!("{field} must be 1 to 256 bytes")));
    }
    Ok(value.to_owned())
}

fn valid_semver(value: &str) -> bool {
    let core = value.split(['-', '+']).next().unwrap_or("");
    let parts = core.split('.').collect::<Vec<_>>();
    parts.len() == 3
        && parts.iter().all(|part| {
            !part.is_empty()
                && part.bytes().all(|b| b.is_ascii_digit())
                && (part == &"0" || !part.starts_with('0'))
        })
}

#[allow(clippy::needless_pass_by_value)]
fn run_npack(arguments: Vec<String>, cancelled: &Arc<AtomicBool>) -> Result<Value, (i64, String)> {
    let executable = env::var_os("NSCRIPT_MCP_NPACK_PATH").unwrap_or_else(|| "npack".into());
    let mut child = Command::new(executable)
        .args(&arguments)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|e| (-32000, format!("cannot start npack: {e}")))?;
    let mut out = child
        .stdout
        .take()
        .ok_or((-32603, "cannot capture npack stdout".to_owned()))?;
    let mut err = child
        .stderr
        .take()
        .ok_or((-32603, "cannot capture npack stderr".to_owned()))?;
    let out_reader = thread::spawn(move || {
        use std::io::Read;
        let mut bytes = Vec::new();
        let _ = out.read_to_end(&mut bytes);
        bytes
    });
    let err_reader = thread::spawn(move || {
        use std::io::Read;
        let mut bytes = Vec::new();
        let _ = err.read_to_end(&mut bytes);
        bytes
    });
    let start = Instant::now();
    let timeout = env::var("NSCRIPT_MCP_NPACK_TIMEOUT_SECS")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(120_u64);
    loop {
        if let Some(status) = child.try_wait().map_err(|e| (-32603, e.to_string()))? {
            let stdout = String::from_utf8_lossy(
                &out_reader
                    .join()
                    .map_err(|_| (-32603, "npack stdout reader failed".to_owned()))?,
            )
            .trim()
            .to_owned();
            let stderr = String::from_utf8_lossy(
                &err_reader
                    .join()
                    .map_err(|_| (-32603, "npack stderr reader failed".to_owned()))?,
            )
            .trim()
            .to_owned();
            if stdout.len() > 4_000_000 || stderr.len() > 1_000_000 {
                return Err((
                    -32000,
                    "npack output exceeded the MCP response size limit".into(),
                ));
            }
            let payload =
                serde_json::from_str::<Value>(&stdout).unwrap_or_else(|_| json!({"output":stdout}));
            return Ok(
                json!({"success":status.success(),"exit_code":status.code(),"result":payload,"stderr":stderr}),
            );
        }
        if cancelled.load(Ordering::Relaxed) || start.elapsed() >= Duration::from_secs(timeout) {
            let _ = child.kill();
            let _ = child.wait();
            let _ = out_reader.join();
            let _ = err_reader.join();
            return Err((
                -32000,
                if cancelled.load(Ordering::Relaxed) {
                    "request cancelled".into()
                } else {
                    format!("npack exceeded the {timeout} second time limit")
                },
            ));
        }
        thread::sleep(Duration::from_millis(30));
    }
}

#[allow(clippy::needless_pass_by_value)]
fn internal(error: impl ToString) -> (i64, String) {
    (-32603, error.to_string())
}

struct TempWorkspace {
    path: PathBuf,
}
impl TempWorkspace {
    fn new() -> Result<Self, String> {
        let base = env::temp_dir();
        for nonce in 0..16 {
            let stamp = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap_or_default()
                .as_nanos();
            let path = base.join(format!(
                "nscript-mcp-package-{}-{stamp}-{nonce}",
                std::process::id()
            ));
            #[cfg(unix)]
            {
                use std::os::unix::fs::DirBuilderExt;
                let mut builder = fs::DirBuilder::new();
                builder.mode(0o700);
                match builder.create(&path) {
                    Ok(()) => return Ok(Self { path }),
                    Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {}
                    Err(e) => return Err(e.to_string()),
                }
            }
            #[cfg(not(unix))]
            {
                match fs::create_dir(&path) {
                    Ok(()) => return Ok(Self { path }),
                    Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {}
                    Err(e) => return Err(e.to_string()),
                }
            }
        }
        Err("could not create temporary package workspace".into())
    }
}
impl Drop for TempWorkspace {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.path);
    }
}
