use std::{
    env,
    fmt::Write as _,
    fs,
    path::{Path, PathBuf},
    process::ExitCode,
};

use nscript_modules::{ModuleDependency, ModuleRegistry, ResolutionError, hash_hex, parse_module};
use nscript_semantics::{analyze_with_modules, check};
use nscript_syntax::{Diagnostic, Program, parse_program};
use semver::VersionReq;
use sha2::{Digest, Sha256};

fn main() -> ExitCode {
    let arguments = env::args().skip(1).collect::<Vec<_>>();
    match arguments.as_slice() {
        [command, rest @ ..] if command == "check" => check_program(rest),
        [command, format, rest @ ..] if command == "inspect" && format == "--json" => {
            inspect_program(rest, true)
        }
        [command, rest @ ..] if command == "inspect" => inspect_program(rest, false),
        [command, rest @ ..] if command == "run" => run_program(rest),
        [command, rest @ ..] if command == "test-event" => test_event(rest),
        [package, manifest, rest @ ..] if package == "package" && manifest == "manifest" => {
            package_manifest(rest)
        }
        [package, lock, rest @ ..] if package == "package" && lock == "lock" => package_lock(rest),
        [package, verify, rest @ ..] if package == "package" && verify == "verify" => {
            package_verify(rest)
        }
        [command, emit, format, rest @ ..]
            if command == "compile" && emit == "--emit" && format == "ir" =>
        {
            compile_program(rest, false)
        }
        [command, emit, format, rest @ ..]
            if command == "compile" && emit == "--emit" && format == "wasm" =>
        {
            compile_program(rest, true)
        }
        [module, command, path] if module == "module" && command == "check" => {
            check_module(path, false)
        }
        [module, command, path] if module == "module" && command == "hash" => {
            check_module(path, true)
        }
        [module, command, path] if module == "module" && command == "describe" => {
            describe_module(path)
        }
        _ => {
            eprintln!(
                "usage:\n  nscript check [-M <directory>]... <file>\n  nscript inspect [--json] [-M <directory>]... <file>\n  nscript run [--dry-run] [-M <directory>]... <file> [--event <json>]... [--events <file>] [--as <key>] [--fail <module.operation>]...\n  nscript test-event [-M <directory>]... <file> --event <json> [--as <key>] [--fail <module.operation>]...\n  nscript package manifest <file> --publisher <npub> --name <name> --version <semver> --artifact <file.npk> [--sha256 <hash>] [--hash-artifact] [--lock <file>] [--output <file>]\n  nscript package lock <file> [-M <directory>]... [--output <file>]\n  nscript package verify <file> --lock <file> [-M <directory>]...\n  nscript compile --emit ir|wasm [-M <directory>]... <file> [--output <file>]\n  nscript module check <file.nsm>\n  nscript module hash <file.nsm>\n  nscript module describe <file.nsm>"
            );
            ExitCode::from(2)
        }
    }
}

#[allow(clippy::too_many_lines)]
fn package_manifest(arguments: &[String]) -> ExitCode {
    let Some(source) = arguments.iter().find(|item| {
        Path::new(item)
            .extension()
            .is_some_and(|extension| extension.eq_ignore_ascii_case("ns"))
    }) else {
        eprintln!("package manifest requires an NScript source file");
        return ExitCode::from(2);
    };
    let flag = |name: &str| {
        arguments
            .windows(2)
            .find(|pair| pair[0] == name)
            .map(|pair| pair[1].clone())
    };
    let Some(publisher) = flag("--publisher") else {
        eprintln!("package manifest requires --publisher");
        return ExitCode::from(2);
    };
    let Some(name) = flag("--name") else {
        eprintln!("package manifest requires --name");
        return ExitCode::from(2);
    };
    let Some(version) = flag("--version") else {
        eprintln!("package manifest requires --version");
        return ExitCode::from(2);
    };
    if semver::Version::parse(&version).is_err() {
        eprintln!("package manifest requires a valid SemVer version");
        return ExitCode::from(2);
    }
    let Some(artifact) = flag("--artifact") else {
        eprintln!("package manifest requires --artifact");
        return ExitCode::from(2);
    };
    let sha256 = if let Some(value) = flag("--sha256") {
        value
    } else if arguments
        .iter()
        .any(|argument| argument == "--hash-artifact")
    {
        let Ok(contents) = fs::read(&artifact) else {
            eprintln!("could not read artifact for hashing: {artifact}");
            return ExitCode::from(1);
        };
        let digest = Sha256::digest(contents);
        let mut fingerprint = String::with_capacity(64);
        for byte in digest {
            write!(&mut fingerprint, "{byte:02x}").expect("writing to a string cannot fail");
        }
        fingerprint
    } else {
        String::new()
    };
    if !sha256.is_empty()
        && (sha256.len() != 64 || !sha256.bytes().all(|byte| byte.is_ascii_hexdigit()))
    {
        eprintln!("--sha256 must be 64 hexadecimal characters");
        return ExitCode::from(2);
    }
    let lock_metadata = if let Some(lock_path) = flag("--lock") {
        let Ok(contents) = fs::read_to_string(&lock_path) else {
            eprintln!("could not read lockfile: {lock_path}");
            return ExitCode::from(1);
        };
        let Ok(actual) = serde_json::from_str::<serde_json::Value>(&contents) else {
            eprintln!("invalid lockfile JSON: {lock_path}");
            return ExitCode::from(1);
        };
        let Ok((_, expected)) = resolve_lockfile(arguments) else {
            return ExitCode::from(2);
        };
        if actual != expected {
            eprintln!("lockfile is out of date: {lock_path}");
            return ExitCode::from(1);
        }
        let digest = Sha256::digest(contents.as_bytes());
        let mut fingerprint = String::with_capacity(64);
        for byte in digest {
            write!(&mut fingerprint, "{byte:02x}").expect("writing to a string cannot fail");
        }
        Some(serde_json::json!({
            "path": lock_path,
            "sha256": fingerprint
        }))
    } else {
        None
    };
    let mut compiler_arguments = vec![source.clone()];
    let mut argument_index = 0;
    while argument_index < arguments.len() {
        if arguments[argument_index] == "-M"
            && let Some(directory) = arguments.get(argument_index + 1)
        {
            compiler_arguments.extend(["-M".to_owned(), directory.clone()]);
            argument_index += 2;
            continue;
        }
        argument_index += 1;
    }
    let Ok((_path, program, graph, mut diagnostics)) = load_program(&compiler_arguments) else {
        return ExitCode::from(2);
    };
    diagnostics.extend(analyze_with_modules(&program, &graph));
    if !diagnostics.is_empty() {
        return finish(source, diagnostics);
    }
    let (checked, typed_diagnostics) = check(&program);
    if !typed_diagnostics.is_empty() {
        return finish(source, typed_diagnostics);
    }
    let Some(checked) = checked else {
        return ExitCode::from(1);
    };
    let dependencies = program
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
    let resolved_modules = graph
        .modules
        .values()
        .map(|module| {
            serde_json::json!({
                "name": module.descriptor.id.name,
                "version": module.descriptor.id.version.to_string(),
                "sha256": hash_hex(&module.descriptor.canonical_hash)
            })
        })
        .collect::<Vec<_>>();
    let manifest = serde_json::json!({
        "publisher": publisher,
        "name": name,
        "version": version,
        "artifact": artifact,
        "sha256": sha256,
        "dependencies": dependencies,
        "conflicts": [],
        "artifact_event": serde_json::Value::Null,
        "os": "any",
        "arch": "any",
        "format": "npk",
        "runtime_requires": ["nscript-runtime >=0.1"],
        "provides": ["nscript-program"],
        "post_install": [],
        "nscript": {
            "source": source,
            "lockfile": lock_metadata,
            "resolved_modules": resolved_modules,
            "effects": checked.effects.iter().map(|effect| format!("{effect:?}").to_lowercase()).collect::<Vec<_>>(),
            "permissions_reviewed": true
        }
    });
    let canonical = arguments.iter().any(|argument| argument == "--canonical");
    let rendered = if canonical {
        serde_json::to_string(&manifest).expect("manifest is serializable")
    } else {
        serde_json::to_string_pretty(&manifest).expect("manifest is serializable")
    };
    if let Some(output) = flag("--output") {
        let contents = if canonical {
            rendered.clone()
        } else {
            format!("{rendered}\n")
        };
        if fs::write(&output, contents).is_err() {
            eprintln!("could not write manifest: {output}");
            return ExitCode::from(1);
        }
    } else if canonical {
        print!("{rendered}");
    } else {
        println!("{rendered}");
    }
    ExitCode::SUCCESS
}

fn package_lock(arguments: &[String]) -> ExitCode {
    let output = arguments
        .windows(2)
        .find(|pair| pair[0] == "--output")
        .map(|pair| pair[1].clone());
    let Ok((_, lockfile)) = resolve_lockfile(arguments) else {
        return ExitCode::from(2);
    };
    let rendered = serde_json::to_string_pretty(&lockfile).expect("lockfile is serializable");
    if let Some(output) = output {
        if fs::write(&output, format!("{rendered}\n")).is_err() {
            eprintln!("could not write lockfile: {output}");
            return ExitCode::from(1);
        }
    } else {
        println!("{rendered}");
    }
    ExitCode::SUCCESS
}

fn package_verify(arguments: &[String]) -> ExitCode {
    let Some(lock_path) = arguments
        .windows(2)
        .find(|pair| pair[0] == "--lock")
        .map(|pair| pair[1].clone())
    else {
        eprintln!("package verify requires --lock <file>");
        return ExitCode::from(2);
    };
    let Ok((_, expected)) = resolve_lockfile(arguments) else {
        return ExitCode::from(2);
    };
    let Ok(contents) = fs::read_to_string(&lock_path) else {
        eprintln!("could not read lockfile: {lock_path}");
        return ExitCode::from(1);
    };
    let Ok(actual) = serde_json::from_str::<serde_json::Value>(&contents) else {
        eprintln!("invalid lockfile JSON: {lock_path}");
        return ExitCode::from(1);
    };
    if actual != expected {
        eprintln!("lockfile is out of date: {lock_path}");
        return ExitCode::from(1);
    }
    println!("lockfile verified: {lock_path}");
    ExitCode::SUCCESS
}

fn resolve_lockfile(arguments: &[String]) -> Result<(String, serde_json::Value), ()> {
    let Some(source) = arguments.iter().find(|item| {
        Path::new(item)
            .extension()
            .is_some_and(|extension| extension.eq_ignore_ascii_case("ns"))
    }) else {
        eprintln!("package lock requires an NScript source file");
        return Err(());
    };
    let mut compiler_arguments = vec![source.clone()];
    let mut argument_index = 0;
    while argument_index < arguments.len() {
        if matches!(arguments[argument_index].as_str(), "-M" | "--module-path")
            && let Some(directory) = arguments.get(argument_index + 1)
        {
            compiler_arguments.extend([arguments[argument_index].clone(), directory.clone()]);
            argument_index += 2;
            continue;
        }
        argument_index += 1;
    }
    let Ok((_path, program, graph, diagnostics)) = load_program(&compiler_arguments) else {
        return Err(());
    };
    if !diagnostics.is_empty() {
        finish(source, diagnostics);
        return Err(());
    }
    let modules = graph
        .modules
        .values()
        .map(|module| {
            serde_json::json!({
                "name": module.descriptor.id.name,
                "version": module.descriptor.id.version.to_string(),
                "sha256": hash_hex(&module.descriptor.canonical_hash),
                "dependencies": module.descriptor.dependencies.iter().map(|dependency| {
                    serde_json::json!({
                        "name": dependency.name,
                        "requirement": dependency.requirement.to_string()
                    })
                }).collect::<Vec<_>>()
            })
        })
        .collect::<Vec<_>>();
    let roots = program
        .imports
        .iter()
        .map(|import| {
            serde_json::json!({
                "name": import.path,
                "requirement": import.requirement.as_deref().unwrap_or("*")
            })
        })
        .collect::<Vec<_>>();
    let lockfile = serde_json::json!({
        "lockfile_version": 1,
        "source": source,
        "roots": roots,
        "modules": modules
    });
    Ok((source.clone(), lockfile))
}

fn describe_module(path: &str) -> ExitCode {
    let Ok(source) = read_source(path) else {
        return ExitCode::from(2);
    };
    let (descriptor, diagnostics) = parse_module(&source);
    if !diagnostics.is_empty() {
        return finish(path, diagnostics);
    }
    let descriptor = descriptor.expect("a valid module has a descriptor");
    println!("module {}@{}", descriptor.id.name, descriptor.id.version);
    println!("language {}", descriptor.language);
    println!("canonical-encoding {}", descriptor.canonical_encoding);
    println!("sha256 {}", hash_hex(&descriptor.canonical_hash));
    for dependency in &descriptor.dependencies {
        println!("dependency {} {}", dependency.name, dependency.requirement);
    }
    let mut types = descriptor.types.iter().collect::<Vec<_>>();
    types.sort_by_key(|item| item.name());
    for item in types {
        println!("type {}", item.name());
    }
    let mut validators = descriptor.validators.iter().collect::<Vec<_>>();
    validators.sort_by_key(|item| &item.name);
    for validator in validators {
        println!("validator {}", validator.name);
    }
    let mut functions = descriptor.functions.iter().collect::<Vec<_>>();
    functions.sort_by_key(|item| &item.name);
    for function in functions {
        println!("function {}", function.name);
    }
    let mut events = descriptor.events.iter().collect::<Vec<_>>();
    events.sort_by_key(|event| &event.name);
    for event in events {
        println!("event {} kind={}", event.name, event.kind);
    }
    let mut tags = descriptor.tags.iter().collect::<Vec<_>>();
    tags.sort_by_key(|tag| &tag.name);
    for tag in tags {
        println!("tag {} wire={}", tag.name, tag.wire_name);
    }
    let mut operations = descriptor.operations.iter().collect::<Vec<_>>();
    operations.sort_by_key(|item| &item.name);
    for operation in operations {
        println!("operation {}", operation.name);
    }
    let mut errors = descriptor.errors.iter().collect::<Vec<_>>();
    errors.sort_by_key(|item| &item.name);
    for error in errors {
        println!("error {}", error.name);
    }
    let mut vectors = descriptor.vectors.iter().collect::<Vec<_>>();
    vectors.sort_by_key(|item| &item.name);
    for vector in vectors {
        println!("vector {}", vector.name);
    }
    ExitCode::SUCCESS
}

fn check_program(arguments: &[String]) -> ExitCode {
    let Ok((path, program, graph, mut diagnostics)) = load_program(arguments) else {
        return ExitCode::from(2);
    };
    diagnostics.extend(analyze_with_modules(&program, &graph));
    finish(&path, diagnostics)
}

fn inspect_program(arguments: &[String], json: bool) -> ExitCode {
    let Ok((path, program, graph, mut diagnostics)) = load_program(arguments) else {
        return ExitCode::from(2);
    };
    diagnostics.extend(analyze_with_modules(&program, &graph));
    if !diagnostics.is_empty() {
        return finish(&path, diagnostics);
    }
    let (checked, typed_diagnostics) = check(&program);
    if !typed_diagnostics.is_empty() {
        return finish(&path, typed_diagnostics);
    }
    let checked = checked.expect("a diagnostic-free program is checked");
    if json {
        let manifest = serde_json::json!({
            "profile": format!("{:?}", program.profile).to_lowercase(),
            "effects": checked.effects.iter().map(|effect| format!("{effect:?}").to_lowercase()).collect::<Vec<_>>(),
            "operations": checked.operation_calls.iter().map(|call| format!("{}.{}", call.module, call.operation)).collect::<Vec<_>>(),
            "publications": checked.publications.len(),
            "publication_trace": checked.publications.iter().map(|publication| serde_json::json!({
                "steps": [
                    {"op": "create_event", "event": publication.event},
                    {"op": "sign_event", "signer": publication.signer},
                    {"op": "publish_event", "relayset": publication.relayset}
                ]
            })).collect::<Vec<_>>(),
            "schedules": checked.schedules.len(),
            "handlers": checked.handlers.iter().map(|handler| serde_json::json!({
                "event": handler.event_type,
                "author": handler.author,
                "tags": handler.tag_equals,
                "filter_trace": {
                    "event": handler.event_type,
                    "author": handler.author,
                    "tags": handler.tag_equals
                }
            })).collect::<Vec<_>>(),
            "footprint": nscript_semantics::footprint(&program, &checked, &graph, &[]),
        });
        println!(
            "{}",
            serde_json::to_string_pretty(&manifest).expect("manifest is serializable")
        );
    } else {
        println!("profile: {:?}", program.profile);
        println!(
            "effects: {}",
            checked
                .effects
                .iter()
                .map(|effect| format!("{effect:?}"))
                .collect::<Vec<_>>()
                .join(", ")
        );
        for call in &checked.operation_calls {
            println!("operation: {}.{}", call.module, call.operation);
        }
        println!("publications: {}", checked.publications.len());
        println!("schedules: {}", checked.schedules.len());
        for handler in &checked.handlers {
            println!("handler: {}", handler.event_type);
            if let Some(author) = &handler.author {
                println!("  author: {author}");
            }
            for (name, value) in &handler.tag_equals {
                println!("  tag {name} == {value}");
            }
        }
    }
    ExitCode::SUCCESS
}

fn compile_program(arguments: &[String], wasm: bool) -> ExitCode {
    let mut source_arguments = Vec::new();
    let mut output = None;
    let mut index = 0;
    while index < arguments.len() {
        if arguments[index] == "--output" {
            index += 1;
            if index >= arguments.len() {
                eprintln!("compile --output requires a path");
                return ExitCode::from(2);
            }
            output = Some(arguments[index].clone());
        } else {
            source_arguments.push(arguments[index].clone());
        }
        index += 1;
    }
    let Ok((path, program, graph, mut diagnostics)) = load_program(&source_arguments) else {
        return ExitCode::from(2);
    };
    diagnostics.extend(analyze_with_modules(&program, &graph));
    if !diagnostics.is_empty() {
        return finish(&path, diagnostics);
    }
    let (checked, typed_diagnostics) = check(&program);
    if !typed_diagnostics.is_empty() {
        return finish(&path, typed_diagnostics);
    }
    let ir = nscript_ir::lower(
        &program,
        &checked.expect("a diagnostic-free program is checked"),
        &graph,
    );
    if wasm {
        let bytes = nscript_ir::emit_wasm(&ir);
        if let Some(output) = output {
            if fs::write(output, bytes).is_err() {
                return ExitCode::from(1);
            }
        } else {
            use std::io::Write;
            if std::io::stdout().write_all(&bytes).is_err() {
                return ExitCode::from(1);
            }
        }
    } else {
        println!(
            "{}",
            serde_json::to_string_pretty(&ir).expect("IR contains only serializable values")
        );
    }
    ExitCode::SUCCESS
}

/// Options that deliver events to handlers during `nscript run`.
#[derive(Default)]
struct RunOptions {
    events: Vec<serde_json::Value>,
    principal: Option<String>,
    /// `(module, operation)` pairs the simulator should make fail.
    failing: Vec<(String, String)>,
}

/// Separates `--event <json>`, `--events <file>`, `--as <key>` and
/// `--fail <module.operation>` from the compiler arguments. `--events` reads one
/// JSON event per line, or a single JSON array of events. `--fail` makes the
/// simulator answer that operation with a recoverable error, so a script's error
/// handling can be exercised.
fn take_run_options(arguments: &[String]) -> Result<(Vec<String>, RunOptions), String> {
    let mut rest = Vec::new();
    let mut options = RunOptions::default();
    let mut index = 0;
    while index < arguments.len() {
        let flag = arguments[index].as_str();
        if !matches!(flag, "--event" | "--events" | "--as" | "--fail") {
            rest.push(arguments[index].clone());
            index += 1;
            continue;
        }
        let Some(value) = arguments.get(index + 1) else {
            return Err(format!("{flag} requires a value"));
        };
        match flag {
            "--event" => options.events.push(
                serde_json::from_str(value)
                    .map_err(|error| format!("--event is not valid JSON: {error}"))?,
            ),
            "--events" => {
                let text = std::fs::read_to_string(value)
                    .map_err(|error| format!("cannot read {value}: {error}"))?;
                if let Ok(serde_json::Value::Array(events)) = serde_json::from_str(&text) {
                    options.events.extend(events);
                } else {
                    for (number, line) in text
                        .lines()
                        .enumerate()
                        .filter(|(_, line)| !line.trim().is_empty())
                    {
                        options
                            .events
                            .push(serde_json::from_str(line).map_err(|error| {
                                format!("{value} line {}: {error}", number + 1)
                            })?);
                    }
                }
            }
            "--fail" => {
                let Some((module, operation)) = value.split_once('.') else {
                    return Err(format!("--fail expects module.operation, found {value}"));
                };
                options
                    .failing
                    .push((module.to_owned(), operation.to_owned()));
            }
            _ => options.principal = Some(value.clone()),
        }
        index += 2;
    }
    Ok((rest, options))
}

/// `(module, operation)` to declared return type, for simulating operations no
/// host implements.
fn declared_returns(
    graph: &nscript_modules::ResolvedModuleGraph,
) -> std::collections::BTreeMap<(String, String), String> {
    graph
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
        .collect()
}

/// Runs the program's top-level module operation calls against the simulator.
/// `run` simulates: what no host implements is answered from the operation's
/// declared return type and recorded, never sent anywhere. Handler and function
/// bodies are excluded, because they run when an event arrives or the function is
/// called, not at startup.
fn run_startup_operations<R, S, C, A>(
    runtime: &mut nscript_runtime::Runtime<R, S, C, A>,
    program: &Program,
    checked: &nscript_semantics::CheckedProgram,
    policy: &nscript_runtime::OperationPolicy,
    operations: &mut nscript_runtime::eval::SimulatedOperations,
) -> Result<(), ExitCode>
where
    R: nscript_runtime::RelayHost,
    S: nscript_runtime::SignerHost,
    C: nscript_runtime::ClockHost,
    A: nscript_runtime::AuditHost,
{
    let mut startup = checked.clone();
    startup.operation_calls =
        nscript_runtime::eval::top_level_operation_calls(Some(program), checked)
            .into_iter()
            .cloned()
            .collect();
    let values = runtime
        .run_operations(&startup, policy, operations)
        .map_err(|error| {
            eprintln!("error[R1002]: {error:?}");
            ExitCode::from(1)
        })?;
    for (index, value) in values.iter().enumerate() {
        println!("operation {index}: {value:?}");
    }
    Ok(())
}

/// The simulator every command that runs handlers uses: it runs what the fake
/// host implements, answers the rest from declared return types, and makes the
/// `--fail` operations fail.
fn simulated_operations(
    graph: &nscript_modules::ResolvedModuleGraph,
    failing: &[(String, String)],
) -> nscript_runtime::eval::SimulatedOperations {
    let mut operations = nscript_runtime::eval::SimulatedOperations::new(declared_returns(graph));
    for (module, operation) in failing {
        operations.fail_operation(module, operation);
    }
    operations
}

fn run_program(arguments: &[String]) -> ExitCode {
    let (arguments, options) = match take_run_options(arguments) {
        Ok(taken) => taken,
        Err(message) => {
            eprintln!("error: {message}");
            return ExitCode::from(2);
        }
    };
    let arguments = arguments.as_slice();
    if arguments.iter().any(|argument| argument == "--dry-run") {
        let json = arguments.iter().any(|argument| argument == "--json");
        let filtered = arguments
            .iter()
            .filter(|argument| argument.as_str() != "--dry-run" && argument.as_str() != "--json")
            .cloned()
            .collect::<Vec<_>>();
        if !json {
            println!("dry-run: no external effects will be executed");
        }
        return inspect_program(&filtered, json);
    }
    let Ok((path, program, graph, mut diagnostics)) = load_program(arguments) else {
        return ExitCode::from(2);
    };
    diagnostics.extend(analyze_with_modules(&program, &graph));
    if !diagnostics.is_empty() {
        return finish(&path, diagnostics);
    }
    let (checked, typed_diagnostics) = check(&program);
    if !typed_diagnostics.is_empty() {
        return finish(&path, typed_diagnostics);
    }
    let relay = nscript_runtime::FakeRelayHost {
        relays: [("fake://public".to_owned(), true)].into_iter().collect(),
        published: Vec::new(),
        ..Default::default()
    };
    let signer = nscript_runtime::FakeSignerHost::default();
    let clock = nscript_runtime::FakeClock { now: 1_700_000_000 };
    let audit = nscript_runtime::RecordingAudit::default();
    let mut runtime = nscript_runtime::Runtime::new(relay, signer, clock, audit);
    let checked = checked.expect("checked program");
    let mut timers = nscript_runtime::FakeTimerHost::default();
    if let Err(error) = runtime.schedule_program(&mut timers, &checked) {
        eprintln!("error[R1003]: {error:?}");
        return ExitCode::from(1);
    }
    for timer in &timers.schedules {
        println!("timer {} at {}", timer.name, timer.next_at);
    }
    let subscriptions = nscript_runtime::Runtime::<
        nscript_runtime::FakeRelayHost,
        nscript_runtime::FakeSignerHost,
        nscript_runtime::FakeClock,
        nscript_runtime::RecordingAudit,
    >::handler_subscriptions(&checked, Some("public"));
    for subscription in &subscriptions {
        println!("subscription {}", subscription.event_type);
    }
    let operation_policy = checked.operation_calls.iter().fold(
        nscript_runtime::OperationPolicy::default(),
        |policy, call| policy.allow(&call.module, &call.operation),
    );
    let mut operation_host = simulated_operations(&graph, &options.failing);
    if let Err(code) = run_startup_operations(
        &mut runtime,
        &program,
        &checked,
        &operation_policy,
        &mut operation_host,
    ) {
        return code;
    }
    let reports = match runtime.run(&program, &checked) {
        Ok(reports) => reports,
        Err(error) => {
            eprintln!("error[R1001]: {error:?}");
            return ExitCode::from(1);
        }
    };
    for (index, report) in reports.iter().enumerate() {
        let accepted = report
            .outcomes
            .iter()
            .filter(|outcome| outcome.accepted)
            .count();
        println!(
            "publication {index}: {accepted}/{} relays accepted",
            report.outcomes.len()
        );
    }
    deliver_events(
        &mut runtime,
        &program,
        &checked,
        &options,
        &operation_policy,
        &mut operation_host,
    )
}

/// One recorded operation call, as `run` and `test-event` print it.
fn describe_operation_call(call: &nscript_runtime::eval::SimulatedCall) -> String {
    let arguments = call
        .arguments
        .iter()
        .map(|argument| format!("{argument:?}"))
        .collect::<Vec<_>>()
        .join(", ");
    let note = if call.simulated { "  [simulated]" } else { "" };
    format!(
        "operation {}.{}({arguments}){note}",
        call.module, call.operation
    )
}

/// A handler failure in words, with the fix for an unconfigured `me`.
fn describe_handler_error(error: &nscript_runtime::RuntimeError) -> String {
    match error {
        nscript_runtime::RuntimeError::EvaluationError { message } if message.contains("`me`") => {
            format!("{message} (pass --as <key>)")
        }
        nscript_runtime::RuntimeError::EvaluationError { message } => message.clone(),
        // A handler that returned an error result (by `?` or `return Err(..)`).
        nscript_runtime::RuntimeError::HandlerError { message } => {
            format!("it returned an error: {message}")
        }
        other => format!("{other:?}"),
    }
}

/// Delivers each `--event` to the handlers it matches and reports what they did:
/// their status, what they logged, and the module operations they called.
fn deliver_events<R, S, C, A>(
    runtime: &mut nscript_runtime::Runtime<R, S, C, A>,
    program: &Program,
    checked: &nscript_semantics::CheckedProgram,
    options: &RunOptions,
    policy: &nscript_runtime::OperationPolicy,
    operations: &mut nscript_runtime::eval::SimulatedOperations,
) -> ExitCode
where
    R: nscript_runtime::RelayHost,
    S: nscript_runtime::SignerHost,
    C: nscript_runtime::ClockHost,
    A: nscript_runtime::AuditHost,
{
    if options.events.is_empty() {
        if !checked.handlers.is_empty() {
            println!(
                "note: {} handler(s) registered; deliver events with --event <json> or --events <file>",
                checked.handlers.len()
            );
        }
        return ExitCode::SUCCESS;
    }
    let mut failed = false;
    for (index, value) in options.events.iter().enumerate() {
        let event = match nscript_runtime::eval::event_from_json(value) {
            Ok(event) => event,
            Err(message) => {
                eprintln!("error[R1004]: event {index}: {message}");
                failed = true;
                continue;
            }
        };
        println!(
            "event {} ({}, kind {})",
            event.id, event.unsigned.event_type, event.unsigned.kind
        );
        let mut log = nscript_runtime::FakeLogHost::default();
        let calls_before = operations.calls.len();
        let outcomes = runtime.run_handlers_for_event(
            program,
            checked,
            &event,
            policy,
            operations,
            &mut log,
            options.principal.as_deref(),
            nscript_runtime::eval::EvalLimits::default(),
        );
        if outcomes.is_empty() {
            println!("  no handler matched");
        }
        for outcome in &outcomes {
            match &outcome.result {
                Ok(_) => println!("  handler {}: ok", outcome.handler),
                Err(error) => {
                    failed = true;
                    let detail = describe_handler_error(error);
                    eprintln!("error[R1004]: handler {} failed: {detail}", outcome.handler);
                }
            }
        }
        for record in &log.records {
            println!("  log {}: {}", record.level, record.message);
        }
        for call in &operations.calls[calls_before..] {
            println!("  {}", describe_operation_call(call));
        }
    }
    if failed {
        ExitCode::from(1)
    } else {
        ExitCode::SUCCESS
    }
}

fn test_event(arguments: &[String]) -> ExitCode {
    let event_text = arguments
        .windows(2)
        .find(|pair| pair[0] == "--event")
        .map(|pair| pair[1].clone());
    let Some(event_text) = event_text else {
        eprintln!("test-event requires --event <json>");
        return ExitCode::from(2);
    };
    let Ok(event_value) = serde_json::from_str::<serde_json::Value>(&event_text) else {
        eprintln!("test-event requires --event to be valid JSON");
        return ExitCode::from(2);
    };
    // `--as <key>` is the value of `me`, as for `run`.
    let principal = arguments
        .windows(2)
        .find(|pair| pair[0] == "--as")
        .map(|pair| pair[1].clone());
    let failing: Vec<(String, String)> = arguments
        .windows(2)
        .filter(|pair| pair[0] == "--fail")
        .filter_map(|pair| {
            pair[1]
                .split_once('.')
                .map(|(module, operation)| (module.to_owned(), operation.to_owned()))
        })
        .collect();
    let mut compiler_arguments = Vec::new();
    let mut argument_index = 0;
    while argument_index < arguments.len() {
        if matches!(
            arguments[argument_index].as_str(),
            "--event" | "--as" | "--fail"
        ) {
            argument_index += 2;
            continue;
        }
        compiler_arguments.push(arguments[argument_index].clone());
        argument_index += 1;
    }
    let Ok((path, program, graph, mut diagnostics)) = load_program(&compiler_arguments) else {
        return ExitCode::from(2);
    };
    diagnostics.extend(analyze_with_modules(&program, &graph));
    if !diagnostics.is_empty() {
        return finish(&path, diagnostics);
    }
    let (checked, typed_diagnostics) = check(&program);
    if !typed_diagnostics.is_empty() {
        return finish(&path, typed_diagnostics);
    }
    let checked = checked.expect("a diagnostic-free program is checked");
    let Ok(event) = parse_test_event(&event_value) else {
        eprintln!(
            "invalid --event: expected an object with event_type, kind, content, tags, created_at, signer, id, signature"
        );
        return ExitCode::from(2);
    };
    let mut relay = nscript_runtime::FakeRelayHost::default();
    let mut storage = nscript_runtime::InMemoryStorage::default();
    let mut logs = nscript_runtime::FakeLogHost::default();
    // Handlers run under the evaluator, so they can call module operations; the
    // simulator records those no host implements rather than sending them.
    let mut operations = simulated_operations(&graph, &failing);
    match nscript_runtime::Runtime::<
        nscript_runtime::FakeRelayHost,
        nscript_runtime::FakeSignerHost,
        nscript_runtime::FakeClock,
        nscript_runtime::RecordingAudit,
    >::simulate_event(
        &program,
        &checked,
        &mut relay,
        &mut storage,
        &mut logs,
        &mut operations,
        principal.as_deref(),
        &event,
    ) {
        Ok(report) => print_simulation_report(&report, &storage),
        Err(error) => {
            eprintln!("error[R1002]: {error:?}");
            ExitCode::from(1)
        }
    }
}

/// Prints what a simulated event did, and returns the exit code: failure if any
/// handler failed.
fn print_simulation_report(
    report: &nscript_runtime::SimulationReport,
    storage: &nscript_runtime::InMemoryStorage,
) -> ExitCode {
    println!(
        "matched: {}/{} handlers",
        report.dispatched,
        report.subscriptions.len()
    );
    for subscription in &report.subscriptions {
        println!("subscription {subscription}");
    }
    for record in &report.logs {
        println!("log {}: {}", record.level, record.message);
    }
    for call in &report.operations {
        println!("{}", describe_operation_call(call));
    }
    for (key, value) in &storage.values {
        println!("storage {key} = {value}");
    }
    for failure in &report.failures {
        eprintln!(
            "error[R1004]: handler {} failed: {}",
            failure.handler,
            describe_handler_error(&failure.error)
        );
    }
    if report.failures.is_empty() {
        ExitCode::SUCCESS
    } else {
        ExitCode::from(1)
    }
}

fn parse_test_event(value: &serde_json::Value) -> Result<nscript_runtime::SignedEvent, ()> {
    let as_text = |key: &str, default: &str| {
        value
            .get(key)
            .and_then(serde_json::Value::as_str)
            .unwrap_or(default)
            .to_owned()
    };
    let kind = value
        .get("kind")
        .and_then(serde_json::Value::as_u64)
        .unwrap_or(1);
    let Ok(kind) = u16::try_from(kind) else {
        return Err(());
    };
    let tags = value
        .get("tags")
        .and_then(serde_json::Value::as_array)
        .map(|array| {
            array
                .iter()
                .filter_map(|tag| {
                    let array = tag.as_array()?;
                    let name = array.first()?.as_str()?;
                    let value = array
                        .get(1)
                        .and_then(serde_json::Value::as_str)
                        .unwrap_or("");
                    Some((name.to_owned(), value.to_owned()))
                })
                .collect::<Vec<_>>()
        })
        .unwrap_or_default();
    Ok(nscript_runtime::SignedEvent {
        unsigned: nscript_runtime::UnsignedEvent {
            event_type: as_text("event_type", "Note"),
            kind,
            content: as_text("content", ""),
            tags,
            created_at: value
                .get("created_at")
                .and_then(serde_json::Value::as_u64)
                .unwrap_or(0),
        },
        signer: as_text("signer", "alice"),
        id: as_text("id", "test-event"),
        signature: as_text("signature", "sig"),
    })
}

fn load_program(
    arguments: &[String],
) -> Result<
    (
        String,
        Program,
        nscript_modules::ResolvedModuleGraph,
        Vec<Diagnostic>,
    ),
    (),
> {
    let Ok((module_paths, path)) = parse_check_arguments(arguments) else {
        eprintln!("expected [-M <directory>]... <file>");
        return Err(());
    };
    let Ok(source) = read_source(path) else {
        return Err(());
    };
    let (program, mut diagnostics) = parse_program(&source);
    let mut registry = ModuleRegistry::with_builtins();
    for module_path in module_paths {
        if let Err(error) = registry.load_root(&module_path) {
            eprintln!("error[E4003]: {error}");
            return Err(());
        }
    }
    let mut roots = Vec::new();
    for import in &program.imports {
        let requirement_text = import.requirement.as_deref().unwrap_or("*");
        let normalized = requirement_text
            .split_whitespace()
            .collect::<Vec<_>>()
            .join(", ");
        match VersionReq::parse(&normalized) {
            Ok(requirement) => roots.push(ModuleDependency {
                name: import.path.clone(),
                requirement,
            }),
            Err(error) => diagnostics.push(Diagnostic {
                code: "E4002",
                message: format!("invalid module requirement `{requirement_text}`: {error}"),
                span: import.span,
            }),
        }
    }
    let graph = match registry.resolve(&roots) {
        Ok(graph) => graph,
        Err(error) => {
            let code = match &error {
                ResolutionError::Cycle(_) => "E4001",
                ResolutionError::Missing { .. } => "E4002",
                ResolutionError::Conflict { .. } => "E4003",
            };
            diagnostics.push(Diagnostic {
                code,
                message: error.to_string(),
                span: program
                    .imports
                    .first()
                    .map_or_else(nscript_syntax::Span::default, |import| import.span),
            });
            nscript_modules::ResolvedModuleGraph {
                modules: std::collections::BTreeMap::new(),
                known: std::collections::BTreeSet::new(),
            }
        }
    };
    Ok((path.to_owned(), program, graph, diagnostics))
}

fn parse_check_arguments(arguments: &[String]) -> Result<(Vec<PathBuf>, &str), ()> {
    let mut module_paths = Vec::new();
    let mut source = None;
    let mut index = 0;
    while index < arguments.len() {
        if matches!(arguments[index].as_str(), "-M" | "--module-path") {
            let Some(path) = arguments.get(index + 1) else {
                return Err(());
            };
            module_paths.push(PathBuf::from(path));
            index += 2;
        } else if source.replace(arguments[index].as_str()).is_some() {
            return Err(());
        } else {
            index += 1;
        }
    }
    source.map(|source| (module_paths, source)).ok_or(())
}

fn check_module(path: &str, print_hash: bool) -> ExitCode {
    let Ok(source) = read_source(path) else {
        return ExitCode::from(2);
    };
    let (descriptor, diagnostics) = parse_module(&source);
    if diagnostics.is_empty() {
        if print_hash {
            let descriptor = descriptor.expect("a valid module has a descriptor");
            println!("{}", hash_hex(&descriptor.canonical_hash));
        }
        ExitCode::SUCCESS
    } else {
        finish(path, diagnostics)
    }
}

fn read_source(path: &str) -> Result<String, ()> {
    fs::read_to_string(path).map_err(|error| {
        eprintln!("{path}: error: {error}");
    })
}

fn finish(path: &str, mut diagnostics: Vec<Diagnostic>) -> ExitCode {
    diagnostics.sort_by_key(|diagnostic| (diagnostic.span.start, diagnostic.code));
    for diagnostic in &diagnostics {
        eprintln!(
            "{}:{}:{}: error[{}]: {}",
            path, diagnostic.span.line, diagnostic.span.column, diagnostic.code, diagnostic.message
        );
    }
    if diagnostics.is_empty() {
        ExitCode::SUCCESS
    } else {
        ExitCode::FAILURE
    }
}
