use std::{env, fs, path::PathBuf, process::ExitCode};

use nscript_modules::{ModuleDependency, ModuleRegistry, ResolutionError, hash_hex, parse_module};
use nscript_semantics::{analyze_with_modules, check};
use nscript_syntax::{Diagnostic, Program, parse_program};
use semver::VersionReq;

fn main() -> ExitCode {
    let arguments = env::args().skip(1).collect::<Vec<_>>();
    match arguments.as_slice() {
        [command, rest @ ..] if command == "check" => check_program(rest),
        [command, format, rest @ ..] if command == "inspect" && format == "--json" => {
            inspect_program(rest, true)
        }
        [command, rest @ ..] if command == "inspect" => inspect_program(rest, false),
        [command, rest @ ..] if command == "run" => run_program(rest),
        [command, emit, format, rest @ ..]
            if command == "compile" && emit == "--emit" && format == "ir" =>
        {
            compile_program(rest)
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
                "usage:\n  nscript check [-M <directory>]... <file>\n  nscript inspect [--json] [-M <directory>]... <file>\n  nscript run [--dry-run] [-M <directory>]... <file>\n  nscript compile --emit ir [-M <directory>]... <file>\n  nscript module check <file.nsm>\n  nscript module hash <file.nsm>\n  nscript module describe <file.nsm>"
            );
            ExitCode::from(2)
        }
    }
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
            "schedules": checked.schedules.len(),
            "handlers": checked.handlers.iter().map(|handler| serde_json::json!({
                "event": handler.event_type,
                "author": handler.author,
                "tags": handler.tag_equals,
            })).collect::<Vec<_>>(),
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

fn compile_program(arguments: &[String]) -> ExitCode {
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
    let ir = nscript_ir::lower(
        &program,
        &checked.expect("a diagnostic-free program is checked"),
        &graph,
    );
    println!(
        "{}",
        serde_json::to_string_pretty(&ir).expect("IR contains only serializable values")
    );
    ExitCode::SUCCESS
}

fn run_program(arguments: &[String]) -> ExitCode {
    if arguments.iter().any(|argument| argument == "--dry-run") {
        let filtered = arguments
            .iter()
            .filter(|argument| argument.as_str() != "--dry-run")
            .cloned()
            .collect::<Vec<_>>();
        println!("dry-run: no external effects will be executed");
        return inspect_program(&filtered, false);
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
    let operation_policy = checked.operation_calls.iter().fold(
        nscript_runtime::OperationPolicy::default(),
        |policy, call| policy.allow(&call.module, &call.operation),
    );
    let mut operation_host = nscript_runtime::FakeOperationHost::default();
    let operation_values =
        match runtime.run_operations(&checked, &operation_policy, &mut operation_host) {
            Ok(values) => values,
            Err(error) => {
                eprintln!("error[R1002]: {error:?}");
                return ExitCode::from(1);
            }
        };
    for (index, value) in operation_values.iter().enumerate() {
        println!("operation {index}: {value:?}");
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
    ExitCode::SUCCESS
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
