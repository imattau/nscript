use std::{env, fs, path::PathBuf, process::ExitCode};

use nscript_modules::{ModuleDependency, ModuleRegistry, ResolutionError, hash_hex, parse_module};
use nscript_semantics::analyze;
use nscript_syntax::{Diagnostic, parse_program};
use semver::VersionReq;

fn main() -> ExitCode {
    let arguments = env::args().skip(1).collect::<Vec<_>>();
    match arguments.as_slice() {
        [command, rest @ ..] if command == "check" => check_program(rest),
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
                "usage:\n  nscript check [-M <directory>]... <file>\n  nscript module check <file.nsm>\n  nscript module hash <file.nsm>\n  nscript module describe <file.nsm>"
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
    ExitCode::SUCCESS
}

fn check_program(arguments: &[String]) -> ExitCode {
    let Ok((module_paths, path)) = parse_check_arguments(arguments) else {
        eprintln!("usage: nscript check [-M <directory>]... <file>");
        return ExitCode::from(2);
    };
    let Ok(source) = read_source(path) else {
        return ExitCode::from(2);
    };
    let (program, mut diagnostics) = parse_program(&source);
    let mut registry = ModuleRegistry::with_builtins();
    for module_path in module_paths {
        if let Err(error) = registry.load_root(&module_path) {
            eprintln!("error[E4003]: {error}");
            return ExitCode::FAILURE;
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
    if diagnostics.is_empty()
        && let Err(error) = registry.resolve(&roots)
    {
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
    }
    diagnostics.extend(analyze(&program));
    finish(path, diagnostics)
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
