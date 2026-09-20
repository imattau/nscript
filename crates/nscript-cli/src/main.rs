use std::{env, fs, process::ExitCode};

use nscript_modules::{hash_hex, parse_module};
use nscript_semantics::analyze;
use nscript_syntax::{Diagnostic, parse_program};

fn main() -> ExitCode {
    let arguments = env::args().skip(1).collect::<Vec<_>>();
    match arguments.as_slice() {
        [command, path] if command == "check" => check_program(path),
        [module, command, path] if module == "module" && command == "check" => {
            check_module(path, false)
        }
        [module, command, path] if module == "module" && command == "hash" => {
            check_module(path, true)
        }
        _ => {
            eprintln!(
                "usage:\n  nscript check <file>\n  nscript module check <file.nsm>\n  nscript module hash <file.nsm>"
            );
            ExitCode::from(2)
        }
    }
}

fn check_program(path: &str) -> ExitCode {
    let Ok(source) = read_source(path) else {
        return ExitCode::from(2);
    };
    let (program, mut diagnostics) = parse_program(&source);
    diagnostics.extend(analyze(&program));
    finish(path, diagnostics)
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
