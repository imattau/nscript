use std::{env, fs, process::ExitCode};

use nscript_semantics::analyze;
use nscript_syntax::parse_program;

fn main() -> ExitCode {
    let mut arguments = env::args().skip(1);
    let Some(command) = arguments.next() else {
        eprintln!("usage: nscript check <file>");
        return ExitCode::from(2);
    };
    if command != "check" {
        eprintln!("unknown command `{command}`; expected `check`");
        return ExitCode::from(2);
    }
    let Some(path) = arguments.next() else {
        eprintln!("usage: nscript check <file>");
        return ExitCode::from(2);
    };
    if arguments.next().is_some() {
        eprintln!("check accepts exactly one source file");
        return ExitCode::from(2);
    }

    let source = match fs::read_to_string(&path) {
        Ok(source) => source,
        Err(error) => {
            eprintln!("{path}: error: {error}");
            return ExitCode::from(2);
        }
    };
    let (program, mut diagnostics) = parse_program(&source);
    diagnostics.extend(analyze(&program));
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
