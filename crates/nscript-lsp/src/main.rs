use std::{
    io::{self, BufReader},
    process::ExitCode,
};

fn main() -> ExitCode {
    let stdin = io::stdin();
    let stdout = io::stdout();
    match nscript_lsp::serve(BufReader::new(stdin.lock()), stdout.lock()) {
        Ok(code) => ExitCode::from(code),
        Err(error) => {
            eprintln!("nscript-lsp: {error}");
            ExitCode::from(1)
        }
    }
}
