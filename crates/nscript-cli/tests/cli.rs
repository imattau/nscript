use std::{path::PathBuf, process::Command};

fn repository_path(relative: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../..")
        .join(relative)
}

#[test]
fn checks_program_with_builtin_imports() {
    let output = Command::new(env!("CARGO_BIN_EXE_nscript"))
        .arg("check")
        .arg(repository_path("conformance/valid/default-publish.ns"))
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
}

#[test]
fn reports_missing_module() {
    let output = Command::new(env!("CARGO_BIN_EXE_nscript"))
        .arg("check")
        .arg(repository_path("examples/moderation.ns"))
        .output()
        .unwrap();
    assert_eq!(output.status.code(), Some(1));
    assert!(String::from_utf8_lossy(&output.stderr).contains("error[E4002]"));
}

#[test]
fn describes_module_deterministically() {
    let output = Command::new(env!("CARGO_BIN_EXE_nscript"))
        .args(["module", "describe"])
        .arg(repository_path("modules/std/nip10/0.1.0.nsm"))
        .output()
        .unwrap();
    assert!(output.status.success());
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("module nip10@0.1.0"));
    assert!(stdout.contains("dependency nip01 ^0.1"));
}
