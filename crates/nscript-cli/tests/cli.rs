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
fn inspects_program_permissions_as_json() {
    let output = Command::new(env!("CARGO_BIN_EXE_nscript"))
        .args(["inspect", "--json"])
        .arg(repository_path("conformance/valid/idempotent-handler.ns"))
        .output()
        .unwrap();
    assert!(output.status.success());
    let value: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(value["profile"], "standard");
    assert!(
        value["effects"]
            .as_array()
            .unwrap()
            .iter()
            .any(|effect| effect == "storage")
    );
    assert!(
        value["effects"]
            .as_array()
            .unwrap()
            .iter()
            .any(|effect| effect == "log")
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

#[test]
fn emits_golden_publication_ir() {
    for (source, vector) in [
        (
            "conformance/valid/hello-note.ns",
            "conformance/vectors/hello-note.ir.json",
        ),
        (
            "conformance/valid/default-publish.ns",
            "conformance/vectors/default-publish.ir.json",
        ),
    ] {
        let output = Command::new(env!("CARGO_BIN_EXE_nscript"))
            .args(["compile", "--emit", "ir"])
            .arg(repository_path(source))
            .output()
            .unwrap();
        assert!(
            output.status.success(),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
        let expected = std::fs::read_to_string(repository_path(vector)).unwrap();
        assert_eq!(
            String::from_utf8_lossy(&output.stdout).trim(),
            expected.trim()
        );
    }
}

#[test]
fn source_conformance_corpus_matches_expected_outcomes() {
    let valid_root = repository_path("conformance/valid");
    for entry in std::fs::read_dir(valid_root).unwrap() {
        let path = entry.unwrap().path();
        if path.extension().is_some_and(|extension| extension == "ns") {
            let output = Command::new(env!("CARGO_BIN_EXE_nscript"))
                .arg("check")
                .arg(&path)
                .output()
                .unwrap();
            assert!(
                output.status.success(),
                "{}: {}",
                path.display(),
                String::from_utf8_lossy(&output.stderr)
            );
        }
    }

    let invalid_root = repository_path("conformance/invalid");
    for entry in std::fs::read_dir(invalid_root).unwrap() {
        let path = entry.unwrap().path();
        if path.extension().is_none_or(|extension| extension != "ns") {
            continue;
        }
        let source = std::fs::read_to_string(&path).unwrap();
        let expected = source
            .lines()
            .find_map(|line| line.strip_prefix("// error: "))
            .and_then(|metadata| metadata.split_whitespace().next())
            .expect("invalid fixture declares an error code");
        let output = Command::new(env!("CARGO_BIN_EXE_nscript"))
            .arg("check")
            .arg(&path)
            .output()
            .unwrap();
        let stderr = String::from_utf8_lossy(&output.stderr);
        assert!(
            !output.status.success(),
            "{} unexpectedly passed",
            path.display()
        );
        assert!(
            stderr.contains(&format!("error[{expected}]")),
            "{} did not report {expected}: {stderr}",
            path.display()
        );
    }
}
