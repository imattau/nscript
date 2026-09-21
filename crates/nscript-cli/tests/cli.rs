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
    assert_eq!(value["handlers"][0]["event"], "Note");
    assert_eq!(value["handlers"][0]["tags"][0][0], "t");
}

#[test]
fn inspect_json_includes_publication_and_filter_traces() {
    let output = Command::new(env!("CARGO_BIN_EXE_nscript"))
        .args(["inspect", "--json"])
        .arg(repository_path("conformance/valid/hello-note.ns"))
        .output()
        .unwrap();
    assert!(output.status.success());
    let value: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(
        value["publication_trace"][0]["steps"][0]["op"],
        "create_event"
    );
    assert_eq!(
        value["publication_trace"][0]["steps"][1]["op"],
        "sign_event"
    );
}

#[test]
fn dry_run_reports_plan_without_external_effects() {
    let output = Command::new(env!("CARGO_BIN_EXE_nscript"))
        .args(["run", "--dry-run"])
        .arg(repository_path("conformance/valid/hello-note.ns"))
        .output()
        .unwrap();
    assert!(output.status.success());
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("dry-run: no external effects"));
    assert!(stdout.contains("publications: 1"));
}

#[test]
fn dry_run_json_is_machine_readable() {
    let output = Command::new(env!("CARGO_BIN_EXE_nscript"))
        .args(["run", "--dry-run", "--json"])
        .arg(repository_path("conformance/valid/idempotent-handler.ns"))
        .output()
        .unwrap();
    assert!(output.status.success());
    let value: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(value["handlers"][0]["event"], "Note");
}

#[test]
fn run_registers_checked_timers() {
    let output = Command::new(env!("CARGO_BIN_EXE_nscript"))
        .arg("run")
        .arg(repository_path("conformance/valid/timer.ns"))
        .output()
        .unwrap();
    assert!(output.status.success());
    assert!(String::from_utf8_lossy(&output.stdout).contains("timer schedule-0"));
}

#[test]
fn run_reports_checked_handler_subscriptions() {
    let output = Command::new(env!("CARGO_BIN_EXE_nscript"))
        .arg("run")
        .arg(repository_path("conformance/valid/idempotent-handler.ns"))
        .output()
        .unwrap();
    assert!(output.status.success());
    assert!(String::from_utf8_lossy(&output.stdout).contains("subscription Note"));
}

#[test]
fn generates_npack_compatible_manifest() {
    let output = Command::new(env!("CARGO_BIN_EXE_nscript"))
        .args([
            "package",
            "manifest",
            "--publisher",
            "npub1publisher",
            "--name",
            "hello",
            "--version",
            "0.1.0",
            "--artifact",
            "hello.npk",
        ])
        .arg(repository_path("conformance/valid/hello-note.ns"))
        .output()
        .unwrap();
    assert!(output.status.success());
    let manifest: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(manifest["format"], "npk");
    assert_eq!(manifest["name"], "hello");
    assert_eq!(manifest["runtime_requires"][0], "nscript-runtime >=0.1");
    assert_eq!(manifest["nscript"]["permissions_reviewed"], true);
    assert_eq!(manifest["dependencies"][0], "nip01 *");
}

#[test]
fn package_manifest_embeds_verified_lockfile_fingerprint() {
    let source = repository_path("conformance/valid/hello-note.ns");
    let lock_path =
        std::env::temp_dir().join(format!("nscript-manifest-lock-{}.json", std::process::id()));
    let generated = Command::new(env!("CARGO_BIN_EXE_nscript"))
        .args(["package", "lock"])
        .arg(&source)
        .args(["--output", lock_path.to_str().unwrap()])
        .output()
        .unwrap();
    assert!(generated.status.success());
    let output = Command::new(env!("CARGO_BIN_EXE_nscript"))
        .args([
            "package",
            "manifest",
            "--publisher",
            "npub1publisher",
            "--name",
            "hello",
            "--version",
            "0.1.0",
            "--artifact",
            "hello.npk",
            "--lock",
        ])
        .arg(&lock_path)
        .arg(&source)
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let manifest: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(
        manifest["nscript"]["lockfile"]["path"],
        lock_path.to_str().unwrap()
    );
    assert_eq!(
        manifest["nscript"]["lockfile"]["sha256"]
            .as_str()
            .unwrap()
            .len(),
        64
    );
    let _ = std::fs::remove_file(lock_path);
}

#[test]
fn generates_deterministic_module_lockfile() {
    let output = Command::new(env!("CARGO_BIN_EXE_nscript"))
        .args(["package", "lock"])
        .arg(repository_path("conformance/valid/hello-note.ns"))
        .output()
        .unwrap();
    assert!(output.status.success());
    let lockfile: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(lockfile["lockfile_version"], 1);
    assert_eq!(lockfile["roots"][0]["name"], "nip01");
    assert!(
        lockfile["modules"]
            .as_array()
            .unwrap()
            .iter()
            .any(|module| {
                module["name"] == "nip01"
                    && module["sha256"]
                        .as_str()
                        .is_some_and(|hash| hash.len() == 64)
            })
    );
}

#[test]
fn verifies_module_lockfile_and_rejects_drift() {
    let lock_path = std::env::temp_dir().join(format!("nscript-lock-{}.json", std::process::id()));
    let source = repository_path("conformance/valid/hello-note.ns");
    let generated = Command::new(env!("CARGO_BIN_EXE_nscript"))
        .args(["package", "lock"])
        .arg(&source)
        .args(["--output", lock_path.to_str().unwrap()])
        .output()
        .unwrap();
    assert!(generated.status.success());
    let verified = Command::new(env!("CARGO_BIN_EXE_nscript"))
        .args(["package", "verify"])
        .arg(&source)
        .args(["--lock", lock_path.to_str().unwrap()])
        .output()
        .unwrap();
    assert!(verified.status.success());
    let mut altered = std::fs::read_to_string(&lock_path).unwrap();
    altered = altered.replace("\"lockfile_version\": 1", "\"lockfile_version\": 2");
    std::fs::write(&lock_path, altered).unwrap();
    let rejected = Command::new(env!("CARGO_BIN_EXE_nscript"))
        .args(["package", "verify"])
        .arg(&source)
        .args(["--lock", lock_path.to_str().unwrap()])
        .output()
        .unwrap();
    assert!(!rejected.status.success());
    let _ = std::fs::remove_file(lock_path);
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
fn compiles_wasm_artifact_with_magic_header() {
    let output = Command::new(env!("CARGO_BIN_EXE_nscript"))
        .args(["compile", "--emit", "wasm"])
        .arg(repository_path("conformance/valid/hello-note.ns"))
        .output()
        .unwrap();
    assert!(output.status.success());
    assert_eq!(&output.stdout[..8], b"\0asm\x01\0\0\0");
    for marker in [
        "nscript.dispatch",
        "create_event",
        "sign_event",
        "publish_event",
    ] {
        assert!(
            output
                .stdout
                .windows(marker.len())
                .any(|window| window == marker.as_bytes()),
            "missing WASM marker {marker}"
        );
    }
}

#[test]
fn writes_wasm_artifact_for_packaging() {
    let output_path = std::env::temp_dir().join(format!("nscript-cli-{}.wasm", std::process::id()));
    let output = Command::new(env!("CARGO_BIN_EXE_nscript"))
        .args(["compile", "--emit", "wasm"])
        .arg(repository_path("conformance/valid/hello-note.ns"))
        .args(["--output", output_path.to_str().unwrap()])
        .output()
        .unwrap();
    assert!(output.status.success());
    let bytes = std::fs::read(&output_path).unwrap();
    assert_eq!(&bytes[..8], b"\0asm\x01\0\0\0");
    let _ = std::fs::remove_file(output_path);
}

#[test]
fn executes_compiled_wasm_through_wasmi_dispatch_host() {
    use nscript_runtime::{RuntimeError, WasmDispatchHost, wasmi_engine::WasmiEngine};
    use serde_json::Value;
    #[derive(Default)]
    struct Host(usize);
    impl WasmDispatchHost for Host {
        fn dispatch(&mut self, _: u64, operation: &Value) -> Result<(), RuntimeError> {
            if operation.is_object() {
                self.0 += 1;
            }
            Ok(())
        }
    }
    let output_path =
        std::env::temp_dir().join(format!("nscript-wasmi-{}.wasm", std::process::id()));
    let compile = Command::new(env!("CARGO_BIN_EXE_nscript"))
        .args(["compile", "--emit", "wasm"])
        .arg(repository_path("conformance/valid/hello-note.ns"))
        .args(["--output", output_path.to_str().unwrap()])
        .output()
        .unwrap();
    assert!(compile.status.success());
    let module = std::fs::read(&output_path).unwrap();
    let imports = [
        ("signer:account".to_owned(), false),
        ("relayset:public".to_owned(), false),
        ("op:0:create_event".to_owned(), true),
        ("op:1:sign_event".to_owned(), true),
        ("op:2:publish_event".to_owned(), true),
    ];
    let host = WasmiEngine::new(100_000)
        .run_with_dispatch_host(&module, &imports, Host::default(), 1)
        .expect("wasmi executes compiled artifact");
    assert_eq!(host.0, 3);
    let _ = std::fs::remove_file(output_path);
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
