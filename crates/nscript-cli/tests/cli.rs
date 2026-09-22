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
fn layer3_example_checks_and_inspects() {
    let output = Command::new(env!("CARGO_BIN_EXE_nscript"))
        .args(["inspect", "--json"])
        .arg(repository_path("examples/layer3-bot.ns"))
        .output()
        .unwrap();
    assert!(output.status.success());
    let value: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(value["publications"], 1);
    assert_eq!(value["handlers"][0]["event"], "Note");
    assert_eq!(value["handlers"][0]["tags"][0][1], "nscript");
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
fn the_idempotent_handler_fixture_actually_dedupes_when_run() {
    // Every other test touching this fixture only checks or inspects it, or
    // runs it with no `--event` at all, so `once(event.id)` — the fixture's
    // whole point — was never actually exercised. Deliver the same id twice.
    let output = Command::new(env!("CARGO_BIN_EXE_nscript"))
        .arg("run")
        .arg(repository_path("conformance/valid/idempotent-handler.ns"))
        .args([
            "--event",
            r#"{"content":"hi","tags":[["t","nostrhost"]],"id":"e1"}"#,
        ])
        .args([
            "--event",
            r#"{"content":"hi again","tags":[["t","nostrhost"]],"id":"e1"}"#,
        ])
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert_eq!(
        stdout.matches("handler Note: ok").count(),
        2,
        "both deliveries match: {stdout}"
    );
    assert_eq!(
        stdout.matches("log info: hi").count(),
        1,
        "but the second delivery's `once` is already claimed: {stdout}"
    );
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
    assert!(
        manifest["nscript"]["resolved_modules"]
            .as_array()
            .unwrap()
            .iter()
            .any(|module| module["name"] == "nip01"
                && module["sha256"].as_str().unwrap().len() == 64)
    );
}

#[test]
fn canonical_manifest_output_is_compact_json() {
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
            "--canonical",
        ])
        .arg(repository_path("conformance/valid/hello-note.ns"))
        .output()
        .unwrap();
    assert!(output.status.success());
    assert!(!output.stdout.contains(&b'\n'));
    let _: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
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
fn package_manifest_can_hash_local_artifact() {
    let source = repository_path("conformance/valid/hello-note.ns");
    let artifact =
        std::env::temp_dir().join(format!("nscript-artifact-{}.npk", std::process::id()));
    std::fs::write(&artifact, b"artifact-bytes").unwrap();
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
        ])
        .arg(&artifact)
        .arg("--hash-artifact")
        .arg(&source)
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let manifest: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(manifest["sha256"].as_str().unwrap().len(), 64);
    let _ = std::fs::remove_file(artifact);
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
    assert!(
        WasmiEngine::new(0)
            .run_with_imports(&module, &imports)
            .is_err(),
        "zero fuel must reject execution"
    );
    WasmiEngine::with_limits(100_000, 64 * 1024, 1, 1)
        .run_with_imports(&module, &imports)
        .expect("a one-page artifact fits the configured memory budget");
    let invalid_imports = [("op:99:create_event".to_owned(), true)];
    assert!(
        WasmiEngine::new(100_000)
            .run_with_dispatch_host(&module, &invalid_imports, Host::default(), 1)
            .is_err(),
        "out-of-range payload imports must fail preflight"
    );
    let mismatched_imports = [("op:0:wrong_event".to_owned(), true)];
    assert!(
        WasmiEngine::new(100_000)
            .run_with_dispatch_host(&module, &mismatched_imports, Host::default(), 1)
            .is_err(),
        "mismatched payload operation names must fail preflight"
    );
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

/// Runs `nscript run` on `source` (written to a temporary file) with `extra`
/// arguments, returning `(exit success, stdout, stderr)`.
fn run_source(name: &str, source: &str, extra: &[&str]) -> (bool, String, String) {
    let path = std::env::temp_dir().join(format!("nscript-run-{}-{name}.ns", std::process::id()));
    std::fs::write(&path, source).unwrap();
    let output = Command::new(env!("CARGO_BIN_EXE_nscript"))
        .arg("run")
        .arg(&path)
        .args(extra)
        .output()
        .unwrap();
    let _ = std::fs::remove_file(&path);
    (
        output.status.success(),
        String::from_utf8_lossy(&output.stdout).into_owned(),
        String::from_utf8_lossy(&output.stderr).into_owned(),
    )
}

const MODERATION_BOT: &str = include_str!("../../../examples/concord-moderation-bot.ns");

#[test]
fn run_starts_a_handler_program_without_executing_its_handler_calls() {
    // Before handlers were evaluated, the handler's `kick event.author` ran once
    // at startup with its argument dropped, and the whole run failed.
    let (ok, stdout, stderr) = run_source("startup", MODERATION_BOT, &[]);
    assert!(ok, "{stderr}");
    assert!(stdout.contains("subscription Note"));
    assert!(stdout.contains("1 handler(s) registered"));
    assert!(
        !stdout.contains("operation "),
        "no operation at startup: {stdout}"
    );
}

#[test]
fn run_delivers_events_to_handlers_and_reports_what_they_did() {
    let (ok, stdout, stderr) = run_source(
        "events",
        MODERATION_BOT,
        &[
            "--event",
            r#"{"id":"e1","content":"buy spam now","signer":"mallory"}"#,
            "--event",
            r#"{"id":"e2","content":"hello","signer":"alice"}"#,
            "--event",
            r#"{"id":"e3","event_type":"Reaction","content":"spam"}"#,
        ],
    );
    assert!(ok, "{stderr}");
    let spam = stdout.split("event e2").next().unwrap();
    assert!(spam.contains("handler Note: ok"));
    assert!(spam.contains("log info: kicking mallory"));
    assert!(spam.contains(r#"operation concord04.kick_member(PubKey("mallory"))  [simulated]"#));
    // The clean message and the other event type cause no operation.
    let rest = &stdout[stdout.find("event e2").unwrap()..];
    assert!(!rest.contains("operation "), "{rest}");
    assert!(rest.contains("no handler matched"));
}

#[test]
fn run_reads_events_from_a_file_of_lines_or_an_array() {
    let dir = std::env::temp_dir();
    let lines = dir.join(format!("nscript-events-{}.ndjson", std::process::id()));
    let array = dir.join(format!("nscript-events-{}.json", std::process::id()));
    std::fs::write(&lines, "{\"id\":\"a\",\"content\":\"spam\",\"signer\":\"x\"}\n\n{\"id\":\"b\",\"content\":\"ok\"}\n").unwrap();
    std::fs::write(
        &array,
        r#"[{"id":"a","content":"spam","signer":"x"},{"id":"b","content":"ok"}]"#,
    )
    .unwrap();
    for file in [&lines, &array] {
        let (ok, stdout, stderr) = run_source(
            "file",
            MODERATION_BOT,
            &["--events", file.to_str().unwrap()],
        );
        assert!(ok, "{stderr}");
        assert!(
            stdout.contains("event a") && stdout.contains("event b"),
            "{stdout}"
        );
        assert_eq!(stdout.matches("kick_member").count(), 1);
    }
    let _ = std::fs::remove_file(lines);
    let _ = std::fs::remove_file(array);
}

#[test]
fn run_reports_a_failing_handler_and_exits_nonzero() {
    let source = "permissions {\n    log\n}\n\non Note {\n    print(me)\n}\n";
    let (ok, _, stderr) = run_source("me", source, &["--event", "{}"]);
    assert!(!ok);
    assert!(
        stderr.contains("error[R1004]: handler Note failed"),
        "{stderr}"
    );
    assert!(
        stderr.contains("pass --as <key>"),
        "the hint names the fix: {stderr}"
    );
    // With a principal the same program succeeds.
    let (ok, stdout, stderr) = run_source("me-ok", source, &["--event", "{}", "--as", "my-key"]);
    assert!(ok, "{stderr}");
    assert!(stdout.contains("log info: my-key"), "{stdout}");
}

#[test]
fn run_rejects_malformed_event_input_without_running_anything() {
    let (ok, _, stderr) = run_source("bad-json", MODERATION_BOT, &["--event", "not json"]);
    assert!(!ok);
    assert!(stderr.contains("--event is not valid JSON"), "{stderr}");
    let (ok, _, stderr) = run_source("bad-shape", MODERATION_BOT, &["--event", "[1]"]);
    assert!(!ok);
    assert!(
        stderr.contains("an event must be a JSON object"),
        "{stderr}"
    );
    let (ok, _, stderr) = run_source("no-value", MODERATION_BOT, &["--event"]);
    assert!(!ok);
    assert!(stderr.contains("--event requires a value"), "{stderr}");
}

#[test]
fn run_bounds_a_runaway_handler() {
    let source = "permissions {\n    log\n}\n\nfn spin(n: Int) -> Int {\n    return spin(n + 1)\n}\n\non Note {\n    print(spin(0))\n}\n";
    let (ok, _, stderr) = run_source("runaway", source, &["--event", "{}"]);
    assert!(!ok);
    assert!(stderr.contains("ResourceLimit"), "{stderr}");
}

#[test]
fn test_event_runs_a_handler_that_calls_a_module_operation() {
    let path = repository_path("examples/concord-moderation-bot.ns");
    let run = |event: &str| {
        let output = Command::new(env!("CARGO_BIN_EXE_nscript"))
            .args(["test-event"])
            .arg(&path)
            .args(["--event", event])
            .output()
            .unwrap();
        (
            output.status.success(),
            String::from_utf8_lossy(&output.stdout).into_owned(),
        )
    };
    let (ok, stdout) = run(r#"{"content":"buy spam now","signer":"mallory"}"#);
    assert!(ok);
    assert!(stdout.contains("matched: 1/1 handlers"), "{stdout}");
    assert!(stdout.contains("log info: kicking mallory"), "{stdout}");
    assert!(
        stdout.contains(r#"operation concord04.kick_member(PubKey("mallory"))  [simulated]"#),
        "{stdout}"
    );
    let (ok, stdout) = run(r#"{"content":"hello"}"#);
    assert!(ok);
    assert!(!stdout.contains("operation "), "{stdout}");
}

#[test]
fn test_event_reports_a_failing_handler_and_runs_every_matching_handler() {
    let source = "permissions {\n    log\n}\n\non Note {\n    print(me)\n}\n\non Note {\n    print(\"second\")\n}\n";
    let path = std::env::temp_dir().join(format!("nscript-test-event-{}.ns", std::process::id()));
    std::fs::write(&path, source).unwrap();
    let run = |extra: &[&str]| {
        Command::new(env!("CARGO_BIN_EXE_nscript"))
            .arg("test-event")
            .arg(&path)
            .args(["--event", "{}"])
            .args(extra)
            .output()
            .unwrap()
    };
    let failed = run(&[]);
    assert!(!failed.status.success());
    let stdout = String::from_utf8_lossy(&failed.stdout);
    let stderr = String::from_utf8_lossy(&failed.stderr);
    assert!(stdout.contains("matched: 2/2 handlers"), "{stdout}");
    assert!(
        stdout.contains("log info: second"),
        "the second handler still ran: {stdout}"
    );
    assert!(
        stderr.contains("`me` is not configured (pass --as <key>)"),
        "{stderr}"
    );
    let fine = run(&["--as", "my-key"]);
    assert!(fine.status.success());
    assert!(String::from_utf8_lossy(&fine.stdout).contains("log info: my-key"));
    let _ = std::fs::remove_file(path);
}

const BOT_WITH_ERRORS: &str =
    include_str!("../../../examples/concord-moderation-bot-with-errors.ns");

#[test]
fn run_lets_a_script_branch_on_an_operations_result() {
    let spam = r#"{"content":"buy spam now","signer":"mallory"}"#;
    let (ok, stdout, stderr) = run_source("branch-ok", BOT_WITH_ERRORS, &["--event", spam]);
    assert!(ok, "{stderr}");
    assert!(stdout.contains("log info: kicked mallory"), "{stdout}");
    // `--fail` makes the simulator refuse the operation; the script's `Err` arm
    // handles it, so the handler itself succeeds and the attempt is recorded.
    let (ok, stdout, stderr) = run_source(
        "branch-err",
        BOT_WITH_ERRORS,
        &["--event", spam, "--fail", "concord04.kick_member"],
    );
    assert!(ok, "{stderr}");
    assert!(
        stdout.contains("log info: could not kick mallory: publication rejected"),
        "{stdout}"
    );
    assert!(stdout.contains("handler Note: ok"), "{stdout}");
    assert!(
        stdout.contains("operation concord04.kick_member"),
        "{stdout}"
    );
}

#[test]
fn run_treats_an_error_returned_by_question_mark_as_a_failed_handler() {
    let source = "use concord04\n\npermissions {\n    concord_kick\n    log\n}\n\non Note {\n    let report = concord04.kick_member(event.author)?\n    print(\"after\")\n}\n";
    let (ok, stdout, stderr) = run_source(
        "question",
        source,
        &["--event", "{}", "--fail", "concord04.kick_member"],
    );
    assert!(!ok);
    assert!(
        stderr.contains("error[R1004]: handler Note failed: it returned an error"),
        "{stderr}"
    );
    assert!(stderr.contains("publication rejected"), "{stderr}");
    assert!(
        !stdout.contains("log info: after"),
        "the statement after `?` did not run: {stdout}"
    );
    // Without a failure the same handler unwraps the result and carries on.
    let (ok, stdout, stderr) = run_source("question-ok", source, &["--event", "{}"]);
    assert!(ok, "{stderr}");
    assert!(stdout.contains("log info: after"), "{stdout}");
}

#[test]
fn run_rejects_a_malformed_fail_option() {
    let (ok, _, stderr) = run_source("bad-fail", BOT_WITH_ERRORS, &["--fail", "nodot"]);
    assert!(!ok);
    assert!(
        stderr.contains("--fail expects module.operation"),
        "{stderr}"
    );
}

#[test]
fn test_event_can_make_an_operation_fail_to_exercise_error_handling() {
    let path = repository_path("examples/concord-moderation-bot-with-errors.ns");
    let output = Command::new(env!("CARGO_BIN_EXE_nscript"))
        .arg("test-event")
        .arg(&path)
        .args(["--event", r#"{"content":"spam","signer":"mallory"}"#])
        .args(["--fail", "concord04.kick_member"])
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "the script handled the error itself"
    );
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains("log info: could not kick mallory: publication rejected"),
        "{stdout}"
    );
}

#[test]
fn run_evaluates_record_guard_and_literal_patterns_from_source() {
    let path = repository_path("examples/concord-spam-filter.ns");
    let output = Command::new(env!("CARGO_BIN_EXE_nscript"))
        .arg("run")
        .arg(&path)
        .args([
            "--event",
            r#"{"id":"a","content":"buy spam now","signer":"mallory"}"#,
        ])
        .args([
            "--event",
            r#"{"id":"b","content":"hello","signer":"alice"}"#,
        ])
        .args([
            "--event",
            r#"{"id":"c","content":"hi","signer":"eve","kind":7}"#,
        ])
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = String::from_utf8_lossy(&output.stdout);
    let after_a = stdout.split("event b").next().unwrap();
    // The guarded record pattern selects the spam and destructures its author.
    assert!(
        after_a.contains(r#"operation concord04.kick_member(PubKey("mallory"))"#),
        "{stdout}"
    );
    // The unguarded record pattern handles the rest, and the literal `kind: 7`
    // pattern picks out the reaction before it.
    assert!(stdout.contains("log info: ok from alice"), "{stdout}");
    assert!(stdout.contains("log info: ignoring a reaction"), "{stdout}");
    assert_eq!(
        stdout.matches("kick_member").count(),
        1,
        "only the spam was kicked: {stdout}"
    );
}

#[test]
fn a_declared_key_is_an_opaque_handle_the_host_provisions() {
    let output = Command::new(env!("CARGO_BIN_EXE_nscript"))
        .arg("run")
        .arg(repository_path("examples/concord-key-bot.ns"))
        .args(["--as", "bot"])
        .args([
            "--event",
            r#"{"event_type":"StreamMessage","content":"ping"}"#,
        ])
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = String::from_utf8_lossy(&output.stdout);
    // The startup call and the handler both received the key, and only its
    // length is ever printed: the bytes are not visible to the script or log.
    assert!(stdout.contains("operation 0: StreamHandle"), "{stdout}");
    assert!(
        stdout.contains("concord01.publish_message(DerivedKey(DerivedKey { length: 32 })"),
        "{stdout}"
    );
}

#[test]
fn the_community_digest_bot_moderates_reacts_and_cross_posts_media() {
    let path = repository_path("examples/community-digest-bot.ns");
    let run = |event: &str| {
        let output = Command::new(env!("CARGO_BIN_EXE_nscript"))
            .arg("run")
            .arg(&path)
            .args(["--event", event])
            .output()
            .unwrap();
        assert!(
            output.status.success(),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
        String::from_utf8_lossy(&output.stdout).into_owned()
    };
    // Spam is reported and its author muted, not reacted to.
    let stdout = run(r#"{"content":"buy spam now","author":"mallory","tags":[["t","community"]]}"#);
    assert!(stdout.contains("log info: muted mallory"), "{stdout}");
    assert!(stdout.contains("nip56.publish_report"), "{stdout}");
    assert!(stdout.contains("nip28.mute_user"), "{stdout}");
    assert!(!stdout.contains("publish_reaction"), "{stdout}");

    // A link gets a reaction and is cross-posted with a `List<Record>`
    // `media` field, constructed from inside a handler body — the same
    // record-in-a-list shape `nip88`'s `Poll` and `nip92` itself use, now
    // proven to convert correctly through the handler evaluator's
    // `Value`/`OperationValue` path, not just the top-level one.
    let stdout = run(
        r#"{"content":"check this out: http://example.com","author":"alice","tags":[["t","community"]]}"#,
    );
    assert!(stdout.contains("nip25.publish_reaction"), "{stdout}");
    assert!(stdout.contains("nip92.publish_note_with_media"), "{stdout}");
    assert!(stdout.contains("MediaAttachment"), "{stdout}");
    assert!(stdout.contains("log info: cross-posted a link from alice"), "{stdout}");

    // Anything else just gets a reaction, nothing more.
    let stdout = run(r#"{"content":"hello","author":"bob","tags":[["t","community"]]}"#);
    assert!(stdout.contains("nip25.publish_reaction"), "{stdout}");
    assert!(!stdout.contains("nip92."), "{stdout}");
    assert!(!stdout.contains("nip56."), "{stdout}");
}

#[test]
fn once_makes_the_community_digest_bot_idempotent_across_a_redelivered_event() {
    // The whole handler body is wrapped in `once(event.id) { ... }`, so
    // redelivering the same event id within one `nscript run` invocation
    // must not mute or report a second time.
    let output = Command::new(env!("CARGO_BIN_EXE_nscript"))
        .arg("run")
        .arg(repository_path("examples/community-digest-bot.ns"))
        .args([
            "--event",
            r#"{"content":"buy spam now","author":"mallory","tags":[["t","community"]],"id":"e1"}"#,
        ])
        .args([
            "--event",
            r#"{"content":"buy spam now","author":"mallory","tags":[["t","community"]],"id":"e1"}"#,
        ])
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert_eq!(
        stdout.matches("handler Note: ok").count(),
        2,
        "both deliveries match the subscription: {stdout}"
    );
    assert_eq!(
        stdout.matches("nip28.mute_user").count(),
        1,
        "but only the first actually mutes: {stdout}"
    );
}

#[test]
fn a_key_must_be_declared_from_a_host_label() {
    let dir = std::env::temp_dir().join("nscript-key-decl");
    std::fs::create_dir_all(&dir).unwrap();
    let path = dir.join("bad.ns");
    std::fs::write(&path, "key k = 1\n").unwrap();
    let output = Command::new(env!("CARGO_BIN_EXE_nscript"))
        .arg("check")
        .arg(&path)
        .output()
        .unwrap();
    assert!(!output.status.success());
    assert!(String::from_utf8_lossy(&output.stderr).contains("E1101"));
}

#[test]
fn a_fold_query_runs_pure_with_no_permission_and_no_result_wrapping() {
    // A genuinely valid, unexpired invite bundle: `invite_is_valid` is a
    // `function` (RFC 0002 §3), so `event.content` can carry it straight
    // into the handler with no permission declared for it anywhere in the
    // script's `permissions` block.
    let owner = "1".repeat(64);
    let owner_salt = "2".repeat(64);
    let community_id = nscript_runtime::authority::community_id(&owner, &owner_salt).unwrap();
    let bundle = serde_json::json!({
        "community_id": community_id,
        "owner": owner,
        "owner_salt": owner_salt,
        "community_root": "3".repeat(64),
        "root_epoch": 1,
        "channels": [],
        "name": "lounge",
    })
    .to_string();
    let event = serde_json::json!({
        "event_type": "Note",
        "content": bundle,
        "created_at": 0,
    })
    .to_string();
    let output = Command::new(env!("CARGO_BIN_EXE_nscript"))
        .arg("run")
        .arg(repository_path("conformance/valid/concord-fold-queries.ns"))
        .args(["--event", &event])
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("invite still valid"), "{stdout}");
}
