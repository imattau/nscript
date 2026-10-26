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
fn ncc07_manifest_lowers_to_the_pinned_wire_vector() {
    let vector: serde_json::Value = serde_json::from_slice(
        &std::fs::read(repository_path("conformance/vectors/ncc07.json")).unwrap(),
    )
    .unwrap();
    let expected = &vector["vectors"][0];
    let output = Command::new(env!("CARGO_BIN_EXE_nscript"))
        .args(["inspect", "--json"])
        .arg(repository_path("conformance/valid/ncc07-manifest.ns"))
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let value: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    let create = &value["publication_trace"][0]["steps"][0];
    assert_eq!(create["op"], "create_event");
    assert_eq!(create["event"], "CapabilityManifest");
    assert_eq!(create["kind"], expected["kind"]);
    assert_eq!(create["tags"], expected["tags"]);
}

#[test]
fn ncc00_ledger_lowers_to_the_pinned_wire_vector() {
    let vector: serde_json::Value = serde_json::from_slice(
        &std::fs::read(repository_path("conformance/vectors/ncc00.json")).unwrap(),
    )
    .unwrap();
    let expected = &vector["vectors"][0];
    let output = Command::new(env!("CARGO_BIN_EXE_nscript"))
        .args(["inspect", "--json"])
        .arg(repository_path("conformance/valid/ncc00-ledger.ns"))
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let value: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    let create = &value["publication_trace"][0]["steps"][0];
    assert_eq!(create["op"], "create_event");
    assert_eq!(create["event"], "NccSupportingDocument");
    assert_eq!(create["kind"], expected["kind"]);
    assert_eq!(create["tags"], expected["tags"]);
}

#[test]
fn ncc02_service_record_lowers_to_the_pinned_wire_vector() {
    let vector: serde_json::Value = serde_json::from_slice(
        &std::fs::read(repository_path("conformance/vectors/ncc02.json")).unwrap(),
    )
    .unwrap();
    let expected = &vector["vectors"][0];
    let output = Command::new(env!("CARGO_BIN_EXE_nscript"))
        .args(["inspect", "--json"])
        .arg(repository_path("conformance/valid/ncc02-service-record.ns"))
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let value: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    let create = &value["publication_trace"][0]["steps"][0];
    assert_eq!(create["op"], "create_event");
    assert_eq!(create["event"], "ServiceRecord");
    assert_eq!(create["kind"], expected["kind"]);
    assert_eq!(create["tags"], expected["tags"]);
}

#[test]
fn ncc05_locator_lowers_to_the_pinned_wire_vector() {
    let vector: serde_json::Value = serde_json::from_slice(
        &std::fs::read(repository_path("conformance/vectors/ncc05.json")).unwrap(),
    )
    .unwrap();
    let expected = &vector["vectors"][0];
    let output = Command::new(env!("CARGO_BIN_EXE_nscript"))
        .args(["inspect", "--json"])
        .arg(repository_path("conformance/valid/ncc05-locator.ns"))
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let value: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    let create = &value["publication_trace"][0]["steps"][0];
    assert_eq!(create["op"], "create_event");
    assert_eq!(create["event"], "Locator");
    assert_eq!(create["kind"], expected["kind"]);
    assert_eq!(create["tags"], expected["tags"]);
    // NCC-05 §5.1: the payload is encrypted into `content` as the
    // handler publishes, so the checked snapshot carries no literal
    // content — nothing that reaches the wire here could be read in the
    // clear from the source.
    assert_eq!(create["content"], expected["content"]);
    assert!(create["content"].is_null());
}

#[test]
fn ncc06_service_profile_lowers_to_the_pinned_wire_vectors() {
    let vector: serde_json::Value = serde_json::from_slice(
        &std::fs::read(repository_path("conformance/vectors/ncc06.json")).unwrap(),
    )
    .unwrap();
    let output = Command::new(env!("CARGO_BIN_EXE_nscript"))
        .args(["inspect", "--json"])
        .arg(repository_path(
            "conformance/valid/ncc06-service-profile.ns",
        ))
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let value: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    // NCC-06 declares no event kinds of its own: the profile's sidecar
    // lowers the NCC-02 Service Record at startup and the NCC-05 Locator
    // from its relocate handler, both pinned here in declaration order.
    let record = &value["publication_trace"][0]["steps"][0];
    assert_eq!(record["op"], "create_event");
    assert_eq!(record["event"], "ServiceRecord");
    assert_eq!(record["kind"], vector["vectors"][0]["kind"]);
    assert_eq!(record["tags"], vector["vectors"][0]["tags"]);
    assert_eq!(record["content"], vector["vectors"][0]["content"]);
    let locator = &value["publication_trace"][1]["steps"][0];
    assert_eq!(locator["op"], "create_event");
    assert_eq!(locator["event"], "Locator");
    assert_eq!(locator["kind"], vector["vectors"][1]["kind"]);
    assert_eq!(locator["tags"], vector["vectors"][1]["tags"]);
    // NCC-05 §5.1 (carried by the profile): the payload is encrypted as
    // the handler publishes, so the checked snapshot carries no literal
    // content for the locator.
    assert_eq!(locator["content"], vector["vectors"][1]["content"]);
    assert!(locator["content"].is_null());
}

#[test]
fn ncc08_handover_proposal_lowers_to_the_pinned_wire_vector() {
    let vector: serde_json::Value = serde_json::from_slice(
        &std::fs::read(repository_path("conformance/vectors/ncc08.json")).unwrap(),
    )
    .unwrap();
    let expected = &vector["vectors"][0];
    let output = Command::new(env!("CARGO_BIN_EXE_nscript"))
        .args(["inspect", "--json"])
        .arg(repository_path("conformance/valid/ncc08-handover.ns"))
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let value: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    let create = &value["publication_trace"][0]["steps"][0];
    assert_eq!(create["op"], "create_event");
    assert_eq!(create["event"], "Handover");
    assert_eq!(create["kind"], expected["kind"]);
    assert_eq!(create["tags"], expected["tags"]);
    // NCC-08 lowers the predecessor proposal as its own event; the
    // successor's acceptance is the other half, published by the other
    // identity, so this fixture carries only the proposal.
    assert_eq!(create["content"], expected["content"]);
    assert_eq!(vector["vectors"].as_array().unwrap().len(), 1);
}

#[test]
fn ncc09_authority_grant_lowers_to_the_pinned_wire_vector() {
    let vector: serde_json::Value = serde_json::from_slice(
        &std::fs::read(repository_path("conformance/vectors/ncc09.json")).unwrap(),
    )
    .unwrap();
    let expected = &vector["vectors"][0];
    let output = Command::new(env!("CARGO_BIN_EXE_nscript"))
        .args(["inspect", "--json"])
        .arg(repository_path(
            "conformance/valid/ncc09-authority-grant.ns",
        ))
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let value: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    let create = &value["publication_trace"][0]["steps"][0];
    assert_eq!(create["op"], "create_event");
    assert_eq!(create["event"], "AuthorityGrant");
    assert_eq!(create["kind"], expected["kind"]);
    assert_eq!(create["tags"], expected["tags"]);
    assert_eq!(create["content"], expected["content"]);
}

#[test]
fn ncc10_service_state_lowers_to_the_pinned_wire_vector() {
    let vector: serde_json::Value = serde_json::from_slice(
        &std::fs::read(repository_path("conformance/vectors/ncc10.json")).unwrap(),
    )
    .unwrap();
    let expected = &vector["vectors"][0];
    let output = Command::new(env!("CARGO_BIN_EXE_nscript"))
        .args(["inspect", "--json"])
        .arg(repository_path("conformance/valid/ncc10-service-state.ns"))
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let value: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    let create = &value["publication_trace"][0]["steps"][0];
    assert_eq!(create["op"], "create_event");
    assert_eq!(create["event"], "ServiceState");
    assert_eq!(create["kind"], expected["kind"]);
    assert_eq!(create["tags"], expected["tags"]);
    assert_eq!(create["content"], expected["content"]);
}

#[test]
fn ncc11_trust_policy_lowers_to_the_pinned_wire_vector() {
    let vector: serde_json::Value = serde_json::from_slice(
        &std::fs::read(repository_path("conformance/vectors/ncc11.json")).unwrap(),
    )
    .unwrap();
    let expected = &vector["vectors"][0];
    let output = Command::new(env!("CARGO_BIN_EXE_nscript"))
        .args(["inspect", "--json"])
        .arg(repository_path("conformance/valid/ncc11-trust-policy.ns"))
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let value: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    let create = &value["publication_trace"][0]["steps"][0];
    assert_eq!(create["op"], "create_event");
    assert_eq!(create["event"], "TrustPolicy");
    assert_eq!(create["kind"], expected["kind"]);
    assert_eq!(create["tags"], expected["tags"]);
    // The rules and certifiers are computed by module builders at publish
    // time (a `.ns` literal cannot carry the tag column separator), so the
    // checked snapshot holds only the literal `d`. The three-column
    // lowering those builders produce is asserted by the deploy test below
    // and by the runtime's own tag round-trip test.
    assert_eq!(create["content"], expected["content"]);
}

#[test]
fn ncc13_package_release_lowers_to_the_pinned_wire_vector() {
    let vector: serde_json::Value = serde_json::from_slice(
        &std::fs::read(repository_path("conformance/vectors/ncc13.json")).unwrap(),
    )
    .unwrap();
    let expected = &vector["vectors"][0];
    let output = Command::new(env!("CARGO_BIN_EXE_nscript"))
        .args(["inspect", "--json"])
        .arg(repository_path(
            "conformance/valid/ncc13-package-release.ns",
        ))
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let value: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    let create = &value["publication_trace"][0]["steps"][0];
    assert_eq!(create["op"], "create_event");
    assert_eq!(create["event"], "ReleaseArtifactSet");
    assert_eq!(create["kind"], expected["kind"]);
    assert_eq!(create["tags"], expected["tags"]);
    // `requires` and `conflicts` are built by ncc13.requirement at publish
    // time (a `.ns` literal cannot carry the tag column separator), so the
    // checked snapshot holds only the literal fields. The two-column
    // lowering that builder produces is asserted by the runtime's own tag
    // round-trip test and by the run-with-event coverage below.
    assert_eq!(create["content"], expected["content"]);
}

#[test]
fn ncc13_release_artifact_set_handler_reads_dependencies_and_upgrade_eligibility() {
    let output = Command::new(env!("CARGO_BIN_EXE_nscript"))
        .arg("run")
        .arg(repository_path("conformance/valid/ncc13-package-release.ns"))
        .args([
            "--event",
            r#"{"event_type": "ReleaseArtifactSet", "kind": 30063, "created_at": 1790380000, "content": "notes", "tags": [["d", "com.example.app@1.4.2"], ["a", "32267:aaa:com.example.app"], ["version", "1.4.2"], ["version_scheme", "semver"], ["channel", "stable"], ["requires", "32267:bbb:com.example.runtime\u001f>=2.0.0"]]}"#,
        ])
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains("upgrade candidate true"),
        "1.4.2 on the stable channel should outrank the fixture's installed 1.4.1: {stdout}"
    );
    assert!(
        stdout.contains("requires 32267:bbb:com.example.runtime >=2.0.0"),
        "the requirement's address and constraint should read back from the two-column tag: {stdout}"
    );
}

#[test]
fn ncc13_artefact_metadata_handler_selects_by_platform() {
    let output = Command::new(env!("CARGO_BIN_EXE_nscript"))
        .arg("run")
        .arg(repository_path("conformance/valid/ncc13-package-release.ns"))
        .args([
            "--event",
            r#"{"event_type": "ArtefactMetadata", "kind": 1063, "created_at": 1790380000, "content": "", "tags": [["url", "https://example.com/app_arm64.deb"], ["os", "linux"], ["arch", "arm64"], ["format", "deb"]]}"#,
        ])
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains("matches linux/arm64: true"),
        "the linux/arm64 artefact should match the fixture's wanted linux/arm64 platform: {stdout}"
    );
}

#[test]
fn ncc03_election_definition_lowers_to_the_pinned_wire_vector() {
    let vector: serde_json::Value = serde_json::from_slice(
        &std::fs::read(repository_path("conformance/vectors/ncc03.json")).unwrap(),
    )
    .unwrap();
    let expected = &vector["vectors"][0];
    let output = Command::new(env!("CARGO_BIN_EXE_nscript"))
        .args(["inspect", "--json"])
        .arg(repository_path("conformance/valid/ncc03-election.ns"))
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let value: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    let create = &value["publication_trace"][0]["steps"][0];
    assert_eq!(create["op"], "create_event");
    assert_eq!(create["event"], "ElectionDefinition");
    assert_eq!(create["kind"], expected["kind"]);
    // `option` entries are built by ncc03.option_entry at publish time (a
    // `.ns` literal cannot carry the tag column separator), so the checked
    // snapshot holds only the literal fields.
    assert_eq!(create["tags"], expected["tags"]);
    assert_eq!(create["content"], expected["content"]);
}

#[test]
fn ncc03_vote_handler_enforces_the_voting_window_and_declared_options() {
    let run_vote = |created_at: u64, choice: &str, reference: &str| {
        let event = format!(
            r#"{{"event_type": "Vote", "kind": 1071, "created_at": {created_at}, "content": "", "tags": [["e", "{reference}"], ["d", "board-chair-2026"], ["choice", "{choice}"]]}}"#
        );
        let output = Command::new(env!("CARGO_BIN_EXE_nscript"))
            .arg("run")
            .arg(repository_path("conformance/valid/ncc03-election.ns"))
            .args(["--event", &event])
            .output()
            .unwrap();
        assert!(
            output.status.success(),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
        String::from_utf8_lossy(&output.stdout).into_owned()
    };

    // §6.2: startsAt is inclusive, endsAt is exclusive.
    assert!(
        run_vote(1_790_380_000, "yes", "board-chair-event").contains("vote for yes: valid true")
    );
    assert!(run_vote(1_790_383_599, "no", "board-chair-event").contains("vote for no: valid true"));
    assert!(run_vote(1_790_383_600, "yes", "board-chair-event").contains("valid false"));
    assert!(run_vote(1_790_379_999, "yes", "board-chair-event").contains("valid false"));
    // §6.3: the option must be declared; §6.1: the election must match.
    assert!(run_vote(1_790_381_000, "maybe", "board-chair-event").contains("valid false"));
    assert!(run_vote(1_790_381_000, "yes", "another-election").contains("valid false"));
}

fn scaffold_into(template: &str, tag: &str) -> PathBuf {
    let directory = std::env::temp_dir().join(format!(
        "nscript-new-{}-{tag}-{template}",
        std::process::id()
    ));
    let _ = std::fs::remove_dir_all(&directory);
    let output = Command::new(env!("CARGO_BIN_EXE_nscript"))
        .args(["new", template])
        .arg(&directory)
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    directory
}

#[test]
fn every_starter_template_scaffolds_checks_and_passes_its_own_samples() {
    let list = Command::new(env!("CARGO_BIN_EXE_nscript"))
        .args(["new", "--list"])
        .output()
        .unwrap();
    assert!(list.status.success());
    let listed = String::from_utf8_lossy(&list.stdout).into_owned();
    let templates: Vec<&str> = listed
        .lines()
        .filter_map(|line| line.split_whitespace().next())
        .collect();
    assert_eq!(
        templates,
        ["moderation-bot", "scheduled-poster", "relay-monitor"]
    );

    for template in templates {
        let directory = scaffold_into(template, "all");
        for file in ["bot.ns", "README.md", "test.sh", "nscript.lock.json"] {
            assert!(
                directory.join(file).is_file(),
                "{template} is missing {file}"
            );
        }

        // `inspect --json` is the permission-footprint review path a new
        // user is told to run; it must succeed with no diagnostics.
        let inspect = Command::new(env!("CARGO_BIN_EXE_nscript"))
            .args(["inspect", "--json"])
            .arg(directory.join("bot.ns"))
            .output()
            .unwrap();
        assert!(
            inspect.status.success(),
            "{template}: {}",
            String::from_utf8_lossy(&inspect.stderr)
        );

        // The generated test.sh checks the source, verifies the lockfile and
        // runs every sample event against its `.expect` line.
        let test = Command::new("bash")
            .arg(directory.join("test.sh"))
            .env("NSCRIPT", env!("CARGO_BIN_EXE_nscript"))
            .output()
            .unwrap();
        assert!(
            test.status.success(),
            "{template}: {}{}",
            String::from_utf8_lossy(&test.stdout),
            String::from_utf8_lossy(&test.stderr)
        );
        let _ = std::fs::remove_dir_all(&directory);
    }
}

#[test]
fn a_starter_template_states_what_is_simulated_and_what_is_live() {
    // Roadmap Phase 5a: a template must not imply live behaviour that
    // `nscript deploy` does not provide.
    for template in ["moderation-bot", "scheduled-poster", "relay-monitor"] {
        let directory = scaffold_into(template, "docs");
        let readme = std::fs::read_to_string(directory.join("README.md")).unwrap();
        assert!(
            readme.contains("## What is simulated and what is live")
                || readme.contains("## What it does and does not tell you"),
            "{template} README must state what is simulated and what is live"
        );
        let bot = std::fs::read_to_string(directory.join("bot.ns")).unwrap();
        assert!(
            bot.contains("simulat") || bot.contains("nscript deploy") || bot.contains("Read-only"),
            "{template} bot.ns must say what its effects are"
        );
        let _ = std::fs::remove_dir_all(&directory);
    }
    let moderation = scaffold_into("moderation-bot", "sim");
    let readme = std::fs::read_to_string(moderation.join("README.md")).unwrap();
    assert!(
        readme.contains("Everything is simulated today"),
        "the moderation template must not read as live moderation"
    );
    let _ = std::fs::remove_dir_all(&moderation);
}

#[test]
fn new_refuses_a_non_empty_directory_and_an_unknown_template() {
    let directory = scaffold_into("relay-monitor", "refuse");
    let again = Command::new(env!("CARGO_BIN_EXE_nscript"))
        .args(["new", "relay-monitor"])
        .arg(&directory)
        .output()
        .unwrap();
    assert!(!again.status.success());
    assert!(
        String::from_utf8_lossy(&again.stderr).contains("already exists and is not empty"),
        "{}",
        String::from_utf8_lossy(&again.stderr)
    );
    let unknown = Command::new(env!("CARGO_BIN_EXE_nscript"))
        .args(["new", "no-such-template"])
        .arg(directory.join("x"))
        .output()
        .unwrap();
    assert_eq!(unknown.status.code(), Some(2));
    assert!(String::from_utf8_lossy(&unknown.stderr).contains("unknown template"));
    let _ = std::fs::remove_dir_all(&directory);
}

/// Every `.ns` source the repository ships: the conformance corpus, the
/// examples, and the starter templates.
fn all_repository_sources() -> Vec<PathBuf> {
    let mut sources = Vec::new();
    for directory in ["conformance/valid", "conformance/invalid", "examples"] {
        for entry in std::fs::read_dir(repository_path(directory)).unwrap() {
            let path = entry.unwrap().path();
            if path.extension().is_some_and(|extension| extension == "ns") {
                sources.push(path);
            }
        }
    }
    for entry in std::fs::read_dir(repository_path("templates")).unwrap() {
        let bot = entry.unwrap().path().join("bot.ns");
        if bot.is_file() {
            sources.push(bot);
        }
    }
    sources.sort();
    sources
}

/// Roadmap Phase 5b: diagnostics seen in an editor must match
/// `nscript check` exactly, for every source the repository ships.
#[test]
fn the_language_server_reports_exactly_the_diagnostics_nscript_check_does() {
    let sources = all_repository_sources();
    assert!(sources.len() > 100, "found only {} sources", sources.len());
    let mut with_diagnostics = 0;
    for path in &sources {
        let text = std::fs::read_to_string(path).unwrap();
        let output = Command::new(env!("CARGO_BIN_EXE_nscript"))
            .arg("check")
            .arg(path)
            .output()
            .unwrap();
        let prefix = format!("{}:", path.display());
        let cli: Vec<(usize, usize, String, String)> = String::from_utf8_lossy(&output.stderr)
            .lines()
            .filter_map(|line| {
                let rest = line.strip_prefix(&prefix)?;
                let (line_number, rest) = rest.split_once(':')?;
                let (column, rest) = rest.split_once(": error[")?;
                let (code, message) = rest.split_once("]: ")?;
                Some((
                    line_number.parse().ok()?,
                    column.parse().ok()?,
                    code.to_owned(),
                    message.to_owned(),
                ))
            })
            .collect();

        let mut server = nscript_lsp::Server::new();
        server.handle(
            &serde_json::json!({"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {}}),
        );
        let published = server.handle(&serde_json::json!({
            "jsonrpc": "2.0",
            "method": "textDocument/didOpen",
            "params": {"textDocument": {"uri": "file:///check.ns", "languageId": "nscript", "version": 1, "text": text}},
        }));
        let editor = published[0]["params"]["diagnostics"].as_array().unwrap();

        assert_eq!(
            editor.len(),
            cli.len(),
            "{}: the editor shows {} diagnostics, `nscript check` {}",
            path.display(),
            editor.len(),
            cli.len()
        );
        if !cli.is_empty() {
            with_diagnostics += 1;
        }
        for (shown, (line, column, code, message)) in editor.iter().zip(&cli) {
            let at = path.display();
            assert_eq!(shown["code"], code.as_str(), "{at}: code");
            assert_eq!(shown["message"], message.as_str(), "{at}: message");
            let start_line =
                usize::try_from(shown["range"]["start"]["line"].as_u64().unwrap()).unwrap();
            assert_eq!(start_line + 1, *line, "{at}: line");
            // LSP columns are UTF-16 units and the CLI's are not, so compare
            // columns only on lines where the two cannot differ.
            let source_line = text.lines().nth(start_line).unwrap_or_default();
            if source_line.is_ascii() {
                let start_column =
                    usize::try_from(shown["range"]["start"]["character"].as_u64().unwrap())
                        .unwrap();
                assert_eq!(start_column + 1, *column, "{at}: column");
            }
        }
    }
    assert!(
        with_diagnostics > 20,
        "the corpus should include many failing sources, found {with_diagnostics}"
    );
}

/// The examples that import modules outside the standard library resolve them
/// from `examples/modules` with `-M`; without it they fail with E4002.
fn run_example_with_modules(example: &str, event: Option<&str>) -> std::process::Output {
    let mut command = Command::new(env!("CARGO_BIN_EXE_nscript"));
    command
        .arg("run")
        .arg("-M")
        .arg(repository_path("examples/modules"))
        .arg(repository_path(example));
    if let Some(event) = event {
        command.args(["--event", event]);
    }
    let output = command.output().unwrap();
    assert!(
        output.status.success(),
        "{example}: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    output
}

#[test]
fn every_example_checks_and_the_external_module_ones_need_their_modules() {
    let mut needing_modules = 0;
    for entry in std::fs::read_dir(repository_path("examples")).unwrap() {
        let path = entry.unwrap().path();
        if path.extension().is_none_or(|extension| extension != "ns") {
            continue;
        }
        let checked = Command::new(env!("CARGO_BIN_EXE_nscript"))
            .args(["check", "-M"])
            .arg(repository_path("examples/modules"))
            .arg(&path)
            .output()
            .unwrap();
        assert!(
            checked.status.success(),
            "{} does not check: {}",
            path.display(),
            String::from_utf8_lossy(&checked.stderr)
        );
        // Without -M, an example that imports an external module reports it
        // as missing rather than failing some other way.
        let bare = Command::new(env!("CARGO_BIN_EXE_nscript"))
            .arg("check")
            .arg(&path)
            .output()
            .unwrap();
        if !bare.status.success() {
            needing_modules += 1;
            assert!(
                String::from_utf8_lossy(&bare.stderr).contains("error[E4002]"),
                "{} fails without -M for the wrong reason: {}",
                path.display(),
                String::from_utf8_lossy(&bare.stderr)
            );
        }
    }
    assert_eq!(
        needing_modules, 4,
        "moderation, server-monitor, constrained-agent, http-integration"
    );
}

#[test]
fn the_external_module_examples_do_what_their_headers_say() {
    let note = |content: &str| {
        format!(
            r#"{{"event_type": "Note", "kind": 1, "id": "abc", "content": "{content}", "tags": [["t", "nostrhost"]]}}"#
        )
    };
    let status = |disk: &str| {
        format!(
            r#"{{"event_type": "ServerStatus", "kind": 9311, "content": "", "tags": [["server", "web-1"], ["disk", "{disk}"]]}}"#
        )
    };
    let stdout = |example: &str, event: Option<&str>| {
        String::from_utf8_lossy(&run_example_with_modules(example, event).stdout).into_owned()
    };

    assert!(
        stdout("examples/moderation.ns", Some(&note("buy spam now")))
            .contains("moderation event published (accepted: true)")
    );
    assert!(
        !stdout("examples/moderation.ns", Some(&note("hello"))).contains("published"),
        "a clean note publishes nothing"
    );
    assert!(
        stdout("examples/server-monitor.ns", Some(&status("critical")))
            .contains("alert published (accepted: true)")
    );
    assert!(
        stdout("examples/server-monitor.ns", Some(&status("ok"))).contains("no handler matched"),
        "a healthy report matches no handler"
    );
    assert!(
        stdout("examples/constrained-agent.ns", Some(&status("critical")))
            .contains("package requested (accepted: true)")
    );
    assert!(stdout("examples/http-integration.ns", None).contains("1/1 relays accepted"));
}

#[test]
fn the_constrained_agent_requests_no_more_authority_than_it_says() {
    let output = Command::new(env!("CARGO_BIN_EXE_nscript"))
        .args(["inspect", "-M"])
        .arg(repository_path("examples/modules"))
        .arg(repository_path("examples/constrained-agent.ns"))
        .output()
        .unwrap();
    assert!(output.status.success());
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("effects: Relay, Sign, Log"), "{stdout}");
    assert!(stdout.contains("publications: 1"), "{stdout}");
    assert!(stdout.contains("schedules: 0"), "{stdout}");
}

/// Roadmap item "check and run agree": an unqualified call `check` accepts is
/// one `run` executes, not one that fails when a handler reaches it.
#[test]
fn bare_and_method_calls_resolve_to_the_same_operations_as_the_qualified_form() {
    let event = r#"{"event_type": "Note", "kind": 1, "created_at": 1790380000, "content": "x", "tags": []}"#;
    let run = |file: &str| {
        let output = Command::new(env!("CARGO_BIN_EXE_nscript"))
            .arg("run")
            .arg(repository_path(file))
            .args(["--event", event])
            .output()
            .unwrap();
        assert!(
            output.status.success(),
            "{file}: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        String::from_utf8_lossy(&output.stdout).into_owned()
    };

    // The sugar: `npub(...)` and `encoded.pubkey()`.
    let sugar = run("conformance/valid/bare-and-method-calls.ns");
    assert!(sugar.contains("log info: converted"), "{sugar}");

    // The same program written with qualified calls executes the same two
    // operations, in the same order, with the receiver as the first argument.
    let qualified_source = std::fs::read_to_string(repository_path(
        "conformance/valid/bare-and-method-calls.ns",
    ))
    .unwrap()
    .replace("= npub(", "= nip19.npub(")
    .replace("encoded.pubkey()", "nip19.pubkey(encoded)");
    let (ok, qualified, stderr) =
        run_source("qualified-calls", &qualified_source, &["--event", event]);
    assert!(ok, "{stderr}");
    let operations = |output: &str| {
        output
            .lines()
            .filter(|line| line.trim_start().starts_with("operation "))
            .map(|line| line.split('(').next().unwrap().trim().to_owned())
            .collect::<Vec<_>>()
    };
    assert_eq!(operations(&sugar), operations(&qualified));
    assert_eq!(
        operations(&sugar),
        ["operation nip19.npub", "operation nip19.pubkey"]
    );
}

#[test]
fn an_unresolved_call_is_a_check_error_not_a_run_failure() {
    for (fixture, code, wording) in [
        ("unknown-function", "E1101", "unknown function `frobnicate`"),
        ("unknown-method", "E1101", "no method `looks_like_spam`"),
        (
            "builtin-wrong-arity",
            "E1102",
            "`len` expects 1 argument, found 2",
        ),
        (
            "method-wrong-arity",
            "E1102",
            "`nip19.pubkey` expects 1 arguments, found 2",
        ),
        (
            "bare-call-missing-permission",
            "E3001",
            "requires `decrypt` permission",
        ),
    ] {
        let path = repository_path(&format!("conformance/invalid/{fixture}.ns"));
        // `run` refuses it before any handler is reached, with the same error.
        for command in ["check", "run"] {
            let output = Command::new(env!("CARGO_BIN_EXE_nscript"))
                .arg(command)
                .arg(&path)
                .output()
                .unwrap();
            let stderr = String::from_utf8_lossy(&output.stderr);
            assert!(!output.status.success(), "{fixture} {command} passed");
            assert!(
                stderr.contains(&format!("error[{code}]")) && stderr.contains(wording),
                "{fixture} {command}: {stderr}"
            );
            assert!(
                !stderr.contains("R1004"),
                "{fixture} {command} reached a handler: {stderr}"
            );
        }
    }
}

#[test]
fn calls_inside_a_select_predicate_are_a_query_not_handler_code() {
    // The predicate language is lowered to a relay filter or run locally, so
    // `follows(me)` and `content.words().count()` are not resolved against
    // modules. Handler code with the same shape is rejected.
    let timeline = Command::new(env!("CARGO_BIN_EXE_nscript"))
        .arg("check")
        .arg(repository_path("examples/timeline.ns"))
        .output()
        .unwrap();
    assert!(
        timeline.status.success(),
        "examples/timeline.ns: {}",
        String::from_utf8_lossy(&timeline.stderr)
    );
    let output = Command::new(env!("CARGO_BIN_EXE_nscript"))
        .arg("check")
        .arg(repository_path(
            "conformance/invalid/unbounded-local-filter.ns",
        ))
        .output()
        .unwrap();
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("error[E2401]"), "{stderr}");
    assert!(!stderr.contains("E1101"), "{stderr}");
}

#[test]
fn a_publish_evaluates_to_a_named_report_with_one_readable_field() {
    let event = r#"{"event_type": "Note", "kind": 1, "created_at": 1790380000, "content": "x", "tags": [["t", "trigger"]]}"#;
    let output = Command::new(env!("CARGO_BIN_EXE_nscript"))
        .arg("run")
        .arg(repository_path("conformance/valid/publish-report.ns"))
        .args(["--event", event])
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(
        String::from_utf8_lossy(&output.stdout).contains("log info: accepted: true"),
        "{}",
        String::from_utf8_lossy(&output.stdout)
    );

    // A field the report does not have is refused at `check`, before any
    // handler runs, naming the one field it does have.
    let output = Command::new(env!("CARGO_BIN_EXE_nscript"))
        .arg("run")
        .arg(repository_path(
            "conformance/invalid/publish-report-unknown-field.ns",
        ))
        .output()
        .unwrap();
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(!output.status.success());
    assert!(
        stderr.contains("`report` (a `PublishReport`) has no field `relays`")
            && stderr.contains("its fields are: accepted"),
        "{stderr}"
    );
    assert!(!stderr.contains("R1004"), "{stderr}");
}

#[test]
fn an_undeclared_name_is_a_check_error_not_a_run_failure() {
    for (fixture, wording) in [
        ("undeclared-name", "unknown name `count`"),
        ("let-out-of-scope", "unknown name `inner`"),
        (
            "top-level-let-in-handler",
            "it is a top-level `let`, which handlers, functions and schedules cannot see",
        ),
        ("event-in-function", "it is only bound inside a handler"),
    ] {
        let path = repository_path(&format!("conformance/invalid/{fixture}.ns"));
        for command in ["check", "run"] {
            let output = Command::new(env!("CARGO_BIN_EXE_nscript"))
                .arg(command)
                .arg(&path)
                .output()
                .unwrap();
            let stderr = String::from_utf8_lossy(&output.stderr);
            assert!(!output.status.success(), "{fixture} {command} passed");
            assert!(
                stderr.contains("error[E1101]") && stderr.contains(wording),
                "{fixture} {command}: {stderr}"
            );
            // Refused before any handler ran, not discovered inside one.
            assert!(
                !stderr.contains("R1004"),
                "{fixture} {command} reached a handler: {stderr}"
            );
        }
    }
}

#[test]
fn every_way_a_name_comes_into_scope_checks_and_runs() {
    let output = Command::new(env!("CARGO_BIN_EXE_nscript"))
        .args(["run", "--as", "alice"])
        .arg(repository_path("conformance/valid/name-scopes.ns"))
        .args([
            "--event",
            r#"{"event_type": "Note", "kind": 1, "created_at": 1790380000, "content": "x", "tags": [["t", "a"], ["t", "b"]]}"#,
        ])
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("log info: tags: 2"), "{stdout}");
    assert!(stdout.contains("log info: alice"), "{stdout}");
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
    assert!(
        stdout.contains("log info: cross-posted a link from alice"),
        "{stdout}"
    );

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
fn publish_from_inside_a_handler_only_fires_when_the_handler_actually_runs() {
    let path = repository_path("examples/handler-publish-bot.ns");

    // No event at all: the handler never runs, so its `publish` must not
    // fire — this used to fire unconditionally at startup regardless of
    // whether any event ever reached the handler it was written inside.
    let output = Command::new(env!("CARGO_BIN_EXE_nscript"))
        .arg("run")
        .arg(&path)
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(!stdout.contains("publication"), "{stdout}");
    assert!(!stdout.contains("log info: true"), "{stdout}");

    // A matching event: the handler runs and really creates, signs and
    // publishes a reply.
    let output = Command::new(env!("CARGO_BIN_EXE_nscript"))
        .arg("run")
        .arg(&path)
        .args([
            "--event",
            r#"{"content":"are you there?","tags":[["t","trigger"]]}"#,
        ])
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("handler Note: ok"), "{stdout}");
    assert!(stdout.contains("log info: true"), "{stdout}");
}

#[test]
fn the_capability_bot_publishes_its_manifest_and_reads_peer_capabilities() {
    let path = repository_path("examples/ncc07-capability-bot.ns");

    // Startup: the 24h body publishes the manifest once and registers the
    // refresh timer.
    let output = Command::new(env!("CARGO_BIN_EXE_nscript"))
        .arg("run")
        .arg(&path)
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains("timer schedule-0 at 1700086400"),
        "{stdout}"
    );
    assert!(
        stdout.contains("publication 0: 1/1 relays accepted"),
        "{stdout}"
    );
    assert!(!stdout.contains("peer advertises"), "{stdout}");

    // A delivered peer manifest: the reader handler selects its cap tags
    // with the module's pure functions.
    let output = Command::new(env!("CARGO_BIN_EXE_nscript"))
        .arg("run")
        .arg(&path)
        .args([
            "--event",
            r#"{"event_type": "CapabilityManifest", "kind": 30062, "content": "", "tags": [["d", "capabilities"], ["cap", "ncc:05"], ["cap", "nip:17"]]}"#,
        ])
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains("handler CapabilityManifest: ok"),
        "{stdout}"
    );
    assert!(
        stdout.contains("peer advertises 2 capabilities"),
        "{stdout}"
    );
    assert!(
        stdout.contains("peer serves community profiles (ncc:05)"),
        "{stdout}"
    );
    assert!(stdout.contains("ncc:05 namespace: ncc"), "{stdout}");
}

#[test]
fn the_implementation_ledger_records_ncc_documents_it_receives() {
    let path = repository_path("examples/ncc00-implementation-ledger.ns");

    // Startup: only the reader handler is registered; the ledger publishes
    // nothing until a convention document arrives.
    let output = Command::new(env!("CARGO_BIN_EXE_nscript"))
        .arg("run")
        .arg(&path)
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("note: 1 handler(s) registered"), "{stdout}");
    assert!(!stdout.contains("ledger record"), "{stdout}");

    // A delivered NCC document NScript implements: the handler publishes
    // the authority-free kind-30053 record that stamps it, timestamped by
    // the delivered event's own created_at.
    let output = Command::new(env!("CARGO_BIN_EXE_nscript"))
        .arg("run")
        .arg(&path)
        .args([
            "--event",
            r##"{"event_type": "NccDocument", "kind": 30050, "id": "doc1", "created_at": 1766012345, "content": "# NCC-00", "tags": [["d", "ncc-00"], ["status", "published"]]}"##,
        ])
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("handler NccDocument: ok"), "{stdout}");
    assert!(
        stdout.contains("ledger record for ncc-00 (published): true"),
        "{stdout}"
    );

    // A convention NScript does not implement: the handler stays quiet.
    let output = Command::new(env!("CARGO_BIN_EXE_nscript"))
        .arg("run")
        .arg(&path)
        .args([
            "--event",
            r##"{"event_type": "NccDocument", "kind": 30050, "content": "# NCC-03", "tags": [["d", "ncc-03"], ["status", "published"]]}"##,
        ])
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("handler NccDocument: ok"), "{stdout}");
    assert!(!stdout.contains("ledger record"), "{stdout}");
}

#[test]
fn the_service_registry_publishes_its_record_and_judges_what_it_receives() {
    let path = repository_path("examples/ncc02-service-registry.ns");
    let run = |extra: &[&str]| {
        Command::new(env!("CARGO_BIN_EXE_nscript"))
            .arg("run")
            .arg(&path)
            .args(extra)
            .output()
            .unwrap()
    };

    // Startup: the 7d schedule publishes the record once and registers the
    // refresh timer; with no record delivered there is no verdict either.
    let output = run(&[]);
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains("timer schedule-0 at 1700604800"),
        "{stdout}"
    );
    assert!(
        stdout.contains("publication 0: 1/1 relays accepted"),
        "{stdout}"
    );
    assert!(!stdout.contains("service relay serves"), "{stdout}");

    // Delivered peer records: `ncc02.record_is_valid` judges each against
    // the event's own created_at — one inside its window, one expired.
    let valid = r#"{"event_type": "ServiceRecord", "kind": 30059, "created_at": 1700000000, "content": "", "tags": [["d", "relay"], ["u", "wss://relay.example.com"], ["k", "9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08"], ["exp", "1700600000"]]}"#;
    let expired = r#"{"event_type": "ServiceRecord", "kind": 30059, "created_at": 1700000000, "content": "", "tags": [["d", "relay"], ["u", "wss://relay.example.com"], ["k", "9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08"], ["exp", "1699999999"]]}"#;
    let output = run(&["--event", valid, "--event", expired]);
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("handler ServiceRecord: ok"), "{stdout}");
    assert!(
        stdout.contains("service relay serves wss://relay.example.com over wss"),
        "{stdout}"
    );
    assert!(
        stdout.contains("service relay rejected: expired or incomplete"),
        "{stdout}"
    );

    // An attestation from the registry's own certifier, one from another
    // key, and the revocation that withdraws the relied-upon attestation.
    let trusted = r#"{"event_type": "CertificateAttestation", "kind": 30060, "created_at": 1700000000, "content": "", "signer": "cab92accfa504f09d3d705a27ecf7bc6b4d65362d9c749e97628a95f9259aa9a", "tags": [["d", "relay:4d3bb1c02befc39da9fcdb96e8065074e13d70c428ae3ef9cda040ce9e6f3130"], ["subj", "4d3bb1c02befc39da9fcdb96e8065074e13d70c428ae3ef9cda040ce9e6f3130"], ["srv", "relay"], ["e", "31e194e9cfeee08eb7cb78e680aed5c2f9ca27a28a189fe54dc1319ec424e859"], ["std", "wss"], ["lvl", "hardened"], ["nbf", "1699900000"], ["exp", "1700600000"]]}"#;
    let untrusted = r#"{"event_type": "CertificateAttestation", "kind": 30060, "created_at": 1700000000, "content": "", "signer": "3f905f84d32cbae986039df02c070175d6fdde0913d1b70df55592956ddd0e0d", "tags": [["d", "relay:4d3bb1c02befc39da9fcdb96e8065074e13d70c428ae3ef9cda040ce9e6f3130"], ["subj", "4d3bb1c02befc39da9fcdb96e8065074e13d70c428ae3ef9cda040ce9e6f3130"], ["srv", "relay"], ["e", "31e194e9cfeee08eb7cb78e680aed5c2f9ca27a28a189fe54dc1319ec424e859"], ["std", "wss"], ["lvl", "verified"], ["nbf", "1699900000"], ["exp", "1700600000"]]}"#;
    let revoked = r#"{"event_type": "Revocation", "kind": 30061, "created_at": 1700000000, "content": "", "tags": [["d", "relay:4d3bb1c02befc39da9fcdb96e8065074e13d70c428ae3ef9cda040ce9e6f3130"], ["e", "31e194e9cfeee08eb7cb78e680aed5c2f9ca27a28a189fe54dc1319ec424e859"], ["reason", "key rotated"]]}"#;
    let output = run(&["--event", trusted, "--event", untrusted, "--event", revoked]);
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains("handler CertificateAttestation: ok"),
        "{stdout}"
    );
    assert!(
        stdout.contains("trusted hardened attestation accepted"),
        "{stdout}"
    );
    assert!(
        stdout.contains("attestation from an untrusted certifier: 3f905f84d32cbae986039df02c070175d6fdde0913d1b70df55592956ddd0e0d"),
        "{stdout}"
    );
    assert!(stdout.contains("handler Revocation: ok"), "{stdout}");
    assert!(
        stdout.contains(
            "attestation 31e194e9cfeee08eb7cb78e680aed5c2f9ca27a28a189fe54dc1319ec424e859 withdrawn: trust it no longer"
        ),
        "{stdout}"
    );
}

#[test]
fn the_locator_bot_encrypts_the_payload_it_publishes_and_judges_what_it_receives() {
    let path = repository_path("examples/ncc05-locator-bot.ns");
    let run = |extra: &[&str]| {
        Command::new(env!("CARGO_BIN_EXE_nscript"))
            .arg("run")
            .arg(&path)
            .args(extra)
            .output()
            .unwrap()
    };

    // No event: both readers idle, and no locator is published.
    let output = run(&[]);
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("note: 2 handler(s) registered"), "{stdout}");
    assert!(!stdout.contains("locator for"), "{stdout}");

    // A peer's Service Record inside its window: the payload is rebuilt
    // from the record, NIP-44-encrypted into `content` (§5.1) and
    // published as the Locator.
    let valid = r#"{"event_type": "ServiceRecord", "kind": 30059, "created_at": 1700000000, "content": "", "tags": [["d", "relay"], ["u", "wss://relay.example.com"], ["k", "9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08"], ["exp", "1700600000"]]}"#;
    let output = run(&["--event", valid]);
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("handler ServiceRecord: ok"), "{stdout}");
    assert!(
        stdout.contains(
            "locator for relay published (accepted: true), endpoints [wss://relay.example.com]"
        ),
        "{stdout}"
    );
    assert!(
        stdout.contains(
            "operation nip44.encrypt_text(Text(\"{\\\"caps\\\":[\\\"nostr-connect\\\"],\\\"endpoints\\\":"
        ),
        "{stdout}"
    );

    // An expired record builds no locator at all.
    let expired = r#"{"event_type": "ServiceRecord", "kind": 30059, "created_at": 1700000000, "content": "", "tags": [["d", "relay"], ["u", "wss://relay.example.com"], ["k", "9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08"], ["exp", "1699999999"]]}"#;
    let output = run(&["--event", expired]);
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains("service relay rejected: expired or incomplete"),
        "{stdout}"
    );
    assert!(!stdout.contains("locator for relay published"), "{stdout}");

    // A locator received in the clear — §5.2's exception, the shape a
    // reader can judge end to end today — is fresh, so it prints.
    let readable = r#"{"event_type": "Locator", "kind": 30058, "created_at": 1700000000, "content": "{\"v\":1,\"ttl\":600,\"updated_at\":1700000000,\"endpoints\":[{\"url\":\"203.0.113.42:9735\",\"priority\":10,\"family\":\"ipv4\"}],\"caps\":[\"nostr-connect\"]}", "tags": [["d", "addr"], ["expiration", "1700000600"]]}"#;
    let output = run(&["--event", readable]);
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("handler Locator: ok"), "{stdout}");
    assert!(
        stdout.contains("addr publishes [203.0.113.42:9735] for [nostr-connect]"),
        "{stdout}"
    );

    // One whose payload window closed, and one whose content cannot be
    // read as a payload at all (the encrypted envelope a peer published):
    // both are discarded rather than used (§7 event selection).
    let stale = r#"{"event_type": "Locator", "kind": 30058, "created_at": 1700000000, "content": "{\"v\":1,\"ttl\":600,\"updated_at\":1699999000,\"endpoints\":[{\"url\":\"203.0.113.42:9735\",\"priority\":10,\"family\":\"ipv4\"}]}", "tags": [["d", "addr"], ["expiration", "1700000600"]]}"#;
    let sealed = r#"{"event_type": "Locator", "kind": 30058, "created_at": 1700000000, "content": "encrypted-1", "tags": [["d", "addr"], ["expiration", "1700000600"]]}"#;
    for event in [stale, sealed] {
        let output = run(&["--event", event]);
        assert!(
            output.status.success(),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
        let stdout = String::from_utf8_lossy(&output.stdout);
        assert!(
            stdout.contains("locator addr discarded: expired, unaddressed, or payload unreadable"),
            "{stdout}"
        );
    }
}

#[test]
fn the_service_monitor_judges_records_and_locators_under_ncc06() {
    let path = repository_path("examples/ncc06-service-monitor.ns");
    let run = |extra: &[&str]| {
        Command::new(env!("CARGO_BIN_EXE_nscript"))
            .arg("run")
            .arg(&path)
            .args(extra)
            .output()
            .unwrap()
    };

    // No event: both readers idle, nothing judged.
    let output = run(&[]);
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("note: 2 handler(s) registered"), "{stdout}");
    assert!(!stdout.contains("service relay"), "{stdout}");

    // A fresh record with a concrete endpoint: §E.1 ranks it in the top
    // tier (secure, pinned k in hand) and §E.2 states the obligation
    // that follows from presenting key material.
    let concrete = r#"{"event_type": "ServiceRecord", "kind": 30059, "created_at": 1700000000, "content": "", "tags": [["d", "relay"], ["u", "wss://relay.example.com"], ["k", "9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08"], ["exp", "1700600000"]]}"#;
    let output = run(&["--event", concrete]);
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("handler ServiceRecord: ok"), "{stdout}");
    assert!(
        stdout.contains(
            "service relay serves wss://relay.example.com at §E.1 rank 0 with pinned k 9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08; §E.2 requires the connection to match it"
        ),
        "{stdout}"
    );

    // An identity reference names a key, not a socket: §Scope decodes
    // which key and never dereferences the reference itself.
    let reference = r#"{"event_type": "ServiceRecord", "kind": 30059, "created_at": 1700000000, "content": "", "tags": [["d", "relay"], ["u", "wss://npub10elfcs4fr0l0r8af98jlmgdh9c8tcxjvz9qkw038js35mp4dma8qzvjptg"], ["k", "9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08"], ["exp", "1700600000"]]}"#;
    let output = run(&["--event", reference]);
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains(
            "service relay names identity 7e7e9c42a91bfef19fa929e5fda1b72e0ebc1a4c1141673e2794234d86addf4e; resolve its records over the publication relays, never the reference"
        ),
        "{stdout}"
    );

    // An expired record is rejected before it is tiered anywhere.
    let expired = r#"{"event_type": "ServiceRecord", "kind": 30059, "created_at": 1700000000, "content": "", "tags": [["d", "relay"], ["u", "wss://relay.example.com"], ["k", "9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08"], ["exp", "1699999999"]]}"#;
    let output = run(&["--event", expired]);
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains("service relay rejected: expired or incomplete"),
        "{stdout}"
    );

    // A fresh locator: §E.1 regroups its endpoints — secure with k,
    // then onion, then insecure — keeping the payload's order within
    // each tier.
    let fresh = r#"{"event_type": "Locator", "kind": 30058, "created_at": 1700000000, "content": "{\"v\":1,\"ttl\":600,\"updated_at\":1700000000,\"endpoints\":[{\"url\":\"ws://a.example.com\"},{\"url\":\"wss://b.example.com\"},{\"url\":\"onion://vww6ybal4bd7st.onion\"}]}", "tags": [["d", "addr"], ["expiration", "1700000600"]]}"#;
    let output = run(&["--event", fresh]);
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("handler Locator: ok"), "{stdout}");
    assert!(
        stdout.contains(
            "locator addr is fresh (§D.3): [wss://b.example.com, onion://vww6ybal4bd7st.onion, ws://a.example.com]"
        ),
        "{stdout}"
    );

    // An expiration tag that has passed over a recently built payload:
    // §D.3's bounded staleness surfaces as "stale" — printed for the
    // operator, not acted on.
    let stale = r#"{"event_type": "Locator", "kind": 30058, "created_at": 1700000000, "content": "{\"v\":1,\"ttl\":600,\"updated_at\":1700000000,\"endpoints\":[{\"url\":\"wss://old.example.com\"}]}", "tags": [["d", "addr"], ["expiration", "1699999999"]]}"#;
    let output = run(&["--event", stale]);
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains("locator addr is stale (§D.3): [wss://old.example.com]"),
        "{stdout}"
    );

    // A payload too old to fall back on (§D.2, past the staleness
    // bound): discarded rather than used.
    let failed = r#"{"event_type": "Locator", "kind": 30058, "created_at": 1700000000, "content": "{\"v\":1,\"ttl\":600,\"updated_at\":1699990000,\"endpoints\":[{\"url\":\"wss://old.example.com\"}]}", "tags": [["d", "addr"], ["expiration", "1700000600"]]}"#;
    let output = run(&["--event", failed]);
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains("locator addr discarded: freshness failed (§D.2)"),
        "{stdout}"
    );
}

#[test]
fn the_rotation_bot_acknowledges_proposals_and_reports_acceptances() {
    let path = repository_path("examples/ncc08-rotation-bot.ns");
    let run = |extra: &[&str]| {
        Command::new(env!("CARGO_BIN_EXE_nscript"))
            .arg("run")
            .arg(&path)
            .args(extra)
            .output()
            .unwrap()
    };
    let handover = "8a1f8a1f8a1f8a1f8a1f8a1f8a1f8a1f8a1f8a1f8a1f8a1f8a1f8a1f8a1f8a1f";

    // No event: the watcher idles, nothing is published.
    let output = run(&[]);
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("note: 2 handler(s) registered"), "{stdout}");
    assert!(!stdout.contains("accepted "), "{stdout}");

    // A predecessor proposal for the service this bot takes over: the
    // successor signs the matching acceptance, which is published.
    let proposal = format!(
        r#"{{"event_type": "Handover", "kind": 1070, "created_at": 1790380000, "content": "", "tags": [["role", "predecessor"], ["handover", "{handover}"], ["service", "relay"], ["p", "2222222222222222222222222222222222222222222222222222222222222222"], ["effective", "1790466400"], ["expires", "1790552800"]]}}"#
    );
    let output = run(&["--event", &proposal]);
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("handler Handover: ok"), "{stdout}");
    assert!(
        stdout.contains(&format!("accepted {handover} for relay (accepted: true)")),
        "{stdout}"
    );

    // A proposal for a service this bot does not take over is ignored.
    let other_service = format!(
        r#"{{"event_type": "Handover", "kind": 1070, "created_at": 1790380000, "content": "", "tags": [["role", "predecessor"], ["handover", "{handover}"], ["service", "media"], ["p", "2222222222222222222222222222222222222222222222222222222222222222"]]}}"#
    );
    let output = run(&["--event", &other_service]);
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains("proposal ignored: this bot takes over `relay` only, not media"),
        "{stdout}"
    );

    // An incomplete proposal is rejected rather than acknowledged.
    let incomplete = format!(
        r#"{{"event_type": "Handover", "kind": 1070, "created_at": 1790380000, "content": "", "tags": [["role", "predecessor"], ["handover", "{handover}"], ["service", "relay"]]}}"#
    );
    let output = run(&["--event", &incomplete]);
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains("proposal rejected: incomplete or backdated"),
        "{stdout}"
    );

    // A peer's acceptance is judged on its shape; one missing its
    // proposal reference is incomplete, not a completed handover.
    let acceptance = format!(
        r#"{{"event_type": "Handover", "kind": 1070, "created_at": 1790383600, "content": "", "tags": [["role", "successor"], ["handover", "{handover}"], ["service", "relay"], ["p", "1111111111111111111111111111111111111111111111111111111111111111"], ["e", "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc"]]}}"#
    );
    let output = run(&["--event", &acceptance]);
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains(&format!(
            "acceptance {handover} acknowledges 1111111111111111111111111111111111111111111111111111111111111111 for relay"
        )),
        "{stdout}"
    );
    let broken = format!(
        r#"{{"event_type": "Handover", "kind": 1070, "created_at": 1790383600, "content": "", "tags": [["role", "successor"], ["handover", "{handover}"], ["service", "relay"], ["p", "1111111111111111111111111111111111111111111111111111111111111111"]]}}"#
    );
    let output = run(&["--event", &broken]);
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains("acceptance rejected: incomplete"),
        "{stdout}"
    );
}

#[test]
fn the_delegation_bot_publishes_a_scoped_grant_and_judges_grants() {
    let path = repository_path("examples/ncc09-operator-grant-bot.ns");
    let run = |extra: &[&str]| {
        Command::new(env!("CARGO_BIN_EXE_nscript"))
            .arg("run")
            .arg(&path)
            .args(extra)
            .output()
            .unwrap()
    };
    let operator = "a".repeat(64);
    let output = run(&[]);
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains("publication 0: 1/1 relays accepted"),
        "{stdout}"
    );

    let active = format!(
        r#"{{"event_type": "AuthorityGrant", "kind": 30064, "created_at": 1791000000, "content": "", "tags": [["d", "relay:{operator}"], ["service", "relay"], ["p", "{operator}"], ["status", "active"], ["scope", "ncc:10:publish"], ["valid_from", "1790380000"], ["expiration", "1792972000"]]}}"#
    );
    let output = run(&["--event", &active]);
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("handler AuthorityGrant: ok"), "{stdout}");
    assert!(
        stdout.contains(&format!(
            "grant {operator} for relay is ncc scope ncc:10:publish, delegated: true"
        )),
        "{stdout}"
    );
    assert!(
        stdout.contains("all scopes: [ncc:10:publish] (spelling valid: true)"),
        "{stdout}"
    );

    // An expired grant stays validly shaped but grants nothing.
    let expired = format!(
        r#"{{"event_type": "AuthorityGrant", "kind": 30064, "created_at": 1795000000, "content": "", "tags": [["d", "relay:{operator}"], ["service", "relay"], ["p", "{operator}"], ["status", "active"], ["scope", "ncc:10:publish"], ["expiration", "1792972000"]]}}"#
    );
    let output = run(&["--event", &expired]);
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains("grant rejected: revoked, expired, not yet valid, or incomplete"),
        "{stdout}"
    );
}

#[test]
fn the_status_bot_publishes_operator_state_and_reports_states() {
    let path = repository_path("examples/ncc10-status-bot.ns");
    let run = |extra: &[&str]| {
        Command::new(env!("CARGO_BIN_EXE_nscript"))
            .arg("run")
            .arg(&path)
            .args(extra)
            .output()
            .unwrap()
    };
    let service_pubkey = "c".repeat(64);
    let maintain = r#"{"event_type": "Note", "kind": 1, "created_at": 1790380000, "content": "please maintain", "tags": [["t", "maintain"]]}"#;
    let output = run(&["--event", maintain]);
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("handler Note: ok"), "{stdout}");
    assert!(
        stdout.contains("operator state published (accepted: true)"),
        "{stdout}"
    );

    // A direct service state is reported as such.
    let direct = r#"{"event_type": "ServiceState", "kind": 30065, "created_at": 1791000000, "content": "", "tags": [["d", "relay"], ["service", "relay"], ["state", "operational"]]}"#;
    let output = run(&["--event", direct]);
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains("service relay reports operational directly"),
        "{stdout}"
    );

    // An operator state names its principal, still only a claim.
    let operator = format!(
        r#"{{"event_type": "ServiceState", "kind": 30065, "created_at": 1791000000, "content": "", "tags": [["d", "{service_pubkey}:relay"], ["service", "relay"], ["state", "maintenance"], ["operator_for", "{service_pubkey}", "relay"]]}}"#
    );
    let output = run(&["--event", &operator]);
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains(&format!(
            "operator claims maintenance for {service_pubkey} (relay)"
        )),
        "{stdout}"
    );
}

#[test]
fn the_policy_client_publishes_and_evaluates_trust_policy() {
    let path = repository_path("examples/ncc11-policy-client.ns");
    let run = |extra: &[&str]| {
        Command::new(env!("CARGO_BIN_EXE_nscript"))
            .arg("run")
            .arg(&path)
            .args(extra)
            .output()
            .unwrap()
    };
    let publish = r#"{"event_type": "Note", "kind": 1, "created_at": 1790380000, "content": "publish", "tags": [["t", "publish-policy"]]}"#;
    let output = run(&["--event", publish]);
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("handler Note: ok"), "{stdout}");
    assert!(
        stdout.contains("policy published (accepted: true)"),
        "{stdout}"
    );

    // A policy received with three-column rule tags is read back and its
    // values checked against the rules NCC-11 defines.
    let policy = r#"{"event_type": "TrustPolicy", "kind": 30067, "created_at": 1790380000, "content": "", "tags": [["d", "default"], ["rule", "ncc:02:key-pinning", "require"], ["rule", "ncc:05:stale-fallback", "allow"], ["rule", "ncc:05:transport:wss", "allow"], ["rule", "ncc:05:transport:http", "deny"], ["rule", "ncc:10:operator-state", "deny"]]}"#;
    let output = run(&["--event", policy]);
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("handler TrustPolicy: ok"), "{stdout}");
    assert!(
        stdout.contains(
            "policy default rules [ncc:02:key-pinning, ncc:05:stale-fallback, ncc:05:transport:wss, ncc:05:transport:http, ncc:10:operator-state]"
        ),
        "{stdout}"
    );
    assert!(
        stdout.contains("key pinning require (known rule: true, value valid: true)"),
        "{stdout}"
    );
    assert!(
        stdout.contains("transport wss allow, http deny; operator state deny"),
        "{stdout}"
    );
}

#[test]
fn the_release_monitor_publishes_judges_upgrades_and_selects_artefacts() {
    let path = repository_path("examples/ncc13-release-monitor.ns");
    let run = |extra: &[&str]| {
        Command::new(env!("CARGO_BIN_EXE_nscript"))
            .arg("run")
            .arg(&path)
            .args(extra)
            .output()
            .unwrap()
    };

    let publish = r#"{"event_type": "Note", "kind": 1, "created_at": 1790380000, "content": "cut a release", "tags": [["t", "publish-release"]]}"#;
    let output = run(&["--event", publish]);
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("handler Note: ok"), "{stdout}");
    assert!(
        stdout.contains("release published (accepted: true)"),
        "{stdout}"
    );

    // A beta release is newer but on the wrong channel: not an upgrade.
    let beta = r#"{"event_type": "ReleaseArtifactSet", "kind": 30063, "created_at": 1790380000, "content": "", "tags": [["d", "com.example.app@1.5.0"], ["a", "32267:aaa:com.example.app"], ["version", "1.5.0"], ["version_scheme", "semver"], ["channel", "beta"]]}"#;
    let output = run(&["--event", beta]);
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains("not an upgrade: 32267:aaa:com.example.app@1.5.0 (beta) — right channel false, newer true"),
        "{stdout}"
    );

    // A stable release newer than the tracked installed version is an
    // upgrade candidate.
    let stable = r#"{"event_type": "ReleaseArtifactSet", "kind": 30063, "created_at": 1790380000, "content": "", "tags": [["d", "com.example.app@1.4.2"], ["a", "32267:aaa:com.example.app"], ["version", "1.4.2"], ["version_scheme", "semver"], ["channel", "stable"], ["requires", "32267:bbb:com.example.runtime\u001f>=2.0.0"]]}"#;
    let output = run(&["--event", stable]);
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains("upgrade candidate: 32267:aaa:com.example.app@1.4.2 (stable, semver)"),
        "{stdout}"
    );
    assert!(
        stdout.contains("requires 32267:bbb:com.example.runtime >=2.0.0"),
        "{stdout}"
    );

    // An artefact whose arch does not match the monitor's own platform is
    // reported, not silently accepted.
    let mismatched = r#"{"event_type": "ArtefactMetadata", "kind": 1063, "created_at": 1790380000, "content": "", "tags": [["url", "https://example.com/app_amd64.deb"], ["os", "linux"], ["arch", "amd64"], ["format", "deb"]]}"#;
    let output = run(&["--event", mismatched]);
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains("artefact linux/amd64 does not match linux/arm64"),
        "{stdout}"
    );

    // A matching artefact is selected.
    let matching = r#"{"event_type": "ArtefactMetadata", "kind": 1063, "created_at": 1790380000, "content": "", "tags": [["url", "https://example.com/app_arm64.deb"], ["os", "linux"], ["arch", "arm64"], ["format", "deb"]]}"#;
    let output = run(&["--event", matching]);
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("selected artefact: deb"), "{stdout}");
}

#[test]
#[allow(clippy::too_many_lines)]
fn the_service_operator_bot_composes_the_full_ncc_service_cluster() {
    let path = repository_path("examples/service-operator-bot.ns");
    let principal = "a".repeat(64);
    let run = |extra: &[&str]| {
        Command::new(env!("CARGO_BIN_EXE_nscript"))
            .arg("run")
            .arg(&path)
            .args(["--as", &principal])
            .args(extra)
            .output()
            .unwrap()
    };

    // No event: the schedule runs once at startup — manifest, service
    // record, encrypted locator and operational state, in real sequence,
    // the `let`s computing the locator's payload and its encrypted content
    // reaching the `publish` after them in the same schedule body — and
    // the 24h timer registers for (never fired) refiring.
    let output = run(&[]);
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("timer schedule-0"), "{stdout}");
    assert!(
        stdout.contains("refresh: manifest true, record true, locator true, state true"),
        "{stdout}"
    );
    assert!(stdout.contains("8 handler(s) registered"), "{stdout}");

    // NCC-09 as principal: delegate two scopes to an automation key.
    let authorise = r#"{"event_type": "Note", "kind": 1, "created_at": 1790380000, "content": "bring up CI", "tags": [["t", "authorise-operator"]]}"#;
    let output = run(&["--event", authorise]);
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains("operator grant published (accepted: true)"),
        "{stdout}"
    );

    // NCC-13 as publisher: a signed release with a dependency and a conflict.
    let cut_release = r#"{"event_type": "Note", "kind": 1, "created_at": 1790380000, "content": "ship it", "tags": [["t", "cut-release"]]}"#;
    let output = run(&["--event", cut_release]);
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains("release published (accepted: true)"),
        "{stdout}"
    );

    // An operator-claimed state is accepted only while the NCC-09 grant
    // this operator issued to itself as "known" is active for that scope.
    let operator = "b".repeat(64);
    let operator_claim = format!(
        r#"{{"event_type": "ServiceState", "kind": 30065, "created_at": 1790380000, "content": "", "tags": [["d", "{operator}:relay-ops"], ["service", "relay-ops"], ["state", "maintenance"], ["operator_for", "{operator}\u001frelay-ops"]]}}"#
    );
    let output = run(&["--event", &operator_claim]);
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains("accepted, ncc:10:publish is active"),
        "{stdout}"
    );

    // A direct state is reported as the service's own claim.
    let direct = r#"{"event_type": "ServiceState", "kind": 30065, "created_at": 1790380000, "content": "", "tags": [["d", "relay-ops"], ["service", "relay-ops"], ["state", "operational"]]}"#;
    let output = run(&["--event", direct]);
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains("relay-ops reports operational directly"),
        "{stdout}"
    );

    // A peer's ServiceRecord is validated under NCC-02 before its Locator
    // (below) is judged worth depending on.
    let peer_record = r#"{"event_type": "ServiceRecord", "kind": 30059, "created_at": 1790380000, "content": "", "tags": [["d", "peer-relay"], ["u", "wss://peer.example.com"], ["k", "6666666666666666666666666666666666666666666666666666666666666666"], ["exp", "1799999999"]]}"#;
    let output = run(&["--event", peer_record]);
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("peer-relay record valid"), "{stdout}");

    // The peer's Locator: ranked by NCC-06 over the NCC-05 payload.
    let peer_locator = r#"{"event_type": "Locator", "kind": 30058, "created_at": 1790380000, "content": "{\"v\":1,\"ttl\":600,\"updated_at\":1790380000,\"endpoints\":[{\"url\":\"wss://peer.example.com\",\"priority\":10},{\"url\":\"ws://peer-onion.onion\"}]}", "tags": [["d", "peer-relay"], ["expiration", "1790470000"]]}"#;
    let output = run(&["--event", peer_locator]);
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains(
            "peer-relay endpoints, ranked: [wss://peer.example.com, ws://peer-onion.onion]"
        ),
        "{stdout}"
    );

    // NCC-11 policy data is reported for the operator to apply elsewhere.
    let policy = r#"{"event_type": "TrustPolicy", "kind": 30067, "created_at": 1790380000, "content": "", "tags": [["d", "default"], ["rule", "ncc:02:key-pinning", "require"], ["rule", "ncc:05:stale-fallback", "deny"]]}"#;
    let output = run(&["--event", policy]);
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains("policy default: key pinning require, stale fallback deny"),
        "{stdout}"
    );

    // A signed release from this service is judged an upgrade candidate.
    let release = format!(
        r#"{{"event_type": "ReleaseArtifactSet", "kind": 30063, "created_at": 1790380000, "content": "", "tags": [["d", "com.example.relay-ops@1.4.2"], ["a", "32267:{}:com.example.relay-ops"], ["version", "1.4.2"], ["version_scheme", "semver"], ["channel", "stable"]]}}"#,
        "c".repeat(64)
    );
    let output = run(&["--event", &release]);
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("upgrade candidate true"), "{stdout}");

    // NCC-09 as reader: a grant received naming this operator as delegate.
    let received_grant = format!(
        r#"{{"event_type": "AuthorityGrant", "kind": 30064, "created_at": 1790380000, "content": "", "tags": [["d", "peer-relay:{c}"], ["service", "peer-relay"], ["p", "{c}"], ["status", "active"], ["scope", "ncc:10:publish"], ["expiration", "1799999999"]]}}"#,
        c = "c".repeat(64)
    );
    let output = run(&["--event", &received_grant]);
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains("received a grant for peer-relay: scopes [ncc:10:publish]"),
        "{stdout}"
    );
}

#[test]
fn the_election_bot_judges_votes_keeps_one_per_pubkey_and_tallies() {
    let path = repository_path("examples/ncc03-election-bot.ns");
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
    let vote = |author: &str, created_at: u64, choice: &str| {
        format!(
            r#"{{"event_type": "Vote", "kind": 1071, "created_at": {created_at}, "author": "{author}", "content": "", "tags": [["e", "board-chair-event"], ["d", "board-chair-2026"], ["choice", "{choice}"]]}}"#
        )
    };

    let stdout = run(
        r#"{"event_type": "Note", "kind": 1, "created_at": 1790380000, "content": "open", "tags": [["t", "open-election"]]}"#,
    );
    assert!(
        stdout.contains("election published (accepted: true)"),
        "{stdout}"
    );

    // A later vote from a roll member replaces the counted one (§7).
    let stdout = run(&vote("aaaa", 1_790_381_000, "yes"));
    assert!(
        stdout.contains("vote counted: yes from aaaa, replacing the vote at 1790380500"),
        "{stdout}"
    );
    // An equal created_at keeps the vote already counted.
    let stdout = run(&vote("aaaa", 1_790_380_500, "no"));
    assert!(
        stdout.contains("vote kept: the earlier vote at 1790380500 still counts"),
        "{stdout}"
    );
    // A pubkey outside the roll is ignored (§5.3).
    let stdout = run(&vote("cccc", 1_790_381_000, "yes"));
    assert!(
        stdout.contains("vote ignored: cccc is not on the electoral roll"),
        "{stdout}"
    );
    // A vote after endsAt is ignored (§6).
    let stdout = run(&vote("aaaa", 1_790_384_000, "yes"));
    assert!(
        stdout.contains("vote ignored: yes is outside the window"),
        "{stdout}"
    );

    // Tally: declared options in order, undeclared choices count nowhere.
    let stdout = run(
        r#"{"event_type": "Note", "kind": 1, "created_at": 1790384000, "content": "close", "tags": [["t", "tally-election"], ["choice", "yes"], ["choice", "yes"], ["choice", "no"], ["choice", "maybe"]]}"#,
    );
    assert!(stdout.contains("tally yes: 2"), "{stdout}");
    assert!(stdout.contains("tally no: 1"), "{stdout}");
    assert!(!stdout.contains("maybe"), "{stdout}");

    // An audit event is read as a claim, not verified.
    let stdout = run(
        r#"{"event_type": "ElectionAudit", "kind": 36999, "created_at": 1790384000, "content": "", "tags": [["d", "board-chair-2026"], ["roll", "board-chair-roll"], ["summary", "abc123"], ["votes", "3"]]}"#,
    );
    assert!(
        stdout.contains(
            "audit for board-chair-2026 (roll board-chair-roll) claims 3 votes, summary abc123"
        ),
        "{stdout}"
    );
}

#[test]
fn the_support_ticket_bot_labels_urgent_tickets_and_always_acknowledges() {
    let path = repository_path("examples/support-ticket-bot.ns");
    let run = |extra: &[&str]| {
        Command::new(env!("CARGO_BIN_EXE_nscript"))
            .arg("run")
            .arg(&path)
            .args(extra)
            .output()
            .unwrap()
    };

    // No event: nothing runs, nothing is published or labeled.
    let output = run(&[]);
    assert!(output.status.success());
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(!stdout.contains("nip32."), "{stdout}");
    assert!(!stdout.contains("log info: true"), "{stdout}");

    // Urgent: labeled, then acknowledged with a real publish.
    let output = run(&[
        "--event",
        r#"{"content":"urgent: site is down","tags":[["t","support"]],"id":"e1"}"#,
    ]);
    assert!(output.status.success(), "{output:?}");
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("log info: labeled urgent"), "{stdout}");
    assert!(stdout.contains("nip32.publish_label"), "{stdout}");
    assert!(stdout.contains("log info: true"), "{stdout}");

    // Not urgent: no label, but still acknowledged.
    let output = run(&[
        "--event",
        r#"{"content":"how do I reset my password?","tags":[["t","support"]],"id":"e2"}"#,
    ]);
    assert!(output.status.success(), "{output:?}");
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(!stdout.contains("nip32."), "{stdout}");
    assert!(stdout.contains("log info: true"), "{stdout}");

    // The label call fails: `?` aborts the handler before the
    // acknowledgement, and the failure is reported, not swallowed.
    let output = run(&[
        "--fail",
        "nip32.publish_label",
        "--event",
        r#"{"content":"urgent: site is down","tags":[["t","support"]],"id":"e3"}"#,
    ]);
    assert!(!output.status.success());
    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("it returned an error"), "{stderr}");
    assert!(!stdout.contains("log info: true"), "{stdout}");
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

mod deploy_with_real_hosts {
    use std::net::{TcpListener, TcpStream};
    use std::thread;

    use nscript_host_crypto::group_key::xonly_pubkey;
    use nscript_host_crypto::nip44;
    use nscript_host_crypto::schnorr::sign_random;
    use serde_json::{Value, json};
    use sha2::{Digest, Sha256};
    use tungstenite::{Message, WebSocket};

    use super::Command;

    fn hex(bytes: &[u8]) -> String {
        use std::fmt::Write as _;
        bytes.iter().fold(String::new(), |mut out, byte| {
            let _ = write!(out, "{byte:02x}");
            out
        })
    }

    fn unhex32(text: &str) -> [u8; 32] {
        let mut out = [0_u8; 32];
        for (slot, pair) in out.iter_mut().zip(text.as_bytes().chunks(2)) {
            *slot = u8::from_str_radix(std::str::from_utf8(pair).unwrap(), 16).unwrap();
        }
        out
    }

    fn event_id(pubkey: &str, created_at: u64, kind: u64, tags: &Value, content: &str) -> String {
        let preimage = json!([0, pubkey, created_at, kind, tags, content]).to_string();
        hex(&Sha256::digest(preimage.as_bytes()))
    }

    /// Builds and signs a real Nostr event with `secret`.
    fn signed_event(
        secret: &[u8; 32],
        kind: u64,
        tags: &Value,
        content: &str,
        created_at: u64,
    ) -> Value {
        let pubkey = hex(&xonly_pubkey(secret).unwrap());
        let id = event_id(&pubkey, created_at, kind, tags, content);
        let sig = sign_random(secret, &unhex32(&id)).unwrap();
        json!({
            "id": id, "pubkey": pubkey, "created_at": created_at,
            "kind": kind, "tags": tags, "content": content, "sig": hex(&sig)
        })
    }

    fn send(socket: &mut WebSocket<TcpStream>, value: &Value) {
        socket
            .send(Message::Text(value.to_string().into()))
            .expect("relay send");
    }

    fn read_json(socket: &mut WebSocket<TcpStream>) -> Value {
        loop {
            if let Message::Text(text) = socket.read().expect("frame") {
                return serde_json::from_str(&text).expect("json");
            }
        }
    }

    /// A relay that expects exactly the sequence `deploy` produces for the
    /// fixture script below: one startup publish, one subscription (answered
    /// with one waiting Note tagged `trigger`, then EOSE), then one reply
    /// publish from the handler. Incoming event signatures are not checked —
    /// nothing downstream of the relay adapter verifies them either, so a
    /// placeholder `sig` on the delivered Note is fine; only the two events
    /// *this test* asserts on (the ones `deploy` itself signs) need to be
    /// real.
    fn fake_relay() -> String {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
        let url = format!("ws://{}", listener.local_addr().expect("addr"));
        thread::spawn(move || {
            let (stream, _) = listener.accept().expect("accept");
            let mut socket = tungstenite::accept(stream).expect("handshake");

            // 1) The program's own top-level `publish`.
            let frame = read_json(&mut socket);
            assert_eq!(frame[0], "EVENT");
            send(&mut socket, &json!(["OK", frame[1]["id"], true, ""]));

            // 2) The handler's subscription: answer with one waiting Note.
            let frame = read_json(&mut socket);
            assert_eq!(frame[0], "REQ");
            let sub_id = frame[1].clone();
            let note = json!({
                "id": "f".repeat(64), "pubkey": "a".repeat(64), "created_at": 1_700_000_000,
                "kind": 1, "tags": [["t", "trigger"]], "content": "are you there?", "sig": "b".repeat(128)
            });
            send(&mut socket, &json!(["EVENT", sub_id, note]));
            send(&mut socket, &json!(["EOSE", sub_id]));

            // 3) The handler's own reply `publish`.
            let frame = read_json(&mut socket);
            assert_eq!(frame[0], "EVENT");
            assert_eq!(frame[1]["content"], "reply: are you there?");
            send(&mut socket, &json!(["OK", frame[1]["id"], true, ""]));
        });
        url
    }

    /// A minimal bunker answering exactly `connect` / `get_public_key` /
    /// `sign_event`, real NIP-44/Schnorr on both sides — see
    /// `nscript-host-crypto`'s own `nip46` tests for the same pattern.
    fn fake_bunker(bunker_secret: [u8; 32], user_secret: [u8; 32]) -> String {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
        let url = format!("ws://{}", listener.local_addr().expect("addr"));
        thread::spawn(move || {
            let (stream, _) = listener.accept().expect("accept");
            let mut socket = tungstenite::accept(stream).expect("handshake");
            let user_pubkey = xonly_pubkey(&user_secret).unwrap();

            let frame = read_json(&mut socket);
            assert_eq!(frame[0], "REQ");
            let sub_id = frame[1].clone();
            send(&mut socket, &json!(["EOSE", sub_id]));

            let mut key = None;
            // `connect` and `get_public_key` happen exactly once (during
            // provisioning); after that, every further request is its own
            // fresh `sign_event` round trip — one per `sign`/`publish` the
            // deployed program makes, not just one overall. Answer
            // `connect`/`get_public_key` first, then keep answering
            // `sign_event` until the client disconnects (the deploy
            // subprocess exiting after its bounded `--cycles` closes the
            // socket, ending this loop with a read error).
            for method in ["connect", "get_public_key"]
                .into_iter()
                .chain(std::iter::repeat("sign_event"))
            {
                let Ok(Message::Text(text)) = socket.read() else {
                    break;
                };
                let frame: Value = serde_json::from_str(&text).unwrap();
                if frame[0] != "EVENT" {
                    continue;
                }
                let event = frame[1].clone();
                send(&mut socket, &json!(["OK", event["id"], true, ""]));

                let client_pubkey = unhex32(event["pubkey"].as_str().unwrap());
                let conversation_key = *key.get_or_insert_with(|| {
                    nip44::conversation_key(&bunker_secret, &client_pubkey).unwrap()
                });
                let plaintext =
                    nip44::decrypt(&conversation_key, event["content"].as_str().unwrap()).unwrap();
                let request: Value = serde_json::from_slice(&plaintext).unwrap();
                assert_eq!(request["method"], method);

                let result = match method {
                    "connect" => json!("ack"),
                    "get_public_key" => json!(hex(&user_pubkey)),
                    "sign_event" => {
                        let template: Value =
                            serde_json::from_str(request["params"][0].as_str().unwrap()).unwrap();
                        json!(
                            signed_event(
                                &user_secret,
                                template["kind"].as_u64().unwrap(),
                                &template["tags"],
                                template["content"].as_str().unwrap(),
                                template["created_at"].as_u64().unwrap(),
                            )
                            .to_string()
                        )
                    }
                    _ => unreachable!(),
                };
                let response = json!({"id": request["id"], "result": result}).to_string();
                let ciphertext = nip44::encrypt(&conversation_key, response.as_bytes()).unwrap();
                let response_event = signed_event(
                    &bunker_secret,
                    24_133,
                    &json!([["p", event["pubkey"]]]),
                    &ciphertext,
                    0,
                );
                send(&mut socket, &json!(["EVENT", sub_id, response_event]));
            }
        });
        url
    }

    #[test]
    fn deploy_publishes_and_dispatches_against_a_real_relay_and_bunker() {
        let bunker_secret = [21_u8; 32];
        let user_secret = [22_u8; 32];
        let relay_url = fake_relay();
        let bunker_url = fake_bunker(bunker_secret, user_secret);
        let bunker_pubkey_hex = hex(&xonly_pubkey(&bunker_secret).unwrap());
        let bunker_connection_string = format!("bunker://{bunker_pubkey_hex}?relay={bunker_url}");

        let source = "use nip01\nuse nip46\n\nsigner account = nip46()\nrelayset public = configured\n\npermissions {\n    read Note from public\n    publish Note to public\n    sign Note with account\n    relay public\n    log\n}\n\npublish Note {\n    content: \"deploy started\",\n} to public with account\n\non Note where tags.t contains \"trigger\" {\n    print(\"handler ran\")\n    let result = publish Note {\n        content: \"reply: \" + event.content,\n    } to public with account\n    print(result.accepted)\n}\n";
        let path = std::env::temp_dir().join(format!("nscript-deploy-{}.ns", std::process::id()));
        std::fs::write(&path, source).unwrap();

        let output = Command::new(env!("CARGO_BIN_EXE_nscript"))
            .arg("deploy")
            .arg(&path)
            .args(["--relay", &relay_url])
            .args(["--signer", &format!("account={bunker_connection_string}")])
            .args(["--cycles", "1"])
            .args(["--poll-interval", "0"])
            .output()
            .unwrap();
        let _ = std::fs::remove_file(&path);

        assert!(
            output.status.success(),
            "stdout:\n{}\nstderr:\n{}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
        let stdout = String::from_utf8_lossy(&output.stdout);
        assert!(
            stdout.contains(&format!("connected: {relay_url}")),
            "{stdout}"
        );
        assert!(
            stdout.contains("provisioning signer `account`... connected"),
            "{stdout}"
        );
        assert!(
            stdout.contains("publication 0: 1/1 relays accepted"),
            "{stdout}"
        );
        assert!(stdout.contains("log info: handler ran"), "{stdout}");
        assert!(stdout.contains("log info: true"), "{stdout}");
        assert!(
            stdout.contains("cycle 1: 1 dispatched, 0 failed"),
            "{stdout}"
        );
    }

    /// A relay that runs the same handshake as `fake_relay` but, once the
    /// handler subscribes, delivers a kind-7 impostor wearing the trigger
    /// tag *first* and only then the real kind-1 Note — a relay that
    /// ignored the subscription's declared-kind filter. The subscription
    /// must carry that filter, and the impostor must never reach the
    /// handler: exactly one reply comes back, quoting the real Note.
    fn fake_relay_kind_filter() -> String {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
        let url = format!("ws://{}", listener.local_addr().expect("addr"));
        thread::spawn(move || {
            let (stream, _) = listener.accept().expect("accept");
            let mut socket = tungstenite::accept(stream).expect("handshake");

            // 1) The program's own top-level `publish`.
            let frame = read_json(&mut socket);
            assert_eq!(frame[0], "EVENT");
            send(&mut socket, &json!(["OK", frame[1]["id"], true, ""]));

            // 2) The handler's subscription must filter on the kind its
            // event declaration resolves to (`Note` is kind 1).
            let frame = read_json(&mut socket);
            assert_eq!(frame[0], "REQ");
            let sub_id = frame[1].clone();
            assert_eq!(
                frame[2]["kinds"],
                json!([1]),
                "the subscription filters on the declared kind"
            );
            let impostor = json!({
                "id": "e".repeat(64), "pubkey": "a".repeat(64),
                "created_at": 1_700_000_001, "kind": 7,
                "tags": [["t", "trigger"]], "content": "impostor",
                "sig": "b".repeat(128)
            });
            let note = json!({
                "id": "f".repeat(64), "pubkey": "a".repeat(64),
                "created_at": 1_700_000_000, "kind": 1,
                "tags": [["t", "trigger"]], "content": "the real one",
                "sig": "b".repeat(128)
            });
            send(&mut socket, &json!(["EVENT", sub_id, impostor]));
            send(&mut socket, &json!(["EVENT", sub_id, note]));
            send(&mut socket, &json!(["EOSE", sub_id]));

            // 3) Exactly one reply, and it quotes the kind-1 Note.
            let frame = read_json(&mut socket);
            assert_eq!(frame[0], "EVENT");
            assert_eq!(
                frame[1]["content"], "reply: the real one",
                "only the kind-1 Note may dispatch: {frame}"
            );
            send(&mut socket, &json!(["OK", frame[1]["id"], true, ""]));
        });
        url
    }

    #[test]
    fn deploy_filters_delivered_events_by_the_declared_kind() {
        let bunker_secret = [31_u8; 32];
        let user_secret = [32_u8; 32];
        let relay_url = fake_relay_kind_filter();
        let bunker_url = fake_bunker(bunker_secret, user_secret);
        let bunker_pubkey_hex = hex(&xonly_pubkey(&bunker_secret).unwrap());
        let bunker_connection_string = format!("bunker://{bunker_pubkey_hex}?relay={bunker_url}");

        let source = "use nip01\nuse nip46\n\nsigner account = nip46()\nrelayset public = configured\n\npermissions {\n    read Note from public\n    publish Note to public\n    sign Note with account\n    relay public\n    log\n}\n\npublish Note {\n    content: \"deploy started\",\n} to public with account\n\non Note where tags.t contains \"trigger\" {\n    let result = publish Note {\n        content: \"reply: \" + event.content,\n    } to public with account\n    print(result.accepted)\n}\n";
        let path =
            std::env::temp_dir().join(format!("nscript-deploy-kind-{}.ns", std::process::id()));
        std::fs::write(&path, source).unwrap();

        let output = Command::new(env!("CARGO_BIN_EXE_nscript"))
            .arg("deploy")
            .arg(&path)
            .args(["--relay", &relay_url])
            .args(["--signer", &format!("account={bunker_connection_string}")])
            .args(["--cycles", "1"])
            .args(["--poll-interval", "0"])
            .output()
            .unwrap();
        let _ = std::fs::remove_file(&path);

        assert!(
            output.status.success(),
            "stdout:\n{}\nstderr:\n{}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
        let stdout = String::from_utf8_lossy(&output.stdout);
        assert!(
            stdout.contains("cycle 1: 1 dispatched, 0 failed"),
            "{stdout}"
        );
        assert!(!stdout.contains("reply: impostor"), "{stdout}");
    }

    /// A bootstrap relay answering exactly what identity resolution
    /// asks: one bounded query for the identity's NCC-02 Service Record
    /// and NCC-05 Locator, answered with both events and EOSE. Both are
    /// signed for real by the identity's own key, so §A's id
    /// recomputation and signature verification both hold. After the
    /// resolver unsubscribes, the relay waits for the startup publish
    /// the pool fans out to every relay it holds.
    fn fake_records_relay(pubkey: &str, service: &Value, locator: &Value) -> String {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
        let url = format!("ws://{}", listener.local_addr().expect("addr"));
        let pubkey = pubkey.to_owned();
        let service = service.clone();
        let locator = locator.clone();
        thread::spawn(move || {
            let (stream, _) = listener.accept().expect("accept");
            let mut socket = tungstenite::accept(stream).expect("handshake");

            // 1) NCC-06 §C.2: the identity's two record kinds, by author.
            let frame = read_json(&mut socket);
            assert_eq!(frame[0], "REQ");
            assert_eq!(frame[2]["kinds"], json!([30059, 30058]));
            assert_eq!(frame[2]["authors"], json!([pubkey]));
            let sub_id = frame[1].clone();
            send(&mut socket, &json!(["EVENT", sub_id, service]));
            send(&mut socket, &json!(["EVENT", sub_id, locator]));
            send(&mut socket, &json!(["EOSE", sub_id]));

            // 2) The resolver's unsubscribe (skipped), then the startup
            // publish fanned out to every pooled relay.
            loop {
                let frame = read_json(&mut socket);
                if frame[0] == "EVENT" {
                    assert_eq!(frame[1]["content"], "resolved deploy started");
                    send(&mut socket, &json!(["OK", frame[1]["id"], true, ""]));
                    break;
                }
            }
        });
        url
    }

    /// The endpoint identity resolution picks. Nothing arrives until
    /// resolution connects it, and then only the startup publish — a
    /// script with no handlers watches for nothing.
    fn fake_resolved_relay() -> String {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
        let url = format!("ws://{}", listener.local_addr().expect("addr"));
        thread::spawn(move || {
            let (stream, _) = listener.accept().expect("accept");
            let mut socket = tungstenite::accept(stream).expect("handshake");
            loop {
                let frame = read_json(&mut socket);
                if frame[0] == "EVENT" {
                    assert_eq!(frame[1]["content"], "resolved deploy started");
                    send(&mut socket, &json!(["OK", frame[1]["id"], true, ""]));
                    break;
                }
            }
        });
        url
    }

    /// The identity's NCC-02 Service Record and NCC-05 Locator, signed
    /// for real by `identity_secret` and pointing at `target_url`. The
    /// payload's `ttl` spans decades from its stamp because the resolver
    /// judges freshness against the wall clock, whenever the test runs.
    fn identity_records(identity_secret: &[u8; 32], target_url: &str) -> (Value, Value) {
        let service = signed_event(
            identity_secret,
            30059,
            &json!([
                ["d", "relay"],
                ["u", target_url],
                [
                    "k",
                    "9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08"
                ],
                ["exp", "1900000000"],
            ]),
            "",
            1_700_000_100,
        );
        let payload = format!(
            "{{\"v\":1,\"ttl\":2000000000,\"updated_at\":1700000000,\
             \"endpoints\":[{{\"url\":\"{target_url}\",\"priority\":10}}]}}"
        );
        let locator = signed_event(
            identity_secret,
            30058,
            &json!([["d", "addr"], ["expiration", "1900000000"]]),
            &payload,
            1_700_000_200,
        );
        (service, locator)
    }

    /// NCC-06 end to end: `--relay` holds an identity reference
    /// (`wss://npub…`), which deploy never connects to. It queries the
    /// concrete bootstrap relay for the identity's records (§C.2),
    /// selects under §A, walks §E.1 to the locator's concrete endpoint,
    /// prints the selection — including the `k` it did not verify (§E.2)
    /// — connects that endpoint instead, and the startup publication
    /// lands on both relays.
    #[test]
    fn deploy_resolves_an_identity_reference_through_the_publication_relays() {
        let identity_secret = [34_u8; 32];
        let pubkey = hex(&xonly_pubkey(&identity_secret).unwrap());
        let identity = "wss://npub1gekhljh9v0jukzdq6xrshdvqx3yqgctc0xs5jjw0yg597xaw8uns47vduw";
        let target_url = fake_resolved_relay();
        let (service, locator) = identity_records(&identity_secret, &target_url);
        let bootstrap_url = fake_records_relay(&pubkey, &service, &locator);

        let bunker_secret = [35_u8; 32];
        let user_secret = [36_u8; 32];
        let bunker_url = fake_bunker(bunker_secret, user_secret);
        let bunker_pubkey_hex = hex(&xonly_pubkey(&bunker_secret).unwrap());
        let bunker_connection_string = format!("bunker://{bunker_pubkey_hex}?relay={bunker_url}");

        let source = "use nip01\nuse nip46\n\nsigner account = nip46()\nrelayset public = configured\n\npermissions {\n    publish Note to public\n    sign Note with account\n    relay public\n}\n\npublish Note {\n    content: \"resolved deploy started\",\n} to public with account\n";
        let path =
            std::env::temp_dir().join(format!("nscript-deploy-resolve-{}.ns", std::process::id()));
        std::fs::write(&path, source).unwrap();

        let output = Command::new(env!("CARGO_BIN_EXE_nscript"))
            .arg("deploy")
            .arg(&path)
            .args(["--relay", &bootstrap_url])
            .args(["--relay", identity])
            .args(["--signer", &format!("account={bunker_connection_string}")])
            .args(["--cycles", "1"])
            .args(["--poll-interval", "0"])
            .output()
            .unwrap();
        let _ = std::fs::remove_file(&path);

        assert!(
            output.status.success(),
            "stdout:\n{}\nstderr:\n{}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
        let stdout = String::from_utf8_lossy(&output.stdout);
        assert!(
            stdout.contains("connecting to 1 relay(s), resolving 1 identity reference(s)..."),
            "{stdout}"
        );
        assert!(
            stdout.contains(&format!("  connected: {bootstrap_url}")),
            "{stdout}"
        );
        assert!(
            stdout.contains(&format!("  {identity} resolved through 1 relay(s):")),
            "{stdout}"
        );
        let short = |event: &Value| event["id"].as_str().unwrap()[..12].to_owned();
        assert!(
            stdout.contains(&format!(
                "    2 candidate record(s); selected service {}, locator {}",
                short(&service),
                short(&locator)
            )),
            "{stdout}"
        );
        assert!(
            stdout.contains(&format!(
                "    endpoint {target_url} (from ncc05 locator, NCC-06 \u{a7}E.1 rank 3)"
            )),
            "{stdout}"
        );
        assert!(
            stdout.contains(
                "    k: 9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08 \
                 (required: no, verified: no \u{2014} TLS key pinning is not implemented)"
            ),
            "{stdout}"
        );
        assert!(
            stdout.contains(&format!("    connected: {target_url}")),
            "{stdout}"
        );
        assert!(
            stdout.contains("provisioning signer `account`... connected"),
            "{stdout}"
        );
        assert!(
            stdout.contains("publication 0: 2/2 relays accepted"),
            "{stdout}"
        );
        assert!(
            stdout.contains("no handlers registered; nothing to watch for"),
            "{stdout}"
        );
    }

    /// A relay that delivers one trigger Note to a handler subscription and
    /// then asserts the three-column `rule` and `trust certifier` tags the
    /// handler's policy publish puts on the wire, answering its `OK`. It
    /// panics — before sending the `OK` — if any tag is missing, so `deploy`
    /// reports the publication as rejected and the test fails with it.
    fn fake_three_column_policy_relay() -> String {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
        let url = format!("ws://{}", listener.local_addr().expect("addr"));
        thread::spawn(move || {
            let (stream, _) = listener.accept().expect("accept");
            let mut socket = tungstenite::accept(stream).expect("handshake");

            // The handler's subscription, answered with one matching Note.
            let frame = read_json(&mut socket);
            assert_eq!(frame[0], "REQ");
            let sub_id = frame[1].clone();
            let note = json!({
                "id": "e".repeat(64), "pubkey": "a".repeat(64), "created_at": 1_790_380_000,
                "kind": 1, "tags": [["t", "publish-policy"]], "content": "publish", "sig": "b".repeat(128)
            });
            send(&mut socket, &json!(["EVENT", sub_id, note]));
            send(&mut socket, &json!(["EOSE", sub_id]));

            // The policy the handler publishes: every column on the wire.
            let frame = read_json(&mut socket);
            assert_eq!(frame[0], "EVENT");
            let tags = frame[1]["tags"].as_array().expect("tags array").clone();
            for expected in [
                json!(["d", "default"]),
                json!(["rule", "ncc:02:key-pinning", "require"]),
                json!([
                    "trust",
                    "certifier",
                    "abababababababababababababababababababababababababababababababab"
                ]),
            ] {
                assert!(
                    tags.contains(&expected),
                    "missing wire tag {expected}: {tags:?}"
                );
            }
            send(&mut socket, &json!(["OK", frame[1]["id"], true, ""]));
        });
        url
    }

    /// NCC-11 end to end: a handler builds a policy with the module's
    /// three-column builders and publishes it over a real relay, which
    /// asserts the exact wire tags. This is the coverage the `inspect`
    /// vector cannot give: the rules are computed at publish time, so the
    /// checked snapshot only holds the literal `d`.
    #[test]
    fn deploy_publishes_three_column_policy_tags() {
        let relay_url = fake_three_column_policy_relay();
        let bunker_secret = [37_u8; 32];
        let user_secret = [38_u8; 32];
        let bunker_url = fake_bunker(bunker_secret, user_secret);
        let bunker_pubkey_hex = hex(&xonly_pubkey(&bunker_secret).unwrap());
        let bunker_connection_string = format!("bunker://{bunker_pubkey_hex}?relay={bunker_url}");

        let source = "use ncc11\nuse nip01\nuse nip46\n\nsigner account = nip46()\nrelayset public = configured\n\npermissions {\n    publish TrustPolicy to public\n    sign TrustPolicy with account\n    read Note from public\n    relay public\n    log\n}\n\non Note where tags.t contains \"publish-policy\" {\n    let pinning = ncc11.rule(\"ncc:02:key-pinning\", \"require\")\n    let certifier = ncc11.certifier(\"abababababababababababababababababababababababababababababababab\")\n    publish TrustPolicy {\n        d: \"default\";\n        rule: [pinning];\n        trust: [certifier];\n        content: \"\";\n    } to public with account\n}\n";
        let path =
            std::env::temp_dir().join(format!("nscript-deploy-policy-{}.ns", std::process::id()));
        std::fs::write(&path, source).unwrap();

        let output = Command::new(env!("CARGO_BIN_EXE_nscript"))
            .arg("deploy")
            .arg(&path)
            .args(["--relay", &relay_url])
            .args(["--signer", &format!("account={bunker_connection_string}")])
            .args(["--cycles", "1"])
            .args(["--poll-interval", "0"])
            .output()
            .unwrap();
        let _ = std::fs::remove_file(&path);

        assert!(
            output.status.success(),
            "stdout:\n{}\nstderr:\n{}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
        let stdout = String::from_utf8_lossy(&output.stdout);
        assert!(
            stdout.contains("cycle 1: 1 dispatched, 0 failed"),
            "{stdout}"
        );
    }
}
