use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};
use std::time::{SystemTime, UNIX_EPOCH};

fn nscript() -> Command {
    Command::new(env!("CARGO_BIN_EXE_nscript"))
}

fn repository_path(relative: &str) -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../..")
        .join(relative)
}

fn unique(name: &str) -> PathBuf {
    let unique = format!(
        "nscript-{name}-{}-{}",
        std::process::id(),
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("clock after the epoch")
            .as_nanos()
    );
    std::env::temp_dir().join(unique)
}

fn run(arguments: &[&str]) -> Output {
    nscript().args(arguments).output().expect("run nscript git")
}

fn rendered_tags(event: &serde_json::Value) -> Vec<Vec<String>> {
    event["tags"]
        .as_array()
        .expect("tags array")
        .iter()
        .map(|tag| {
            tag.as_array()
                .expect("tag array")
                .iter()
                .map(|value| value.as_str().expect("tag value").to_owned())
                .collect::<Vec<_>>()
        })
        .collect()
}

fn expanded_tags(event: &serde_json::Value) -> Vec<Vec<String>> {
    rendered_tags(event)
        .into_iter()
        .map(|tag| {
            let mut columns = Vec::new();
            for (index, column) in tag.into_iter().enumerate() {
                if index == 0 {
                    columns.push(column);
                } else {
                    columns.extend(column.split('\u{1f}').map(str::to_owned));
                }
            }
            columns
        })
        .collect()
}

fn object(event: &serde_json::Value) -> &serde_json::Value {
    &event["events"][0]
}

#[test]
fn announce_reads_nip34_json_and_flags() {
    let directory = unique("git-announce");
    fs::create_dir_all(&directory).expect("create directory");
    fs::write(
        directory.join("nip34.json"),
        r#"{
            "identifier": "demo",
            "name": "Demo",
            "description": "A demo repository",
            "web": ["https://example.com/demo"],
            "clone": ["https://example.com/demo.git"],
            "relays": ["wss://relay.example.com"],
            "maintainers": ["aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"],
            "topics": ["nostr"]
        }"#,
    )
    .expect("write config");
    let output = nscript()
        .args(["git", "announce", "--repo"])
        .arg(&directory)
        .args(["--dry-run", "--json"])
        .output()
        .expect("run announce");
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let value: serde_json::Value = serde_json::from_slice(&output.stdout).expect("json");
    let event = object(&value);
    assert_eq!(event["kind"], 30617);
    let tags = rendered_tags(event);
    assert_eq!(tags[0], ["d", "demo"]);
    assert!(tags.contains(&vec!["name".to_owned(), "Demo".to_owned()]));
    assert!(tags.contains(&vec![
        "clone".to_owned(),
        "https://example.com/demo.git".to_owned()
    ]));
    assert!(tags.contains(&vec![
        "relays".to_owned(),
        "wss://relay.example.com".to_owned()
    ]));
    fs::remove_dir_all(directory).expect("remove directory");
}

#[test]
fn state_from_git_reads_refs_and_head() {
    let directory = unique("git-state");
    fs::create_dir_all(&directory).expect("create directory");
    for arguments in [
        vec!["init", "-q"],
        vec!["config", "user.email", "ada@example.com"],
        vec!["config", "user.name", "Ada"],
    ] {
        let status = Command::new("git")
            .arg("-C")
            .arg(&directory)
            .args(&arguments)
            .status()
            .expect("run git");
        assert!(status.success(), "git {arguments:?} failed");
    }
    fs::write(directory.join("README.md"), "hello\n").expect("write file");
    for arguments in [
        vec!["add", "README.md"],
        vec!["commit", "-qm", "init"],
        vec!["tag", "v1.0.0"],
    ] {
        let status = Command::new("git")
            .arg("-C")
            .arg(&directory)
            .args(&arguments)
            .status()
            .expect("run git");
        assert!(status.success(), "git {arguments:?} failed");
    }
    let output = nscript()
        .args(["git", "state", "--repo"])
        .arg(&directory)
        .args(["--d", "demo", "--from-git", "--dry-run", "--json"])
        .output()
        .expect("run state");
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let value: serde_json::Value = serde_json::from_slice(&output.stdout).expect("json");
    let event = object(&value);
    assert_eq!(event["kind"], 30618);
    let tags = rendered_tags(event);
    assert_eq!(tags[0], ["d", "demo"]);
    assert!(
        tags.iter().any(|tag| tag[0] == "refs"
            && (tag[1] == "refs/heads/master" || tag[1] == "refs/heads/main"))
    );
    assert!(
        tags.iter()
            .any(|tag| tag[0] == "refs" && tag[1] == "refs/tags/v1.0.0")
    );
    assert!(
        tags.iter()
            .any(|tag| tag[0] == "HEAD" && tag[1].starts_with("ref: refs/heads/"))
    );
    fs::remove_dir_all(directory).expect("remove directory");
}

#[test]
fn status_maps_merged_to_applied_with_a_root_marker() {
    let root = "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc";
    let output = run(&[
        "git",
        "status",
        "--status",
        "merged",
        "--root-event",
        root,
        "--dry-run",
        "--json",
    ]);
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let value: serde_json::Value = serde_json::from_slice(&output.stdout).expect("json");
    let event = object(&value);
    assert_eq!(event["kind"], 1631);
    let tags = rendered_tags(event);
    assert_eq!(tags[0], ["e", root, "", "root"]);
}

#[test]
fn patch_auto_addresses_the_repository_owner() {
    let owner = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
    let address = format!("30617:{owner}:demo");
    let output = run(&[
        "git",
        "patch",
        "--repository",
        &address,
        "--content",
        "From abc Mon Sep 17 00:00:00 2001",
        "--root",
        "--dry-run",
        "--json",
    ]);
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let value: serde_json::Value = serde_json::from_slice(&output.stdout).expect("json");
    let event = object(&value);
    assert_eq!(event["kind"], 1617);
    let tags = rendered_tags(event);
    assert!(tags.contains(&vec!["a".to_owned(), address]));
    assert!(tags.contains(&vec!["p".to_owned(), owner.to_owned()]));
    assert!(tags.contains(&vec!["t".to_owned(), "root".to_owned()]));
}

#[test]
fn invalid_inputs_exit_two() {
    let out = run(&[
        "git",
        "patch",
        "--repository",
        "not-an-address",
        "--content",
        "x",
    ]);
    assert_eq!(out.status.code(), Some(2));
    assert!(String::from_utf8_lossy(&out.stderr).contains("repository address"));

    let out = run(&["git", "state", "--ref", "main=abc"]);
    assert_eq!(out.status.code(), Some(2));
    assert!(String::from_utf8_lossy(&out.stderr).contains("refs/heads/"));

    let out = run(&[
        "git",
        "patch",
        "--repository",
        "30617:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb:demo",
    ]);
    assert_eq!(out.status.code(), Some(2));
    assert!(String::from_utf8_lossy(&out.stderr).contains("--content"));
}

#[test]
fn conformance_fixtures_match_the_stored_vectors() {
    let vectors: serde_json::Value = serde_json::from_slice(
        &fs::read(repository_path("conformance/vectors/nip34.json")).expect("read vectors"),
    )
    .expect("parse vectors");
    let fixtures = [
        (
            "repository-announcement",
            "nip34-repository-announcement.ns",
        ),
        ("repository-state", "nip34-repository-state.ns"),
        ("patch", "nip34-patch.ns"),
        ("pull-request", "nip34-pull-request.ns"),
        ("issue", "nip34-issue.ns"),
        ("status-applied", "nip34-status.ns"),
        ("grasp-list", "nip34-grasp-list.ns"),
    ];
    for (type_name, fixture) in fixtures {
        let output = nscript()
            .args(["inspect", "--json"])
            .arg(repository_path(&format!("conformance/valid/{fixture}")))
            .output()
            .expect("inspect fixture");
        assert!(
            output.status.success(),
            "{fixture}: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        let value: serde_json::Value = serde_json::from_slice(&output.stdout).expect("json");
        let step = &value["publication_trace"][0]["steps"][0];
        let expected = vectors["vectors"]
            .as_array()
            .expect("vectors array")
            .iter()
            .find(|vector| vector["type"] == type_name)
            .unwrap_or_else(|| panic!("missing vector {type_name}"));
        assert_eq!(step["kind"], expected["kind"], "{type_name} kind");
        assert_eq!(
            step["content"].as_str().unwrap_or(""),
            expected["content"].as_str().unwrap_or(""),
            "{type_name} content"
        );
        assert_eq!(
            expanded_tags(step),
            rendered_tags(expected),
            "{type_name} tags"
        );
    }
}
