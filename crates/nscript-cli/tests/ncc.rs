use std::collections::BTreeSet;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::{SystemTime, UNIX_EPOCH};

use nscript_ncc::{Metadata, NccEntry, Status, build_document};

fn fixture() -> PathBuf {
    let unique = format!(
        "nscript-ncc-test-{}-{}",
        std::process::id(),
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("clock after the epoch")
            .as_nanos()
    );
    let root = std::env::temp_dir().join(unique);
    fs::create_dir_all(root.join("ncc-00")).expect("create fixture");
    fs::write(
        root.join("ncc-00/ncc.json"),
        r#"{
            "title": "Test NCC",
            "summary": "A test convention.",
            "status": "published",
            "topics": ["nostr", "conventions"],
            "lang": "en",
            "version": "1.0.0",
            "license": "MIT",
            "authors": ["npub1test"]
        }"#,
    )
    .expect("write metadata");
    fs::write(root.join("ncc-00/README.md"), "# Test NCC\n\nBody.\n").expect("write readme");
    root
}

fn write_convention(root: &Path, id: &str, status: &str) {
    let directory = root.join(id);
    fs::create_dir_all(&directory).expect("create convention");
    fs::write(
        directory.join("ncc.json"),
        format!(r#"{{"title":"{id}","status":"{status}"}}"#),
    )
    .expect("write metadata");
    fs::write(directory.join("README.md"), format!("# {id}\n\nBody.\n")).expect("write readme");
}

fn nscript() -> Command {
    Command::new(env!("CARGO_BIN_EXE_nscript"))
}

#[test]
fn check_reports_metadata_as_json() {
    let root = fixture();
    let output = nscript()
        .args(["ncc", "check", "--repo"])
        .arg(&root)
        .arg("--json")
        .output()
        .expect("run ncc check");
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let value: serde_json::Value = serde_json::from_slice(&output.stdout).expect("json output");
    assert_eq!(value["conventions"][0]["id"], "ncc-00");
    assert_eq!(value["conventions"][0]["status"], "published");
    assert_eq!(value["conventions"][0]["title"], "Test NCC");
    fs::remove_dir_all(root).expect("remove fixture");
}

#[test]
fn dry_run_emits_the_full_ncc_tag_set() {
    let root = fixture();
    let output = nscript()
        .args(["ncc", "publish", "--repo"])
        .arg(&root)
        .args([
            "--all",
            "--published-at",
            "1766012345",
            "--dry-run",
            "--json",
        ])
        .output()
        .expect("run ncc publish");
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let value: serde_json::Value = serde_json::from_slice(&output.stdout).expect("json output");
    let document = &value["documents"][0];
    assert_eq!(document["id"], "ncc-00");
    assert_eq!(document["kind"], 30050);
    assert_eq!(
        document["content_bytes"],
        serde_json::json!("# Test NCC\n\nBody.\n".len())
    );
    let tags = document["tags"].as_array().expect("tags array");
    let rendered = tags
        .iter()
        .map(|tag| {
            tag.as_array()
                .expect("tag array")
                .iter()
                .map(|value| value.as_str().expect("tag value").to_owned())
                .collect::<Vec<_>>()
        })
        .collect::<Vec<_>>();
    assert!(rendered.contains(&vec!["d".to_owned(), "ncc-00".to_owned()]));
    assert!(rendered.contains(&vec!["status".to_owned(), "published".to_owned()]));
    assert!(rendered.contains(&vec!["published_at".to_owned(), "1766012345".to_owned()]));
    assert!(rendered.contains(&vec!["title".to_owned(), "Test NCC".to_owned()]));
    assert!(rendered.contains(&vec!["t".to_owned(), "nostr".to_owned()]));
    fs::remove_dir_all(root).expect("remove fixture");
}

#[test]
fn release_tag_selects_the_convention_and_overrides_its_version() {
    let root = fixture();
    let output = nscript()
        .args(["ncc", "publish", "--repo"])
        .arg(&root)
        .args(["--tag", "ncc-00-v2.0.0", "--dry-run", "--json"])
        .output()
        .expect("run ncc publish");
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let value: serde_json::Value = serde_json::from_slice(&output.stdout).expect("json output");
    assert_eq!(value["documents"][0]["version"], "2.0.0");
    fs::remove_dir_all(root).expect("remove fixture");
}

#[test]
fn check_rejects_metadata_without_status() {
    let root = fixture();
    fs::write(root.join("ncc-00/ncc.json"), r#"{"title":"Test NCC"}"#).expect("write metadata");
    let output = nscript()
        .args(["ncc", "check", "--repo"])
        .arg(&root)
        .output()
        .expect("run ncc check");
    assert!(!output.status.success());
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("status"), "{stderr}");
    fs::remove_dir_all(root).expect("remove fixture");
}

#[test]
fn cli_tag_schema_matches_the_ncc00_module() {
    let (descriptor, diagnostics) =
        nscript_modules::parse_module(include_str!("../../../modules/std/ncc00/0.1.0.nsm"));
    assert!(diagnostics.is_empty(), "{diagnostics:?}");
    let descriptor = descriptor.expect("ncc00 parses");
    let document = descriptor
        .events
        .iter()
        .find(|event| event.name == "NccDocument")
        .expect("NccDocument exists");
    assert_eq!(document.kind, nscript_ncc::DOCUMENT_KIND);

    let module_fields = document
        .fields
        .iter()
        .map(|field| field.name.as_str())
        .collect::<BTreeSet<_>>();

    let entry = NccEntry {
        id: "ncc-00".to_owned(),
        directory: PathBuf::from("ncc-00"),
        metadata: Metadata {
            title: "Test NCC".to_owned(),
            summary: Some("Summary".to_owned()),
            status: Status::Published,
            topics: vec!["nostr".to_owned()],
            lang: Some("en".to_owned()),
            version: Some("1.0.0".to_owned()),
            license: Some("MIT".to_owned()),
            authors: vec!["npub1test".to_owned()],
            supersedes: vec!["ncc-99".to_owned()],
        },
        content: "# Test NCC\n".to_owned(),
    };
    let event = build_document(&entry, 1_766_012_345, None).expect("builds");
    let cli_fields = event
        .tags
        .iter()
        .map(|(name, _)| name.as_str())
        .collect::<BTreeSet<_>>();
    assert_eq!(cli_fields, module_fields);
}

#[test]
fn all_skips_drafts_unless_included() {
    let root = fixture();
    write_convention(&root, "ncc-03", "draft");

    let output = nscript()
        .args(["ncc", "publish", "--repo"])
        .arg(&root)
        .args(["--all", "--dry-run", "--json"])
        .output()
        .expect("run ncc publish");
    assert!(output.status.success());
    let value: serde_json::Value = serde_json::from_slice(&output.stdout).expect("json output");
    assert_eq!(value["documents"].as_array().unwrap().len(), 1);
    assert_eq!(value["documents"][0]["id"], "ncc-00");

    let output = nscript()
        .args(["ncc", "publish", "--repo"])
        .arg(&root)
        .args(["--all", "--include-drafts", "--dry-run", "--json"])
        .output()
        .expect("run ncc publish");
    assert!(output.status.success());
    let value: serde_json::Value = serde_json::from_slice(&output.stdout).expect("json output");
    assert_eq!(value["documents"].as_array().unwrap().len(), 2);
    fs::remove_dir_all(root).expect("remove fixture");
}

#[test]
fn version_option_sets_the_version_tag() {
    let root = fixture();
    let output = nscript()
        .args(["ncc", "publish", "--repo"])
        .arg(&root)
        .args(["ncc-00", "--version", "3.0.0", "--dry-run", "--json"])
        .output()
        .expect("run ncc publish");
    assert!(output.status.success());
    let value: serde_json::Value = serde_json::from_slice(&output.stdout).expect("json output");
    assert_eq!(value["documents"][0]["version"], "3.0.0");
    fs::remove_dir_all(root).expect("remove fixture");
}
