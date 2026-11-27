use std::collections::BTreeSet;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::{SystemTime, UNIX_EPOCH};

use nscript_ncc::{
    DOCUMENT_KIND, ENDORSEMENT_KIND, EndorsementMetadata, Metadata, NccEntry, SUCCESSION_KIND,
    SUPPORTING_DOCUMENT_KIND, Status, SuccessionMetadata, SupportingEntry, SupportingMetadata,
    build_document, build_endorsement, build_succession, build_supporting_document,
};

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

fn write_supporting(root: &Path, ncc_id: &str, slug: &str, sidecar: &str, content: &str) {
    let directory = root.join(ncc_id).join("supporting");
    fs::create_dir_all(&directory).expect("create supporting directory");
    fs::write(directory.join(format!("{slug}.md")), content).expect("write supporting markdown");
    fs::write(directory.join(format!("{slug}.json")), sidecar).expect("write supporting sidecar");
}

fn nscript() -> Command {
    Command::new(env!("CARGO_BIN_EXE_nscript"))
}

fn find_event(value: &serde_json::Value, kind: u64) -> &serde_json::Value {
    value["events"]
        .as_array()
        .expect("events array")
        .iter()
        .find(|event| event["kind"] == kind)
        .unwrap_or_else(|| panic!("kind {kind} not found in {}", value["events"]))
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
    assert_eq!(value["supporting"].as_array().unwrap().len(), 0);
    fs::remove_dir_all(root).expect("remove fixture");
}

#[test]
fn dry_run_emits_the_full_document_tag_set() {
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
    let document = find_event(&value, u64::from(DOCUMENT_KIND));
    assert_eq!(document["id"], "ncc-00");
    assert_eq!(
        document["content_bytes"],
        serde_json::json!("# Test NCC\n\nBody.\n".len())
    );
    let tags = rendered_tags(document);
    assert!(tags.contains(&vec!["d".to_owned(), "ncc-00".to_owned()]));
    assert!(tags.contains(&vec!["status".to_owned(), "published".to_owned()]));
    assert!(tags.contains(&vec!["published_at".to_owned(), "1766012345".to_owned()]));
    assert!(tags.contains(&vec!["title".to_owned(), "Test NCC".to_owned()]));
    assert!(tags.contains(&vec!["t".to_owned(), "nostr".to_owned()]));
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
    assert_eq!(
        find_event(&value, u64::from(DOCUMENT_KIND))["version"],
        "2.0.0"
    );
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
    assert_eq!(value["events"].as_array().unwrap().len(), 1);
    assert_eq!(value["events"][0]["id"], "ncc-00");

    let output = nscript()
        .args(["ncc", "publish", "--repo"])
        .arg(&root)
        .args(["--all", "--include-drafts", "--dry-run", "--json"])
        .output()
        .expect("run ncc publish");
    assert!(output.status.success());
    let value: serde_json::Value = serde_json::from_slice(&output.stdout).expect("json output");
    assert_eq!(value["events"].as_array().unwrap().len(), 2);
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
    assert_eq!(
        find_event(&value, u64::from(DOCUMENT_KIND))["version"],
        "3.0.0"
    );
    fs::remove_dir_all(root).expect("remove fixture");
}

#[test]
fn support_dry_run_emits_a_supporting_document() {
    let root = fixture();
    write_supporting(
        &root,
        "ncc-00",
        "implementation",
        r#"{
            "title": "Implementation",
            "status": "published",
            "type": "implementation",
            "lang": "en",
            "topics": ["nostr"]
        }"#,
        "# Implementation\n",
    );
    let output = nscript()
        .args(["ncc", "support", "--repo"])
        .arg(&root)
        .args([
            "--ncc",
            "ncc-00",
            "--published-at",
            "1766012345",
            "--dry-run",
            "--json",
        ])
        .output()
        .expect("run ncc support");
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let value: serde_json::Value = serde_json::from_slice(&output.stdout).expect("json output");
    let supporting = find_event(&value, u64::from(SUPPORTING_DOCUMENT_KIND));
    assert_eq!(supporting["id"], "ncc-00-implementation");
    let tags = rendered_tags(supporting);
    assert!(tags.contains(&vec!["d".to_owned(), "ncc-00-implementation".to_owned()]));
    assert!(tags.contains(&vec!["for".to_owned(), "ncc-00".to_owned()]));
    assert!(tags.contains(&vec!["title".to_owned(), "Implementation".to_owned()]));
    assert!(tags.contains(&vec!["status".to_owned(), "published".to_owned()]));
    assert!(tags.contains(&vec!["type".to_owned(), "implementation".to_owned()]));
    fs::remove_dir_all(root).expect("remove fixture");
}

#[test]
fn publish_supporting_includes_documents_and_supporting_docs() {
    let root = fixture();
    write_supporting(
        &root,
        "ncc-00",
        "implementation",
        r#"{"title":"Implementation","status":"published","type":"implementation"}"#,
        "# Implementation\n",
    );
    let output = nscript()
        .args(["ncc", "publish", "--repo"])
        .arg(&root)
        .args(["--all", "--supporting", "--dry-run", "--json"])
        .output()
        .expect("run ncc publish");
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let value: serde_json::Value = serde_json::from_slice(&output.stdout).expect("json output");
    assert_eq!(value["events"].as_array().unwrap().len(), 2);
    assert_eq!(find_event(&value, u64::from(DOCUMENT_KIND))["id"], "ncc-00");
    assert_eq!(
        find_event(&value, u64::from(SUPPORTING_DOCUMENT_KIND))["id"],
        "ncc-00-implementation"
    );
    fs::remove_dir_all(root).expect("remove fixture");
}

#[test]
fn check_reports_supporting_documents() {
    let root = fixture();
    write_supporting(
        &root,
        "ncc-00",
        "implementation",
        r#"{"title":"Implementation","status":"published"}"#,
        "# Implementation\n",
    );
    let output = nscript()
        .args(["ncc", "check", "--repo"])
        .arg(&root)
        .arg("--json")
        .output()
        .expect("run ncc check");
    assert!(output.status.success());
    let value: serde_json::Value = serde_json::from_slice(&output.stdout).expect("json output");
    assert_eq!(value["supporting"].as_array().unwrap().len(), 1);
    assert_eq!(value["supporting"][0]["d"], "ncc-00-implementation");
    assert_eq!(value["conventions"][0]["supporting"], 1);
    fs::remove_dir_all(root).expect("remove fixture");
}

#[test]
fn succession_dry_run_normalizes_event_reference() {
    let root = fixture();
    let id = "a".repeat(64);
    let pubkey = "b".repeat(64);
    let output = nscript()
        .args(["ncc", "succession", "--repo"])
        .arg(&root)
        .args([
            "--ncc",
            "ncc-00",
            "--authoritative",
            &id,
            "--steward",
            &pubkey,
            "--previous",
            &format!("event:{id}"),
            "--reason",
            "Refresh",
            "--effective-at",
            "1766012999",
            "--content",
            "Acknowledged.",
            "--published-at",
            "1766012345",
            "--dry-run",
            "--json",
        ])
        .output()
        .expect("run ncc succession");
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let value: serde_json::Value = serde_json::from_slice(&output.stdout).expect("json output");
    let succession = find_event(&value, u64::from(SUCCESSION_KIND));
    let tags = rendered_tags(succession);
    assert!(tags.contains(&vec!["d".to_owned(), "ncc-00".to_owned()]));
    assert!(tags.contains(&vec!["authoritative".to_owned(), format!("event:{id}")]));
    assert!(tags.contains(&vec!["steward".to_owned(), format!("pubkey:{pubkey}")]));
    assert!(tags.contains(&vec!["previous".to_owned(), format!("event:{id}")]));
    assert!(tags.contains(&vec!["reason".to_owned(), "Refresh".to_owned()]));
    assert!(tags.contains(&vec!["effective_at".to_owned(), "1766012999".to_owned()]));
    fs::remove_dir_all(root).expect("remove fixture");
}

#[test]
fn endorse_dry_run_emits_endorsement_tags() {
    let root = fixture();
    let id = "c".repeat(64);
    let output = nscript()
        .args(["ncc", "endorse", "--repo"])
        .arg(&root)
        .args([
            "--ncc",
            "ncc-00",
            "--event",
            &format!("event:{id}"),
            "--role",
            "client",
            "--role",
            "CLIENT",
            "--implementation",
            "NScript",
            "--note",
            "Used internally",
            "--topic",
            "nostr",
            "--content",
            "Endorsed.",
            "--published-at",
            "1766012345",
            "--dry-run",
            "--json",
        ])
        .output()
        .expect("run ncc endorse");
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let value: serde_json::Value = serde_json::from_slice(&output.stdout).expect("json output");
    let endorsement = find_event(&value, u64::from(ENDORSEMENT_KIND));
    let tags = rendered_tags(endorsement);
    assert!(tags.contains(&vec!["d".to_owned(), "ncc-00".to_owned()]));
    assert!(tags.contains(&vec!["endorses".to_owned(), format!("event:{id}")]));
    assert!(tags.contains(&vec!["status".to_owned(), "published".to_owned()]));
    assert_eq!(
        tags.iter()
            .filter(|tag| tag[0] == "role" && tag[1] == "client")
            .count(),
        1
    );
    assert!(tags.contains(&vec!["implementation".to_owned(), "NScript".to_owned()]));
    assert!(tags.contains(&vec!["note".to_owned(), "Used internally".to_owned()]));
    fs::remove_dir_all(root).expect("remove fixture");
}

#[test]
fn endorse_rejects_invalid_roles() {
    let root = fixture();
    let output = nscript()
        .args(["ncc", "endorse", "--repo"])
        .arg(&root)
        .args([
            "--ncc",
            "ncc-00",
            "--event",
            &"d".repeat(64),
            "--role",
            "implementer",
            "--dry-run",
        ])
        .output()
        .expect("run ncc endorse");
    assert!(!output.status.success());
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("role must be author, client, or user"),
        "{stderr}"
    );
    fs::remove_dir_all(root).expect("remove fixture");
}

#[test]
fn publish_succession_dry_run_adds_the_placeholder() {
    let root = fixture();
    let output = nscript()
        .args(["ncc", "publish", "--repo"])
        .arg(&root)
        .args(["--all", "--succession", "--dry-run", "--json"])
        .output()
        .expect("run ncc publish");
    assert!(output.status.success());
    let value: serde_json::Value = serde_json::from_slice(&output.stdout).expect("json output");
    assert_eq!(value["succession"]["d"], "ncc-00");
    assert_eq!(
        value["succession"]["authoritative"],
        "event:<document-event-id>"
    );
    fs::remove_dir_all(root).expect("remove fixture");
}

#[test]
fn cli_tag_schema_matches_all_ncc00_events() {
    let (descriptor, diagnostics) =
        nscript_modules::parse_module(include_str!("../../../modules/std/ncc00/0.1.0.nsm"));
    assert!(diagnostics.is_empty(), "{diagnostics:?}");
    let descriptor = descriptor.expect("ncc00 parses");
    let id = "a".repeat(64);

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
    let document = build_document(&entry, 1_766_012_345, None).expect("document");
    assert_schema(&descriptor, "NccDocument", DOCUMENT_KIND, &document);

    let succession = build_succession(
        &SuccessionMetadata {
            d: "ncc-00".to_owned(),
            authoritative: id.clone(),
            steward: Some("b".repeat(64)),
            previous: Some(id.clone()),
            reason: Some("Refresh".to_owned()),
            effective_at: Some(1_766_012_345),
            content: "Acknowledged.".to_owned(),
        },
        1_766_012_345,
    )
    .expect("succession");
    assert_schema(&descriptor, "NccSuccession", SUCCESSION_KIND, &succession);

    let endorsement = build_endorsement(
        &EndorsementMetadata {
            d: "ncc-00".to_owned(),
            endorses: id.clone(),
            status: Status::Published,
            roles: vec!["client".to_owned()],
            implementation: Some("NScript".to_owned()),
            note: Some("Used".to_owned()),
            topics: vec!["nostr".to_owned()],
            content: "Endorsed.".to_owned(),
        },
        1_766_012_345,
    )
    .expect("endorsement");
    assert_schema(
        &descriptor,
        "NccEndorsement",
        ENDORSEMENT_KIND,
        &endorsement,
    );

    let supporting = build_supporting_document(
        &SupportingEntry {
            ncc_id: "ncc-00".to_owned(),
            d: "ncc-00-implementation".to_owned(),
            slug: "implementation".to_owned(),
            directory: PathBuf::from("ncc-00/supporting"),
            markdown_path: PathBuf::from("ncc-00/supporting/implementation.md"),
            metadata: SupportingMetadata {
                d: Some("ncc-00-implementation".to_owned()),
                title: "Implementation".to_owned(),
                status: Status::Published,
                doc_type: Some("implementation".to_owned()),
                lang: Some("en".to_owned()),
                topics: vec!["nostr".to_owned()],
                authors: vec!["npub1test".to_owned()],
                license: Some("MIT".to_owned()),
                for_event: Some(id),
                published_at: None,
            },
            content: "# Implementation\n".to_owned(),
        },
        1_766_012_345,
    )
    .expect("supporting");
    assert_schema(
        &descriptor,
        "NccSupportingDocument",
        SUPPORTING_DOCUMENT_KIND,
        &supporting,
    );
}

fn assert_schema(
    descriptor: &nscript_modules::ModuleDescriptor,
    event_name: &str,
    kind: u16,
    event: &nscript_runtime::UnsignedEvent,
) {
    let definition = descriptor
        .events
        .iter()
        .find(|event| event.name == event_name)
        .unwrap_or_else(|| panic!("{event_name} exists"));
    assert_eq!(definition.kind, kind);
    let module_fields = definition
        .fields
        .iter()
        .map(|field| field.name.as_str())
        .collect::<BTreeSet<_>>();
    let cli_fields = event
        .tags
        .iter()
        .map(|(name, _)| name.as_str())
        .collect::<BTreeSet<_>>();
    assert_eq!(cli_fields, module_fields, "{event_name}");
}
