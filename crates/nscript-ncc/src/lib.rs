//! `NCC-00` document metadata and event construction.
//!
//! The `ncc00` `NScript` module is the language-facing schema for `NCC-00`
//! events. This crate is the repository-facing half: it reads the `ncc.json`
//! metadata file that sits beside each convention's `README.md`, validates it,
//! and constructs the matching kind `30050` event without requiring a script
//! to embed a large Markdown document as a string literal.
//!
//! It deliberately covers only NCC document publication. Succession,
//! endorsement, and supporting-document events remain available through the
//! `ncc00` module and are not constructed here.

use std::fmt::{Display, Formatter};
use std::fs;
use std::path::{Path, PathBuf};

use nscript_runtime::UnsignedEvent;
use serde::{Deserialize, Serialize};

/// The `NCC-00` kind for a convention document.
pub const DOCUMENT_KIND: u16 = 30050;
/// The maximum content size `NCC-00` allows for a document.
pub const MAX_CONTENT_BYTES: usize = 256 * 1024;

/// A failure to load, validate, or construct an NCC document.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NccError {
    message: String,
}

impl NccError {
    fn new(message: impl Into<String>) -> Self {
        Self {
            message: message.into(),
        }
    }

    /// The human-readable failure message.
    #[must_use]
    pub fn message(&self) -> &str {
        &self.message
    }
}

impl Display for NccError {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(&self.message)
    }
}

impl std::error::Error for NccError {}

/// The `NCC-00` status values.
#[derive(Debug, Clone, Copy, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum Status {
    /// A draft that is not yet published.
    Draft,
    /// A published convention.
    Published,
    /// A convention superseded by another document.
    Superseded,
    /// A withdrawn convention.
    Withdrawn,
}

impl Status {
    /// The lowercase wire value used in the `status` tag.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Draft => "draft",
            Self::Published => "published",
            Self::Superseded => "superseded",
            Self::Withdrawn => "withdrawn",
        }
    }
}

/// The repository metadata stored in `ncc-XX/ncc.json`.
#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Metadata {
    /// The document title, published as the `title` tag.
    pub title: String,
    /// An optional summary, published as the `summary` tag.
    #[serde(default)]
    pub summary: Option<String>,
    /// The `NCC-00` status, published as the `status` tag.
    pub status: Status,
    /// Optional topics, each published as a repeated `t` tag.
    #[serde(default)]
    pub topics: Vec<String>,
    /// An optional language, published as the `lang` tag.
    #[serde(default)]
    pub lang: Option<String>,
    /// An optional version, published as the `version` tag.
    #[serde(default)]
    pub version: Option<String>,
    /// An optional license, published as the `license` tag.
    #[serde(default)]
    pub license: Option<String>,
    /// Optional editorial credits, each published as a repeated `authors` tag.
    #[serde(default)]
    pub authors: Vec<String>,
    /// Optional superseded convention identifiers, each published as a
    /// repeated `supersedes` tag.
    #[serde(default)]
    pub supersedes: Vec<String>,
}

/// A discovered convention: its `ncc.json`, its `README.md`, and its id.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NccEntry {
    /// The convention identifier derived from the directory name.
    pub id: String,
    /// The convention directory.
    pub directory: PathBuf,
    /// The parsed `ncc.json` metadata.
    pub metadata: Metadata,
    /// The exact Markdown content from `README.md`.
    pub content: String,
}

impl NccEntry {
    /// The numeric part of the identifier, used only for deterministic
    /// ordering.
    #[must_use]
    pub fn number(&self) -> u32 {
        self.id
            .strip_prefix("ncc-")
            .and_then(|value| value.parse().ok())
            .unwrap_or(u32::MAX)
    }

    fn validate(&self) -> Result<(), NccError> {
        if self.content.trim().is_empty() {
            return Err(NccError::new(format!("{}: README.md is empty", self.id)));
        }
        if self.content.len() > MAX_CONTENT_BYTES {
            return Err(NccError::new(format!(
                "{}: README.md is {} bytes, over the NCC-00 limit of {MAX_CONTENT_BYTES}",
                self.id,
                self.content.len()
            )));
        }
        validate_required_text(&self.id, "title", &self.metadata.title)?;
        validate_optional_text(&self.id, "summary", self.metadata.summary.as_deref())?;
        validate_optional_text(&self.id, "lang", self.metadata.lang.as_deref())?;
        validate_optional_text(&self.id, "version", self.metadata.version.as_deref())?;
        validate_optional_text(&self.id, "license", self.metadata.license.as_deref())?;
        for (field, values) in [
            ("topics", &self.metadata.topics),
            ("authors", &self.metadata.authors),
            ("supersedes", &self.metadata.supersedes),
        ] {
            for value in values {
                if value.trim().is_empty() {
                    return Err(NccError::new(format!(
                        "{}: {field} must not contain an empty value",
                        self.id
                    )));
                }
                reject_line_break(&self.id, field, value)?;
            }
        }
        Ok(())
    }
}

/// Discovers every `ncc-<digits>` directory under `root` that contains an
/// `ncc.json` and a `README.md`, validates the pair, and returns them in
/// numeric order.
///
/// # Errors
///
/// Returns an error when the root cannot be read, a convention directory is
/// missing either file, the JSON is invalid, or the metadata or content does
/// not satisfy `NCC-00`.
pub fn discover(root: &Path) -> Result<Vec<NccEntry>, NccError> {
    let read_dir = fs::read_dir(root).map_err(|error| {
        NccError::new(format!(
            "cannot read repository directory {}: {error}",
            root.display()
        ))
    })?;
    let mut entries = Vec::new();
    for entry in read_dir {
        let entry = entry.map_err(|error| {
            NccError::new(format!(
                "cannot read an entry under {}: {error}",
                root.display()
            ))
        })?;
        let name = entry.file_name().to_string_lossy().into_owned();
        if !is_ncc_directory(&name) {
            continue;
        }
        if !entry
            .file_type()
            .map_err(|error| {
                NccError::new(format!(
                    "cannot inspect {}: {error}",
                    entry.path().display()
                ))
            })?
            .is_dir()
        {
            continue;
        }
        entries.push(load_entry(entry.path(), &name)?);
    }
    entries.sort_by_key(NccEntry::number);
    Ok(entries)
}

/// Constructs the kind `30050` event for a convention.
///
/// `version_override` is used by release-tag publication so the tag's version
/// wins over `ncc.json`. The event's `created_at` and `published_at` both use
/// `published_at`.
///
/// # Errors
///
/// Returns an error when the entry no longer validates, `published_at` is
/// zero, or the version override is empty.
pub fn build_document(
    entry: &NccEntry,
    published_at: u64,
    version_override: Option<&str>,
) -> Result<UnsignedEvent, NccError> {
    entry.validate()?;
    if published_at == 0 {
        return Err(NccError::new(format!(
            "{}: published_at must be a positive Unix timestamp",
            entry.id
        )));
    }
    if let Some(version) = version_override {
        validate_required_text(&entry.id, "version override", version)?;
    }

    let mut tags = Vec::with_capacity(11);
    tags.push(("d".to_owned(), entry.id.clone()));
    tags.push(("title".to_owned(), entry.metadata.title.clone()));
    tags.push(("published_at".to_owned(), published_at.to_string()));
    tags.push((
        "status".to_owned(),
        entry.metadata.status.as_str().to_owned(),
    ));
    if let Some(summary) = &entry.metadata.summary {
        tags.push(("summary".to_owned(), summary.clone()));
    }
    for topic in &entry.metadata.topics {
        tags.push(("t".to_owned(), topic.clone()));
    }
    if let Some(lang) = &entry.metadata.lang {
        tags.push(("lang".to_owned(), lang.clone()));
    }
    if let Some(version) = version_override.or(entry.metadata.version.as_deref()) {
        tags.push(("version".to_owned(), version.to_owned()));
    }
    for supersedes in &entry.metadata.supersedes {
        tags.push(("supersedes".to_owned(), supersedes.clone()));
    }
    if let Some(license) = &entry.metadata.license {
        tags.push(("license".to_owned(), license.clone()));
    }
    for author in &entry.metadata.authors {
        tags.push(("authors".to_owned(), author.clone()));
    }

    Ok(UnsignedEvent {
        event_type: "NccDocument".to_owned(),
        kind: DOCUMENT_KIND,
        content: entry.content.clone(),
        tags,
        created_at: published_at,
    })
}

/// Parses a release tag such as `ncc-02-v0.6.0` into its identifier and
/// version.
///
/// # Errors
///
/// Returns an error when the tag is not `<ncc-id>-v<version>`.
pub fn parse_release_tag(tag: &str) -> Result<(String, String), NccError> {
    let tag = tag.trim();
    let (id, version) = tag.split_once("-v").ok_or_else(|| {
        NccError::new(format!(
            "release tag `{tag}` must look like `ncc-02-v0.6.0`"
        ))
    })?;
    if !is_ncc_directory(id) {
        return Err(NccError::new(format!(
            "release tag `{tag}` must start with an NCC identifier such as `ncc-02`"
        )));
    }
    validate_required_text(id, "version", version)?;
    Ok((id.to_owned(), version.to_owned()))
}

fn load_entry(directory: PathBuf, id: &str) -> Result<NccEntry, NccError> {
    let metadata_path = directory.join("ncc.json");
    let readme_path = directory.join("README.md");
    let metadata_text = fs::read_to_string(&metadata_path).map_err(|error| {
        NccError::new(format!(
            "{id}: cannot read {}: {error}",
            metadata_path.display()
        ))
    })?;
    let metadata = serde_json::from_str::<Metadata>(&metadata_text).map_err(|error| {
        NccError::new(format!(
            "{id}: invalid {}: {error}",
            metadata_path.display()
        ))
    })?;
    let content = fs::read_to_string(&readme_path).map_err(|error| {
        NccError::new(format!(
            "{id}: cannot read {}: {error}",
            readme_path.display()
        ))
    })?;
    let entry = NccEntry {
        id: id.to_owned(),
        directory,
        metadata,
        content,
    };
    entry.validate()?;
    Ok(entry)
}

fn is_ncc_directory(name: &str) -> bool {
    name.strip_prefix("ncc-").is_some_and(|suffix| {
        !suffix.is_empty() && suffix.bytes().all(|byte| byte.is_ascii_digit())
    })
}

fn validate_required_text(id: &str, field: &str, value: &str) -> Result<(), NccError> {
    if value.trim().is_empty() {
        return Err(NccError::new(format!("{id}: {field} must not be empty")));
    }
    reject_line_break(id, field, value)
}

fn validate_optional_text(id: &str, field: &str, value: Option<&str>) -> Result<(), NccError> {
    value.map_or(Ok(()), |value| validate_required_text(id, field, value))
}

fn reject_line_break(id: &str, field: &str, value: &str) -> Result<(), NccError> {
    if value.contains(['\n', '\r', '\u{1f}']) {
        return Err(NccError::new(format!(
            "{id}: {field} must not contain a line break or tag separator"
        )));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_entry() -> NccEntry {
        NccEntry {
            id: "ncc-00".to_owned(),
            directory: PathBuf::from("ncc-00"),
            metadata: Metadata {
                title: "Publishing NCCs on Nostr".to_owned(),
                summary: Some("How NCCs work.".to_owned()),
                status: Status::Published,
                topics: vec!["nostr".to_owned(), "conventions".to_owned()],
                lang: Some("en".to_owned()),
                version: Some("1.0.0".to_owned()),
                license: Some("MIT".to_owned()),
                authors: vec!["npub1example".to_owned()],
                supersedes: vec!["ncc-99".to_owned()],
            },
            content: "# NCC-00\n".to_owned(),
        }
    }

    #[test]
    fn builds_every_tag_in_order() {
        let event = build_document(&sample_entry(), 1_766_012_345, None).unwrap();
        assert_eq!(event.kind, DOCUMENT_KIND);
        assert_eq!(event.content, "# NCC-00\n");
        assert_eq!(
            event.tags,
            vec![
                ("d".to_owned(), "ncc-00".to_owned()),
                ("title".to_owned(), "Publishing NCCs on Nostr".to_owned()),
                ("published_at".to_owned(), "1766012345".to_owned()),
                ("status".to_owned(), "published".to_owned()),
                ("summary".to_owned(), "How NCCs work.".to_owned()),
                ("t".to_owned(), "nostr".to_owned()),
                ("t".to_owned(), "conventions".to_owned()),
                ("lang".to_owned(), "en".to_owned()),
                ("version".to_owned(), "1.0.0".to_owned()),
                ("supersedes".to_owned(), "ncc-99".to_owned()),
                ("license".to_owned(), "MIT".to_owned()),
                ("authors".to_owned(), "npub1example".to_owned()),
            ]
        );
    }

    #[test]
    fn release_tag_overrides_the_metadata_version() {
        let event = build_document(&sample_entry(), 1_766_012_345, Some("2.0.0")).unwrap();
        assert!(
            event
                .tags
                .contains(&("version".to_owned(), "2.0.0".to_owned()))
        );
        assert!(
            !event
                .tags
                .contains(&("version".to_owned(), "1.0.0".to_owned()))
        );
    }

    #[test]
    fn omits_absent_optional_tags() {
        let mut entry = sample_entry();
        entry.metadata.summary = None;
        entry.metadata.topics.clear();
        entry.metadata.lang = None;
        entry.metadata.version = None;
        entry.metadata.license = None;
        entry.metadata.authors.clear();
        entry.metadata.supersedes.clear();
        let event = build_document(&entry, 1_766_012_345, None).unwrap();
        let names = event
            .tags
            .iter()
            .map(|(name, _)| name.as_str())
            .collect::<Vec<_>>();
        assert_eq!(names, ["d", "title", "published_at", "status"]);
    }

    #[test]
    fn parses_release_tags() {
        assert_eq!(
            parse_release_tag("ncc-02-v0.6.0").unwrap(),
            ("ncc-02".to_owned(), "0.6.0".to_owned())
        );
        assert!(parse_release_tag("v0.6.0").is_err());
        assert!(parse_release_tag("ncc-02").is_err());
        assert!(parse_release_tag("ncc-02-v").is_err());
    }

    #[test]
    fn rejects_invalid_status_and_unknown_fields() {
        let json = r#"{"title":"T","status":"active"}"#;
        assert!(serde_json::from_str::<Metadata>(json).is_err());
        let json = r#"{"title":"T","status":"published","extra":true}"#;
        assert!(serde_json::from_str::<Metadata>(json).is_err());
    }

    #[test]
    fn rejects_empty_or_oversized_content() {
        let mut entry = sample_entry();
        entry.content.clear();
        assert!(build_document(&entry, 1_766_012_345, None).is_err());

        let mut oversized = sample_entry();
        oversized.content = "x".repeat(MAX_CONTENT_BYTES + 1);
        assert!(build_document(&oversized, 1_766_012_345, None).is_err());
    }

    #[test]
    fn rejects_line_breaks_and_tag_separators_in_tags() {
        let mut entry = sample_entry();
        entry.metadata.title = "bad\ntitle".to_owned();
        assert!(build_document(&entry, 1_766_012_345, None).is_err());

        let mut entry = sample_entry();
        entry.metadata.title = "bad\u{1f}title".to_owned();
        assert!(build_document(&entry, 1_766_012_345, None).is_err());
    }
}
