//! `NCC-00` metadata and event construction.
//!
//! The `ncc00` `NScript` module is the language-facing schema for `NCC-00`
//! events. This crate is the repository-facing half: it reads the `ncc.json`
//! metadata beside each convention's `README.md`, the supporting-document
//! sidecars, and constructs the matching kind `30050`, `30051`, `30052`, or
//! `30053` event without requiring a script to embed Markdown as a string
//! literal.

use std::collections::BTreeSet;
use std::fmt::{Display, Formatter};
use std::fs;
use std::path::{Path, PathBuf};

use nscript_runtime::UnsignedEvent;
use serde::{Deserialize, Serialize};

/// The `NCC-00` kind for a convention document.
pub const DOCUMENT_KIND: u16 = 30050;
/// The `NCC-00` kind for a succession record.
pub const SUCCESSION_KIND: u16 = 30051;
/// The `NCC-00` kind for an endorsement record.
pub const ENDORSEMENT_KIND: u16 = 30052;
/// The `NCC-00` kind for a supporting document.
pub const SUPPORTING_DOCUMENT_KIND: u16 = 30053;

/// The maximum content size `NCC-00` allows for a document.
pub const MAX_CONTENT_BYTES: usize = 256 * 1024;
/// The maximum content size `NCC-00` allows for a succession record.
pub const MAX_SUCCESSION_BYTES: usize = 32 * 1024;
/// The maximum content size `NCC-00` allows for an endorsement.
pub const MAX_ENDORSEMENT_BYTES: usize = 8 * 1024;
/// The maximum content size accepted for a supporting document.
pub const MAX_SUPPORTING_BYTES: usize = 256 * 1024;

const SUPPORTING_TYPES: [&str; 6] = [
    "guide",
    "implementation",
    "faq",
    "migration",
    "examples",
    "rationale",
];
const ENDORSEMENT_ROLES: [&str; 3] = ["author", "client", "user"];

/// A failure to load, validate, or construct an NCC event.
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

    /// Parses an `NCC-00` status value.
    ///
    /// # Errors
    ///
    /// Returns an error for any value outside `draft`, `published`,
    /// `superseded`, and `withdrawn`.
    pub fn parse(value: &str) -> Result<Self, NccError> {
        match value.trim().to_ascii_lowercase().as_str() {
            "draft" => Ok(Self::Draft),
            "published" => Ok(Self::Published),
            "superseded" => Ok(Self::Superseded),
            "withdrawn" => Ok(Self::Withdrawn),
            other => Err(NccError::new(format!(
                "status must be draft, published, superseded, or withdrawn, found `{other}`"
            ))),
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
        ncc_number(&self.id).unwrap_or(u32::MAX)
    }

    fn validate(&self) -> Result<(), NccError> {
        validate_content(&self.id, "README.md", &self.content, MAX_CONTENT_BYTES)?;
        validate_required_text(&self.id, "title", &self.metadata.title)?;
        validate_optional_text(&self.id, "summary", self.metadata.summary.as_deref())?;
        validate_optional_text(&self.id, "lang", self.metadata.lang.as_deref())?;
        validate_optional_text(&self.id, "version", self.metadata.version.as_deref())?;
        validate_optional_text(&self.id, "license", self.metadata.license.as_deref())?;
        validate_text_list(&self.id, "topics", &self.metadata.topics)?;
        validate_text_list(&self.id, "authors", &self.metadata.authors)?;
        validate_text_list(&self.id, "supersedes", &self.metadata.supersedes)?;
        Ok(())
    }
}

/// The fields for a kind `30051` succession record.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SuccessionMetadata {
    /// The convention identifier.
    pub d: String,
    /// The authoritative document event, accepted as bare hex or
    /// `event:<hex>`.
    pub authoritative: String,
    /// Optional current steward, accepted as bare hex, `pubkey:<hex>`, or
    /// `npub:npub1...`.
    pub steward: Option<String>,
    /// Optional previous event reference.
    pub previous: Option<String>,
    /// Optional short reason.
    pub reason: Option<String>,
    /// Optional Unix timestamp when the succession takes effect.
    pub effective_at: Option<u64>,
    /// The human-readable succession content.
    pub content: String,
}

/// The fields for a kind `30052` endorsement record.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EndorsementMetadata {
    /// The convention identifier.
    pub d: String,
    /// The endorsed document event, accepted as bare hex or `event:<hex>`.
    pub endorses: String,
    /// The `NCC-00` status.
    pub status: Status,
    /// Optional roles: `author`, `client`, or `user`.
    pub roles: Vec<String>,
    /// Optional implementation name or URL.
    pub implementation: Option<String>,
    /// Optional short note.
    pub note: Option<String>,
    /// Optional topics, each published as a repeated `t` tag.
    pub topics: Vec<String>,
    /// Human-readable endorsement content.
    pub content: String,
}

/// The sidecar metadata stored beside a supporting-document Markdown file.
#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct SupportingMetadata {
    /// The supporting-document identifier. Defaults to `<ncc-id>-<slug>`.
    #[serde(default)]
    pub d: Option<String>,
    /// The document title.
    pub title: String,
    /// The `NCC-00` status.
    pub status: Status,
    /// Optional supporting-document type.
    #[serde(default, rename = "type")]
    pub doc_type: Option<String>,
    /// Optional language.
    #[serde(default)]
    pub lang: Option<String>,
    /// Optional topics.
    #[serde(default)]
    pub topics: Vec<String>,
    /// Optional editorial credits.
    #[serde(default)]
    pub authors: Vec<String>,
    /// Optional license.
    #[serde(default)]
    pub license: Option<String>,
    /// Optional document event this material is pinned to.
    #[serde(default)]
    pub for_event: Option<String>,
    /// Optional fixed publication timestamp.
    #[serde(default)]
    pub published_at: Option<u64>,
}

/// A discovered supporting document.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SupportingEntry {
    /// The convention this document supports.
    pub ncc_id: String,
    /// The supporting-document identifier.
    pub d: String,
    /// The file stem used to derive the default identifier.
    pub slug: String,
    /// The directory containing the Markdown and sidecar.
    pub directory: PathBuf,
    /// The Markdown path.
    pub markdown_path: PathBuf,
    /// The parsed sidecar metadata.
    pub metadata: SupportingMetadata,
    /// The exact Markdown content.
    pub content: String,
}

impl SupportingEntry {
    fn validate(&self) -> Result<(), NccError> {
        validate_ncc_id("supporting document", &self.ncc_id)?;
        validate_required_text(&self.d, "d", &self.d)?;
        validate_content(
            &self.d,
            "supporting Markdown",
            &self.content,
            MAX_SUPPORTING_BYTES,
        )?;
        validate_required_text(&self.d, "title", &self.metadata.title)?;
        validate_optional_text(&self.d, "lang", self.metadata.lang.as_deref())?;
        validate_optional_text(&self.d, "license", self.metadata.license.as_deref())?;
        validate_text_list(&self.d, "topics", &self.metadata.topics)?;
        validate_text_list(&self.d, "authors", &self.metadata.authors)?;
        if let Some(doc_type) = &self.metadata.doc_type {
            validate_supporting_type(&self.d, doc_type)?;
        }
        if let Some(for_event) = &self.metadata.for_event {
            normalize_event_reference(for_event, "for_event")?;
        }
        if self.metadata.published_at == Some(0) {
            return Err(NccError::new(format!(
                "{}: published_at must be a positive Unix timestamp",
                self.d
            )));
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

/// Discovers `ncc-XX/supporting/*.md` files and their adjacent `*.json`
/// sidecars.
///
/// # Errors
///
/// Returns an error for unreadable directories, missing or invalid sidecars,
/// duplicate document identifiers, or metadata that does not satisfy
/// `NCC-00`.
pub fn discover_supporting(root: &Path) -> Result<Vec<SupportingEntry>, NccError> {
    let read_dir = fs::read_dir(root).map_err(|error| {
        NccError::new(format!(
            "cannot read repository directory {}: {error}",
            root.display()
        ))
    })?;
    let mut entries = Vec::new();
    let mut identifiers = BTreeSet::new();
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
        let directory = entry.path();
        if !directory.is_dir() {
            continue;
        }
        let supporting_directory = directory.join("supporting");
        if !supporting_directory.is_dir() {
            continue;
        }
        for supporting in fs::read_dir(&supporting_directory).map_err(|error| {
            NccError::new(format!(
                "cannot read {}: {error}",
                supporting_directory.display()
            ))
        })? {
            let supporting = supporting.map_err(|error| {
                NccError::new(format!(
                    "cannot read an entry under {}: {error}",
                    supporting_directory.display()
                ))
            })?;
            let path = supporting.path();
            if path.extension().is_none_or(|extension| extension != "md") {
                continue;
            }
            let slug = path
                .file_stem()
                .map_or_else(String::new, |stem| stem.to_string_lossy().into_owned());
            validate_slug(&name, &slug)?;
            let sidecar = path.with_extension("json");
            let metadata_text = fs::read_to_string(&sidecar).map_err(|error| {
                NccError::new(format!(
                    "{name}/{slug}: cannot read {}: {error}",
                    sidecar.display()
                ))
            })?;
            let metadata =
                serde_json::from_str::<SupportingMetadata>(&metadata_text).map_err(|error| {
                    NccError::new(format!(
                        "{name}/{slug}: invalid {}: {error}",
                        sidecar.display()
                    ))
                })?;
            let content = fs::read_to_string(&path).map_err(|error| {
                NccError::new(format!(
                    "{name}/{slug}: cannot read {}: {error}",
                    path.display()
                ))
            })?;
            let d = metadata
                .d
                .clone()
                .unwrap_or_else(|| format!("{name}-{slug}"));
            if !identifiers.insert((name.clone(), d.clone())) {
                return Err(NccError::new(format!(
                    "{name}: duplicate supporting-document identifier `{d}`"
                )));
            }
            let entry = SupportingEntry {
                ncc_id: name.clone(),
                d,
                slug,
                directory: supporting_directory.clone(),
                markdown_path: path,
                metadata,
                content,
            };
            entry.validate()?;
            entries.push(entry);
        }
    }
    entries.sort_by(|left, right| {
        ncc_number(&left.ncc_id)
            .cmp(&ncc_number(&right.ncc_id))
            .then_with(|| left.slug.cmp(&right.slug))
    });
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
#[must_use = "a document event must be published or discarded"]
pub fn build_document(
    entry: &NccEntry,
    published_at: u64,
    version_override: Option<&str>,
) -> Result<UnsignedEvent, NccError> {
    entry.validate()?;
    validate_timestamp(&entry.id, published_at)?;
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

/// Constructs the kind `30051` succession event.
///
/// # Errors
///
/// Returns an error for an invalid identifier, event reference, steward,
/// text field, content size, or zero timestamp.
#[must_use = "a succession event must be published or discarded"]
pub fn build_succession(
    metadata: &SuccessionMetadata,
    created_at: u64,
) -> Result<UnsignedEvent, NccError> {
    validate_ncc_id("succession", &metadata.d)?;
    validate_timestamp(&metadata.d, created_at)?;
    validate_content(
        &metadata.d,
        "succession content",
        &metadata.content,
        MAX_SUCCESSION_BYTES,
    )?;
    let authoritative = normalize_event_reference(&metadata.authoritative, "authoritative")?;
    let steward = metadata
        .steward
        .as_deref()
        .map(normalize_steward)
        .transpose()?;
    let previous = metadata
        .previous
        .as_deref()
        .map(|value| normalize_event_reference(value, "previous"))
        .transpose()?;
    validate_optional_text(&metadata.d, "reason", metadata.reason.as_deref())?;

    let mut tags = Vec::with_capacity(6);
    tags.push(("d".to_owned(), metadata.d.clone()));
    tags.push(("authoritative".to_owned(), authoritative));
    if let Some(steward) = steward {
        tags.push(("steward".to_owned(), steward));
    }
    if let Some(previous) = previous {
        tags.push(("previous".to_owned(), previous));
    }
    if let Some(reason) = &metadata.reason {
        tags.push(("reason".to_owned(), reason.clone()));
    }
    if let Some(effective_at) = metadata.effective_at {
        tags.push(("effective_at".to_owned(), effective_at.to_string()));
    }

    Ok(UnsignedEvent {
        event_type: "NccSuccession".to_owned(),
        kind: SUCCESSION_KIND,
        content: metadata.content.clone(),
        tags,
        created_at,
    })
}

/// Constructs the kind `30052` endorsement event.
///
/// # Errors
///
/// Returns an error for an invalid identifier, event reference, role, text
/// field, content size, or zero timestamp.
#[must_use = "an endorsement event must be published or discarded"]
pub fn build_endorsement(
    metadata: &EndorsementMetadata,
    created_at: u64,
) -> Result<UnsignedEvent, NccError> {
    validate_ncc_id("endorsement", &metadata.d)?;
    validate_timestamp(&metadata.d, created_at)?;
    validate_content(
        &metadata.d,
        "endorsement content",
        &metadata.content,
        MAX_ENDORSEMENT_BYTES,
    )?;
    let endorses = normalize_event_reference(&metadata.endorses, "endorses")?;
    let roles = normalize_roles(&metadata.d, &metadata.roles)?;
    validate_optional_text(
        &metadata.d,
        "implementation",
        metadata.implementation.as_deref(),
    )?;
    validate_optional_text(&metadata.d, "note", metadata.note.as_deref())?;
    validate_text_list(&metadata.d, "topics", &metadata.topics)?;

    let mut tags = Vec::with_capacity(6);
    tags.push(("d".to_owned(), metadata.d.clone()));
    tags.push(("endorses".to_owned(), endorses));
    tags.push(("status".to_owned(), metadata.status.as_str().to_owned()));
    for role in roles {
        tags.push(("role".to_owned(), role));
    }
    if let Some(implementation) = &metadata.implementation {
        tags.push(("implementation".to_owned(), implementation.clone()));
    }
    if let Some(note) = &metadata.note {
        tags.push(("note".to_owned(), note.clone()));
    }
    for topic in &metadata.topics {
        tags.push(("t".to_owned(), topic.clone()));
    }

    Ok(UnsignedEvent {
        event_type: "NccEndorsement".to_owned(),
        kind: ENDORSEMENT_KIND,
        content: metadata.content.clone(),
        tags,
        created_at,
    })
}

/// Constructs the kind `30053` supporting-document event.
///
/// # Errors
///
/// Returns an error for an invalid identifier, event reference, type, text
/// field, content size, or zero timestamp.
#[must_use = "a supporting document event must be published or discarded"]
pub fn build_supporting_document(
    entry: &SupportingEntry,
    published_at: u64,
) -> Result<UnsignedEvent, NccError> {
    entry.validate()?;
    validate_timestamp(&entry.d, published_at)?;
    if let Some(for_event) = &entry.metadata.for_event {
        normalize_event_reference(for_event, "for_event")?;
    }

    let mut tags = Vec::with_capacity(11);
    tags.push(("d".to_owned(), entry.d.clone()));
    tags.push(("for".to_owned(), entry.ncc_id.clone()));
    tags.push(("title".to_owned(), entry.metadata.title.clone()));
    tags.push(("published_at".to_owned(), published_at.to_string()));
    tags.push((
        "status".to_owned(),
        entry.metadata.status.as_str().to_owned(),
    ));
    if let Some(for_event) = &entry.metadata.for_event {
        tags.push((
            "for_event".to_owned(),
            normalize_event_reference(for_event, "for_event")?,
        ));
    }
    if let Some(doc_type) = &entry.metadata.doc_type {
        tags.push(("type".to_owned(), doc_type.clone()));
    }
    if let Some(lang) = &entry.metadata.lang {
        tags.push(("lang".to_owned(), lang.clone()));
    }
    for topic in &entry.metadata.topics {
        tags.push(("t".to_owned(), topic.clone()));
    }
    for author in &entry.metadata.authors {
        tags.push(("authors".to_owned(), author.clone()));
    }
    if let Some(license) = &entry.metadata.license {
        tags.push(("license".to_owned(), license.clone()));
    }

    Ok(UnsignedEvent {
        event_type: "NccSupportingDocument".to_owned(),
        kind: SUPPORTING_DOCUMENT_KIND,
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
#[must_use = "a parsed release tag must be used"]
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

/// Normalizes a bare event id or `event:<id>` into `event:<lowercase-hex>`.
///
/// # Errors
///
/// Returns an error when the value is not a 64-character hexadecimal event id.
#[must_use = "a normalized event reference must be used"]
pub fn normalize_event_reference(value: &str, field: &str) -> Result<String, NccError> {
    let value = value.trim();
    let hex = value.strip_prefix("event:").unwrap_or(value);
    if hex.len() != 64 || !hex.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return Err(NccError::new(format!(
            "{field} must be an event id (64 hexadecimal characters, optionally prefixed with `event:`)"
        )));
    }
    Ok(format!("event:{}", hex.to_ascii_lowercase()))
}

/// Normalizes a bare pubkey, `pubkey:<hex>`, or `npub:npub1...` steward value.
///
/// # Errors
///
/// Returns an error when the value is neither a 64-character hexadecimal
/// pubkey nor an `npub1...` identifier.
#[must_use = "a normalized steward must be used"]
pub fn normalize_steward(value: &str) -> Result<String, NccError> {
    let value = value.trim();
    if let Some(pubkey) = value.strip_prefix("pubkey:") {
        if pubkey.len() == 64 && pubkey.bytes().all(|byte| byte.is_ascii_hexdigit()) {
            return Ok(format!("pubkey:{}", pubkey.to_ascii_lowercase()));
        }
        return Err(NccError::new(
            "steward `pubkey:` value must be 64 hexadecimal characters",
        ));
    }
    if let Some(npub) = value.strip_prefix("npub:") {
        if npub.starts_with("npub1") {
            return Ok(format!("npub:{npub}"));
        }
        return Err(NccError::new(
            "steward `npub:` value must start with `npub1`",
        ));
    }
    if value.len() == 64 && value.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return Ok(format!("pubkey:{}", value.to_ascii_lowercase()));
    }
    if value.starts_with("npub1") {
        return Ok(format!("npub:{value}"));
    }
    Err(NccError::new(
        "steward must be a 64-character pubkey, `pubkey:<hex>`, or `npub1...`",
    ))
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

fn ncc_number(id: &str) -> Option<u32> {
    id.strip_prefix("ncc-").and_then(|value| value.parse().ok())
}

fn validate_ncc_id(context: &str, id: &str) -> Result<(), NccError> {
    validate_required_text(context, "d", id)?;
    if !is_ncc_directory(id) {
        return Err(NccError::new(format!(
            "{context}: `{id}` must look like `ncc-00`"
        )));
    }
    Ok(())
}

fn validate_content(id: &str, field: &str, content: &str, limit: usize) -> Result<(), NccError> {
    if content.trim().is_empty() {
        return Err(NccError::new(format!("{id}: {field} is empty")));
    }
    if content.len() > limit {
        return Err(NccError::new(format!(
            "{id}: {field} is {} bytes, over the NCC-00 limit of {limit}",
            content.len()
        )));
    }
    Ok(())
}

fn validate_timestamp(id: &str, timestamp: u64) -> Result<(), NccError> {
    if timestamp == 0 {
        return Err(NccError::new(format!(
            "{id}: published_at must be a positive Unix timestamp"
        )));
    }
    Ok(())
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

fn validate_text_list(id: &str, field: &str, values: &[String]) -> Result<(), NccError> {
    for value in values {
        validate_required_text(id, field, value)?;
    }
    Ok(())
}

fn validate_supporting_type(id: &str, value: &str) -> Result<(), NccError> {
    if SUPPORTING_TYPES.contains(&value) {
        Ok(())
    } else {
        Err(NccError::new(format!(
            "{id}: type must be one of {}",
            SUPPORTING_TYPES.join(", ")
        )))
    }
}

fn normalize_roles(id: &str, roles: &[String]) -> Result<Vec<String>, NccError> {
    let mut normalized = Vec::new();
    for role in roles {
        let role = role.trim().to_ascii_lowercase();
        if !ENDORSEMENT_ROLES.contains(&role.as_str()) {
            return Err(NccError::new(format!(
                "{id}: role must be author, client, or user, found `{role}`"
            )));
        }
        if !normalized.contains(&role) {
            normalized.push(role);
        }
    }
    Ok(normalized)
}

fn validate_slug(ncc_id: &str, slug: &str) -> Result<(), NccError> {
    if slug.is_empty()
        || !slug
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-' || byte == b'_')
    {
        return Err(NccError::new(format!(
            "{ncc_id}: supporting file name `{slug}` must use letters, digits, `-`, or `_`"
        )));
    }
    Ok(())
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

    fn sample_supporting() -> SupportingEntry {
        SupportingEntry {
            ncc_id: "ncc-00".to_owned(),
            d: "ncc-00-implementation".to_owned(),
            slug: "implementation".to_owned(),
            directory: PathBuf::from("ncc-00/supporting"),
            markdown_path: PathBuf::from("ncc-00/supporting/implementation.md"),
            metadata: SupportingMetadata {
                d: Some("ncc-00-implementation".to_owned()),
                title: "Implementation notes".to_owned(),
                status: Status::Published,
                doc_type: Some("implementation".to_owned()),
                lang: Some("en".to_owned()),
                topics: vec!["nostr".to_owned()],
                authors: vec!["npub1example".to_owned()],
                license: Some("MIT".to_owned()),
                for_event: Some(
                    "event:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
                        .to_owned(),
                ),
                published_at: None,
            },
            content: "# Implementation\n".to_owned(),
        }
    }

    #[test]
    fn builds_every_document_tag_in_order() {
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
    fn omits_absent_optional_document_tags() {
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
    fn builds_succession_tags() {
        let event = build_succession(
            &SuccessionMetadata {
                d: "ncc-00".to_owned(),
                authoritative: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
                    .to_owned(),
                steward: Some(
                    "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb".to_owned(),
                ),
                previous: Some(
                    "event:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc"
                        .to_owned(),
                ),
                reason: Some("Refresh".to_owned()),
                effective_at: Some(1_766_012_345),
                content: "Acknowledged.".to_owned(),
            },
            1_766_012_345,
        )
        .unwrap();
        assert_eq!(event.kind, SUCCESSION_KIND);
        assert_eq!(
            event.tags,
            vec![
                ("d".to_owned(), "ncc-00".to_owned()),
                (
                    "authoritative".to_owned(),
                    "event:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
                        .to_owned()
                ),
                (
                    "steward".to_owned(),
                    "pubkey:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
                        .to_owned()
                ),
                (
                    "previous".to_owned(),
                    "event:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc"
                        .to_owned()
                ),
                ("reason".to_owned(), "Refresh".to_owned()),
                ("effective_at".to_owned(), "1766012345".to_owned()),
            ]
        );
    }

    #[test]
    fn builds_endorsement_tags() {
        let event = build_endorsement(
            &EndorsementMetadata {
                d: "ncc-00".to_owned(),
                endorses: "dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd"
                    .to_owned(),
                status: Status::Published,
                roles: vec!["client".to_owned(), "CLIENT".to_owned(), "user".to_owned()],
                implementation: Some("NScript".to_owned()),
                note: Some("Used internally".to_owned()),
                topics: vec!["nostr".to_owned()],
                content: "Endorsed.".to_owned(),
            },
            1_766_012_345,
        )
        .unwrap();
        assert_eq!(event.kind, ENDORSEMENT_KIND);
        assert_eq!(
            event.tags,
            vec![
                ("d".to_owned(), "ncc-00".to_owned()),
                (
                    "endorses".to_owned(),
                    "event:dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd"
                        .to_owned()
                ),
                ("status".to_owned(), "published".to_owned()),
                ("role".to_owned(), "client".to_owned()),
                ("role".to_owned(), "user".to_owned()),
                ("implementation".to_owned(), "NScript".to_owned()),
                ("note".to_owned(), "Used internally".to_owned()),
                ("t".to_owned(), "nostr".to_owned()),
            ]
        );
    }

    #[test]
    fn builds_supporting_document_tags() {
        let event = build_supporting_document(&sample_supporting(), 1_766_012_345).unwrap();
        assert_eq!(event.kind, SUPPORTING_DOCUMENT_KIND);
        assert_eq!(
            event.tags,
            vec![
                ("d".to_owned(), "ncc-00-implementation".to_owned()),
                ("for".to_owned(), "ncc-00".to_owned()),
                ("title".to_owned(), "Implementation notes".to_owned()),
                ("published_at".to_owned(), "1766012345".to_owned()),
                ("status".to_owned(), "published".to_owned()),
                (
                    "for_event".to_owned(),
                    "event:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
                        .to_owned()
                ),
                ("type".to_owned(), "implementation".to_owned()),
                ("lang".to_owned(), "en".to_owned()),
                ("t".to_owned(), "nostr".to_owned()),
                ("authors".to_owned(), "npub1example".to_owned()),
                ("license".to_owned(), "MIT".to_owned()),
            ]
        );
    }

    #[test]
    fn normalizes_event_references_and_stewards() {
        let id = "a".repeat(64);
        assert_eq!(
            normalize_event_reference(&id, "authoritative").unwrap(),
            format!("event:{id}")
        );
        assert_eq!(
            normalize_event_reference(&format!("event:{}", id.to_uppercase()), "authoritative")
                .unwrap(),
            format!("event:{id}")
        );
        assert!(normalize_event_reference("event:nope", "authoritative").is_err());
        assert_eq!(normalize_steward(&id).unwrap(), format!("pubkey:{id}"));
        assert_eq!(
            normalize_steward("npub1example").unwrap(),
            "npub:npub1example"
        );
        assert!(normalize_steward("nope").is_err());
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

        let mut supporting = sample_supporting();
        supporting.content = "x".repeat(MAX_SUPPORTING_BYTES + 1);
        assert!(build_supporting_document(&supporting, 1_766_012_345).is_err());
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

    #[test]
    fn rejects_invalid_roles_and_supporting_types() {
        let endorsement = EndorsementMetadata {
            d: "ncc-00".to_owned(),
            endorses: "a".repeat(64),
            status: Status::Published,
            roles: vec!["implementer".to_owned()],
            implementation: None,
            note: None,
            topics: vec![],
            content: "Endorsed.".to_owned(),
        };
        assert!(build_endorsement(&endorsement, 1_766_012_345).is_err());

        let mut supporting = sample_supporting();
        supporting.metadata.doc_type = Some("unknown".to_owned());
        assert!(build_supporting_document(&supporting, 1_766_012_345).is_err());
    }

    #[test]
    fn discovers_supporting_sidecars() {
        let root = std::env::temp_dir().join(format!(
            "nscript-ncc-support-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        let supporting = root.join("ncc-00/supporting");
        fs::create_dir_all(&supporting).unwrap();
        fs::write(supporting.join("implementation.md"), "# Implementation\n").unwrap();
        fs::write(
            supporting.join("implementation.json"),
            r#"{"title":"Implementation","status":"published","type":"implementation"}"#,
        )
        .unwrap();
        let entries = discover_supporting(&root).unwrap();
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].d, "ncc-00-implementation");
        assert_eq!(entries[0].ncc_id, "ncc-00");
        fs::remove_dir_all(root).unwrap();
    }
}
