//! NIP-5D manifest and shell-handler validation.
//!
//! NIP-5D is a draft, and its event shapes are shared by the CLI, the
//! `nip5d` `NScript` module, and any host that wants to audit a manifest. This
//! crate is the single implementation of the event-level rules: which kinds
//! exist, which tags are required, and what a well-formed domain, intent,
//! source, or media blob looks like.
//!
//! It deliberately does not touch the browser side of NIP-5D. The
//! `postMessage` transport, `MessagePort` binding, NAP calls, iframe sandbox,
//! CSP injection, and artifact byte verification stay in the shell. This crate
//! validates the signed event; it does not load an applet.

/// A Nostr tag in its wire shape: the tag name followed by its columns.
pub type Tag = Vec<String>;

/// Snapshot manifest: a regular event pinning one immutable napplet version.
pub const SNAPSHOT_KIND: u64 = 5129;
/// Root napplet manifest: a replaceable event.
pub const ROOT_KIND: u64 = 15129;
/// Named napplet manifest: an addressable event with a `d` tag.
pub const NAMED_KIND: u64 = 35129;
/// NIP-89 handler information event used by a shell to advertise itself.
pub const SHELL_HANDLER_KIND: u64 = 31990;

/// Column separator used when the evaluator carries a multi-column tag as one
/// text value. `NScript`'s event value joins extra columns with U+001F.
pub const COLUMN_SEPARATOR: char = '\u{1f}';

/// The three NIP-5D manifest kinds.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ManifestKind {
    Snapshot,
    Root,
    Named,
}

impl ManifestKind {
    /// The manifest kind for a raw event kind, or `None` when the kind is not
    /// a NIP-5D manifest.
    #[must_use]
    pub fn from_kind(kind: u64) -> Option<Self> {
        match kind {
            SNAPSHOT_KIND => Some(Self::Snapshot),
            ROOT_KIND => Some(Self::Root),
            NAMED_KIND => Some(Self::Named),
            _ => None,
        }
    }

    /// The raw event kind.
    #[must_use]
    pub fn kind(self) -> u64 {
        match self {
            Self::Snapshot => SNAPSHOT_KIND,
            Self::Root => ROOT_KIND,
            Self::Named => NAMED_KIND,
        }
    }

    /// Whether this kind carries a `d` identifier. Only named napplets do.
    #[must_use]
    pub fn has_identifier(self) -> bool {
        matches!(self, Self::Named)
    }
}

/// Whether a diagnostic rejects the event or only advises its reader.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Severity {
    Error,
    Warning,
}

/// One validation finding.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Diagnostic {
    /// A stable machine-readable code.
    pub code: &'static str,
    /// A human-readable explanation.
    pub message: String,
    /// Whether this finding rejects the event.
    pub severity: Severity,
}

impl Diagnostic {
    /// Create an error.
    #[must_use]
    pub fn error(code: &'static str, message: impl Into<String>) -> Self {
        Self {
            code,
            message: message.into(),
            severity: Severity::Error,
        }
    }

    /// Create a warning.
    #[must_use]
    pub fn warning(code: &'static str, message: impl Into<String>) -> Self {
        Self {
            code,
            message: message.into(),
            severity: Severity::Warning,
        }
    }

    /// Whether this finding rejects the event.
    #[must_use]
    pub fn is_error(&self) -> bool {
        self.severity == Severity::Error
    }
}

/// Parse the evaluator's `name=value` tag text into wire columns.
///
/// The evaluator renders every event tag as `name=value`; extra wire columns
/// beyond the first value are joined by [`COLUMN_SEPARATOR`]. This reverses
/// that rendering so pure functions can validate a script's `event.tags`.
#[must_use]
pub fn tag_from_text(value: &str) -> Tag {
    let Some((name, rest)) = value.split_once('=') else {
        return vec![value.to_owned()];
    };
    let mut tag = vec![name.to_owned()];
    tag.extend(rest.split(COLUMN_SEPARATOR).map(str::to_owned));
    tag
}

/// Parse a list of evaluator tag texts.
#[must_use]
pub fn tags_from_text<I, S>(values: I) -> Vec<Tag>
where
    I: IntoIterator<Item = S>,
    S: AsRef<str>,
{
    values
        .into_iter()
        .map(|value| tag_from_text(value.as_ref()))
        .collect()
}

/// Whether `value` is a 64-character lowercase hexadecimal SHA-256.
#[must_use]
pub fn artifact_is_sha256(value: &str) -> bool {
    value.len() == 64 && value.bytes().all(is_lower_hex)
}

fn is_lower_hex(byte: u8) -> bool {
    matches!(byte, b'0'..=b'9' | b'a'..=b'f')
}

fn is_bare_domain(value: &str) -> bool {
    let mut bytes = value.bytes();
    matches!(bytes.next(), Some(b'a'..=b'z'))
        && bytes.all(|byte| matches!(byte, b'a'..=b'z' | b'0'..=b'9' | b'-'))
}

fn is_queryless_identity(value: &str) -> bool {
    !value.is_empty() && !value.contains(['?', '#']) && !value.chars().any(char::is_whitespace)
}

fn is_http_origin(value: &str) -> bool {
    let Some(rest) = value
        .strip_prefix("https://")
        .or_else(|| value.strip_prefix("http://"))
    else {
        return false;
    };
    !rest.is_empty() && !rest.contains(['/', '?', '#']) && !rest.chars().any(char::is_whitespace)
}

fn is_source_location(value: &str) -> bool {
    if value.is_empty() || value.chars().any(char::is_whitespace) {
        return false;
    }
    if value.starts_with("https://")
        || value.starts_with("http://")
        || value.starts_with("ssh://")
        || value.starts_with("git://")
    {
        return value
            .split_once("://")
            .is_some_and(|(_, rest)| !rest.is_empty());
    }
    if let Some(naddr) = value.strip_prefix("nostr://") {
        return !naddr.is_empty();
    }
    // Git's scp-like SSH syntax: `[user@]host:path`.
    !value.contains("://")
        && !value.starts_with('/')
        && !value.starts_with('.')
        && value
            .split_once(':')
            .is_some_and(|(host, path)| !host.is_empty() && !path.is_empty())
}

fn is_napplet_address(value: &str) -> bool {
    let mut parts = value.splitn(3, ':');
    match (parts.next(), parts.next(), parts.next()) {
        (Some("35129"), Some(pubkey), Some(identifier)) => {
            artifact_is_sha256(pubkey) && !identifier.is_empty()
        }
        (Some("15129"), Some(pubkey), Some("")) => artifact_is_sha256(pubkey),
        _ => false,
    }
}

fn is_https_url_without_credentials_or_fragment(value: &str) -> bool {
    let Some(rest) = value.strip_prefix("https://") else {
        return false;
    };
    if rest.is_empty() || rest.contains('#') || rest.chars().any(char::is_whitespace) {
        return false;
    }
    let authority = rest.split('/').next().unwrap_or_default();
    !authority.is_empty() && !authority.contains('@')
}

fn tag<'a>(tags: &'a [Tag], name: &str) -> impl Iterator<Item = &'a Tag> {
    tags.iter()
        .filter(move |tag| tag.first().is_some_and(|value| value == name))
}

fn value(tag: &Tag, index: usize) -> Option<&str> {
    tag.get(index).map(String::as_str)
}

fn validate_tag_shape(diagnostics: &mut Vec<Diagnostic>, name: &str, tag: &Tag, arity: usize) {
    if tag.len() != arity {
        diagnostics.push(Diagnostic::error(
            "nip5d.tag.arity",
            format!(
                "`{name}` tag must have {arity} elements, found {}",
                tag.len()
            ),
        ));
    }
}

fn validate_domains(tags: &[Tag], name: &str, diagnostics: &mut Vec<Diagnostic>) {
    for tag in tag(tags, name) {
        validate_tag_shape(diagnostics, name, tag, 2);
        let Some(domain) = value(tag, 1) else {
            continue;
        };
        if !is_bare_domain(domain) {
            diagnostics.push(Diagnostic::error(
                "nip5d.domain",
                format!(
                    "`{name}` must be a bare lowercase NAP domain such as `relay`, found {domain:?}"
                ),
            ));
        }
    }
}

fn validate_media(tags: &[Tag], name: &str, diagnostics: &mut Vec<Diagnostic>) {
    for tag in tag(tags, name) {
        if tag.len() < 2 {
            diagnostics.push(Diagnostic::error(
                "nip5d.tag.arity",
                format!("`{name}` tag must carry NIP-92 metadata fields"),
            ));
            continue;
        }
        let mut hashes = 0;
        let mut fields = std::collections::BTreeMap::new();
        for column in tag.iter().skip(1) {
            let (key, item_value) = column.split_once(' ').unwrap_or((column, ""));
            if key.is_empty() {
                diagnostics.push(Diagnostic::error(
                    "nip5d.media.field",
                    format!("`{name}` contains an empty metadata field"),
                ));
                continue;
            }
            if fields.insert(key, item_value).is_some() {
                diagnostics.push(Diagnostic::warning(
                    "nip5d.media.duplicate",
                    format!("`{name}` repeats the `{key}` field; readers ignore it"),
                ));
            }
            if key == "x" {
                hashes += 1;
                if !artifact_is_sha256(item_value) {
                    diagnostics.push(Diagnostic::error(
                        "nip5d.media.hash",
                        format!("`{name}` x field must be a lowercase SHA-256"),
                    ));
                }
            }
        }
        if hashes != 1 {
            diagnostics.push(Diagnostic::error(
                "nip5d.media.hash",
                format!("`{name}` must carry exactly one x field, found {hashes}"),
            ));
        }
        if let Some(size) = fields.get("size")
            && (size.is_empty() || size.parse::<u64>().is_err())
        {
            diagnostics.push(Diagnostic::warning(
                "nip5d.media.size",
                format!("`{name}` size must be an integer number of bytes"),
            ));
        }
        if let Some(dim) = fields.get("dim")
            && !dim.split_once('x').is_some_and(|(w, h)| {
                w.parse::<u32>().is_ok_and(|w| w > 0) && h.parse::<u32>().is_ok_and(|h| h > 0)
            })
        {
            diagnostics.push(Diagnostic::warning(
                "nip5d.media.dim",
                format!("`{name}` dim must look like `WIDTHxHEIGHT`"),
            ));
        }
    }
}

fn validate_source(tags: &[Tag], diagnostics: &mut Vec<Diagnostic>) {
    let sources = tag(tags, "source").collect::<Vec<_>>();
    if sources.len() > 1 {
        diagnostics.push(Diagnostic::error(
            "nip5d.source.duplicate",
            "a manifest must contain at most one `source` tag",
        ));
    }
    for source in sources {
        validate_tag_shape(diagnostics, "source", source, 2);
        let Some(location) = value(source, 1) else {
            continue;
        };
        if !is_source_location(location) {
            diagnostics.push(Diagnostic::error(
                "nip5d.source.location",
                format!("`source` is not a supported repository or archive location: {location:?}"),
            ));
        }
    }

    let commits = tag(tags, "source-commit").collect::<Vec<_>>();
    if commits.len() > 1 {
        diagnostics.push(Diagnostic::error(
            "nip5d.source-commit.duplicate",
            "a manifest must contain at most one `source-commit` tag",
        ));
    }
    for commit in commits {
        validate_tag_shape(diagnostics, "source-commit", commit, 2);
        let Some(commit) = value(commit, 1) else {
            continue;
        };
        let valid_length = commit.len() == 40 || commit.len() == 64;
        if !valid_length || !commit.bytes().all(is_lower_hex) {
            diagnostics.push(Diagnostic::error(
                "nip5d.source-commit.hash",
                "`source-commit` must be a full lowercase-hex Git commit id",
            ));
        }
        if tag(tags, "source").next().is_none() {
            diagnostics.push(Diagnostic::warning(
                "nip5d.source-commit.orphan",
                "`source-commit` is ignored without a `source` tag",
            ));
        }
    }

    let archives = tag(tags, "source-archive").collect::<Vec<_>>();
    if archives.len() > 1 {
        diagnostics.push(Diagnostic::error(
            "nip5d.source-archive.duplicate",
            "a manifest must contain at most one `source-archive` tag",
        ));
    }
    for archive in archives {
        validate_tag_shape(diagnostics, "source-archive", archive, 4);
        let Some(url) = value(archive, 1) else {
            continue;
        };
        if !is_https_url_without_credentials_or_fragment(url) {
            diagnostics.push(Diagnostic::error(
                "nip5d.source-archive.url",
                "`source-archive` must be an absolute HTTPS URL without credentials or a fragment",
            ));
        }
        if let Some(hash) = value(archive, 2)
            && !artifact_is_sha256(hash)
        {
            diagnostics.push(Diagnostic::error(
                "nip5d.source-archive.hash",
                "`source-archive` must carry a lowercase SHA-256 of the archive bytes",
            ));
        }
        if value(archive, 3).is_none_or(str::is_empty) {
            diagnostics.push(Diagnostic::error(
                "nip5d.source-archive.mime",
                "`source-archive` must carry the archive MIME type",
            ));
        }
    }
}

#[allow(clippy::too_many_lines)]
fn validate_manifest_tags(kind: ManifestKind, tags: &[Tag], diagnostics: &mut Vec<Diagnostic>) {
    let d_count = tag(tags, "d").count();
    if kind.has_identifier() {
        if d_count != 1 {
            diagnostics.push(Diagnostic::error(
                "nip5d.d",
                format!("kind {NAMED_KIND} must have exactly one `d` tag, found {d_count}"),
            ));
        }
        for identifier in tag(tags, "d") {
            validate_tag_shape(diagnostics, "d", identifier, 2);
            if value(identifier, 1).is_none_or(str::is_empty) {
                diagnostics.push(Diagnostic::error("nip5d.d", "`d` must not be empty"));
            }
        }
    } else if d_count != 0 {
        diagnostics.push(Diagnostic::error(
            "nip5d.d",
            format!("`d` must be absent on kind {}", kind.kind()),
        ));
    }

    let x_count = tag(tags, "x").count();
    if x_count != 1 {
        diagnostics.push(Diagnostic::error(
            "nip5d.x",
            format!("a manifest must have exactly one `x` tag, found {x_count}"),
        ));
    }
    for hash in tag(tags, "x") {
        validate_tag_shape(diagnostics, "x", hash, 2);
        if let Some(value) = value(hash, 1)
            && !artifact_is_sha256(value)
        {
            diagnostics.push(Diagnostic::error(
                "nip5d.x",
                "`x` must be the 64-character lowercase SHA-256 of the index.html artifact",
            ));
        }
    }

    for archetype in tag(tags, "z") {
        validate_tag_shape(diagnostics, "z", archetype, 2);
        let Some(archetype) = value(archetype, 1) else {
            continue;
        };
        if !is_queryless_identity(archetype) {
            diagnostics.push(Diagnostic::error(
                "nip5d.z",
                format!("`z` must be one non-empty archetype, found {archetype:?}"),
            ));
        }
    }

    for intent in tag(tags, "i") {
        if intent.len() < 2 {
            diagnostics.push(Diagnostic::error(
                "nip5d.i",
                "`i` must carry an intent identity",
            ));
            continue;
        }
        let identity = &intent[1];
        if !is_queryless_identity(identity) {
            diagnostics.push(Diagnostic::error(
                "nip5d.i",
                format!("intent `{identity}` must be a queryless identity without whitespace"),
            ));
        } else if !identity.starts_with("napplet:") {
            diagnostics.push(Diagnostic::warning(
                "nip5d.i.namespace",
                format!("intent `{identity}` is outside the `napplet:` namespace"),
            ));
        }
        for parameter in intent.iter().skip(2) {
            if parameter.is_empty() {
                diagnostics.push(Diagnostic::error(
                    "nip5d.i.parameter",
                    "intent parameter names must not be empty",
                ));
            }
        }
    }

    validate_domains(tags, "R", diagnostics);
    validate_domains(tags, "O", diagnostics);

    let titles = tag(tags, "title").collect::<Vec<_>>();
    if titles.len() > 1 {
        diagnostics.push(Diagnostic::error(
            "nip5d.title.duplicate",
            "a manifest must contain at most one `title` tag",
        ));
    }
    for title in titles {
        validate_tag_shape(diagnostics, "title", title, 2);
        if value(title, 1).is_none_or(|value| value.trim().is_empty()) {
            diagnostics.push(Diagnostic::error(
                "nip5d.title",
                "`title` must not be empty",
            ));
        }
    }

    if tag(tags, "description").next().is_some() {
        diagnostics.push(Diagnostic::warning(
            "nip5d.description",
            "`description` is not a NIP-5D tag; put the description in the event content",
        ));
    }

    for server in tag(tags, "server") {
        validate_tag_shape(diagnostics, "server", server, 2);
        if let Some(origin) = value(server, 1)
            && !is_http_origin(origin)
        {
            diagnostics.push(Diagnostic::error(
                "nip5d.server",
                format!("`server` must be an HTTP(S) origin, found {origin:?}"),
            ));
        }
    }

    let icons = tag(tags, "icon").collect::<Vec<_>>();
    if icons.len() > 1 {
        diagnostics.push(Diagnostic::error(
            "nip5d.icon.duplicate",
            "a manifest must contain at most one `icon` tag",
        ));
    }
    for icon in icons {
        validate_tag_shape(diagnostics, "icon", icon, 3);
        if let Some(hash) = value(icon, 1)
            && !artifact_is_sha256(hash)
        {
            diagnostics.push(Diagnostic::error(
                "nip5d.icon.hash",
                "`icon` must start with a lowercase SHA-256 of the icon blob",
            ));
        }
        if let Some(mime) = value(icon, 2)
            && !matches!(mime, "image/png" | "image/jpeg" | "image/webp")
        {
            diagnostics.push(Diagnostic::error(
                "nip5d.icon.mime",
                "`icon` MIME type must be image/png, image/jpeg, or image/webp",
            ));
        }
    }

    validate_media(tags, "screenshot", diagnostics);
    let previews = tag(tags, "preview").collect::<Vec<_>>();
    if previews.len() > 1 {
        diagnostics.push(Diagnostic::error(
            "nip5d.preview.duplicate",
            "a manifest must contain at most one `preview` tag",
        ));
    }
    validate_media(tags, "preview", diagnostics);

    let lineage = tag(tags, "a").chain(tag(tags, "A")).collect::<Vec<_>>();
    if !lineage.is_empty() && kind != ManifestKind::Snapshot {
        diagnostics.push(Diagnostic::error(
            "nip5d.lineage",
            "`a` and `A` lineage tags are only valid on kind 5129 snapshots",
        ));
    }
    for name in ["a", "A"] {
        let addresses = tag(tags, name).collect::<Vec<_>>();
        if addresses.len() > 1 {
            diagnostics.push(Diagnostic::error(
                "nip5d.lineage.duplicate",
                format!("a manifest must contain at most one `{name}` tag"),
            ));
        }
        for address in addresses {
            validate_tag_shape(diagnostics, name, address, 2);
            if let Some(value) = value(address, 1)
                && !is_napplet_address(value)
            {
                diagnostics.push(Diagnostic::error(
                    "nip5d.lineage.address",
                    format!("`{name}` must address a 35129 or 15129 napplet, found {value:?}"),
                ));
            }
        }
    }
}

/// Validate a napplet manifest event.
///
/// Returns every finding, including warnings. A manifest is accepted when no
/// returned diagnostic is an error.
#[must_use]
pub fn validate_manifest(kind: u64, content: &str, tags: &[Tag]) -> Vec<Diagnostic> {
    let mut diagnostics = Vec::new();
    let Some(manifest_kind) = ManifestKind::from_kind(kind) else {
        diagnostics.push(Diagnostic::error(
            "nip5d.kind",
            format!("kind {kind} is not a NIP-5D napplet manifest"),
        ));
        return diagnostics;
    };
    if content.trim().is_empty() {
        diagnostics.push(Diagnostic::error(
            "nip5d.content",
            "manifest content must contain a non-empty plain-text description",
        ));
    }
    for tag in tags {
        if tag.first().is_none_or(String::is_empty) {
            diagnostics.push(Diagnostic::error(
                "nip5d.tag.name",
                "every tag must have a non-empty name",
            ));
        }
    }
    validate_manifest_tags(manifest_kind, tags, &mut diagnostics);
    validate_source(tags, &mut diagnostics);
    diagnostics
}

/// Whether a manifest has no error-level diagnostics.
#[must_use]
pub fn manifest_is_valid(kind: u64, content: &str, tags: &[Tag]) -> bool {
    validate_manifest(kind, content, tags)
        .iter()
        .all(|diagnostic| !diagnostic.is_error())
}

/// Validate a NIP-89 shell handler event that advertises NIP-5D support.
#[must_use]
pub fn validate_shell_handler(content: &str, tags: &[Tag]) -> Vec<Diagnostic> {
    let mut diagnostics = Vec::new();
    if content.trim().is_empty() {
        diagnostics.push(Diagnostic::error(
            "nip5d.shell.content",
            "shell handler content must contain a non-empty description",
        ));
    }

    let d_tags = tag(tags, "d").collect::<Vec<_>>();
    if d_tags.len() != 1 {
        diagnostics.push(Diagnostic::error(
            "nip5d.shell.d",
            format!(
                "a shell handler must have exactly one `d` tag, found {}",
                d_tags.len()
            ),
        ));
    }
    for identifier in d_tags {
        validate_tag_shape(&mut diagnostics, "d", identifier, 2);
        if value(identifier, 1).is_none_or(str::is_empty) {
            diagnostics.push(Diagnostic::error(
                "nip5d.shell.d",
                "shell handler `d` must not be empty",
            ));
        }
    }

    let kinds = tag(tags, "k").collect::<Vec<_>>();
    if kinds.is_empty() {
        diagnostics.push(Diagnostic::error(
            "nip5d.shell.k",
            "a shell handler must advertise at least one napplet manifest kind in a `k` tag",
        ));
    }
    for kind in kinds {
        validate_tag_shape(&mut diagnostics, "k", kind, 2);
        let Some(raw) = value(kind, 1) else {
            continue;
        };
        if raw
            .parse::<u64>()
            .ok()
            .and_then(ManifestKind::from_kind)
            .is_none()
        {
            diagnostics.push(Diagnostic::error(
                "nip5d.shell.k",
                format!("`k` must be 5129, 15129, or 35129, found {raw:?}"),
            ));
        }
    }

    validate_domains(tags, "N", &mut diagnostics);

    let web_tags = tag(tags, "web").collect::<Vec<_>>();
    if web_tags.is_empty() {
        diagnostics.push(Diagnostic::warning(
            "nip5d.shell.web",
            "NIP-89 shells should provide at least one `web` handler template",
        ));
    }
    for web in web_tags {
        validate_tag_shape(&mut diagnostics, "web", web, 2);
        let Some(template) = value(web, 1) else {
            continue;
        };
        if !template.starts_with("https://") || !template.contains("<bech32>") {
            diagnostics.push(Diagnostic::error(
                "nip5d.shell.web",
                "`web` must be an HTTPS template containing `<bech32>`",
            ));
        }
    }

    for tag in tags {
        if tag.first().is_none_or(String::is_empty) {
            diagnostics.push(Diagnostic::error(
                "nip5d.tag.name",
                "every tag must have a non-empty name",
            ));
        }
    }

    diagnostics
}

/// Whether a shell handler has no error-level diagnostics.
#[must_use]
pub fn shell_handler_is_valid(content: &str, tags: &[Tag]) -> bool {
    validate_shell_handler(content, tags)
        .iter()
        .all(|diagnostic| !diagnostic.is_error())
}

/// The first value of the first tag with `name`, if any.
#[must_use]
pub fn first_tag_value<'a>(tags: &'a [Tag], name: &str) -> Option<&'a str> {
    tags.iter()
        .find(|tag| tag.first().is_some_and(|value| value == name))
        .and_then(|tag| value(tag, 1))
}

fn domain_values(tags: &[Tag], name: &str) -> Vec<String> {
    let mut domains = Vec::new();
    for tag in tag(tags, name) {
        if let Some(domain) = value(tag, 1)
            && is_bare_domain(domain)
            && !domains.iter().any(|existing| existing == domain)
        {
            domains.push(domain.to_owned());
        }
    }
    domains
}

/// The NAP domains a manifest marks as required (`R` tags), in tag order.
#[must_use]
pub fn required_domains(tags: &[Tag]) -> Vec<String> {
    domain_values(tags, "R")
}

/// The NAP domains a manifest marks as optional (`O` tags), in tag order.
#[must_use]
pub fn optional_domains(tags: &[Tag]) -> Vec<String> {
    domain_values(tags, "O")
}

/// The NAP domains a shell can expose (`N` tags), in tag order.
#[must_use]
pub fn shell_domains(tags: &[Tag]) -> Vec<String> {
    domain_values(tags, "N")
}

/// The napplet manifest kinds a shell advertises in `k` tags.
#[must_use]
pub fn shell_manifest_kinds(tags: &[Tag]) -> Vec<u64> {
    let mut kinds = Vec::new();
    for tag in tag(tags, "k") {
        if let Some(raw) = value(tag, 1)
            && let Ok(kind) = raw.parse::<u64>()
            && ManifestKind::from_kind(kind).is_some()
            && !kinds.contains(&kind)
        {
            kinds.push(kind);
        }
    }
    kinds
}

/// Required domains absent from a shell's advertised set, in requirement order.
#[must_use]
pub fn missing_domains(required: &[String], available: &[String]) -> Vec<String> {
    required
        .iter()
        .filter(|domain| !available.iter().any(|candidate| candidate == *domain))
        .cloned()
        .collect()
}

/// Whether a shell advertises every NAP domain a manifest requires.
#[must_use]
pub fn compatible(manifest_tags: &[Tag], shell_tags: &[Tag]) -> bool {
    missing_domains(&required_domains(manifest_tags), &shell_domains(shell_tags)).is_empty()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tag(columns: &[&str]) -> Tag {
        columns.iter().map(|column| (*column).to_owned()).collect()
    }

    fn hash(byte: char) -> String {
        std::iter::repeat_n(byte, 64).collect()
    }

    fn manifest_tags() -> Vec<Tag> {
        vec![
            tag(&["d", "my-napplet"]),
            tag(&["x", &hash('a')]),
            tag(&["z", "feed"]),
            tag(&["i", "napplet:feed/open"]),
            tag(&["i", "napplet:feed/edit", "filters", "relays"]),
            tag(&["R", "relay"]),
            tag(&["O", "theme"]),
            tag(&["icon", &hash('b'), "image/png"]),
            tag(&["server", "https://blossom.example.com"]),
            tag(&["title", "My Napplet"]),
            tag(&["source", "https://github.com/example/my-napplet"]),
        ]
    }

    #[test]
    fn a_named_manifest_with_the_documented_tags_is_valid() {
        let tags = manifest_tags();
        let diagnostics = validate_manifest(NAMED_KIND, "A feed viewer and editor", &tags);
        assert!(
            diagnostics.iter().all(|diagnostic| !diagnostic.is_error()),
            "{diagnostics:?}"
        );
        assert_eq!(required_domains(&tags), ["relay"]);
        assert_eq!(optional_domains(&tags), ["theme"]);
    }

    #[test]
    fn missing_hash_identifier_and_description_are_rejected() {
        let tags = vec![tag(&["d", "my-napplet"])];
        let diagnostics = validate_manifest(NAMED_KIND, "", &tags);
        let codes = diagnostics
            .iter()
            .map(|diagnostic| diagnostic.code)
            .collect::<Vec<_>>();
        assert!(codes.contains(&"nip5d.x"));
        assert!(codes.contains(&"nip5d.content"));
    }

    #[test]
    fn identifiers_follow_the_manifest_kind() {
        let named = vec![tag(&["x", &hash('a')])];
        assert!(
            validate_manifest(NAMED_KIND, "description", &named)
                .iter()
                .any(|diagnostic| diagnostic.code == "nip5d.d")
        );
        let snapshot = vec![tag(&["d", "unexpected"]), tag(&["x", &hash('a')])];
        assert!(
            validate_manifest(SNAPSHOT_KIND, "description", &snapshot)
                .iter()
                .any(|diagnostic| diagnostic.code == "nip5d.d")
        );
    }

    #[test]
    fn hash_shape_is_lowercase_hex_and_exactly_one() {
        assert!(artifact_is_sha256(&hash('a')));
        assert!(!artifact_is_sha256(&hash('A')));
        assert!(!artifact_is_sha256("abc"));
        let tags = vec![tag(&["x", &hash('a')]), tag(&["x", &hash('b')])];
        assert!(
            validate_manifest(ROOT_KIND, "description", &tags)
                .iter()
                .any(|diagnostic| diagnostic.code == "nip5d.x")
        );
    }

    #[test]
    fn domains_must_be_bare_lowercase_names() {
        let tags = vec![
            tag(&["x", &hash('a')]),
            tag(&["R", "NAP-RELAY"]),
            tag(&["R", "relay@1"]),
            tag(&["O", "theme"]),
        ];
        let diagnostics = validate_manifest(ROOT_KIND, "description", &tags);
        assert_eq!(
            diagnostics
                .iter()
                .filter(|diagnostic| diagnostic.code == "nip5d.domain")
                .count(),
            2
        );
        assert_eq!(optional_domains(&tags), ["theme"]);
    }

    #[test]
    fn intents_are_queryless_and_parameters_are_preserved() {
        let tags = vec![
            tag(&["x", &hash('a')]),
            tag(&["i", "napplet:feed/open?bad=1"]),
            tag(&["i", "napplet:feed/edit", "", "relays"]),
            tag(&["i", "other:thing"]),
        ];
        let diagnostics = validate_manifest(ROOT_KIND, "description", &tags);
        assert!(
            diagnostics
                .iter()
                .any(|diagnostic| diagnostic.code == "nip5d.i")
        );
        assert!(
            diagnostics
                .iter()
                .any(|diagnostic| diagnostic.code == "nip5d.i.parameter")
        );
        assert!(
            diagnostics
                .iter()
                .any(|diagnostic| diagnostic.code == "nip5d.i.namespace")
        );
    }

    #[test]
    fn source_and_archive_rules_follow_the_nip() {
        let tags = vec![
            tag(&["x", &hash('a')]),
            tag(&["source", "https://github.com/example/napplet"]),
            tag(&["source-commit", &"c".repeat(40)]),
            tag(&[
                "source-archive",
                "https://example.com/a.tar.gz",
                &hash('d'),
                "application/gzip",
            ]),
        ];
        assert!(
            validate_manifest(ROOT_KIND, "description", &tags)
                .iter()
                .all(|diagnostic| !diagnostic.is_error())
        );
        assert!(
            validate_manifest(
                ROOT_KIND,
                "description",
                &[
                    tag(&["x", &hash('a')]),
                    tag(&["source", "file:///tmp/x"]),
                    tag(&[
                        "source-archive",
                        "https://user:pass@example.com/a.tar.gz",
                        &hash('d'),
                        "application/gzip"
                    ]),
                ],
            )
            .iter()
            .any(|diagnostic| diagnostic.code == "nip5d.source.location")
        );
    }

    #[test]
    fn snapshots_may_carry_lineage_tags_only() {
        let with_lineage = vec![
            tag(&["x", &hash('a')]),
            tag(&["a", &format!("35129:{}:parent", hash('b'))]),
            tag(&["A", &format!("15129:{}:", hash('c'))]),
        ];
        assert!(
            validate_manifest(SNAPSHOT_KIND, "description", &with_lineage)
                .iter()
                .all(|diagnostic| !diagnostic.is_error())
        );
        assert!(
            validate_manifest(ROOT_KIND, "description", &with_lineage)
                .iter()
                .any(|diagnostic| diagnostic.code == "nip5d.lineage")
        );
    }

    #[test]
    fn media_hash_cardinality_and_icon_mime_are_checked() {
        let tags = vec![
            tag(&["x", &hash('a')]),
            tag(&["icon", &hash('b'), "image/svg+xml"]),
            tag(&["screenshot", "m image/png", "dim 1200x750"]),
            tag(&["screenshot", &format!("x {}", hash('c')), "dim wide"]),
            tag(&["preview", &format!("x {}", hash('d'))]),
            tag(&["preview", &format!("x {}", hash('e'))]),
        ];
        let diagnostics = validate_manifest(ROOT_KIND, "description", &tags);
        assert!(
            diagnostics
                .iter()
                .any(|diagnostic| diagnostic.code == "nip5d.media.hash")
        );
        assert!(
            diagnostics
                .iter()
                .any(|diagnostic| diagnostic.code == "nip5d.icon.mime")
        );
        assert!(
            diagnostics
                .iter()
                .any(|diagnostic| diagnostic.code == "nip5d.preview.duplicate")
        );
    }

    #[test]
    fn shell_handlers_advertise_manifest_kinds_and_domains() {
        let tags = vec![
            tag(&["d", "my-shell"]),
            tag(&["k", "35129"]),
            tag(&["k", "5129"]),
            tag(&["N", "relay"]),
            tag(&["N", "storage"]),
            tag(&["web", "https://shell.example.com/<bech32>"]),
        ];
        let diagnostics = validate_shell_handler("A napplet shell", &tags);
        assert!(
            diagnostics.iter().all(|diagnostic| !diagnostic.is_error()),
            "{diagnostics:?}"
        );
        assert_eq!(shell_domains(&tags), ["relay", "storage"]);
        assert_eq!(shell_manifest_kinds(&tags), [35129, 5129]);
    }

    #[test]
    fn shell_handlers_reject_unknown_kinds_and_bad_domains() {
        let tags = vec![
            tag(&["d", "my-shell"]),
            tag(&["k", "1"]),
            tag(&["N", "NAP-RELAY"]),
        ];
        let diagnostics = validate_shell_handler("A napplet shell", &tags);
        assert!(
            diagnostics
                .iter()
                .any(|diagnostic| diagnostic.code == "nip5d.shell.k")
        );
        assert!(
            diagnostics
                .iter()
                .any(|diagnostic| diagnostic.code == "nip5d.domain")
        );
    }

    #[test]
    fn compatibility_reports_the_exact_missing_domains() {
        let manifest = vec![
            tag(&["x", &hash('a')]),
            tag(&["R", "relay"]),
            tag(&["R", "storage"]),
        ];
        let shell = vec![tag(&["N", "relay"])];
        assert_eq!(
            missing_domains(&required_domains(&manifest), &shell_domains(&shell)),
            ["storage"]
        );
        assert!(!compatible(&manifest, &shell));
    }

    #[test]
    fn evaluator_tag_text_is_parsed_back_into_columns() {
        assert_eq!(
            tag_from_text("R=relay"),
            vec!["R".to_owned(), "relay".to_owned()]
        );
        assert_eq!(
            tag_from_text("i=napplet:feed/edit\u{1f}filters\u{1f}relays"),
            vec![
                "i".to_owned(),
                "napplet:feed/edit".to_owned(),
                "filters".to_owned(),
                "relays".to_owned(),
            ]
        );
        assert_eq!(
            tags_from_text(["x", "R=relay"]),
            vec![
                vec!["x".to_owned()],
                vec!["R".to_owned(), "relay".to_owned()]
            ]
        );
    }
}
