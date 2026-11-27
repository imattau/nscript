//! NIP-34 git event construction.
//!
//! This crate builds the wire events NIP-34 defines — repository
//! announcements and state, patches, pull requests and their updates, issues,
//! status events, and the grasp list — as [`UnsignedEvent`] values that the
//! CLI signs and publishes.
//!
//! Git object transport is not part of NIP-34 and is not implemented here:
//! clone URLs point at ordinary git servers or grasp services.

use nscript_runtime::{TAG_COLUMN_SEPARATOR, UnsignedEvent};

/// Repository announcement.
pub const REPOSITORY_KIND: u16 = 30617;
/// Repository state announcement.
pub const REPOSITORY_STATE_KIND: u16 = 30618;
/// Patch.
pub const PATCH_KIND: u16 = 1617;
/// Pull request.
pub const PULL_REQUEST_KIND: u16 = 1618;
/// Pull request update.
pub const PULL_REQUEST_UPDATE_KIND: u16 = 1619;
/// Issue.
pub const ISSUE_KIND: u16 = 1621;
/// Open status.
pub const STATUS_OPEN_KIND: u16 = 1630;
/// Applied/merged status.
pub const STATUS_APPLIED_KIND: u16 = 1631;
/// Closed status.
pub const STATUS_CLOSED_KIND: u16 = 1632;
/// Draft status.
pub const STATUS_DRAFT_KIND: u16 = 1633;
/// User grasp list.
pub const GRASP_LIST_KIND: u16 = 10317;

/// A NIP-34 validation or construction failure.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Nip34Error {
    message: String,
}

impl Nip34Error {
    fn new(message: impl Into<String>) -> Self {
        Self {
            message: message.into(),
        }
    }

    /// The human-readable reason.
    #[must_use]
    pub fn message(&self) -> &str {
        &self.message
    }
}

impl std::fmt::Display for Nip34Error {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(&self.message)
    }
}

impl std::error::Error for Nip34Error {}

/// The four NIP-34 status kinds.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StatusKind {
    /// Kind `1630`.
    Open,
    /// Kind `1631`; also the merge and resolve status.
    Applied,
    /// Kind `1632`.
    Closed,
    /// Kind `1633`.
    Draft,
}

impl StatusKind {
    /// The wire kind.
    #[must_use]
    pub fn kind(self) -> u16 {
        match self {
            Self::Open => STATUS_OPEN_KIND,
            Self::Applied => STATUS_APPLIED_KIND,
            Self::Closed => STATUS_CLOSED_KIND,
            Self::Draft => STATUS_DRAFT_KIND,
        }
    }

    /// The canonical lowercase name.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Open => "open",
            Self::Applied => "applied",
            Self::Closed => "closed",
            Self::Draft => "draft",
        }
    }

    /// Parses the CLI spellings, including the issue and patch synonyms.
    ///
    /// # Errors
    ///
    /// Returns an error for any other value.
    pub fn parse(value: &str) -> Result<Self, Nip34Error> {
        match value.trim().to_ascii_lowercase().as_str() {
            "open" => Ok(Self::Open),
            "applied" | "merged" | "resolved" => Ok(Self::Applied),
            "closed" => Ok(Self::Closed),
            "draft" => Ok(Self::Draft),
            other => Err(Nip34Error::new(format!(
                "status must be open, applied, merged, resolved, closed, or draft, found `{other}`"
            ))),
        }
    }
}

/// A subordinate fork reference for the `u` tag.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct RepositoryFork {
    /// The fork's `30617:<pubkey>:<identifier>` address.
    pub address: String,
    /// The preferred HTTPS git URL of the fork.
    pub git_url: Option<String>,
    /// An optional relay hint.
    pub relay: Option<String>,
    /// An optional fork author pubkey.
    pub author: Option<String>,
}

/// A kind `30617` repository announcement.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct RepositoryAnnouncement {
    /// The `d` identifier, usually a kebab-case short name.
    pub identifier: String,
    /// The human-readable project name.
    pub name: Option<String>,
    /// A short project description.
    pub description: Option<String>,
    /// Web pages for browsing the repository.
    pub web: Vec<String>,
    /// URLs accepted by `git clone`.
    pub clone: Vec<String>,
    /// Relays monitored for patches and issues.
    pub relays: Vec<String>,
    /// The earliest unique commit, tagged with the `euc` marker.
    pub earliest_unique_commit: Option<String>,
    /// Other recognised maintainer pubkeys.
    pub maintainers: Vec<String>,
    /// Subordinate forks.
    pub forks: Vec<RepositoryFork>,
    /// Hashtags labelling the repository.
    pub topics: Vec<String>,
}

/// A kind `30618` repository state announcement.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct RepositoryState {
    /// The `d` identifier matching the repository announcement.
    pub identifier: String,
    /// `refs/heads/<name>` or `refs/tags/<name>` to commit id.
    pub refs: Vec<(String, String)>,
    /// The default branch, as `refs/heads/<name>`.
    pub head: Option<String>,
}

/// A git committer, stored as the multi-column `committer` tag.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Committer {
    /// Committer name.
    pub name: String,
    /// Committer email.
    pub email: String,
    /// Unix timestamp.
    pub timestamp: i64,
    /// Timezone offset in minutes.
    pub timezone_offset_minutes: i32,
}

/// A kind `1617` patch.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Patch {
    /// The `30617:<pubkey>:<identifier>` repository address.
    pub repository: String,
    /// The repository's earliest unique commit.
    pub earliest_unique_commit: Option<String>,
    /// Pubkeys to notify, including the repository owner.
    pub recipients: Vec<String>,
    /// The contents of `git format-patch`.
    pub content: String,
    /// Marks the first patch in a series with `t root`.
    pub root: bool,
    /// Marks the first patch in a revision with `t root-revision`.
    pub root_revision: bool,
    /// The current commit id.
    pub commit: Option<String>,
    /// The parent commit id.
    pub parent_commit: Option<String>,
    /// The commit's PGP signature, empty when unsigned.
    pub commit_pgp_sig: Option<String>,
    /// Committer details.
    pub committers: Vec<Committer>,
}

/// A kind `1618` pull request.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PullRequest {
    /// The repository address.
    pub repository: String,
    /// The repository's earliest unique commit.
    pub earliest_unique_commit: Option<String>,
    /// Pubkeys to notify.
    pub recipients: Vec<String>,
    /// The markdown body.
    pub content: String,
    /// The PR subject.
    pub subject: String,
    /// Optional labels.
    pub labels: Vec<String>,
    /// The tip of the PR branch.
    pub commit: String,
    /// Clone URLs where the commit can be fetched.
    pub clone: Vec<String>,
    /// A recommended branch name.
    pub branch_name: Option<String>,
    /// A root patch this PR revises.
    pub revision_of: Option<String>,
    /// The merge base with the target branch.
    pub merge_base: Option<String>,
}

/// A kind `1619` pull request update.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PullRequestUpdate {
    /// The repository address.
    pub repository: String,
    /// The repository's earliest unique commit.
    pub earliest_unique_commit: Option<String>,
    /// Pubkeys to notify.
    pub recipients: Vec<String>,
    /// The updated pull request event id.
    pub pull_request: String,
    /// The pull request author.
    pub pull_request_author: String,
    /// The markdown body.
    pub content: String,
    /// The updated tip commit.
    pub commit: String,
    /// Clone URLs where the commit can be fetched.
    pub clone: Vec<String>,
    /// The merge base with the target branch.
    pub merge_base: Option<String>,
}

/// A kind `1621` issue.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Issue {
    /// The repository address.
    pub repository: String,
    /// Pubkeys to notify, including the repository owner.
    pub recipients: Vec<String>,
    /// The markdown body.
    pub content: String,
    /// An optional issue subject.
    pub subject: Option<String>,
    /// Optional labels.
    pub labels: Vec<String>,
}

/// A kind `1630`–`1633` status event.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Status {
    /// Which status this is.
    pub kind: StatusKind,
    /// The repository address; NIP-34 makes it optional.
    pub repository: Option<String>,
    /// The repository's earliest unique commit.
    pub earliest_unique_commit: Option<String>,
    /// The root patch, pull request, or issue event id.
    pub root: String,
    /// An accepted revision event id.
    pub revision: Option<String>,
    /// Pubkeys to notify.
    pub recipients: Vec<String>,
    /// The markdown body.
    pub content: String,
    /// Applied or merged patch event ids; kind `1631` only.
    pub applied: Vec<String>,
    /// The merge commit id; kind `1631` only.
    pub merge_commit: Option<String>,
    /// Commits the patch was applied as; kind `1631` only.
    pub applied_as_commits: Vec<String>,
}

/// A kind `10317` grasp list.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct GraspList {
    /// Grasp service websocket URLs, in preference order.
    pub servers: Vec<String>,
}

fn join_columns(columns: &[String]) -> String {
    columns.join(&TAG_COLUMN_SEPARATOR.to_string())
}

fn tag(name: &str, value: impl Into<String>) -> (String, String) {
    (name.to_owned(), value.into())
}

fn check_text(field: &str, value: &str) -> Result<(), Nip34Error> {
    if value.contains(TAG_COLUMN_SEPARATOR) {
        return Err(Nip34Error::new(format!(
            "{field} cannot contain the tag column separator"
        )));
    }
    Ok(())
}

/// Validates a lowercase 64-character event id or pubkey.
///
/// # Errors
///
/// Returns an error for any other shape.
pub fn validate_pubkey(field: &str, value: &str) -> Result<(), Nip34Error> {
    if value.len() != 64
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err(Nip34Error::new(format!(
            "{field} must be 64 lowercase hexadecimal characters"
        )));
    }
    Ok(())
}

/// Validates a git commit id: 40 hex characters (SHA-1) or 64 (SHA-256).
///
/// # Errors
///
/// Returns an error for any other shape.
pub fn validate_commit(field: &str, value: &str) -> Result<(), Nip34Error> {
    if (value.len() != 40 && value.len() != 64)
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err(Nip34Error::new(format!(
            "{field} must be a 40- or 64-character lowercase hexadecimal commit id"
        )));
    }
    Ok(())
}

/// Validates a repository identifier.
///
/// # Errors
///
/// Returns an error when the identifier is empty or contains whitespace.
pub fn validate_identifier(value: &str) -> Result<(), Nip34Error> {
    check_text("identifier", value)?;
    if value.is_empty() {
        return Err(Nip34Error::new("identifier must not be empty"));
    }
    if value.chars().any(char::is_whitespace) {
        return Err(Nip34Error::new("identifier must not contain whitespace"));
    }
    Ok(())
}

/// Parses a `30617:<pubkey>:<identifier>` repository address.
///
/// # Errors
///
/// Returns an error when the kind, pubkey, or identifier is invalid.
pub fn parse_repository_address(value: &str) -> Result<(String, String), Nip34Error> {
    let mut parts = value.splitn(3, ':');
    let kind = parts.next().unwrap_or_default();
    let author = parts.next().unwrap_or_default();
    let identifier = parts.next().unwrap_or_default();
    if kind != "30617" || author.is_empty() || identifier.is_empty() {
        return Err(Nip34Error::new(
            "repository address must be `30617:<pubkey>:<identifier>`",
        ));
    }
    validate_pubkey("repository address pubkey", author)?;
    validate_identifier(identifier)?;
    Ok((author.to_owned(), identifier.to_owned()))
}

/// Builds a `30617:<pubkey>:<identifier>` address.
///
/// # Errors
///
/// Returns an error when the pubkey or identifier is invalid.
pub fn repository_address(author: &str, identifier: &str) -> Result<String, Nip34Error> {
    validate_pubkey("repository address pubkey", author)?;
    validate_identifier(identifier)?;
    Ok(format!("30617:{author}:{identifier}"))
}

fn check_repository(field: &str, value: &str) -> Result<(), Nip34Error> {
    parse_repository_address(value)
        .map(|_| ())
        .map_err(|error| Nip34Error::new(format!("{field}: {}", error.message())))
}

fn check_relay(value: &str) -> Result<(), Nip34Error> {
    check_text("relay", value)?;
    if !(value.starts_with("wss://") || value.starts_with("ws://")) {
        return Err(Nip34Error::new(format!(
            "relay `{value}` must be a ws:// or wss:// URL"
        )));
    }
    Ok(())
}

fn check_url(field: &str, value: &str) -> Result<(), Nip34Error> {
    check_text(field, value)?;
    if value.is_empty() || value.chars().any(char::is_whitespace) {
        return Err(Nip34Error::new(format!(
            "{field} must be a non-empty URL without whitespace"
        )));
    }
    Ok(())
}

fn check_optional_text(field: &str, value: Option<&String>) -> Result<(), Nip34Error> {
    if let Some(value) = value {
        check_text(field, value)?;
    }
    Ok(())
}

fn push_many(tags: &mut Vec<(String, String)>, name: &str, values: &[String]) {
    for value in values {
        tags.push(tag(name, value.clone()));
    }
}

/// Builds the kind `30617` repository announcement.
///
/// # Errors
///
/// Returns an error when the identifier, URLs, relays, or pubkeys are invalid.
pub fn build_repository_announcement(
    announcement: &RepositoryAnnouncement,
    created_at: u64,
) -> Result<UnsignedEvent, Nip34Error> {
    validate_identifier(&announcement.identifier)?;
    check_optional_text("name", announcement.name.as_ref())?;
    check_optional_text("description", announcement.description.as_ref())?;
    for url in announcement.web.iter().chain(&announcement.clone) {
        check_url("repository URL", url)?;
    }
    for relay in &announcement.relays {
        check_relay(relay)?;
    }
    for maintainer in &announcement.maintainers {
        validate_pubkey("maintainer", maintainer)?;
    }
    for topic in &announcement.topics {
        check_text("topic", topic)?;
    }
    if let Some(commit) = &announcement.earliest_unique_commit {
        validate_commit("earliest unique commit", commit)?;
    }

    let mut tags = vec![tag("d", announcement.identifier.clone())];
    if let Some(name) = &announcement.name {
        tags.push(tag("name", name.clone()));
    }
    if let Some(description) = &announcement.description {
        tags.push(tag("description", description.clone()));
    }
    push_many(&mut tags, "web", &announcement.web);
    push_many(&mut tags, "clone", &announcement.clone);
    push_many(&mut tags, "relays", &announcement.relays);
    if let Some(commit) = &announcement.earliest_unique_commit {
        tags.push((
            "r".to_owned(),
            join_columns(&[commit.clone(), "euc".to_owned()]),
        ));
    }
    push_many(&mut tags, "maintainers", &announcement.maintainers);
    for fork in &announcement.forks {
        let (address, _) = parse_repository_address(&fork.address)?;
        let mut columns = vec![match &fork.git_url {
            Some(url) => {
                check_url("fork git URL", url)?;
                format!("{}|{url}", fork.address)
            }
            None => fork.address.clone(),
        }];
        if let Some(relay) = &fork.relay {
            check_relay(relay)?;
            columns.push(relay.clone());
        } else if fork.author.is_some() {
            columns.push(String::new());
        }
        if let Some(author) = &fork.author {
            validate_pubkey("fork author", author)?;
            columns.push(author.clone());
        }
        let _ = address;
        tags.push(("u".to_owned(), join_columns(&columns)));
    }
    push_many(&mut tags, "t", &announcement.topics);

    Ok(UnsignedEvent {
        event_type: "RepositoryAnnouncement".to_owned(),
        kind: REPOSITORY_KIND,
        content: String::new(),
        tags,
        created_at,
    })
}

/// Builds the kind `30618` repository state announcement.
///
/// # Errors
///
/// Returns an error for an invalid identifier, ref name, commit id, or HEAD.
pub fn build_repository_state(
    state: &RepositoryState,
    created_at: u64,
) -> Result<UnsignedEvent, Nip34Error> {
    validate_identifier(&state.identifier)?;
    let mut seen = std::collections::BTreeSet::new();
    for (name, commit) in &state.refs {
        let valid = name.starts_with("refs/heads/") || name.starts_with("refs/tags/");
        if !valid || name.len() <= "refs/heads/".len() {
            return Err(Nip34Error::new(format!(
                "ref `{name}` must be refs/heads/<name> or refs/tags/<name>"
            )));
        }
        check_text("ref name", name)?;
        validate_commit("ref commit", commit)?;
        if !seen.insert(name.clone()) {
            return Err(Nip34Error::new(format!("duplicate ref `{name}`")));
        }
    }
    if let Some(head) = &state.head {
        check_text("HEAD", head)?;
        if !head.starts_with("refs/heads/") || head.len() <= "refs/heads/".len() {
            return Err(Nip34Error::new("HEAD must be `refs/heads/<branch-name>`"));
        }
    }

    let mut tags = vec![tag("d", state.identifier.clone())];
    push_many(
        &mut tags,
        "refs",
        &state
            .refs
            .iter()
            .map(|(name, commit)| join_columns(&[name.clone(), commit.clone()]))
            .collect::<Vec<_>>(),
    );
    if let Some(head) = &state.head {
        tags.push(("HEAD".to_owned(), format!("ref: {head}")));
    }

    Ok(UnsignedEvent {
        event_type: "RepositoryState".to_owned(),
        kind: REPOSITORY_STATE_KIND,
        content: String::new(),
        tags,
        created_at,
    })
}

/// Builds the kind `1617` patch.
///
/// # Errors
///
/// Returns an error when the repository, content, ids, or committers are invalid.
pub fn build_patch(patch: &Patch, created_at: u64) -> Result<UnsignedEvent, Nip34Error> {
    check_repository("repository", &patch.repository)?;
    if patch.content.is_empty() {
        return Err(Nip34Error::new("patch content must not be empty"));
    }
    if let Some(commit) = &patch.earliest_unique_commit {
        validate_commit("earliest unique commit", commit)?;
    }
    for recipient in &patch.recipients {
        validate_pubkey("patch recipient", recipient)?;
    }
    for commit in patch.commit.iter().chain(&patch.parent_commit) {
        validate_commit("patch commit", commit)?;
    }
    check_optional_text("commit PGP signature", patch.commit_pgp_sig.as_ref())?;
    for committer in &patch.committers {
        check_text("committer name", &committer.name)?;
        check_text("committer email", &committer.email)?;
        if committer.name.is_empty() || committer.email.is_empty() {
            return Err(Nip34Error::new(
                "a committer needs a non-empty name and email",
            ));
        }
        if !(-1440..=1440).contains(&committer.timezone_offset_minutes) {
            return Err(Nip34Error::new(
                "a committer timezone offset must be between -1440 and 1440 minutes",
            ));
        }
    }

    let mut tags = vec![tag("a", patch.repository.clone())];
    if let Some(commit) = &patch.earliest_unique_commit {
        tags.push(("r".to_owned(), commit.clone()));
    }
    push_many(&mut tags, "p", &patch.recipients);
    if patch.root {
        tags.push(tag("t", "root"));
    }
    if patch.root_revision {
        tags.push(tag("t", "root-revision"));
    }
    if let Some(commit) = &patch.commit {
        tags.push(("commit".to_owned(), commit.clone()));
        tags.push(("r".to_owned(), commit.clone()));
    }
    if let Some(parent) = &patch.parent_commit {
        tags.push(("parent-commit".to_owned(), parent.clone()));
    }
    if let Some(signature) = &patch.commit_pgp_sig {
        tags.push(("commit-pgp-sig".to_owned(), signature.clone()));
    }
    for committer in &patch.committers {
        tags.push((
            "committer".to_owned(),
            join_columns(&[
                committer.name.clone(),
                committer.email.clone(),
                committer.timestamp.to_string(),
                committer.timezone_offset_minutes.to_string(),
            ]),
        ));
    }

    Ok(UnsignedEvent {
        event_type: "Patch".to_owned(),
        kind: PATCH_KIND,
        content: patch.content.clone(),
        tags,
        created_at,
    })
}

/// Builds the kind `1618` pull request.
///
/// # Errors
///
/// Returns an error when required fields are missing or malformed.
pub fn build_pull_request(
    pull_request: &PullRequest,
    created_at: u64,
) -> Result<UnsignedEvent, Nip34Error> {
    check_repository("repository", &pull_request.repository)?;
    if pull_request.subject.is_empty() {
        return Err(Nip34Error::new("a pull request needs a subject"));
    }
    check_text("subject", &pull_request.subject)?;
    if let Some(commit) = &pull_request.earliest_unique_commit {
        validate_commit("earliest unique commit", commit)?;
    }
    for recipient in &pull_request.recipients {
        validate_pubkey("pull request recipient", recipient)?;
    }
    for label in &pull_request.labels {
        check_text("label", label)?;
    }
    validate_commit("pull request commit", &pull_request.commit)?;
    if pull_request.clone.is_empty() {
        return Err(Nip34Error::new(
            "a pull request needs at least one clone URL",
        ));
    }
    for url in &pull_request.clone {
        check_url("clone URL", url)?;
    }
    check_optional_text("branch name", pull_request.branch_name.as_ref())?;
    if let Some(revision) = &pull_request.revision_of {
        validate_pubkey("revised event id", revision)?;
    }
    if let Some(merge_base) = &pull_request.merge_base {
        validate_commit("merge base", merge_base)?;
    }

    let mut tags = vec![tag("a", pull_request.repository.clone())];
    if let Some(commit) = &pull_request.earliest_unique_commit {
        tags.push(("r".to_owned(), commit.clone()));
    }
    push_many(&mut tags, "p", &pull_request.recipients);
    tags.push(tag("subject", pull_request.subject.clone()));
    push_many(&mut tags, "t", &pull_request.labels);
    tags.push(tag("c", pull_request.commit.clone()));
    push_many(&mut tags, "clone", &pull_request.clone);
    if let Some(branch) = &pull_request.branch_name {
        tags.push(tag("branch-name", branch.clone()));
    }
    if let Some(revision) = &pull_request.revision_of {
        tags.push(tag("e", revision.clone()));
    }
    if let Some(merge_base) = &pull_request.merge_base {
        tags.push(tag("merge-base", merge_base.clone()));
    }

    Ok(UnsignedEvent {
        event_type: "PullRequest".to_owned(),
        kind: PULL_REQUEST_KIND,
        content: pull_request.content.clone(),
        tags,
        created_at,
    })
}

/// Builds the kind `1619` pull request update.
///
/// # Errors
///
/// Returns an error when required fields are missing or malformed.
pub fn build_pull_request_update(
    update: &PullRequestUpdate,
    created_at: u64,
) -> Result<UnsignedEvent, Nip34Error> {
    check_repository("repository", &update.repository)?;
    if let Some(commit) = &update.earliest_unique_commit {
        validate_commit("earliest unique commit", commit)?;
    }
    for recipient in &update.recipients {
        validate_pubkey("pull request update recipient", recipient)?;
    }
    validate_pubkey("pull request event id", &update.pull_request)?;
    validate_pubkey("pull request author", &update.pull_request_author)?;
    validate_commit("pull request update commit", &update.commit)?;
    if update.clone.is_empty() {
        return Err(Nip34Error::new(
            "a pull request update needs at least one clone URL",
        ));
    }
    for url in &update.clone {
        check_url("clone URL", url)?;
    }
    if let Some(merge_base) = &update.merge_base {
        validate_commit("merge base", merge_base)?;
    }

    let mut tags = vec![tag("a", update.repository.clone())];
    if let Some(commit) = &update.earliest_unique_commit {
        tags.push(("r".to_owned(), commit.clone()));
    }
    push_many(&mut tags, "p", &update.recipients);
    tags.push(tag("E", update.pull_request.clone()));
    tags.push(tag("P", update.pull_request_author.clone()));
    tags.push(tag("c", update.commit.clone()));
    push_many(&mut tags, "clone", &update.clone);
    if let Some(merge_base) = &update.merge_base {
        tags.push(tag("merge-base", merge_base.clone()));
    }

    Ok(UnsignedEvent {
        event_type: "PullRequestUpdate".to_owned(),
        kind: PULL_REQUEST_UPDATE_KIND,
        content: update.content.clone(),
        tags,
        created_at,
    })
}

/// Builds the kind `1621` issue.
///
/// # Errors
///
/// Returns an error when the repository, recipients, or subject are invalid.
pub fn build_issue(issue: &Issue, created_at: u64) -> Result<UnsignedEvent, Nip34Error> {
    check_repository("repository", &issue.repository)?;
    for recipient in &issue.recipients {
        validate_pubkey("issue recipient", recipient)?;
    }
    check_optional_text("subject", issue.subject.as_ref())?;
    for label in &issue.labels {
        check_text("label", label)?;
    }
    if issue.content.is_empty() && issue.subject.is_none() {
        return Err(Nip34Error::new("an issue needs content or a subject"));
    }

    let mut tags = vec![tag("a", issue.repository.clone())];
    push_many(&mut tags, "p", &issue.recipients);
    if let Some(subject) = &issue.subject {
        tags.push(tag("subject", subject.clone()));
    }
    push_many(&mut tags, "t", &issue.labels);

    Ok(UnsignedEvent {
        event_type: "Issue".to_owned(),
        kind: ISSUE_KIND,
        content: issue.content.clone(),
        tags,
        created_at,
    })
}

/// Builds a kind `1630`–`1633` status event.
///
/// # Errors
///
/// Returns an error for invalid ids or for merge fields on a non-applied status.
pub fn build_status(status: &Status, created_at: u64) -> Result<UnsignedEvent, Nip34Error> {
    if let Some(repository) = &status.repository {
        check_repository("repository", repository)?;
    }
    if let Some(commit) = &status.earliest_unique_commit {
        validate_commit("earliest unique commit", commit)?;
    }
    validate_pubkey("root event id", &status.root)?;
    if let Some(revision) = &status.revision {
        validate_pubkey("revision event id", revision)?;
    }
    for recipient in &status.recipients {
        validate_pubkey("status recipient", recipient)?;
    }
    for event_id in &status.applied {
        validate_pubkey("applied event id", event_id)?;
    }
    if let Some(commit) = &status.merge_commit {
        validate_commit("merge commit", commit)?;
    }
    for commit in &status.applied_as_commits {
        validate_commit("applied commit", commit)?;
    }
    if status.kind != StatusKind::Applied
        && (status.merge_commit.is_some()
            || !status.applied_as_commits.is_empty()
            || !status.applied.is_empty())
    {
        return Err(Nip34Error::new(
            "merge and applied fields belong only to an applied (1631) status",
        ));
    }

    let mut tags = vec![(
        "e".to_owned(),
        join_columns(&[status.root.clone(), String::new(), "root".to_owned()]),
    )];
    if let Some(revision) = &status.revision {
        tags.push((
            "e".to_owned(),
            join_columns(&[revision.clone(), String::new(), "reply".to_owned()]),
        ));
    }
    if let Some(repository) = &status.repository {
        tags.push(tag("a", repository.clone()));
    }
    push_many(&mut tags, "p", &status.recipients);
    if let Some(commit) = &status.earliest_unique_commit {
        tags.push(("r".to_owned(), commit.clone()));
    }
    for event_id in &status.applied {
        tags.push((
            "q".to_owned(),
            join_columns(&[event_id.clone(), String::new(), String::new()]),
        ));
    }
    if let Some(commit) = &status.merge_commit {
        tags.push(("merge-commit".to_owned(), commit.clone()));
        tags.push(("r".to_owned(), commit.clone()));
    }
    for commit in &status.applied_as_commits {
        tags.push(("applied-as-commits".to_owned(), commit.clone()));
        tags.push(("r".to_owned(), commit.clone()));
    }

    Ok(UnsignedEvent {
        event_type: "Status".to_owned(),
        kind: status.kind.kind(),
        content: status.content.clone(),
        tags,
        created_at,
    })
}

/// Builds the kind `10317` grasp list.
///
/// # Errors
///
/// Returns an error for a non-websocket or duplicated server URL.
pub fn build_grasp_list(list: &GraspList, created_at: u64) -> Result<UnsignedEvent, Nip34Error> {
    let mut seen = std::collections::BTreeSet::new();
    for server in &list.servers {
        check_relay(server)?;
        if !seen.insert(server) {
            return Err(Nip34Error::new(format!(
                "duplicate grasp server `{server}`"
            )));
        }
    }
    if list.servers.is_empty() {
        return Err(Nip34Error::new(
            "a grasp list needs at least one server URL",
        ));
    }

    let mut tags = Vec::new();
    push_many(&mut tags, "g", &list.servers);

    Ok(UnsignedEvent {
        event_type: "GraspList".to_owned(),
        kind: GRASP_LIST_KIND,
        content: String::new(),
        tags,
        created_at,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hex(value: char) -> String {
        std::iter::repeat_n(value, 64).collect()
    }

    fn commit(value: char) -> String {
        std::iter::repeat_n(value, 40).collect()
    }

    fn columns(parts: &[&str]) -> String {
        parts.join(&TAG_COLUMN_SEPARATOR.to_string())
    }

    #[test]
    fn status_kind_mapping_and_synonyms() {
        assert_eq!(StatusKind::parse("open").unwrap().kind(), 1630);
        assert_eq!(StatusKind::parse("applied").unwrap().kind(), 1631);
        assert_eq!(StatusKind::parse("merged").unwrap().kind(), 1631);
        assert_eq!(StatusKind::parse("resolved").unwrap().kind(), 1631);
        assert_eq!(StatusKind::parse("closed").unwrap().kind(), 1632);
        assert_eq!(StatusKind::parse("draft").unwrap().kind(), 1633);
        assert!(StatusKind::parse("wontfix").is_err());
    }

    #[test]
    fn repository_address_round_trips() {
        let author = hex('a');
        let address = repository_address(&author, "nscript").unwrap();
        assert_eq!(address, format!("30617:{author}:nscript"));
        assert_eq!(
            parse_repository_address(&address).unwrap(),
            (author.clone(), "nscript".to_owned())
        );
        assert!(parse_repository_address("30618:aa:nscript").is_err());
        assert!(parse_repository_address(&format!("30617:{author}:")).is_err());
    }

    #[test]
    fn builds_the_announcement_in_wire_order() {
        let author = hex('a');
        let announcement = RepositoryAnnouncement {
            identifier: "nscript".to_owned(),
            name: Some("NScript".to_owned()),
            description: Some("A scripting language for Nostr".to_owned()),
            web: vec!["https://example.com/nscript".to_owned()],
            clone: vec!["https://example.com/nscript.git".to_owned()],
            relays: vec!["wss://relay.example.com".to_owned()],
            earliest_unique_commit: Some(commit('b')),
            maintainers: vec![author.clone()],
            forks: vec![RepositoryFork {
                address: format!("30617:{author}:upstream"),
                git_url: Some("https://example.com/upstream.git".to_owned()),
                relay: Some("wss://relay.example.com".to_owned()),
                author: Some(author.clone()),
            }],
            topics: vec!["nostr".to_owned()],
        };
        let event = build_repository_announcement(&announcement, 1_700_000_000).unwrap();
        assert_eq!(event.kind, REPOSITORY_KIND);
        assert_eq!(event.event_type, "RepositoryAnnouncement");
        assert_eq!(event.content, "");
        assert_eq!(
            event.tags,
            vec![
                ("d".to_owned(), "nscript".to_owned()),
                ("name".to_owned(), "NScript".to_owned()),
                (
                    "description".to_owned(),
                    "A scripting language for Nostr".to_owned()
                ),
                ("web".to_owned(), "https://example.com/nscript".to_owned()),
                (
                    "clone".to_owned(),
                    "https://example.com/nscript.git".to_owned()
                ),
                ("relays".to_owned(), "wss://relay.example.com".to_owned()),
                ("r".to_owned(), columns(&[&commit('b'), "euc"])),
                ("maintainers".to_owned(), author.clone()),
                (
                    "u".to_owned(),
                    columns(&[
                        &format!("30617:{author}:upstream|https://example.com/upstream.git"),
                        "wss://relay.example.com",
                        &author,
                    ])
                ),
                ("t".to_owned(), "nostr".to_owned()),
            ]
        );
    }

    #[test]
    fn announcement_rejects_bad_input() {
        let mut announcement = RepositoryAnnouncement {
            identifier: "nscript".to_owned(),
            ..RepositoryAnnouncement::default()
        };
        assert!(build_repository_announcement(&announcement, 1).is_ok());

        announcement.identifier = "not a slug".to_owned();
        assert!(build_repository_announcement(&announcement, 1).is_err());

        announcement.identifier = "nscript".to_owned();
        announcement.relays = vec!["https://relay.example.com".to_owned()];
        assert!(build_repository_announcement(&announcement, 1).is_err());

        announcement.relays.clear();
        announcement.maintainers = vec!["abc".to_owned()];
        assert!(build_repository_announcement(&announcement, 1).is_err());
    }

    #[test]
    fn builds_repository_state_with_refs_and_head() {
        let state = RepositoryState {
            identifier: "nscript".to_owned(),
            refs: vec![
                ("refs/heads/main".to_owned(), commit('a')),
                ("refs/tags/v1".to_owned(), commit('b')),
            ],
            head: Some("refs/heads/main".to_owned()),
        };
        let event = build_repository_state(&state, 1).unwrap();
        assert_eq!(event.kind, REPOSITORY_STATE_KIND);
        assert_eq!(
            event.tags,
            vec![
                ("d".to_owned(), "nscript".to_owned()),
                (
                    "refs".to_owned(),
                    columns(&["refs/heads/main", &commit('a')])
                ),
                ("refs".to_owned(), columns(&["refs/tags/v1", &commit('b')])),
                ("HEAD".to_owned(), "ref: refs/heads/main".to_owned()),
            ]
        );
    }

    #[test]
    fn repository_state_rejects_bad_refs() {
        let base = RepositoryState {
            identifier: "nscript".to_owned(),
            refs: vec![("refs/heads/main".to_owned(), commit('a'))],
            head: None,
        };
        assert!(build_repository_state(&base, 1).is_ok());

        assert!(
            build_repository_state(
                &RepositoryState {
                    refs: vec![("main".to_owned(), commit('a'))],
                    ..base.clone()
                },
                1
            )
            .is_err()
        );
        assert!(
            build_repository_state(
                &RepositoryState {
                    refs: vec![
                        ("refs/heads/main".to_owned(), commit('a')),
                        ("refs/heads/main".to_owned(), commit('b')),
                    ],
                    ..base.clone()
                },
                1
            )
            .is_err()
        );
        assert!(
            build_repository_state(
                &RepositoryState {
                    refs: vec![("refs/heads/main".to_owned(), "xyz".to_owned())],
                    ..base.clone()
                },
                1
            )
            .is_err()
        );
        assert!(
            build_repository_state(
                &RepositoryState {
                    head: Some("main".to_owned()),
                    ..base
                },
                1
            )
            .is_err()
        );
    }

    #[test]
    fn builds_a_patch_with_commit_metadata() {
        let patch = Patch {
            repository: format!("30617:{}:nscript", hex('a')),
            earliest_unique_commit: Some(commit('b')),
            recipients: vec![hex('a')],
            content: "From abc Mon Sep 17 00:00:00 2001\n".to_owned(),
            root: true,
            root_revision: true,
            commit: Some(commit('c')),
            parent_commit: Some(commit('d')),
            commit_pgp_sig: Some(String::new()),
            committers: vec![Committer {
                name: "Ada".to_owned(),
                email: "ada@example.com".to_owned(),
                timestamp: 1_700_000_000,
                timezone_offset_minutes: -300,
            }],
        };
        let event = build_patch(&patch, 1).unwrap();
        assert_eq!(event.kind, PATCH_KIND);
        assert_eq!(
            event.tags,
            vec![
                ("a".to_owned(), patch.repository.clone()),
                ("r".to_owned(), commit('b')),
                ("p".to_owned(), hex('a')),
                ("t".to_owned(), "root".to_owned()),
                ("t".to_owned(), "root-revision".to_owned()),
                ("commit".to_owned(), commit('c')),
                ("r".to_owned(), commit('c')),
                ("parent-commit".to_owned(), commit('d')),
                ("commit-pgp-sig".to_owned(), String::new()),
                (
                    "committer".to_owned(),
                    columns(&["Ada", "ada@example.com", "1700000000", "-300"])
                ),
            ]
        );
        assert_eq!(event.content, patch.content);
    }

    #[test]
    fn patch_requires_content() {
        let patch = Patch {
            repository: format!("30617:{}:nscript", hex('a')),
            earliest_unique_commit: None,
            recipients: Vec::new(),
            content: String::new(),
            root: false,
            root_revision: false,
            commit: None,
            parent_commit: None,
            commit_pgp_sig: None,
            committers: Vec::new(),
        };
        assert!(build_patch(&patch, 1).is_err());
    }

    #[test]
    fn builds_a_pull_request() {
        let author = hex('a');
        let pull_request = PullRequest {
            repository: format!("30617:{author}:nscript"),
            earliest_unique_commit: Some(commit('b')),
            recipients: vec![author.clone()],
            content: "Please review.".to_owned(),
            subject: "Add NIP-34".to_owned(),
            labels: vec!["enhancement".to_owned()],
            commit: commit('c'),
            clone: vec!["https://example.com/nscript.git".to_owned()],
            branch_name: Some("nip34".to_owned()),
            revision_of: Some(hex('d')),
            merge_base: Some(commit('e')),
        };
        let event = build_pull_request(&pull_request, 1).unwrap();
        assert_eq!(event.kind, PULL_REQUEST_KIND);
        assert_eq!(
            event.tags,
            vec![
                ("a".to_owned(), pull_request.repository.clone()),
                ("r".to_owned(), commit('b')),
                ("p".to_owned(), author),
                ("subject".to_owned(), "Add NIP-34".to_owned()),
                ("t".to_owned(), "enhancement".to_owned()),
                ("c".to_owned(), commit('c')),
                (
                    "clone".to_owned(),
                    "https://example.com/nscript.git".to_owned()
                ),
                ("branch-name".to_owned(), "nip34".to_owned()),
                ("e".to_owned(), hex('d')),
                ("merge-base".to_owned(), commit('e')),
            ]
        );
    }

    #[test]
    fn pull_request_requires_a_clone_url() {
        let pull_request = PullRequest {
            repository: format!("30617:{}:nscript", hex('a')),
            earliest_unique_commit: None,
            recipients: Vec::new(),
            content: String::new(),
            subject: "Subject".to_owned(),
            labels: Vec::new(),
            commit: commit('c'),
            clone: Vec::new(),
            branch_name: None,
            revision_of: None,
            merge_base: None,
        };
        assert!(build_pull_request(&pull_request, 1).is_err());
    }

    #[test]
    fn builds_a_pull_request_update() {
        let update = PullRequestUpdate {
            repository: format!("30617:{}:nscript", hex('a')),
            earliest_unique_commit: None,
            recipients: vec![hex('a')],
            pull_request: hex('b'),
            pull_request_author: hex('c'),
            content: "Rebased.".to_owned(),
            commit: commit('d'),
            clone: vec!["https://example.com/nscript.git".to_owned()],
            merge_base: None,
        };
        let event = build_pull_request_update(&update, 1).unwrap();
        assert_eq!(event.kind, PULL_REQUEST_UPDATE_KIND);
        assert_eq!(
            event.tags,
            vec![
                ("a".to_owned(), update.repository.clone()),
                ("p".to_owned(), hex('a')),
                ("E".to_owned(), hex('b')),
                ("P".to_owned(), hex('c')),
                ("c".to_owned(), commit('d')),
                (
                    "clone".to_owned(),
                    "https://example.com/nscript.git".to_owned()
                ),
            ]
        );
    }

    #[test]
    fn builds_an_issue() {
        let issue = Issue {
            repository: format!("30617:{}:nscript", hex('a')),
            recipients: vec![hex('a')],
            content: "It crashes.".to_owned(),
            subject: Some("Crash".to_owned()),
            labels: vec!["bug".to_owned()],
        };
        let event = build_issue(&issue, 1).unwrap();
        assert_eq!(event.kind, ISSUE_KIND);
        assert_eq!(
            event.tags,
            vec![
                ("a".to_owned(), issue.repository.clone()),
                ("p".to_owned(), hex('a')),
                ("subject".to_owned(), "Crash".to_owned()),
                ("t".to_owned(), "bug".to_owned()),
            ]
        );
    }

    #[test]
    fn builds_a_status_with_root_markers() {
        let status = Status {
            kind: StatusKind::Applied,
            repository: Some(format!("30617:{}:nscript", hex('a'))),
            earliest_unique_commit: Some(commit('b')),
            root: hex('c'),
            revision: Some(hex('d')),
            recipients: vec![hex('a')],
            content: "Merged.".to_owned(),
            applied: vec![hex('d')],
            merge_commit: Some(commit('e')),
            applied_as_commits: vec![commit('f')],
        };
        let event = build_status(&status, 1).unwrap();
        assert_eq!(event.kind, STATUS_APPLIED_KIND);
        assert_eq!(
            event.tags,
            vec![
                ("e".to_owned(), columns(&[&hex('c'), "", "root"])),
                ("e".to_owned(), columns(&[&hex('d'), "", "reply"])),
                ("a".to_owned(), format!("30617:{}:nscript", hex('a'))),
                ("p".to_owned(), hex('a')),
                ("r".to_owned(), commit('b')),
                ("q".to_owned(), columns(&[&hex('d'), "", ""])),
                ("merge-commit".to_owned(), commit('e')),
                ("r".to_owned(), commit('e')),
                ("applied-as-commits".to_owned(), commit('f')),
                ("r".to_owned(), commit('f')),
            ]
        );
    }

    #[test]
    fn merge_fields_are_only_for_applied_status() {
        let status = Status {
            kind: StatusKind::Closed,
            repository: None,
            earliest_unique_commit: None,
            root: hex('c'),
            revision: None,
            recipients: Vec::new(),
            content: String::new(),
            applied: Vec::new(),
            merge_commit: Some(commit('e')),
            applied_as_commits: Vec::new(),
        };
        assert!(build_status(&status, 1).is_err());
    }

    #[test]
    fn builds_a_grasp_list() {
        let list = GraspList {
            servers: vec![
                "wss://relay.ngit.dev".to_owned(),
                "wss://git.shakespeare.diy".to_owned(),
            ],
        };
        let event = build_grasp_list(&list, 1).unwrap();
        assert_eq!(event.kind, GRASP_LIST_KIND);
        assert_eq!(
            event.tags,
            vec![
                ("g".to_owned(), "wss://relay.ngit.dev".to_owned()),
                ("g".to_owned(), "wss://git.shakespeare.diy".to_owned()),
            ]
        );
    }

    #[test]
    fn grasp_list_rejects_duplicates_and_bad_urls() {
        assert!(
            build_grasp_list(
                &GraspList {
                    servers: vec![
                        "wss://relay.ngit.dev".to_owned(),
                        "wss://relay.ngit.dev".to_owned()
                    ],
                },
                1
            )
            .is_err()
        );
        assert!(
            build_grasp_list(
                &GraspList {
                    servers: vec!["https://relay.ngit.dev".to_owned()],
                },
                1
            )
            .is_err()
        );
        assert!(build_grasp_list(&GraspList::default(), 1).is_err());
    }
}
