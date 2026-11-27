//! Repository-facing NIP-34 `git` publication commands.
//!
//! `nscript git` builds the NIP-34 events for a git repository, signs them
//! with a local key, and publishes them to the relays you name. It does not
//! implement git object transport: clone URLs point at ordinary git servers
//! or grasp services.

use std::collections::BTreeSet;
use std::fs;
use std::io::Read;
use std::path::{Path, PathBuf};
use std::process::{Command, ExitCode, Stdio};

use crate::publish::{
    EventToPublish, Failure, connect_relays, finish, finish_publish, load_signer, normalize_pubkey,
    now, option_value, parse_u64, parse_usize, publish_event_list,
};
use nscript_nip34::{
    Committer, GraspList, Issue, Patch, PullRequest, PullRequestUpdate, REPOSITORY_KIND,
    REPOSITORY_STATE_KIND, RepositoryAnnouncement, RepositoryFork, RepositoryState, Status,
    StatusKind, build_grasp_list, build_issue, build_patch, build_pull_request,
    build_pull_request_update, build_repository_announcement, build_repository_state, build_status,
    parse_repository_address,
};
use nscript_runtime::{SubscriptionHost, SubscriptionRequest, UnsignedEvent};
use serde_json::json;

/// Runs `nscript git <command>`.
pub fn run(arguments: &[String]) -> ExitCode {
    if arguments
        .iter()
        .any(|argument| argument == "-h" || argument == "--help")
    {
        usage();
        return ExitCode::SUCCESS;
    }
    let result = match arguments.first().map(String::as_str) {
        Some("announce") => announce_inner(&arguments[1..]),
        Some("state") => state_inner(&arguments[1..]),
        Some("patch") => patch_inner(&arguments[1..]),
        Some("pr") => pr_inner(&arguments[1..]),
        Some("pr-update") => pr_update_inner(&arguments[1..]),
        Some("issue") => issue_inner(&arguments[1..]),
        Some("status") => status_inner(&arguments[1..]),
        Some("grasp") => grasp_inner(&arguments[1..]),
        Some("latest") => latest_inner(&arguments[1..]),
        _ => {
            usage();
            return ExitCode::from(2);
        }
    };
    finish(result)
}

#[derive(Debug, Default)]
#[allow(clippy::struct_excessive_bools)]
struct Options {
    repo: Option<PathBuf>,
    relays: Vec<String>,
    relay_tags: Vec<String>,
    signer_key_env: Option<String>,
    published_at: Option<u64>,
    require_accepted: Option<usize>,
    dry_run: bool,
    json: bool,
    identifier: Option<String>,
    name: Option<String>,
    description: Option<String>,
    web: Vec<String>,
    clone: Vec<String>,
    maintainers: Vec<String>,
    topics: Vec<String>,
    euc: Option<String>,
    forks: Vec<String>,
    refs: Vec<String>,
    head: Option<String>,
    from_git: bool,
    repository: Option<String>,
    content: Option<String>,
    content_file: Option<PathBuf>,
    subject: Option<String>,
    labels: Vec<String>,
    commit: Option<String>,
    branch_name: Option<String>,
    revision_of: Option<String>,
    merge_base: Option<String>,
    pull_request: Option<String>,
    pull_request_author: Option<String>,
    root_event: Option<String>,
    revisions: Vec<String>,
    status: Option<String>,
    quotes: Vec<String>,
    merge_commit: Option<String>,
    applied_as: Vec<String>,
    grasp: Vec<String>,
    root_patch: bool,
    root_revision: bool,
    parent_commit: Option<String>,
    pgp_sig: Option<String>,
    committers: Vec<String>,
    to: Vec<String>,
    author: Option<String>,
    kind: Option<u16>,
}

impl Options {
    fn directory(&self) -> PathBuf {
        self.repo.clone().unwrap_or_else(|| PathBuf::from("."))
    }

    fn created_at(&self) -> u64 {
        self.published_at.unwrap_or_else(now)
    }
}

fn announce_inner(arguments: &[String]) -> Result<(), Failure> {
    let options = parse_options(arguments)?;
    let directory = options.directory();
    let config = load_config(&directory)?;
    let identifier = identifier(&options, &config, &directory)?;
    let announcement = RepositoryAnnouncement {
        identifier,
        name: options.name.clone().or(config.name),
        description: options.description.clone().or(config.description),
        web: prefer(&options.web, &config.web),
        clone: prefer(&options.clone, &config.clone),
        relays: prefer(&options.relay_tags, &config.relays),
        earliest_unique_commit: options.euc.clone().or(config.earliest_unique_commit),
        maintainers: normalize_keys(&prefer(&options.maintainers, &config.maintainers))?,
        forks: options
            .forks
            .iter()
            .map(|address| RepositoryFork {
                address: address.clone(),
                git_url: None,
                relay: None,
                author: None,
            })
            .collect(),
        topics: prefer(&options.topics, &config.topics),
    };
    let event = build_repository_announcement(&announcement, options.created_at())
        .map_err(|error| usage_error(&error))?;
    publish(
        &options,
        &[event_to_publish("RepositoryAnnouncement", event)],
    )
}

fn state_inner(arguments: &[String]) -> Result<(), Failure> {
    let options = parse_options(arguments)?;
    let directory = options.directory();
    let config = load_config(&directory)?;
    let identifier = identifier(&options, &config, &directory)?;
    let (refs, head) = if options.from_git {
        if !options.refs.is_empty() || options.head.is_some() {
            return Err(Failure::Usage(
                "--from-git reads refs and HEAD; it cannot be combined with --ref or --head"
                    .to_owned(),
            ));
        }
        git_state(&directory)?
    } else {
        let mut parsed = Vec::new();
        for value in &options.refs {
            parsed.push(parse_ref(value)?);
        }
        (parsed, options.head.clone())
    };
    let state = RepositoryState {
        identifier,
        refs,
        head,
    };
    let event = build_repository_state(&state, options.created_at())
        .map_err(|error| usage_error(&error))?;
    publish(&options, &[event_to_publish("RepositoryState", event)])
}

fn patch_inner(arguments: &[String]) -> Result<(), Failure> {
    let options = parse_options(arguments)?;
    let repository = required(
        options.repository.as_ref(),
        "--repository <30617:pubkey:identifier>",
    )?;
    let content = content(&options)?;
    let mut committers = Vec::new();
    for value in &options.committers {
        committers.push(parse_committer(value)?);
    }
    let patch = Patch {
        repository: repository.to_owned(),
        earliest_unique_commit: options.euc.clone(),
        recipients: recipients(&options, Some(repository))?,
        content,
        root: options.root_patch,
        root_revision: options.root_revision,
        commit: options.commit.clone(),
        parent_commit: options.parent_commit.clone(),
        commit_pgp_sig: options.pgp_sig.clone(),
        committers,
    };
    let event = build_patch(&patch, options.created_at()).map_err(|error| usage_error(&error))?;
    publish(&options, &[event_to_publish("Patch", event)])
}

fn pr_inner(arguments: &[String]) -> Result<(), Failure> {
    let options = parse_options(arguments)?;
    let repository = required(
        options.repository.as_ref(),
        "--repository <30617:pubkey:identifier>",
    )?;
    let pull_request = PullRequest {
        repository: repository.to_owned(),
        earliest_unique_commit: options.euc.clone(),
        recipients: recipients(&options, Some(repository))?,
        content: content_optional(&options)?,
        subject: required(options.subject.as_ref(), "--subject <text>")?.to_owned(),
        labels: options.labels.clone(),
        commit: required(options.commit.as_ref(), "--commit <commit-id>")?.to_owned(),
        clone: options.clone.clone(),
        branch_name: options.branch_name.clone(),
        revision_of: options.revision_of.clone(),
        merge_base: options.merge_base.clone(),
    };
    let event = build_pull_request(&pull_request, options.created_at())
        .map_err(|error| usage_error(&error))?;
    publish(&options, &[event_to_publish("PullRequest", event)])
}

fn pr_update_inner(arguments: &[String]) -> Result<(), Failure> {
    let options = parse_options(arguments)?;
    let repository = required(
        options.repository.as_ref(),
        "--repository <30617:pubkey:identifier>",
    )?;
    let update = PullRequestUpdate {
        repository: repository.to_owned(),
        earliest_unique_commit: options.euc.clone(),
        recipients: recipients(&options, Some(repository))?,
        pull_request: required(options.pull_request.as_ref(), "--pr <event-id>")?.to_owned(),
        pull_request_author: normalize_pubkey(required(
            options.pull_request_author.as_ref(),
            "--pr-author <pubkey>",
        )?)?,
        content: content_optional(&options)?,
        commit: required(options.commit.as_ref(), "--commit <commit-id>")?.to_owned(),
        clone: options.clone.clone(),
        merge_base: options.merge_base.clone(),
    };
    let event = build_pull_request_update(&update, options.created_at())
        .map_err(|error| usage_error(&error))?;
    publish(&options, &[event_to_publish("PullRequestUpdate", event)])
}

fn issue_inner(arguments: &[String]) -> Result<(), Failure> {
    let options = parse_options(arguments)?;
    let repository = required(
        options.repository.as_ref(),
        "--repository <30617:pubkey:identifier>",
    )?;
    let issue = Issue {
        repository: repository.to_owned(),
        recipients: recipients(&options, Some(repository))?,
        content: content_optional(&options)?,
        subject: options.subject.clone(),
        labels: options.labels.clone(),
    };
    let event = build_issue(&issue, options.created_at()).map_err(|error| usage_error(&error))?;
    publish(&options, &[event_to_publish("Issue", event)])
}

fn status_inner(arguments: &[String]) -> Result<(), Failure> {
    let options = parse_options(arguments)?;
    let kind = StatusKind::parse(required(options.status.as_ref(), "--status <status>")?)
        .map_err(|error| usage_error(&error))?;
    let status = Status {
        kind,
        repository: options.repository.clone(),
        earliest_unique_commit: options.euc.clone(),
        root: required(options.root_event.as_ref(), "--root-event <event-id>")?.to_owned(),
        revision: options.revisions.first().cloned(),
        recipients: recipients(&options, options.repository.as_deref())?,
        content: content_optional(&options)?,
        applied: options.quotes.clone(),
        merge_commit: options.merge_commit.clone(),
        applied_as_commits: options.applied_as.clone(),
    };
    if options.revisions.len() > 1 {
        return Err(Failure::Usage(
            "--revision names one accepted revision; repeat --q for applied patches".to_owned(),
        ));
    }
    let event = build_status(&status, options.created_at()).map_err(|error| usage_error(&error))?;
    publish(&options, &[event_to_publish("Status", event)])
}

fn grasp_inner(arguments: &[String]) -> Result<(), Failure> {
    let options = parse_options(arguments)?;
    if options.grasp.is_empty() {
        return Err(Failure::Usage(
            "grasp needs at least one --grasp <wss://url>".to_owned(),
        ));
    }
    let list = GraspList {
        servers: options.grasp.clone(),
    };
    let event =
        build_grasp_list(&list, options.created_at()).map_err(|error| usage_error(&error))?;
    publish(&options, &[event_to_publish("GraspList", event)])
}

struct LatestRepository {
    event_id: String,
    author: String,
    created_at: u64,
}

fn latest_inner(arguments: &[String]) -> Result<(), Failure> {
    let options = parse_options(arguments)?;
    let identifier = required(options.identifier.as_ref(), "--d <identifier>")?.to_owned();
    let kind = options.kind.unwrap_or(REPOSITORY_KIND);
    if kind != REPOSITORY_KIND && kind != REPOSITORY_STATE_KIND {
        return Err(Failure::Usage(format!(
            "--kind must be {REPOSITORY_KIND} or {REPOSITORY_STATE_KIND}, found {kind}"
        )));
    }
    let author = options
        .author
        .as_deref()
        .map(normalize_pubkey)
        .transpose()?;
    if options.relays.is_empty() {
        return Err(Failure::Usage(
            "latest needs at least one --relay <wss://url>".to_owned(),
        ));
    }
    let mut pool = connect_relays(&options.relays)?;
    let relays = pool.relay_urls();
    let latest = query_latest(&mut pool, &relays, kind, &identifier, author.as_deref())?;
    if options.json {
        println!(
            "{}",
            serde_json::to_string_pretty(&json!({
                "kind": kind,
                "d": &identifier,
                "author": &latest.author,
                "event_id": &latest.event_id,
                "created_at": latest.created_at,
            }))
            .expect("serializing a JSON value cannot fail")
        );
    } else {
        println!("latest kind {kind} for {identifier}: {}", latest.event_id);
        println!("  author: {}", latest.author);
        println!("  created_at: {}", latest.created_at);
    }
    Ok(())
}

fn query_latest<S: SubscriptionHost>(
    host: &mut S,
    relays: &[String],
    kind: u16,
    identifier: &str,
    author: Option<&str>,
) -> Result<LatestRepository, Failure> {
    let mut seen = BTreeSet::new();
    let mut candidates = Vec::new();
    let event_type = if kind == REPOSITORY_STATE_KIND {
        "RepositoryState"
    } else {
        "RepositoryAnnouncement"
    };
    for relay in relays {
        let request = SubscriptionRequest {
            event_type: event_type.to_owned(),
            relayset: Some(relay.clone()),
            kinds: vec![kind],
            tag_equals: vec![("d".to_owned(), identifier.to_owned())],
            cursor: None,
            author: author.map(str::to_owned),
            since: None,
            limit: Some(50),
        };
        match host.subscribe(0, &request) {
            Ok(handle) => {
                match host.poll(0, &handle) {
                    Ok(batch) => {
                        for event in batch.events {
                            if event.unsigned.kind == kind && seen.insert(event.id.clone()) {
                                candidates.push(event);
                            }
                        }
                    }
                    Err(error) => eprintln!("warning: query on {relay} failed: {error:?}"),
                }
                let _ = host.unsubscribe(0, &handle);
            }
            Err(error) => eprintln!("warning: could not subscribe on {relay}: {error:?}"),
        }
    }
    let latest = candidates
        .into_iter()
        .max_by(|left, right| {
            left.unsigned
                .created_at
                .cmp(&right.unsigned.created_at)
                .then_with(|| right.id.cmp(&left.id))
        })
        .ok_or_else(|| {
            Failure::Runtime(format!(
                "no kind {kind} repository found for d={identifier}{}",
                author.map_or_else(String::new, |author| format!(" and author {author}"))
            ))
        })?;
    Ok(LatestRepository {
        event_id: latest.id,
        author: latest.signer,
        created_at: latest.unsigned.created_at,
    })
}

fn publish(options: &Options, events: &[EventToPublish]) -> Result<(), Failure> {
    if options.dry_run {
        print_dry_run(events, options);
        return Ok(());
    }
    if options.relays.is_empty() {
        return Err(Failure::Usage(
            "publishing needs at least one --relay <wss://url>".to_owned(),
        ));
    }
    let signer = load_signer(options.signer_key_env.as_deref())?;
    let mut pool = connect_relays(&options.relays)?;
    let results = publish_event_list(events, &mut pool, &signer, options.json)?;
    let require = options.require_accepted.unwrap_or(1);
    finish_publish(&results, require, options.json)
}

fn print_dry_run(events: &[EventToPublish], options: &Options) {
    if options.json {
        let events = events
            .iter()
            .map(|item| {
                json!({
                    "label": &item.label,
                    "event_type": &item.event.event_type,
                    "kind": item.event.kind,
                    "tags": item.event.wire_tags(),
                    "content": &item.event.content,
                    "published_at": item.event.created_at,
                })
            })
            .collect::<Vec<_>>();
        println!(
            "{}",
            serde_json::to_string_pretty(&json!({ "events": events }))
                .expect("serializing a JSON value cannot fail")
        );
        return;
    }
    for item in events {
        println!(
            "{}: kind {}, {} bytes, {} tags",
            item.label,
            item.event.kind,
            item.event.content.len(),
            item.event.wire_tags().len()
        );
        println!(
            "  {}",
            serde_json::to_string(&item.event.wire_tags()).expect("serializing tags cannot fail")
        );
    }
}

fn event_to_publish(label: &str, event: UnsignedEvent) -> EventToPublish {
    EventToPublish {
        label: label.to_owned(),
        event,
    }
}

fn usage_error(error: &nscript_nip34::Nip34Error) -> Failure {
    Failure::Usage(error.message().to_owned())
}

fn required<'a>(value: Option<&'a String>, flag: &str) -> Result<&'a str, Failure> {
    value
        .map(String::as_str)
        .ok_or_else(|| Failure::Usage(format!("this command needs {flag}")))
}

fn content(options: &Options) -> Result<String, Failure> {
    let text = content_optional(options)?;
    if text.is_empty() {
        return Err(Failure::Usage(
            "this command needs --content or --content-file".to_owned(),
        ));
    }
    Ok(text)
}

fn content_optional(options: &Options) -> Result<String, Failure> {
    if options.content.is_some() && options.content_file.is_some() {
        return Err(Failure::Usage(
            "use --content or --content-file, not both".to_owned(),
        ));
    }
    if let Some(text) = &options.content {
        return Ok(text.clone());
    }
    let Some(path) = &options.content_file else {
        return Ok(String::new());
    };
    if path == Path::new("-") {
        let mut text = String::new();
        std::io::stdin()
            .read_to_string(&mut text)
            .map_err(|error| Failure::Runtime(format!("could not read stdin: {error}")))?;
        return Ok(text);
    }
    fs::read_to_string(path)
        .map_err(|error| Failure::Usage(format!("could not read `{}`: {error}", path.display())))
}

fn recipients(options: &Options, repository: Option<&str>) -> Result<Vec<String>, Failure> {
    let mut recipients = Vec::new();
    let mut seen = BTreeSet::new();
    if let Some(address) = repository {
        let owner = owner_of(address)?;
        if seen.insert(owner.clone()) {
            recipients.push(owner);
        }
    }
    for value in &options.to {
        let key = normalize_pubkey(value)?;
        if seen.insert(key.clone()) {
            recipients.push(key);
        }
    }
    Ok(recipients)
}

fn owner_of(address: &str) -> Result<String, Failure> {
    parse_repository_address(address)
        .map(|(owner, _)| owner)
        .map_err(|error| usage_error(&error))
}

fn parse_ref(value: &str) -> Result<(String, String), Failure> {
    let Some((name, commit)) = value.split_once('=') else {
        return Err(Failure::Usage(format!(
            "--ref expects `<ref-name>=<commit-id>`, found `{value}`"
        )));
    };
    let valid = name.starts_with("refs/heads/") || name.starts_with("refs/tags/");
    if !valid || name.len() <= "refs/heads/".len() {
        return Err(Failure::Usage(format!(
            "--ref name `{name}` must be refs/heads/<name> or refs/tags/<name>"
        )));
    }
    Ok((name.to_owned(), commit.to_owned()))
}

fn parse_committer(value: &str) -> Result<Committer, Failure> {
    let parts = value.splitn(4, ',').collect::<Vec<_>>();
    let [name, email, timestamp, timezone] = parts.as_slice() else {
        return Err(Failure::Usage(format!(
            "--committer expects `<name>,<email>,<timestamp>,<timezone-minutes>`, found `{value}`"
        )));
    };
    let timestamp = timestamp.parse::<i64>().map_err(|_| {
        Failure::Usage(format!(
            "committer timestamp `{timestamp}` is not an integer"
        ))
    })?;
    let timezone_offset_minutes = timezone.parse::<i32>().map_err(|_| {
        Failure::Usage(format!("committer timezone `{timezone}` is not an integer"))
    })?;
    Ok(Committer {
        name: (*name).to_owned(),
        email: (*email).to_owned(),
        timestamp,
        timezone_offset_minutes,
    })
}

type Refs = Vec<(String, String)>;

fn git_state(directory: &Path) -> Result<(Refs, Option<String>), Failure> {
    let output = git(
        directory,
        &[
            "for-each-ref",
            "--format=%(refname) %(objectname)",
            "refs/heads",
            "refs/tags",
        ],
    )?;
    let mut refs = Vec::new();
    for line in output.lines() {
        let mut parts = line.split_whitespace();
        let (Some(name), Some(commit)) = (parts.next(), parts.next()) else {
            continue;
        };
        if name.starts_with("refs/heads/") || name.starts_with("refs/tags/") {
            refs.push((name.to_owned(), commit.to_owned()));
        }
    }
    refs.sort_by(|left, right| left.0.cmp(&right.0));
    let head = git(directory, &["symbolic-ref", "-q", "HEAD"])
        .ok()
        .map(|value| value.trim().to_owned())
        .filter(|value| value.starts_with("refs/heads/"));
    Ok((refs, head))
}

fn git(directory: &Path, arguments: &[&str]) -> Result<String, Failure> {
    let output = Command::new("git")
        .arg("-C")
        .arg(directory)
        .args(arguments)
        .stderr(Stdio::piped())
        .output()
        .map_err(|error| Failure::Runtime(format!("could not run git: {error}")))?;
    if !output.status.success() {
        return Err(Failure::Runtime(format!(
            "git {} failed: {}",
            arguments.join(" "),
            String::from_utf8_lossy(&output.stderr).trim()
        )));
    }
    Ok(String::from_utf8_lossy(&output.stdout).into_owned())
}

#[derive(Debug, Default)]
struct Config {
    identifier: Option<String>,
    name: Option<String>,
    description: Option<String>,
    web: Vec<String>,
    clone: Vec<String>,
    relays: Vec<String>,
    maintainers: Vec<String>,
    topics: Vec<String>,
    earliest_unique_commit: Option<String>,
}

fn load_config(directory: &Path) -> Result<Config, Failure> {
    let path = directory.join("nip34.json");
    if !path.exists() {
        return Ok(Config::default());
    }
    let text = fs::read_to_string(&path)
        .map_err(|error| Failure::Usage(format!("could not read `{}`: {error}", path.display())))?;
    let value: serde_json::Value = serde_json::from_str(&text).map_err(|error| {
        Failure::Usage(format!("`{}` is not valid JSON: {error}", path.display()))
    })?;
    let Config {
        identifier,
        name,
        description,
        web,
        clone,
        relays,
        maintainers,
        topics,
        earliest_unique_commit,
    } = Config {
        identifier: config_string(&value, "identifier")?,
        name: config_string(&value, "name")?,
        description: config_string(&value, "description")?,
        web: config_strings(&value, "web")?,
        clone: config_strings(&value, "clone")?,
        relays: config_strings(&value, "relays")?,
        maintainers: config_strings(&value, "maintainers")?,
        topics: config_strings(&value, "topics")?,
        earliest_unique_commit: config_string(&value, "earliest_unique_commit")?,
    };
    Ok(Config {
        identifier,
        name,
        description,
        web,
        clone,
        relays,
        maintainers,
        topics,
        earliest_unique_commit,
    })
}

fn config_string(value: &serde_json::Value, field: &str) -> Result<Option<String>, Failure> {
    match value.get(field) {
        None | Some(serde_json::Value::Null) => Ok(None),
        Some(serde_json::Value::String(text)) => Ok(Some(text.clone())),
        Some(_) => Err(Failure::Usage(format!(
            "nip34.json: `{field}` must be a string"
        ))),
    }
}

fn config_strings(value: &serde_json::Value, field: &str) -> Result<Vec<String>, Failure> {
    let Some(entry) = value.get(field) else {
        return Ok(Vec::new());
    };
    let Some(items) = entry.as_array() else {
        return Err(Failure::Usage(format!(
            "nip34.json: `{field}` must be an array of strings"
        )));
    };
    items
        .iter()
        .map(|item| {
            item.as_str().map(str::to_owned).ok_or_else(|| {
                Failure::Usage(format!("nip34.json: `{field}` must be an array of strings"))
            })
        })
        .collect()
}

fn identifier(options: &Options, config: &Config, directory: &Path) -> Result<String, Failure> {
    if let Some(identifier) = &options.identifier {
        return Ok(identifier.clone());
    }
    if let Some(identifier) = &config.identifier {
        return Ok(identifier.clone());
    }
    let canonical = fs::canonicalize(directory).unwrap_or_else(|_| directory.to_path_buf());
    canonical
        .file_name()
        .and_then(|name| name.to_str())
        .map(str::to_owned)
        .ok_or_else(|| {
            Failure::Usage(
                "cannot derive a repository identifier from the directory; pass --d <identifier>"
                    .to_owned(),
            )
        })
}

fn prefer(flags: &[String], config: &[String]) -> Vec<String> {
    if flags.is_empty() {
        config.to_vec()
    } else {
        flags.to_vec()
    }
}

fn normalize_keys(values: &[String]) -> Result<Vec<String>, Failure> {
    values.iter().map(|value| normalize_pubkey(value)).collect()
}

#[allow(clippy::too_many_lines)]
fn parse_options(arguments: &[String]) -> Result<Options, Failure> {
    let mut options = Options::default();
    let mut index = 0;
    while index < arguments.len() {
        let argument = arguments[index].as_str();
        match argument {
            "--repo" => {
                options.repo = Some(PathBuf::from(option_value(
                    arguments, &mut index, argument,
                )?));
            }
            "--relay" => {
                options
                    .relays
                    .push(option_value(arguments, &mut index, argument)?);
            }
            "--relay-tag" => {
                options
                    .relay_tags
                    .push(option_value(arguments, &mut index, argument)?);
            }
            "--signer-key-env" => {
                options.signer_key_env = Some(option_value(arguments, &mut index, argument)?);
            }
            "--published-at" => {
                let value = option_value(arguments, &mut index, argument)?;
                options.published_at = Some(parse_u64(&value, argument)?);
            }
            "--require-accepted" => {
                let value = option_value(arguments, &mut index, argument)?;
                options.require_accepted = Some(parse_usize(&value, argument)?);
            }
            "--dry-run" => {
                options.dry_run = true;
                index += 1;
            }
            "--json" => {
                options.json = true;
                index += 1;
            }
            "--d" => {
                options.identifier = Some(option_value(arguments, &mut index, argument)?);
            }
            "--name" => {
                options.name = Some(option_value(arguments, &mut index, argument)?);
            }
            "--description" => {
                options.description = Some(option_value(arguments, &mut index, argument)?);
            }
            "--web" => {
                options
                    .web
                    .push(option_value(arguments, &mut index, argument)?);
            }
            "--clone" => {
                options
                    .clone
                    .push(option_value(arguments, &mut index, argument)?);
            }
            "--maintainer" => {
                options
                    .maintainers
                    .push(option_value(arguments, &mut index, argument)?);
            }
            "--topic" => {
                options
                    .topics
                    .push(option_value(arguments, &mut index, argument)?);
            }
            "--euc" => {
                options.euc = Some(option_value(arguments, &mut index, argument)?);
            }
            "--fork" => {
                options
                    .forks
                    .push(option_value(arguments, &mut index, argument)?);
            }
            "--ref" => {
                options
                    .refs
                    .push(option_value(arguments, &mut index, argument)?);
            }
            "--head" => {
                options.head = Some(option_value(arguments, &mut index, argument)?);
            }
            "--from-git" => {
                options.from_git = true;
                index += 1;
            }
            "--repository" => {
                options.repository = Some(option_value(arguments, &mut index, argument)?);
            }
            "--content" => {
                options.content = Some(option_value(arguments, &mut index, argument)?);
            }
            "--content-file" => {
                options.content_file = Some(PathBuf::from(option_value(
                    arguments, &mut index, argument,
                )?));
            }
            "--subject" => {
                options.subject = Some(option_value(arguments, &mut index, argument)?);
            }
            "--label" => {
                options
                    .labels
                    .push(option_value(arguments, &mut index, argument)?);
            }
            "--commit" => {
                options.commit = Some(option_value(arguments, &mut index, argument)?);
            }
            "--branch-name" => {
                options.branch_name = Some(option_value(arguments, &mut index, argument)?);
            }
            "--revision-of" => {
                options.revision_of = Some(option_value(arguments, &mut index, argument)?);
            }
            "--merge-base" => {
                options.merge_base = Some(option_value(arguments, &mut index, argument)?);
            }
            "--pr" => {
                options.pull_request = Some(option_value(arguments, &mut index, argument)?);
            }
            "--pr-author" => {
                options.pull_request_author = Some(option_value(arguments, &mut index, argument)?);
            }
            "--root-event" => {
                options.root_event = Some(option_value(arguments, &mut index, argument)?);
            }
            "--revision" => {
                options
                    .revisions
                    .push(option_value(arguments, &mut index, argument)?);
            }
            "--status" => {
                options.status = Some(option_value(arguments, &mut index, argument)?);
            }
            "--q" => {
                options
                    .quotes
                    .push(option_value(arguments, &mut index, argument)?);
            }
            "--merge-commit" => {
                options.merge_commit = Some(option_value(arguments, &mut index, argument)?);
            }
            "--applied-as-commit" => {
                options
                    .applied_as
                    .push(option_value(arguments, &mut index, argument)?);
            }
            "--grasp" => {
                options
                    .grasp
                    .push(option_value(arguments, &mut index, argument)?);
            }
            "--root" => {
                options.root_patch = true;
                index += 1;
            }
            "--root-revision" => {
                options.root_revision = true;
                index += 1;
            }
            "--parent-commit" => {
                options.parent_commit = Some(option_value(arguments, &mut index, argument)?);
            }
            "--pgp-sig" => {
                options.pgp_sig = Some(option_value(arguments, &mut index, argument)?);
            }
            "--committer" => {
                options
                    .committers
                    .push(option_value(arguments, &mut index, argument)?);
            }
            "--to" => {
                options
                    .to
                    .push(option_value(arguments, &mut index, argument)?);
            }
            "--author" => {
                options.author = Some(option_value(arguments, &mut index, argument)?);
            }
            "--kind" => {
                let value = option_value(arguments, &mut index, argument)?;
                options.kind = Some(value.parse().map_err(|_| {
                    Failure::Usage(format!("--kind expects an event kind, found `{value}`"))
                })?);
            }
            other if other.starts_with('-') => {
                return Err(Failure::Usage(format!("unknown git option `{other}`")));
            }
            other => {
                return Err(Failure::Usage(format!(
                    "unexpected argument `{other}`; git commands take only flags"
                )));
            }
        }
    }
    Ok(options)
}

fn usage() {
    eprintln!(
        "usage:\n  \
nscript git announce [--repo <directory>] [--d <id>] [--name <text>] [--description <text>] [--web <url>]... [--clone <url>]... [--relay-tag <wss://url>]... [--maintainer <pubkey|npub>]... [--topic <text>]... [--euc <commit>] [--fork <30617:pubkey:id>]... --relay <wss://url>... --signer-key-env <environment-variable> [--published-at <seconds>] [--require-accepted <n>] [--dry-run] [--json]\n  \
nscript git state [--repo <directory>] [--d <id>] (--ref <ref-name>=<commit-id>... | --from-git) [--head <ref-name>] --relay <wss://url>... --signer-key-env <environment-variable> [--published-at <seconds>] [--require-accepted <n>] [--dry-run] [--json]\n  \
nscript git patch --repository <30617:pubkey:id> (--content <text> | --content-file <path|->) [--to <pubkey>]... [--euc <commit>] [--root] [--root-revision] [--commit <commit-id>] [--parent-commit <commit-id>] [--pgp-sig <text>] [--committer <name,email,timestamp,timezone-minutes>]... --relay <wss://url>... --signer-key-env <environment-variable> [--published-at <seconds>] [--require-accepted <n>] [--dry-run] [--json]\n  \
nscript git pr --repository <30617:pubkey:id> --subject <text> [--content <text> | --content-file <path|->] --commit <commit-id> --clone <url>... [--to <pubkey>]... [--label <text>]... [--branch-name <name>] [--revision-of <event-id>] [--merge-base <commit-id>] [--euc <commit>] --relay <wss://url>... --signer-key-env <environment-variable> [--published-at <seconds>] [--require-accepted <n>] [--dry-run] [--json]\n  \
nscript git pr-update --pr <event-id> --pr-author <pubkey> --repository <30617:pubkey:id> --commit <commit-id> --clone <url>... [--to <pubkey>]... [--content <text> | --content-file <path|->] [--merge-base <commit-id>] [--euc <commit>] --relay <wss://url>... --signer-key-env <environment-variable> [--published-at <seconds>] [--require-accepted <n>] [--dry-run] [--json]\n  \
nscript git issue --repository <30617:pubkey:id> [--subject <text>] (--content <text> | --content-file <path|->) [--to <pubkey>]... [--label <text>]... --relay <wss://url>... --signer-key-env <environment-variable> [--published-at <seconds>] [--require-accepted <n>] [--dry-run] [--json]\n  \
nscript git status --status <open|applied|merged|resolved|closed|draft> --root-event <event-id> [--repository <30617:pubkey:id>] [--to <pubkey>]... [--revision <event-id>]... [--q <event-id>]... [--merge-commit <commit-id>] [--applied-as-commit <commit-id>]... [--euc <commit>] [--content <text> | --content-file <path|->] --relay <wss://url>... --signer-key-env <environment-variable> [--published-at <seconds>] [--require-accepted <n>] [--dry-run] [--json]\n  \
nscript git grasp --grasp <wss://url>... --relay <wss://url>... --signer-key-env <environment-variable> [--published-at <seconds>] [--require-accepted <n>] [--dry-run] [--json]\n  \
nscript git latest --d <id> [--kind 30617|30618] [--author <pubkey|npub>] --relay <wss://url>... [--json]"
    );
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_refs_and_report_bad_shapes() {
        assert_eq!(
            parse_ref("refs/heads/main=abc").unwrap(),
            ("refs/heads/main".to_owned(), "abc".to_owned())
        );
        assert!(parse_ref("main=abc").is_err());
        assert!(parse_ref("refs/heads/main").is_err());
        assert!(parse_ref("refs/heads/=abc").is_err());
    }

    #[test]
    fn parses_commit_metadata() {
        let committer = parse_committer("Ada,ada@example.com,1700000000,-300").expect("committer");
        assert_eq!(committer.name, "Ada");
        assert_eq!(committer.email, "ada@example.com");
        assert_eq!(committer.timestamp, 1_700_000_000);
        assert_eq!(committer.timezone_offset_minutes, -300);
        assert!(parse_committer("Ada,ada@example.com,not-a-time,-300").is_err());
        assert!(parse_committer("Ada,ada@example.com").is_err());
    }

    fn repository_event(id: &str, created_at: u64) -> nscript_runtime::SignedEvent {
        nscript_runtime::SignedEvent {
            unsigned: UnsignedEvent {
                event_type: "RepositoryAnnouncement".to_owned(),
                kind: REPOSITORY_KIND,
                content: String::new(),
                tags: vec![("d".to_owned(), "demo".to_owned())],
                created_at,
            },
            signer: "b".repeat(64),
            id: id.to_owned(),
            signature: "sig".to_owned(),
        }
    }

    #[test]
    fn latest_selects_the_newest_repository_and_breaks_ties_lowest() {
        let mut relay = nscript_runtime::FakeRelayHost::default();
        relay.queued_events.insert(
            1,
            vec![
                repository_event("new", 1_766_000_100),
                repository_event("old", 1_766_000_000),
            ],
        );
        let latest = query_latest(
            &mut relay,
            &["wss://relay.example".to_owned()],
            REPOSITORY_KIND,
            "demo",
            None,
        )
        .unwrap();
        assert_eq!(latest.event_id, "new");
        assert_eq!(latest.author, "b".repeat(64));

        let mut relay = nscript_runtime::FakeRelayHost::default();
        relay.queued_events.insert(
            1,
            vec![
                repository_event("bbbb", 1_766_000_000),
                repository_event("aaaa", 1_766_000_000),
            ],
        );
        let latest = query_latest(
            &mut relay,
            &["wss://relay.example".to_owned()],
            REPOSITORY_KIND,
            "demo",
            None,
        )
        .unwrap();
        assert_eq!(latest.event_id, "aaaa");
    }

    #[test]
    fn reads_config_and_flags() {
        let unique = format!("nscript-git-config-{}-{}", std::process::id(), now());
        let directory = std::env::temp_dir().join(unique);
        fs::create_dir_all(&directory).expect("create temp directory");
        fs::write(
            directory.join("nip34.json"),
            r#"{
                "identifier": "nscript",
                "name": "NScript",
                "web": ["https://example.com"],
                "clone": ["https://example.com/nscript.git"],
                "relays": ["wss://relay.example.com"],
                "maintainers": ["aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"],
                "topics": ["nostr"]
            }"#,
        )
        .expect("write config");
        let config = load_config(&directory).expect("config");
        assert_eq!(config.identifier.as_deref(), Some("nscript"));
        assert_eq!(config.clone, ["https://example.com/nscript.git"]);
        assert_eq!(config.relays, ["wss://relay.example.com"]);
        let options = parse_options(&[
            "--repo".to_owned(),
            directory.display().to_string(),
            "--name".to_owned(),
            "Override".to_owned(),
        ])
        .expect("options");
        assert_eq!(options.name.as_deref(), Some("Override"));
        assert_eq!(
            identifier(&options, &config, &directory).unwrap(),
            "nscript"
        );
        fs::remove_dir_all(&directory).expect("remove temp directory");
    }
}
