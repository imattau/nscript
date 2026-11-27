//! Repository-facing `NCC-00` publication commands.

use std::collections::BTreeSet;
use std::fs;
use std::path::PathBuf;
use std::process::ExitCode;

use crate::publish::{
    EventToPublish, Failure, connect_relays, count_failures, finish, finish_publish, hex_encode,
    load_signer, now, option_value, parse_u64, parse_usize, publish_event_list,
};
use nscript_ncc::{
    EndorsementMetadata, NccEntry, Status, SuccessionMetadata, SupportingEntry, build_document,
    build_endorsement, build_succession, build_supporting_document, discover, discover_supporting,
    parse_release_tag,
};
use nscript_runtime::{SubscriptionHost, SubscriptionRequest, UnsignedEvent};
use serde_json::json;

/// Runs `nscript ncc <command>`.
pub fn run(arguments: &[String]) -> ExitCode {
    if arguments
        .iter()
        .any(|argument| argument == "-h" || argument == "--help")
    {
        usage();
        return ExitCode::SUCCESS;
    }
    match arguments.first().map(String::as_str) {
        Some("check") => finish(check_inner(&arguments[1..])),
        Some("publish") => finish(publish_inner(&arguments[1..])),
        Some("support") => finish(support_inner(&arguments[1..])),
        Some("succession") => finish(succession_inner(&arguments[1..])),
        Some("endorse") => finish(endorse_inner(&arguments[1..])),
        Some("latest") => finish(latest_inner(&arguments[1..])),
        _ => {
            usage();
            ExitCode::from(2)
        }
    }
}

#[derive(Debug, Default)]
#[allow(clippy::struct_excessive_bools)]
struct Options {
    repo: Option<PathBuf>,
    all: bool,
    tag: Option<String>,
    ids: Vec<String>,
    relays: Vec<String>,
    signer_key_env: Option<String>,
    version: Option<String>,
    published_at: Option<u64>,
    require_accepted: Option<usize>,
    include_drafts: bool,
    dry_run: bool,
    json: bool,
    ncc: Option<String>,
    author: Option<String>,
    slug: Option<String>,
    authoritative: Option<String>,
    event: Option<String>,
    steward: Option<String>,
    previous: Option<String>,
    reason: Option<String>,
    effective_at: Option<u64>,
    status: Option<String>,
    roles: Vec<String>,
    implementation: Option<String>,
    note: Option<String>,
    topics: Vec<String>,
    content: Option<String>,
    content_file: Option<PathBuf>,
    supporting: bool,
    succession: bool,
    succession_reason: Option<String>,
    succession_content: Option<String>,
}

impl Options {
    fn selectors(&self) -> usize {
        let mut count = 0;
        if self.all {
            count += 1;
        }
        if self.tag.is_some() {
            count += 1;
        }
        if !self.ids.is_empty() {
            count += 1;
        }
        count
    }

    fn has_non_check_options(&self) -> bool {
        !self.relays.is_empty()
            || self.signer_key_env.is_some()
            || self.version.is_some()
            || self.published_at.is_some()
            || self.require_accepted.is_some()
            || self.include_drafts
            || self.dry_run
            || self.ncc.is_some()
            || self.author.is_some()
            || self.slug.is_some()
            || self.authoritative.is_some()
            || self.event.is_some()
            || self.steward.is_some()
            || self.previous.is_some()
            || self.reason.is_some()
            || self.effective_at.is_some()
            || self.status.is_some()
            || !self.roles.is_empty()
            || self.implementation.is_some()
            || self.note.is_some()
            || !self.topics.is_empty()
            || self.content.is_some()
            || self.content_file.is_some()
            || self.supporting
            || self.succession
            || self.succession_reason.is_some()
            || self.succession_content.is_some()
    }
}

struct DryRunSuccession {
    d: String,
    reason: Option<String>,
    content: String,
}

fn check_inner(arguments: &[String]) -> Result<(), Failure> {
    let options = parse_options(arguments)?;
    if options.has_non_check_options() {
        return Err(Failure::Usage(
            "check accepts only --repo, --all, explicit NCC ids, --tag, and --json".to_owned(),
        ));
    }
    if options.selectors() > 1 {
        return Err(Failure::Usage(
            "use only one of --all, --tag, or explicit NCC ids".to_owned(),
        ));
    }
    let root = repository(&options);
    let entries = discover(&root).map_err(|error| Failure::Runtime(error.to_string()))?;
    if entries.is_empty() {
        return Err(Failure::Runtime(format!(
            "no ncc-<digits> directories found in {}",
            root.display()
        )));
    }
    let selected = select_for_check(entries, &options)?;
    let supporting = discover_supporting(&root)
        .map_err(|error| Failure::Runtime(error.to_string()))?
        .into_iter()
        .filter(|entry| selected.iter().any(|doc| doc.id == entry.ncc_id))
        .collect::<Vec<_>>();
    if options.json {
        let conventions = selected
            .iter()
            .map(|entry| {
                json!({
                    "id": &entry.id,
                    "title": &entry.metadata.title,
                    "status": entry.metadata.status.as_str(),
                    "version": &entry.metadata.version,
                    "content_bytes": entry.content.len(),
                    "supporting": supporting.iter().filter(|supporting| supporting.ncc_id == entry.id).count(),
                })
            })
            .collect::<Vec<_>>();
        let supporting_json = supporting
            .iter()
            .map(|entry| {
                json!({
                    "ncc": &entry.ncc_id,
                    "d": &entry.d,
                    "title": &entry.metadata.title,
                    "status": entry.metadata.status.as_str(),
                    "content_bytes": entry.content.len(),
                })
            })
            .collect::<Vec<_>>();
        println!(
            "{}",
            serde_json::to_string_pretty(&json!({
                "conventions": conventions,
                "supporting": supporting_json,
            }))
            .expect("serializing a JSON value cannot fail")
        );
    } else {
        for entry in &selected {
            let supporting_count = supporting
                .iter()
                .filter(|supporting| supporting.ncc_id == entry.id)
                .count();
            println!(
                "{}: ok ({}; {} bytes; {supporting_count} supporting)",
                entry.id,
                entry.metadata.status.as_str(),
                entry.content.len()
            );
        }
        println!(
            "checked {} convention(s) and {} supporting document(s)",
            selected.len(),
            supporting.len()
        );
    }
    Ok(())
}

#[allow(clippy::too_many_lines)]
fn publish_inner(arguments: &[String]) -> Result<(), Failure> {
    let options = parse_options(arguments)?;
    validate_publish_options(&options)?;
    let root = repository(&options);
    let entries = discover(&root).map_err(|error| Failure::Runtime(error.to_string()))?;
    if entries.is_empty() {
        return Err(Failure::Runtime(format!(
            "no ncc-<digits> directories found in {}",
            root.display()
        )));
    }
    let (selected, tag_version) = select_for_publish(entries, &options)?;
    if options.succession && selected.len() != 1 {
        return Err(Failure::Usage(
            "--succession applies to exactly one selected convention".to_owned(),
        ));
    }
    let version_override = options.version.clone().or(tag_version);
    let published_at = options.published_at.unwrap_or_else(now);
    if published_at == 0 {
        return Err(Failure::Runtime(
            "published_at resolved to zero; pass --published-at <seconds>".to_owned(),
        ));
    }

    let mut events = selected
        .iter()
        .map(|entry| {
            build_document(entry, published_at, version_override.as_deref())
                .map(|event| EventToPublish {
                    label: format!("{} document", entry.id),
                    event,
                })
                .map_err(|error| Failure::Runtime(error.to_string()))
        })
        .collect::<Result<Vec<_>, _>>()?;

    if options.supporting {
        let selected_ids = selected
            .iter()
            .map(|entry| entry.id.as_str())
            .collect::<BTreeSet<_>>();
        let supporting = discover_supporting(&root)
            .map_err(|error| Failure::Runtime(error.to_string()))?
            .into_iter()
            .filter(|entry| selected_ids.contains(entry.ncc_id.as_str()))
            .collect::<Vec<_>>();
        for entry in &supporting {
            let timestamp = options
                .published_at
                .or(entry.metadata.published_at)
                .unwrap_or(published_at);
            let event = build_supporting_document(entry, timestamp)
                .map_err(|error| Failure::Runtime(error.to_string()))?;
            events.push(EventToPublish {
                label: format!("{} supporting {}", entry.ncc_id, entry.d),
                event,
            });
        }
    }

    let dry_run_succession = options.succession.then(|| DryRunSuccession {
        d: selected[0].id.clone(),
        reason: options.succession_reason.clone(),
        content: options
            .succession_content
            .clone()
            .unwrap_or_else(default_succession_content),
    });

    if options.dry_run {
        print_dry_run(&events, &options, dry_run_succession.as_ref());
        return Ok(());
    }

    let signer = load_signer(options.signer_key_env.as_deref())?;
    let mut pool = connect_relays(&options.relays)?;
    let require = options.require_accepted.unwrap_or(1);
    let mut results = publish_event_list(&events, &mut pool, &signer, options.json)?;
    if count_failures(&results, require) > 0 {
        return finish_publish(&results, require, options.json);
    }

    if options.succession {
        let metadata = SuccessionMetadata {
            d: selected[0].id.clone(),
            authoritative: format!("event:{}", results[0].event_id),
            steward: None,
            previous: None,
            reason: options.succession_reason.clone(),
            effective_at: None,
            content: options
                .succession_content
                .clone()
                .unwrap_or_else(default_succession_content),
        };
        let event = build_succession(&metadata, published_at)
            .map_err(|error| Failure::Runtime(error.to_string()))?;
        let succession = [EventToPublish {
            label: format!("{} succession", selected[0].id),
            event,
        }];
        results.extend(publish_event_list(
            &succession,
            &mut pool,
            &signer,
            options.json,
        )?);
        if count_failures(&results, require) > 0 {
            return finish_publish(&results, require, options.json);
        }
    }

    finish_publish(&results, require, options.json)
}

fn support_inner(arguments: &[String]) -> Result<(), Failure> {
    let options = parse_options(arguments)?;
    validate_support_options(&options)?;
    let root = repository(&options);
    let entries =
        discover_supporting(&root).map_err(|error| Failure::Runtime(error.to_string()))?;
    let selected = select_supporting(entries, &options)?;
    let default_time = options.published_at.unwrap_or_else(now);
    let events = selected
        .iter()
        .map(|entry| {
            let timestamp = options
                .published_at
                .or(entry.metadata.published_at)
                .unwrap_or(default_time);
            build_supporting_document(entry, timestamp)
                .map(|event| EventToPublish {
                    label: format!("{} supporting {}", entry.ncc_id, entry.d),
                    event,
                })
                .map_err(|error| Failure::Runtime(error.to_string()))
        })
        .collect::<Result<Vec<_>, _>>()?;
    if options.dry_run {
        print_dry_run(&events, &options, None);
        return Ok(());
    }
    let signer = load_signer(options.signer_key_env.as_deref())?;
    let mut pool = connect_relays(&options.relays)?;
    let require = options.require_accepted.unwrap_or(1);
    let results = publish_event_list(&events, &mut pool, &signer, options.json)?;
    finish_publish(&results, require, options.json)
}

fn succession_inner(arguments: &[String]) -> Result<(), Failure> {
    let options = parse_options(arguments)?;
    validate_succession_options(&options)?;
    let d = options.ncc.clone().expect("validated --ncc");
    let created_at = options.published_at.unwrap_or_else(now);
    let content = content_text(
        &options,
        "Steward acknowledges the authoritative NCC document.",
    )?;
    let mut preloaded_signer = None;
    let authoritative = if options.authoritative.as_deref() == Some("latest") {
        let author = if let Some(author) = &options.author {
            normalize_author(author)?
        } else {
            let signer = load_signer(options.signer_key_env.as_deref())?;
            let pubkey = signer.public_key_hex.clone();
            preloaded_signer = Some(signer);
            pubkey
        };
        let mut pool = connect_relays(&options.relays)?;
        let relays = pool.relay_urls();
        let latest = query_latest(&mut pool, &relays, &d, Some(&author))?;
        format!("event:{}", latest.event_id)
    } else {
        options
            .authoritative
            .clone()
            .expect("validated --authoritative")
    };
    let metadata = SuccessionMetadata {
        d: d.clone(),
        authoritative,
        steward: options.steward.clone(),
        previous: options.previous.clone(),
        reason: options.reason.clone(),
        effective_at: options.effective_at,
        content,
    };
    let event = build_succession(&metadata, created_at)
        .map_err(|error| Failure::Runtime(error.to_string()))?;
    let events = [EventToPublish {
        label: format!("{d} succession"),
        event,
    }];
    if options.dry_run {
        print_dry_run(&events, &options, None);
        return Ok(());
    }
    let signer = match preloaded_signer {
        Some(signer) => signer,
        None => load_signer(options.signer_key_env.as_deref())?,
    };
    let mut pool = connect_relays(&options.relays)?;
    let require = options.require_accepted.unwrap_or(1);
    let results = publish_event_list(&events, &mut pool, &signer, options.json)?;
    finish_publish(&results, require, options.json)
}

fn endorse_inner(arguments: &[String]) -> Result<(), Failure> {
    let options = parse_options(arguments)?;
    validate_endorse_options(&options)?;
    let d = options.ncc.clone().expect("validated --ncc");
    let created_at = options.published_at.unwrap_or_else(now);
    let status = options
        .status
        .as_deref()
        .map(Status::parse)
        .transpose()
        .map_err(|error| Failure::Usage(error.to_string()))?
        .unwrap_or(Status::Published);
    let content = content_text(&options, "Endorsed.")?;
    let endorses = if options.event.as_deref() == Some("latest") {
        let author = options.author.as_deref().ok_or_else(|| {
            Failure::Usage("endorse --event latest needs --author <pubkey>".to_owned())
        })?;
        let author = normalize_author(author)?;
        let mut pool = connect_relays(&options.relays)?;
        let relays = pool.relay_urls();
        let latest = query_latest(&mut pool, &relays, &d, Some(&author))?;
        format!("event:{}", latest.event_id)
    } else {
        options.event.clone().expect("validated --event")
    };
    let metadata = EndorsementMetadata {
        d: d.clone(),
        endorses,
        status,
        roles: options.roles.clone(),
        implementation: options.implementation.clone(),
        note: options.note.clone(),
        topics: options.topics.clone(),
        content,
    };
    let event = build_endorsement(&metadata, created_at)
        .map_err(|error| Failure::Runtime(error.to_string()))?;
    let events = [EventToPublish {
        label: format!("{d} endorsement"),
        event,
    }];
    if options.dry_run {
        print_dry_run(&events, &options, None);
        return Ok(());
    }
    let signer = load_signer(options.signer_key_env.as_deref())?;
    let mut pool = connect_relays(&options.relays)?;
    let require = options.require_accepted.unwrap_or(1);
    let results = publish_event_list(&events, &mut pool, &signer, options.json)?;
    finish_publish(&results, require, options.json)
}

struct LatestDocument {
    event_id: String,
    author: String,
    created_at: u64,
    title: Option<String>,
    status: Option<String>,
}

fn latest_inner(arguments: &[String]) -> Result<(), Failure> {
    let options = parse_options(arguments)?;
    validate_latest_options(&options)?;
    let ncc = options.ncc.clone().expect("validated --ncc");
    let author = options
        .author
        .as_deref()
        .map(normalize_author)
        .transpose()?;
    let mut pool = connect_relays(&options.relays)?;
    let relays = pool.relay_urls();
    let latest = query_latest(&mut pool, &relays, &ncc, author.as_deref())?;
    if options.json {
        println!(
            "{}",
            serde_json::to_string_pretty(&json!({
                "ncc": &ncc,
                "author": &latest.author,
                "event_id": &latest.event_id,
                "created_at": latest.created_at,
                "title": &latest.title,
                "status": &latest.status,
            }))
            .expect("serializing a JSON value cannot fail")
        );
    } else {
        println!("latest {ncc} document: {}", latest.event_id);
        println!("  author: {}", latest.author);
        println!("  created_at: {}", latest.created_at);
        if let Some(title) = &latest.title {
            println!("  title: {title}");
        }
        if let Some(status) = &latest.status {
            println!("  status: {status}");
        }
    }
    Ok(())
}

fn query_latest<S: SubscriptionHost>(
    host: &mut S,
    relays: &[String],
    ncc: &str,
    author: Option<&str>,
) -> Result<LatestDocument, Failure> {
    let mut events = BTreeSet::new();
    let mut candidates = Vec::new();
    for relay in relays {
        let request = SubscriptionRequest {
            event_type: "NccDocument".to_owned(),
            relayset: Some(relay.clone()),
            kinds: vec![30050],
            tag_equals: vec![("d".to_owned(), ncc.to_owned())],
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
                            if event.unsigned.kind == 30050 && events.insert(event.id.clone()) {
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
                "no kind 30050 document found for d={ncc}{}",
                author.map_or_else(String::new, |author| format!(" and author {author}"))
            ))
        })?;
    Ok(LatestDocument {
        event_id: latest.id,
        author: latest.signer,
        created_at: latest.unsigned.created_at,
        title: tag_value(&latest.unsigned, "title").map(str::to_owned),
        status: tag_value(&latest.unsigned, "status").map(str::to_owned),
    })
}

fn validate_latest_options(options: &Options) -> Result<(), Failure> {
    if options.ncc.is_none() {
        return Err(Failure::Usage("latest needs --ncc <id>".to_owned()));
    }
    if options.relays.is_empty() {
        return Err(Failure::Usage(
            "latest needs at least one --relay <wss://url>".to_owned(),
        ));
    }
    if options.all
        || options.tag.is_some()
        || !options.ids.is_empty()
        || options.version.is_some()
        || options.published_at.is_some()
        || options.require_accepted.is_some()
        || options.include_drafts
        || options.dry_run
        || options.slug.is_some()
        || options.authoritative.is_some()
        || options.event.is_some()
        || options.steward.is_some()
        || options.previous.is_some()
        || options.reason.is_some()
        || options.effective_at.is_some()
        || options.status.is_some()
        || !options.roles.is_empty()
        || options.implementation.is_some()
        || options.note.is_some()
        || !options.topics.is_empty()
        || options.content.is_some()
        || options.content_file.is_some()
        || options.supporting
        || options.succession
        || options.succession_reason.is_some()
        || options.succession_content.is_some()
        || options.signer_key_env.is_some()
    {
        return Err(Failure::Usage(
            "latest accepts --ncc, --author, --relay, --repo, and --json".to_owned(),
        ));
    }
    Ok(())
}

fn normalize_author(value: &str) -> Result<String, Failure> {
    let value = value.trim();
    let bare = value.strip_prefix("pubkey:").unwrap_or(value);
    if bare.len() == 64 && bare.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return Ok(bare.to_ascii_lowercase());
    }
    let npub = value.strip_prefix("npub:").unwrap_or(value);
    if npub.starts_with("npub1") {
        let (hrp, data) = bech32::decode(npub)
            .map_err(|error| Failure::Usage(format!("invalid npub: {error}")))?;
        if hrp.to_string() != "npub" {
            return Err(Failure::Usage("author is not an npub".to_owned()));
        }
        if data.len() != 32 {
            return Err(Failure::Usage(format!(
                "an npub must decode to 32 bytes, found {}",
                data.len()
            )));
        }
        return Ok(hex_encode(&data));
    }
    Err(Failure::Usage(
        "author must be a 64-character pubkey or npub1...".to_owned(),
    ))
}

fn validate_publish_options(options: &Options) -> Result<(), Failure> {
    if options.selectors() > 1 {
        return Err(Failure::Usage(
            "use only one of --all, --tag, or explicit NCC ids".to_owned(),
        ));
    }
    if options.selectors() == 0 {
        return Err(Failure::Usage(
            "select conventions with --all, --tag, or an NCC id".to_owned(),
        ));
    }
    if options.tag.is_some() && options.version.is_some() {
        return Err(Failure::Usage(
            "use --tag or --version, not both".to_owned(),
        ));
    }
    if options.succession && options.selectors() != 1 {
        return Err(Failure::Usage(
            "--succession applies to exactly one selected convention".to_owned(),
        ));
    }
    if !options.succession
        && (options.succession_reason.is_some() || options.succession_content.is_some())
    {
        return Err(Failure::Usage(
            "--succession-reason and --succession-content need --succession".to_owned(),
        ));
    }
    validate_common_publish(options)
}

fn validate_support_options(options: &Options) -> Result<(), Failure> {
    if options.tag.is_some()
        || !options.ids.is_empty()
        || options.version.is_some()
        || options.include_drafts
        || options.supporting
        || options.succession
    {
        return Err(Failure::Usage(
            "support does not accept --tag, NCC ids, --version, --include-drafts, --supporting, or --succession"
                .to_owned(),
        ));
    }
    if options.slug.is_some() && options.ncc.is_none() {
        return Err(Failure::Usage("--slug needs --ncc".to_owned()));
    }
    validate_common_publish(options)
}

fn validate_succession_options(options: &Options) -> Result<(), Failure> {
    if options.ncc.is_none() || options.authoritative.is_none() {
        return Err(Failure::Usage(
            "succession needs --ncc <id> and --authoritative <event-id>".to_owned(),
        ));
    }
    if options.all
        || options.tag.is_some()
        || !options.ids.is_empty()
        || options.version.is_some()
        || options.include_drafts
        || options.slug.is_some()
        || options.event.is_some()
        || options.supporting
        || options.succession
        || options.status.is_some()
        || !options.roles.is_empty()
        || options.implementation.is_some()
        || options.note.is_some()
        || !options.topics.is_empty()
    {
        return Err(Failure::Usage(
            "succession accepts --ncc, --authoritative, --steward, --previous, --reason, --effective-at, --content, and the shared publish options"
                .to_owned(),
        ));
    }
    validate_common_publish(options)
}

fn validate_endorse_options(options: &Options) -> Result<(), Failure> {
    if options.ncc.is_none() || options.event.is_none() {
        return Err(Failure::Usage(
            "endorse needs --ncc <id> and --event <event-id>".to_owned(),
        ));
    }
    if options.event.as_deref() == Some("latest") && options.author.is_none() {
        return Err(Failure::Usage(
            "endorse --event latest needs --author <pubkey>".to_owned(),
        ));
    }
    if options.all
        || options.tag.is_some()
        || !options.ids.is_empty()
        || options.version.is_some()
        || options.include_drafts
        || options.slug.is_some()
        || options.authoritative.is_some()
        || options.steward.is_some()
        || options.previous.is_some()
        || options.reason.is_some()
        || options.effective_at.is_some()
        || options.supporting
        || options.succession
    {
        return Err(Failure::Usage(
            "endorse accepts --ncc, --event, --status, --role, --implementation, --note, --topic, --content, and the shared publish options"
                .to_owned(),
        ));
    }
    validate_common_publish(options)
}

fn validate_common_publish(options: &Options) -> Result<(), Failure> {
    if !options.dry_run {
        if options.relays.is_empty() {
            return Err(Failure::Usage(
                "publishing needs at least one --relay <wss://url>".to_owned(),
            ));
        }
        if options.signer_key_env.is_none() {
            return Err(Failure::Usage(
                "publishing needs --signer-key-env <environment-variable>".to_owned(),
            ));
        }
    }
    Ok(())
}

fn select_for_check(entries: Vec<NccEntry>, options: &Options) -> Result<Vec<NccEntry>, Failure> {
    if let Some(tag) = &options.tag {
        let (id, _version) =
            parse_release_tag(tag).map_err(|error| Failure::Usage(error.to_string()))?;
        return find_one(&entries, &id);
    }
    if options.all || options.ids.is_empty() {
        return Ok(entries);
    }
    find_ids(&entries, &options.ids)
}

fn select_for_publish(
    entries: Vec<NccEntry>,
    options: &Options,
) -> Result<(Vec<NccEntry>, Option<String>), Failure> {
    if let Some(tag) = &options.tag {
        let (id, version) =
            parse_release_tag(tag).map_err(|error| Failure::Usage(error.to_string()))?;
        let entry = find_one(&entries, &id)?.remove(0);
        return Ok((vec![entry], Some(version)));
    }
    if options.all {
        let selected = if options.include_drafts {
            entries
        } else {
            entries
                .into_iter()
                .filter(|entry| entry.metadata.status != Status::Draft)
                .collect()
        };
        if selected.is_empty() {
            return Err(Failure::Runtime(
                "no published conventions selected; pass --include-drafts to include drafts"
                    .to_owned(),
            ));
        }
        return Ok((selected, None));
    }
    find_ids(&entries, &options.ids).map(|entries| (entries, None))
}

fn select_supporting(
    entries: Vec<SupportingEntry>,
    options: &Options,
) -> Result<Vec<SupportingEntry>, Failure> {
    let selected = entries
        .into_iter()
        .filter(|entry| {
            options.ncc.as_ref().is_none_or(|ncc| &entry.ncc_id == ncc)
                && options.slug.as_ref().is_none_or(|slug| &entry.slug == slug)
        })
        .collect::<Vec<_>>();
    if selected.is_empty() {
        return Err(Failure::Runtime(
            "no supporting documents matched the selection".to_owned(),
        ));
    }
    Ok(selected)
}

fn find_one(entries: &[NccEntry], id: &str) -> Result<Vec<NccEntry>, Failure> {
    entries
        .iter()
        .find(|entry| entry.id == id)
        .cloned()
        .map(|entry| vec![entry])
        .ok_or_else(|| Failure::Usage(format!("unknown NCC `{id}`")))
}

fn find_ids(entries: &[NccEntry], ids: &[String]) -> Result<Vec<NccEntry>, Failure> {
    ids.iter()
        .map(|id| {
            entries
                .iter()
                .find(|entry| &entry.id == id)
                .cloned()
                .ok_or_else(|| Failure::Usage(format!("unknown NCC `{id}`")))
        })
        .collect()
}

fn print_dry_run(
    events: &[EventToPublish],
    options: &Options,
    succession: Option<&DryRunSuccession>,
) {
    if options.json {
        let events = events
            .iter()
            .map(|item| {
                json!({
                    "label": &item.label,
                    "id": tag_value(&item.event, "d"),
                    "version": tag_value(&item.event, "version"),
                    "event_type": &item.event.event_type,
                    "kind": item.event.kind,
                    "tags": item.event.wire_tags(),
                    "content_bytes": item.event.content.len(),
                    "published_at": item.event.created_at,
                })
            })
            .collect::<Vec<_>>();
        let mut object = json!({ "events": events });
        if let Some(succession) = succession {
            object["succession"] = json!({
                "d": &succession.d,
                "authoritative": "event:<document-event-id>",
                "reason": &succession.reason,
                "content": &succession.content,
            });
        }
        println!(
            "{}",
            serde_json::to_string_pretty(&object).expect("serializing a JSON value cannot fail")
        );
        return;
    }
    for item in events {
        println!(
            "{}: kind {}, {} bytes, {} tags",
            item.label,
            item.event.kind,
            item.event.content.len(),
            item.event.tags.len()
        );
        println!(
            "  tags: {}",
            serde_json::to_string(&item.event.wire_tags())
                .expect("serializing a JSON value cannot fail")
        );
    }
    if let Some(succession) = succession {
        println!(
            "succession: {} will reference event:<document-event-id>",
            succession.d
        );
    }
    if !options.relays.is_empty() {
        println!("relays: {}", options.relays.join(", "));
    }
}

fn tag_value<'a>(event: &'a UnsignedEvent, name: &str) -> Option<&'a str> {
    event
        .tags
        .iter()
        .find(|(tag, _)| tag == name)
        .map(|(_, value)| value.as_str())
}

fn content_text(options: &Options, default: &str) -> Result<String, Failure> {
    if options.content.is_some() && options.content_file.is_some() {
        return Err(Failure::Usage(
            "use --content or --content-file, not both".to_owned(),
        ));
    }
    if let Some(path) = &options.content_file {
        return fs::read_to_string(path)
            .map_err(|error| Failure::Runtime(format!("cannot read {}: {error}", path.display())));
    }
    Ok(options
        .content
        .clone()
        .unwrap_or_else(|| default.to_owned()))
}

fn default_succession_content() -> String {
    "Steward acknowledges the authoritative NCC document.".to_owned()
}

fn repository(options: &Options) -> PathBuf {
    options.repo.clone().unwrap_or_else(|| PathBuf::from("."))
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
            "--all" => {
                options.all = true;
                index += 1;
            }
            "--tag" => {
                options.tag = Some(option_value(arguments, &mut index, argument)?);
            }
            "--relay" => {
                options
                    .relays
                    .push(option_value(arguments, &mut index, argument)?);
            }
            "--signer-key-env" => {
                options.signer_key_env = Some(option_value(arguments, &mut index, argument)?);
            }
            "--version" => {
                options.version = Some(option_value(arguments, &mut index, argument)?);
            }
            "--published-at" => {
                let value = option_value(arguments, &mut index, argument)?;
                options.published_at = Some(parse_u64(&value, argument)?);
            }
            "--require-accepted" => {
                let value = option_value(arguments, &mut index, argument)?;
                options.require_accepted = Some(parse_usize(&value, argument)?);
            }
            "--include-drafts" => {
                options.include_drafts = true;
                index += 1;
            }
            "--dry-run" => {
                options.dry_run = true;
                index += 1;
            }
            "--json" => {
                options.json = true;
                index += 1;
            }
            "--ncc" => {
                options.ncc = Some(option_value(arguments, &mut index, argument)?);
            }
            "--author" => {
                options.author = Some(option_value(arguments, &mut index, argument)?);
            }
            "--slug" => {
                options.slug = Some(option_value(arguments, &mut index, argument)?);
            }
            "--authoritative" => {
                options.authoritative = Some(option_value(arguments, &mut index, argument)?);
            }
            "--event" => {
                options.event = Some(option_value(arguments, &mut index, argument)?);
            }
            "--steward" => {
                options.steward = Some(option_value(arguments, &mut index, argument)?);
            }
            "--previous" => {
                options.previous = Some(option_value(arguments, &mut index, argument)?);
            }
            "--reason" => {
                options.reason = Some(option_value(arguments, &mut index, argument)?);
            }
            "--effective-at" => {
                let value = option_value(arguments, &mut index, argument)?;
                options.effective_at = Some(parse_u64(&value, argument)?);
            }
            "--status" => {
                options.status = Some(option_value(arguments, &mut index, argument)?);
            }
            "--role" => {
                options
                    .roles
                    .push(option_value(arguments, &mut index, argument)?);
            }
            "--implementation" => {
                options.implementation = Some(option_value(arguments, &mut index, argument)?);
            }
            "--note" => {
                options.note = Some(option_value(arguments, &mut index, argument)?);
            }
            "--topic" => {
                options
                    .topics
                    .push(option_value(arguments, &mut index, argument)?);
            }
            "--content" => {
                options.content = Some(option_value(arguments, &mut index, argument)?);
            }
            "--content-file" => {
                options.content_file = Some(PathBuf::from(option_value(
                    arguments, &mut index, argument,
                )?));
            }
            "--supporting" => {
                options.supporting = true;
                index += 1;
            }
            "--succession" => {
                options.succession = true;
                index += 1;
            }
            "--succession-reason" => {
                options.succession_reason = Some(option_value(arguments, &mut index, argument)?);
            }
            "--succession-content" => {
                options.succession_content = Some(option_value(arguments, &mut index, argument)?);
            }
            other if other.starts_with('-') => {
                return Err(Failure::Usage(format!("unknown ncc option `{other}`")));
            }
            other => {
                options.ids.push(other.to_owned());
                index += 1;
            }
        }
    }
    Ok(options)
}

fn usage() {
    eprintln!(
        "usage:\n  nscript ncc check [--repo <directory>] [--all | <ncc-id>... | --tag <tag>] [--json]\n  nscript ncc publish [--repo <directory>] [--all | <ncc-id>... | --tag <tag> | --version <version>] [--supporting] [--succession [--succession-reason <text>] [--succession-content <text>]] --relay <wss://url>... --signer-key-env <environment-variable> [--published-at <seconds>] [--require-accepted <n>] [--include-drafts] [--dry-run] [--json]\n  nscript ncc support [--repo <directory>] [--ncc <id>] [--slug <slug>] --relay <wss://url>... --signer-key-env <environment-variable> [--published-at <seconds>] [--require-accepted <n>] [--dry-run] [--json]\n  nscript ncc succession --repo <directory> --ncc <id> --authoritative <event-id|latest> [--author <pubkey|npub>] [--steward <key>] [--previous <event-id>] [--reason <text>] [--effective-at <seconds>] [--content <text> | --content-file <path>] --relay <wss://url>... --signer-key-env <environment-variable> [--published-at <seconds>] [--require-accepted <n>] [--dry-run] [--json]\n  nscript ncc latest --ncc <id> [--author <pubkey|npub>] --relay <wss://url>... [--json]\n  nscript ncc endorse --repo <directory> --ncc <id> --event <event-id|latest> [--author <pubkey|npub>] [--status <status>] [--role <role>]... [--implementation <text>] [--note <text>] [--topic <topic>]... [--content <text> | --content-file <path>] --relay <wss://url>... --signer-key-env <environment-variable> [--published-at <seconds>] [--require-accepted <n>] [--dry-run] [--json]"
    );
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::publish::{
        LocalSigner, decode_hex, decode_hex_32, parse_secret_key, publish_one, sign_event,
    };
    use nscript_host_crypto::group_key::xonly_pubkey;
    use nscript_host_crypto::schnorr::verify;
    use nscript_ncc::{Metadata, SupportingMetadata};
    use nscript_runtime::SignedEvent;

    #[test]
    fn parses_hex_and_nsec_keys() {
        let hex = "0000000000000000000000000000000000000000000000000000000000000001";
        assert_eq!(parse_secret_key(hex).unwrap(), decode_hex_32(hex).unwrap());

        let secret = [1_u8; 32];
        let nsec = bech32::encode::<bech32::Bech32>(
            bech32::Hrp::parse("nsec").expect("valid hrp"),
            &secret,
        )
        .expect("valid nsec");
        assert_eq!(parse_secret_key(&nsec).unwrap(), secret);

        assert!(parse_secret_key("nsec1invalid").is_err());
        assert!(parse_secret_key("not-a-key").is_err());
    }

    #[test]
    fn signs_and_verifies_an_event() {
        let secret = [1_u8; 32];
        let public_key = xonly_pubkey(&secret).unwrap();
        let public_key_hex = hex_encode(&public_key);
        let unsigned = UnsignedEvent {
            event_type: "NccDocument".to_owned(),
            kind: 30050,
            content: "# Test\n".to_owned(),
            tags: vec![("d".to_owned(), "ncc-00".to_owned())],
            created_at: 1_766_012_345,
        };
        let signed = sign_event(&unsigned, &secret, &public_key, &public_key_hex).unwrap();
        assert_eq!(signed.signer, public_key_hex);
        assert_eq!(signed.id.len(), 64);
        assert_eq!(signed.signature.len(), 128);
        assert!(verify(
            &public_key,
            &decode_hex_32(&signed.id).unwrap(),
            &decode_hex::<64>(&signed.signature).unwrap()
        ));
    }

    fn signed_document(id: &str, created_at: u64) -> SignedEvent {
        SignedEvent {
            unsigned: UnsignedEvent {
                event_type: "NccDocument".to_owned(),
                kind: 30050,
                content: String::new(),
                tags: vec![
                    ("d".to_owned(), "ncc-00".to_owned()),
                    ("title".to_owned(), format!("title-{created_at}")),
                    ("status".to_owned(), "published".to_owned()),
                ],
                created_at,
            },
            signer: "b".repeat(64),
            id: id.to_owned(),
            signature: "sig".to_owned(),
        }
    }

    #[test]
    fn query_latest_selects_the_newest_document() {
        let mut relay = nscript_runtime::FakeRelayHost::default();
        relay.queued_events.insert(
            1,
            vec![
                signed_document("old", 1_766_000_000),
                signed_document("new", 1_766_000_100),
            ],
        );
        let latest = query_latest(
            &mut relay,
            &["wss://relay.example".to_owned()],
            "ncc-00",
            Some("bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"),
        )
        .unwrap();
        assert_eq!(latest.event_id, "new");
        assert_eq!(latest.title.as_deref(), Some("title-1766000100"));
        assert_eq!(latest.status.as_deref(), Some("published"));
    }

    #[test]
    fn query_latest_breaks_ties_by_lowest_event_id() {
        let mut relay = nscript_runtime::FakeRelayHost::default();
        relay.queued_events.insert(
            1,
            vec![
                signed_document("bbbb", 1_766_000_000),
                signed_document("aaaa", 1_766_000_000),
            ],
        );
        let latest = query_latest(
            &mut relay,
            &["wss://relay.example".to_owned()],
            "ncc-00",
            None,
        )
        .unwrap();
        assert_eq!(latest.event_id, "aaaa");
    }

    #[test]
    fn normalizes_author_pubkeys_and_npubs() {
        let hex = "b5d34eedc7d8f81ceaa5ed377b5a2d534ee949fae0c5ab3bae0a576aa7475cbf";
        assert_eq!(normalize_author(hex).unwrap(), hex);
        assert_eq!(
            normalize_author("npub1khf5amw8mrupe649a5mhkk3d2d8wjj06urz6kwawpftk4f68tjlstdmd3q")
                .unwrap(),
            hex
        );
        assert!(normalize_author("not-an-author").is_err());
    }

    #[test]
    fn rejects_invalid_hex() {
        assert!(decode_hex_32("00").is_err());
        assert!(decode_hex_32(&"z".repeat(64)).is_err());
    }

    #[test]
    fn requires_exactly_one_selector() {
        let mut options = Options::default();
        assert!(validate_publish_options(&options).is_err());
        options.all = true;
        options.ids.push("ncc-00".to_owned());
        assert!(validate_publish_options(&options).is_err());
    }

    fn sample_entry() -> NccEntry {
        NccEntry {
            id: "ncc-00".to_owned(),
            directory: PathBuf::from("ncc-00"),
            metadata: Metadata {
                title: "Test NCC".to_owned(),
                summary: None,
                status: Status::Published,
                topics: vec![],
                lang: None,
                version: None,
                license: None,
                authors: vec![],
                supersedes: vec![],
            },
            content: "# Test NCC\n".to_owned(),
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
                title: "Implementation".to_owned(),
                status: Status::Published,
                doc_type: Some("implementation".to_owned()),
                lang: None,
                topics: vec![],
                authors: vec![],
                license: None,
                for_event: None,
                published_at: None,
            },
            content: "# Implementation\n".to_owned(),
        }
    }

    #[test]
    fn publish_one_signs_and_counts_acceptance() {
        let event = build_document(&sample_entry(), 1_766_012_345, None).unwrap();
        let item = EventToPublish {
            label: "ncc-00 document".to_owned(),
            event,
        };
        let signer = LocalSigner {
            secret: [1_u8; 32],
            public_key: xonly_pubkey(&[1_u8; 32]).unwrap(),
            public_key_hex: hex_encode(&xonly_pubkey(&[1_u8; 32]).unwrap()),
        };
        let mut relay = nscript_runtime::FakeRelayHost {
            relays: [("fake://public".to_owned(), true)].into_iter().collect(),
            ..nscript_runtime::FakeRelayHost::default()
        };
        let published = publish_one(&item, &mut relay, &signer, false).unwrap();
        assert_eq!(published.accepted, 1);
        assert_eq!(published.kind, 30050);
        assert_eq!(relay.published.len(), 1);
        assert_eq!(relay.published[0].signer, signer.public_key_hex);
    }

    #[test]
    fn publish_one_counts_a_rejected_relay() {
        let event = build_supporting_document(&sample_supporting(), 1_766_012_345).unwrap();
        let item = EventToPublish {
            label: "ncc-00 supporting ncc-00-implementation".to_owned(),
            event,
        };
        let signer = LocalSigner {
            secret: [1_u8; 32],
            public_key: xonly_pubkey(&[1_u8; 32]).unwrap(),
            public_key_hex: hex_encode(&xonly_pubkey(&[1_u8; 32]).unwrap()),
        };
        let mut relay = nscript_runtime::FakeRelayHost {
            relays: [("fake://public".to_owned(), false)].into_iter().collect(),
            ..nscript_runtime::FakeRelayHost::default()
        };
        let published = publish_one(&item, &mut relay, &signer, false).unwrap();
        assert_eq!(published.accepted, 0);
        assert_eq!(relay.published, Vec::new());
    }
}
