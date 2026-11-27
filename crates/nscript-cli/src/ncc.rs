//! Repository-facing `NCC-00` publication commands.

use std::env;
use std::fmt::Write as _;
use std::path::PathBuf;
use std::process::ExitCode;
use std::time::{SystemTime, UNIX_EPOCH};

use nscript_host_crypto::group_key::xonly_pubkey;
use nscript_host_crypto::schnorr::{sign_random, verify};
use nscript_ncc::{NccEntry, Status, build_document, discover, parse_release_tag};
use nscript_runtime::{RealRelayPool, RelayHost, SignedEvent, UnsignedEvent, compute_event_id};
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
        _ => {
            usage();
            ExitCode::from(2)
        }
    }
}

#[derive(Debug)]
enum Failure {
    Usage(String),
    Runtime(String),
}

impl Failure {
    fn message(&self) -> &str {
        match self {
            Self::Usage(message) | Self::Runtime(message) => message,
        }
    }

    fn exit_code(&self) -> u8 {
        match self {
            Self::Usage(_) => 2,
            Self::Runtime(_) => 1,
        }
    }
}

fn finish(result: Result<(), Failure>) -> ExitCode {
    match result {
        Ok(()) => ExitCode::SUCCESS,
        Err(failure) => {
            eprintln!("error: {}", failure.message());
            ExitCode::from(failure.exit_code())
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
}

impl Options {
    fn has_publish_only_options(&self) -> bool {
        !self.relays.is_empty()
            || self.signer_key_env.is_some()
            || self.version.is_some()
            || self.published_at.is_some()
            || self.require_accepted.is_some()
            || self.dry_run
    }

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
}

fn check_inner(arguments: &[String]) -> Result<(), Failure> {
    let options = parse_options(arguments)?;
    if options.has_publish_only_options() {
        return Err(Failure::Usage(
            "check does not accept --relay, --signer-key-env, --published-at, --require-accepted, or --dry-run"
                .to_owned(),
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
                })
            })
            .collect::<Vec<_>>();
        println!(
            "{}",
            serde_json::to_string_pretty(&json!({ "conventions": conventions }))
                .expect("serializing a JSON value cannot fail")
        );
    } else {
        for entry in &selected {
            println!(
                "{}: ok ({}; {} bytes)",
                entry.id,
                entry.metadata.status.as_str(),
                entry.content.len()
            );
        }
        println!("checked {} convention(s)", selected.len());
    }
    Ok(())
}

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
    if options.version.is_some() && selected.len() != 1 {
        return Err(Failure::Usage(
            "--version applies to exactly one selected convention".to_owned(),
        ));
    }
    let version_override = options.version.clone().or(tag_version);
    let published_at = options.published_at.unwrap_or_else(now);
    if published_at == 0 {
        return Err(Failure::Runtime(
            "published_at resolved to zero; pass --published-at <seconds>".to_owned(),
        ));
    }
    let documents = selected
        .iter()
        .map(|entry| {
            build_document(entry, published_at, version_override.as_deref())
                .map(|event| (entry, event))
                .map_err(|error| Failure::Runtime(error.to_string()))
        })
        .collect::<Result<Vec<_>, _>>()?;

    if options.dry_run {
        print_dry_run(&documents, &options);
        return Ok(());
    }

    let Some(key_name) = &options.signer_key_env else {
        return Err(Failure::Usage(
            "publish needs --signer-key-env <environment-variable>".to_owned(),
        ));
    };
    let raw_key = env::var(key_name).map_err(|_| {
        Failure::Usage(format!(
            "environment variable `{key_name}` is not set; pass --signer-key-env with the variable that holds the key"
        ))
    })?;
    if raw_key.trim().is_empty() {
        return Err(Failure::Usage(format!(
            "environment variable `{key_name}` is empty"
        )));
    }
    let secret = parse_secret_key(&raw_key).map_err(Failure::Runtime)?;
    let public_key = xonly_pubkey(&secret)
        .map_err(|error| Failure::Runtime(format!("invalid key: {error:?}")))?;
    let public_key_hex = hex_encode(&public_key);
    let mut pool = connect_relays(&options.relays)?;
    let require = options.require_accepted.unwrap_or(1);
    let failures = publish_documents(
        &documents,
        &mut pool,
        &secret,
        &public_key,
        &public_key_hex,
        require,
        options.json,
    )?;
    if failures > 0 {
        return Err(Failure::Runtime(format!(
            "{failures} document(s) were accepted by fewer than {require} relay(s)"
        )));
    }
    Ok(())
}

fn connect_relays(relays: &[String]) -> Result<RealRelayPool, Failure> {
    let mut pool = RealRelayPool::new();
    let mut connected = 0_usize;
    for relay in relays {
        match pool.add_relay(relay.clone()) {
            Ok(()) => {
                connected += 1;
                println!("connected: {relay}");
            }
            Err(error) => eprintln!("warning: could not connect to {relay}: {error:?}"),
        }
    }
    if connected == 0 {
        return Err(Failure::Runtime(
            "could not connect to any relay; no event was attempted".to_owned(),
        ));
    }
    Ok(pool)
}

fn publish_documents<R: RelayHost>(
    documents: &[(&NccEntry, UnsignedEvent)],
    pool: &mut R,
    secret: &[u8; 32],
    public_key: &[u8; 32],
    public_key_hex: &str,
    require: usize,
    json_output: bool,
) -> Result<usize, Failure> {
    let mut failures = 0_usize;
    let mut results = Vec::new();
    for (entry, unsigned) in documents {
        let signed =
            sign_event(unsigned, secret, public_key, public_key_hex).map_err(Failure::Runtime)?;
        let report = pool.publish(0, &signed, "public").map_err(|error| {
            Failure::Runtime(format!("publishing {} failed: {error:?}", entry.id))
        })?;
        let accepted = report
            .outcomes
            .iter()
            .filter(|outcome| outcome.accepted)
            .count();
        if accepted < require {
            failures += 1;
        }
        if json_output {
            results.push(json!({
                "id": &entry.id,
                "event_id": &signed.id,
                "accepted": accepted,
                "total": report.outcomes.len(),
                "relays": report.outcomes.iter().map(|outcome| json!({
                    "relay": &outcome.relay,
                    "accepted": outcome.accepted,
                    "detail": &outcome.detail,
                })).collect::<Vec<_>>(),
            }));
        } else {
            println!(
                "{}: event {} accepted {accepted}/{} relays",
                entry.id,
                signed.id,
                report.outcomes.len()
            );
            for outcome in &report.outcomes {
                if !outcome.accepted {
                    eprintln!("  {}: {}", outcome.relay, outcome.detail);
                }
            }
        }
    }
    if json_output {
        println!(
            "{}",
            serde_json::to_string_pretty(&json!({ "published": results }))
                .expect("serializing a JSON value cannot fail")
        );
    }
    Ok(failures)
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
    if !options.dry_run {
        if options.relays.is_empty() {
            return Err(Failure::Usage(
                "publish needs at least one --relay <wss://url>".to_owned(),
            ));
        }
        if options.signer_key_env.is_none() {
            return Err(Failure::Usage(
                "publish needs --signer-key-env <environment-variable>".to_owned(),
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

fn print_dry_run(documents: &[(&NccEntry, UnsignedEvent)], options: &Options) {
    if options.json {
        let documents = documents
            .iter()
            .map(|(entry, event)| {
                json!({
                    "id": &entry.id,
                    "event_type": &event.event_type,
                    "kind": event.kind,
                    "tags": event.wire_tags(),
                    "content_bytes": event.content.len(),
                    "published_at": event.created_at,
                    "version": tag_value(event, "version"),
                    "relays": &options.relays,
                })
            })
            .collect::<Vec<_>>();
        println!(
            "{}",
            serde_json::to_string_pretty(&json!({ "documents": documents }))
                .expect("serializing a JSON value cannot fail")
        );
        return;
    }
    for (entry, event) in documents {
        println!(
            "{}: kind {}, {} bytes, {} tags",
            entry.id,
            event.kind,
            event.content.len(),
            event.tags.len()
        );
        println!(
            "  tags: {}",
            serde_json::to_string(&event.wire_tags())
                .expect("serializing a JSON value cannot fail")
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

fn sign_event(
    unsigned: &UnsignedEvent,
    secret: &[u8; 32],
    public_key: &[u8; 32],
    public_key_hex: &str,
) -> Result<SignedEvent, String> {
    let id = compute_event_id(public_key_hex, unsigned);
    let id_bytes = decode_hex_32(&id)?;
    let signature = sign_random(secret, &id_bytes)
        .map_err(|error| format!("could not sign {}: {error:?}", unsigned.event_type))?;
    if !verify(public_key, &id_bytes, &signature) {
        return Err("the local signer produced a signature that does not verify".to_owned());
    }
    Ok(SignedEvent {
        unsigned: unsigned.clone(),
        signer: public_key_hex.to_owned(),
        id,
        signature: hex_encode(&signature),
    })
}

fn parse_secret_key(raw: &str) -> Result<[u8; 32], String> {
    let raw = raw.trim();
    if raw.len() == 64 && raw.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return decode_hex_32(raw);
    }
    if raw.starts_with("nsec1") {
        let (hrp, data) = bech32::decode(raw).map_err(|error| format!("invalid nsec: {error}"))?;
        if hrp.to_string() != "nsec" {
            return Err("the provided key is not an nsec".to_owned());
        }
        if data.len() != 32 {
            return Err(format!(
                "an nsec must decode to 32 bytes, found {}",
                data.len()
            ));
        }
        let mut key = [0_u8; 32];
        key.copy_from_slice(&data);
        return Ok(key);
    }
    Err("signing key must be 64 hexadecimal characters or an nsec1... string".to_owned())
}

fn decode_hex_32(text: &str) -> Result<[u8; 32], String> {
    decode_hex::<32>(text)
}

fn decode_hex<const N: usize>(text: &str) -> Result<[u8; N], String> {
    if text.len() != N * 2 {
        return Err(format!(
            "expected {} hexadecimal characters, found {}",
            N * 2,
            text.len()
        ));
    }
    let mut bytes = [0_u8; N];
    for (index, chunk) in text.as_bytes().chunks_exact(2).enumerate() {
        let pair = std::str::from_utf8(chunk)
            .map_err(|_| "the hexadecimal value contains non-UTF-8 bytes".to_owned())?;
        bytes[index] = u8::from_str_radix(pair, 16)
            .map_err(|_| format!("invalid hexadecimal byte `{pair}`"))?;
    }
    Ok(bytes)
}

fn hex_encode(bytes: &[u8]) -> String {
    let mut output = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        write!(output, "{byte:02x}").expect("writing to a String cannot fail");
    }
    output
}

fn now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |duration| duration.as_secs())
}

fn repository(options: &Options) -> PathBuf {
    options.repo.clone().unwrap_or_else(|| PathBuf::from("."))
}

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

fn option_value(arguments: &[String], index: &mut usize, flag: &str) -> Result<String, Failure> {
    let Some(value) = arguments.get(*index + 1) else {
        return Err(Failure::Usage(format!("{flag} needs a value")));
    };
    *index += 2;
    Ok(value.clone())
}

fn parse_u64(value: &str, flag: &str) -> Result<u64, Failure> {
    value.parse().map_err(|_| {
        Failure::Usage(format!(
            "{flag} expects a non-negative integer, found `{value}`"
        ))
    })
}

fn parse_usize(value: &str, flag: &str) -> Result<usize, Failure> {
    value.parse().map_err(|_| {
        Failure::Usage(format!(
            "{flag} expects a non-negative integer, found `{value}`"
        ))
    })
}

fn usage() {
    eprintln!(
        "usage:\n  nscript ncc check [--repo <directory>] [--all | <ncc-id>... | --tag <tag>] [--json]\n  nscript ncc publish [--repo <directory>] [--all | <ncc-id>... | --tag <tag> | --version <version>] --relay <wss://url>... --signer-key-env <environment-variable> [--published-at <seconds>] [--require-accepted <n>] [--include-drafts] [--dry-run] [--json]"
    );
}

#[cfg(test)]
mod tests {
    use super::*;
    use nscript_ncc::Metadata;

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

    #[test]
    fn publish_documents_signs_and_counts_acceptance() {
        let entry = sample_entry();
        let unsigned = build_document(&entry, 1_766_012_345, None).unwrap();
        let documents = [(&entry, unsigned)];
        let secret = [1_u8; 32];
        let public_key = xonly_pubkey(&secret).unwrap();
        let public_key_hex = hex_encode(&public_key);
        let mut relay = nscript_runtime::FakeRelayHost {
            relays: [("fake://public".to_owned(), true)].into_iter().collect(),
            ..nscript_runtime::FakeRelayHost::default()
        };
        let failures = publish_documents(
            &documents,
            &mut relay,
            &secret,
            &public_key,
            &public_key_hex,
            1,
            false,
        )
        .unwrap();
        assert_eq!(failures, 0);
        assert_eq!(relay.published.len(), 1);
        assert_eq!(relay.published[0].signer, public_key_hex);
        assert_eq!(relay.published[0].unsigned.kind, 30050);
    }

    #[test]
    fn publish_documents_counts_a_rejected_relay() {
        let entry = sample_entry();
        let unsigned = build_document(&entry, 1_766_012_345, None).unwrap();
        let documents = [(&entry, unsigned)];
        let secret = [1_u8; 32];
        let public_key = xonly_pubkey(&secret).unwrap();
        let public_key_hex = hex_encode(&public_key);
        let mut relay = nscript_runtime::FakeRelayHost {
            relays: [("fake://public".to_owned(), false)].into_iter().collect(),
            ..nscript_runtime::FakeRelayHost::default()
        };
        let failures = publish_documents(
            &documents,
            &mut relay,
            &secret,
            &public_key,
            &public_key_hex,
            1,
            false,
        )
        .unwrap();
        assert_eq!(failures, 1);
        assert!(relay.published.is_empty());
    }
}
