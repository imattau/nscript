//! Interop against a live Concord community from an invite link.
//!
//! * `read`    fetch the bundle, read and verify the Control Plane. Read-only.
//! * `history` also read and decrypt the public channel's chat. Read-only.
//! * `ops`     read the public channel through the real `concord01` host
//!   operations (`unwrap_stream`, `open_message`). Read-only.
//! * `publish` send ONE message through the real `publish_message` operation:
//!   the runtime's policy gate, then `RealRelayPool` over TLS.
//! * `whoami`  print the roster and what the identity in `<keyfile>` may do
//!   (rank, permission bits, staff). Read-only.
//! * `post`    join the Guestbook and post a few messages as a throwaway
//!   identity kept in `<keyfile>` (created if absent, never printed).
//!
//! Usage: `concord_interop <mode> <link_signer_hex> <fragment> [keyfile]`

mod common;

use std::time::{SystemTime, UNIX_EPOCH};

use nscript_host_crypto::group_key::{GroupKey, group_key, xonly_pubkey};
use nscript_host_crypto::stream::{
    SealForm, build_stream_event_with_tags, open_stream_event, rumor,
};
use nscript_host_crypto::{nip44, random32};
use nscript_runtime::authority::AuthorityFold;
use nscript_runtime::community::{parse_channel_metadata, parse_community_metadata};
use nscript_runtime::edition::{FoldMode, VSK_CHANNEL_METADATA, VSK_COMMUNITY_METADATA, VSK_ROLE};
use nscript_runtime::expiry::expiration_tag;
use nscript_runtime::invite::{CommunityInvite, bundle_key, decode_fragment, parse_invite};
use nscript_runtime::wire::parse_edition_rumor;
use serde_json::{Value, json};

use common::{hex, publish, query, unhex32};

struct Loaded {
    invite: CommunityInvite,
    authority: AuthorityFold,
    timer: Option<u64>,
}

fn load(signer: &str, fragment: &str) -> Loaded {
    let fragment = decode_fragment(fragment).expect("fragment");
    let bundle = fragment
        .relays
        .iter()
        .find_map(|relay| {
            query(
                relay,
                &json!({"kinds": [33301], "authors": [signer], "#d": [""]}),
            )
            .ok()?
            .into_iter()
            .next()
        })
        .expect("bundle");
    let plaintext = nip44::decrypt(
        &bundle_key(&fragment.token),
        bundle["content"].as_str().unwrap(),
    )
    .expect("bundle decrypts");
    let invite = parse_invite(&String::from_utf8(plaintext).unwrap()).expect("bundle validates");
    let root = unhex32(invite.community_root());
    let cid = unhex32(&invite.community_id);
    let control_pk = unhex32(invite.control_pk.as_ref().expect("split community"));
    let read = group_key("concord/control", &root, &cid, Some(invite.root_epoch));

    let mut wraps = Vec::new();
    for relay in &invite.relays {
        if let Ok(found) = query(
            relay,
            &json!({"kinds": [1059], "authors": [hex(&control_pk)]}),
        ) {
            wraps.extend(found);
        }
    }
    let mut authority = AuthorityFold::new(
        &invite.owner,
        &invite.owner_salt,
        &invite.community_id,
        FoldMode::FreshJoiner,
        4096,
    )
    .expect("owner verifies");
    let mut seen = std::collections::BTreeSet::new();
    let (mut opened, mut refused) = (0, 0);
    for wrap in wraps {
        if !seen.insert(wrap["id"].as_str().unwrap_or("").to_owned()) {
            continue;
        }
        match open_stream_event(
            &control_pk,
            &read.conversation_key(),
            SealForm::Plaintext,
            &wrap.to_string(),
        ) {
            Ok(event) => {
                opened += 1;
                if let Ok(edition) = parse_edition_rumor(&event.author, &event.rumor_json) {
                    authority.insert(edition);
                }
            }
            Err(_) => refused += 1,
        }
    }
    println!("control plane: {opened} wraps opened, {refused} refused");
    let timer = authority
        .heads(VSK_COMMUNITY_METADATA)
        .iter()
        .find_map(|head| parse_community_metadata(&head.content))
        .and_then(|meta| meta.message_expiration);
    Loaded {
        invite,
        authority,
        timer,
    }
}

fn print_structure(loaded: &Loaded) {
    for head in loaded.authority.heads(VSK_COMMUNITY_METADATA) {
        if let Some(meta) = parse_community_metadata(&head.content) {
            println!(
                "community '{}' (metadata v{}), message_expiration {:?}",
                meta.name, head.version, meta.message_expiration
            );
        }
    }
    for head in loaded.authority.heads(VSK_CHANNEL_METADATA) {
        if let Some((channel, deleted)) = parse_channel_metadata(&head.entity_id, &head.content) {
            println!(
                "channel '{}' {} private={} deleted={deleted}",
                channel.name, channel.channel_id, channel.private
            );
        }
    }
    println!("roles: {}", loaded.authority.heads(VSK_ROLE).len());
}

fn public_channel(loaded: &Loaded, name: &str) -> String {
    loaded
        .authority
        .heads(VSK_CHANNEL_METADATA)
        .iter()
        .find_map(|head| {
            let (channel, deleted) = parse_channel_metadata(&head.entity_id, &head.content)?;
            (channel.name == name && !channel.private && !deleted).then_some(channel.channel_id)
        })
        .expect("public channel")
}

fn channel_key(loaded: &Loaded, channel_id: &str) -> GroupKey {
    // A Public Channel's key derives from the community_root (CORD-03 §1).
    group_key(
        "concord/channel",
        &unhex32(loaded.invite.community_root()),
        &unhex32(channel_id),
        Some(loaded.invite.root_epoch),
    )
}

fn now() -> (u64, u64) {
    let elapsed = SystemTime::now().duration_since(UNIX_EPOCH).expect("clock");
    (elapsed.as_secs(), u64::from(elapsed.subsec_millis()))
}

fn history(loaded: &Loaded, channel_id: &str) -> Vec<(String, Value)> {
    let key = channel_key(loaded, channel_id);
    let mut out = Vec::new();
    let mut seen = std::collections::BTreeSet::new();
    for relay in &loaded.invite.relays {
        let Ok(found) = query(
            relay,
            &json!({"kinds": [1059], "authors": [hex(&key.xonly_pubkey())], "limit": 200}),
        ) else {
            continue;
        };
        for wrap in found {
            if !seen.insert(wrap["id"].as_str().unwrap_or("").to_owned()) {
                continue;
            }
            if let Ok(event) = open_stream_event(
                &key.xonly_pubkey(),
                &key.conversation_key(),
                SealForm::Encrypted,
                &wrap.to_string(),
            ) && let Ok(rumor) = serde_json::from_str::<Value>(&event.rumor_json)
            {
                out.push((event.author, rumor));
            }
        }
    }
    out.sort_by_key(|(_, r)| r["created_at"].as_u64().unwrap_or(0));
    out
}

fn short(text: &str) -> String {
    text.chars().take(8).collect()
}

fn print_history(loaded: &Loaded, channel_id: &str) {
    let messages = history(loaded, channel_id);
    println!(
        "--- #{} history: {} events ---",
        short(channel_id),
        messages.len()
    );
    for (author, rumor) in &messages {
        println!(
            "[{}] kind {} from {}…: {}",
            rumor["created_at"],
            rumor["kind"],
            short(author),
            rumor["content"].as_str().unwrap_or("").replace('\n', " ⏎ ")
        );
    }
}

/// Reads the channel through the real host operations rather than the
/// lower-level stream functions.
fn ops_history(loaded: &Loaded, channel_id: &str) {
    use nscript_host_crypto::host::Nip44OperationHost;
    use nscript_runtime::{DerivedKey, OperationHost, OperationValue, StreamWrap};

    let key = channel_key(loaded, channel_id);
    let plane = DerivedKey::new(key.secret_bytes().to_vec()).expect("key");
    let mut host = Nip44OperationHost::new([1; 32]);
    let mut seen = std::collections::BTreeSet::new();
    let (mut opened, mut refused) = (0, 0);
    for relay in &loaded.invite.relays {
        let filter = json!({"kinds": [1059], "authors": [hex(&key.xonly_pubkey())], "limit": 200});
        for wrap in query(relay, &filter).unwrap_or_default() {
            if !seen.insert(wrap["id"].as_str().unwrap_or("").to_owned()) {
                continue;
            }
            let call = |host: &mut Nip44OperationHost, op: &str, value: OperationValue| {
                host.call(
                    1,
                    "concord01",
                    op,
                    &[OperationValue::DerivedKey(plane.clone()), value],
                )
            };
            let result = StreamWrap::from_wire(&wrap.to_string())
                .ok()
                .and_then(|w| call(&mut host, "unwrap_stream", OperationValue::StreamWrap(w)).ok())
                .and_then(|sealed| call(&mut host, "open_message", sealed).ok());
            match result {
                Some(OperationValue::SignedBytes(rumor)) => {
                    opened += 1;
                    let rumor: Value = serde_json::from_slice(rumor.as_bytes()).expect("json");
                    println!(
                        "  kind {} — {}",
                        rumor["kind"],
                        short(rumor["content"].as_str().unwrap_or(""))
                    );
                }
                _ => refused += 1,
            }
        }
    }
    println!("real host operations: {opened} opened, {refused} refused");
}

/// One message via the runtime's own path: `OperationPolicy` gate, the real
/// `Nip44OperationHost`, and `RealRelayPool` for delivery.
fn publish_via_runtime(loaded: &Loaded, channel_id: &str, secret: &[u8; 32]) {
    use nscript_host_crypto::host::{Nip44OperationHost, PublishTarget};
    use nscript_runtime::{
        DerivedKey, FakeClock, FakeRelayHost, FakeSignerHost, OperationPolicy, OperationValue,
        RealRelayPool, RecordingAudit, Runtime, StreamMessage,
    };

    let mut pool = RealRelayPool::new();
    for relay in &loaded.invite.relays {
        match pool.add_relay(relay.clone()) {
            Ok(()) => println!("connected {relay}"),
            Err(error) => println!("could not connect {relay}: {error:?}"),
        }
    }
    let target = PublishTarget {
        channel_id: channel_id.to_owned(),
        epoch: loaded.invite.root_epoch,
        timer: loaded.timer,
        relayset: "community".to_owned(),
    };
    let mut host = Nip44OperationHost::new(*secret).with_publisher(target, Box::new(pool));
    let key =
        DerivedKey::new(channel_key(loaded, channel_id).secret_bytes().to_vec()).expect("key");
    let me = hex(&xonly_pubkey(secret).expect("pubkey"));
    let content = "This one was sent by an NScript program, not a hand-written client:\n\nuse concord01\n\npermissions {\n    concord_publish\n}\n\nlet result = concord01.publish_message(stream, StreamMessage {\n    author: me;\n    content: \"…\";\n})\n\nThe call passed the runtime's OperationPolicy gate, the Concord host sealed and wrapped it (kind 1059, expiration mirrored onto the wrap), and the runtime's own RealRelayPool delivered it over TLS. That pool used to panic on wss:// and hang on a silent relay; both are fixed as of today.";

    let mut runtime = Runtime::new(
        FakeRelayHost::default(),
        FakeSignerHost::default(),
        FakeClock::default(),
        RecordingAudit::default(),
    );
    let policy = OperationPolicy::default().allow("concord01", "publish_message");
    let result = runtime.invoke_authorized_operation(
        &policy,
        &mut host,
        "concord01",
        "publish_message",
        &[
            OperationValue::DerivedKey(key),
            OperationValue::StreamMessage(StreamMessage {
                author: me,
                content: content.to_owned(),
            }),
        ],
    );
    match result {
        Ok(OperationValue::PublishReport(report)) => {
            for outcome in &report.outcomes {
                println!(
                    "  {}: accepted={} {}",
                    outcome.relay, outcome.accepted, outcome.detail
                );
            }
        }
        other => println!("publish failed: {other:?}"),
    }
}

fn whoami(loaded: &Loaded, secret: &[u8; 32]) {
    let me = hex(&xonly_pubkey(secret).expect("pubkey"));
    let roster = loaded.authority.roster();
    println!("identity {me}");
    println!("owner {}", roster.owner);
    for role in roster.roles.values() {
        println!(
            "role position {} permissions {} (server_scope {})",
            role.position, role.permissions, role.server_scope
        );
    }
    println!("grants held by members: {}", roster.grants.len());
    println!("my roles: {:?}", roster.grants.get(&me).map_or(0, Vec::len));
    let stranger = "ab".repeat(32);
    println!(
        "rank {} | permission bits {} | staff {}",
        roster.rank(&me),
        roster.permissions(&me),
        roster.is_staff(&me)
    );
    println!(
        "can kick a role-less member: {} | can ban one: {} | banned: {}",
        roster.can(&me, nscript_runtime::authority::perm::KICK, Some(&stranger)),
        roster.can(&me, nscript_runtime::authority::perm::BAN, Some(&stranger)),
        roster.banned.len()
    );
}

fn identity(path: &str) -> [u8; 32] {
    if let Ok(text) = std::fs::read_to_string(path) {
        return unhex32(text.trim());
    }
    let secret = random32().expect("os rng");
    std::fs::write(path, hex(&secret)).expect("write keyfile");
    secret
}

/// A chat rumor for `channel_id` with the channel binding, sub-second `ms`
/// and the CORD-08 expiration tag when the community's timer is set.
fn chat_rumor(
    secret: &[u8; 32],
    kind: u64,
    channel_id: &str,
    epoch: u64,
    timer: Option<u64>,
    extra: &[Value],
    content: &str,
) -> (Value, Vec<Vec<String>>) {
    let (created_at, ms) = now();
    let mut tags = vec![
        json!(["channel", channel_id]),
        json!(["epoch", epoch.to_string()]),
        json!(["ms", ms.to_string()]),
    ];
    tags.extend(extra.iter().cloned());
    let outer: Vec<Vec<String>> = expiration_tag(kind, created_at, timer)
        .into_iter()
        .collect();
    for tag in &outer {
        tags.push(json!(tag));
    }
    (
        rumor(secret, kind, &Value::Array(tags), content, created_at).expect("rumor"),
        outer,
    )
}

fn send(
    loaded: &Loaded,
    key: &GroupKey,
    form: SealForm,
    secret: &[u8; 32],
    rumor: &Value,
    outer: &[Vec<String>],
) {
    let created_at = rumor["created_at"].as_u64().expect("created_at");
    let wrap = build_stream_event_with_tags(
        &key.secret_bytes(),
        &key.conversation_key(),
        form,
        secret,
        rumor,
        outer,
        created_at,
    )
    .expect("wrap");
    let wrap: Value = serde_json::from_str(&wrap).expect("json");
    for relay in &loaded.invite.relays {
        match publish(relay, &wrap) {
            Ok((accepted, message)) => println!("  {relay}: accepted={accepted} {message}"),
            Err(error) => println!("  {relay}: {error}"),
        }
    }
}

fn post(loaded: &Loaded, channel_id: &str, secret: &[u8; 32]) {
    let root = unhex32(loaded.invite.community_root());
    let cid = unhex32(&loaded.invite.community_id);
    let epoch = loaded.invite.root_epoch;
    let me = hex(&xonly_pubkey(secret).expect("pubkey"));
    println!("posting as {me}");

    // 1. Announce membership on the Guestbook plane (member-writable).
    let guestbook = group_key("concord/guestbook", &root, &cid, Some(epoch));
    let (created_at, ms) = now();
    let join = rumor(
        secret,
        3306,
        &json!([["ms", ms.to_string()]]),
        "join",
        created_at,
    )
    .expect("rumor");
    println!("join:");
    send(loaded, &guestbook, SealForm::Encrypted, secret, &join, &[]);

    // 2. Chat messages in the public channel.
    let channel = channel_key(loaded, channel_id);
    let timer = loaded.timer;
    let say = |kind: u64, extra: &[Value], text: &str| {
        let (rumor, outer) = chat_rumor(secret, kind, channel_id, epoch, timer, extra, text);
        println!("kind {kind}: {}", text.lines().next().unwrap_or(""));
        send(
            loaded,
            &channel,
            SealForm::Encrypted,
            secret,
            &rumor,
            &outer,
        );
        std::thread::sleep(std::time::Duration::from_secs(2));
        rumor
    };

    let intro = say(
        9,
        &[],
        "gm 👋 I'm an NScript interop test client, joining with a throwaway key. NScript is a statically typed scripting language for Nostr, and this message was sealed and wrapped by its Concord host: real CORD-01 stream events, verified against this community's own Control Plane.",
    );
    let intro_id = intro["id"].as_str().unwrap().to_owned();

    let bot = say(
        9,
        &[],
        "Here's how an NScript moderation bot is granted only what it needs:\n\nuse concord04\n\npermissions {\n    concord_kick\n}\n\nlet result = concord04.kick_member(alice)\n\nSwap kick_member for ban_member and the checker refuses to compile it (E3001), because the script was never granted concord_ban. At run time the host still enforces CORD-04: the bot must hold the KICK bit *and* strictly outrank its target.",
    );
    let bot_id = bot["id"].as_str().unwrap().to_owned();

    say(
        9,
        &[json!(["q", intro_id, "", me])],
        "Fun fact from reading this community's Control Plane: message_expiration is 7776000, so 90 days. Under CORD-08 that means every message carries an expiration tag twice: inside the signed rumor (what readers enforce) and on the outer wrap (so relays can actually delete the ciphertext).",
    );

    say(
        1111,
        &[
            json!(["K", "9"]),
            json!(["E", bot_id, "", me]),
            json!(["P", me]),
            json!(["k", "9"]),
            json!(["e", bot_id, "", me]),
            json!(["p", me]),
        ],
        "Threaded replies are a separate kind (1111) from inline quotes: uppercase K/E/P pin the thread root, lowercase k/e/p the immediate parent. Decoding this one is a good test that a client tells the two apart 🧵",
    );
}

fn main() {
    common::init_tls();
    let args: Vec<String> = std::env::args().collect();
    let mode = args[1].as_str();
    let loaded = load(&args[2], &args[3]);
    print_structure(&loaded);
    let channel_id = public_channel(&loaded, "general");
    match mode {
        "read" => {}
        "history" => print_history(&loaded, &channel_id),
        "ops" => ops_history(&loaded, &channel_id),
        "whoami" => whoami(&loaded, &identity(&args[4])),
        "publish" => {
            let secret = identity(&args[4]);
            publish_via_runtime(&loaded, &channel_id, &secret);
            std::thread::sleep(std::time::Duration::from_secs(3));
            println!("--- read back ---");
            ops_history(&loaded, &channel_id);
        }
        "post" => {
            let secret = identity(&args[4]);
            print_history(&loaded, &channel_id);
            post(&loaded, &channel_id, &secret);
            std::thread::sleep(std::time::Duration::from_secs(3));
            println!("--- read back after posting ---");
            print_history(&loaded, &channel_id);
        }
        other => panic!("unknown mode {other}"),
    }
}
