//! A Channel reader delivers only what an honest client would show.

use std::collections::BTreeSet;

use nscript_host_crypto::group_key::{group_key, xonly_pubkey};
use nscript_host_crypto::reader::{ChannelReader, Dropped};
use nscript_host_crypto::stream::{SealForm, build_stream_event_with_tags, rumor};
use nscript_runtime::DerivedKey;
use serde_json::{Value, json};

const ROOT: [u8; 32] = [7; 32];
const CHANNEL: &str = "cc00000000000000000000000000000000000000000000000000000000000003";
const OTHER: &str = "dd00000000000000000000000000000000000000000000000000000000000004";
const ALICE: [u8; 32] = [5; 32];
const MALLORY: [u8; 32] = [6; 32];
const NOW: u64 = 1_700_000_000;

fn hex(bytes: &[u8]) -> String {
    use std::fmt::Write as _;
    bytes.iter().fold(String::new(), |mut out, b| {
        let _ = write!(out, "{b:02x}");
        out
    })
}

fn unhex32(text: &str) -> [u8; 32] {
    let bytes: Vec<u8> = (0..64)
        .step_by(2)
        .map(|i| u8::from_str_radix(&text[i..i + 2], 16).unwrap())
        .collect();
    bytes.try_into().unwrap()
}

fn pk(secret: &[u8; 32]) -> String {
    hex(&xonly_pubkey(secret).unwrap())
}

fn plane(channel: &str) -> nscript_host_crypto::group_key::GroupKey {
    group_key("concord/channel", &ROOT, &unhex32(channel), Some(0))
}

fn reader() -> ChannelReader {
    let key = DerivedKey::new(plane(CHANNEL).secret_bytes().to_vec()).unwrap();
    ChannelReader::new(&key, CHANNEL, 0).unwrap()
}

/// A wrap of a rumor authored by `author` on `channel`'s plane.
fn wrap(author: &[u8; 32], kind: u64, tags: &Value, content: &str, created_at: u64) -> String {
    let key = plane(CHANNEL);
    let rumor = rumor(author, kind, tags, content, created_at).unwrap();
    build_stream_event_with_tags(
        &key.secret_bytes(),
        &key.conversation_key(),
        SealForm::Encrypted,
        author,
        &rumor,
        &[],
        created_at,
    )
    .unwrap()
}

fn bound(extra: &[Value]) -> Value {
    let mut tags = vec![json!(["channel", CHANNEL]), json!(["epoch", "0"])];
    tags.extend(extra.iter().cloned());
    Value::Array(tags)
}

#[test]
fn a_valid_message_is_delivered_with_its_proven_author() {
    let mut reader = reader();
    let wrap = wrap(&ALICE, 9, &bound(&[json!(["ms", "417"])]), "hello", NOW);
    let message = reader.ingest(&wrap, NOW, &BTreeSet::new()).unwrap();
    assert_eq!(message.author, pk(&ALICE));
    assert_eq!((message.kind, message.content.as_str()), (9, "hello"));
    assert_eq!(message.time_ms, NOW * 1000 + 417);
    assert_eq!(message.id.len(), 64);
    assert_eq!(reader.address(), hex(&plane(CHANNEL).xonly_pubkey()));
}

#[test]
fn threaded_replies_are_messages_but_reactions_are_not() {
    let mut reader = reader();
    let none = BTreeSet::new();
    assert!(
        reader
            .ingest(
                &wrap(&ALICE, 1111, &bound(&[]), "in a thread", NOW),
                NOW,
                &none
            )
            .is_ok()
    );
    assert_eq!(
        reader.ingest(&wrap(&ALICE, 7, &bound(&[]), "🔥", NOW), NOW, &none),
        Err(Dropped::NotAMessage)
    );
    assert_eq!(
        reader.ingest(&wrap(&ALICE, 5, &bound(&[]), "", NOW), NOW, &none),
        Err(Dropped::NotAMessage)
    );
}

#[test]
fn messages_rewrapped_into_another_channel_or_epoch_are_refused() {
    let mut reader = reader();
    let none = BTreeSet::new();
    let other_channel = json!([["channel", OTHER], ["epoch", "0"]]);
    let other_epoch = json!([["channel", CHANNEL], ["epoch", "1"]]);
    let unbound = json!([]);
    for tags in [other_channel, other_epoch, unbound] {
        assert_eq!(
            reader.ingest(&wrap(&ALICE, 9, &tags, "x", NOW), NOW, &none),
            Err(Dropped::WrongBinding),
            "{tags}"
        );
    }
}

#[test]
fn expired_messages_are_refused_at_ingest_by_their_own_signed_tag() {
    let mut reader = reader();
    let none = BTreeSet::new();
    let expiring = |at: u64| bound(&[json!(["expiration", at.to_string()])]);
    assert_eq!(
        reader.ingest(&wrap(&ALICE, 9, &expiring(NOW), "gone", NOW), NOW, &none),
        Err(Dropped::Expired)
    );
    assert!(
        reader
            .ingest(
                &wrap(&ALICE, 9, &expiring(NOW + 1), "fresh", NOW),
                NOW,
                &none
            )
            .is_ok()
    );
    // Without the tag a message does not expire.
    assert!(
        reader
            .ingest(
                &wrap(&ALICE, 9, &bound(&[]), "forever", NOW),
                NOW + 10_000_000,
                &none
            )
            .is_ok()
    );
}

#[test]
fn banned_authors_vanish_entirely() {
    let mut reader = reader();
    let banned = BTreeSet::from([pk(&MALLORY)]);
    assert_eq!(
        reader.ingest(&wrap(&MALLORY, 9, &bound(&[]), "spam", NOW), NOW, &banned),
        Err(Dropped::Banned)
    );
    assert!(
        reader
            .ingest(&wrap(&ALICE, 9, &bound(&[]), "ok", NOW), NOW, &banned)
            .is_ok()
    );
}

#[test]
fn a_replayed_wrap_is_delivered_once() {
    let mut reader = reader();
    let none = BTreeSet::new();
    let wrap = wrap(&ALICE, 9, &bound(&[json!(["ms", "1"])]), "once", NOW);
    assert!(reader.ingest(&wrap, NOW, &none).is_ok());
    assert_eq!(reader.ingest(&wrap, NOW, &none), Err(Dropped::Duplicate));
}

#[test]
fn foreign_tampered_and_malformed_events_are_not_openable_or_malformed() {
    let mut reader = reader();
    let none = BTreeSet::new();
    // A wrap on a different plane's address.
    let other = plane(OTHER);
    let rumor = rumor(&ALICE, 9, &bound(&[]), "x", NOW).unwrap();
    let foreign = build_stream_event_with_tags(
        &other.secret_bytes(),
        &other.conversation_key(),
        SealForm::Encrypted,
        &ALICE,
        &rumor,
        &[],
        NOW,
    )
    .unwrap();
    assert_eq!(
        reader.ingest(&foreign, NOW, &none),
        Err(Dropped::NotOpenable)
    );
    assert_eq!(
        reader.ingest("not json", NOW, &none),
        Err(Dropped::NotOpenable)
    );
    let mut tampered: Value =
        serde_json::from_str(&wrap(&ALICE, 9, &bound(&[]), "x", NOW)).unwrap();
    tampered["created_at"] = json!(1);
    assert_eq!(
        reader.ingest(&tampered.to_string(), NOW, &none),
        Err(Dropped::NotOpenable)
    );
    // An out-of-range `ms` is malformed, not interpreted.
    for ms in ["1000", "-1", "07"] {
        let tags = bound(&[json!(["ms", ms])]);
        assert_eq!(
            reader.ingest(&wrap(&ALICE, 9, &tags, "x", NOW), NOW, &none),
            Err(Dropped::Malformed),
            "{ms}"
        );
    }
}

#[test]
fn delivery_is_ordered_by_millisecond_time_then_id() {
    let mut reader = reader();
    let events = [
        wrap(&ALICE, 9, &bound(&[json!(["ms", "900"])]), "third", NOW),
        wrap(&ALICE, 9, &bound(&[json!(["ms", "100"])]), "second", NOW),
        wrap(&ALICE, 9, &bound(&[]), "first", NOW - 1),
    ];
    let messages = reader.ingest_all(events.iter().map(String::as_str), NOW, &BTreeSet::new());
    let order: Vec<_> = messages.iter().map(|m| m.content.as_str()).collect();
    assert_eq!(order, ["first", "second", "third"]);
}
