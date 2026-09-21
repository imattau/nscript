//! Real CORD-01 wrap/seal round trips and rejection cases.

use nscript_host_crypto::group_key::{group_key, xonly_pubkey};
use nscript_host_crypto::stream::{
    SealForm, StreamError, build_stream_event, open_stream_event, rumor,
};
use serde_json::{Value, json};

const AUTHOR: [u8; 32] = [5; 32];

fn hex(bytes: &[u8]) -> String {
    use std::fmt::Write as _;
    bytes.iter().fold(String::new(), |mut out, b| {
        let _ = write!(out, "{b:02x}");
        out
    })
}

struct Plane {
    signer: [u8; 32],
    pubkey: [u8; 32],
    conv: [u8; 32],
}

fn plane(label: &str) -> Plane {
    let key = group_key(label, &[7; 32], &[9; 32], Some(1));
    Plane {
        signer: key.secret_bytes(),
        pubkey: key.xonly_pubkey(),
        conv: key.conversation_key(),
    }
}

fn chat_rumor(text: &str) -> Value {
    rumor(
        &AUTHOR,
        9,
        &json!([["channel", "cc"], ["epoch", "1"]]),
        text,
        1_700_000_000,
    )
    .unwrap()
}

#[test]
fn encrypted_wrap_round_trips_and_looks_like_a_stream_event() {
    let p = plane("concord/channel");
    let sent = chat_rumor("Hey chat!");
    let wrap = build_stream_event(
        &p.signer,
        &p.conv,
        SealForm::Encrypted,
        &AUTHOR,
        &sent,
        1_700_000_000,
    )
    .unwrap();
    let event: Value = serde_json::from_str(&wrap).unwrap();
    assert_eq!(event["kind"], 1059);
    assert_eq!(event["pubkey"], hex(&p.pubkey));
    assert_eq!(event["tags"][0][0], "p", "ephemeral p tag");
    assert!(
        !wrap.contains("Hey chat!"),
        "content is encrypted at every layer"
    );

    let opened = open_stream_event(&p.pubkey, &p.conv, SealForm::Encrypted, &wrap).unwrap();
    assert_eq!(
        serde_json::from_str::<Value>(&opened.rumor_json).unwrap(),
        sent
    );
    assert_eq!(opened.author, sent["pubkey"].as_str().unwrap());
}

#[test]
fn plaintext_seals_carry_the_rumor_bytes_verbatim() {
    let p = plane("concord/control");
    let sent = chat_rumor("edition");
    let wrap = build_stream_event(
        &p.signer,
        &p.conv,
        SealForm::Plaintext,
        &AUTHOR,
        &sent,
        1_700_000_000,
    )
    .unwrap();
    let opened = open_stream_event(&p.pubkey, &p.conv, SealForm::Plaintext, &wrap).unwrap();
    assert_eq!(opened.rumor_json, sent.to_string());
}

#[test]
fn wrong_stream_key_or_seal_form_or_read_key_is_refused() {
    let p = plane("concord/channel");
    let other = plane("concord/guestbook");
    let wrap = build_stream_event(
        &p.signer,
        &p.conv,
        SealForm::Encrypted,
        &AUTHOR,
        &chat_rumor("x"),
        1,
    )
    .unwrap();
    assert_eq!(
        open_stream_event(&other.pubkey, &p.conv, SealForm::Encrypted, &wrap),
        Err(StreamError::WrongStream)
    );
    assert_eq!(
        open_stream_event(&p.pubkey, &p.conv, SealForm::Plaintext, &wrap),
        Err(StreamError::WrongSealKind)
    );
    assert!(open_stream_event(&p.pubkey, &other.conv, SealForm::Encrypted, &wrap).is_err());
}

#[test]
fn tampering_and_impersonation_are_detected() {
    let p = plane("concord/channel");
    let wrap = build_stream_event(
        &p.signer,
        &p.conv,
        SealForm::Encrypted,
        &AUTHOR,
        &chat_rumor("x"),
        1,
    )
    .unwrap();
    let mut event: Value = serde_json::from_str(&wrap).unwrap();
    event["created_at"] = json!(2);
    assert_eq!(
        open_stream_event(&p.pubkey, &p.conv, SealForm::Encrypted, &event.to_string()),
        Err(StreamError::BadSignature)
    );
    // A rumor authored by someone other than the seal's signer is impersonation.
    let forged = rumor(&[6; 32], 9, &json!([]), "spoof", 1).unwrap();
    let wrap =
        build_stream_event(&p.signer, &p.conv, SealForm::Encrypted, &AUTHOR, &forged, 1).unwrap();
    assert_eq!(
        open_stream_event(&p.pubkey, &p.conv, SealForm::Encrypted, &wrap),
        Err(StreamError::AuthorMismatch)
    );
    assert_eq!(
        open_stream_event(&p.pubkey, &p.conv, SealForm::Encrypted, r#"{"kind":4}"#),
        Err(StreamError::NotAWrap)
    );
    let _ = xonly_pubkey(&AUTHOR).unwrap();
}
