//! The real `concord01` operations: seal, wrap, unwrap and open.

use nscript_host_crypto::group_key::group_key;
use nscript_host_crypto::host::{Nip44KeyHost, Nip44OperationHost};
use nscript_host_crypto::stream::{SealForm, open_stream_event};
use nscript_runtime::stream::GroupKeyLabel;
use nscript_runtime::{
    ConcordKeyHost, DerivedKey, OperationHost, OperationValue, RuntimeError, SharedSecret,
    SignedBytes,
};
use serde_json::{Value, json};

const AUTHOR: [u8; 32] = [5; 32];
const ROOT: [u8; 32] = [7; 32];
const CHANNEL: &str = "cc00000000000000000000000000000000000000000000000000000000000003";

fn hex(bytes: &[u8]) -> String {
    use std::fmt::Write as _;
    bytes.iter().fold(String::new(), |mut out, b| {
        let _ = write!(out, "{b:02x}");
        out
    })
}

fn plane_key(label: GroupKeyLabel, id: &str) -> DerivedKey {
    let secret = SharedSecret::new(ROOT.to_vec()).unwrap();
    Nip44KeyHost::default()
        .derive_group_key(1, label, &secret, id, 0)
        .unwrap()
}

fn host() -> Nip44OperationHost {
    let mut host = Nip44OperationHost::new(AUTHOR);
    host.fixed_time = Some(1_700_000_000);
    host
}

fn rumor_bytes(content: &str, tags: &Value) -> SignedBytes {
    let author = hex(&nscript_host_crypto::group_key::xonly_pubkey(&AUTHOR).unwrap());
    let rumor = json!({"kind": 9, "pubkey": author, "content": content, "tags": tags, "created_at": 1_700_000_000});
    SignedBytes::new(rumor.to_string().into_bytes()).unwrap()
}

fn call(
    host: &mut Nip44OperationHost,
    op: &str,
    args: &[OperationValue],
) -> Result<OperationValue, RuntimeError> {
    host.call(1, "concord01", op, args)
}

#[test]
fn seal_wrap_unwrap_open_round_trips_exact_rumor_bytes() {
    let key = plane_key(GroupKeyLabel::Channel, CHANNEL);
    let mut host = host();
    let rumor = rumor_bytes("Hey chat!", &json!([["channel", CHANNEL], ["epoch", "0"]]));
    let seal = call(
        &mut host,
        "seal_message",
        &[
            OperationValue::DerivedKey(key.clone()),
            OperationValue::SignedBytes(rumor.clone()),
        ],
    )
    .unwrap();
    let wrap = call(
        &mut host,
        "wrap_stream",
        &[OperationValue::DerivedKey(key.clone()), seal],
    )
    .unwrap();
    let OperationValue::StreamWrap(inner) = &wrap else {
        panic!("wrap")
    };
    assert_eq!(inner.kind, 1059);
    let wire = inner.wire.clone().unwrap();
    assert!(!wire.contains("Hey chat!"), "encrypted at every layer");

    let unwrapped = call(
        &mut host,
        "unwrap_stream",
        &[OperationValue::DerivedKey(key.clone()), wrap],
    )
    .unwrap();
    let opened = call(
        &mut host,
        "open_message",
        &[OperationValue::DerivedKey(key.clone()), unwrapped],
    )
    .unwrap();
    assert_eq!(opened, OperationValue::SignedBytes(rumor));

    // The wire event is an ordinary CORD-01 event any implementation can open.
    let secret: [u8; 32] = key.as_bytes().try_into().unwrap();
    let pubkey = nscript_host_crypto::group_key::xonly_pubkey(&secret).unwrap();
    let conv = group_key("concord/channel", &ROOT, &hex_to_32(CHANNEL), Some(0)).conversation_key();
    assert!(open_stream_event(&pubkey, &conv, SealForm::Encrypted, &wire).is_ok());
}

fn hex_to_32(text: &str) -> [u8; 32] {
    let bytes: Vec<u8> = (0..64)
        .step_by(2)
        .map(|i| u8::from_str_radix(&text[i..i + 2], 16).unwrap())
        .collect();
    bytes.try_into().unwrap()
}

#[test]
fn control_seals_are_plaintext_and_verbatim() {
    let key = plane_key(GroupKeyLabel::Guestbook, CHANNEL);
    let mut host = host();
    let rumor = rumor_bytes("edition", &json!([]));
    let sealed = call(
        &mut host,
        "seal_control_message",
        &[
            OperationValue::DerivedKey(key.clone()),
            OperationValue::SignedBytes(rumor.clone()),
        ],
    )
    .unwrap();
    let OperationValue::SealedEvent(seal) = &sealed else {
        panic!("seal")
    };
    assert_eq!(seal.kind().wire_kind(), 20014);
    let opened = call(
        &mut host,
        "open_message",
        &[OperationValue::DerivedKey(key), sealed],
    )
    .unwrap();
    assert_eq!(opened, OperationValue::SignedBytes(rumor));
}

#[test]
fn the_wrap_mirrors_the_rumors_expiration_tag_for_relays() {
    let key = plane_key(GroupKeyLabel::Channel, CHANNEL);
    let mut host = host();
    let with = rumor_bytes("ephemeral", &json!([["expiration", "1707776000"]]));
    let seal = call(
        &mut host,
        "seal_message",
        &[
            OperationValue::DerivedKey(key.clone()),
            OperationValue::SignedBytes(with),
        ],
    )
    .unwrap();
    let OperationValue::StreamWrap(wrap) = call(
        &mut host,
        "wrap_stream",
        &[OperationValue::DerivedKey(key.clone()), seal],
    )
    .unwrap() else {
        panic!()
    };
    let event: Value = serde_json::from_str(wrap.wire.as_deref().unwrap()).unwrap();
    assert!(
        event["tags"]
            .as_array()
            .unwrap()
            .contains(&json!(["expiration", "1707776000"]))
    );

    let without = rumor_bytes("forever", &json!([]));
    let seal = call(
        &mut host,
        "seal_message",
        &[
            OperationValue::DerivedKey(key.clone()),
            OperationValue::SignedBytes(without),
        ],
    )
    .unwrap();
    let OperationValue::StreamWrap(wrap) = call(
        &mut host,
        "wrap_stream",
        &[OperationValue::DerivedKey(key), seal],
    )
    .unwrap() else {
        panic!()
    };
    let event: Value = serde_json::from_str(wrap.wire.as_deref().unwrap()).unwrap();
    assert!(!event["tags"].to_string().contains("expiration"));
}

#[test]
fn wrong_keys_and_unwired_wraps_are_refused_and_unsupported_ops_unavailable() {
    let key = plane_key(GroupKeyLabel::Channel, CHANNEL);
    let other = plane_key(GroupKeyLabel::Guestbook, CHANNEL);
    let mut host = host();
    let seal = call(
        &mut host,
        "seal_message",
        &[
            OperationValue::DerivedKey(key.clone()),
            OperationValue::SignedBytes(rumor_bytes("x", &json!([]))),
        ],
    )
    .unwrap();
    let wrap = call(
        &mut host,
        "wrap_stream",
        &[OperationValue::DerivedKey(key.clone()), seal.clone()],
    )
    .unwrap();
    assert!(matches!(
        call(
            &mut host,
            "unwrap_stream",
            &[OperationValue::DerivedKey(other.clone()), wrap.clone()]
        ),
        Err(RuntimeError::InvalidOperationArguments { .. })
    ));
    assert!(matches!(
        call(
            &mut host,
            "open_message",
            &[OperationValue::DerivedKey(other), seal.clone()]
        ),
        Err(RuntimeError::InvalidOperationArguments { .. })
    ));
    // A fake-host wrap carries no wire event, so a real host cannot open it.
    let OperationValue::StreamWrap(mut unwired) = wrap else {
        panic!()
    };
    unwired.wire = None;
    assert!(matches!(
        call(
            &mut host,
            "unwrap_stream",
            &[
                OperationValue::DerivedKey(key.clone()),
                OperationValue::StreamWrap(unwired)
            ]
        ),
        Err(RuntimeError::InvalidOperationArguments { .. })
    ));
    for op in ["derive_stream_key", "publish_message"] {
        assert!(matches!(
            call(&mut host, op, &[OperationValue::DerivedKey(key.clone())]),
            Err(RuntimeError::OperationUnavailable { .. })
        ));
    }
    assert!(matches!(
        host.call(1, "nip17", "send_private", &[]),
        Err(RuntimeError::OperationUnavailable { .. })
    ));
}
