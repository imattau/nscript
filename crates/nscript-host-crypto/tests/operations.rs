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

mod publishing {
    use std::sync::{Arc, Mutex};

    use nscript_host_crypto::group_key::xonly_pubkey;
    use nscript_host_crypto::host::{Nip44OperationHost, PublishTarget};
    use nscript_host_crypto::stream::{SealForm, open_stream_event};
    use nscript_runtime::stream::GroupKeyLabel;
    use nscript_runtime::{
        FakeClock, FakeSignerHost, InvocationId, OperationPolicy, OperationValue, PublishReport,
        RecordingAudit, RelayHost, RelayOutcome, Runtime, RuntimeError, SignedEvent, StreamMessage,
    };
    use serde_json::{Value, json};

    use super::{AUTHOR, CHANNEL, ROOT, hex, hex_to_32, plane_key};

    /// Records what the host sends to the relay layer.
    #[derive(Clone, Default)]
    struct Recorder(Arc<Mutex<Vec<SignedEvent>>>);

    impl RelayHost for Recorder {
        fn publish(
            &mut self,
            _invocation: InvocationId,
            event: &SignedEvent,
            _relayset: &str,
        ) -> Result<PublishReport, RuntimeError> {
            self.0.lock().unwrap().push(event.clone());
            Ok(PublishReport {
                outcomes: vec![RelayOutcome {
                    relay: "recorded".to_owned(),
                    accepted: true,
                    detail: String::new(),
                }],
            })
        }
    }

    fn target(timer: Option<u64>) -> PublishTarget {
        PublishTarget {
            channel_id: CHANNEL.to_owned(),
            epoch: 0,
            timer,
            relayset: "community".to_owned(),
        }
    }

    fn host(recorder: &Recorder, timer: Option<u64>) -> Nip44OperationHost {
        let mut host = Nip44OperationHost::new(AUTHOR)
            .with_publisher(target(timer), Box::new(recorder.clone()));
        host.fixed_time = Some(1_700_000_000);
        host
    }

    fn me() -> String {
        hex(&xonly_pubkey(&AUTHOR).unwrap())
    }

    fn message(author: &str, content: &str) -> OperationValue {
        OperationValue::StreamMessage(StreamMessage {
            author: author.to_owned(),
            content: content.to_owned(),
        })
    }

    fn wire(event: &SignedEvent) -> String {
        json!({
            "id": event.id, "pubkey": event.signer, "created_at": event.unsigned.created_at,
            "kind": event.unsigned.kind, "tags": event.unsigned.wire_tags(),
            "content": event.unsigned.content, "sig": event.signature,
        })
        .to_string()
    }

    #[test]
    fn publish_message_sends_a_real_bound_expiring_stream_event() {
        let recorder = Recorder::default();
        let mut host = host(&recorder, Some(7_776_000));
        let key = plane_key(GroupKeyLabel::Channel, CHANNEL);
        let report = nscript_runtime::OperationHost::call(
            &mut host,
            1,
            "concord01",
            "publish_message",
            &[
                OperationValue::DerivedKey(key),
                message(&me(), "Deployment finished"),
            ],
        )
        .unwrap();
        assert!(matches!(report, OperationValue::PublishReport(r) if r.accepted()));

        let sent = recorder.0.lock().unwrap();
        assert_eq!(sent.len(), 1);
        let event = &sent[0];
        assert_eq!(event.unsigned.kind, 1059);
        assert!(
            event
                .unsigned
                .tags
                .contains(&("expiration".to_owned(), "1707776000".to_owned()))
        );
        assert!(!event.unsigned.content.contains("Deployment"), "encrypted");

        // Any CORD-01 implementation holding the channel key can open it.
        let channel = nscript_host_crypto::group_key::group_key(
            "concord/channel",
            &ROOT,
            &hex_to_32(CHANNEL),
            Some(0),
        );
        let opened = open_stream_event(
            &channel.xonly_pubkey(),
            &channel.conversation_key(),
            SealForm::Encrypted,
            &wire(event),
        )
        .unwrap();
        assert_eq!(opened.author, me());
        let rumor: Value = serde_json::from_str(&opened.rumor_json).unwrap();
        assert_eq!(
            (rumor["kind"].clone(), rumor["content"].clone()),
            (json!(9), json!("Deployment finished"))
        );
        let tags = rumor["tags"].to_string();
        assert!(
            tags.contains(&format!(r#"["channel","{CHANNEL}"]"#))
                && tags.contains(r#"["epoch","0"]"#)
        );
        assert!(
            tags.contains(r#"["expiration","1707776000"]"#),
            "rumor copy is authoritative"
        );
    }

    #[test]
    fn no_expiration_when_the_timer_is_off() {
        let recorder = Recorder::default();
        let mut host = host(&recorder, None);
        let key = plane_key(GroupKeyLabel::Channel, CHANNEL);
        nscript_runtime::OperationHost::call(
            &mut host,
            1,
            "concord01",
            "publish_message",
            &[OperationValue::DerivedKey(key), message(&me(), "hello")],
        )
        .unwrap();
        assert!(
            !recorder.0.lock().unwrap()[0]
                .unsigned
                .tags
                .iter()
                .any(|(n, _)| n == "expiration")
        );
    }

    #[test]
    fn a_script_cannot_publish_as_someone_else_or_without_a_publisher() {
        let recorder = Recorder::default();
        let mut host = host(&recorder, None);
        let key = plane_key(GroupKeyLabel::Channel, CHANNEL);
        for bad in [message(&"ab".repeat(32), "spoof"), message(&me(), "")] {
            let result = nscript_runtime::OperationHost::call(
                &mut host,
                1,
                "concord01",
                "publish_message",
                &[OperationValue::DerivedKey(key.clone()), bad],
            );
            assert!(matches!(
                result,
                Err(RuntimeError::InvalidOperationArguments { .. })
            ));
        }
        assert!(recorder.0.lock().unwrap().is_empty(), "nothing was sent");

        let mut bare = Nip44OperationHost::new(AUTHOR);
        let result = nscript_runtime::OperationHost::call(
            &mut bare,
            1,
            "concord01",
            "publish_message",
            &[OperationValue::DerivedKey(key), message(&me(), "x")],
        );
        assert!(matches!(
            result,
            Err(RuntimeError::OperationUnavailable { .. })
        ));
    }

    #[test]
    fn the_runtime_policy_gate_applies_before_the_host_is_reached() {
        let recorder = Recorder::default();
        let mut host = host(&recorder, None);
        let key = plane_key(GroupKeyLabel::Channel, CHANNEL);
        let mut runtime = Runtime::new(
            nscript_runtime::FakeRelayHost::default(),
            FakeSignerHost::default(),
            FakeClock::default(),
            RecordingAudit::default(),
        );
        let args = [OperationValue::DerivedKey(key), message(&me(), "policy")];
        let denied = runtime.invoke_authorized_operation(
            &OperationPolicy::default(),
            &mut host,
            "concord01",
            "publish_message",
            &args,
        );
        assert!(matches!(denied, Err(RuntimeError::CapabilityDenied { .. })));
        assert!(recorder.0.lock().unwrap().is_empty());
        let allowed = OperationPolicy::default().allow("concord01", "publish_message");
        assert!(
            runtime
                .invoke_authorized_operation(
                    &allowed,
                    &mut host,
                    "concord01",
                    "publish_message",
                    &args
                )
                .is_ok()
        );
        assert_eq!(recorder.0.lock().unwrap().len(), 1);
    }
}

#[test]
fn stream_yields_a_public_address_handle_and_never_key_material() {
    let key = plane_key(GroupKeyLabel::Channel, CHANNEL);
    let mut host = host();
    let handle = call(
        &mut host,
        "stream",
        &[OperationValue::DerivedKey(key.clone())],
    )
    .unwrap();
    let OperationValue::StreamHandle(handle) = handle else {
        panic!("expected a stream handle")
    };
    let secret: [u8; 32] = key.as_bytes().try_into().unwrap();
    let expected = hex(&nscript_host_crypto::group_key::xonly_pubkey(&secret).unwrap());
    assert_eq!(handle.address, expected);
    assert!(
        !format!("{handle:?}").contains(&hex(&secret)),
        "no secret in the handle"
    );
    // A wrong argument shape is refused.
    assert!(matches!(
        call(&mut host, "stream", &[]),
        Err(RuntimeError::InvalidOperationArguments { .. })
    ));
}
