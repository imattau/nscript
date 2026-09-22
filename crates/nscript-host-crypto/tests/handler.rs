//! A moderation bot, end to end: real encrypted messages are read, an `NScript`
//! handler decides, and its `kick` becomes a real Guestbook directive that an
//! independent reader folds.

use std::collections::BTreeSet;
use std::sync::{Arc, Mutex};

use nscript_host_crypto::group_key::{group_key, xonly_pubkey};
use nscript_host_crypto::moderation::{CommunityKeys, ConcordModerationHost};
use nscript_host_crypto::reader::ChannelReader;
use nscript_host_crypto::stream::{
    SealForm, build_stream_event_with_tags, open_stream_event, rumor,
};
use nscript_runtime::authority::{AuthorityFold, community_id, grant_locator};
use nscript_runtime::edition::{FoldMode, VSK_GRANT, VSK_ROLE};
use nscript_runtime::eval::{EvalLimits, RuntimeSession, Value, run_handler};
use nscript_runtime::guestbook::{Guestbook, MemberState, parse_guestbook_rumor};
use nscript_runtime::wire::build_edition;
use nscript_runtime::{
    DerivedKey, FakeClock, FakeLogHost, FakeRelayHost, FakeSignerHost, InvocationId,
    OperationPolicy, PublishReport, RecordingAudit, RelayHost, RelayOutcome, Runtime, RuntimeError,
    SignedEvent,
};
use nscript_syntax::ast::{Item, StatementKind};
use serde_json::json;

const SALT: &str = "0202020202020202020202020202020202020202020202020202020202020202";
const ROOT: [u8; 32] = [7; 32];
const OWNER: [u8; 32] = [1; 32];
const BOT: [u8; 32] = [3; 32];
const ALICE: [u8; 32] = [5; 32];
const SPAMMER: [u8; 32] = [6; 32];
const MOD_ROLE: &str = "2200000000000000000000000000000000000000000000000000000000000000";
const CHANNEL: &str = "cc00000000000000000000000000000000000000000000000000000000000003";
const NOW: u64 = 1_700_000_000;

const BOT_SOURCE: &str = r#"
use concord04

permissions {
    concord_kick
    log
}

on messages {
    if event.content contains "spam" {
        print("kicking " + event.author)
        kick event.author
    }
}
"#;

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

#[derive(Clone, Default)]
struct Recorder(Arc<Mutex<Vec<SignedEvent>>>);

impl RelayHost for Recorder {
    fn publish(
        &mut self,
        _: InvocationId,
        event: &SignedEvent,
        _: &str,
    ) -> Result<PublishReport, RuntimeError> {
        self.0.lock().unwrap().push(event.clone());
        Ok(PublishReport {
            outcomes: vec![RelayOutcome {
                relay: "r".into(),
                accepted: true,
                detail: String::new(),
            }],
        })
    }
}

fn wire(event: &SignedEvent) -> String {
    json!({"id": event.id, "pubkey": event.signer, "created_at": event.unsigned.created_at,
        "kind": event.unsigned.kind, "tags": event.unsigned.wire_tags(),
        "content": event.unsigned.content, "sig": event.signature})
    .to_string()
}

/// A community in which BOT holds a KICK-only role.
fn moderation_host(recorder: &Recorder) -> (ConcordModerationHost, String) {
    let cid = community_id(&pk(&OWNER), SALT).unwrap();
    let mut fold = AuthorityFold::new(&pk(&OWNER), SALT, &cid, FoldMode::Tracking, 64).unwrap();
    let role = format!(
        r#"{{"role_id":"{MOD_ROLE}","name":"mod","position":5,"permissions":"8","scope":{{"kind":"server"}}}}"#
    );
    let (role, _) = build_edition(VSK_ROLE, MOD_ROLE, None, &role, &pk(&OWNER), None, NOW).unwrap();
    let grant = format!(r#"{{"member":"{}","role_ids":["{MOD_ROLE}"]}}"#, pk(&BOT));
    let (grant, _) = build_edition(
        VSK_GRANT,
        &grant_locator(&cid, &pk(&BOT)).unwrap(),
        None,
        &grant,
        &pk(&OWNER),
        None,
        NOW,
    )
    .unwrap();
    assert!(fold.insert(role) && fold.insert(grant));
    let keys = CommunityKeys {
        community_id: unhex32(&cid),
        community_root: ROOT,
        epoch: 0,
        control_root: None,
    };
    let mut host =
        ConcordModerationHost::new(BOT, keys, fold, Box::new(recorder.clone()), "community");
    host.fixed_time = Some(NOW + 60);
    (host, cid)
}

fn channel_wrap(author: &[u8; 32], content: &str, ms: u64) -> String {
    let plane = group_key("concord/channel", &ROOT, &unhex32(CHANNEL), Some(0));
    let tags = json!([["channel", CHANNEL], ["epoch", "0"], ["ms", ms.to_string()]]);
    let rumor = rumor(author, 9, &tags, content, NOW).unwrap();
    build_stream_event_with_tags(
        &plane.secret_bytes(),
        &plane.conversation_key(),
        SealForm::Encrypted,
        author,
        &rumor,
        &[],
        NOW,
    )
    .unwrap()
}

fn handler_body(source: &str) -> (nscript_syntax::Program, Vec<Item>) {
    let (program, diagnostics) = nscript_syntax::parse_program(source);
    assert!(diagnostics.is_empty(), "{diagnostics:?}");
    let (checked, diagnostics) = nscript_semantics::check(&program);
    assert!(
        diagnostics.is_empty(),
        "the bot passes the static check: {diagnostics:?}"
    );
    assert!(checked.is_some());
    let body = program
        .ast
        .items
        .iter()
        .find_map(|item| match item {
            Item::Statement(statement) => match &statement.value {
                StatementKind::On { body, .. } => Some(body.clone()),
                _ => None,
            },
            _ => None,
        })
        .expect("a handler");
    (program, body)
}

#[test]
fn a_script_reads_a_real_channel_and_kicks_the_spammer() {
    let plane = DerivedKey::new(
        group_key("concord/channel", &ROOT, &unhex32(CHANNEL), Some(0))
            .secret_bytes()
            .to_vec(),
    )
    .unwrap();
    let mut reader = ChannelReader::new(&plane, CHANNEL, 0).unwrap();
    let wraps = [
        channel_wrap(&ALICE, "hello everyone", 100),
        channel_wrap(&SPAMMER, "buy spam now", 200),
    ];
    let messages = reader.ingest_all(wraps.iter().map(String::as_str), NOW, &BTreeSet::new());
    assert_eq!(messages.len(), 2);

    let recorder = Recorder::default();
    let (mut moderation, cid) = moderation_host(&recorder);
    let (program, body) = handler_body(BOT_SOURCE);
    let policy = OperationPolicy::default().allow("concord04", "kick_member");
    let mut runtime = Runtime::new(
        FakeRelayHost::default(),
        FakeSignerHost::default(),
        FakeClock::default(),
        RecordingAudit::default(),
    );
    let mut log = FakeLogHost::default();

    for message in &messages {
        let mut session = RuntimeSession {
            runtime: &mut runtime,
            policy: &policy,
            operations: &mut moderation,
            log: &mut log,
            principal: Some(pk(&BOT)),
            idempotency: None,
        };
        let event = Value::from_event(&message.to_signed_event());
        run_handler(&program, &body, event, &mut session, EvalLimits::default()).unwrap();
    }

    // The handler acted on exactly one message, and said so.
    let sent = recorder.0.lock().unwrap().clone();
    assert_eq!(sent.len(), 1, "one directive for one spam message");
    assert_eq!(log.records.len(), 1);
    assert_eq!(log.records[0].message, format!("kicking {}", pk(&SPAMMER)));

    // An independent reader opens the directive and folds it.
    let book = group_key("concord/guestbook", &ROOT, &unhex32(&cid), Some(0));
    let opened = open_stream_event(
        &book.xonly_pubkey(),
        &book.conversation_key(),
        SealForm::Encrypted,
        &wire(&sent[0]),
    )
    .unwrap();
    assert_eq!(
        opened.author,
        pk(&BOT),
        "the kick is signed by the bot's identity"
    );
    let entry = parse_guestbook_rumor(&opened.author, &opened.rumor_json).unwrap();
    let mut authority =
        AuthorityFold::new(&pk(&OWNER), SALT, &cid, FoldMode::Tracking, 64).unwrap();
    for (vsk, eid, id) in [
        (VSK_ROLE, MOD_ROLE.to_owned(), MOD_ROLE.to_owned()),
        (VSK_GRANT, grant_locator(&cid, &pk(&BOT)).unwrap(), pk(&BOT)),
    ] {
        let content = if vsk == VSK_ROLE {
            format!(
                r#"{{"role_id":"{id}","name":"mod","position":5,"permissions":"8","scope":{{"kind":"server"}}}}"#
            )
        } else {
            format!(r#"{{"member":"{id}","role_ids":["{MOD_ROLE}"]}}"#)
        };
        authority.insert(
            build_edition(vsk, &eid, None, &content, &pk(&OWNER), None, NOW)
                .unwrap()
                .0,
        );
    }
    let roster = authority.roster();
    let guestbook = Guestbook::fold(&[entry], &authority, &roster, None, 2_000_000_000_000);
    assert_eq!(guestbook.state(&pk(&SPAMMER)), Some(MemberState::Kicked));
    assert_eq!(
        guestbook.state(&pk(&ALICE)),
        None,
        "the innocent member is untouched"
    );
}

#[test]
fn the_script_cannot_do_more_than_the_program_was_granted() {
    let recorder = Recorder::default();
    let (mut moderation, _) = moderation_host(&recorder);
    let (program, body) = handler_body(BOT_SOURCE);
    let mut runtime = Runtime::new(
        FakeRelayHost::default(),
        FakeSignerHost::default(),
        FakeClock::default(),
        RecordingAudit::default(),
    );
    let mut log = FakeLogHost::default();
    let nothing = OperationPolicy::default();
    let mut session = RuntimeSession {
        runtime: &mut runtime,
        policy: &nothing,
        operations: &mut moderation,
        log: &mut log,
        principal: Some(pk(&BOT)),
        idempotency: None,
    };
    let spam = nscript_runtime::SignedEvent {
        unsigned: nscript_runtime::UnsignedEvent {
            event_type: "StreamMessage".into(),
            kind: 9,
            content: "spam".into(),
            tags: vec![],
            created_at: NOW,
        },
        signer: pk(&SPAMMER),
        id: "e".into(),
        signature: String::new(),
    };
    let error = run_handler(
        &program,
        &body,
        Value::from_event(&spam),
        &mut session,
        EvalLimits::default(),
    )
    .unwrap_err();
    assert!(
        matches!(error, RuntimeError::CapabilityDenied { .. }),
        "{error:?}"
    );
    assert!(
        recorder.0.lock().unwrap().is_empty(),
        "nothing was published"
    );
}

const RESULT_BOT: &str = r#"
use concord04

permissions {
    concord_kick
    log
}

on messages {
    match concord04.kick_member(event.author) {
        Ok(report) => print("kicked " + event.author)
        Err(error) => print("could not kick " + event.author + ": " + error.message)
    }
}
"#;

#[test]
fn a_script_branches_on_a_kick_the_roster_refuses() {
    use nscript_runtime::eval::WithReturns;

    let plane = DerivedKey::new(
        group_key("concord/channel", &ROOT, &unhex32(CHANNEL), Some(0))
            .secret_bytes()
            .to_vec(),
    )
    .unwrap();
    let mut reader = ChannelReader::new(&plane, CHANNEL, 0).unwrap();
    // The owner is unremovable; the spammer holds no role.
    let wraps = [
        channel_wrap(&OWNER, "spam from the owner", 100),
        channel_wrap(&SPAMMER, "spam", 200),
    ];
    let messages = reader.ingest_all(wraps.iter().map(String::as_str), NOW, &BTreeSet::new());
    assert_eq!(messages.len(), 2);

    let recorder = Recorder::default();
    let (mut moderation, _) = moderation_host(&recorder);
    let mut with_types = WithReturns {
        inner: &mut moderation,
        returns: std::collections::BTreeMap::from([(
            ("concord04".to_owned(), "kick_member".to_owned()),
            "Result<PublishReport,ModerationError>".to_owned(),
        )]),
    };
    let (program, body) = handler_body(RESULT_BOT);
    let policy = OperationPolicy::default().allow("concord04", "kick_member");
    let mut runtime = Runtime::new(
        FakeRelayHost::default(),
        FakeSignerHost::default(),
        FakeClock::default(),
        RecordingAudit::default(),
    );
    let mut log = FakeLogHost::default();
    for message in &messages {
        let mut session = RuntimeSession {
            runtime: &mut runtime,
            policy: &policy,
            operations: &mut with_types,
            log: &mut log,
            principal: Some(pk(&BOT)),
            idempotency: None,
        };
        // The refusal is a value the script handled, so neither handler fails.
        run_handler(
            &program,
            &body,
            Value::from_event(&message.to_signed_event()),
            &mut session,
            EvalLimits::default(),
        )
        .unwrap();
    }

    let said: Vec<_> = log.records.iter().map(|r| r.message.clone()).collect();
    assert_eq!(
        said,
        [
            format!("could not kick {}: not authorized to kick", pk(&OWNER)),
            format!("kicked {}", pk(&SPAMMER)),
        ],
        "the Roster's refusal reached the script as an Err it could read"
    );
    assert_eq!(
        recorder.0.lock().unwrap().len(),
        1,
        "only the permitted kick was published"
    );
}

const STREAM_BOT: &str = r#"
use concord01
use concord04

permissions {
    concord_read
    concord_kick
    read StreamMessage from chat
    log
}

let chat = concord01.stream(channel_key)
stream messages = select StreamMessage from chat

on messages {
    if event.content contains "spam" {
        print("kicking " + event.author)
        kick event.author
    }
}
"#;

#[test]
fn a_stream_handler_receives_the_messages_the_reader_delivers() {
    use nscript_runtime::eval::policy_for;

    let (program, diagnostics) = nscript_syntax::parse_program(STREAM_BOT);
    assert!(diagnostics.is_empty(), "{diagnostics:?}");
    let (checked, diagnostics) = nscript_semantics::check(&program);
    assert!(diagnostics.is_empty(), "{diagnostics:?}");
    let checked = checked.unwrap();
    // The handler's event type is the stream's element type, not the stream's
    // name, so a received StreamMessage matches it. (It used to be `messages`,
    // which no received message could ever match.)
    assert_eq!(checked.handlers[0].event_type, "StreamMessage");

    let plane = DerivedKey::new(
        group_key("concord/channel", &ROOT, &unhex32(CHANNEL), Some(0))
            .secret_bytes()
            .to_vec(),
    )
    .unwrap();
    let mut reader = ChannelReader::new(&plane, CHANNEL, 0).unwrap();
    let wraps = [
        channel_wrap(&ALICE, "hello everyone", 100),
        channel_wrap(&SPAMMER, "buy spam now", 200),
    ];
    let messages = reader.ingest_all(wraps.iter().map(String::as_str), NOW, &BTreeSet::new());

    let recorder = Recorder::default();
    let (mut moderation, _) = moderation_host(&recorder);
    let mut runtime = Runtime::new(
        FakeRelayHost::default(),
        FakeSignerHost::default(),
        FakeClock::default(),
        RecordingAudit::default(),
    );
    let mut log = FakeLogHost::default();
    let policy = policy_for(&checked);
    for message in &messages {
        // Ordinary event matching: no special-casing of the event's type.
        let outcomes = runtime.run_handlers_for_event(
            &program,
            &checked,
            &message.to_signed_event(),
            &policy,
            &mut moderation,
            &mut log,
            Some(&pk(&BOT)),
            EvalLimits::default(),
            None,
        );
        assert_eq!(
            outcomes.len(),
            1,
            "the stream handler matched the received message"
        );
        assert!(outcomes[0].result.is_ok(), "{:?}", outcomes[0].result);
    }
    assert_eq!(log.records.len(), 1);
    assert_eq!(log.records[0].message, format!("kicking {}", pk(&SPAMMER)));
    assert_eq!(
        recorder.0.lock().unwrap().len(),
        1,
        "one real Guestbook kick was published"
    );
}
