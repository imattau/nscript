//! Real moderation directives, published then re-read by an independent
//! reader that folds them with the runtime's authority and Guestbook code.

use std::sync::{Arc, Mutex};

use nscript_host_crypto::group_key::{group_key, xonly_pubkey};
use nscript_host_crypto::moderation::{CommunityKeys, ConcordModerationHost};
use nscript_host_crypto::stream::{SealForm, build_seal, build_wrap, open_stream_event};
use nscript_runtime::authority::{
    AuthorityFold, Roster, banlist_locator, community_id, grant_locator,
};
use nscript_runtime::edition::{Edition, FoldMode, VSK_GRANT, VSK_ROLE, Vac};
use nscript_runtime::guestbook::{Guestbook, GuestbookEntry, MemberState, parse_guestbook_rumor};
use nscript_runtime::wire::{build_edition, parse_edition_rumor};
use nscript_runtime::{
    FakeClock, FakeRelayHost, FakeSignerHost, InvocationId, OperationPolicy, OperationValue,
    PublishReport, RecordingAudit, RelayHost, RelayOutcome, Runtime, RuntimeError, SignedEvent,
};
use serde_json::json;

const SALT: &str = "0202020202020202020202020202020202020202020202020202020202020202";
const ROOT: [u8; 32] = [7; 32];
const CONTROL_ROOT: [u8; 32] = [8; 32];
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

fn pubkey(secret: &[u8; 32]) -> String {
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
                relay: "rec".into(),
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

struct Community {
    owner: [u8; 32],
    cid: String,
    setup: Vec<(Edition, String)>,
    relay: Recorder,
    setup_wires: Vec<String>,
}

const ADMIN: [u8; 32] = [2; 32]; // position 1: KICK | BAN | MANAGE_ROLES
const MODER: [u8; 32] = [3; 32]; // position 5: KICK only
const VICTIM: [u8; 32] = [4; 32]; // holds the low-ranking `helper` role
const SPAMMER: [u8; 32] = [5; 32]; // no roles
const ADMIN_ROLE: &str = "1100000000000000000000000000000000000000000000000000000000000000";
const MOD_ROLE: &str = "2200000000000000000000000000000000000000000000000000000000000000";
const HELPER_ROLE: &str = "3300000000000000000000000000000000000000000000000000000000000000";

impl Community {
    fn new() -> Self {
        let owner = [1_u8; 32];
        let cid = community_id(&pubkey(&owner), SALT).unwrap();
        let mut c = Self {
            owner,
            cid,
            setup: Vec::new(),
            relay: Recorder::default(),
            setup_wires: Vec::new(),
        };
        for (id, pos, bits) in [
            (ADMIN_ROLE, 1, 1 | 8 | 16),
            (MOD_ROLE, 5, 8),
            (HELPER_ROLE, 9, 0),
        ] {
            let content = format!(
                r#"{{"role_id":"{id}","name":"r","position":{pos},"permissions":"{bits}","scope":{{"kind":"server"}}}}"#
            );
            c.owner_edition(VSK_ROLE, id, &content);
        }
        for (member, role) in [
            (&ADMIN, ADMIN_ROLE),
            (&MODER, MOD_ROLE),
            (&VICTIM, HELPER_ROLE),
        ] {
            let m = pubkey(member);
            let eid = grant_locator(&c.cid, &m).unwrap();
            c.owner_edition(
                VSK_GRANT,
                &eid,
                &format!(r#"{{"member":"{m}","role_ids":["{role}"]}}"#),
            );
        }
        c
    }

    fn owner_edition(&mut self, vsk: u8, eid: &str, content: &str) {
        let (edition, json) =
            build_edition(vsk, eid, None, content, &pubkey(&self.owner), None, NOW).unwrap();
        self.setup_wires.push(self.control_wrap(&self.owner, &json));
        self.setup.push((edition, json));
    }

    fn control_wrap(&self, author: &[u8; 32], rumor_json: &str) -> String {
        let cid = unhex32(&self.cid);
        let signer = group_key("concord/control-signer", &CONTROL_ROOT, &cid, Some(0));
        let read = group_key("concord/control", &ROOT, &cid, Some(0)).conversation_key();
        let seal = build_seal(&read, SealForm::Plaintext, author, rumor_json, NOW).unwrap();
        build_wrap(&signer.secret_bytes(), &read, &seal, &[], NOW).unwrap()
    }

    fn fold(&self) -> AuthorityFold {
        let mut fold = AuthorityFold::new(
            &pubkey(&self.owner),
            SALT,
            &self.cid,
            FoldMode::Tracking,
            256,
        )
        .unwrap();
        for (edition, _) in &self.setup {
            assert!(fold.insert(edition.clone()));
        }
        fold
    }

    fn keys(&self, staff: bool) -> CommunityKeys {
        CommunityKeys {
            community_id: unhex32(&self.cid),
            community_root: ROOT,
            epoch: 0,
            control_root: staff.then_some(CONTROL_ROOT),
        }
    }

    fn host(&self, actor: &[u8; 32], staff: bool) -> ConcordModerationHost {
        let mut host = ConcordModerationHost::new(
            *actor,
            self.keys(staff),
            self.fold(),
            Box::new(self.relay.clone()),
            "community",
        );
        host.fixed_time = Some(NOW + 60);
        host
    }

    fn published(&self) -> Vec<SignedEvent> {
        self.relay.0.lock().unwrap().clone()
    }

    /// An independent reader: holds only what a member holds (the control
    /// public key and the `community_root`), opens every wrap, and folds.
    fn read(&self) -> (Roster, Guestbook) {
        let cid = unhex32(&self.cid);
        let control_pk =
            group_key("concord/control-signer", &CONTROL_ROOT, &cid, Some(0)).xonly_pubkey();
        let control_read = group_key("concord/control", &ROOT, &cid, Some(0)).conversation_key();
        let book = group_key("concord/guestbook", &ROOT, &cid, Some(0));
        let mut authority = AuthorityFold::new(
            &pubkey(&self.owner),
            SALT,
            &self.cid,
            FoldMode::Tracking,
            256,
        )
        .unwrap();
        let mut entries: Vec<GuestbookEntry> = Vec::new();
        let wires = self
            .setup_wires
            .iter()
            .cloned()
            .chain(self.published().into_iter().map(|event| wire(&event)));
        for wire in wires {
            if let Ok(opened) =
                open_stream_event(&control_pk, &control_read, SealForm::Plaintext, &wire)
            {
                authority.insert(parse_edition_rumor(&opened.author, &opened.rumor_json).unwrap());
            } else if let Ok(opened) = open_stream_event(
                &book.xonly_pubkey(),
                &book.conversation_key(),
                SealForm::Encrypted,
                &wire,
            ) {
                entries.push(parse_guestbook_rumor(&opened.author, &opened.rumor_json).unwrap());
            }
        }
        let roster = authority.roster();
        let guestbook = Guestbook::fold(&entries, &authority, &roster, None, 2_000_000_000_000);
        (roster, guestbook)
    }
}

fn call(
    host: &mut ConcordModerationHost,
    op: &str,
    target: &[u8; 32],
) -> Result<OperationValue, RuntimeError> {
    nscript_runtime::OperationHost::call(
        host,
        1,
        "concord04",
        op,
        &[OperationValue::PubKey(pubkey(target))],
    )
}

#[test]
fn a_ban_becomes_a_banlist_edition_every_reader_honours() {
    let c = Community::new();
    let mut host = c.host(&ADMIN, true);
    let report = call(&mut host, "ban_member", &SPAMMER).unwrap();
    assert!(matches!(report, OperationValue::PublishReport(r) if r.accepted()));
    assert_eq!(c.published().len(), 1);
    assert_eq!(c.published()[0].unsigned.kind, 1059);

    let (roster, _) = c.read();
    assert!(
        roster.banned.contains(&pubkey(&SPAMMER)),
        "an independent reader folds the ban"
    );
    assert!(
        !roster.can(&pubkey(&SPAMMER), 8, Some(&pubkey(&VICTIM))),
        "and the banned can do nothing"
    );
    // The host's own view already reflects what it published.
    assert!(host.authority().roster().banned.contains(&pubkey(&SPAMMER)));
}

#[test]
fn successive_bans_chain_into_one_replace_entire_list() {
    let c = Community::new();
    let mut host = c.host(&ADMIN, true);
    call(&mut host, "ban_member", &SPAMMER).unwrap();
    call(&mut host, "ban_member", &VICTIM).unwrap();
    let (roster, _) = c.read();
    assert_eq!(
        roster.banned.len(),
        2,
        "the second edition keeps the first ban"
    );
    let heads = host
        .authority()
        .heads(nscript_runtime::edition::VSK_BANLIST);
    assert_eq!(heads.len(), 1);
    assert_eq!(heads[0].version, 2);
    assert_eq!(heads[0].entity_id, banlist_locator(&c.cid).unwrap());
    assert!(
        heads[0].vac.is_some(),
        "a non-owner cites the Grant it acts under"
    );
}

#[test]
fn bans_the_actor_may_not_make_publish_nothing() {
    let c = Community::new();
    let mut moderator = c.host(&MODER, true);
    assert!(
        matches!(
            call(&mut moderator, "ban_member", &SPAMMER),
            Err(RuntimeError::AuthorityDenied { .. })
        ),
        "no BAN bit"
    );
    let mut admin = c.host(&ADMIN, true);
    let owner = &c.owner;
    assert!(
        matches!(
            call(&mut admin, "ban_member", owner),
            Err(RuntimeError::AuthorityDenied { .. })
        ),
        "the owner is unremovable"
    );
    // Without the staff write key there is nowhere to publish.
    let mut keyless = c.host(&ADMIN, false);
    assert!(matches!(
        call(&mut keyless, "ban_member", &SPAMMER),
        Err(RuntimeError::CapabilityDenied { .. })
    ));
    assert!(c.published().is_empty());
}

#[test]
fn a_kick_strips_roles_then_departs_when_the_actor_may_do_both() {
    let c = Community::new();
    let mut admin = c.host(&ADMIN, true);
    call(&mut admin, "kick_member", &VICTIM).unwrap();
    assert_eq!(
        c.published().len(),
        2,
        "role removal first, then the Guestbook directive"
    );

    let (roster, guestbook) = c.read();
    assert!(
        roster.grants[&pubkey(&VICTIM)].is_empty(),
        "the target's authority is gone"
    );
    assert_eq!(guestbook.state(&pubkey(&VICTIM)), Some(MemberState::Kicked));
}

#[test]
fn a_kick_degrades_to_the_weaker_removal_without_role_authority() {
    let c = Community::new();
    let mut moderator = c.host(&MODER, false);
    call(&mut moderator, "kick_member", &VICTIM).unwrap();
    assert_eq!(
        c.published().len(),
        1,
        "no MANAGE_ROLES or control key: directive only"
    );
    let (roster, guestbook) = c.read();
    assert_eq!(
        roster.grants[&pubkey(&VICTIM)],
        vec![HELPER_ROLE.to_owned()],
        "roles untouched"
    );
    assert_eq!(guestbook.state(&pubkey(&VICTIM)), Some(MemberState::Kicked));
}

#[test]
fn kicks_the_actor_may_not_make_publish_nothing() {
    let c = Community::new();
    let mut moderator = c.host(&MODER, false);
    let admin = &ADMIN;
    assert!(
        matches!(
            call(&mut moderator, "kick_member", admin),
            Err(RuntimeError::AuthorityDenied { .. })
        ),
        "must outrank"
    );
    assert_eq!(
        call(&mut moderator, "can_kick", &SPAMMER).unwrap(),
        OperationValue::Integer(1)
    );
    assert_eq!(
        call(&mut moderator, "can_ban", &SPAMMER).unwrap(),
        OperationValue::Integer(0)
    );
    assert!(c.published().is_empty());
}

#[test]
fn the_runtime_policy_gate_still_applies_first() {
    let c = Community::new();
    let mut admin = c.host(&ADMIN, true);
    let mut runtime = Runtime::new(
        FakeRelayHost::default(),
        FakeSignerHost::default(),
        FakeClock::default(),
        RecordingAudit::default(),
    );
    let kick_only = OperationPolicy::default().allow("concord04", "kick_member");
    let args = [OperationValue::PubKey(pubkey(&SPAMMER))];
    let denied = runtime.invoke_authorized_operation(
        &kick_only,
        &mut admin,
        "concord04",
        "ban_member",
        &args,
    );
    assert!(
        matches!(denied, Err(RuntimeError::CapabilityDenied { .. })),
        "an admin identity does not widen the script's grant"
    );
    assert!(c.published().is_empty());
}

#[test]
fn a_demoted_actor_cannot_ban_and_its_stale_grant_is_not_cited() {
    // The owner strips the admin's Grant; the host's next view has no rank.
    let c = Community::new();
    let mut fold = c.fold();
    let admin = pubkey(&ADMIN);
    let eid = grant_locator(&c.cid, &admin).unwrap();
    let old = fold
        .heads(VSK_GRANT)
        .into_iter()
        .find(|h| h.entity_id == eid)
        .unwrap();
    let (strip, _) = build_edition(
        VSK_GRANT,
        &eid,
        Some(&old),
        &format!(r#"{{"member":"{admin}","role_ids":[]}}"#),
        &pubkey(&c.owner),
        None,
        NOW + 1,
    )
    .unwrap();
    fold.insert(strip);
    let mut host = ConcordModerationHost::new(
        ADMIN,
        c.keys(true),
        fold,
        Box::new(c.relay.clone()),
        "community",
    );
    assert!(matches!(
        call(&mut host, "ban_member", &SPAMMER),
        Err(RuntimeError::AuthorityDenied { .. })
    ));
    assert!(c.published().is_empty());
    let _ = Vac {
        grant_eid: eid,
        version: 1,
        hash: String::new(),
    };
}
