//! A whole Refounding on a self-made community, checked from the outside.

use std::sync::{Arc, Mutex};

use nscript_host_crypto::group_key::{group_key, xonly_pubkey};
use nscript_host_crypto::moderation::{CommunityKeys, ConcordModerationHost};
use nscript_host_crypto::refound::{
    ChannelRekey, ControlArchive, RefoundError, RefoundingKeys, RefoundingRequest, plan_refounding,
};
use nscript_host_crypto::rekey::{ReceiveOutcome, Receiver, Recipient, receive_rekey};
use nscript_host_crypto::stream::{SealForm, build_seal, build_wrap, open_stream_event};
use nscript_runtime::authority::{AuthorityFold, banlist_locator, community_id, grant_locator};
use nscript_runtime::edition::{
    Edition, FoldMode, VSK_CHANNEL_METADATA, VSK_COMMUNITY_METADATA, VSK_GRANT, VSK_ROLE, Vac,
};
use nscript_runtime::guestbook::{Guestbook, MemberState, parse_guestbook_rumor};
use nscript_runtime::rekey::{AcceptedKey, Scope};
use nscript_runtime::wire::{build_edition, parse_edition_rumor};
use nscript_runtime::{
    InvocationId, OperationHost, OperationValue, PublishReport, RelayHost, RelayOutcome,
    RuntimeError, SignedEvent,
};
use serde_json::json;

const SALT: &str = "0202020202020202020202020202020202020202020202020202020202020202";
const OLD_ROOT: [u8; 32] = [7; 32];
const OLD_CONTROL: [u8; 32] = [8; 32];
const NEW_ROOT: [u8; 32] = [21; 32];
const NEW_CONTROL: [u8; 32] = [22; 32];
const NOW: u64 = 1_700_000_000;
const OWNER: [u8; 32] = [1; 32];
const ADMIN: [u8; 32] = [2; 32]; // position 1: KICK | BAN | MANAGE_ROLES
const MODER: [u8; 32] = [3; 32]; // position 5: KICK only
const VICTIM: [u8; 32] = [4; 32];
const SPAMMER: [u8; 32] = [5; 32];
const ADMIN_ROLE: &str = "1100000000000000000000000000000000000000000000000000000000000000";
const MOD_ROLE: &str = "2200000000000000000000000000000000000000000000000000000000000000";
const PRIVATE: &str = "9900000000000000000000000000000000000000000000000000000000000009";

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
struct Recorder {
    events: Arc<Mutex<Vec<SignedEvent>>>,
    /// Refuse every event whose position is below this count.
    reject_first: usize,
}

impl RelayHost for Recorder {
    fn publish(
        &mut self,
        _: InvocationId,
        event: &SignedEvent,
        _: &str,
    ) -> Result<PublishReport, RuntimeError> {
        let mut events = self.events.lock().unwrap();
        let accepted = events.len() >= self.reject_first;
        events.push(event.clone());
        Ok(PublishReport {
            outcomes: vec![RelayOutcome {
                relay: "r".into(),
                accepted,
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

struct World {
    cid: String,
    keys: CommunityKeys,
    fold: AuthorityFold,
    archive: ControlArchive,
    vac: Vac,
}

fn old_control_wrap(cid: &[u8; 32], author: &[u8; 32], rumor_json: &str) -> String {
    let signer = group_key("concord/control-signer", &OLD_CONTROL, cid, Some(0));
    let read = group_key("concord/control", &OLD_ROOT, cid, Some(0)).conversation_key();
    let seal = build_seal(&read, SealForm::Plaintext, author, rumor_json, NOW).unwrap();
    build_wrap(&signer.secret_bytes(), &read, &seal, &[], NOW).unwrap()
}

impl World {
    /// Owner genesis + roles + grants, then the admin bans the spammer.
    fn new() -> Self {
        let cid = community_id(&pk(&OWNER), SALT).unwrap();
        let cid_bytes = unhex32(&cid);
        let mut fold =
            AuthorityFold::new(&pk(&OWNER), SALT, &cid, FoldMode::Tracking, 256).unwrap();
        let mut archive = ControlArchive::default();
        let (old_pk, old_read) = (
            group_key("concord/control-signer", &OLD_CONTROL, &cid_bytes, Some(0)).xonly_pubkey(),
            group_key("concord/control", &OLD_ROOT, &cid_bytes, Some(0)).conversation_key(),
        );
        let mut editions = Vec::new();
        let mut owner_edition = |vsk: u8, eid: &str, content: String| {
            let (edition, json) =
                build_edition(vsk, eid, None, &content, &pk(&OWNER), None, NOW).unwrap();
            let wrap = old_control_wrap(&cid_bytes, &OWNER, &json);
            let ingested = archive.ingest(&old_pk, &old_read, &wrap).unwrap();
            assert_eq!(
                ingested, edition,
                "the archive decodes exactly what was built"
            );
            fold.insert(edition.clone());
            editions.push(edition);
        };
        owner_edition(
            VSK_COMMUNITY_METADATA,
            &cid,
            r#"{"name":"lab","relays":["wss://r"]}"#.to_owned(),
        );
        owner_edition(
            VSK_CHANNEL_METADATA,
            &"aa".repeat(32),
            r#"{"name":"general","private":false}"#.to_owned(),
        );
        for (id, pos, bits) in [(ADMIN_ROLE, 1, 1 | 8 | 16), (MOD_ROLE, 5, 8)] {
            owner_edition(
                VSK_ROLE,
                id,
                format!(
                    r#"{{"role_id":"{id}","name":"r","position":{pos},"permissions":"{bits}","scope":{{"kind":"server"}}}}"#
                ),
            );
        }
        for (member, role) in [
            (&ADMIN, ADMIN_ROLE),
            (&MODER, MOD_ROLE),
            (&VICTIM, MOD_ROLE),
        ] {
            let m = pk(member);
            owner_edition(
                VSK_GRANT,
                &grant_locator(&cid, &m).unwrap(),
                format!(r#"{{"member":"{m}","role_ids":["{role}"]}}"#),
            );
        }
        let keys = CommunityKeys {
            community_id: cid_bytes,
            community_root: OLD_ROOT,
            epoch: 0,
            control_root: Some(OLD_CONTROL),
        };

        // The admin bans the spammer through the real moderation host.
        let recorder = Recorder::default();
        let mut host = ConcordModerationHost::new(
            ADMIN,
            keys.clone(),
            fold,
            Box::new(recorder.clone()),
            "community",
        );
        host.fixed_time = Some(NOW + 60);
        host.call(
            1,
            "concord04",
            "ban_member",
            &[OperationValue::PubKey(pk(&SPAMMER))],
        )
        .unwrap();
        for event in recorder.events.lock().unwrap().iter() {
            let edition = archive.ingest(&old_pk, &old_read, &wire(event)).unwrap();
            editions.push(edition);
        }
        let fold = rebuild(&pk(&OWNER), &cid, &editions);
        let grant = fold
            .heads(VSK_GRANT)
            .into_iter()
            .find(|h| h.entity_id == grant_locator(&cid, &pk(&ADMIN)).unwrap())
            .unwrap();
        let vac = Vac {
            grant_eid: grant.entity_id.clone(),
            version: grant.version,
            hash: grant.hash().unwrap(),
        };
        Self {
            cid,
            keys,
            fold,
            archive,
            vac,
        }
    }

    fn remaining() -> Vec<Recipient> {
        vec![
            Recipient {
                pubkey: pk(&ADMIN),
                staff: true,
            },
            Recipient {
                pubkey: pk(&MODER),
                staff: false,
            },
            Recipient {
                pubkey: pk(&VICTIM),
                staff: false,
            },
        ]
    }

    fn request<'a>(&'a self, rotator: &'a [u8; 32], vac: Option<Vac>) -> RefoundingRequest<'a> {
        RefoundingRequest {
            rotator_secret: rotator,
            current: &self.keys,
            authority: &self.fold,
            archive: &self.archive,
            new_keys: RefoundingKeys {
                community_root: NEW_ROOT,
                control_root: NEW_CONTROL,
            },
            remaining: Self::remaining(),
            removed: vec![pk(&SPAMMER)],
            channels: vec![ChannelRekey {
                channel_id: PRIVATE.to_owned(),
                prior_key: [33; 32],
                prior_epoch: 0,
                new_key: [44; 32],
                recipients: vec![Recipient {
                    pubkey: pk(&VICTIM),
                    staff: false,
                }],
            }],
            vac,
            created_at: NOW + 120,
        }
    }
}

/// Rebuilds a fold from editions (the moderation host owns its own fold).
fn rebuild(owner: &str, cid: &str, editions: &[Edition]) -> AuthorityFold {
    let mut fold = AuthorityFold::new(owner, SALT, cid, FoldMode::Tracking, 256).unwrap();
    for edition in editions {
        fold.insert(edition.clone());
    }
    fold
}

fn receiver(secret: &[u8; 32], cid: [u8; 32]) -> Receiver<'_> {
    Receiver {
        secret,
        community_id: cid,
        scope: Scope::Community,
        prior_root: OLD_ROOT,
        held_epoch: 0,
        held_key: OLD_ROOT,
    }
}

fn allow(_: &str, _: Option<&Vac>, _: &Scope) -> bool {
    true
}

#[test]
fn a_remaining_member_follows_the_rotation_and_reads_an_equivalent_compacted_control_plane() {
    let world = World::new();
    let plan = plan_refounding(&world.request(&ADMIN, Some(world.vac.clone()))).unwrap();
    assert_eq!(plan.epoch, 1);
    let cid = world.keys.community_id;

    // The member finds the rotation at the address only an old-key holder can derive.
    let ReceiveOutcome::Adopted(AcceptedKey::Base {
        root,
        control_pk,
        control_root: None,
    }) = receive_rekey(&receiver(&VICTIM, cid), &plan.root_roll, allow)
    else {
        panic!("victim did not adopt");
    };
    assert_eq!(root, NEW_ROOT);

    // The compacted Control Plane reads under the new keys, addressed by the delivered control_pk.
    let read = group_key("concord/control", &root, &cid, Some(1)).conversation_key();
    let mut joiner =
        AuthorityFold::new(&pk(&OWNER), SALT, &world.cid, FoldMode::FreshJoiner, 256).unwrap();
    let mut actors = Vec::new();
    for wrap in &plan.compaction {
        let opened = open_stream_event(&control_pk, &read, SealForm::Plaintext, wrap)
            .expect("verifies at the new epoch");
        let edition = parse_edition_rumor(&opened.author, &opened.rumor_json).unwrap();
        actors.push((edition.rumor_id.clone(), edition.actor.clone()));
        joiner.insert(edition);
    }

    // Verbatim re-wrap: every head keeps its original author and rumor id.
    let mut expected: Vec<(String, String)> = [
        VSK_COMMUNITY_METADATA,
        VSK_CHANNEL_METADATA,
        VSK_ROLE,
        VSK_GRANT,
        4,
    ]
    .iter()
    .flat_map(|vsk| world.fold.heads(*vsk))
    .map(|e| (e.rumor_id, e.actor))
    .collect();
    expected.sort();
    actors.sort();
    assert_eq!(actors, expected, "signatures survive the epoch change");

    // A fresh joiner folds to the same authority state the old epoch had.
    let (before, after) = (world.fold.roster(), joiner.roster());
    assert_eq!(after.banned, before.banned);
    assert_eq!(after.grants, before.grants);
    assert_eq!(after.roles, before.roles);
    assert!(after.banned.contains(&pk(&SPAMMER)));
    assert!(
        joiner
            .heads(VSK_COMMUNITY_METADATA)
            .iter()
            .any(|h| h.content.contains("lab"))
    );
    assert_eq!(
        banlist_locator(&world.cid),
        joiner.heads(4).first().map(|h| h.entity_id.clone())
    );
}

#[test]
fn staff_receive_the_control_secret_and_the_removed_are_cut_off() {
    let world = World::new();
    let plan = plan_refounding(&world.request(&ADMIN, Some(world.vac.clone()))).unwrap();
    let cid = world.keys.community_id;
    match receive_rekey(&receiver(&ADMIN, cid), &plan.root_roll, allow) {
        ReceiveOutcome::Adopted(AcceptedKey::Base {
            control_root: Some(secret),
            ..
        }) => assert_eq!(secret, NEW_CONTROL),
        other => panic!("{other:?}"),
    }
    assert_eq!(
        receive_rekey(&receiver(&SPAMMER, cid), &plan.root_roll, allow),
        ReceiveOutcome::Removed
    );

    // The removed member holds only the old root: the new plane is unreadable.
    let new_pk = group_key("concord/control-signer", &NEW_CONTROL, &cid, Some(1)).xonly_pubkey();
    let old_read = group_key("concord/control", &OLD_ROOT, &cid, Some(1)).conversation_key();
    assert!(
        plan.compaction.iter().all(|w| open_stream_event(
            &new_pk,
            &old_read,
            SealForm::Plaintext,
            w
        )
        .is_err())
    );
}

#[test]
fn the_snapshot_seeds_survivors_and_the_private_channel_rekeys_under_the_prior_root() {
    let world = World::new();
    let plan = plan_refounding(&world.request(&ADMIN, Some(world.vac.clone()))).unwrap();
    let cid = world.keys.community_id;

    let book = group_key("concord/guestbook", &NEW_ROOT, &cid, Some(1));
    let entries: Vec<_> = plan
        .snapshot
        .iter()
        .map(|w| {
            open_stream_event(
                &book.xonly_pubkey(),
                &book.conversation_key(),
                SealForm::Encrypted,
                w,
            )
            .unwrap()
        })
        .map(|o| parse_guestbook_rumor(&o.author, &o.rumor_json).unwrap())
        .collect();
    let roster = world.fold.roster();
    let guestbook = Guestbook::fold(
        &entries,
        &world.fold,
        &roster,
        Some(&pk(&ADMIN)),
        2_000_000_000_000,
    );
    for survivor in [&ADMIN, &MODER, &VICTIM] {
        assert_eq!(guestbook.state(&pk(survivor)), Some(MemberState::Present));
    }
    assert_eq!(
        guestbook.state(&pk(&SPAMMER)),
        None,
        "the removed are not seeded"
    );
    // Only the refounder's snapshot is honoured.
    let ignored = Guestbook::fold(
        &entries,
        &world.fold,
        &roster,
        Some(&pk(&OWNER)),
        2_000_000_000_000,
    );
    assert_eq!(ignored.state(&pk(&VICTIM)), None);

    // The private channel's new key travels under the PRIOR root.
    let channel_rx = |secret| Receiver {
        secret,
        community_id: cid,
        scope: Scope::Channel(PRIVATE.to_owned()),
        prior_root: OLD_ROOT,
        held_epoch: 0,
        held_key: [33; 32],
    };
    assert!(matches!(
        receive_rekey(&channel_rx(&VICTIM), &plan.channel_rekeys, allow),
        ReceiveOutcome::Adopted(AcceptedKey::Channel { key }) if key == [44; 32]
    ));
    assert_eq!(
        receive_rekey(&channel_rx(&MODER), &plan.channel_rekeys, allow),
        ReceiveOutcome::Removed
    );
}

#[test]
fn refounding_needs_authority_and_a_complete_archive() {
    let world = World::new();
    // The moderator lacks BAN.
    let mod_grant = world
        .fold
        .heads(VSK_GRANT)
        .into_iter()
        .find(|h| h.entity_id == grant_locator(&world.cid, &pk(&MODER)).unwrap())
        .unwrap();
    let mod_vac = Vac {
        grant_eid: mod_grant.entity_id.clone(),
        version: mod_grant.version,
        hash: mod_grant.hash().unwrap(),
    };
    assert!(matches!(
        plan_refounding(&world.request(&MODER, Some(mod_vac))),
        Err(RefoundError::Unauthorized(_))
    ));
    // Without a citation the rotation would be dropped by readers, so it is refused.
    assert!(matches!(
        plan_refounding(&world.request(&ADMIN, None)),
        Err(RefoundError::Unauthorized(_))
    ));
    // The removed target may not outrank the rotator: the owner cannot be removed.
    let mut request = world.request(&ADMIN, Some(world.vac.clone()));
    request.removed = vec![pk(&OWNER)];
    assert!(matches!(
        plan_refounding(&request),
        Err(RefoundError::Unauthorized(_))
    ));

    // A head with no archived seal cannot be re-wrapped: abort, never drop it.
    let empty = ControlArchive::default();
    let mut request = world.request(&ADMIN, Some(world.vac.clone()));
    request.archive = &empty;
    assert!(matches!(
        plan_refounding(&request),
        Err(RefoundError::CannotCompact { .. })
    ));
}

#[test]
fn the_compaction_is_only_published_after_the_root_roll_is_confirmed() {
    let world = World::new();
    let plan = plan_refounding(&world.request(&ADMIN, Some(world.vac.clone()))).unwrap();

    // Happy path: strictly root roll, compaction, channel rekeys, snapshot.
    let ok = Recorder::default();
    plan.execute(&mut ok.clone(), "community").unwrap();
    let sent = ok.events.lock().unwrap().clone();
    let wire_ids: Vec<String> = plan
        .root_roll
        .iter()
        .chain(&plan.compaction)
        .chain(&plan.channel_rekeys)
        .chain(&plan.snapshot)
        .map(|w| {
            serde_json::from_str::<serde_json::Value>(w).unwrap()["id"]
                .as_str()
                .unwrap()
                .to_owned()
        })
        .collect();
    assert_eq!(
        sent.iter().map(|e| e.id.clone()).collect::<Vec<_>>(),
        wire_ids
    );

    // A refused root roll stops everything after it.
    let refusing = Recorder {
        reject_first: usize::MAX,
        ..Recorder::default()
    };
    let err = plan
        .execute(&mut refusing.clone(), "community")
        .unwrap_err();
    assert_eq!(err, RefoundError::RootRollNotConfirmed);
    assert_eq!(
        refusing.events.lock().unwrap().len(),
        plan.root_roll.len(),
        "no compaction leaked out"
    );
}
