//! Rekey delivery: what a rotator builds, every receiver can (or cannot) use.

use nscript_host_crypto::group_key::{group_key, xonly_pubkey};
use nscript_host_crypto::rekey::{
    ReceiveOutcome, Receiver, Recipient, Rotation3303, build_rekey_events, receive_rekey,
};
use nscript_runtime::rekey::{AcceptedKey, MAX_BLOBS_PER_EVENT, Scope};

const CID: [u8; 32] = [9; 32];
const OLD_ROOT: [u8; 32] = [7; 32];
const NEW_ROOT: [u8; 32] = [11; 32];
const NEW_CONTROL: [u8; 32] = [12; 32];
const ROTATOR: [u8; 32] = [1; 32];
const CHANNEL: &str = "cc00000000000000000000000000000000000000000000000000000000000003";

fn hex(bytes: &[u8]) -> String {
    use std::fmt::Write as _;
    bytes.iter().fold(String::new(), |mut out, b| {
        let _ = write!(out, "{b:02x}");
        out
    })
}

fn member(seed: u8) -> [u8; 32] {
    [seed; 32]
}

fn recipient(secret: &[u8; 32], staff: bool) -> Recipient {
    Recipient {
        pubkey: hex(&xonly_pubkey(secret).unwrap()),
        staff,
    }
}

fn base_plan(root: [u8; 32], control: [u8; 32]) -> Rotation3303<'static> {
    Rotation3303 {
        rotator_secret: &ROTATOR,
        community_id: CID,
        scope: Scope::Community,
        prior_root: OLD_ROOT,
        prior_scope_key: OLD_ROOT,
        prior_epoch: 4,
        new_epoch: 5,
        new_key: root,
        new_control_root: Some(control),
        vac: None,
        created_at: 1_700_000_000,
    }
}

fn receiver(secret: &[u8; 32]) -> Receiver<'_> {
    Receiver {
        secret,
        community_id: CID,
        scope: Scope::Community,
        prior_root: OLD_ROOT,
        held_epoch: 4,
        held_key: OLD_ROOT,
    }
}

fn allow(_: &str, _: Option<&nscript_runtime::edition::Vac>, _: &Scope) -> bool {
    true
}

#[test]
fn members_and_staff_adopt_their_forms_and_the_removed_do_not() {
    let (staff, plain, removed) = (member(20), member(21), member(22));
    let events = build_rekey_events(
        &base_plan(NEW_ROOT, NEW_CONTROL),
        &[recipient(&staff, true), recipient(&plain, false)],
    )
    .unwrap();
    assert_eq!(events.len(), 1);
    assert!(
        !events[0].contains(&hex(&NEW_ROOT)),
        "keys are never on the wire in the clear"
    );

    let control_pk =
        group_key("concord/control-signer", &NEW_CONTROL, &CID, Some(5)).xonly_pubkey();
    match receive_rekey(&receiver(&plain), &events, allow) {
        ReceiveOutcome::Adopted(AcceptedKey::Base {
            root,
            control_pk: pk,
            control_root: None,
        }) => {
            assert_eq!((root, pk), (NEW_ROOT, control_pk));
        }
        other => panic!("member: {other:?}"),
    }
    match receive_rekey(&receiver(&staff), &events, allow) {
        ReceiveOutcome::Adopted(AcceptedKey::Base {
            control_root: Some(secret),
            ..
        }) => assert_eq!(secret, NEW_CONTROL),
        other => panic!("staff: {other:?}"),
    }
    assert_eq!(
        receive_rekey(&receiver(&removed), &events, allow),
        ReceiveOutcome::Removed
    );
}

#[test]
fn a_missing_chunk_is_never_a_removal() {
    let many: Vec<[u8; 32]> = (0..=u8::try_from(MAX_BLOBS_PER_EVENT).unwrap() + 4)
        .map(|i| member(i.wrapping_add(30)))
        .collect();
    let recipients: Vec<Recipient> = many.iter().map(|s| recipient(s, false)).collect();
    let events = build_rekey_events(&base_plan(NEW_ROOT, NEW_CONTROL), &recipients).unwrap();
    assert_eq!(
        events.len(),
        2,
        "chunked at {MAX_BLOBS_PER_EVENT} recipients per event"
    );

    let in_second_chunk = many.last().unwrap();
    // Only the first chunk arrived: nothing can be concluded yet.
    assert_eq!(
        receive_rekey(&receiver(in_second_chunk), &events[..1], allow),
        ReceiveOutcome::Incomplete { missing: vec![1] }
    );
    assert!(matches!(
        receive_rekey(&receiver(in_second_chunk), &events, allow),
        ReceiveOutcome::Adopted(_)
    ));
    // Someone left out is Removed only once *every* chunk is held.
    let outsider = member(200);
    assert!(matches!(
        receive_rekey(&receiver(&outsider), &events[..1], allow),
        ReceiveOutcome::Incomplete { .. }
    ));
    assert_eq!(
        receive_rekey(&receiver(&outsider), &events, allow),
        ReceiveOutcome::Removed
    );
}

#[test]
fn unauthorised_rotators_and_forks_are_never_adopted() {
    let me = member(20);
    let events =
        build_rekey_events(&base_plan(NEW_ROOT, NEW_CONTROL), &[recipient(&me, false)]).unwrap();
    // A rotator the roster does not authorise: holding a key is not authority.
    assert_eq!(
        receive_rekey(&receiver(&me), &events, |_, _, _| false),
        ReceiveOutcome::Nothing
    );
    // The rotation must extend the very key this client holds.
    let mut forked = receiver(&me);
    forked.held_key = [99; 32];
    assert_eq!(
        receive_rekey(&forked, &events, allow),
        ReceiveOutcome::Nothing
    );
    // A client at another epoch derives a different rekey address, so a rotation
    // for epoch 5 is simply not found there; it never adopts the wrong epoch.
    let mut behind = receiver(&me);
    behind.held_epoch = 2;
    assert_eq!(
        receive_rekey(&behind, &events, allow),
        ReceiveOutcome::Nothing
    );
    // The address derives from the prior root: a wrong root finds nothing.
    let mut lost = receiver(&me);
    lost.prior_root = [1; 32];
    assert_eq!(
        receive_rekey(&lost, &events, allow),
        ReceiveOutcome::Nothing
    );
}

#[test]
fn racing_rotators_converge_on_the_lowest_new_base_key() {
    let me = member(20);
    let rival = [2_u8; 32];
    let low = build_rekey_events(&base_plan([5; 32], [6; 32]), &[recipient(&me, false)]).unwrap();
    let mut high_plan = base_plan([50; 32], [60; 32]);
    high_plan.rotator_secret = &rival;
    let high = build_rekey_events(&high_plan, &[recipient(&me, false)]).unwrap();
    let both: Vec<String> = high.into_iter().chain(low).collect();
    match receive_rekey(&receiver(&me), &both, allow) {
        ReceiveOutcome::Adopted(AcceptedKey::Base { root, .. }) => assert_eq!(root, [5; 32]),
        other => panic!("{other:?}"),
    }
}

#[test]
fn a_private_channel_rekey_delivers_only_that_channels_key() {
    let (keeper, dropped) = (member(20), member(21));
    let old_channel_key = [33_u8; 32];
    let new_channel_key = [44_u8; 32];
    let plan = Rotation3303 {
        rotator_secret: &ROTATOR,
        community_id: CID,
        scope: Scope::Channel(CHANNEL.to_owned()),
        // Channel rekeys are addressed under the community_root, committed over the channel key.
        prior_root: OLD_ROOT,
        prior_scope_key: old_channel_key,
        prior_epoch: 1,
        new_epoch: 2,
        new_key: new_channel_key,
        new_control_root: None,
        vac: None,
        created_at: 1_700_000_000,
    };
    let events = build_rekey_events(&plan, &[recipient(&keeper, false)]).unwrap();
    let rx = |secret| Receiver {
        secret,
        community_id: CID,
        scope: Scope::Channel(CHANNEL.to_owned()),
        prior_root: OLD_ROOT,
        held_epoch: 1,
        held_key: old_channel_key,
    };
    assert!(
        matches!(receive_rekey(&rx(&keeper), &events, allow), ReceiveOutcome::Adopted(AcceptedKey::Channel { key }) if key == new_channel_key)
    );
    assert_eq!(
        receive_rekey(&rx(&dropped), &events, allow),
        ReceiveOutcome::Removed
    );
    // The same wraps are not a base rotation.
    assert_eq!(
        receive_rekey(&receiver(&keeper), &events, allow),
        ReceiveOutcome::Nothing
    );
}

#[test]
fn a_rotation_with_no_recipients_is_refused() {
    assert!(build_rekey_events(&base_plan(NEW_ROOT, NEW_CONTROL), &[]).is_err());
    let bad = Recipient {
        pubkey: "nope".to_owned(),
        staff: false,
    };
    assert!(build_rekey_events(&base_plan(NEW_ROOT, NEW_CONTROL), &[bad]).is_err());
}
