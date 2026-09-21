//! `group_key` derivation properties and cross-checks.

use nscript_host_crypto::group_key::{coordinate, group_key, xonly_pubkey};
use nscript_host_crypto::host::Nip44KeyHost;
use nscript_host_crypto::nip44::{decrypt, encrypt_with_nonce};
use nscript_runtime::authority::{banlist_locator, community_id, grant_locator};
use nscript_runtime::stream::GroupKeyLabel;
use nscript_runtime::{ConcordKeyHost, RuntimeError, SharedSecret};

const SECRET: [u8; 32] = [7; 32];
const ID: [u8; 32] = [9; 32];

fn hex(bytes: &[u8]) -> String {
    use std::fmt::Write as _;
    bytes.iter().fold(String::new(), |mut out, b| {
        let _ = write!(out, "{b:02x}");
        out
    })
}

#[test]
fn derivation_is_deterministic_and_domain_separated() {
    let base = group_key("concord/channel", &SECRET, &ID, Some(1));
    assert_eq!(
        base.xonly_pubkey(),
        group_key("concord/channel", &SECRET, &ID, Some(1)).xonly_pubkey()
    );
    let others = [
        group_key("concord/guestbook", &SECRET, &ID, Some(1)),
        group_key("concord/channel", &[8; 32], &ID, Some(1)),
        group_key("concord/channel", &SECRET, &[1; 32], Some(1)),
        group_key("concord/channel", &SECRET, &ID, Some(2)),
        group_key("concord/channel", &SECRET, &ID, None),
    ];
    for other in others {
        assert_ne!(base.xonly_pubkey(), other.xonly_pubkey());
    }
}

#[test]
fn the_secret_matches_its_public_key_and_debug_hides_it() {
    let key = group_key("concord/control", &SECRET, &ID, Some(3));
    assert_eq!(
        xonly_pubkey(&key.secret_bytes()).unwrap(),
        key.xonly_pubkey()
    );
    assert!(!format!("{key:?}").contains(&hex(&key.secret_bytes())));
}

#[test]
fn a_plane_key_encrypts_and_decrypts_its_own_wrap() {
    let key = group_key("concord/channel", &SECRET, &ID, Some(1));
    let conv = key.conversation_key();
    let payload = encrypt_with_nonce(&conv, &[5; 32], b"Hey chat!").unwrap();
    assert_eq!(decrypt(&conv, &payload).unwrap(), b"Hey chat!");
    // A different plane's key cannot open it.
    let other = group_key("concord/guestbook", &SECRET, &ID, Some(1)).conversation_key();
    assert!(decrypt(&other, &payload).is_err());
}

#[test]
fn hkdf_agrees_with_the_runtimes_independent_implementation() {
    // The runtime derives coordinates with its own RFC 5869-tested HKDF; the
    // two implementations must produce identical keyless coordinates.
    let owner = "01".repeat(32);
    let salt = "02".repeat(32);
    let member = "aa".repeat(32);
    let cid = community_id(&owner, &salt).unwrap();
    let cid_bytes: [u8; 32] = (0..32)
        .map(|i| u8::from_str_radix(&cid[2 * i..2 * i + 2], 16).unwrap())
        .collect::<Vec<_>>()
        .try_into()
        .unwrap();
    let member_bytes = [0xaa_u8; 32];
    assert_eq!(
        hex(&coordinate(
            &cid_bytes,
            "concord/grant",
            &member_bytes,
            None
        )),
        grant_locator(&cid, &member).unwrap()
    );
    assert_eq!(
        hex(&coordinate(&cid_bytes, "concord/banlist", &[0; 32], None)),
        banlist_locator(&cid).unwrap()
    );
}

#[test]
fn the_host_derives_real_keys_behind_the_capability_gate() {
    let secret = SharedSecret::new(SECRET.to_vec()).unwrap();
    let id = hex(&ID);
    let mut host = Nip44KeyHost::default();
    let key = host
        .derive_group_key(1, GroupKeyLabel::Channel, &secret, &id, 1)
        .unwrap();
    let expected = group_key("concord/channel", &SECRET, &ID, Some(1));
    assert_eq!(key.as_bytes(), expected.secret_bytes());
    assert_eq!(host.derivations, 1);

    assert!(matches!(
        host.derive_group_key(2, GroupKeyLabel::Channel, &secret, "short", 1),
        Err(RuntimeError::InvalidOperationArguments { .. })
    ));
    assert!(matches!(
        host.derive_stream_key(3, &secret),
        Err(RuntimeError::OperationUnavailable { .. })
    ));
    let mut denied = Nip44KeyHost {
        denied: true,
        ..Nip44KeyHost::default()
    };
    assert!(matches!(
        denied.derive_group_key(4, GroupKeyLabel::Channel, &secret, &id, 1),
        Err(RuntimeError::CapabilityDenied { .. })
    ));
}
