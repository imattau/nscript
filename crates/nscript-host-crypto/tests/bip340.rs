//! Official BIP-340 test vectors (bitcoin/bips `test-vectors.csv`).

use nscript_host_crypto::schnorr::{sign, sign_random, verify};

fn unhex(text: &str) -> Vec<u8> {
    (0..text.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&text[i..i + 2], 16).unwrap())
        .collect()
}

fn array<const N: usize>(text: &str) -> [u8; N] {
    unhex(text).try_into().unwrap()
}

#[test]
fn every_official_vector_signs_and_verifies_as_specified() {
    let csv = include_str!("vectors/bip340-vectors.csv");
    let mut signed = 0;
    let mut verified = 0;
    for line in csv.lines().skip(1) {
        let fields: Vec<&str> = line.splitn(8, ',').collect();
        let (secret, pubkey, aux, message, signature, expected) = (
            fields[1], fields[2], fields[3], fields[4], fields[5], fields[6],
        );
        let message = unhex(message);
        let signature: [u8; 64] = array(signature);
        // Public keys that are not on the curve fail verification outright.
        let pubkey: Option<[u8; 32]> = unhex(pubkey).try_into().ok();
        let valid = pubkey.is_some_and(|key| verify(&key, &message, &signature));
        assert_eq!(valid, expected == "TRUE", "verify: {line}");
        verified += 1;
        if !secret.is_empty() {
            let produced = sign(&array(secret), &message, &array(aux)).unwrap();
            assert_eq!(produced, signature, "sign: {line}");
            signed += 1;
        }
    }
    assert_eq!((signed, verified), (8, 19));
}

#[test]
fn random_signatures_verify_and_are_bound_to_the_message() {
    let secret = [7_u8; 32];
    let pubkey = nscript_host_crypto::group_key::xonly_pubkey(&secret).unwrap();
    let id = [0x42_u8; 32];
    let signature = sign_random(&secret, &id).unwrap();
    assert!(verify(&pubkey, &id, &signature));
    assert!(!verify(&pubkey, &[0x43; 32], &signature));
    let mut flipped = signature;
    flipped[10] ^= 1;
    assert!(!verify(&pubkey, &id, &flipped));
    // Fresh aux randomness gives a different (still valid) signature.
    assert_ne!(sign_random(&secret, &id).unwrap(), signature);
}
