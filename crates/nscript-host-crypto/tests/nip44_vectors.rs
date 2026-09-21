//! Official NIP-44 v2 test vectors (paulmillr/nip44, `nip44.vectors.json`).

use nscript_host_crypto::nip44::{
    Nip44Error, calc_padded_len, conversation_key, decrypt, encrypt_with_nonce, message_keys,
};
use serde_json::Value;
use sha2::{Digest, Sha256};

fn vectors() -> Value {
    let raw = include_str!("vectors/nip44.vectors.json");
    serde_json::from_str::<Value>(raw).unwrap()["v2"].clone()
}

fn unhex<const N: usize>(text: &str) -> [u8; N] {
    let bytes: Vec<u8> = (0..text.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&text[i..i + 2], 16).unwrap())
        .collect();
    bytes.try_into().unwrap()
}

fn hex(bytes: &[u8]) -> String {
    use std::fmt::Write as _;
    bytes.iter().fold(String::new(), |mut out, b| {
        let _ = write!(out, "{b:02x}");
        out
    })
}

fn text<'a>(value: &'a Value, field: &str) -> &'a str {
    value[field].as_str().unwrap()
}

#[test]
fn conversation_keys_match() {
    let cases = vectors()["valid"]["get_conversation_key"].clone();
    for case in cases.as_array().unwrap() {
        let key = conversation_key(&unhex(text(case, "sec1")), &unhex(text(case, "pub2"))).unwrap();
        assert_eq!(hex(&key), text(case, "conversation_key"), "{case}");
    }
}

#[test]
fn invalid_conversation_key_inputs_are_rejected() {
    let cases = vectors()["invalid"]["get_conversation_key"].clone();
    for case in cases.as_array().unwrap() {
        let result = conversation_key(&unhex(text(case, "sec1")), &unhex(text(case, "pub2")));
        assert!(result.is_err(), "{case}");
    }
}

#[test]
fn message_keys_match() {
    let group = vectors()["valid"]["get_message_keys"].clone();
    let conv: [u8; 32] = unhex(text(&group, "conversation_key"));
    for case in group["keys"].as_array().unwrap() {
        let keys = message_keys(&conv, &unhex(text(case, "nonce")));
        assert_eq!(hex(&keys.chacha_key), text(case, "chacha_key"));
        assert_eq!(hex(&keys.chacha_nonce), text(case, "chacha_nonce"));
        assert_eq!(hex(&keys.hmac_key), text(case, "hmac_key"));
    }
}

#[test]
fn padded_lengths_match() {
    for pair in vectors()["valid"]["calc_padded_len"].as_array().unwrap() {
        let (len, padded) = (pair[0].as_u64().unwrap(), pair[1].as_u64().unwrap());
        assert_eq!(
            calc_padded_len(usize::try_from(len).unwrap()),
            usize::try_from(padded).unwrap()
        );
    }
}

#[test]
fn encrypt_and_decrypt_match_byte_for_byte() {
    for case in vectors()["valid"]["encrypt_decrypt"].as_array().unwrap() {
        let conv: [u8; 32] = unhex(text(case, "conversation_key"));
        let nonce: [u8; 32] = unhex(text(case, "nonce"));
        let plaintext = text(case, "plaintext");
        let payload = encrypt_with_nonce(&conv, &nonce, plaintext.as_bytes()).unwrap();
        assert_eq!(payload, text(case, "payload"), "{case}");
        assert_eq!(decrypt(&conv, &payload).unwrap(), plaintext.as_bytes());
    }
}

#[test]
fn long_messages_match_by_hash() {
    for case in vectors()["valid"]["encrypt_decrypt_long_msg"]
        .as_array()
        .unwrap()
    {
        let conv: [u8; 32] = unhex(text(case, "conversation_key"));
        let nonce: [u8; 32] = unhex(text(case, "nonce"));
        let repeat = usize::try_from(case["repeat"].as_u64().unwrap()).unwrap();
        let plaintext = text(case, "pattern").repeat(repeat);
        assert_eq!(
            hex(&Sha256::digest(plaintext.as_bytes())),
            text(case, "plaintext_sha256")
        );
        let payload = encrypt_with_nonce(&conv, &nonce, plaintext.as_bytes()).unwrap();
        assert_eq!(
            hex(&Sha256::digest(payload.as_bytes())),
            text(case, "payload_sha256")
        );
        assert_eq!(decrypt(&conv, &payload).unwrap(), plaintext.as_bytes());
    }
}

#[test]
fn out_of_range_plaintext_lengths_are_refused() {
    let conv = [7_u8; 32];
    let nonce = [1_u8; 32];
    for len in vectors()["invalid"]["encrypt_msg_lengths"]
        .as_array()
        .unwrap()
    {
        let plaintext = vec![b'a'; usize::try_from(len.as_u64().unwrap()).unwrap()];
        assert_eq!(
            encrypt_with_nonce(&conv, &nonce, &plaintext),
            Err(Nip44Error::InvalidPlaintextLength),
            "length {len}"
        );
    }
}

#[test]
fn invalid_payloads_are_refused() {
    for case in vectors()["invalid"]["decrypt"].as_array().unwrap() {
        let conv: [u8; 32] = unhex(text(case, "conversation_key"));
        let result = decrypt(&conv, text(case, "payload"));
        assert!(result.is_err(), "{}: {case}", text(case, "note"));
    }
}

#[test]
fn a_tampered_payload_fails_the_mac() {
    let conv = [9_u8; 32];
    let payload = encrypt_with_nonce(&conv, &[3_u8; 32], b"hello").unwrap();
    let mut bytes: Vec<char> = payload.chars().collect();
    let last = bytes.len() - 6;
    bytes[last] = if bytes[last] == 'A' { 'B' } else { 'A' };
    let tampered: String = bytes.into_iter().collect();
    assert_eq!(decrypt(&conv, &tampered), Err(Nip44Error::InvalidMac));
}
