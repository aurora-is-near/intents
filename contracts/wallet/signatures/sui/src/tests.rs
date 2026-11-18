use std::cell::Cell;

use base64::{Engine, engine::general_purpose::STANDARD};
use defuse_crypto::{ed25519::Ed25519, p256::P256, secp256k1::Secp256k1};
use serde_json::Value;

use super::*;

fn check<C: SuiScheme>(vector: &Value) {
    let key: SuiPublicKey = vector["public_key"].as_str().unwrap().parse().unwrap();
    let proof = vector["proof"].as_str().unwrap();
    let bytes = STANDARD.decode(proof).unwrap();

    let mut wrong_flag = bytes.clone();
    wrong_flag[0] = 3;

    let mut wrong_key = bytes.clone();
    wrong_key[65] ^= 1;

    // Same encoded length, but the decoded key/signature envelope is too long.
    let mut wrong_length = bytes;
    wrong_length.push(0);

    // Set an unused padding bit without changing the decoded key bytes.
    let alphabet = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let last = proof.trim_end_matches('=').len() - 1;
    let mut noncanonical = proof.as_bytes().to_vec();
    let position = alphabet
        .iter()
        .position(|&b| b == noncanonical[last])
        .unwrap();

    noncanonical[last] = alphabet[position | 1];

    let noncanonical = String::from_utf8(noncanonical).unwrap();

    for malformed in [
        String::new(),
        "!".repeat(proof.len()),
        format!("{proof}A"),
        proof.trim_end_matches('=').to_owned(),
        STANDARD.encode(wrong_flag),
        STANDARD.encode(wrong_key),
        STANDARD.encode(wrong_length),
        noncanonical,
    ] {
        // Rejecting eventually is insufficient: malformed envelopes must skip rendering.
        assert!(!WalletSui::<C>::verify(
            &key,
            || panic!("malformed proof must not render a message"),
            &malformed,
        ));
    }

    let mismatched = if key.flag() == 0 {
        SuiPublicKey::Secp256k1([0; 33])
    } else {
        SuiPublicKey::Ed25519([0; 32])
    };

    assert!(!WalletSui::<C>::verify(
        &mismatched,
        || panic!("another scheme must not render a message"),
        proof,
    ));

    let calls = Cell::new(0);

    assert!(WalletSui::<C>::verify(
        &key,
        || {
            calls.set(calls.get() + 1);
            Ok(vector["message"].as_str().unwrap().to_owned())
        },
        proof,
    ));
    assert_eq!(calls.get(), 1);
    assert!(!WalletSui::<C>::verify(
        &key,
        || Err(MessageError::TooLarge),
        proof
    ));
}

#[test]
fn proofs_are_checked_before_rendering_for_every_scheme() {
    let fixture: Value = serde_json::from_str(include_str!("../tests/fixtures/sui.json")).unwrap();

    for vector in fixture["vectors"].as_array().unwrap() {
        let key: SuiPublicKey = vector["public_key"].as_str().unwrap().parse().unwrap();

        match key.flag() {
            0 => check::<Ed25519>(vector),
            1 => check::<Secp256k1>(vector),
            2 => check::<P256>(vector),
            _ => unreachable!(),
        }
    }
}
