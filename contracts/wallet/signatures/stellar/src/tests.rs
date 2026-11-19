use std::cell::Cell;

use serde_json::Value;

use super::*;

fn vectors() -> Vec<Value> {
    serde_json::from_str::<Value>(include_str!("../tests/fixtures/stellar.json")).unwrap()
        ["vectors"]
        .as_array()
        .unwrap()
        .clone()
}

fn key(vector: &Value) -> Ed25519PublicKey {
    let address = vector["address"].as_str().unwrap();

    Ed25519PublicKey(
        stellar_strkey::ed25519::PublicKey::from_string(address)
            .unwrap()
            .0,
    )
}

#[test]
fn malformed_proof_skips_message_provider() {
    let vector = &vectors()[0];
    let proof = vector["proof"].as_str().unwrap();

    // Unused bits of the last character set: not canonical base64.
    let mut loose = proof.to_owned();
    loose.replace_range(85..86, "x");
    assert_ne!(loose, proof);

    for proof in [
        String::new(),
        proof[..87].to_owned(),
        format!("{proof}="),
        proof.trim_end_matches('=').to_owned(),
        format!("{}  ", proof.trim_end_matches('=')),
        "!".repeat(PROOF_LEN),
        // 65 and 66 bytes also take 88 characters.
        STANDARD.encode([0; 65]),
        STANDARD.encode([0; 66]),
        loose,
        format!("ed25519:{}", &proof[8..]),
    ] {
        // A false result alone would not catch eager message construction.
        assert!(!WalletStellar::verify(
            &key(vector),
            || panic!("malformed proof must not render a message: {proof}"),
            &proof,
        ));
    }
}

#[test]
fn valid_proofs_render_once() {
    for vector in vectors() {
        let proof = vector["proof"].as_str().unwrap();
        let calls = Cell::new(0);

        assert!(WalletStellar::verify(
            &key(&vector),
            || {
                calls.set(calls.get() + 1);
                Ok(vector["message"].as_str().unwrap().to_owned())
            },
            proof,
        ));
        assert_eq!(calls.get(), 1);
        assert!(!WalletStellar::verify(
            &key(&vector),
            || Err(MessageError::TooLarge),
            proof
        ));
    }
}

#[test]
fn unparseable_key_skips_message_provider() {
    let proof = vectors()[0]["proof"].as_str().unwrap().to_owned();
    let invalid = (0u8..=255)
        .map(|byte| Ed25519PublicKey([byte; 32]))
        .find(|key| <Ed25519 as Curve>::PublicKey::try_from(key).is_err())
        .expect("the corpus must contain an invalid compressed point");

    assert!(!WalletStellar::verify(
        &invalid,
        || panic!("an unparseable key must not render a message"),
        &proof,
    ));
}
