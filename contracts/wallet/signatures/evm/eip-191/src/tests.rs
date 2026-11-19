use std::cell::Cell;

use defuse_crypto::secp256k1::Secp256k1RecoverableSignature;
use serde_json::Value;

use super::*;

fn vectors() -> Vec<Value> {
    serde_json::from_str::<Value>(include_str!("../tests/fixtures/eip191.json")).unwrap()["vectors"]
        .as_array()
        .unwrap()
        .clone()
}

fn address(vector: &Value) -> EthAddress {
    vector["address"].as_str().unwrap().parse().unwrap()
}

#[test]
fn malformed_proof_skips_message_provider() {
    let vector = &vectors()[0];
    let proof = vector["proof"].as_str().unwrap();
    let signature: Secp256k1RecoverableSignature = proof.parse().unwrap();

    let mut proofs = vec![
        String::new(),
        "secp256k1:".to_owned(),
        "secp256k1:0".to_owned(),
        format!("secp256k1:{}", "1".repeat(91)),
        proof.replacen("secp256k1:", "SECP256K1:", 1),
        proof.replacen("secp256k1:", "ed25519:", 1),
        proof.strip_prefix("secp256k1:").unwrap().to_owned(),
    ];

    // Recovery ids other than 0 and 1, including the wallets' 27.
    for v in [2, 3, 27, 28] {
        let mut bytes = signature.0;
        bytes[64] = v;
        proofs.push(Secp256k1RecoverableSignature(bytes).to_string());
    }

    for proof in proofs {
        // A false result alone would not catch eager message construction.
        assert!(!WalletEip191::verify(
            &address(vector),
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

        assert!(WalletEip191::verify(
            &address(&vector),
            || {
                calls.set(calls.get() + 1);
                Ok(vector["message"].as_str().unwrap().to_owned())
            },
            proof,
        ));
        assert_eq!(calls.get(), 1);
        assert!(!WalletEip191::verify(
            &address(&vector),
            || Err(MessageError::TooLarge),
            proof
        ));
    }
}
