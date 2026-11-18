//! Run this consumer separately for each feature set; workspace tests unify features.
#![cfg(test)]

use base64::{Engine, engine::general_purpose::STANDARD};
use defuse_wallet_sui::SuiPublicKey;
// Native NEAR host mocks are needed by the shared message formatter.
use near_sdk as _;
use serde_json::Value;

fn vectors() -> Vec<Value> {
    serde_json::from_str::<Value>(include_str!("../fixtures/sui.json")).unwrap()["vectors"]
        .as_array()
        .unwrap()
        .clone()
}

fn key(vector: &Value) -> (SuiPublicKey, Vec<u8>) {
    let bytes = STANDARD
        .decode(
            vector["public_key"]
                .as_str()
                .unwrap()
                .strip_prefix("sui:")
                .unwrap(),
        )
        .unwrap();
    // StateInit can supply Borsh state directly, bypassing public-key parsing.
    (borsh::from_slice(&bytes).unwrap(), bytes)
}

#[test]
fn only_enabled_schemes_parse_and_verify() {
    for vector in vectors() {
        let (key, bytes) = key(&vector);
        let enabled = match key.flag() {
            0 => cfg!(feature = "ed25519"),
            1 => cfg!(feature = "secp256k1"),
            2 => cfg!(feature = "p256"),
            _ => unreachable!(),
        };
        assert_eq!(SuiPublicKey::from_sui_bytes(&bytes).is_ok(), enabled);
        assert_eq!(
            key.verify_personal_message(
                vector["message"].as_str().unwrap().as_bytes(),
                vector["proof"].as_str().unwrap(),
            ),
            enabled
        );
        #[cfg(feature = "ed25519")]
        check_schema::<defuse_wallet_sui::crypto::ed25519::Ed25519>(&key, &vector);
        #[cfg(feature = "secp256k1")]
        check_schema::<defuse_wallet_sui::crypto::secp256k1::Secp256k1>(&key, &vector);
        #[cfg(feature = "p256")]
        check_schema::<defuse_wallet_sui::crypto::p256::P256>(&key, &vector);
    }
}

#[cfg(any(feature = "ed25519", feature = "secp256k1", feature = "p256"))]
fn check_schema<C: defuse_wallet_sui::protocol::SuiScheme>(key: &SuiPublicKey, vector: &Value) {
    use defuse_wallet::SignatureSchema;
    use defuse_wallet_sui::WalletSui;

    let proof = vector["proof"].as_str().unwrap();
    let verified = match vector["kind"].as_str().unwrap() {
        "request" => WalletSui::<C>::verify_request_msg(
            key,
            &serde_json::from_value(vector["msg"].clone()).unwrap(),
            proof,
        ),
        "offchain" => WalletSui::<C>::verify_offchain_msg(
            key,
            &serde_json::from_value(vector["msg"].clone()).unwrap(),
            proof,
        ),
        kind => panic!("unexpected fixture kind: {kind}"),
    };
    assert_eq!(verified, key.flag() == C::FLAG);
}

#[test]
fn malformed_proofs_never_authorize() {
    for vector in vectors() {
        let (key, _) = key(&vector);
        let message = vector["message"].as_str().unwrap().as_bytes();
        for size in 0..220 {
            assert!(!key.verify_personal_message(message, &STANDARD.encode(vec![0; size])));
        }
        let original = STANDARD.decode(vector["proof"].as_str().unwrap()).unwrap();
        for index in 0..original.len() {
            let mut mutated = original.clone();
            mutated[index] ^= 1;
            assert!(!key.verify_personal_message(message, &STANDARD.encode(mutated)));
        }
    }
}
