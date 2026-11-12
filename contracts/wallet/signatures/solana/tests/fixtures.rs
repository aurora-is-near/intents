use std::time::Duration;

use defuse_wallet::{RequestMessage, SignatureSchema, offchain::OffchainMessage};
use defuse_wallet_solana::{
    WalletSolana,
    crypto::ed25519::{
        Ed25519PublicKey, Ed25519Signature,
        ed25519_dalek::{Signature, Verifier, VerifyingKey},
    },
    offchain_signing_message, request_signing_message,
};
use serde_json::{Value, json};

fn vectors() -> Vec<Value> {
    serde_json::from_str::<Value>(include_str!("fixtures/solana.json")).unwrap()["vectors"]
        .as_array()
        .unwrap()
        .clone()
}
fn key(v: &Value) -> Ed25519PublicKey {
    format!("ed25519:{}", v["public_key"].as_str().unwrap())
        .parse()
        .unwrap()
}

#[test]
fn independent_openssl_vectors() {
    for v in vectors() {
        let public_key = key(&v);
        let proof = v["proof"].as_str().unwrap();
        if v["kind"] == "request" {
            let msg: RequestMessage = serde_json::from_value(v["msg"].clone()).unwrap();
            assert_eq!(
                request_signing_message(&public_key, &msg).unwrap(),
                v["message"]
            );
            assert!(WalletSolana::verify_request_msg(&public_key, &msg, proof));
        } else {
            let msg: OffchainMessage = serde_json::from_value(v["msg"].clone()).unwrap();
            assert_eq!(
                offchain_signing_message(&public_key, &msg).unwrap(),
                v["message"]
            );
            assert!(WalletSolana::verify_offchain_msg(&public_key, &msg, proof));
        }
    }
}

#[test]
fn execution_fields_are_bound() {
    let all = vectors();
    let v = &all[2];
    let original = &v["msg"];
    let mutations = [
        ("/chain_id", json!("testnet")),
        ("/signer_id", json!("other.near")),
        ("/nonce", json!(43)),
        ("/created_at", json!("2026-11-03T12:34:56.123456788Z")),
        ("/timeout_secs", json!(301)),
        ("/pay_for_gas", json!(false)),
        ("/request/internal/0/payload/enable", json!(true)),
        (
            "/request/internal/1/payload/account_id",
            json!("other.near"),
        ),
        ("/request/internal/1/op", json!("add_extension")),
        ("/request/internal/2/payload/token_id", json!("other.near")),
        ("/request/internal/2/payload/decimals", json!(17)),
        ("/request/internal/2/payload/symbol", json!("TKM")),
        ("/request/external/0/receiver_id", json!("other.near")),
        (
            "/request/external/0/actions/0/payload/function_name",
            json!("other"),
        ),
        ("/request/external/0/actions/0/payload/args", json!("e30=")),
        ("/request/external/0/actions/0/payload/deposit", json!("2")),
        ("/request/external/0/actions/0/payload/gas", json!("1")),
        (
            "/request/external/0/actions/0/payload/gas_weight",
            json!("1"),
        ),
    ];
    for (pointer, value) in mutations {
        let mut changed = original.clone();
        *changed.pointer_mut(pointer).unwrap() = value;
        let msg: RequestMessage = serde_json::from_value(changed).unwrap();
        assert!(
            !WalletSolana::verify_request_msg(&key(v), &msg, v["proof"].as_str().unwrap()),
            "accepted {pointer}"
        );
    }
    for pointer in ["/request/internal", "/request/external/0/actions"] {
        let mut changed = original.clone();
        changed
            .pointer_mut(pointer)
            .unwrap()
            .as_array_mut()
            .unwrap()
            .reverse();
        let msg: RequestMessage = serde_json::from_value(changed).unwrap();
        assert!(!WalletSolana::verify_request_msg(
            &key(v),
            &msg,
            v["proof"].as_str().unwrap()
        ));
    }
}

#[test]
fn transfer_refund_and_state_init_are_bound() {
    let all = vectors();
    for (index, pointer, value) in [
        (1, "/request/external/0/refund_to", json!("other.near")),
        (
            1,
            "/request/external/0/actions/0/payload/amount",
            json!("1"),
        ),
        (
            3,
            "/request/external/0/actions/0/payload/deposit",
            json!("10"),
        ),
        (
            3,
            "/request/external/0/actions/0/payload/state_init/V1/code/account_id",
            json!("other.near"),
        ),
        (
            3,
            "/request/external/0/actions/0/payload/state_init/V1/data/AAEC",
            json!("AQ=="),
        ),
    ] {
        let v = &all[index];
        let mut changed = v["msg"].clone();
        *changed.pointer_mut(pointer).unwrap() = value;
        let msg: RequestMessage = serde_json::from_value(changed).unwrap();
        assert!(
            !WalletSolana::verify_request_msg(&key(v), &msg, v["proof"].as_str().unwrap()),
            "accepted {pointer}"
        );
    }
}

#[test]
fn offchain_fields_are_bound_without_normalizing_payload() {
    let all = vectors();
    let v = &all[5];
    for (pointer, value) in [
        ("/chain_id", json!("mainnet")),
        ("/signer_id", json!("other.near")),
        ("/path", json!(["app.near", "parent.near"])),
        ("/path", json!([])),
        ("/path", json!(["parent.near", "app.near", "other.near"])),
        ("/timestamp", json!("2026-11-03T12:34:56.120000001Z")),
        ("/payload", json!("different")),
        (
            "/payload",
            json!(v["msg"]["payload"].as_str().unwrap().replace(' ', "")),
        ),
    ] {
        let mut changed = v["msg"].clone();
        *changed.pointer_mut(pointer).unwrap() = value;
        let msg: OffchainMessage = serde_json::from_value(changed).unwrap();
        assert!(
            !WalletSolana::verify_offchain_msg(&key(v), &msg, v["proof"].as_str().unwrap()),
            "accepted {pointer}"
        );
    }
}

#[test]
fn malformed_wrong_key_and_cross_domain_proofs_fail() {
    let all = vectors();
    let v = &all[0];
    let msg: RequestMessage = serde_json::from_value(v["msg"].clone()).unwrap();
    for proof in [
        "",
        "ed25519:",
        "secp256k1:invalid",
        "not a signature",
        all[4]["proof"].as_str().unwrap(),
    ] {
        assert!(!WalletSolana::verify_request_msg(&key(v), &msg, proof));
    }
    assert!(!WalletSolana::verify_request_msg(
        &Ed25519PublicKey([0; 32]),
        &msg,
        v["proof"].as_str().unwrap()
    ));
    // With the identity point as the key, R = identity and s = 0 satisfy the
    // Ed25519 equation for every message (the NEAR host function accepts
    // such a forgery); only the weak-key check rejects it.
    let mut identity = [0; 32];
    identity[0] = 1;
    let mut forged = [0; 64];
    forged[0] = 1;
    let message = request_signing_message(&Ed25519PublicKey(identity), &msg).unwrap();
    assert!(
        VerifyingKey::from_bytes(&identity)
            .unwrap()
            .verify(message.as_bytes(), &Signature::from_bytes(&forged))
            .is_ok()
    );
    assert!(!WalletSolana::verify_request_msg(
        &Ed25519PublicKey(identity),
        &msg,
        &Ed25519Signature(forged).to_string()
    ));
    let auth: OffchainMessage = serde_json::from_value(all[4]["msg"].clone()).unwrap();
    assert!(!WalletSolana::verify_offchain_msg(
        &key(v),
        &auth,
        v["proof"].as_str().unwrap()
    ));
}

#[test]
fn limits_and_ambiguous_timeout_are_rejected() {
    let all = vectors();
    let v = &all[0];
    let mut msg: RequestMessage = serde_json::from_value(v["msg"].clone()).unwrap();
    msg.timeout = Duration::from_nanos(1);
    assert!(request_signing_message(&key(v), &msg).is_err());
    msg.timeout = Duration::from_secs(u64::from(u32::MAX) + 1);
    assert!(request_signing_message(&key(v), &msg).is_err());
    let mut auth: OffchainMessage = serde_json::from_value(all[4]["msg"].clone()).unwrap();
    auth.payload = "x".repeat(16 * 1024);
    assert!(offchain_signing_message(&key(v), &auth).is_err());
    auth.payload = "bidi\u{202e} and emoji 🌍".to_string();
    let rendered = offchain_signing_message(&key(v), &auth).unwrap();
    assert!(rendered.is_ascii());
    assert!(rendered.contains("\\u202e"));
    assert!(rendered.contains("\\ud83c\\udf0d"));
}

#[test]
fn state_init_fixture_uses_derived_receiver() {
    let table: serde_json::Value =
        serde_json::from_str(include_str!("fixtures/solana.json")).unwrap();
    for v in table["vectors"].as_array().unwrap() {
        if v["kind"] != "request" {
            continue;
        }
        let msg: defuse_wallet::RequestMessage = serde_json::from_value(v["msg"].clone()).unwrap();
        for promise in msg.request.external {
            for action in promise.actions {
                if let defuse_wallet::actions::NearAction::DeterministicStateInit(init) = action {
                    assert_eq!(promise.receiver_id, init.state_init.derive_account_id());
                }
            }
        }
    }
}
