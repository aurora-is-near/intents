use std::{str::FromStr, time::Duration};

use defuse_wallet::{RequestMessage, SignatureSchema, offchain::OffchainMessage};
use defuse_wallet_evm_eip191::{
    EthAddress, WalletEip191,
    crypto::secp256k1::{Secp256k1RecoverableSignature, k256},
    offchain_signing_message, request_signing_message,
};
use serde_json::{Value, json};

fn vectors() -> Vec<Value> {
    serde_json::from_str::<Value>(include_str!("fixtures/eip191.json")).unwrap()["vectors"]
        .as_array()
        .unwrap()
        .clone()
}

fn address(v: &Value) -> EthAddress {
    v["address"].as_str().unwrap().parse().unwrap()
}

#[test]
fn independent_noble_vectors() {
    for v in vectors() {
        let address = address(&v);
        let proof = v["proof"].as_str().unwrap();
        if v["kind"] == "request" {
            let msg: RequestMessage = serde_json::from_value(v["msg"].clone()).unwrap();
            assert_eq!(
                request_signing_message(&address, &msg).unwrap(),
                v["message"]
            );
            assert!(WalletEip191::verify_request_msg(&address, &msg, proof));
        } else {
            let msg: OffchainMessage = serde_json::from_value(v["msg"].clone()).unwrap();
            assert_eq!(
                offchain_signing_message(&address, &msg).unwrap(),
                v["message"]
            );
            assert!(WalletEip191::verify_offchain_msg(&address, &msg, proof));
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
            !WalletEip191::verify_request_msg(&address(v), &msg, v["proof"].as_str().unwrap()),
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
        assert!(!WalletEip191::verify_request_msg(
            &address(v),
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
            !WalletEip191::verify_request_msg(&address(v), &msg, v["proof"].as_str().unwrap()),
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
            !WalletEip191::verify_offchain_msg(&address(v), &msg, v["proof"].as_str().unwrap()),
            "accepted {pointer}"
        );
    }
}

#[test]
fn malformed_wrong_address_and_cross_domain_proofs_fail() {
    let all = vectors();
    let v = &all[0];
    let msg: RequestMessage = serde_json::from_value(v["msg"].clone()).unwrap();
    let proof = v["proof"].as_str().unwrap();
    for proof in [
        "",
        "secp256k1:",
        "secp256k1:invalid",
        "ed25519:invalid",
        "not a signature",
        // the same signature without the curve prefix or in another case
        proof.strip_prefix("secp256k1:").unwrap(),
        &proof.replace("secp256k1:", "SECP256K1:"),
        all[4]["proof"].as_str().unwrap(),
    ] {
        assert!(
            !WalletEip191::verify_request_msg(&address(v), &msg, proof),
            "accepted {proof:?}"
        );
    }
    assert!(!WalletEip191::verify_request_msg(
        &EthAddress([0; 20]),
        &msg,
        proof
    ));
    let auth: OffchainMessage = serde_json::from_value(all[4]["msg"].clone()).unwrap();
    assert!(!WalletEip191::verify_offchain_msg(
        &address(v),
        &auth,
        proof
    ));
}

/// Only the canonical `r || s || v` form is accepted: low-S, `v` in `{0, 1}`.
#[test]
fn malleated_and_wallet_encoded_signatures_fail() {
    let all = vectors();
    let v = &all[0];
    let msg: RequestMessage = serde_json::from_value(v["msg"].clone()).unwrap();
    let proof = Secp256k1RecoverableSignature::from_str(v["proof"].as_str().unwrap()).unwrap();
    let (signature, recovery_id) =
        <(k256::ecdsa::Signature, k256::ecdsa::RecoveryId)>::try_from(&proof).unwrap();

    // `(r, n - s)` with the flipped recovery id is the same key's high-S signature.
    let high_s = k256::ecdsa::Signature::from_scalars(signature.r(), -signature.s()).unwrap();
    let flipped = k256::ecdsa::RecoveryId::from_byte(recovery_id.to_byte() ^ 1).unwrap();
    let prehash = defuse_erc191::Erc191::prehash(v["message"].as_str().unwrap());
    assert_eq!(
        k256::ecdsa::VerifyingKey::recover_from_prehash(&prehash, &high_s, flipped).unwrap(),
        k256::ecdsa::VerifyingKey::recover_from_prehash(&prehash, &signature, recovery_id).unwrap(),
        "malleated signature must recover the same key",
    );
    let malleated = Secp256k1RecoverableSignature::from((high_s, flipped)).to_string();

    let mut wallet_v = proof.0;
    wallet_v[64] += 27;
    let wallet_v = Secp256k1RecoverableSignature(wallet_v).to_string();

    let mut other_id = proof.0;
    other_id[64] ^= 1;
    let other_id = Secp256k1RecoverableSignature(other_id).to_string();

    // Recovery ids 2 and 3 are outside the EVM proof format.
    let mut x_reduced = proof.0;
    x_reduced[64] |= 2;
    let x_reduced = Secp256k1RecoverableSignature(x_reduced).to_string();

    for proof in [malleated, wallet_v, other_id, x_reduced] {
        assert!(
            !WalletEip191::verify_request_msg(&address(v), &msg, &proof),
            "accepted {proof}"
        );
    }
}

#[test]
fn limits_and_ambiguous_timeout_are_rejected() {
    let all = vectors();
    let v = &all[0];
    let mut msg: RequestMessage = serde_json::from_value(v["msg"].clone()).unwrap();
    msg.timeout = Duration::from_nanos(1);
    assert!(request_signing_message(&address(v), &msg).is_err());
    msg.timeout = Duration::from_secs(u64::from(u32::MAX) + 1);
    assert!(request_signing_message(&address(v), &msg).is_err());
    let mut auth: OffchainMessage = serde_json::from_value(all[4]["msg"].clone()).unwrap();
    auth.payload = "x".repeat(16 * 1024);
    assert!(offchain_signing_message(&address(v), &auth).is_err());
    auth.payload = "bidi\u{202e} and emoji 🌍".to_string();
    let rendered = offchain_signing_message(&address(v), &auth).unwrap();
    assert!(rendered.is_ascii());
    assert!(rendered.contains("\\u202e"));
    assert!(rendered.contains("\\ud83c\\udf0d"));
}

#[test]
fn state_init_fixture_uses_derived_receiver() {
    for v in vectors() {
        if v["kind"] != "request" {
            continue;
        }
        let msg: RequestMessage = serde_json::from_value(v["msg"].clone()).unwrap();
        for promise in msg.request.external {
            for action in promise.actions {
                if let defuse_wallet::actions::NearAction::DeterministicStateInit(init) = action {
                    assert_eq!(promise.receiver_id, init.state_init.derive_account_id());
                }
            }
        }
    }
}
