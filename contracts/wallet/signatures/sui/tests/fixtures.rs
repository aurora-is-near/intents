mod common;
use common::TestSui as WalletSui;
use std::time::Duration;

use defuse_wallet::{RequestMessage, SignatureSchema, offchain::OffchainMessage};
use defuse_wallet_sui::{SuiPublicKey, offchain_signing_message, request_signing_message};
// Link the native NEAR host mocks used by the deterministic-address hash.
use near_sdk as _;
use serde_json::{Value, json};

fn vectors() -> Vec<Value> {
    serde_json::from_str::<Value>(include_str!("fixtures/sui.json")).unwrap()["vectors"]
        .as_array()
        .unwrap()
        .clone()
}
fn key(v: &Value) -> SuiPublicKey {
    v["public_key"].as_str().unwrap().parse().unwrap()
}

#[test]
fn official_sui_sdk_vectors() {
    for v in vectors() {
        let public_key = key(&v);
        let proof = v["proof"].as_str().unwrap();
        if v["kind"] == "request" {
            let msg: RequestMessage = serde_json::from_value(v["msg"].clone()).unwrap();
            assert_eq!(
                request_signing_message(&public_key, &msg).unwrap(),
                v["message"]
            );
            assert!(WalletSui::verify_request_msg(&public_key, &msg, proof));
        } else {
            let msg: OffchainMessage = serde_json::from_value(v["msg"].clone()).unwrap();
            assert_eq!(
                offchain_signing_message(&public_key, &msg).unwrap(),
                v["message"]
            );
            assert!(WalletSui::verify_offchain_msg(&public_key, &msg, proof));
        }
    }
}

#[test]
fn execution_fields_are_bound() {
    for all in vectors().chunks_exact(9) {
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
            ("/request/internal/2/payload/decimals", json!(17)),
            ("/request/internal/2/payload/symbol", json!("TKM")),
            (
                "/request/external/0/actions/0/payload/function_name",
                json!("other"),
            ),
            (
                "/request/external/0/actions/0/payload/args",
                json!("eyJyZWNlaXZlcl9pZCI6Im90aGVyLm5lYXIiLCJhbW91bnQiOiIyIn0="),
            ),
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
            assert_ne!(
                request_signing_message(&key(v), &msg).expect("mutation must render"),
                v["message"]
            );
            assert!(
                !WalletSui::verify_request_msg(&key(v), &msg, v["proof"].as_str().unwrap()),
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
            assert_ne!(
                request_signing_message(&key(v), &msg).expect("mutation must render"),
                v["message"]
            );
            assert!(!WalletSui::verify_request_msg(
                &key(v),
                &msg,
                v["proof"].as_str().unwrap()
            ));
        }
        // Move the metadata requirement and receiver together; the original proof must fail.
        let mut moved: RequestMessage = serde_json::from_value(original.clone()).unwrap();
        let defuse_wallet::WalletOp::RequireFtMetadata { token_id, .. } =
            &mut moved.request.internal[2]
        else {
            unreachable!()
        };
        *token_id = "other.near".parse().unwrap();
        moved.request.external[0].receiver_id = token_id.clone();
        request_signing_message(&key(v), &moved).unwrap();
        assert!(!WalletSui::verify_request_msg(
            &key(v),
            &moved,
            v["proof"].as_str().unwrap()
        ));
        // A native transfer has no token-metadata coupling.
        let transfer = &all[1];
        let mut msg: RequestMessage = serde_json::from_value(transfer["msg"].clone()).unwrap();
        msg.request.external[0].receiver_id = "other.near".parse().unwrap();
        request_signing_message(&key(transfer), &msg).unwrap();
        assert!(!WalletSui::verify_request_msg(
            &key(transfer),
            &msg,
            transfer["proof"].as_str().unwrap()
        ));
    }
}

#[test]
fn transfer_refund_and_state_init_are_bound() {
    for all in vectors().chunks_exact(9) {
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
            assert_ne!(
                request_signing_message(&key(v), &msg).expect("mutation must render"),
                v["message"]
            );
            assert!(
                !WalletSui::verify_request_msg(&key(v), &msg, v["proof"].as_str().unwrap()),
                "accepted {pointer}"
            );
        }
    }
}

#[test]
fn offchain_fields_are_bound_without_normalizing_payload() {
    for all in vectors().chunks_exact(9) {
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
            assert_ne!(
                offchain_signing_message(&key(v), &msg).expect("mutation must render"),
                v["message"]
            );
            assert!(
                !WalletSui::verify_offchain_msg(&key(v), &msg, v["proof"].as_str().unwrap()),
                "accepted {pointer}"
            );
        }
    }
}

#[test]
fn malformed_wrong_key_and_cross_domain_proofs_fail() {
    for all in vectors().chunks_exact(9) {
        let v = &all[0];
        let msg: RequestMessage = serde_json::from_value(v["msg"].clone()).unwrap();
        for proof in [
            "",
            "ed25519:",
            "secp256k1:invalid",
            "not a signature",
            all[4]["proof"].as_str().unwrap(),
        ] {
            assert!(!WalletSui::verify_request_msg(&key(v), &msg, proof));
        }
        assert!(!WalletSui::verify_request_msg(
            &SuiPublicKey::Ed25519([0; 32]),
            &msg,
            v["proof"].as_str().unwrap()
        ));
        let auth: OffchainMessage = serde_json::from_value(all[4]["msg"].clone()).unwrap();
        assert!(!WalletSui::verify_offchain_msg(
            &key(v),
            &auth,
            v["proof"].as_str().unwrap()
        ));
    }
}

#[test]
fn limits_and_ambiguous_timeout_are_rejected() {
    for all in vectors().chunks_exact(9) {
        let v = &all[0];
        let mut msg: RequestMessage = serde_json::from_value(v["msg"].clone()).unwrap();
        msg.timeout = Duration::from_nanos(1);
        assert!(request_signing_message(&key(v), &msg).is_err());
        assert!(!WalletSui::verify_request_msg(
            &key(v),
            &msg,
            v["proof"].as_str().unwrap()
        ));
        msg.timeout = Duration::from_secs(u64::from(u32::MAX) + 1);
        assert!(request_signing_message(&key(v), &msg).is_err());
        assert!(!WalletSui::verify_request_msg(
            &key(v),
            &msg,
            v["proof"].as_str().unwrap()
        ));
        let mut auth: OffchainMessage = serde_json::from_value(all[4]["msg"].clone()).unwrap();
        auth.payload = "x".repeat(16 * 1024);
        assert!(offchain_signing_message(&key(v), &auth).is_err());
        auth.payload = "bidi\u{202e} and emoji 🌍".to_string();
        let rendered = offchain_signing_message(&key(v), &auth).unwrap();
        assert!(rendered.is_ascii());
        assert!(rendered.contains("\\u202e"));
        assert!(rendered.contains("\\ud83c\\udf0d"));
    }
}

#[test]
fn state_init_fixture_uses_derived_receiver() {
    let table: serde_json::Value = serde_json::from_str(include_str!("fixtures/sui.json")).unwrap();
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

async fn metadata_binding<C, S>(raw: S)
where
    C: defuse_wallet_sui::sui::SuiScheme,
    S: defuse_wallet_sui::crypto::Signer<C>,
    S::Error: core::fmt::Debug,
{
    use defuse_wallet_sdk::WalletSigner;
    use defuse_wallet_sui::{WalletSui as Schema, WalletSuiSigner};
    let signer = WalletSuiSigner::<C, _>::new(raw);
    let mut msg: RequestMessage = serde_json::from_value(vectors()[2]["msg"].clone()).unwrap();
    msg.request.external.clear();
    let proof = signer.sign_request_msg(&msg).await.unwrap();
    assert!(Schema::<C>::verify_request_msg(
        &signer.public_key(),
        &msg,
        &proof
    ));
    let defuse_wallet::WalletOp::RequireFtMetadata { token_id, .. } = &mut msg.request.internal[2]
    else {
        unreachable!()
    };
    *token_id = "other.near".parse().unwrap();
    request_signing_message(&signer.public_key(), &msg).unwrap();
    assert!(!Schema::<C>::verify_request_msg(
        &signer.public_key(),
        &msg,
        &proof
    ));
}

#[tokio::test]
async fn metadata_token_id_is_bound_without_a_transfer() {
    use defuse_wallet_sui::crypto::{
        ed25519::{Ed25519, ed25519_dalek},
        p256::{P256, p256},
        secp256k1::{Secp256k1, k256},
    };
    metadata_binding::<Ed25519, _>(ed25519_dalek::SigningKey::from_bytes(&[42; 32])).await;
    metadata_binding::<Secp256k1, _>(
        k256::ecdsa::SigningKey::from_bytes((&[42; 32]).into()).unwrap(),
    )
    .await;
    metadata_binding::<P256, _>(p256::ecdsa::SigningKey::from_bytes((&[42; 32]).into()).unwrap())
        .await;
}

/// Frozen vectors computed outside this repository: `0s` and the last 20
/// bytes of `keccak256(borsh(StateInit))`. A change of the stored identity or
/// of the state layout changes every wallet address.
#[test]
fn derived_accounts_match_known_answers() {
    use defuse_wallet::{GlobalContractId, State, StateInit, StateInitV1};
    let all = vectors();
    for (index, subwallet_id, timeout, expected) in [
        (0, 0, 3600, "0s49051dd7652c535b2f422312d808d4702ae81678"),
        (0, 1, 3600, "0sbe69bfac8784d0a031a24ede2cc64bf701f4bdb2"),
        (0, 0, 300, "0s72b48612a269c7040a20e4a7180191af911de5fb"),
        (9, 0, 3600, "0sb569e1108c1e485d495072ccd28abf686742fadb"),
        (9, 1, 3600, "0s4716ec2dd8f5a97184792a125176b554949176f4"),
        (18, 0, 3600, "0sba9edac674b105460073c20e1548240cd259b34d"),
        (18, 1, 3600, "0s6f681ded58dec1caaa2ee11e7e42cad3c1ac2c9c"),
    ] {
        let state = State::new(key(&all[index]))
            .subwallet_id(subwallet_id)
            .timeout(Duration::from_secs(timeout));
        let account = StateInit::V1(StateInitV1 {
            code: GlobalContractId::CodeHash([0x11; 32]),
            data: state.as_storage(),
        })
        .derive_account_id();
        assert_eq!(account.as_str(), expected);
    }
}
