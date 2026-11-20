mod common;
use std::time::Duration;

use common::{FixtureScheme, each_scheme, key, stored, verify};
use defuse_wallet::{RequestMessage, SignatureSchema, offchain::OffchainMessage};
use defuse_wallet_sui::{
    WalletSui,
    crypto::{ed25519::Ed25519, p256::P256, secp256k1::Secp256k1},
    offchain_signing_message, request_signing_message,
};
// Link the native NEAR host mocks used by the deterministic-address hash.
use near_sdk as _;
use serde_json::{Value, json};

/// Kinds of the vectors of each scheme, in the order the tests index them.
const LAYOUT: [&str; 9] = [
    "request", "request", "request", "request", "offchain", "offchain", "offchain", "request",
    "request",
];

/// Vectors of the scheme `C`, checked against [`LAYOUT`], so that a
/// regenerated fixture cannot silently drop vectors or shift the indexes.
fn scheme<C: FixtureScheme>() -> Vec<Value> {
    let group = common::vectors::<C>();
    let kinds: Vec<&str> = group.iter().map(|v| v["kind"].as_str().unwrap()).collect();

    assert_eq!(kinds, LAYOUT, "{}", C::NAME);

    group
}

#[test]
fn every_vector_belongs_to_one_of_the_three_schemes() {
    let grouped = scheme::<Ed25519>().len() + scheme::<Secp256k1>().len() + scheme::<P256>().len();

    assert_eq!(grouped, common::all_vectors().len());
}

#[test]
fn official_sui_sdk_vectors() {
    fn check<C: FixtureScheme>() {
        for v in scheme::<C>() {
            let public_key = key::<C>(&v);
            let rendered = if v["kind"] == "request" {
                let msg: RequestMessage = serde_json::from_value(v["msg"].clone()).unwrap();

                request_signing_message(&public_key, &msg).unwrap()
            } else {
                let msg: OffchainMessage = serde_json::from_value(v["msg"].clone()).unwrap();

                offchain_signing_message(&public_key, &msg).unwrap()
            };

            assert_eq!(rendered, v["message"]);
            assert!(verify(&public_key, &v, v["proof"].as_str().unwrap()));
        }
    }

    each_scheme!(check);
}

#[test]
fn execution_fields_are_bound() {
    fn check<C: FixtureScheme>() {
        let all = scheme::<C>();
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
            (
                "/request/external/0/actions/0/payload/function_name",
                json!("other"),
            ),
            (
                "/request/external/0/actions/0/payload/args",
                json!("eyJyZWNlaXZlcl9pZCI6Im90aGVyLm5lYXIiLCJhbW91bnQiOiIyIn0="),
            ),
            // Mutate the generic call: a non-one-yocto FT deposit is invalid before verification.
            ("/request/external/0/actions/1/payload/deposit", json!("2")),
            ("/request/external/0/actions/0/payload/gas", json!("1")),
            (
                "/request/external/0/actions/0/payload/gas_weight",
                json!("1"),
            ),
        ];

        for (pointer, value) in mutations {
            let mut changed = original.clone();
            // Optional fields may be absent in the wire input, but their defaults are signed.
            let (parent, field) = pointer.rsplit_once('/').unwrap();

            changed
                .pointer_mut(parent)
                .unwrap()
                .as_object_mut()
                .unwrap()
                .insert(field.to_owned(), value);

            let msg: RequestMessage = serde_json::from_value(changed).unwrap();

            assert_ne!(
                request_signing_message(&key::<C>(v), &msg).expect("mutation must render"),
                v["message"]
            );
            assert!(
                !WalletSui::<C>::verify_request_msg(
                    &key::<C>(v),
                    &msg,
                    v["proof"].as_str().unwrap()
                ),
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
                request_signing_message(&key::<C>(v), &msg).expect("mutation must render"),
                v["message"]
            );
            assert!(!WalletSui::<C>::verify_request_msg(
                &key::<C>(v),
                &msg,
                v["proof"].as_str().unwrap()
            ));
        }

        // The token contract is part of the signature.
        let mut moved: RequestMessage = serde_json::from_value(original.clone()).unwrap();

        moved.request.external[0].receiver_id = "other.near".parse().unwrap();
        request_signing_message(&key::<C>(v), &moved).unwrap();

        assert!(!WalletSui::<C>::verify_request_msg(
            &key::<C>(v),
            &moved,
            v["proof"].as_str().unwrap()
        ));

        // The native transfer recipient is bound independently as well.
        let transfer = &all[1];
        let mut msg: RequestMessage = serde_json::from_value(transfer["msg"].clone()).unwrap();

        msg.request.external[0].receiver_id = "other.near".parse().unwrap();
        request_signing_message(&key::<C>(transfer), &msg).unwrap();

        assert!(!WalletSui::<C>::verify_request_msg(
            &key::<C>(transfer),
            &msg,
            transfer["proof"].as_str().unwrap()
        ));
    }

    each_scheme!(check);
}

#[test]
fn transfer_refund_and_state_init_are_bound() {
    fn check<C: FixtureScheme>() {
        let all = scheme::<C>();
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
                request_signing_message(&key::<C>(v), &msg).expect("mutation must render"),
                v["message"]
            );
            assert!(
                !WalletSui::<C>::verify_request_msg(
                    &key::<C>(v),
                    &msg,
                    v["proof"].as_str().unwrap()
                ),
                "accepted {pointer}"
            );
        }
    }

    each_scheme!(check);
}

#[test]
fn offchain_fields_are_bound_without_normalizing_payload() {
    fn check<C: FixtureScheme>() {
        let all = scheme::<C>();
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
                offchain_signing_message(&key::<C>(v), &msg).expect("mutation must render"),
                v["message"]
            );
            assert!(
                !WalletSui::<C>::verify_offchain_msg(
                    &key::<C>(v),
                    &msg,
                    v["proof"].as_str().unwrap()
                ),
                "accepted {pointer}"
            );
        }
    }

    each_scheme!(check);
}

#[test]
fn malformed_wrong_key_and_cross_domain_proofs_fail() {
    fn check<C: FixtureScheme>() {
        let all = scheme::<C>();
        let v = &all[0];
        let msg: RequestMessage = serde_json::from_value(v["msg"].clone()).unwrap();

        for proof in [
            "",
            "ed25519:",
            "secp256k1:invalid",
            "not a signature",
            all[4]["proof"].as_str().unwrap(),
        ] {
            assert!(!WalletSui::<C>::verify_request_msg(
                &key::<C>(v),
                &msg,
                proof
            ));
        }

        // `StateInit` can store any key: the proof of another key is refused.
        let wrong = stored::<C>(&vec![0; key::<C>(v).raw_bytes().len()]);

        assert!(!WalletSui::<C>::verify_request_msg(
            &wrong,
            &msg,
            v["proof"].as_str().unwrap()
        ));

        let auth: OffchainMessage = serde_json::from_value(all[4]["msg"].clone()).unwrap();

        assert!(!WalletSui::<C>::verify_offchain_msg(
            &key::<C>(v),
            &auth,
            v["proof"].as_str().unwrap()
        ));
    }

    each_scheme!(check);
}

#[test]
fn limits_and_ambiguous_timeout_are_rejected() {
    fn check<C: FixtureScheme>() {
        let all = scheme::<C>();
        let v = &all[0];
        let mut msg: RequestMessage = serde_json::from_value(v["msg"].clone()).unwrap();

        msg.timeout = Duration::from_nanos(1);

        assert!(request_signing_message(&key::<C>(v), &msg).is_err());
        assert!(!WalletSui::<C>::verify_request_msg(
            &key::<C>(v),
            &msg,
            v["proof"].as_str().unwrap()
        ));

        msg.timeout = Duration::from_secs(u64::from(u32::MAX) + 1);

        assert!(request_signing_message(&key::<C>(v), &msg).is_err());
        assert!(!WalletSui::<C>::verify_request_msg(
            &key::<C>(v),
            &msg,
            v["proof"].as_str().unwrap()
        ));

        let mut auth: OffchainMessage = serde_json::from_value(all[4]["msg"].clone()).unwrap();
        auth.payload = "x".repeat(16 * 1024);

        assert!(offchain_signing_message(&key::<C>(v), &auth).is_err());

        auth.payload = "bidi\u{202e} and emoji 🌍".to_string();

        let rendered = offchain_signing_message(&key::<C>(v), &auth).unwrap();

        assert!(rendered.is_ascii());
        assert!(rendered.contains("\\u202e"));
        assert!(rendered.contains("\\ud83c\\udf0d"));
    }

    each_scheme!(check);
}

#[test]
fn state_init_fixture_uses_derived_receiver() {
    for v in common::all_vectors() {
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

/// Frozen vectors computed outside this repository: `0s` and the last 20
/// bytes of `keccak256(borsh(StateInit))`. A change of the stored identity or
/// of the state layout changes every wallet address.
#[test]
fn derived_accounts_match_known_answers() {
    use defuse_wallet::{GlobalContractId, State, StateInit, StateInitV1};

    fn check<C: FixtureScheme>(known: &[(u32, u64, &str)]) {
        let public_key = key::<C>(&scheme::<C>()[0]);

        for &(subwallet_id, timeout, expected) in known {
            let state = State::new(public_key)
                .subwallet_id(subwallet_id)
                .timeout(Duration::from_secs(timeout));
            let account = StateInit::V1(StateInitV1 {
                code: GlobalContractId::CodeHash([0x11; 32]),
                data: state.as_storage(),
            })
            .derive_account_id();

            assert_eq!(account.as_str(), expected, "{}", C::NAME);
        }
    }

    check::<Ed25519>(&[
        (0, 3600, "0s4a8437992cee5812f4bdc749e9e5ae0cef7ff6f8"),
        (1, 3600, "0sc07d0962bdb16423339c6f66b4e04a402d24bb0b"),
        (0, 300, "0s6e1818d42750a7eb70e2a108514d4d62d6fc62ce"),
    ]);
    check::<Secp256k1>(&[
        (0, 3600, "0s05a737b0b48b9f072456d250152b440873786830"),
        (1, 3600, "0sd8fdeebf26a3ec48cb94d883f26016f7cd03cdb1"),
    ]);
    check::<P256>(&[
        (0, 3600, "0s896c6c95b46ec102f962d7807aa3cb1d1c92381a"),
        (1, 3600, "0sd2628ffa3454bc15cfefa17c7b6c98c949ec5fee"),
    ]);
}
