use std::str::FromStr;

use defuse_wallet::{
    RequestMessage, SignatureSchema, WalletOp, actions::NearAction, offchain::OffchainMessage,
};
use defuse_wallet_evm_eip191::{WalletEip191, request_signing_message};
use defuse_wallet_evm_eip712::{
    DOMAIN_TYPE, Eip712Error, EthAddress, OFFCHAIN_TYPE, REQUEST_TYPE, WalletEip712,
    crypto::secp256k1::{Secp256k1RecoverableSignature, k256},
    domain_separator, offchain_digest, request_digest,
};
use serde_json::{Value, json};

fn fixture() -> Value {
    serde_json::from_str(include_str!("fixtures/eip712.json")).unwrap()
}

fn vectors() -> Vec<Value> {
    fixture()["vectors"].as_array().unwrap().clone()
}

fn address(v: &Value) -> EthAddress {
    v["address"].as_str().unwrap().parse().unwrap()
}

fn request(value: Value) -> RequestMessage {
    serde_json::from_value(value).unwrap()
}

/// Set or insert the member at `pointer`.
fn set(value: &mut Value, pointer: &str, member: Value) {
    let (parent, key) = pointer.rsplit_once('/').unwrap();
    value
        .pointer_mut(parent)
        .unwrap()
        .as_object_mut()
        .unwrap()
        .insert(key.to_owned(), member);
}

fn proof(v: &Value) -> &str {
    v["proof"].as_str().unwrap()
}

#[test]
fn types_and_domain_match_eth_sig_util() {
    let fixture = fixture();
    assert_eq!(fixture["encode_type"]["ExecuteRequest"], REQUEST_TYPE);
    assert_eq!(
        fixture["encode_type"]["OffchainAuthorization"],
        OFFCHAIN_TYPE
    );
    assert_eq!(DOMAIN_TYPE, "EIP712Domain(string name,string version)");
    assert_eq!(fixture["domain_separator"], hex::encode(domain_separator()));
}

#[test]
fn independent_vectors_verify() {
    for v in vectors() {
        let digest = if v["kind"] == "request" {
            let msg = request(v["msg"].clone());
            assert!(WalletEip712::verify_request_msg(
                &address(&v),
                &msg,
                proof(&v)
            ));
            request_digest(&msg).unwrap()
        } else {
            let msg: OffchainMessage = serde_json::from_value(v["msg"].clone()).unwrap();
            assert!(WalletEip712::verify_offchain_msg(
                &address(&v),
                &msg,
                proof(&v)
            ));
            offchain_digest(&msg).unwrap()
        };
        assert_eq!(v["digest"], hex::encode(digest));
    }
}

#[test]
fn execution_fields_are_bound() {
    let all = vectors();
    for (index, pointer, value) in [
        (2, "/chain_id", json!("testnet")),
        (2, "/signer_id", json!("other.near")),
        (2, "/nonce", json!(43)),
        (2, "/created_at", json!("2026-11-03T12:34:56.123456788Z")),
        (2, "/timeout_secs", json!(301)),
        (2, "/pay_for_gas", json!(false)),
        (2, "/request/internal/0/payload/enable", json!(true)),
        (
            2,
            "/request/internal/1/payload/account_id",
            json!("other.near"),
        ),
        (2, "/request/internal/1/op", json!("add_extension")),
        (
            2,
            "/request/internal/2/payload/token_id",
            json!("other.near"),
        ),
        (2, "/request/internal/2/payload/decimals", json!(17)),
        (2, "/request/internal/2/payload/symbol", json!("TKM")),
        (2, "/request/external/0/receiver_id", json!("other.near")),
        (2, "/request/external/0/refund_to", json!("token.near")),
        (
            2,
            "/request/external/0/actions/0/payload/function_name",
            json!("other"),
        ),
        (
            2,
            "/request/external/0/actions/0/payload/args",
            json!("eyJyZWNlaXZlcl9pZCI6Im90aGVyLm5lYXIiLCJhbW91bnQiOiIyIn0="),
        ),
        (
            2,
            "/request/external/0/actions/0/payload/deposit",
            json!("2"),
        ),
        (2, "/request/external/0/actions/0/payload/gas", json!("1")),
        (
            2,
            "/request/external/0/actions/0/payload/gas_weight",
            json!("1"),
        ),
        (1, "/request/external/0/refund_to", json!("other.near")),
        (
            1,
            "/request/external/0/actions/0/payload/amount",
            json!("1"),
        ),
        (
            1,
            "/request/internal/0/payload/account_id",
            json!("other.near"),
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
        (
            7,
            "/request/external/0/actions/0/payload/state_init/V1/code/hash",
            json!("11111111111111111111111111111112"),
        ),
    ] {
        let v = &all[index];
        let mut changed = v["msg"].clone();
        set(&mut changed, pointer, value);
        let changed = request(changed);
        assert_ne!(
            hex::encode(request_digest(&changed).expect("mutation must hash")),
            v["digest"]
        );
        assert!(
            !WalletEip712::verify_request_msg(&address(v), &changed, proof(v)),
            "accepted {index} {pointer}"
        );
    }
}

/// Order of operations and actions, and an absent refund target, are bound.
#[test]
fn order_and_absent_refund_are_bound() {
    let all = vectors();
    for pointer in ["/request/internal", "/request/external/0/actions"] {
        let v = &all[2];
        let mut changed = v["msg"].clone();
        changed
            .pointer_mut(pointer)
            .unwrap()
            .as_array_mut()
            .unwrap()
            .reverse();
        let changed = request(changed);
        assert_ne!(
            hex::encode(request_digest(&changed).expect("mutation must hash")),
            v["digest"]
        );
        assert!(!WalletEip712::verify_request_msg(
            &address(v),
            &changed,
            proof(v)
        ));
    }
    // An absent refund target differs from any account.
    let v = &all[1];
    let mut changed = v["msg"].clone();
    changed["request"]["external"][0]
        .as_object_mut()
        .unwrap()
        .remove("refund_to");
    let changed = request(changed);
    assert_ne!(
        hex::encode(request_digest(&changed).expect("mutation must hash")),
        v["digest"]
    );
    assert!(!WalletEip712::verify_request_msg(
        &address(v),
        &changed,
        proof(v)
    ));
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
            hex::encode(offchain_digest(&msg).expect("mutation must hash")),
            v["digest"]
        );
        assert!(
            !WalletEip712::verify_offchain_msg(&address(v), &msg, proof(v)),
            "accepted {pointer}"
        );
    }
}

/// Proofs are not interchangeable between execution and offchain types, or
/// with EIP-191 `personal_sign` proofs of the same key.
#[test]
fn proofs_are_bound_to_their_domain() {
    let all = vectors();
    let msg = request(all[0]["msg"].clone());
    let auth: OffchainMessage = serde_json::from_value(all[4]["msg"].clone()).unwrap();
    assert!(!WalletEip712::verify_request_msg(
        &address(&all[0]),
        &msg,
        proof(&all[4])
    ));
    assert!(!WalletEip712::verify_offchain_msg(
        &address(&all[4]),
        &auth,
        proof(&all[0])
    ));
    assert!(!WalletEip191::verify_request_msg(
        &address(&all[0]),
        &msg,
        proof(&all[0])
    ));
    assert!(!WalletEip712::verify_request_msg(
        &EthAddress([0; 20]),
        &msg,
        proof(&all[0])
    ));
    assert!(request_signing_message(&address(&all[0]), &msg).is_ok());
}

#[test]
fn malleated_and_noncanonical_proofs_fail() {
    let all = vectors();
    let v = &all[0];
    let msg = request(v["msg"].clone());
    let parsed = Secp256k1RecoverableSignature::from_str(proof(v)).unwrap();
    let (signature, recovery_id) =
        <(k256::ecdsa::Signature, k256::ecdsa::RecoveryId)>::try_from(&parsed).unwrap();
    let high_s = k256::ecdsa::Signature::from_scalars(signature.r(), -signature.s()).unwrap();
    let flipped = k256::ecdsa::RecoveryId::from_byte(recovery_id.to_byte() ^ 1).unwrap();
    let mut variants = vec![
        Secp256k1RecoverableSignature::from((high_s, flipped)).to_string(),
        proof(v).strip_prefix("secp256k1:").unwrap().to_owned(),
        String::new(),
    ];
    for byte in [27, 2, 3] {
        let mut bytes = parsed.0;
        bytes[64] = byte;
        variants.push(Secp256k1RecoverableSignature(bytes).to_string());
    }
    for proof in variants {
        assert!(
            !WalletEip712::verify_request_msg(&address(v), &msg, &proof),
            "accepted {proof}"
        );
    }
}

/// What typed data cannot show safely is rejected rather than signed.
#[test]
fn unsupported_content_is_rejected() {
    let base = request(vectors()[2]["msg"].clone());
    let call = |name: &str, args: &str| {
        let mut msg = base.clone();
        let NearAction::FunctionCall(call) = &mut msg.request.external[0].actions[0] else {
            unreachable!()
        };
        call.function_name = name.to_owned();
        call.args = args.as_bytes().to_vec();
        msg
    };
    for (msg, expected) in [
        (call("ft_transfer", r#"{"memo":"Привет"}"#), "args"),
        (call("ft_transfer", "{\"memo\":\"\\u202e\"}"), "args"),
        (call("ft_transfer", r#"{"a":1,"a":2}"#), "args"),
        (call("ft_transfer", r#"{"a": 1}"#), "args"),
        (call("ft_transfer", ""), "args"),
        (
            call("w_execute_extension", r#"{"request":{}}"#),
            "unsupported",
        ),
        (call("ft_transfer\u{7f}", "{}"), "text"),
        // NEP-141 transfers: only the method's parameters, canonical amount.
        (
            call(
                "ft_transfer",
                r#"{"receiver_id":"a.near","amount_display":"1.5 USDC","amount":"1"}"#,
            ),
            "args",
        ),
        (call("ft_transfer", r#"{"receiver_id":"a.near"}"#), "args"),
        (
            call("ft_transfer", r#"{"receiver_id":"a.near","amount":"01"}"#),
            "args",
        ),
        (
            call("ft_transfer", r#"{"receiver_id":"a.near","amount":1}"#),
            "args",
        ),
        (
            call(
                "ft_transfer",
                r#"{"receiver_id":"a.near","amount":"1","msg":""}"#,
            ),
            "args",
        ),
    ] {
        let error = request_digest(&msg).unwrap_err();
        // What cannot be hashed cannot be authorized.
        let signed = &vectors()[2];
        assert!(!WalletEip712::verify_request_msg(
            &address(signed),
            &msg,
            proof(signed)
        ));
        assert!(
            match expected {
                "args" => matches!(error, Eip712Error::FunctionArgs),
                "unsupported" => matches!(error, Eip712Error::Unsupported),
                _ => matches!(error, Eip712Error::Text),
            },
            "{expected}: {error:?}"
        );
    }
    request_digest(&call(
        "ft_transfer_call",
        r#"{"receiver_id":"a.near","amount":"1","memo":"m","msg":""}"#,
    ))
    .unwrap();
    let mut msg = base.clone();
    msg.chain_id = "main\u{202e}net".to_owned();
    assert!(matches!(request_digest(&msg), Err(Eip712Error::Text)));
    let large = "x".repeat(16 * 1024 + 1);
    assert!(matches!(
        request_digest(&call("submit", &large)),
        Err(Eip712Error::TooLarge)
    ));
    let mut auth: OffchainMessage = serde_json::from_value(vectors()[5]["msg"].clone()).unwrap();
    auth.payload = "caf\u{e9}".to_owned();
    assert!(matches!(offchain_digest(&auth), Err(Eip712Error::Text)));
    auth.payload = large;
    assert!(matches!(offchain_digest(&auth), Err(Eip712Error::TooLarge)));
}

/// Vectors 8 and 9 sit exactly at the text and item limits; one more is rejected.
#[test]
fn text_and_item_budget_is_enforced() {
    let all = vectors();
    let mut msg = request(all[8]["msg"].clone());
    let NearAction::FunctionCall(call) = &mut msg.request.external[0].actions[0] else {
        unreachable!()
    };
    // `{"padding":"a…"}`: one more padding byte.
    call.args.insert(12, b'a');
    assert!(matches!(request_digest(&msg), Err(Eip712Error::TooLarge)));

    let mut msg = request(all[9]["msg"].clone());
    let extra = msg.request.external[0].actions[0].clone();
    msg.request.external[0].actions.push(extra);
    assert!(matches!(request_digest(&msg), Err(Eip712Error::TooLarge)));

    let mut auth: OffchainMessage = serde_json::from_value(all[4]["msg"].clone()).unwrap();
    auth.path = vec!["a.near".parse().unwrap(); 128];
    offchain_digest(&auth).unwrap();
    auth.path.push("a.near".parse().unwrap());
    assert!(matches!(offchain_digest(&auth), Err(Eip712Error::TooLarge)));
    let mut msg = request(all[2]["msg"].clone());
    let WalletOp::RequireFtMetadata { symbol, .. } = &mut msg.request.internal[2] else {
        unreachable!()
    };
    *symbol = "X".repeat(100 * 1024);
    assert!(matches!(request_digest(&msg), Err(Eip712Error::TooLarge)));

    // Each add_extension is an operation and a warning.
    let mut msg = request(all[2]["msg"].clone());
    msg.request.external.clear();
    let extension = "a.near".parse::<defuse_wallet::AccountId>().unwrap();
    msg.request.internal = vec![WalletOp::add_extension(extension); 64];
    request_digest(&msg).unwrap();
    msg.request
        .internal
        .push(WalletOp::set_signature_mode(true));
    assert!(matches!(request_digest(&msg), Err(Eip712Error::TooLarge)));
    msg.request.internal = vec![WalletOp::set_signature_mode(true); 100_000];
    assert!(matches!(request_digest(&msg), Err(Eip712Error::TooLarge)));
}
