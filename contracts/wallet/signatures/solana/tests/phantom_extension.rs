use defuse_wallet::{RequestMessage, SignatureSchema, offchain::OffchainMessage};
use defuse_wallet_solana::{
    WalletPhantom, crypto::ed25519::Ed25519PublicKey, offchain_signing_message,
    request_signing_message,
};
use serde_json::{Value, json};

fn vectors() -> Vec<Value> {
    serde_json::from_str::<Value>(include_str!("fixtures/phantom-extension.json")).unwrap()["vectors"]
        .as_array()
        .unwrap()
        .clone()
}

fn public_key(vector: &Value) -> Ed25519PublicKey {
    format!("ed25519:{}", vector["public_key"].as_str().unwrap())
        .parse()
        .unwrap()
}

#[test]
fn captured_phantom_execution_signature_matches_contract_bytes() {
    let all = vectors();
    let vector = &all[0];
    let key = public_key(vector);
    let proof = vector["proof"].as_str().unwrap();
    let msg: RequestMessage = serde_json::from_value(vector["msg"].clone()).unwrap();

    assert_eq!(
        request_signing_message(&key, &msg).unwrap(),
        vector["message"]
    );
    assert!(WalletPhantom::verify_request_msg(&key, &msg, proof));
    assert!(!WalletPhantom::verify_request_msg(
        &key,
        &msg,
        all[1]["proof"].as_str().unwrap()
    ));
    for (pointer, value) in [
        ("/chain_id", json!("mainnet")),
        ("/request/external/0/receiver_id", json!("other.near")),
        (
            "/request/external/0/actions/0/payload/amount",
            json!("1000000000000000000000001"),
        ),
        (
            "/request/internal/0/payload/account_id",
            json!("other.near"),
        ),
    ] {
        let mut changed = vector["msg"].clone();
        *changed.pointer_mut(pointer).unwrap() = value;
        let changed = serde_json::from_value(changed).unwrap();
        assert!(!WalletPhantom::verify_request_msg(&key, &changed, proof));
    }
}

#[test]
fn captured_phantom_offchain_signature_preserves_exact_payload() {
    let all = vectors();
    let vector = &all[1];
    let key = public_key(vector);
    let proof = vector["proof"].as_str().unwrap();
    let mut msg: OffchainMessage = serde_json::from_value(vector["msg"].clone()).unwrap();

    assert_eq!(
        offchain_signing_message(&key, &msg).unwrap(),
        vector["message"]
    );
    assert!(WalletPhantom::verify_offchain_msg(&key, &msg, proof));
    assert!(!WalletPhantom::verify_offchain_msg(
        &key,
        &msg,
        all[0]["proof"].as_str().unwrap()
    ));
    msg.payload.push(' ');
    assert!(!WalletPhantom::verify_offchain_msg(&key, &msg, proof));
}
