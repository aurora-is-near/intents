use defuse_wallet::{RequestMessage, SignatureSchema, offchain::OffchainMessage};
use defuse_wallet_solana::{
    WalletSolana,
    crypto::{
        Curve,
        ed25519::{Ed25519, Ed25519PublicKey, Ed25519Signature},
    },
    offchain_signing_message, request_signing_message,
};
use serde_json::Value;

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

/// Phantom signed exactly the captured bytes.
fn signs(key: &Ed25519PublicKey, message: &str, proof: &str) -> bool {
    let key = <Ed25519 as Curve>::PublicKey::try_from(key).unwrap();
    let signature: Ed25519Signature = proof.parse().unwrap();
    Ed25519::verify(&key, message.as_bytes(), &signature.into())
}

#[test]
fn captured_phantom_execution_signature_predates_amount_format() {
    let all = vectors();
    let vector = &all[0];
    let key = public_key(vector);
    let proof = vector["proof"].as_str().unwrap();
    let signed = vector["message"].as_str().unwrap();
    let msg: RequestMessage = serde_json::from_value(vector["msg"].clone()).unwrap();

    assert!(signs(&key, signed, proof));
    assert!(!signs(&key, signed, all[1]["proof"].as_str().unwrap()));
    // Captured before amounts were shown with decimals and symbol: the
    // contract now renders a different message and rejects this proof.
    // A new capture is needed for execution display.
    assert!(signed.contains("\"amount_yoctonear\""));
    assert_ne!(request_signing_message(&key, &msg).unwrap(), signed);
    assert!(!WalletSolana::verify_request_msg(&key, &msg, proof));
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
    assert!(WalletSolana::verify_offchain_msg(&key, &msg, proof));
    assert!(!WalletSolana::verify_offchain_msg(
        &key,
        &msg,
        all[0]["proof"].as_str().unwrap()
    ));
    msg.payload.push(' ');
    assert!(!WalletSolana::verify_offchain_msg(&key, &msg, proof));
}
