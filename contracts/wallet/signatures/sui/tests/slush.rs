use defuse_wallet::{RequestMessage, SignatureSchema, offchain::OffchainMessage};
use defuse_wallet_sui::{
    SuiPublicKey, WalletSui, crypto::ed25519::Ed25519, offchain_signing_message,
    request_signing_message,
};
use serde_json::Value;

#[test]
fn real_slush_personal_message_signatures_match_the_rust_schema() {
    let fixture: Value = serde_json::from_str(include_str!("fixtures/slush.json")).unwrap();
    let captures = fixture["captures"].as_array().unwrap();
    assert!(!captures.is_empty());
    for capture in captures {
        assert_eq!(capture["msg"]["chain_id"], "sui-display-check-only");
        let key: SuiPublicKey = capture["publicKey"].as_str().unwrap().parse().unwrap();
        assert_eq!(key.flag(), 0);
        let proof = capture["proof"].as_str().unwrap();
        let (rendered, valid) = match capture["kind"].as_str().unwrap() {
            "execution" => {
                let msg: RequestMessage = serde_json::from_value(capture["msg"].clone()).unwrap();
                (
                    request_signing_message(&key, &msg).unwrap(),
                    WalletSui::<Ed25519>::verify_request_msg(&key, &msg, proof),
                )
            }
            "offchain" => {
                let msg: OffchainMessage = serde_json::from_value(capture["msg"].clone()).unwrap();
                (
                    offchain_signing_message(&key, &msg).unwrap(),
                    WalletSui::<Ed25519>::verify_offchain_msg(&key, &msg, proof),
                )
            }
            kind => panic!("unknown capture kind: {kind}"),
        };
        assert_eq!(rendered, capture["signingMessage"].as_str().unwrap());
        assert!(valid);
    }
}
