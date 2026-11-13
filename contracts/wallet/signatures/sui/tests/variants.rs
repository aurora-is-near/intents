use defuse_wallet::{RequestMessage, SignatureSchema, offchain::OffchainMessage};
use defuse_wallet_sui::{
    SuiPublicKey, WalletSui,
    crypto::{ed25519::Ed25519, p256::P256, secp256k1::Secp256k1},
};
use near_sdk as _;
use serde_json::Value;

#[test]
fn each_schema_rejects_valid_proofs_and_keys_from_other_sui_schemes() {
    let fixture: Value = serde_json::from_str(include_str!("fixtures/sui.json")).unwrap();
    for v in fixture["vectors"].as_array().unwrap() {
        let key: SuiPublicKey = v["public_key"].as_str().unwrap().parse().unwrap();
        let proof = v["proof"].as_str().unwrap();
        let accepted = if v["kind"] == "request" {
            let msg: RequestMessage = serde_json::from_value(v["msg"].clone()).unwrap();
            [
                WalletSui::<Ed25519>::verify_request_msg(&key, &msg, proof),
                WalletSui::<Secp256k1>::verify_request_msg(&key, &msg, proof),
                WalletSui::<P256>::verify_request_msg(&key, &msg, proof),
            ]
        } else {
            let msg: OffchainMessage = serde_json::from_value(v["msg"].clone()).unwrap();
            [
                WalletSui::<Ed25519>::verify_offchain_msg(&key, &msg, proof),
                WalletSui::<Secp256k1>::verify_offchain_msg(&key, &msg, proof),
                WalletSui::<P256>::verify_offchain_msg(&key, &msg, proof),
            ]
        };
        for (flag, valid) in accepted.into_iter().enumerate() {
            assert_eq!(valid, usize::from(key.flag()) == flag);
        }
    }
}
