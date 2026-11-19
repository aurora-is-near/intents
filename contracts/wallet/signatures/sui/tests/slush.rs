//! Real Slush `signPersonalMessage` signatures from the display check (see
//! `provenance` in `fixtures/slush.json`).

use defuse_wallet::{RequestMessage, SignatureSchema, offchain::OffchainMessage};
use defuse_wallet_sui::{
    SuiPublicKey, WalletSui, crypto::ed25519::Ed25519, offchain_signing_message,
    request_signing_message,
};
use serde_json::Value;

#[test]
fn real_slush_signatures_verify() {
    let fixture: Value = serde_json::from_str(include_str!("fixtures/slush.json")).unwrap();
    let vectors = fixture["vectors"].as_array().unwrap();
    assert_eq!(vectors.len(), 5);

    for v in vectors {
        let key: SuiPublicKey = v["public_key"].as_str().unwrap().parse().unwrap();
        assert_eq!(key.flag(), 0);

        // Slush signed exactly the captured bytes as a Sui personal message.
        let proof = v["proof"].as_str().unwrap();
        let signed = v["message"].as_str().unwrap();
        assert!(key.verify_personal_message(signed.as_bytes(), proof));

        // The signature covers the final LF.
        assert!(!key.verify_personal_message(signed.trim_end().as_bytes(), proof));

        // A proof signs only its own message.
        for other in vectors.iter().filter(|other| *other != v) {
            let other = other["message"].as_str().unwrap();
            assert!(!key.verify_personal_message(other.as_bytes(), proof));
        }

        // The contract renders exactly that text and accepts the proof.
        let (rendered, verified) = if v["kind"] == "request" {
            let msg: RequestMessage = serde_json::from_value(v["msg"].clone()).unwrap();
            (
                request_signing_message(&key, &msg).unwrap(),
                WalletSui::<Ed25519>::verify_request_msg(&key, &msg, proof),
            )
        } else {
            let msg: OffchainMessage = serde_json::from_value(v["msg"].clone()).unwrap();
            (
                offchain_signing_message(&key, &msg).unwrap(),
                WalletSui::<Ed25519>::verify_offchain_msg(&key, &msg, proof),
            )
        };

        assert_eq!(rendered, signed);
        assert!(verified);
    }
}
