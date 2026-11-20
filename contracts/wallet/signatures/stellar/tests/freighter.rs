//! Real Freighter `signMessage` signatures from the display check (see
//! `provenance` in `fixtures/freighter.json`).

use base64::{Engine, engine::general_purpose::STANDARD};
use defuse_sep53::Sep53;
use defuse_wallet::{RequestMessage, SignatureSchema, offchain::OffchainMessage};
use defuse_wallet_stellar::{
    WalletStellar,
    crypto::ed25519::{
        Ed25519PublicKey,
        ed25519_dalek::{Signature, Verifier, VerifyingKey},
    },
    offchain_signing_message, request_signing_message, stellar_address,
};
use serde_json::Value;

fn public_key(vector: &Value) -> Ed25519PublicKey {
    let address = vector["address"].as_str().unwrap();

    Ed25519PublicKey(
        stellar_strkey::ed25519::PublicKey::from_string(address)
            .unwrap()
            .0,
    )
}

/// Freighter signed exactly the captured bytes as a SEP-53 message.
fn signs(key: &Ed25519PublicKey, message: &str, proof: &str) -> bool {
    let signature: [u8; 64] = STANDARD.decode(proof).unwrap().try_into().unwrap();

    VerifyingKey::from_bytes(&key.0)
        .unwrap()
        .verify(&Sep53::prehash(message), &Signature::from_bytes(&signature))
        .is_ok()
}

#[test]
fn real_freighter_signatures_verify() {
    let fixture: Value = serde_json::from_str(include_str!("fixtures/freighter.json")).unwrap();
    let vectors = fixture["vectors"].as_array().unwrap();
    assert_eq!(vectors.len(), 5);

    for v in vectors {
        let key = public_key(v);
        assert_eq!(stellar_address(&key), v["address"]);

        let proof = v["proof"].as_str().unwrap();
        let signed = v["message"].as_str().unwrap();
        assert!(signs(&key, signed, proof));

        // The signature covers the final LF.
        assert!(!signs(&key, signed.trim_end(), proof));

        // A proof signs only its own message.
        for other in vectors.iter().filter(|other| *other != v) {
            assert!(!signs(&key, other["message"].as_str().unwrap(), proof));
        }

        // The contract renders exactly that text and accepts the proof.
        let (rendered, verified) = if v["kind"] == "request" {
            let msg: RequestMessage = serde_json::from_value(v["msg"].clone()).unwrap();
            (
                request_signing_message(&key, &msg).unwrap(),
                WalletStellar::verify_request_msg(&key, &msg, proof),
            )
        } else {
            let msg: OffchainMessage = serde_json::from_value(v["msg"].clone()).unwrap();
            (
                offchain_signing_message(&key, &msg).unwrap(),
                WalletStellar::verify_offchain_msg(&key, &msg, proof),
            )
        };

        assert_eq!(rendered, signed);
        assert!(verified);
    }
}
