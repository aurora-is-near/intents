mod common;
use common::TestSui as WalletSui;
use defuse_wallet::{RequestMessage, SignatureSchema, offchain::OffchainMessage};
use defuse_wallet_sui::{SuiPublicKey, sui::personal_message_digest};
use serde_json::Value;

fn fixtures() -> Value {
    serde_json::from_str(include_str!("fixtures/sui.json")).unwrap()
}

#[test]
fn sdk_addresses_hashes_and_native_intent_boundaries() {
    let fixtures = fixtures();
    for v in fixtures["vectors"].as_array().unwrap() {
        let key: SuiPublicKey = v["public_key"].as_str().unwrap().parse().unwrap();
        assert_eq!(key.address(), v["address"]);
        assert_eq!(key.to_string(), v["public_key"]);
        assert_eq!(borsh::to_vec(&key).unwrap(), key.to_sui_bytes());
        assert_eq!(serde_json::to_value(key).unwrap(), v["public_key"]);
        let message = v["message"].as_str().unwrap().as_bytes();
        assert_eq!(
            hex::encode(personal_message_digest(message).unwrap()),
            v["digest_hex"]
        );
        assert!(key.verify_personal_message(message, v["proof"].as_str().unwrap()));
        assert!(!key.verify_personal_message(message, v["transaction_proof"].as_str().unwrap()));
        if let Some(proof) = v["high_s_proof"].as_str() {
            assert!(!key.verify_personal_message(message, proof));
        }
        let mut changed = message.to_vec();
        changed.push(b' ');
        assert!(!key.verify_personal_message(&changed, v["proof"].as_str().unwrap()));
    }
    for v in fixtures["boundaries"].as_array().unwrap() {
        let message = vec![b'a'; usize::try_from(v["length"].as_u64().unwrap()).unwrap()];
        assert_eq!(
            hex::encode(personal_message_digest(&message).unwrap()),
            v["digest_hex"]
        );
    }
}

#[test]
fn malformed_native_envelopes_and_cross_purpose_proofs_fail() {
    use base64::{Engine, engine::general_purpose::STANDARD};
    let fixtures = fixtures();
    for v in fixtures["vectors"].as_array().unwrap() {
        let key: SuiPublicKey = v["public_key"].as_str().unwrap().parse().unwrap();
        let proof = v["proof"].as_str().unwrap();
        let original = STANDARD.decode(proof).unwrap();
        let message = v["message"].as_str().unwrap().as_bytes();
        let mut bad = vec![Vec::new(), original[..original.len() - 1].to_vec()];
        let mut longer = original.clone();
        longer.push(0);
        bad.push(longer);
        for flag in 0..=6 {
            if flag != key.flag() {
                let mut bytes = original.clone();
                bytes[0] = flag;
                bad.push(bytes);
            }
        }
        for index in [1, 32, 64, 65, original.len() - 1] {
            let mut bytes = original.clone();
            bytes[index] ^= 1;
            bad.push(bytes);
        }
        for bytes in bad {
            assert!(!key.verify_personal_message(message, &STANDARD.encode(bytes)));
        }
        assert!(!key.verify_personal_message(message, proof.trim_end_matches('=')));
        assert!(!key.verify_personal_message(message, &format!("{proof}\n")));
        for flag in [3, 4, 5, 6, 255] {
            let mut bytes = key.to_sui_bytes();
            bytes[0] = flag;
            assert!(SuiPublicKey::from_sui_bytes(&bytes).is_err());
        }
        if v["kind"] == "request" {
            let msg: RequestMessage = serde_json::from_value(v["msg"].clone()).unwrap();
            assert!(!WalletSui::verify_request_msg(
                &key,
                &msg,
                v["transaction_proof"].as_str().unwrap()
            ));
        } else {
            let msg: OffchainMessage = serde_json::from_value(v["msg"].clone()).unwrap();
            assert!(!WalletSui::verify_offchain_msg(
                &key,
                &msg,
                v["transaction_proof"].as_str().unwrap()
            ));
        }
    }
    assert!(SuiPublicKey::from_sui_bytes(&[0; 33]).is_err());
    for flag in [1, 2] {
        let mut bytes = vec![0; 34];
        bytes[0] = flag;
        assert!(SuiPublicKey::from_sui_bytes(&bytes).is_err());
    }
}
