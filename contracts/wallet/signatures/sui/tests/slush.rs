//! Real Slush `signPersonalMessage` signatures from the display check and the
//! text copied from each prompt (see the provenance fields of
//! `fixtures/slush.json`).

use defuse_wallet::{RequestMessage, SignatureSchema, offchain::OffchainMessage};
use defuse_wallet_sui::{
    SuiPublicKey, WalletSui, crypto::ed25519::Ed25519, offchain_signing_message,
    request_signing_message,
};
use serde_json::Value;

/// Non-empty lines without indentation.
fn lines(text: &str) -> Vec<&str> {
    text.lines()
        .map(str::trim)
        .filter(|line| !line.is_empty())
        .collect()
}

#[test]
fn real_slush_personal_message_signatures_verify() {
    let fixture: Value = serde_json::from_str(include_str!("fixtures/slush.json")).unwrap();
    let captures = fixture["captures"].as_array().unwrap();

    assert_eq!(captures.len(), 1);

    for capture in captures {
        assert_eq!(capture["msg"]["chain_id"], "sui-display-check-only");

        let key: SuiPublicKey = capture["publicKey"].as_str().unwrap().parse().unwrap();
        assert_eq!(key.flag(), 0);

        let proof = capture["proof"].as_str().unwrap();
        let signed = capture["signingMessage"].as_str().unwrap();

        // Slush signed exactly the captured bytes as a Sui personal message
        // and showed them between the prompt's `Message` heading and buttons.
        assert!(key.verify_personal_message(signed.as_bytes(), proof));

        // The signature covers the final LF.
        assert!(!key.verify_personal_message(signed.trim_end().as_bytes(), proof));

        // A proof signs only its own message.
        for other in captures.iter().filter(|other| *other != capture) {
            let other = other["signingMessage"].as_str().unwrap();
            assert!(!key.verify_personal_message(other.as_bytes(), proof));
        }

        let prompt = lines(capture["prompt"].as_str().unwrap());
        let start = prompt.iter().position(|line| *line == "Message").unwrap() + 1;
        let end = prompt.iter().rposition(|line| *line == "Reject").unwrap();

        assert_eq!(prompt[start..end], lines(signed));

        // The contract renders exactly that text and accepts the proof.
        let (rendered, verified) = match capture["kind"].as_str().unwrap() {
            "execution" => {
                let msg: RequestMessage = serde_json::from_value(capture["msg"].clone()).unwrap();
                (
                    request_signing_message(&key, &msg).unwrap(),
                    WalletSui::<Ed25519>::verify_request_msg(&key, &msg, proof),
                )
            }
            "offchain" => {
                let msg: OffchainMessage = serde_json::from_value(capture["msg"].clone()).unwrap();
                // Exercise rejection even when there is only one capture. Payload bytes are opaque.
                let mut changed = msg.clone();
                changed.payload.push(' ');
                let changed_text = offchain_signing_message(&key, &changed).unwrap();
                assert_ne!(changed_text, signed);
                assert!(!WalletSui::<Ed25519>::verify_offchain_msg(
                    &key, &changed, proof
                ));
                (
                    offchain_signing_message(&key, &msg).unwrap(),
                    WalletSui::<Ed25519>::verify_offchain_msg(&key, &msg, proof),
                )
            }
            kind => panic!("unknown capture kind: {kind}"),
        };

        assert_eq!(rendered, signed);
        assert!(verified);
    }
}
