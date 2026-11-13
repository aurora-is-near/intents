//! Real Slush `signPersonalMessage` signatures from the display check and the
//! text copied from each prompt (see the provenance fields of
//! `fixtures/slush.json`).

use defuse_wallet::{RequestMessage, SignatureSchema, offchain::OffchainMessage};
use defuse_wallet_sui::{
    MAX_SIGNING_MESSAGE_BYTES, SuiPublicKey, WalletSui, crypto::ed25519::Ed25519,
    offchain_signing_message, request_signing_message,
};
use serde_json::Value;

/// Non-empty lines without indentation.
fn lines(text: &str) -> Vec<&str> {
    text.lines()
        .map(str::trim)
        .filter(|line| !line.is_empty())
        .collect()
}

fn message<'a>(captures: &'a [Value], profile: &str) -> &'a str {
    captures
        .iter()
        .find(|capture| capture["profile"] == profile)
        .unwrap()["signingMessage"]
        .as_str()
        .unwrap()
}

#[test]
fn real_slush_personal_message_signatures_verify() {
    let fixture: Value = serde_json::from_str(include_str!("fixtures/slush.json")).unwrap();
    let captures = fixture["captures"].as_array().unwrap();
    assert_eq!(captures.len(), 5);
    for capture in captures {
        assert_eq!(capture["msg"]["chain_id"], "sui-display-check-only");
        let key: SuiPublicKey = capture["publicKey"].as_str().unwrap().parse().unwrap();
        assert_eq!(key.flag(), 0);
        let proof = capture["proof"].as_str().unwrap();
        let signed = capture["signingMessage"].as_str().unwrap();
        // Slush signed exactly the captured bytes as a Sui personal message
        // and showed them between the prompt's `Message` heading and buttons.
        assert!(key.verify_personal_message(signed.as_bytes(), proof));
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
    // Slush showed the warnings before the JSON, NEAR and token amounts with
    // decimals and symbol, the nested request decoded, and the largest
    // accepted message in full.
    let effects = message(captures, "execution-effects");
    for warning in [
        "WARNING: add_extension gives temporary.display-check.near full control of this wallet.\n",
        "WARNING: add_extension gives recovery.display-check.near full control of this wallet.\n",
        "WARNING: up to 1.5 NEAR sent to recipient.display-check.near can be refunded to refund.native.display-check.near, not to this wallet.\n",
        "WARNING: up to 0.000000000000000000000002 NEAR sent to usdc.display-check.near can be refunded to refund.token.display-check.near, not to this wallet.\n",
    ] {
        assert!(effects.find(warning).unwrap() < effects.find('{').unwrap());
    }
    assert!(effects.contains("\"amount\": \"1.5 USDC\""));
    assert!(effects.contains("\"amount\": \"1.5 NEAR\""));
    let deployment = message(captures, "execution-deployment");
    assert!(deployment.contains(
        "WARNING: up to 0.375 NEAR sent to 0s762910a479b0c04f9725b03cd7931dc5064ab0ab can be refunded to refund.deploy.display-check.near, not to this wallet.\n"
    ));
    assert!(deployment.contains("\"deposit\": \"0.25 NEAR\""));
    let extension = message(captures, "execution-extension");
    assert!(extension.contains(
        "WARNING: add_extension gives helper.display-check.near full control of wallet vault.display-check.near.\n"
    ));
    assert!(extension.contains("\"function_name\": \"w_execute_extension\""));
    assert!(extension.contains("\"amount\": \"2.5 USDC\""));
    let limit = message(captures, "execution-limit");
    assert_eq!(limit.len(), MAX_SIGNING_MESSAGE_BYTES);
    assert!(limit.contains("|END\""));
}
