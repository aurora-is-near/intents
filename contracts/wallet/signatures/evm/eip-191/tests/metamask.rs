//! Real `MetaMask` `personal_sign` signatures from the display check and the
//! text copied from each prompt (see `provenance` in `fixtures/metamask.json`).

use defuse_erc191::Erc191;
use defuse_wallet::{RequestMessage, SignatureSchema, offchain::OffchainMessage};
use defuse_wallet_evm_eip191::{
    EthAddress, EvmProof, MAX_SIGNING_MESSAGE_BYTES, WalletEip191, offchain_signing_message,
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

fn message<'a>(vectors: &'a [Value], profile: &str) -> &'a str {
    vectors.iter().find(|v| v["profile"] == profile).unwrap()["message"]
        .as_str()
        .unwrap()
}

#[test]
fn real_metamask_signatures_verify() {
    let fixture: Value = serde_json::from_str(include_str!("fixtures/metamask.json")).unwrap();
    let vectors = fixture["vectors"].as_array().unwrap();
    assert_eq!(vectors.len(), 5);
    for v in vectors {
        let address: EthAddress = v["address"].as_str().unwrap().parse().unwrap();
        let proof = v["proof"].as_str().unwrap();
        let signed = v["message"].as_str().unwrap();
        // MetaMask signed exactly the captured text, and the prompt showed it
        // after its `Message` heading.
        let signer = EvmProof::parse(proof)
            .unwrap()
            .signer(&Erc191::prehash(signed));
        assert_eq!(signer, Some(address));
        let prompt = lines(v["prompt"].as_str().unwrap());
        let shown = prompt.iter().position(|line| *line == "Message").unwrap() + 1;
        assert_eq!(prompt[shown..], lines(signed));
        // The contract renders exactly that text and accepts the proof.
        let (rendered, verified) = if v["kind"] == "request" {
            let msg: RequestMessage = serde_json::from_value(v["msg"].clone()).unwrap();
            (
                request_signing_message(&address, &msg).unwrap(),
                WalletEip191::verify_request_msg(&address, &msg, proof),
            )
        } else {
            let msg: OffchainMessage = serde_json::from_value(v["msg"].clone()).unwrap();
            (
                offchain_signing_message(&address, &msg).unwrap(),
                WalletEip191::verify_offchain_msg(&address, &msg, proof),
            )
        };
        assert_eq!(rendered, signed);
        assert!(verified);
    }
    // MetaMask showed the warnings before the JSON, NEAR and token amounts
    // with decimals and symbol, the nested request decoded, and the largest
    // accepted message in full.
    let effects = message(vectors, "execution-effects");
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
    let deployment = message(vectors, "execution-deployment");
    assert!(deployment.contains(
        "WARNING: up to 0.375 NEAR sent to 0s762910a479b0c04f9725b03cd7931dc5064ab0ab can be refunded to refund.deploy.display-check.near, not to this wallet.\n"
    ));
    assert!(deployment.contains("\"deposit\": \"0.25 NEAR\""));
    assert!(deployment.contains("\"amount\": \"0.125 NEAR\""));
    let extension = message(vectors, "execution-extension");
    assert!(extension.contains(
        "WARNING: add_extension gives helper.display-check.near full control of wallet vault.display-check.near.\n"
    ));
    assert!(extension.contains("\"function_name\": \"w_execute_extension\""));
    assert!(extension.contains("\"amount\": \"2.5 USDC\""));
    let limit = message(vectors, "execution-limit");
    assert_eq!(limit.len(), MAX_SIGNING_MESSAGE_BYTES);
    assert!(limit.contains("|END\""));
}
