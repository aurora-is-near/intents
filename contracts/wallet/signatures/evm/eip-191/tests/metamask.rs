//! Real `MetaMask` `personal_sign` signatures from the display check and the
//! text copied from each prompt (see `provenance` in `fixtures/metamask.json`).

use defuse_erc191::Erc191;
use defuse_wallet::{RequestMessage, SignatureSchema, offchain::OffchainMessage};
use defuse_wallet_evm_eip191::{
    EthAddress, EvmProof, WalletEip191, offchain_signing_message, request_signing_message,
};
use serde_json::Value;

/// Non-empty lines without indentation.
fn lines(text: &str) -> Vec<&str> {
    text.lines()
        .map(str::trim)
        .filter(|line| !line.is_empty())
        .collect()
}

/// `MetaMask` signed exactly the captured bytes.
fn signs(address: EthAddress, message: &str, proof: &str) -> bool {
    EvmProof::parse(proof)
        .unwrap()
        .signer(&Erc191::prehash(message))
        == Some(address)
}

#[test]
fn real_metamask_signatures_verify() {
    let fixture: Value = serde_json::from_str(include_str!("fixtures/metamask.json")).unwrap();
    let vectors = fixture["vectors"].as_array().unwrap();
    assert_eq!(vectors.len(), 1);
    for v in vectors {
        let address: EthAddress = v["address"].as_str().unwrap().parse().unwrap();
        let proof = v["proof"].as_str().unwrap();
        let signed = v["message"].as_str().unwrap();
        assert!(signs(address, signed, proof));
        // The signature covers the final LF.
        assert!(!signs(address, signed.trim_end(), proof));
        // The prompt showed the signed text after its `Message` heading.
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
            // Exercise rejection even when there is only one capture. Payload bytes are opaque.
            let mut changed = msg.clone();
            changed.payload.push(' ');
            let changed_text = offchain_signing_message(&address, &changed).unwrap();
            assert_ne!(changed_text, signed);
            assert!(!WalletEip191::verify_offchain_msg(
                &address, &changed, proof
            ));
            (
                offchain_signing_message(&address, &msg).unwrap(),
                WalletEip191::verify_offchain_msg(&address, &msg, proof),
            )
        };
        assert_eq!(rendered, signed);
        assert!(verified);
    }
}
