//! Real `MetaMask` `personal_sign` signatures from the display check (see
//! `provenance` in `fixtures/metamask.json`).

use defuse_erc191::Erc191;
use defuse_wallet::{RequestMessage, SignatureSchema, offchain::OffchainMessage};
use defuse_wallet_evm_eip191::{
    EthAddress, EvmProof, WalletEip191, offchain_signing_message, request_signing_message,
};
use serde_json::Value;

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
    assert_eq!(vectors.len(), 5);

    for v in vectors {
        let address: EthAddress = v["address"].as_str().unwrap().parse().unwrap();
        let proof = v["proof"].as_str().unwrap();
        let signed = v["message"].as_str().unwrap();
        assert!(signs(address, signed, proof));

        // The signature covers the final LF.
        assert!(!signs(address, signed.trim_end(), proof));

        // A proof signs only its own message.
        for other in vectors.iter().filter(|other| *other != v) {
            assert!(!signs(address, other["message"].as_str().unwrap(), proof));
        }

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
}
