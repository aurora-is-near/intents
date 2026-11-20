//! Real `MetaMask` `eth_signTypedData_v4` signatures from the display check
//! (see `provenance` in `fixtures/metamask.json`).

use defuse_wallet::{RequestMessage, SignatureSchema, offchain::OffchainMessage};
use defuse_wallet_evm_eip191::WalletEip191;
use defuse_wallet_evm_eip712::{
    EthAddress, EvmProof, WalletEip712, offchain_digest, request_digest,
};
use serde_json::Value;

fn digest(vector: &Value) -> [u8; 32] {
    hex::decode(vector["digest"].as_str().unwrap())
        .unwrap()
        .try_into()
        .unwrap()
}

#[test]
fn real_metamask_signatures_verify() {
    let fixture: Value = serde_json::from_str(include_str!("fixtures/metamask.json")).unwrap();
    let vectors = fixture["vectors"].as_array().unwrap();
    assert_eq!(vectors.len(), 4);

    for v in vectors {
        let address: EthAddress = v["address"].as_str().unwrap().parse().unwrap();
        let proof = v["proof"].as_str().unwrap();
        let signer = |digest: &[u8; 32]| EvmProof::parse(proof).unwrap().signer(digest);

        // MetaMask signed the digest of the typed data it was given
        // (`typed_data.rs` hashes that typed data independently).
        let signed = digest(v);
        assert_eq!(signer(&signed), Some(address));

        // A proof signs only its own typed data.
        for other in vectors.iter().filter(|other| *other != v) {
            assert_ne!(signer(&digest(other)), Some(address));
        }

        // The contract derives that digest from the message alone and accepts
        // the proof; the EIP-191 variant rejects the same proof.
        let (derived, verified) = if v["kind"] == "request" {
            let msg: RequestMessage = serde_json::from_value(v["msg"].clone()).unwrap();
            assert!(!WalletEip191::verify_request_msg(&address, &msg, proof));

            (
                request_digest(&msg).unwrap(),
                WalletEip712::verify_request_msg(&address, &msg, proof),
            )
        } else {
            let msg: OffchainMessage = serde_json::from_value(v["msg"].clone()).unwrap();
            assert!(!WalletEip191::verify_offchain_msg(&address, &msg, proof));

            (
                offchain_digest(&msg).unwrap(),
                WalletEip712::verify_offchain_msg(&address, &msg, proof),
            )
        };

        assert_eq!(derived, signed);
        assert!(verified);
    }
}
