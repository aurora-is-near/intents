//! Real `MetaMask` `eth_signTypedData_v4` signatures from the display check
//! and the text copied from each prompt (see `provenance` in
//! `fixtures/metamask.json`).

use defuse_wallet::{RequestMessage, SignatureSchema, offchain::OffchainMessage};
use defuse_wallet_evm_eip191::WalletEip191;
use defuse_wallet_evm_eip712::{
    EthAddress, EvmProof, WalletEip712, offchain_digest, request_digest,
};
use serde_json::Value;

/// Non-empty lines without indentation.
fn lines(text: &str) -> Vec<&str> {
    text.lines()
        .map(str::trim)
        .filter(|line| !line.is_empty())
        .collect()
}

/// How `MetaMask` lists typed data: each field as `Name:` and its value, each
/// array item as `i:`; empty values show nothing.
fn listed(types: &Value, ty: &str, value: &Value, out: &mut Vec<String>) {
    if let Some(item) = ty.strip_suffix("[]") {
        for (i, value) in value.as_array().unwrap().iter().enumerate() {
            out.push(format!("{i}:"));
            listed(types, item, value, out);
        }
    } else if let Some(fields) = types[ty].as_array() {
        for field in fields {
            let name = field["name"].as_str().unwrap();
            out.push(format!("{}{}:", name[..1].to_uppercase(), &name[1..]));
            listed(types, field["type"].as_str().unwrap(), &value[name], out);
        }
    } else {
        let text = value
            .as_str()
            .map_or_else(|| value.to_string(), str::to_owned);
        if !text.is_empty() {
            out.push(text);
        }
    }
}

#[test]
fn real_metamask_signatures_verify() {
    let fixture: Value = serde_json::from_str(include_str!("fixtures/metamask.json")).unwrap();
    let vectors = fixture["vectors"].as_array().unwrap();
    assert_eq!(vectors.len(), 1);
    for v in vectors {
        let address: EthAddress = v["address"].as_str().unwrap().parse().unwrap();
        let proof = v["proof"].as_str().unwrap();
        // The prompt listed every field of the typed data after its `Message`
        // heading, and MetaMask signed the digest that `eth-sig-util`
        // computed for that typed data.
        let typed = &v["typed_data"];
        let primary = typed["primaryType"].as_str().unwrap();
        let mut expected = vec!["Primary type:".to_owned(), primary.to_owned()];
        listed(&typed["types"], primary, &typed["message"], &mut expected);
        let prompt = lines(v["prompt"].as_str().unwrap());
        let shown = prompt.iter().position(|line| *line == "Message").unwrap() + 1;
        assert_eq!(prompt[shown..], expected);
        let signed: [u8; 32] = hex::decode(v["digest"].as_str().unwrap())
            .unwrap()
            .try_into()
            .unwrap();
        let signer = |digest: &[u8; 32]| EvmProof::parse(proof).unwrap().signer(digest);
        assert_eq!(signer(&signed), Some(address));
        // The contract derives that digest from the message alone and accepts
        // the proof; the EIP-191 variant rejects the same proof.
        let (digest, verified) = if v["kind"] == "request" {
            let msg: RequestMessage = serde_json::from_value(v["msg"].clone()).unwrap();
            assert!(!WalletEip191::verify_request_msg(&address, &msg, proof));
            (
                request_digest(&msg).unwrap(),
                WalletEip712::verify_request_msg(&address, &msg, proof),
            )
        } else {
            let msg: OffchainMessage = serde_json::from_value(v["msg"].clone()).unwrap();
            // Exercise rejection even when there is only one capture. Payload bytes are opaque.
            let mut changed = msg.clone();
            changed.payload.push(' ');
            let changed_digest = offchain_digest(&changed).unwrap();
            assert_ne!(changed_digest, signed);
            assert!(!WalletEip712::verify_offchain_msg(
                &address, &changed, proof
            ));
            assert!(!WalletEip191::verify_offchain_msg(&address, &msg, proof));
            (
                offchain_digest(&msg).unwrap(),
                WalletEip712::verify_offchain_msg(&address, &msg, proof),
            )
        };
        assert_eq!(digest, signed);
        assert!(verified);
    }
}
