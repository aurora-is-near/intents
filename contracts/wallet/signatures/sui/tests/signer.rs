#![cfg(feature = "signer")]

use defuse_wallet::{RequestMessage, offchain::OffchainMessage};
use defuse_wallet_sdk::WalletSigner;
use defuse_wallet_sui::{
    WalletSuiSigner,
    crypto::{
        Signer,
        ed25519::{Ed25519, ed25519_dalek},
        p256::{P256, p256},
        secp256k1::{Secp256k1, k256},
    },
    sui::SuiScheme,
};
use serde_json::Value;

async fn check<C: SuiScheme, S: Signer<C>>(signer: S, scheme: &str) {
    let signer = WalletSuiSigner::<C, _>::new(signer);
    let fixture: Value = serde_json::from_str(include_str!("fixtures/sui.json")).unwrap();
    for v in fixture["vectors"]
        .as_array()
        .unwrap()
        .iter()
        .filter(|v| v["scheme"] == scheme)
    {
        assert_eq!(signer.public_key().to_string(), v["public_key"]);
        let proof = if v["kind"] == "request" {
            let msg: RequestMessage = serde_json::from_value(v["msg"].clone()).unwrap();
            signer.sign_request_msg(&msg).await.unwrap()
        } else {
            let msg: OffchainMessage = serde_json::from_value(v["msg"].clone()).unwrap();
            signer.sign_offchain_msg(&msg).await.unwrap()
        };
        // Both implementations use deterministic signing; compare the entire
        // native proof, not just acceptance by our own verifier.
        assert_eq!(proof, v["proof"]);
    }
}

#[tokio::test]
async fn rust_signers_match_official_sdk_proofs_for_both_paths() {
    // Deliberately public deterministic test secret, also in the fixture metadata.
    let seed = core::array::from_fn(|i| u8::try_from(i + 1).unwrap());
    check::<Ed25519, _>(ed25519_dalek::SigningKey::from_bytes(&seed), "ED25519").await;
    check::<Secp256k1, _>(
        k256::ecdsa::SigningKey::from_bytes((&seed).into()).unwrap(),
        "Secp256k1",
    )
    .await;
    check::<P256, _>(
        p256::ecdsa::SigningKey::from_bytes((&seed).into()).unwrap(),
        "Secp256r1",
    )
    .await;
}
