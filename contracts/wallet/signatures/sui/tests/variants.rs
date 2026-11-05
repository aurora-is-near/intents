use defuse_wallet::{
    RequestMessage, SignatureSchema, State, StateInit, StateInitV1, offchain::OffchainMessage,
};
use defuse_wallet_sui::{
    SuiPublicKey, WalletSui,
    crypto::{
        ed25519::{Ed25519, Ed25519PublicKey},
        p256::{P256, P256CompressedPublicKey},
        secp256k1::{Secp256k1, Secp256k1CompressedPublicKey},
    },
};
use near_sdk as _;
use serde_json::Value;

#[test]
fn each_schema_rejects_valid_proofs_and_keys_from_other_sui_schemes() {
    let fixture: Value = serde_json::from_str(include_str!("fixtures/sui.json")).unwrap();
    for v in fixture["vectors"].as_array().unwrap() {
        let key: SuiPublicKey = v["public_key"].as_str().unwrap().parse().unwrap();
        let proof = v["proof"].as_str().unwrap();
        let accepted = if v["kind"] == "request" {
            let msg: RequestMessage = serde_json::from_value(v["msg"].clone()).unwrap();
            [
                WalletSui::<Ed25519>::verify_request_msg(&key, &msg, proof),
                WalletSui::<Secp256k1>::verify_request_msg(&key, &msg, proof),
                WalletSui::<P256>::verify_request_msg(&key, &msg, proof),
            ]
        } else {
            let msg: OffchainMessage = serde_json::from_value(v["msg"].clone()).unwrap();
            [
                WalletSui::<Ed25519>::verify_offchain_msg(&key, &msg, proof),
                WalletSui::<Secp256k1>::verify_offchain_msg(&key, &msg, proof),
                WalletSui::<P256>::verify_offchain_msg(&key, &msg, proof),
            ]
        };
        for (flag, valid) in accepted.into_iter().enumerate() {
            assert_eq!(valid, usize::from(key.flag()) == flag);
        }
    }
}

// Frozen pre-refactor state-key representation, retained only as a compatibility oracle.
#[derive(borsh::BorshSerialize)]
#[borsh(use_discriminant = true)]
#[repr(u8)]
enum LegacyKey {
    Ed25519(Ed25519PublicKey) = 0,
    Secp256k1(Secp256k1CompressedPublicKey) = 1,
    Secp256r1(P256CompressedPublicKey) = 2,
}

#[test]
fn tagged_state_and_addresses_match_the_pre_refactor_layout_for_fixed_global_id() {
    let fixture: Value = serde_json::from_str(include_str!("fixtures/sui.json")).unwrap();
    for v in fixture["vectors"].as_array().unwrap() {
        let key: SuiPublicKey = v["public_key"].as_str().unwrap().parse().unwrap();
        let legacy = match key {
            SuiPublicKey::Ed25519(bytes) => LegacyKey::Ed25519(Ed25519PublicKey(bytes)),
            SuiPublicKey::Secp256k1(bytes) => {
                LegacyKey::Secp256k1(Secp256k1CompressedPublicKey(bytes))
            }
            SuiPublicKey::Secp256r1(bytes) => LegacyKey::Secp256r1(P256CompressedPublicKey(bytes)),
        };
        let old = State::new(legacy).subwallet_id(7);
        let new = State::new(key).subwallet_id(7);
        assert_eq!(borsh::to_vec(&old).unwrap(), borsh::to_vec(&new).unwrap());
        let state_init = |data| {
            StateInit::V1(StateInitV1 {
                code: [42; 32].into(),
                data,
            })
        };
        assert_eq!(
            state_init(old.as_storage()).derive_account_id(),
            state_init(new.as_storage()).derive_account_id()
        );
    }
}
