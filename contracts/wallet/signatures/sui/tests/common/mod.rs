// Each test binary uses its own subset of these helpers.
#![allow(dead_code)]

use defuse_wallet::SignatureSchema;
use defuse_wallet_sui::{
    SuiPublicKey, WalletSui,
    crypto::{ed25519::Ed25519, p256::P256, secp256k1::Secp256k1},
    protocol::SuiScheme,
};
use serde_json::Value;

/// A scheme under its name in the fixtures of the official SDK.
pub trait FixtureScheme: SuiScheme {
    const NAME: &'static str;
}

impl FixtureScheme for Ed25519 {
    const NAME: &'static str = "ED25519";
}

impl FixtureScheme for Secp256k1 {
    const NAME: &'static str = "Secp256k1";
}

impl FixtureScheme for P256 {
    const NAME: &'static str = "Secp256r1";
}

/// Run a check that is generic over the scheme once for each of the three
/// schemes: a key belongs to exactly one, so no check can mix them by accident.
#[allow(unused_macros)]
macro_rules! each_scheme {
    ($check:ident) => {{
        $check::<defuse_wallet_sui::crypto::ed25519::Ed25519>();
        $check::<defuse_wallet_sui::crypto::secp256k1::Secp256k1>();
        $check::<defuse_wallet_sui::crypto::p256::P256>();
    }};
}

#[allow(unused_imports)]
pub(crate) use each_scheme;

pub fn fixture() -> Value {
    serde_json::from_str(include_str!("../fixtures/sui.json")).unwrap()
}

/// Every vector of the fixture, of all three schemes.
pub fn all_vectors() -> Vec<Value> {
    fixture()["vectors"].as_array().unwrap().clone()
}

/// The vectors of the scheme `C`, in the order of the fixture.
pub fn vectors<C: FixtureScheme>() -> Vec<Value> {
    all_vectors()
        .into_iter()
        .filter(|v| v["scheme"] == C::NAME)
        .collect()
}

pub fn key<C: SuiScheme>(v: &Value) -> SuiPublicKey<C> {
    v["public_key"].as_str().unwrap().parse().unwrap()
}

/// A key as `StateInit` can store it: any bytes of the right length, bypassing
/// the validation of public-key parsing.
pub fn stored<C: SuiScheme>(raw: &[u8]) -> SuiPublicKey<C> {
    borsh::from_slice(raw).unwrap()
}

/// Verify `proof` over the message of the vector `v`, as the contract variant
/// of the scheme `C` does for the stored `key`.
pub fn verify<C: SuiScheme>(key: &SuiPublicKey<C>, v: &Value, proof: &str) -> bool {
    let msg = v["msg"].clone();

    match v["kind"].as_str().unwrap() {
        "request" => {
            WalletSui::<C>::verify_request_msg(key, &serde_json::from_value(msg).unwrap(), proof)
        }
        "offchain" => {
            WalletSui::<C>::verify_offchain_msg(key, &serde_json::from_value(msg).unwrap(), proof)
        }
        kind => panic!("unexpected fixture kind: {kind}"),
    }
}
