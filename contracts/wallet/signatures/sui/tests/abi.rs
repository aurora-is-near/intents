#![cfg(feature = "abi")]

use defuse_wallet_sui::{
    SuiPublicKey,
    crypto::{ed25519::Ed25519, p256::P256, secp256k1::Secp256k1},
    protocol::SuiScheme,
};

fn check<C: SuiScheme>() {
    let schema = schemars::schema_for!(SuiPublicKey<C>);
    let value = serde_json::to_value(schema).unwrap();

    assert_eq!(value["type"], "string");
    assert!(value.get("oneOf").is_none());
}

#[test]
fn public_key_json_schema_describes_the_serialized_string() {
    check::<Ed25519>();
    check::<Secp256k1>();
    check::<P256>();
}
