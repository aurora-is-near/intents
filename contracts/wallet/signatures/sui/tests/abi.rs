#![cfg(feature = "abi")]

#[test]
fn public_key_json_schema_describes_the_serialized_string() {
    let schema = schemars::schema_for!(defuse_wallet_sui::SuiPublicKey);
    let value = serde_json::to_value(schema).unwrap();
    assert_eq!(value["type"], "string");
    assert!(value.get("oneOf").is_none());
}
