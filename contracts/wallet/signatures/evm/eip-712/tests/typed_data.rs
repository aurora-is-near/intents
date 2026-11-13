//! Probe: an independent, generic EIP-712 (v4) encoder written from the
//! specification, applied to the `typed_data` stored in the fixtures, compared
//! with the fixture digests and with the digests the contract derives from the
//! execution message alone.

use std::{collections::BTreeSet, fmt::Write as _};

use defuse_digest::{Digest, sha3::Keccak256};
use defuse_wallet::{RequestMessage, offchain::OffchainMessage};
use defuse_wallet_evm_eip712::{offchain_digest, request_digest};
use serde_json::Value;

fn keccak(data: &[u8]) -> [u8; 32] {
    Keccak256::digest(data).into()
}

fn deps(types: &Value, ty: &str, out: &mut BTreeSet<String>) {
    let base = ty.trim_end_matches("[]");
    if out.contains(base) || types.get(base).is_none() {
        return;
    }
    out.insert(base.to_owned());
    for field in types[base].as_array().unwrap() {
        deps(types, field["type"].as_str().unwrap(), out);
    }
}

fn encode_type(types: &Value, primary: &str) -> String {
    let mut all = BTreeSet::new();
    deps(types, primary, &mut all);
    all.remove(primary);
    let mut order = vec![primary.to_owned()];
    order.extend(all); // BTreeSet iterates sorted by name
    let mut encoded = String::new();
    for name in order {
        let fields: Vec<String> = types[&name]
            .as_array()
            .unwrap()
            .iter()
            .map(|f| {
                format!(
                    "{} {}",
                    f["type"].as_str().unwrap(),
                    f["name"].as_str().unwrap()
                )
            })
            .collect();
        write!(encoded, "{name}({})", fields.join(",")).unwrap();
    }
    encoded
}

fn encode_value(types: &Value, ty: &str, value: &Value) -> [u8; 32] {
    if let Some(item) = ty.strip_suffix("[]") {
        let mut buf = Vec::new();
        for v in value.as_array().expect("array") {
            buf.extend_from_slice(&encode_value(types, item, v));
        }
        return keccak(&buf);
    }
    if types.get(ty).is_some() {
        return hash_struct(types, ty, value);
    }
    match ty {
        "string" => keccak(value.as_str().expect("string").as_bytes()),
        "bytes" => {
            let s = value.as_str().expect("bytes hex");
            keccak(&hex::decode(s.strip_prefix("0x").expect("0x")).unwrap())
        }
        "bool" => {
            let mut w = [0u8; 32];
            w[31] = u8::from(value.as_bool().expect("bool"));
            w
        }
        t if t.starts_with("uint") => {
            let bits: u32 = t[4..].parse().unwrap();
            let n: u128 = match value {
                Value::Number(n) => u128::from(n.as_u64().expect("u64 number")),
                Value::String(s) => s.parse().expect("decimal string"),
                other => panic!("uint value {other}"),
            };
            if bits < 128 {
                assert!(n < (1u128 << bits), "{n} does not fit {t}");
            }
            let mut w = [0u8; 32];
            w[16..].copy_from_slice(&n.to_be_bytes());
            w
        }
        other => panic!("unsupported type {other}"),
    }
}

fn hash_struct(types: &Value, ty: &str, value: &Value) -> [u8; 32] {
    let mut buf = keccak(encode_type(types, ty).as_bytes()).to_vec();
    let object = value.as_object().expect("struct object");
    let fields = types[ty].as_array().unwrap();
    // every message member must be a declared field and vice versa
    assert_eq!(
        object.len(),
        fields.len(),
        "extra or missing members in {ty}"
    );
    for field in fields {
        let name = field["name"].as_str().unwrap();
        let v = object
            .get(name)
            .unwrap_or_else(|| panic!("missing {ty}.{name}"));
        buf.extend_from_slice(&encode_value(types, field["type"].as_str().unwrap(), v));
    }
    keccak(&buf)
}

fn digest(typed: &Value) -> [u8; 32] {
    let types = &typed["types"];
    let domain = hash_struct(types, "EIP712Domain", &typed["domain"]);
    let message = hash_struct(
        types,
        typed["primaryType"].as_str().unwrap(),
        &typed["message"],
    );
    let mut buf = vec![0x19, 0x01];
    buf.extend_from_slice(&domain);
    buf.extend_from_slice(&message);
    keccak(&buf)
}

fn check(file: &str) {
    let fixture: Value = serde_json::from_str(match file {
        "eip712.json" => include_str!("fixtures/eip712.json"),
        "metamask.json" => include_str!("fixtures/metamask.json"),
        _ => unreachable!(),
    })
    .unwrap();
    let vectors = fixture["vectors"].as_array().unwrap();
    for (i, v) in vectors.iter().enumerate() {
        let typed = &v["typed_data"];
        let independent = digest(typed);
        assert_eq!(
            hex::encode(independent),
            v["digest"].as_str().unwrap(),
            "{file} vector {i}: generic EIP-712 digest of typed_data != fixture digest"
        );
        let derived = if v["kind"] == "request" {
            let msg: RequestMessage = serde_json::from_value(v["msg"].clone()).unwrap();
            request_digest(&msg).unwrap()
        } else {
            let msg: OffchainMessage = serde_json::from_value(v["msg"].clone()).unwrap();
            offchain_digest(&msg).unwrap()
        };
        assert_eq!(derived, independent, "{file} vector {i}: contract digest");
        // encodeType computed from `types` equals the contract's constants.
        let primary = typed["primaryType"].as_str().unwrap();
        let et = encode_type(&typed["types"], primary);
        let expected = if primary == "ExecuteRequest" {
            defuse_wallet_evm_eip712::REQUEST_TYPE
        } else {
            defuse_wallet_evm_eip712::OFFCHAIN_TYPE
        };
        assert_eq!(et, expected, "{file} vector {i}: encodeType");
        assert_eq!(
            encode_type(&typed["types"], "EIP712Domain"),
            defuse_wallet_evm_eip712::DOMAIN_TYPE
        );
        assert_eq!(
            typed["domain"]["name"],
            defuse_wallet_evm_eip712::DOMAIN_NAME
        );
        assert_eq!(
            typed["domain"]["version"],
            defuse_wallet_evm_eip712::DOMAIN_VERSION
        );
        assert_eq!(typed["domain"].as_object().unwrap().len(), 2);
        println!(
            "{file} vector {i} ({primary}): ok {}",
            hex::encode(independent)
        );
    }
}

#[test]
fn fixture_typed_data_hashes_to_fixture_and_contract_digest() {
    check("eip712.json");
    check("metamask.json");
}
