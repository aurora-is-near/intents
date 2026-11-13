//! EIP-712 `hashStruct` and `encodeData` for the member types used here.

use defuse_digest::{Digest, sha3::Keccak256};

/// `keccak256` output.
pub type Hash = [u8; 32];

/// `hashStruct(s) = keccak256(typeHash ‖ encodeData(s))`, where
/// `typeHash = keccak256(encodeType)` and `members` are encoded 32-byte words.
pub fn hash_struct(encode_type: &str, members: impl IntoIterator<Item = Hash>) -> Hash {
    members
        .into_iter()
        .fold(
            Keccak256::new_with_prefix(Keccak256::digest(encode_type)),
            Digest::chain_update,
        )
        .finalize()
        .into()
}

/// `string` (UTF-8) and `bytes`: `keccak256` of the contents.
pub fn dynamic(value: impl AsRef<[u8]>) -> Hash {
    Keccak256::digest(value).into()
}

/// `uint8` to `uint128`: big-endian, left-padded to 32 bytes.
pub fn uint(value: impl Into<u128>) -> Hash {
    let mut word = [0; 32];
    word[16..].copy_from_slice(&value.into().to_be_bytes());
    word
}

/// `bool`: `uint256` `0` or `1`.
pub fn boolean(value: bool) -> Hash {
    uint(u8::from(value))
}

/// Arrays: `keccak256` of the concatenated encoded items.
pub fn array(items: impl IntoIterator<Item = Hash>) -> Hash {
    items
        .into_iter()
        .fold(Keccak256::new(), Digest::chain_update)
        .finalize()
        .into()
}

/// The signed digest: `keccak256(0x19 ‖ 0x01 ‖ domainSeparator ‖ hashStruct(message))`.
pub fn digest(domain_separator: &Hash, struct_hash: &Hash) -> Hash {
    Keccak256::new_with_prefix(b"\x19\x01")
        .chain_update(domain_separator)
        .chain_update(struct_hash)
        .finalize()
        .into()
}

#[cfg(test)]
mod tests {
    use hex_literal::hex;

    use super::*;

    /// `address` and `uint256` words for the EIP-712 example.
    fn word(bytes: &[u8]) -> Hash {
        let mut word = [0; 32];
        word[32 - bytes.len()..].copy_from_slice(bytes);
        word
    }

    /// The `Mail` example of the EIP-712 specification.
    #[test]
    fn specification_example() {
        const PERSON: &str = "Person(string name,address wallet)";
        let person =
            |name: &str, wallet: [u8; 20]| hash_struct(PERSON, [dynamic(name), word(&wallet)]);
        let domain = hash_struct(
            "EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)",
            [
                dynamic("Ether Mail"),
                dynamic("1"),
                uint(1u8),
                word(&hex!("CcCCccccCCCCcCCCCCCcCcCccCcCCCcCcccccccC")),
            ],
        );
        let mail = hash_struct(
            "Mail(Person from,Person to,string contents)Person(string name,address wallet)",
            [
                person("Cow", hex!("CD2a3d9F938E13CD947Ec05AbC7FE734Df8DD826")),
                person("Bob", hex!("bBbBBBBbbBBBbbbBbbBbbbbBBbBbbbbBbBbbBBbB")),
                dynamic("Hello, Bob!"),
            ],
        );
        assert_eq!(
            domain,
            hex!("f2cee375fa42b42143804025fc449deafd50cc031ca257e0b194a650a912090f")
        );
        assert_eq!(
            mail,
            hex!("c52c0ee5d84264471806290a3f2c4cecfc5490626bf912d01f240d7a274b371e")
        );
        assert_eq!(
            digest(&domain, &mail),
            hex!("be609aee343fb3c4b28e1df9e632fca64fcfaede20f02e86244efddf30957bd2")
        );
    }

    #[test]
    fn atomic_and_array_encodings() {
        assert_eq!(uint(u128::MAX)[..16], [0; 16]);
        assert_eq!(boolean(true), uint(1u8));
        assert_eq!(array([]), dynamic([]));
        assert_eq!(
            array([uint(1u8), uint(2u8)]),
            dynamic([uint(1u8), uint(2u8)].concat())
        );
    }
}
