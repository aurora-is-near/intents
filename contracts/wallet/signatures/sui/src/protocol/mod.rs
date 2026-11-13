//! Sui single-key personal-message encoding and verification.
//!
//! Supports native flags 0, 1 and 2, not multisig, zkLogin, passkey or address
//! aliases. No Sui RPC or account-authority resolution is performed.

use std::{fmt, str::FromStr};

use base64::{Engine, engine::general_purpose::STANDARD};
use borsh::{BorshDeserialize, BorshSerialize};
use defuse_crypto::Curve;
#[cfg(feature = "ed25519")]
use defuse_crypto::ed25519::{Ed25519, Ed25519PublicKey};
#[cfg(feature = "p256")]
use defuse_crypto::p256::{P256, P256CompressedPublicKey};
#[cfg(feature = "secp256k1")]
use defuse_crypto::secp256k1::{Secp256k1, Secp256k1CompressedPublicKey};
mod hash;
#[cfg(any(feature = "p256", feature = "secp256k1"))]
use defuse_digest::{Digest, sha2::Sha256};
use hash::blake2b256;

pub use defuse_crypto as crypto;

/// A direct Sui signing key. Borsh discriminants match the native scheme flags.
#[derive(
    Debug,
    Clone,
    Copy,
    PartialEq,
    Eq,
    BorshSerialize,
    BorshDeserialize,
    serde_with::SerializeDisplay,
    serde_with::DeserializeFromStr,
)]
#[cfg_attr(feature = "abi", derive(borsh::BorshSchema))]
#[borsh(use_discriminant = true)]
#[repr(u8)]
pub enum SuiPublicKey {
    Ed25519([u8; 32]) = 0,
    Secp256k1([u8; 33]) = 1,
    Secp256r1([u8; 33]) = 2,
}

#[cfg(feature = "abi")]
impl schemars::JsonSchema for SuiPublicKey {
    fn schema_name() -> String {
        "SuiPublicKey".to_owned()
    }
    fn json_schema(generator: &mut schemars::r#gen::SchemaGenerator) -> schemars::schema::Schema {
        <String as schemars::JsonSchema>::json_schema(generator)
    }
}

/// Malformed, unsupported or invalid Sui public key.
#[derive(Debug, thiserror::Error)]
#[error("invalid Sui single-key identity")]
pub struct PublicKeyError;

impl SuiPublicKey {
    /// Native signature-scheme flag.
    pub const fn flag(&self) -> u8 {
        match self {
            Self::Ed25519(_) => 0,
            Self::Secp256k1(_) => 1,
            Self::Secp256r1(_) => 2,
        }
    }

    /// Raw 32-byte Ed25519 or compressed 33-byte ECDSA public key.
    pub const fn raw_bytes(&self) -> &[u8] {
        match self {
            Self::Ed25519(key) => key,
            Self::Secp256k1(key) | Self::Secp256r1(key) => key,
        }
    }

    /// Native Sui `flag || public_key` bytes.
    pub fn to_sui_bytes(&self) -> Vec<u8> {
        let mut bytes = vec![self.flag()];
        bytes.extend_from_slice(self.raw_bytes());
        bytes
    }

    /// Canonical base64 of native Sui public-key bytes, without the `sui:` tag.
    pub fn to_base64(&self) -> String {
        STANDARD.encode(self.to_sui_bytes())
    }

    /// Direct key-derived Sui address. Does not resolve Sui address aliases.
    pub fn address(&self) -> String {
        format!("0x{}", hex::encode(blake2b256(self.to_sui_bytes())))
    }

    /// Parse native Sui public-key bytes, validating points and weak keys.
    #[cfg(any(feature = "ed25519", feature = "secp256k1", feature = "p256"))]
    pub fn from_sui_bytes(bytes: &[u8]) -> Result<Self, PublicKeyError> {
        let key = match bytes {
            [0, rest @ ..] => Self::Ed25519(rest.try_into().map_err(|_| PublicKeyError)?),
            [1, rest @ ..] => Self::Secp256k1(rest.try_into().map_err(|_| PublicKeyError)?),
            [2, rest @ ..] => Self::Secp256r1(rest.try_into().map_err(|_| PublicKeyError)?),
            _ => return Err(PublicKeyError),
        };
        let valid = match key.flag() {
            #[cfg(feature = "ed25519")]
            0 => Ed25519::parse_public_key(key.raw_bytes()).is_some(),
            #[cfg(feature = "secp256k1")]
            1 => Secp256k1::parse_public_key(key.raw_bytes()).is_some(),
            #[cfg(feature = "p256")]
            2 => P256::parse_public_key(key.raw_bytes()).is_some(),
            _ => false,
        };
        valid.then_some(key).ok_or(PublicKeyError)
    }

    /// Verify a native personal-message proof against this exact stored key.
    ///
    /// Only canonical padded base64 with the exact scheme-dependent length is
    /// accepted. ECDSA low-S checks and weak-key rejection use shared crypto.
    #[cfg(any(feature = "ed25519", feature = "secp256k1", feature = "p256"))]
    pub fn verify_personal_message(&self, message: &[u8], proof: &str) -> bool {
        if proof.len() != 132 {
            return false;
        }
        let Ok(bytes) = STANDARD.decode(proof) else {
            return false;
        };
        if bytes.len() != 65 + self.raw_bytes().len()
            || bytes[0] != self.flag()
            || &bytes[65..] != self.raw_bytes()
            || STANDARD.encode(&bytes) != proof
        {
            return false;
        }
        let Some(digest) = personal_message_digest(message) else {
            return false;
        };
        match self.flag() {
            #[cfg(feature = "ed25519")]
            0 => verify::<Ed25519>(self.raw_bytes(), &digest, &bytes[1..65]),
            #[cfg(feature = "secp256k1")]
            1 => verify::<Secp256k1>(self.raw_bytes(), &Sha256::digest(digest), &bytes[1..65]),
            #[cfg(feature = "p256")]
            2 => verify::<P256>(self.raw_bytes(), &Sha256::digest(digest), &bytes[1..65]),
            _ => false,
        }
    }

    /// No algorithm is enabled: public-key parsing must deny authorization.
    #[cfg(not(any(feature = "ed25519", feature = "secp256k1", feature = "p256")))]
    pub fn from_sui_bytes(_bytes: &[u8]) -> Result<Self, PublicKeyError> {
        Err(PublicKeyError)
    }

    /// No algorithm is enabled: proofs are never accepted.
    #[cfg(not(any(feature = "ed25519", feature = "secp256k1", feature = "p256")))]
    pub const fn verify_personal_message(&self, _message: &[u8], _proof: &str) -> bool {
        false
    }

    /// Serialize a 64-byte signature in the native Sui proof format.
    pub fn encode_signature(&self, signature: &[u8; 64]) -> String {
        let mut bytes = vec![self.flag()];
        bytes.extend_from_slice(signature);
        bytes.extend_from_slice(self.raw_bytes());
        STANDARD.encode(bytes)
    }
}

#[cfg(any(feature = "ed25519", feature = "secp256k1", feature = "p256"))]
fn verify<'a, C: SuiScheme>(key: &[u8], digest: &[u8], signature: &'a [u8]) -> bool
where
    C::Signature: TryFrom<&'a [u8]>,
{
    let (Some(key), Ok(signature)) = (C::parse_public_key(key), C::Signature::try_from(signature))
    else {
        return false;
    };
    C::verify(&key, digest, &signature)
}

impl fmt::Display for SuiPublicKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "sui:{}", self.to_base64())
    }
}

impl FromStr for SuiPublicKey {
    type Err = PublicKeyError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let encoded = s.strip_prefix("sui:").ok_or(PublicKeyError)?;
        if encoded.len() > 48 {
            return Err(PublicKeyError);
        }
        let bytes = STANDARD.decode(encoded).map_err(|_| PublicKeyError)?;
        if STANDARD.encode(&bytes) != encoded {
            return Err(PublicKeyError);
        }
        Self::from_sui_bytes(&bytes)
    }
}

/// BLAKE2b-256 of `[3,0,0] || BCS(vector<u8>(message))`.
///
/// The BCS vector length is a canonical ULEB128 u32. Returns `None` for larger
/// messages. This is the native protocol hash, not a wallet display format.
pub fn personal_message_digest(message: &[u8]) -> Option<[u8; 32]> {
    let mut length = u32::try_from(message.len()).ok()?;
    let mut bytes = Vec::with_capacity(message.len().checked_add(8)?);
    bytes.extend_from_slice(&[3, 0, 0]);
    loop {
        let mut byte = u8::try_from(length & 0x7f).expect("seven bits");
        length >>= 7;
        if length != 0 {
            byte |= 0x80;
        }
        bytes.push(byte);
        if length == 0 {
            break;
        }
    }
    bytes.extend_from_slice(message);
    Some(blake2b256(bytes))
}

mod sealed {
    pub trait Sealed {}
    #[cfg(feature = "ed25519")]
    impl Sealed for super::Ed25519 {}
    #[cfg(feature = "secp256k1")]
    impl Sealed for super::Secp256k1 {}
    #[cfg(feature = "p256")]
    impl Sealed for super::P256 {}
}

/// Native single-key scheme glue for SDK signers using the shared crypto traits.
/// Only the three explicitly supported Sui algorithms implement this trait.
pub trait SuiScheme: sealed::Sealed + Curve + Send + Sync + 'static {
    const FLAG: u8;
    fn parse_public_key(bytes: &[u8]) -> Option<Self::PublicKey>;
    fn sui_public_key(key: Self::PublicKey) -> SuiPublicKey;
    fn signature_bytes(signature: Self::Signature) -> [u8; 64];
    fn signing_digest(personal_message_digest: [u8; 32]) -> [u8; 32];
}

#[cfg(feature = "ed25519")]
impl SuiScheme for Ed25519 {
    const FLAG: u8 = 0;
    fn parse_public_key(bytes: &[u8]) -> Option<Self::PublicKey> {
        let key: Self::PublicKey = (&Ed25519PublicKey(bytes.try_into().ok()?))
            .try_into()
            .ok()?;
        (!key.is_weak()).then_some(key)
    }
    fn sui_public_key(key: Self::PublicKey) -> SuiPublicKey {
        SuiPublicKey::Ed25519(key.to_bytes())
    }
    fn signature_bytes(signature: Self::Signature) -> [u8; 64] {
        signature.to_bytes()
    }
    fn signing_digest(digest: [u8; 32]) -> [u8; 32] {
        digest
    }
}

#[cfg(any(feature = "secp256k1", feature = "p256"))]
macro_rules! ecdsa_scheme {
    ($curve:ty, $stored:ident, $variant:ident, $flag:literal) => {
        impl SuiScheme for $curve {
            const FLAG: u8 = $flag;
            fn parse_public_key(bytes: &[u8]) -> Option<Self::PublicKey> {
                if !matches!(bytes.first(), Some(0x02 | 0x03)) {
                    return None;
                }
                (&$stored(bytes.try_into().ok()?)).try_into().ok()
            }
            fn sui_public_key(key: Self::PublicKey) -> SuiPublicKey {
                SuiPublicKey::$variant($stored::from(key).0)
            }
            fn signature_bytes(signature: Self::Signature) -> [u8; 64] {
                signature.to_bytes().into()
            }
            fn signing_digest(digest: [u8; 32]) -> [u8; 32] {
                Sha256::digest(digest).into()
            }
        }
    };
}
#[cfg(feature = "secp256k1")]
ecdsa_scheme!(Secp256k1, Secp256k1CompressedPublicKey, Secp256k1, 1);
#[cfg(feature = "p256")]
ecdsa_scheme!(P256, P256CompressedPublicKey, Secp256r1, 2);
