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
#[cfg(any(feature = "p256", feature = "secp256k1"))]
use defuse_digest::{Digest, sha2::Sha256};
use impl_tools::autoimpl;

#[cfg(near)]
use near_sdk::env;

use crate::MessageError;

pub use defuse_crypto as crypto;

/// A direct Sui signing key of the scheme `C`.
///
/// The native scheme flag is [`SuiScheme::FLAG`]: it is part of the type, so
/// the key of one scheme cannot be used with another. Only the raw key is
/// stored, so Borsh is exactly the key bytes.
#[derive(
    BorshSerialize, BorshDeserialize, serde_with::SerializeDisplay, serde_with::DeserializeFromStr,
)]
#[cfg_attr(feature = "abi", derive(borsh::BorshSchema))]
#[autoimpl(Debug, Clone, Copy, PartialEq, Eq where C::Key: trait)]
#[repr(transparent)]
pub struct SuiPublicKey<C: SuiScheme>(
    /// Raw 32-byte Ed25519 or compressed 33-byte ECDSA public key.
    #[cfg_attr(feature = "abi", borsh(schema(params = "C => C::Key")))]
    pub C::Key,
);

#[cfg(feature = "abi")]
impl<C: SuiScheme> schemars::JsonSchema for SuiPublicKey<C> {
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

impl<C: SuiScheme> SuiPublicKey<C> {
    /// Store the key of a signer of this scheme.
    pub fn from_public_key(key: C::PublicKey) -> Self {
        Self(C::public_key_bytes(key))
    }

    /// Raw 32-byte Ed25519 or compressed 33-byte ECDSA public key.
    pub fn raw_bytes(&self) -> &[u8] {
        self.0.as_ref()
    }

    /// Native Sui `flag || public_key` bytes.
    pub fn to_sui_bytes(&self) -> Vec<u8> {
        [&[C::FLAG], self.raw_bytes()].concat()
    }

    /// Canonical base64 of native Sui public-key bytes, without the `sui:` tag.
    pub fn to_base64(&self) -> String {
        STANDARD.encode(self.to_sui_bytes())
    }

    /// Direct key-derived Sui address. Does not resolve Sui address aliases.
    pub fn address(&self) -> String {
        format!("0x{}", hex::encode(blake2b256(self.to_sui_bytes())))
    }

    /// Parse native Sui public-key bytes of this scheme, validating points and
    /// weak keys. The key of another scheme is rejected by its flag.
    pub fn from_sui_bytes(bytes: &[u8]) -> Result<Self, PublicKeyError> {
        let [flag, key @ ..] = bytes else {
            return Err(PublicKeyError);
        };

        if *flag != C::FLAG || C::parse_public_key(key).is_none() {
            return Err(PublicKeyError);
        }

        key.try_into().map(Self).map_err(|_| PublicKeyError)
    }

    /// Verify a native personal-message proof against this exact stored key.
    ///
    /// Only canonical padded base64 with the exact scheme-dependent length is
    /// accepted. ECDSA low-S checks and weak-key rejection use shared crypto.
    pub fn verify_personal_message(&self, message: &[u8], proof: &str) -> bool {
        self.verify_personal_message_with(|| Ok(message), proof)
    }

    // Decode and bind the proof once, before paying to render or hash a message.
    pub(crate) fn verify_personal_message_with<M: AsRef<[u8]>>(
        &self,
        message: impl FnOnce() -> Result<M, MessageError>,
        proof: &str,
    ) -> bool {
        const SIGNATURE_LEN: usize = 64;
        const PUBLIC_KEY_OFFSET: usize = 1 + SIGNATURE_LEN;

        let key = self.raw_bytes();
        let expected_len = PUBLIC_KEY_OFFSET + key.len();

        if Some(proof.len()) != base64::encoded_len(expected_len, true) {
            return false;
        }

        let Ok(bytes) = STANDARD.decode(proof) else {
            return false;
        };

        // The proof of another scheme is rejected here by its flag.
        if bytes.len() != expected_len || bytes[0] != C::FLAG || &bytes[PUBLIC_KEY_OFFSET..] != key
        {
            return false;
        }

        // Report rendering failures on-chain without embedding Rust source locations.
        #[cfg(near)]
        let message = message().unwrap_or_else(|error| env::panic_str(&error.to_string()));

        // Native verification remains a predicate, including for unreadable messages.
        #[cfg(not(near))]
        let Ok(message) = message() else {
            return false;
        };

        let Some(digest) = personal_message_digest(message.as_ref()) else {
            return false;
        };

        let signature = &bytes[1..PUBLIC_KEY_OFFSET];

        verify::<C>(key, digest, signature)
    }

    /// Serialize a 64-byte signature in the native Sui proof format.
    pub fn encode_signature(&self, signature: &[u8; 64]) -> String {
        let bytes = [&[C::FLAG], signature.as_ref(), self.raw_bytes()].concat();

        STANDARD.encode(bytes)
    }
}

fn verify<C: SuiScheme>(key: &[u8], digest: [u8; 32], signature: &[u8]) -> bool {
    let (Some(key), Ok(signature)) = (C::parse_public_key(key), C::Signature::try_from(signature))
    else {
        return false;
    };

    C::verify(&key, &C::signing_digest(digest), &signature)
}

impl<C: SuiScheme> fmt::Display for SuiPublicKey<C> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "sui:{}", self.to_base64())
    }
}

impl<C: SuiScheme> FromStr for SuiPublicKey<C> {
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
    use ::blake2::{Blake2b, Digest, digest::consts::U32};

    let mut length = u32::try_from(message.len()).ok()?;

    // Hash the parts in place: the message is not copied.
    let mut hasher = Blake2b::<U32>::new();

    hasher.update([3, 0, 0]);

    loop {
        let mut byte = u8::try_from(length & 0x7f).expect("seven bits");
        length >>= 7;

        if length != 0 {
            byte |= 0x80;
        }

        hasher.update([byte]);

        if length == 0 {
            break;
        }
    }

    hasher.update(message);

    Some(hasher.finalize().into())
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
pub trait SuiScheme:
    sealed::Sealed + Curve<Signature: for<'a> TryFrom<&'a [u8]>> + Send + Sync + 'static
{
    /// Native signature-scheme flag.
    const FLAG: u8;

    /// Raw public key, as stored in the wallet state.
    type Key: Copy
        + Eq
        + fmt::Debug
        + AsRef<[u8]>
        + for<'a> TryFrom<&'a [u8]>
        + BorshSerialize
        + BorshDeserialize
        + Send
        + Sync
        + 'static;

    fn parse_public_key(bytes: &[u8]) -> Option<Self::PublicKey>;
    fn public_key_bytes(key: Self::PublicKey) -> Self::Key;
    fn signature_bytes(signature: Self::Signature) -> [u8; 64];
    fn signing_digest(personal_message_digest: [u8; 32]) -> [u8; 32];
}

#[cfg(feature = "ed25519")]
impl SuiScheme for Ed25519 {
    const FLAG: u8 = 0;

    type Key = [u8; 32];

    fn parse_public_key(bytes: &[u8]) -> Option<Self::PublicKey> {
        let key: Self::PublicKey = (&Ed25519PublicKey(bytes.try_into().ok()?))
            .try_into()
            .ok()?;

        (!key.is_weak()).then_some(key)
    }

    fn public_key_bytes(key: Self::PublicKey) -> Self::Key {
        key.to_bytes()
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
    ($curve:ty, $stored:ident, $flag:literal) => {
        impl SuiScheme for $curve {
            const FLAG: u8 = $flag;

            type Key = [u8; 33];

            fn parse_public_key(bytes: &[u8]) -> Option<Self::PublicKey> {
                if !matches!(bytes.first(), Some(0x02 | 0x03)) {
                    return None;
                }

                (&$stored(bytes.try_into().ok()?)).try_into().ok()
            }

            fn public_key_bytes(key: Self::PublicKey) -> Self::Key {
                $stored::from(key).0
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
ecdsa_scheme!(Secp256k1, Secp256k1CompressedPublicKey, 1);
#[cfg(feature = "p256")]
ecdsa_scheme!(P256, P256CompressedPublicKey, 2);

/// BLAKE2b-256 with its native 32-byte output parameter (not truncated BLAKE2b-512).
/// Uses the vetted `RustCrypto` backend on both NEAR/WASM and native targets.
fn blake2b256(data: impl AsRef<[u8]>) -> [u8; 32] {
    use ::blake2::{Blake2b, Digest, digest::consts::U32};

    Blake2b::<U32>::digest(data).into()
}
