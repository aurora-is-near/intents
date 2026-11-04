#![doc = include_str!("../README.md")]

#[cfg(feature = "contract")]
mod contract;
mod message;
#[cfg(feature = "signer")]
mod signer;

pub use self::message::*;
#[cfg(feature = "signer")]
pub use self::signer::*;
pub use defuse_crypto as crypto;

use core::str::FromStr;

use defuse_crypto::{
    Curve,
    ed25519::{Ed25519, Ed25519PublicKey, Ed25519Signature},
};
use defuse_wallet::{RequestMessage, SignatureSchema, offchain::OffchainMessage};

/// Phantom Solana `signMessage(bytes, "utf8")` over the full readable message.
///
/// This is deliberately incompatible with the digest-signing Ed25519 variant.
pub struct WalletPhantom;

impl WalletPhantom {
    fn verify(
        public_key: &Ed25519PublicKey,
        message: impl FnOnce() -> Result<String, MessageError>,
        proof: &str,
    ) -> bool {
        let (Ok(key), Ok(signature)) = (
            <Ed25519 as Curve>::PublicKey::try_from(public_key),
            Ed25519Signature::from_str(proof),
        ) else {
            return false;
        };
        let Ok(message) = message() else {
            return false;
        };
        Ed25519::verify(&key, message.as_bytes(), &signature.into())
    }
}

impl SignatureSchema for WalletPhantom {
    type PublicKey = Ed25519PublicKey;

    fn verify_request_msg(public_key: &Self::PublicKey, msg: &RequestMessage, proof: &str) -> bool {
        // Reject oversized or non-Ed25519 proofs before rendering the message.
        if proof.len() > 100 || !proof.starts_with("ed25519:") {
            return false;
        }
        Self::verify(
            public_key,
            || request_signing_message(public_key, msg),
            proof,
        )
    }

    fn verify_offchain_msg(
        public_key: &Self::PublicKey,
        msg: &OffchainMessage,
        proof: &str,
    ) -> bool {
        if proof.len() > 100 || !proof.starts_with("ed25519:") {
            return false;
        }
        Self::verify(
            public_key,
            || offchain_signing_message(public_key, msg),
            proof,
        )
    }
}
