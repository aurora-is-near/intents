#![doc = include_str!("../README.md")]

mod message;
pub mod protocol;
#[cfg(feature = "signer")]
mod signer;

pub use message::*;
pub use protocol::{SuiPublicKey, crypto};
#[cfg(feature = "signer")]
pub use signer::*;

#[cfg(test)]
mod tests;

use core::marker::PhantomData;
use protocol::SuiScheme;

use defuse_wallet::{RequestMessage, SignatureSchema, offchain::OffchainMessage};

/// Sui native personal-message signatures over the full readable NEAR message.
pub struct WalletSui<C: SuiScheme>(PhantomData<C>);

impl<C: SuiScheme> WalletSui<C> {
    fn verify(
        public_key: &SuiPublicKey<C>,
        message: impl FnOnce() -> Result<String, MessageError>,
        proof: &str,
    ) -> bool {
        // The proof is bound to the key and its scheme `C` before any message work.
        public_key.verify_personal_message_with(message, proof)
    }
}

impl<C: SuiScheme> SignatureSchema for WalletSui<C> {
    type PublicKey = SuiPublicKey<C>;

    fn verify_request_msg(public_key: &Self::PublicKey, msg: &RequestMessage, proof: &str) -> bool {
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
        Self::verify(
            public_key,
            || offchain_signing_message(public_key, msg),
            proof,
        )
    }
}
