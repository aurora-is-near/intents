#![doc = include_str!("../README.md")]

mod message;
pub mod protocol;
#[cfg(feature = "signer")]
mod signer;

pub use message::*;
pub use protocol as sui;
pub use protocol::{SuiPublicKey, crypto};
#[cfg(feature = "signer")]
pub use signer::*;

use core::marker::PhantomData;
use protocol::SuiScheme;

use defuse_wallet::{RequestMessage, SignatureSchema, offchain::OffchainMessage};

/// Sui native personal-message signatures over the full readable NEAR message.
pub struct WalletSui<C: SuiScheme>(PhantomData<C>);

impl<C: SuiScheme> SignatureSchema for WalletSui<C> {
    type PublicKey = SuiPublicKey;

    fn verify_request_msg(public_key: &Self::PublicKey, msg: &RequestMessage, proof: &str) -> bool {
        public_key.flag() == C::FLAG
            && proof.len() == 132
            && request_signing_message(public_key, msg)
                .is_ok_and(|message| public_key.verify_personal_message(message.as_bytes(), proof))
    }

    fn verify_offchain_msg(
        public_key: &Self::PublicKey,
        msg: &OffchainMessage,
        proof: &str,
    ) -> bool {
        public_key.flag() == C::FLAG
            && proof.len() == 132
            && offchain_signing_message(public_key, msg)
                .is_ok_and(|message| public_key.verify_personal_message(message.as_bytes(), proof))
    }
}
