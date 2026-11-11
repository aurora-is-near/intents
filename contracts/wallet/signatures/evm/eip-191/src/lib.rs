#![doc = include_str!("../README.md")]

mod address;
#[cfg(feature = "contract")]
mod contract;
mod message;
mod proof;
#[cfg(feature = "signer")]
mod signer;

pub use defuse_crypto as crypto;

#[cfg(feature = "signer")]
pub use self::signer::*;
pub use self::{address::*, message::*, proof::*};

use defuse_erc191::Erc191;
use defuse_wallet::{RequestMessage, SignatureSchema, offchain::OffchainMessage};

/// `personal_sign` (ERC-191 version `0x45`) over the readable v1 message.
pub struct WalletEip191;

impl WalletEip191 {
    fn verify(
        address: &EthAddress,
        message: impl FnOnce() -> Result<String, MessageError>,
        proof: &str,
    ) -> bool {
        // The proof is parsed before the message is rendered.
        EvmProof::parse(proof).is_some_and(|proof| {
            message().is_ok_and(|message| proof.signer(&Erc191::prehash(message)) == Some(*address))
        })
    }
}

impl SignatureSchema for WalletEip191 {
    type PublicKey = EthAddress;

    fn verify_request_msg(address: &Self::PublicKey, msg: &RequestMessage, proof: &str) -> bool {
        Self::verify(address, || request_signing_message(address, msg), proof)
    }

    fn verify_offchain_msg(address: &Self::PublicKey, msg: &OffchainMessage, proof: &str) -> bool {
        Self::verify(address, || offchain_signing_message(address, msg), proof)
    }
}
