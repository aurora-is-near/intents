#![doc = include_str!("../README.md")]

#[cfg(feature = "contract")]
mod contract;
mod eip712;
mod message;
#[cfg(feature = "signer")]
mod signer;

pub use defuse_wallet_evm_eip191::{EthAddress, EvmProof, crypto};

#[cfg(feature = "signer")]
pub use self::signer::*;
pub use self::{eip712::Hash, message::*};

use defuse_wallet::{RequestMessage, SignatureSchema, offchain::OffchainMessage};

/// `eth_signTypedData_v4` (EIP-712) over typed data derived from the message.
pub struct WalletEip712;

impl WalletEip712 {
    fn verify(
        address: &EthAddress,
        digest: impl FnOnce() -> Result<Hash, Eip712Error>,
        proof: &str,
    ) -> bool {
        // The proof is parsed before the typed data is encoded.
        EvmProof::parse(proof).is_some_and(|proof| {
            digest().is_ok_and(|digest| proof.signer(&digest) == Some(*address))
        })
    }
}

impl SignatureSchema for WalletEip712 {
    type PublicKey = EthAddress;

    fn verify_request_msg(address: &Self::PublicKey, msg: &RequestMessage, proof: &str) -> bool {
        Self::verify(address, || request_digest(msg), proof)
    }

    fn verify_offchain_msg(address: &Self::PublicKey, msg: &OffchainMessage, proof: &str) -> bool {
        Self::verify(address, || offchain_digest(msg), proof)
    }
}
