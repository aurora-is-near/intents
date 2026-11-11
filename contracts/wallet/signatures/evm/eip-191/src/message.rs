use defuse_wallet::{RequestMessage, offchain::OffchainMessage, readable_message};

pub use defuse_wallet::readable_message::{
    MAX_SIGNING_MESSAGE_BYTES, MessageError, OFFCHAIN_PREFIX, REQUEST_PREFIX,
};

use crate::EthAddress;

/// Reconstruct the readable v1 execution message for this Ethereum address.
pub fn request_signing_message(
    address: &EthAddress,
    msg: &RequestMessage,
) -> Result<String, MessageError> {
    readable_message::request_signing_message(&[("evm_address", &address.to_string())], msg)
}

/// Reconstruct all five NEP-641 fields, preserving the exact payload string.
pub fn offchain_signing_message(
    address: &EthAddress,
    msg: &OffchainMessage,
) -> Result<String, MessageError> {
    readable_message::offchain_signing_message(&[("evm_address", &address.to_string())], msg)
}
