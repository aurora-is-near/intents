use crate::SuiPublicKey;
use defuse_wallet::{RequestMessage, offchain::OffchainMessage, readable_message};

pub use defuse_wallet::readable_message::{
    MAX_SIGNING_MESSAGE_BYTES, MessageError, OFFCHAIN_PREFIX, REQUEST_PREFIX,
};

/// Reconstruct the full readable Sui execution message from the stored key.
pub fn request_signing_message(
    public_key: &SuiPublicKey,
    msg: &RequestMessage,
) -> Result<String, MessageError> {
    // Sui native base64 (flag plus key) and its directly derived address.
    let (key, address) = (public_key.to_base64(), public_key.address());
    readable_message::request_signing_message(
        &[("sui_public_key", key.as_str()), ("sui_address", &address)],
        msg,
    )
}

/// Reconstruct the full readable Sui NEP-641 authorization message.
pub fn offchain_signing_message(
    public_key: &SuiPublicKey,
    msg: &OffchainMessage,
) -> Result<String, MessageError> {
    let (key, address) = (public_key.to_base64(), public_key.address());
    readable_message::offchain_signing_message(
        &[("sui_public_key", key.as_str()), ("sui_address", &address)],
        msg,
    )
}
