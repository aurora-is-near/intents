use crate::SuiPublicKey;
use defuse_wallet::readable_message::SigningIdentity;
use defuse_wallet::{RequestMessage, offchain::OffchainMessage};

pub use defuse_wallet::readable_message::{
    MAX_SIGNING_MESSAGE_BYTES, MessageError, OFFCHAIN_PREFIX, REQUEST_PREFIX,
};

/// Reconstruct the full readable Sui execution message from the stored key.
pub fn request_signing_message(
    public_key: &SuiPublicKey,
    msg: &RequestMessage,
) -> Result<String, MessageError> {
    defuse_wallet::readable_message::request_signing_message(
        SigningIdentity::Sui {
            public_key: &public_key.to_base64(),
            address: &public_key.address(),
        },
        msg,
    )
}

/// Reconstruct the full readable Sui NEP-641 authorization message.
pub fn offchain_signing_message(
    public_key: &SuiPublicKey,
    msg: &OffchainMessage,
) -> Result<String, MessageError> {
    defuse_wallet::readable_message::offchain_signing_message(
        SigningIdentity::Sui {
            public_key: &public_key.to_base64(),
            address: &public_key.address(),
        },
        msg,
    )
}
