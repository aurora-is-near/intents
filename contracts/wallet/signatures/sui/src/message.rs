use crate::SuiPublicKey;
use defuse_wallet::{RequestMessage, offchain::OffchainMessage};
use defuse_wallet_readable::SigningIdentity;

pub use defuse_wallet_readable::{
    MAX_SIGNING_MESSAGE_BYTES, MessageError, OFFCHAIN_PREFIX, REQUEST_PREFIX,
};

/// Render with the identity fields of the stored key: its Sui native base64
/// (flag plus key) and its directly derived address.
fn with_identity<T>(public_key: &SuiPublicKey, render: impl FnOnce(SigningIdentity<'_>) -> T) -> T {
    let (key, address) = (public_key.to_base64(), public_key.address());

    render(&[
        ("sui_public_key", key.as_str()),
        ("sui_address", address.as_str()),
    ])
}

/// Reconstruct the full readable Sui execution message from the stored key.
pub fn request_signing_message(
    public_key: &SuiPublicKey,
    msg: &RequestMessage,
) -> Result<String, MessageError> {
    with_identity(public_key, |identity| {
        defuse_wallet_readable::request_signing_message(identity, msg)
    })
}

/// Reconstruct the full readable Sui NEP-641 authorization message.
pub fn offchain_signing_message(
    public_key: &SuiPublicKey,
    msg: &OffchainMessage,
) -> Result<String, MessageError> {
    with_identity(public_key, |identity| {
        defuse_wallet_readable::offchain_signing_message(identity, msg)
    })
}
