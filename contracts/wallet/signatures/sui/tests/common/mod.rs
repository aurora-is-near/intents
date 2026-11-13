use defuse_wallet::{RequestMessage, SignatureSchema, offchain::OffchainMessage};
use defuse_wallet_sui::{
    SuiPublicKey, WalletSui,
    crypto::{ed25519::Ed25519, p256::P256, secp256k1::Secp256k1},
};

// Test-only dispatch lets one fixture table exercise three concrete schemas.
// No universal contract variant is built from this helper.
pub struct TestSui;
impl SignatureSchema for TestSui {
    type PublicKey = SuiPublicKey;
    fn verify_request_msg(key: &SuiPublicKey, msg: &RequestMessage, proof: &str) -> bool {
        match key.flag() {
            0 => WalletSui::<Ed25519>::verify_request_msg(key, msg, proof),
            1 => WalletSui::<Secp256k1>::verify_request_msg(key, msg, proof),
            2 => WalletSui::<P256>::verify_request_msg(key, msg, proof),
            _ => false,
        }
    }
    fn verify_offchain_msg(key: &SuiPublicKey, msg: &OffchainMessage, proof: &str) -> bool {
        match key.flag() {
            0 => WalletSui::<Ed25519>::verify_offchain_msg(key, msg, proof),
            1 => WalletSui::<Secp256k1>::verify_offchain_msg(key, msg, proof),
            2 => WalletSui::<P256>::verify_offchain_msg(key, msg, proof),
            _ => false,
        }
    }
}
