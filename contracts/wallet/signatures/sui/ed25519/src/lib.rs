use defuse_wallet::wallet;
use defuse_wallet_sui::{WalletSui, crypto::ed25519::Ed25519};

wallet! {
    #[wallet(
        schema = WalletSui<Ed25519>,
        metadata(standard(standard = "wallet-sui-ed25519", version = "1.0.0"))
    )]
    struct Contract(_);
}
