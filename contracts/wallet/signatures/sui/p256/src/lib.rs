use defuse_wallet::wallet;
use defuse_wallet_sui::{WalletSui, crypto::p256::P256};

wallet! {
    #[wallet(
        schema = WalletSui<P256>,
        metadata(standard(standard = "wallet-sui-p256", version = "1.0.0"))
    )]
    struct Contract(_);
}
