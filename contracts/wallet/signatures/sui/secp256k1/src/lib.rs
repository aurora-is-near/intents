use defuse_wallet::wallet;
use defuse_wallet_sui::{WalletSui, crypto::secp256k1::Secp256k1};

wallet! {
    #[wallet(
        schema = WalletSui<Secp256k1>,
        metadata(standard(standard = "wallet-sui-secp256k1", version = "1.0.0"))
    )]
    struct Contract(_);
}
