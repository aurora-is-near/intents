use defuse_wallet::wallet;

use crate::WalletPhantom;

wallet! {
    #[wallet(
        schema = WalletPhantom,
        metadata(
            standard(standard = "wallet-phantom", version = "1.0.0")
        )
    )]
    struct Contract(_);
}
