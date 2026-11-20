use defuse_wallet::wallet;

use crate::WalletEip191;

wallet! {
    #[wallet(
        schema = WalletEip191,
        metadata(
            standard(standard = "wallet-evm-eip191", version = "1.0.0")
        )
    )]
    struct Contract(_);
}
