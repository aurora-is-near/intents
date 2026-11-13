#![cfg(feature = "near-kit")]

use std::{env, fs, path::Path, sync::LazyLock};

use defuse_nep641::{JsonPayload, resolver::RpcResolver};
use defuse_wallet::{NearPromise, Request, WalletOp, actions::FunctionCall};
use defuse_wallet_ed25519::{WalletEd25519, WalletEd25519Signer, crypto::ed25519::ed25519_dalek};
use defuse_wallet_sdk::{
    Gas, NearToken, WalletBuilder, WalletSigner,
    client::{WExecuteExtensionArgs, WExecuteSignedArgs, WalletContract},
};
use futures::{
    StreamExt, TryStreamExt, future,
    stream::{self, FuturesUnordered},
    try_join,
};
use near_kit::{CryptoHash, Near, protocol::PublishMode, transaction::Final};
use near_kit_sandbox::SandboxConfig;
use rand::{rand_core::UnwrapErr, rngs::SysRng};
use rstest::{fixture, rstest};
use sha2::{Digest, Sha256};
use tokio::sync::OnceCell;
use tracing_subscriber::EnvFilter;

type Wallet = defuse_wallet_sdk::Wallet<WalletEd25519>;

#[rstest]
#[tokio::test]
#[awt]
async fn metadata_weight_overflow_rolls_back_request(#[future] near: Near) {
    let signer = WalletEd25519Signer(ed25519_dalek::SigningKey::generate(&mut UnwrapErr(SysRng)));
    let wallet = Wallet::new(*WALLET_ED25519_CODE_HASH, signer.clone())
        .with_client(near.clone())
        .with_relayer(near.clone());
    wallet.initialize().await.unwrap();
    let token = "missing-metadata.near"
        .parse::<defuse_wallet::AccountId>()
        .unwrap();
    let sibling = "must-not-run.near"
        .parse::<defuse_wallet::AccountId>()
        .unwrap();
    let request = overflowing_checked_request()
        .internal([WalletOp::add_extension(near.account_id().clone())]);
    // The digest-signing schema deliberately bypasses the readable renderer,
    // exercising the shared execution core with a cryptographically valid proof.
    let (mut msg, proof) = wallet.sign(request).await.unwrap();
    let before = near
        .account(wallet.account_id())
        .await
        .unwrap()
        .storage_usage;
    let contract = near.contract::<WalletContract>(wallet.account_id());
    let result = contract
        .w_execute_signed((&msg, proof.as_str()).into())
        .gas(Gas::from_tgas(80))
        .await
        .unwrap();
    let error = result
        .result()
        .expect_err("overflowing aggregate weight must reject");
    assert!(
        error
            .to_string()
            .contains("total gas weight for checked promise exceeds")
    );
    assert!(!result.receipts_outcome.iter().any(|receipt| {
        receipt.outcome.executor_id == token || receipt.outcome.executor_id == sibling
    }));
    assert_eq!(
        near.account(wallet.account_id())
            .await
            .unwrap()
            .storage_usage,
        before
    );
    assert!(contract.w_extensions().await.unwrap().is_empty());

    // Reusing the exact nonce succeeds: the failed receipt committed no nonce.
    msg.request = Request::new();
    let proof = signer.sign_request_msg(&msg).await.unwrap();
    contract
        .w_execute_signed((&msg, proof.as_str()).into())
        .gas(Gas::from_tgas(30))
        .await
        .unwrap()
        .result()
        .unwrap();

    check_extension_weight_overflow(&near, &wallet).await;
}

fn overflowing_checked_request() -> Request {
    Request::new()
        .internal([WalletOp::require_ft_metadata(
            "missing-metadata.near"
                .parse::<defuse_wallet::AccountId>()
                .unwrap(),
            6,
            "TEST",
        )])
        .external([
            NearPromise::new(
                "must-not-run.near"
                    .parse::<defuse_wallet::AccountId>()
                    .unwrap(),
            )
            .function_call(
                FunctionCall::name("submit")
                    .args(b"{}")
                    .gas(Gas::from_tgas(1)),
            ),
            NearPromise::new(
                "missing-metadata.near"
                    .parse::<defuse_wallet::AccountId>()
                    .unwrap(),
            )
            .function_call(
                FunctionCall::name("first")
                    .args(b"{}")
                    .gas(Gas::from_tgas(1))
                    .unused_gas_weight(u64::MAX),
            )
            .function_call(
                FunctionCall::name("second")
                    .args(b"{}")
                    .gas(Gas::from_tgas(1))
                    .unused_gas_weight(1),
            ),
        ])
}

async fn check_extension_weight_overflow(near: &Near, wallet: &Wallet) {
    wallet
        .sign_and_send(WalletOp::add_extension(near.account_id().clone()))
        .await
        .unwrap()
        .status(near)
        .wait_until::<Final>()
        .await
        .unwrap()
        .result()
        .unwrap();
    // Extensions have no readable-message verifier; the core must still reject.
    let result = near
        .contract::<WalletContract>(wallet.account_id())
        .w_execute_extension(overflowing_checked_request().into())
        .deposit(NearToken::from_yoctonear(1))
        .gas(Gas::from_tgas(80))
        .await
        .unwrap();
    let error = result
        .result()
        .expect_err("extension execution must reject overflowing weights");
    assert!(
        error
            .to_string()
            .contains("total gas weight for checked promise exceeds")
    );
}

#[rstest]
#[tokio::test]
#[awt]
async fn rotate(
    #[future] near: Near,

    #[from(wallet)]
    #[future]
    master: Wallet,

    #[from(wallet)]
    #[future]
    extension: Wallet,
) {
    master
        .sign_and_send(
            Request::new()
                .internal([WalletOp::AddExtension {
                    account_id: extension.real_account_id().clone(),
                }])
                .external([NearPromise::new(extension.real_account_id())
                    .deterministic_state_init(
                        extension.deterministic_state_init().clone(),
                        NearToken::ZERO,
                    )
                    .function_call(
                        FunctionCall::name("w_execute_signed")
                            .attach_deposit(NearToken::from_yoctonear(1))
                            .args_json({
                                let (msg, proof) = extension
                                    .sign(
                                        NearPromise::new(master.real_account_id()).function_call(
                                            FunctionCall::name("w_execute_extension")
                                                .attach_deposit(NearToken::from_yoctonear(1))
                                                .args_json(WExecuteExtensionArgs::from(
                                                    Request::from(WalletOp::SetSignatureMode {
                                                        enable: false,
                                                    }),
                                                ))
                                                .gas(Gas::from_tgas(10)),
                                        ),
                                    )
                                    .await
                                    .unwrap();

                                WExecuteSignedArgs::from((msg, proof))
                            })
                            .gas(Gas::from_tgas(20)),
                    )]),
        )
        .await
        .unwrap()
        .status(&near)
        .wait_until::<Final>()
        .await
        .unwrap()
        .result()
        .expect("key rotation failed");

    master
        .sign_and_send(Request::new())
        .await
        .unwrap()
        .status(&near)
        .wait_until::<Final>()
        .await
        .unwrap()
        .result()
        .expect_err("signature should be disabled");

    let extension = extension.as_extension_of(master);

    extension
        .sign_and_send(Request::new())
        .await
        .unwrap()
        .status(&near)
        .wait_until::<Final>()
        .await
        .unwrap()
        .result()
        .expect("extension should be able to execute requests on behalf of root");
}

#[rstest]
#[tokio::test]
#[awt]
async fn w_init(
    #[future] near: Near,

    #[from(wallet)]
    #[future]
    extension: Wallet,

    #[from(wallet)]
    #[future]
    receiver: Wallet,
) {
    near.deploy_from(CryptoHash::from(*WALLET_NO_SIGN_CODE_HASH))
        .add_action(
            near_kit::transaction::FunctionCall::new("w_init")
                .gas(Gas::from_tgas(5))
                .deposit(NearToken::from_yoctonear(1)),
        )
        .wait_until::<Final>()
        .await
        .unwrap()
        .result()
        .unwrap();

    near.contract::<WalletContract>(near.account_id())
        .w_execute_extension(
            Request::new()
                .internal([WalletOp::RemoveExtension {
                    account_id: near.account_id().into(),
                }])
                .into(),
        )
        .deposit(NearToken::from_yoctonear(1))
        .await
        .unwrap()
        .result()
        .expect_err("cannot accidentally delete itself from extension");

    near.contract::<WalletContract>(near.account_id())
        .w_execute_extension(
            Request::new()
                .internal([WalletOp::AddExtension {
                    account_id: extension.account_id().clone(),
                }])
                .into(),
        )
        .deposit(NearToken::from_yoctonear(1))
        .await
        .unwrap()
        .result()
        .unwrap();

    extension
        .as_extension_of(near.account_id())
        .sign_and_send(NearPromise::new(receiver.account_id()).transfer(NearToken::from_near(5)))
        .await
        .unwrap()
        .status(&near)
        .wait_until::<Final>()
        .await
        .unwrap()
        .result()
        .unwrap();

    assert_eq!(
        near.balance(receiver.account_id())
            .await
            .expect("implicit account should be created by incoming transfer")
            .total,
        NearToken::from_near(5),
    );
}

#[rstest]
#[case::empty("")]
#[case::test("test")]
#[case::json(JsonPayload {
    domain: "Near MPC".to_string(),
    action: "sign".to_string(),
    msg: "Hello, Near!".to_string(),
}.into())]
#[tokio::test]
#[awt]
async fn w_resolve_auth(
    #[case] payload: String,

    #[from(extension)]
    #[with(3)] // extensions depth
    #[future]
    wallet: Wallet,

    #[with(3)] // sub-authorizations depth
    #[future]
    resolver: RpcResolver,
) {
    let authorization = wallet
        .sign_offchain_msg(&payload, None) // top-level
        .await
        .expect("failed to sign");

    let resolved = resolver
        .resolve_auth(wallet.account_id(), &authorization)
        .await
        .expect("invalid authorization");

    println!("{authorization}\n{} -> {resolved}", wallet.account_id());
    assert_eq!(payload, resolved, "resolved invalid payload");
}

#[fixture]
#[awt]
async fn wallet(
    #[default(WalletBuilder::new())] builder: WalletBuilder,
    #[future] near: Near,
) -> Wallet {
    builder
        .build(
            *WALLET_ED25519_CODE_HASH,
            WalletEd25519Signer(ed25519_dalek::SigningKey::generate(&mut UnwrapErr(SysRng))),
        )
        .with_client(near.clone())
        .with_relayer(near)
}

#[fixture]
#[awt]
async fn extension(
    #[default(1)] depth: usize,

    #[from(wallet)]
    #[future]
    ext: Wallet,

    #[future] near: Near,
) -> Wallet {
    // recursively create chain of extensions
    let wallets = stream::unfold(ext, |ext| async {
        let w = wallet(
            WalletBuilder::new().extension(&ext),
            future::ready(near.clone()),
        )
        .await;
        Some((ext, w))
    })
    .take(depth + 1) // preserve original wallet
    .collect::<Vec<_>>()
    .await;

    // initialize all wallets
    wallets
        .iter()
        .map(Wallet::initialize)
        .collect::<FuturesUnordered<_>>()
        .try_collect::<()>()
        .await
        .unwrap();

    // reduce as extension chain
    wallets.into_iter().reduce(Wallet::as_extension_of).unwrap()
}

#[fixture]
#[awt]
async fn resolver(#[default(0)] depth: usize, #[future] near: Near) -> RpcResolver {
    RpcResolver::new(near.rpc().clone())
        .await
        .expect("failed to initialize RPC resolver")
        .with_max_sub_authorizations(depth)
        .with_max_depth(depth)
}

#[fixture]
async fn near() -> Near {
    static DEPLOY: OnceCell<()> = OnceCell::const_new();

    let near = SandboxConfig::shared()
        .await
        .expect("failed to start sandbox")
        .client();

    DEPLOY
        .get_or_init(|| async {
            tracing_subscriber::fmt()
                .with_env_filter(EnvFilter::from_default_env())
                .pretty()
                .init();

            try_join!(
                near.publish(&**WALLET_ED25519_WASM, PublishMode::Immutable)
                    .into_future(),
                near.publish(&**WALLET_NO_SIGN_WASM, PublishMode::Immutable)
                    .into_future(),
            )
            .expect("failed to deploy global contracts by hash");
        })
        .await;

    near
}

static WALLET_ED25519_WASM: LazyLock<Vec<u8>> =
    LazyLock::new(|| read_wasm("defuse-wallet-ed25519.wasm"));
static WALLET_ED25519_CODE_HASH: LazyLock<[u8; 32]> =
    LazyLock::new(|| Sha256::digest(&*WALLET_ED25519_WASM).into());

static WALLET_NO_SIGN_WASM: LazyLock<Vec<u8>> =
    LazyLock::new(|| read_wasm("defuse-wallet-no-sign.wasm"));
static WALLET_NO_SIGN_CODE_HASH: LazyLock<[u8; 32]> =
    LazyLock::new(|| Sha256::digest(&*WALLET_NO_SIGN_WASM).into());

fn read_wasm(path: impl AsRef<Path>) -> Vec<u8> {
    let path = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../../")
        // if out dir path is absolute - base is ignored during join
        .join(env::var("DEFUSE_USE_OUT_DIR").as_deref().unwrap_or("./res"))
        .join(path);

    let path = fs::canonicalize(&path)
        .unwrap_or_else(|e| panic!("Failed to canonicalize path: {} {e}", path.display()));

    fs::read(&path)
        .unwrap_or_else(|e| panic!("Failed to read WASM file at {}: {e}", path.display()))
}
