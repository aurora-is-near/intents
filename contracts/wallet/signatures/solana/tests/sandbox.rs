#![cfg(feature = "signer")]

use std::{env, fs, path::Path};

use defuse_nep641::resolver::RpcResolver;
use defuse_wallet::{Gas, NearPromise, NearToken, Request, WalletOp};
use defuse_wallet_sdk::{Wallet, WalletBuilder, client::WalletContract};
use defuse_wallet_solana::{
    WalletPhantom, WalletPhantomSigner, crypto::ed25519::ed25519_dalek::SigningKey,
};
use near_kit::{Near, protocol::PublishMode, signer::InMemorySigner, transaction::Final};
use near_kit_sandbox::SandboxConfig;
use rand::{rand_core::UnwrapErr, rngs::SysRng};
use sha2::{Digest, Sha256};

async fn near() -> Near {
    if let Ok(url) = env::var("PHANTOM_SANDBOX_RPC_URL") {
        // This override is strictly for an isolated native sandbox, never a public network.
        assert!(is_loopback_sandbox_url(&url));
        let signer = InMemorySigner::new("sandbox", "ed25519:3tgdk2wPraJzT4nsTuf86UX41xgPNk3MHnq8epARMdBNs29AFEztAuaQ7iHddDfXG9F2RzV1XNQYgJyAyoW51UBB").unwrap();
        let provisional = Near::custom(&url, "sandbox").build();
        let chain = provisional.rpc().status().await.unwrap().chain_id;
        Near::custom(url, chain).signer(signer).build()
    } else {
        SandboxConfig::shared()
            .await
            .expect("NEAR sandbox requires Docker or PHANTOM_SANDBOX_RPC_URL")
            .client()
    }
}

fn is_loopback_sandbox_url(url: &str) -> bool {
    let Some(endpoint) = url
        .strip_prefix("http://127.0.0.1:")
        .or_else(|| url.strip_prefix("http://localhost:"))
    else {
        return false;
    };
    let port = endpoint.strip_suffix('/').unwrap_or(endpoint);
    !port.is_empty()
        && port.bytes().all(|byte| byte.is_ascii_digit())
        && port.parse::<u16>().is_ok_and(|port| port != 0)
}

#[test]
fn sandbox_url_guard_rejects_remote_hosts_and_credentials() {
    for url in ["http://127.0.0.1:49206", "http://localhost:49206/"] {
        assert!(is_loopback_sandbox_url(url));
    }
    for url in [
        "http://127.0.0.1:80@attacker.example/",
        "http://localhost:80@attacker.example/",
        "http://127.0.0.1.attacker.example:80/",
        "http://localhost:0",
        "http://localhost:65536",
        "http://localhost:+80",
        "https://localhost:80",
        "http://localhost:80/path",
        "http://localhost:80?redirect=attacker.example",
    ] {
        assert!(!is_loopback_sandbox_url(url), "accepted {url}");
    }
}

async fn execute(near: &Near, wallet: &Wallet<WalletPhantom>, request: impl Into<Request>) {
    wallet
        .sign_and_send(request)
        .await
        .unwrap()
        .status(near)
        .wait_until::<Final>()
        .await
        .unwrap()
        .result()
        .unwrap();
}

#[tokio::test]
async fn wallet_executes_and_resolves_authorization_in_wasm() {
    let near = near().await;
    let directory = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../../..")
        .join(env::var("DEFUSE_USE_OUT_DIR").as_deref().unwrap_or("res"));
    let wasm = fs::read(directory.join("defuse-wallet-solana.wasm"))
        .expect("build with make defuse-wallet-solana first");
    let code_hash: [u8; 32] = Sha256::digest(&wasm).into();
    near.publish(wasm, PublishMode::Immutable)
        .await
        .unwrap()
        .result()
        .unwrap();
    let wallet = Wallet::<WalletPhantom>::new(
        code_hash,
        WalletPhantomSigner(SigningKey::generate(&mut UnwrapErr(SysRng))),
    )
    .with_client(near.clone())
    .with_relayer(near.clone());
    let recipient = WalletBuilder::new()
        .subwallet_id(1)
        .build(
            code_hash,
            WalletPhantomSigner(SigningKey::generate(&mut UnwrapErr(SysRng))),
        )
        .with_client(near.clone())
        .with_relayer(near.clone());
    assert_eq!(
        wallet.deterministic_state_init().derive_account_id(),
        *wallet.account_id()
    );
    assert_ne!(wallet.account_id(), recipient.account_id());
    wallet.initialize().await.unwrap();
    recipient.initialize().await.unwrap();
    let contract = near.contract::<WalletContract>(wallet.account_id());
    assert_eq!(
        contract.w_public_key().await.unwrap(),
        wallet.public_key().to_string()
    );

    // Fund only these isolated sandbox accounts; this key is public test material.
    near.transaction(wallet.account_id())
        .transfer(NearToken::from_near(5))
        .send()
        .wait_until::<Final>()
        .await
        .unwrap()
        .result()
        .unwrap();
    let before = near.balance(recipient.account_id()).await.unwrap().total;
    execute(
        &near,
        &wallet,
        NearPromise::new(recipient.account_id()).transfer(NearToken::from_near(1)),
    )
    .await;
    assert_eq!(
        near.balance(recipient.account_id()).await.unwrap().total,
        before.saturating_add(NearToken::from_near(1))
    );

    check_nonce_rollback_and_replay(&near, &wallet).await;

    // The full NEP-641 route resolves exactly the signed payload, including whitespace.
    let payload = "{ \"domain\": \"Phantom test\", \"amount\": \"9007199254740993\" }";
    let authorization = wallet.sign_offchain_msg(payload, None).await.unwrap();
    let resolver = RpcResolver::new(near.rpc().clone()).await.unwrap();
    assert_eq!(
        resolver
            .resolve_auth(wallet.account_id(), &authorization)
            .await
            .unwrap(),
        payload
    );

    check_lockout_and_rotation(&near, wallet, recipient, payload, resolver).await;
}

async fn check_nonce_rollback_and_replay(near: &Near, wallet: &Wallet<WalletPhantom>) {
    let contract = near.contract::<WalletContract>(wallet.account_id());
    // A bad proof must roll back the nonce commitment; its valid counterpart still works.
    let (msg, proof) = wallet.sign(Request::new()).await.unwrap();
    let failed = contract
        .w_execute_signed((&msg, "ed25519:invalid").into())
        .gas(Gas::from_tgas(30))
        .await
        .unwrap();
    failed.result().expect_err("invalid proof must fail");
    contract
        .w_execute_signed((&msg, proof.as_str()).into())
        .gas(Gas::from_tgas(30))
        .await
        .unwrap()
        .result()
        .unwrap();
    contract
        .w_execute_signed((&msg, proof.as_str()).into())
        .gas(Gas::from_tgas(30))
        .await
        .unwrap()
        .result()
        .expect_err("nonce replay must fail");
}

async fn check_lockout_and_rotation(
    near: &Near,
    wallet: Wallet<WalletPhantom>,
    recipient: Wallet<WalletPhantom>,
    payload: &str,
    resolver: RpcResolver,
) {
    let contract = near.contract::<WalletContract>(wallet.account_id());
    // Lockout and external self-call checks remain enforced by the shared core.
    let (msg, proof) = wallet.sign(WalletOp::disable_signature()).await.unwrap();
    contract
        .w_execute_signed((&msg, proof.as_str()).into())
        .gas(Gas::from_tgas(30))
        .await
        .unwrap()
        .result()
        .expect_err("last authentication method cannot be disabled");
    let (msg, proof) = wallet
        .sign(NearPromise::new(wallet.account_id()).transfer(NearToken::from_yoctonear(1)))
        .await
        .unwrap();
    contract
        .w_execute_signed((&msg, proof.as_str()).into())
        .gas(Gas::from_tgas(30))
        .await
        .unwrap()
        .result()
        .expect_err("self-call must fail");

    // Installing another Phantom wallet as an extension and rotating control works.
    execute(
        near,
        &wallet,
        WalletOp::add_extension(recipient.account_id().clone()),
    )
    .await;
    execute(near, &wallet, WalletOp::disable_signature()).await;
    let (msg, proof) = wallet.sign(Request::new()).await.unwrap();
    contract
        .w_execute_signed((&msg, proof.as_str()).into())
        .gas(Gas::from_tgas(30))
        .await
        .unwrap()
        .result()
        .expect_err("disabled signatures must fail");
    let extension = recipient.as_extension_of(wallet);
    execute(near, &extension, Request::new()).await;
    let authorization = extension.sign_offchain_msg(payload, None).await.unwrap();
    assert_eq!(
        resolver
            .with_max_sub_authorizations(1)
            .with_max_depth(1)
            .resolve_auth(extension.account_id(), &authorization)
            .await
            .unwrap(),
        payload
    );
}
