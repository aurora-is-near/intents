#![cfg(feature = "signer")]

use std::{env, fs, path::Path};

use defuse_nep641::resolver::RpcResolver;
use defuse_wallet::{AccountId, Gas, NearPromise, NearToken, Request, actions::FunctionCall};
use defuse_wallet_evm_eip191::{WalletEip191, WalletEip191Signer};
use defuse_wallet_evm_eip712::{
    WalletEip712, WalletEip712Signer,
    crypto::secp256k1::k256::ecdsa::SigningKey,
    crypto::secp256k1::{Secp256k1RecoverableSignature, k256::ecdsa},
};
use defuse_wallet_sdk::{Wallet, WalletSigner, client::WalletContract};
use k256::elliptic_curve::Generate;
use near_kit::{Final, PublishMode, sandbox::SandboxConfig};
use sha2::{Digest, Sha256};

type Eip712Wallet = Wallet<WalletEip712>;

fn signer() -> WalletEip712Signer<SigningKey> {
    WalletEip712Signer(SigningKey::generate())
}

#[tokio::test]
async fn wallet_executes_and_resolves_authorization_in_wasm() {
    let near = SandboxConfig::shared().await.client();
    let directory = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../../../..")
        .join(env::var("DEFUSE_USE_OUT_DIR").as_deref().unwrap_or("res"));
    let wasm = fs::read(directory.join("defuse-wallet-evm-eip712.wasm"))
        .expect("build with make defuse-wallet-evm-eip712 first");
    let code_hash: [u8; 32] = Sha256::digest(&wasm).into();
    near.publish(wasm, PublishMode::Immutable)
        .wait_until::<Final>()
        .await
        .unwrap()
        .result()
        .unwrap();
    let key = signer();
    let wallet = Eip712Wallet::new(code_hash, key.clone())
        .with_client(near.clone())
        .with_relayer(near.clone());
    wallet.initialize().await.unwrap();
    let contract = near.contract::<WalletContract>(wallet.account_id());
    assert_eq!(
        contract.w_public_key().await.unwrap(),
        wallet.public_key().to_string()
    );
    near.transaction(wallet.account_id())
        .transfer(NearToken::from_near(5))
        .wait_until::<Final>()
        .await
        .unwrap()
        .result()
        .unwrap();

    // A signed NEAR transfer executes.
    let recipient: AccountId = near.account_id().clone();
    let before = near.balance(&recipient).await.unwrap().total;
    wallet
        .sign_and_send(NearPromise::new(&recipient).transfer(NearToken::from_near(1)))
        .await
        .unwrap()
        .status(&near)
        .wait_until::<Final>()
        .await
        .unwrap()
        .result()
        .unwrap();
    assert!(near.balance(&recipient).await.unwrap().total > before);

    // An invalid proof rolls back the nonce; replay, another key, an EIP-191
    // proof of the same key and the high-S twin are rejected.
    let (msg, proof) = wallet.sign(Request::new()).await.unwrap();
    let submit = async |proof: &str| {
        contract
            .w_execute_signed((&msg, proof).into())
            .gas(Gas::from_tgas(30))
            .await
            .unwrap()
            .result()
    };
    submit("secp256k1:invalid")
        .await
        .expect_err("invalid proof");
    let other = WalletSigner::<WalletEip712>::sign_request_msg(&signer(), &msg)
        .await
        .unwrap();
    submit(&other).await.expect_err("another address");
    let personal =
        WalletSigner::<WalletEip191>::sign_request_msg(&WalletEip191Signer(key.0.clone()), &msg)
            .await
            .unwrap();
    submit(&personal).await.expect_err("EIP-191 proof");
    let (signature, recovery_id) = <(ecdsa::Signature, ecdsa::RecoveryId)>::try_from(
        &proof.parse::<Secp256k1RecoverableSignature>().unwrap(),
    )
    .unwrap();
    let high_s = Secp256k1RecoverableSignature::from((
        ecdsa::Signature::from_scalars(signature.r(), -signature.s()).unwrap(),
        ecdsa::RecoveryId::from_byte(recovery_id.to_byte() ^ 1).unwrap(),
    ))
    .to_string();
    submit(&high_s).await.expect_err("high-S signature");
    submit(&proof).await.unwrap();
    submit(&proof).await.expect_err("nonce replay");

    largest_arguments_gas(&contract, &wallet, &key, &recipient).await;

    // The NEP-641 route resolves exactly the signed payload.
    let payload = "{ \"domain\": \"EIP-712 test\", \"amount\": \"9007199254740993\" }";
    let authorization = wallet.sign_offchain_msg(payload, None).await.unwrap();
    let resolver = RpcResolver::new(near.rpc().clone()).await.unwrap();
    assert_eq!(
        resolver
            .resolve_auth(wallet.account_id(), &authorization)
            .await
            .unwrap(),
        payload
    );
}

/// Gas profiles near the limits: about 16 KiB of arguments, and 128 items.
async fn largest_arguments_gas(
    contract: &<WalletContract as near_kit::Contract>::Client,
    wallet: &Eip712Wallet,
    key: &WalletEip712Signer<SigningKey>,
    recipient: &AccountId,
) {
    let mut profile = serde_json::Map::new();
    let padding = 16 * 1024 - 256;
    let calls = NearPromise::new(recipient).function_call(
        FunctionCall::name("w_public_key")
            .args(format!("{{\"padding\":\"{}\"}}", "a".repeat(padding)))
            .gas(Gas::from_tgas(5))
            .unused_gas_weight(0),
    );
    // A receipt holds at most 100 actions: two promises of 63 transfers.
    let transfers = (0..63).fold(NearPromise::new(recipient), |promise, _| {
        promise.transfer(NearToken::from_yoctonear(1))
    });
    let transfers = Request::new().external([transfers.clone(), transfers]);
    for (name, request) in [("args_16k", Request::from(calls)), ("items_128", transfers)] {
        let (mut msg, _) = wallet.sign(Request::new()).await.unwrap();
        msg.request = request;
        let proof = WalletSigner::<WalletEip712>::sign_request_msg(key, &msg)
            .await
            .unwrap();
        let result = contract
            .w_execute_signed((&msg, proof.as_str()).into())
            .gas(Gas::from_tgas(300))
            .await
            .unwrap();
        result.result().unwrap();
        profile.insert(name.into(), result.total_gas_used().as_gas().into());
    }
    println!(
        "EIP712_RESOURCE_PROFILE {}",
        serde_json::Value::Object(profile)
    );
}
