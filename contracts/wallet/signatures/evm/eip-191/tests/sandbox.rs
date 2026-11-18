#![cfg(feature = "signer")]

#[path = "../../../readable/test-utils/entrypoints.rs"]
mod entrypoints;

use std::{env, fs, path::Path};

use defuse_nep641::resolver::RpcResolver;
use defuse_wallet::{
    AccountId, Gas, NearPromise, NearToken, Request, StateInit, StateInitV1, WalletOp,
    actions::FunctionCall,
};
use defuse_wallet_evm_eip191::{
    WalletEip191, WalletEip191Signer, crypto::secp256k1::k256::ecdsa::SigningKey,
    request_signing_message,
};
use defuse_wallet_sdk::{Wallet, WalletBuilder, client::WalletContract};
use k256::elliptic_curve::Generate;
use near_kit::{Near, protocol::PublishMode, rpc::FinalExecutionOutcome, transaction::Final};
use near_kit_sandbox::SandboxConfig;
use sha2::{Digest, Sha256};

type EvmWallet = Wallet<WalletEip191>;

async fn execute(
    near: &Near,
    wallet: &EvmWallet,
    request: impl Into<Request>,
) -> FinalExecutionOutcome {
    let outcome = wallet
        .sign_and_send(request)
        .await
        .unwrap()
        .status(near)
        .wait_until::<Final>()
        .await
        .unwrap();
    outcome.result().unwrap();
    outcome
}

fn signer() -> WalletEip191Signer<SigningKey> {
    WalletEip191Signer(SigningKey::generate())
}

#[tokio::test]
async fn wallet_executes_and_resolves_authorization_in_wasm() {
    let near = SandboxConfig::shared()
        .await
        .expect("failed to start sandbox")
        .client();
    let directory = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../../../..")
        .join(env::var("DEFUSE_USE_OUT_DIR").as_deref().unwrap_or("res"));
    let wasm = fs::read(directory.join("defuse-wallet-evm-eip191.wasm"))
        .expect("build with make defuse-wallet-evm-eip191 first");
    let code_hash: [u8; 32] = Sha256::digest(&wasm).into();
    near.publish(wasm, PublishMode::Immutable)
        .wait_until::<Final>()
        .await
        .unwrap()
        .result()
        .unwrap();
    let key = signer();
    let wallet = EvmWallet::new(code_hash, key.clone())
        .with_client(near.clone())
        .with_relayer(near.clone());
    let recipient = WalletBuilder::new()
        .subwallet_id(1)
        .build(code_hash, signer())
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
    // The stored identity is the `0x` address shown in the signed message.
    assert_eq!(
        contract.w_public_key().await.unwrap(),
        wallet.public_key().to_string()
    );
    assert!(contract.w_public_key().await.unwrap().starts_with("0x"));

    // Fund only these isolated sandbox accounts; the keys are random test keys.
    near.transaction(wallet.account_id())
        .transfer(NearToken::from_near(5))
        .wait_until::<Final>()
        .await
        .unwrap()
        .result()
        .unwrap();

    check_public_entrypoints(&near, &wallet, &key).await;

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

    check_ft_transfer(&near, &wallet, &recipient).await;
    check_nonce_rollback_and_replay(&near, &wallet).await;
    check_largest_message_and_high_s(&near, &wallet, &recipient, &key).await;

    // The full NEP-641 route resolves exactly the signed payload, including whitespace.
    let payload = "{ \"domain\": \"EVM test\", \"amount\": \"9007199254740993\" }";
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

async fn check_nonce_rollback_and_replay(near: &Near, wallet: &EvmWallet) {
    let contract = near.contract::<WalletContract>(wallet.account_id());
    // A bad proof must roll back the nonce commitment; its valid counterpart still works.
    let (msg, proof) = wallet.sign(Request::new()).await.unwrap();
    contract
        .w_execute_signed((&msg, "secp256k1:invalid").into())
        .gas(Gas::from_tgas(30))
        .await
        .unwrap()
        .result()
        .expect_err("invalid proof must fail");
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

    // A valid proof of another EVM key does not control this wallet.
    let (msg, _) = wallet.sign(Request::new()).await.unwrap();
    let other = defuse_wallet_sdk::WalletSigner::<WalletEip191>::sign_request_msg(&signer(), &msg)
        .await
        .unwrap();
    contract
        .w_execute_signed((&msg, other.as_str()).into())
        .gas(Gas::from_tgas(30))
        .await
        .unwrap()
        .result()
        .expect_err("another address must fail");
}

/// The largest readable message (16 KiB) verifies in wasm; an oversized one and
/// the high-S twin of a valid signature are rejected without consuming the nonce.
async fn check_largest_message_and_high_s(
    near: &Near,
    wallet: &EvmWallet,
    recipient: &EvmWallet,
    key: &WalletEip191Signer<SigningKey>,
) {
    use defuse_wallet_evm_eip191::{
        MAX_SIGNING_MESSAGE_BYTES,
        crypto::secp256k1::{Secp256k1RecoverableSignature, k256::ecdsa},
    };
    let contract = near.contract::<WalletContract>(wallet.account_id());
    let (original, _) = wallet.sign(Request::new()).await.unwrap();
    let with_payload = |length| {
        let mut msg = original.clone();
        msg.request = NearPromise::new(recipient.account_id())
            .function_call(
                FunctionCall::name("w_public_key")
                    .args(format!("{{\"padding\":\"{}\"}}", "a".repeat(length)))
                    .gas(Gas::from_tgas(5))
                    .unused_gas_weight(0),
            )
            .into();
        msg
    };
    let address = wallet.public_key();
    let (mut low, mut high) = (0, MAX_SIGNING_MESSAGE_BYTES);
    while low + 1 < high {
        let middle = usize::midpoint(low, high);
        if request_signing_message(&address, &with_payload(middle)).is_ok() {
            low = middle;
        } else {
            high = middle;
        }
    }
    let (msg, oversized) = (with_payload(low), with_payload(high));
    let length = request_signing_message(&address, &msg).unwrap().len();
    // Each ASCII padding byte adds exactly one display byte.
    assert_eq!(length, MAX_SIGNING_MESSAGE_BYTES);
    assert!(request_signing_message(&address, &oversized).is_err());

    // A well-formed but wrong proof for a message that cannot be displayed.
    let mut wrong = [1; 65];
    wrong[64] = 0;
    let failed = contract
        .w_execute_signed(
            (
                &oversized,
                Secp256k1RecoverableSignature(wrong).to_string().as_str(),
            )
                .into(),
        )
        .gas(Gas::from_tgas(80))
        .await
        .unwrap();
    failed.result().expect_err("oversized display must reject");

    let proof = defuse_wallet_sdk::WalletSigner::<WalletEip191>::sign_request_msg(key, &msg)
        .await
        .unwrap();
    let (signature, recovery_id) = <(ecdsa::Signature, ecdsa::RecoveryId)>::try_from(
        &proof.parse::<Secp256k1RecoverableSignature>().unwrap(),
    )
    .unwrap();
    let high_s = ecdsa::Signature::from_scalars(signature.r(), -signature.s()).unwrap();
    let flipped = ecdsa::RecoveryId::from_byte(recovery_id.to_byte() ^ 1).unwrap();
    let high_s = Secp256k1RecoverableSignature::from((high_s, flipped)).to_string();
    contract
        .w_execute_signed((&msg, high_s.as_str()).into())
        .gas(Gas::from_tgas(80))
        .await
        .unwrap()
        .result()
        .expect_err("high-S signature must be rejected by env::ecrecover");

    let result = contract
        .w_execute_signed((&msg, proof.as_str()).into())
        .gas(Gas::from_tgas(80))
        .await
        .unwrap();
    result.result().unwrap();
    println!(
        "EVM_RESOURCE_PROFILE {}",
        serde_json::json!({
            "message_bytes": length,
            "proof_bytes": proof.len(),
            "gas": result.total_gas_used().as_gas(),
            "oversized_rejection_gas": failed.total_gas_used().as_gas(),
        })
    );
    contract
        .w_execute_signed((&msg, proof.as_str()).into())
        .gas(Gas::from_tgas(40))
        .await
        .unwrap()
        .result()
        .expect_err("large-request replay");
}

async fn check_lockout_and_rotation(
    near: &Near,
    wallet: EvmWallet,
    recipient: EvmWallet,
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

    // Installing another EVM wallet as an extension and rotating control works.
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

/// A NEP-141 transfer is signed and executed with its exact base-unit amount.
async fn check_ft_transfer(near: &Near, wallet: &EvmWallet, recipient: &EvmWallet) {
    // near-sdk example fungible token.
    let wasm = fs::read(
        Path::new(env!("CARGO_MANIFEST_DIR")).join("../../../../../releases/fungible-token.wasm"),
    )
    .unwrap();
    let token: AccountId = format!("ft{}.{}", rand::random::<u32>(), near.account_id())
        .parse()
        .unwrap();
    near.transaction(&token)
        .create_account()
        .transfer(NearToken::from_near(5))
        .deploy(wasm.clone())
        .call("new_default_meta")
        .args(serde_json::json!({
            "owner_id": wallet.account_id(),
            "total_supply": NearToken::from_near(10).as_yoctonear().to_string(),
        }))
        .gas(Gas::from_tgas(30))
        .finish()
        .call("storage_deposit")
        .args(serde_json::json!({ "account_id": recipient.account_id() }))
        .deposit(NearToken::from_millinear(10))
        .gas(Gas::from_tgas(30))
        .finish()
        .wait_until::<Final>()
        .await
        .unwrap()
        .result()
        .unwrap();
    let transfer =
        NearPromise::new(token.clone()).function_call(ft_transfer(recipient.account_id()));
    let (msg, _) = wallet.sign(transfer.clone()).await.unwrap();
    let message = request_signing_message(&wallet.public_key(), &msg).unwrap();
    assert!(
        message.contains(r#""amount": "1500000000000000000000000""#),
        "{message}"
    );

    execute(near, wallet, transfer).await;
    assert_eq!(
        ft_balance(near, &token, recipient.account_id()).await,
        NearToken::from_millinear(1500).as_yoctonear().to_string()
    );

    check_ft_bootstrap(near, wallet, recipient, wasm).await;
}

/// A token is created, initialized and transferred in one promise.
async fn check_ft_bootstrap(near: &Near, wallet: &EvmWallet, recipient: &EvmWallet, wasm: Vec<u8>) {
    let ft_hash: [u8; 32] = Sha256::digest(&wasm).into();
    near.publish(wasm, PublishMode::Immutable)
        .wait_until::<Final>()
        .await
        .unwrap()
        .result()
        .unwrap();
    let mut init = StateInitV1::code(ft_hash);
    // Unique account for each run, also on a reused sandbox.
    init.data
        .insert(b"test_run".to_vec(), rand::random::<[u8; 8]>().to_vec());
    let init = StateInit::from(init);
    let token = init.derive_account_id();
    let create = NearPromise::new(token.clone())
        .deterministic_state_init(init.clone(), NearToken::ZERO)
        // Storage for the token state written by `new_default_meta`.
        .transfer(NearToken::from_millinear(100))
        .function_call(
            FunctionCall::name("new_default_meta")
                .args(
                    serde_json::json!({
                        "owner_id": wallet.account_id(),
                        "total_supply": NearToken::from_near(10).as_yoctonear().to_string(),
                    })
                    .to_string(),
                )
                .gas(Gas::from_tgas(30)),
        )
        .function_call(
            FunctionCall::name("storage_deposit")
                .args(serde_json::json!({ "account_id": recipient.account_id() }).to_string())
                .attach_deposit(NearToken::from_millinear(10))
                .gas(Gas::from_tgas(30)),
        );
    check_state_init_deposit(near, wallet, &init, recipient.account_id()).await;
    let bootstrap = create.function_call(ft_transfer(recipient.account_id()));
    execute(near, wallet, bootstrap).await;
    assert_eq!(
        ft_balance(near, &token, recipient.account_id()).await,
        NearToken::from_millinear(1500).as_yoctonear().to_string()
    );
}

/// A `StateInit` deposit settles only current storage; excess is refunded even
/// when a later initializing call needs more storage in the same promise.
async fn check_state_init_deposit(
    near: &Near,
    wallet: &EvmWallet,
    init: &StateInit,
    refund_to: &AccountId,
) {
    let token = init.derive_account_id();
    let deposit = NearToken::from_near(1);
    let before = near.balance(refund_to).await.unwrap().total;
    let attempt = NearPromise::new(token.clone())
        .refund_to(refund_to.clone())
        .deterministic_state_init(init.clone(), deposit)
        .function_call(
            FunctionCall::name("new_default_meta")
                .args(
                    serde_json::json!({
                        "owner_id": wallet.account_id(),
                        "total_supply": "1000000",
                    })
                    .to_string(),
                )
                .gas(Gas::from_tgas(30)),
        );
    let outcome = execute(near, wallet, attempt).await;
    assert!(
        outcome
            .receipts_outcome
            .iter()
            .any(|r| { format!("{:?}", r.outcome.status).contains("LackBalanceForState") }),
        "{outcome:?}"
    );
    assert!(near.account(&token).await.is_err());
    assert_eq!(
        near.balance(refund_to).await.unwrap().total,
        before.saturating_add(deposit)
    );

    // The same deposit is entirely refunded on successful initialization of a
    // small ZBA. It never becomes a general-purpose balance at the receiver.
    execute(
        near,
        wallet,
        NearPromise::new(token.clone())
            .refund_to(refund_to.clone())
            .deterministic_state_init(init.clone(), deposit),
    )
    .await;
    assert_eq!(near.balance(&token).await.unwrap().total, NearToken::ZERO);
    assert_eq!(
        near.balance(refund_to).await.unwrap().total,
        before.saturating_add(deposit).saturating_add(deposit)
    );
}

/// `ft_transfer` of 1500000000000000000000000 base units to `receiver_id`.
fn ft_transfer(receiver_id: &AccountId) -> FunctionCall {
    FunctionCall::name("ft_transfer")
        .args(
            serde_json::json!({
                "receiver_id": receiver_id,
                "amount": NearToken::from_millinear(1500).as_yoctonear().to_string(),
            })
            .to_string(),
        )
        .attach_deposit(NearToken::from_yoctonear(1))
        .gas(Gas::from_tgas(10))
}

async fn ft_balance(near: &Near, token: &AccountId, account_id: &AccountId) -> String {
    near.view::<String>(token, "ft_balance_of")
        .args(serde_json::json!({ "account_id": account_id }))
        .await
        .unwrap()
}

async fn check_public_entrypoints(
    near: &near_kit::Near,
    wallet: &EvmWallet,
    signer: &WalletEip191Signer<SigningKey>,
) {
    let (msg, proof) = wallet
        .sign(defuse_wallet::WalletOp::add_extension(
            near.account_id().clone(),
        ))
        .await
        .unwrap();
    entrypoints::check(near, wallet.account_id(), &msg, &proof).await;
    execute(
        near,
        wallet,
        WalletOp::remove_extension(near.account_id().clone()),
    )
    .await;
    let (msg, _) = wallet.sign(defuse_wallet::Request::new()).await.unwrap();
    entrypoints::context(near, wallet.account_id(), &msg, signer).await;
}
