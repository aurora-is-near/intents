#![cfg(feature = "signer")]

#[path = "../../readable/test-utils/entrypoints.rs"]
mod entrypoints;

use std::{env, fs, path::Path, time::Duration};

use defuse_nep641::resolver::{ContractError, ResolveErrorKind, RpcResolver};
use defuse_wallet::{
    AccountId, Gas, NearPromise, NearToken, Request, RequestMessage, SignatureSchema, StateInit,
    StateInitV1, Timestamp, WalletAuthorization, WalletOp, actions::FunctionCall,
    offchain::OffchainMessage,
};
use defuse_wallet_sdk::{Wallet, WalletBuilder, WalletSigner, client::WalletContract};
use defuse_wallet_sui::{
    MAX_SIGNING_MESSAGE_BYTES, MessageError, WalletSui, WalletSuiSigner,
    crypto::{
        Signer,
        ed25519::{Ed25519, ed25519_dalek},
        p256::{P256, p256},
        secp256k1::{Secp256k1, k256},
    },
    offchain_signing_message,
    protocol::SuiScheme,
    request_signing_message,
};
use near_kit::{Near, protocol::PublishMode, rpc::FinalExecutionOutcome, transaction::Final};
use near_kit_sandbox::SandboxConfig;
// Link the native NEAR host mocks used by near-kit's deterministic-address hash.
use near_sdk as _;
use sha2::{Digest, Sha256};

async fn near() -> Near {
    SandboxConfig::shared()
        .await
        .expect("failed to start sandbox")
        .client()
}

async fn execute<C: SuiScheme>(
    near: &Near,
    wallet: &Wallet<WalletSui<C>>,
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

#[tokio::test]
async fn wallet_executes_and_resolves_authorization_in_wasm() {
    let near = near().await;

    run_variant::<Ed25519, _>(
        &near,
        "ed25519",
        ed25519_dalek::SigningKey::from_bytes(&[1; 32]),
    )
    .await;
    run_variant::<Secp256k1, _>(
        &near,
        "secp256k1",
        k256::ecdsa::SigningKey::from_bytes((&[2; 32]).into()).unwrap(),
    )
    .await;
    run_variant::<P256, _>(
        &near,
        "p256",
        p256::ecdsa::SigningKey::from_bytes((&[3; 32]).into()).unwrap(),
    )
    .await;
}

async fn run_variant<C, S>(near: &Near, variant: &str, raw_signer: S)
where
    C: SuiScheme,
    S: Signer<C> + Clone + 'static,
    S::Error: std::error::Error + Send + Sync + 'static,
{
    let signer = WalletSuiSigner::<C, _>::new(raw_signer);
    let directory = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../../..")
        .join(env::var("DEFUSE_USE_OUT_DIR").as_deref().unwrap_or("res"));
    let wasm = fs::read(directory.join(format!("defuse-wallet-sui-{variant}.wasm")))
        .expect("build all three Sui contract variants first");
    let code_hash: [u8; 32] = Sha256::digest(&wasm).into();

    near.publish(wasm, PublishMode::Immutable)
        .await
        .unwrap()
        .result()
        .unwrap();

    // StateInit accepts Borsh state directly. A valid proof for another scheme
    // must still fail even if its key was deliberately placed in this leaf.
    check_wrong_global_scheme::<C, Ed25519, _>(
        near,
        code_hash,
        ed25519_dalek::SigningKey::from_bytes(&[4; 32]),
    )
    .await;
    check_wrong_global_scheme::<C, Secp256k1, _>(
        near,
        code_hash,
        k256::ecdsa::SigningKey::from_bytes((&[4; 32]).into()).unwrap(),
    )
    .await;
    check_wrong_global_scheme::<C, P256, _>(
        near,
        code_hash,
        p256::ecdsa::SigningKey::from_bytes((&[4; 32]).into()).unwrap(),
    )
    .await;

    let run_id = rand::random::<u32>() & !1;
    let scheme = C::FLAG;
    let wallet = WalletBuilder::new()
        .subwallet_id(run_id)
        .build(code_hash, signer.clone())
        .with_client(near.clone())
        .with_relayer(near.clone());
    let recipient = WalletBuilder::new()
        .subwallet_id(run_id + 1)
        .build(code_hash, signer.clone())
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

    check_public_entrypoints(near, &wallet).await;

    let before = near.balance(recipient.account_id()).await.unwrap().total;
    execute(
        near,
        &wallet,
        NearPromise::new(recipient.account_id()).transfer(NearToken::from_near(1)),
    )
    .await;
    assert_eq!(
        near.balance(recipient.account_id()).await.unwrap().total,
        before.saturating_add(NearToken::from_near(1))
    );

    if C::FLAG == 0 {
        check_ft_transfer(near, &wallet, &recipient).await;
    }

    check_resources_and_context(near, &wallet, &recipient, scheme, &signer).await;
    check_nonce_rollback_and_replay(near, &wallet).await;

    // The full NEP-641 route resolves exactly the signed payload, including whitespace.
    let payload = "{ \"domain\": \"Sui test\", \"amount\": \"9007199254740993\" }";
    let authorization = wallet.sign_offchain_msg(payload, None).await.unwrap();
    let resolver = RpcResolver::new(near.rpc().clone()).await.unwrap();

    assert_eq!(
        resolver
            .resolve_auth(wallet.account_id(), &authorization)
            .await
            .unwrap(),
        payload
    );

    check_lockout_and_rotation(near, wallet, recipient, payload, resolver).await;
}

/// A NEP-141 transfer is signed and executed with its exact base-unit amount.
async fn check_ft_transfer<C: SuiScheme>(
    near: &Near,
    wallet: &Wallet<WalletSui<C>>,
    recipient: &Wallet<WalletSui<C>>,
) {
    // near-sdk example token: decimals 24, symbol "EXAMPLE".
    let wasm = fs::read(
        Path::new(env!("CARGO_MANIFEST_DIR")).join("../../../../releases/fungible-token.wasm"),
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
        .send()
        .wait_until::<Final>()
        .await
        .unwrap()
        .result()
        .unwrap();
    let transfer =
        NearPromise::new(token.clone()).function_call(ft_transfer(recipient.account_id()));
    let (msg, proof) = wallet.sign(transfer.clone()).await.unwrap();
    let message = request_signing_message(&wallet.public_key(), &msg).unwrap();

    assert!(
        message.contains(r#""amount": "1500000000000000000000000""#),
        "{message}"
    );

    let storage_before = near
        .account(wallet.account_id())
        .await
        .unwrap()
        .storage_usage;

    let outcome = execute(near, wallet, transfer).await;
    outcome.result().unwrap();

    assert_eq!(
        ft_balance(near, &token, recipient.account_id()).await,
        NearToken::from_millinear(1500).as_yoctonear().to_string()
    );

    let gas = outcome
        .receipts_outcome
        .iter()
        .map(|r| r.outcome.gas_burnt.as_gas())
        .fold(0_u64, u64::saturating_add);
    let storage_after = near
        .account(wallet.account_id())
        .await
        .unwrap()
        .storage_usage;

    eprintln!(
        "direct FT: message={} bytes, proof={} bytes, receipt gas={gas}, storage={storage_before}->{storage_after}",
        message.len(),
        proof.len()
    );

    check_ft_bootstrap(near, wallet, recipient, wasm).await;
}

/// A token is created, initialized and transferred in one promise.
async fn check_ft_bootstrap<C: SuiScheme>(
    near: &Near,
    wallet: &Wallet<WalletSui<C>>,
    recipient: &Wallet<WalletSui<C>>,
    wasm: Vec<u8>,
) {
    let ft_hash: [u8; 32] = Sha256::digest(&wasm).into();

    near.publish(wasm, PublishMode::Immutable)
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
    execute(near, wallet, bootstrap).await.result().unwrap();

    assert_eq!(
        ft_balance(near, &token, recipient.account_id()).await,
        NearToken::from_millinear(1500).as_yoctonear().to_string()
    );
}

/// A `StateInit` deposit settles only current storage; excess is refunded even
/// when a later initializing call needs more storage in the same promise.
async fn check_state_init_deposit<C: SuiScheme>(
    near: &Near,
    wallet: &Wallet<WalletSui<C>>,
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

/// `ft_transfer` of 1.5 tokens with 24 decimals to `receiver_id`.
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
    near.view(token, "ft_balance_of")
        .args(serde_json::json!({ "account_id": account_id }))
        .await
        .unwrap()
}

/// The key of the foreign scheme `F` in a leaf of the contract variant `C`.
///
/// The stored key has no flag: the other ECDSA key has the same length, so the
/// state is readable and the proof is refused; a key of another length leaves
/// a state that the variant cannot read at all.
async fn check_wrong_global_scheme<C, F, S>(near: &Near, code_hash: [u8; 32], signer: S)
where
    C: SuiScheme,
    F: SuiScheme,
    S: Signer<F> + Clone + 'static,
    S::Error: std::error::Error + Send + Sync + 'static,
{
    if C::FLAG == F::FLAG {
        return;
    }

    let expected = if size_of::<C::Key>() == size_of::<F::Key>() {
        "invalid signature"
    } else {
        "Cannot deserialize the contract state"
    };
    let signer = WalletSuiSigner::<F, _>::new(signer);
    let wallet = WalletBuilder::new()
        .subwallet_id(rand::random())
        .build(code_hash, signer.clone())
        .with_client(near.clone())
        .with_relayer(near.clone());

    near.transaction(wallet.account_id())
        .state_init(wallet.deterministic_state_init().clone(), NearToken::ZERO)
        .send()
        .wait_until::<Final>()
        .await
        .unwrap()
        .result()
        .unwrap();

    let before = near
        .account(wallet.account_id())
        .await
        .unwrap()
        .storage_usage;
    let (msg, proof) = wallet.sign(Request::new()).await.unwrap();

    assert!(WalletSui::<F>::verify_request_msg(
        &wallet.public_key(),
        &msg,
        &proof,
    ));

    let error = near
        .contract::<WalletContract>(wallet.account_id())
        .w_execute_signed((&msg, proof.as_str()).into())
        .gas(Gas::from_tgas(30))
        .await
        .unwrap()
        .result()
        .expect_err("another scheme cannot authorize this global contract");

    assert!(error.to_string().contains(expected), "{error:?}");
    assert_eq!(
        near.account(wallet.account_id())
            .await
            .unwrap()
            .storage_usage,
        before
    );

    let msg = OffchainMessage {
        chain_id: wallet.chain_id().clone(),
        signer_id: wallet.account_id().clone(),
        path: vec![],
        timestamp: Timestamp::now() - Duration::from_mins(1),
        payload: "wrong global scheme".to_owned(),
    };
    let proof = signer.sign_offchain_msg(&msg).await.unwrap();

    assert!(WalletSui::<F>::verify_offchain_msg(
        &wallet.public_key(),
        &msg,
        &proof,
    ));

    let authorization = String::from(WalletAuthorization::Signature { msg, proof });
    let resolver = RpcResolver::new(near.rpc().clone()).await.unwrap();
    let error = resolver
        .resolve_auth(wallet.account_id(), &authorization)
        .await
        .unwrap_err();

    assert!(format!("{error:?}").contains(expected), "{error:?}");
}

async fn check_nonce_rollback_and_replay<C: SuiScheme>(near: &Near, wallet: &Wallet<WalletSui<C>>) {
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

async fn check_lockout_and_rotation<C: SuiScheme>(
    near: &Near,
    wallet: Wallet<WalletSui<C>>,
    recipient: Wallet<WalletSui<C>>,
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

    // Installing another Sui wallet as an extension and rotating control works.
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

async fn check_oversized_offchain_rejection<C: SuiScheme, S: WalletSigner<WalletSui<C>>>(
    near: &Near,
    wallet: &Wallet<WalletSui<C>>,
    signer: &S,
) {
    let key = wallet.public_key();
    let resolver = RpcResolver::new(near.rpc().clone()).await.unwrap();
    let msg = OffchainMessage {
        chain_id: wallet.chain_id().clone(),
        signer_id: wallet.account_id().clone(),
        path: vec![],
        timestamp: Timestamp::now() - Duration::from_mins(1),
        payload: "render error control".to_owned(),
    };
    let proof = signer.sign_offchain_msg(&msg).await.unwrap();
    let authorization = String::from(WalletAuthorization::Signature {
        msg: msg.clone(),
        proof,
    });
    let resolved = resolver
        .resolve_auth(wallet.account_id(), &authorization)
        .await
        .unwrap();

    assert_eq!(resolved, msg.payload);

    let mut oversized = msg;
    oversized.payload = "a".repeat(MAX_SIGNING_MESSAGE_BYTES);

    assert!(matches!(
        offchain_signing_message(&key, &oversized),
        Err(MessageError::TooLarge)
    ));

    for proof in ["invalid".to_owned(), key.encode_signature(&[0; 64])] {
        let authorization = String::from(WalletAuthorization::Signature {
            msg: oversized.clone(),
            proof,
        });
        let error = resolver
            .resolve_auth(wallet.account_id(), &authorization)
            .await
            .expect_err("oversized offchain authorization must reject");
        assert!(
            matches!(
                &error.kind,
                ResolveErrorKind::Contract(ContractError::Panic(message))
                    if message == "invalid signature"
            ),
            "{error:?}"
        );
    }
}

/// Both failure paths must leave nonce storage untouched.
async fn check_oversized_request_rejection<C: SuiScheme>(
    near: &Near,
    wallet: &Wallet<WalletSui<C>>,
    oversized: &RequestMessage,
) -> (u64, FinalExecutionOutcome) {
    let contract = near.contract::<WalletContract>(wallet.account_id());
    let key = wallet.public_key();

    let before = near
        .account(wallet.account_id())
        .await
        .unwrap()
        .storage_usage;

    let error = contract
        .w_execute_signed((oversized, "invalid").into())
        .gas(Gas::from_tgas(80))
        .await
        .unwrap()
        .result()
        .expect_err("malformed proof must reject");

    assert!(error.to_string().contains("invalid signature"), "{error:?}");

    let invalid = key.encode_signature(&[0; 64]);
    let failed = contract
        .w_execute_signed((oversized, invalid.as_str()).into())
        .gas(Gas::from_tgas(80))
        .await
        .unwrap();

    let error = failed.result().expect_err("oversized display must reject");

    assert!(error.to_string().contains("invalid signature"), "{error:?}");
    assert!(!error.to_string().contains("panicked at"), "{error:?}");
    assert!(!error.to_string().contains("src/"), "{error:?}");

    assert_eq!(
        near.account(wallet.account_id())
            .await
            .unwrap()
            .storage_usage,
        before
    );

    (before, failed)
}

async fn check_resources_and_context<C: SuiScheme, S: WalletSigner<WalletSui<C>>>(
    near: &Near,
    wallet: &Wallet<WalletSui<C>>,
    recipient: &Wallet<WalletSui<C>>,
    scheme: u8,
    signer: &S,
) {
    let contract = near.contract::<WalletContract>(wallet.account_id());
    let (original, _) = wallet.sign(Request::new()).await.unwrap();

    entrypoints::context(near, wallet.account_id(), &original, signer).await;

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
    let key = wallet.public_key();
    let (mut low, mut high) = (0, MAX_SIGNING_MESSAGE_BYTES);

    while low + 1 < high {
        let middle = usize::midpoint(low, high);

        if request_signing_message(&key, &with_payload(middle)).is_ok() {
            low = middle;
        } else {
            high = middle;
        }
    }

    let (msg, oversized) = (with_payload(low), with_payload(high));
    let length = request_signing_message(&key, &msg).unwrap().len();

    // Each ASCII padding byte adds exactly one display byte.
    assert_eq!(length, MAX_SIGNING_MESSAGE_BYTES);
    assert!(matches!(
        request_signing_message(&key, &oversized),
        Err(MessageError::TooLarge)
    ));

    check_oversized_offchain_rejection(near, wallet, signer).await;

    let (before, failed) = check_oversized_request_rejection(near, wallet, &oversized).await;

    // The failed request committed this same nonce first; receipt rollback must free it.
    assert_eq!(msg.nonce, oversized.nonce);
    assert_eq!(msg.created_at, oversized.created_at);

    let proof = signer.sign_request_msg(&msg).await.unwrap();

    if scheme != 0 {
        check_high_s_rejected(near, wallet, &msg, &proof, scheme).await;
    }

    let result = contract
        .w_execute_signed((&msg, proof.as_str()).into())
        .gas(Gas::from_tgas(80))
        .await
        .unwrap();

    result.result().unwrap();

    let after = near
        .account(wallet.account_id())
        .await
        .unwrap()
        .storage_usage;

    println!(
        "SUI_RESOURCE_PROFILE {}",
        serde_json::json!({"scheme":scheme,"message_bytes":length,"proof_bytes":proof.len(),"gas":result.total_gas_used().as_gas(),"oversized_rejection_gas":failed.total_gas_used().as_gas(),"storage_before":before,"storage_after":after})
    );

    contract
        .w_execute_signed((&msg, proof.as_str()).into())
        .gas(Gas::from_tgas(40))
        .await
        .unwrap()
        .result()
        .expect_err("large-request replay");

    check_sparse_nonce_growth(near, wallet, scheme, &original, signer).await;
}

async fn check_high_s_rejected<C: SuiScheme>(
    near: &Near,
    wallet: &Wallet<WalletSui<C>>,
    msg: &RequestMessage,
    proof: &str,
    scheme: u8,
) {
    use base64::{Engine, engine::general_purpose::STANDARD};

    let contract = near.contract::<WalletContract>(wallet.account_id());
    let mut bytes = STANDARD.decode(proof).unwrap();

    macro_rules! high_s {
        ($curve:ident) => {{
            let signature = $curve::ecdsa::Signature::from_slice(&bytes[1..65]).unwrap();
            let (r, s) = signature.split_scalars();
            $curve::ecdsa::Signature::from_scalars(r.to_bytes(), (-s).to_bytes())
                .unwrap()
                .to_bytes()
        }};
    }

    let signature = match scheme {
        1 => high_s!(k256),
        2 => high_s!(p256),
        _ => unreachable!(),
    };

    bytes[1..65].copy_from_slice(&signature);

    let proof = STANDARD.encode(bytes);

    contract
        .w_execute_signed((msg, proof.as_str()).into())
        .gas(Gas::from_tgas(80))
        .await
        .unwrap()
        .result()
        .expect_err("high-S must fail in WASM");
}

async fn check_sparse_nonce_growth<C: SuiScheme, S: WalletSigner<WalletSui<C>>>(
    near: &Near,
    wallet: &Wallet<WalletSui<C>>,
    scheme: u8,
    original: &RequestMessage,
    signer: &S,
) {
    let contract = near.contract::<WalletContract>(wallet.account_id());
    let before = near
        .account(wallet.account_id())
        .await
        .unwrap()
        .storage_usage;
    let gas = Gas::from_tgas(40);

    for page in 1..=4 {
        let mut msg = original.clone();

        msg.nonce = original.nonce.wrapping_add(page << 10);
        msg.request = Request::new();

        let proof = signer.sign_request_msg(&msg).await.unwrap();

        contract
            .w_execute_signed((&msg, proof.as_str()).into())
            .gas(gas)
            .await
            .unwrap()
            .result()
            .unwrap();
    }

    let after = near
        .account(wallet.account_id())
        .await
        .unwrap()
        .storage_usage;

    assert!(after > before);

    println!(
        "SUI_NONCE_STORAGE {}",
        serde_json::json!({"scheme":scheme,"new_pages":4,"before":before,"after":after})
    );
}

async fn check_public_entrypoints<C: SuiScheme>(near: &Near, wallet: &Wallet<WalletSui<C>>) {
    let (msg, proof) = wallet
        .sign(WalletOp::add_extension(near.account_id().clone()))
        .await
        .unwrap();

    entrypoints::check(near, wallet.account_id(), &msg, &proof).await;

    // The later lockout check needs a wallet without extensions.
    execute(
        near,
        wallet,
        WalletOp::remove_extension(near.account_id().clone()),
    )
    .await;
}
