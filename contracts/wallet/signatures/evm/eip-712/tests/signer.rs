use defuse_wallet::{
    AccountId, NearPromise, Request, RequestMessage, SignatureSchema, WalletOp,
    actions::FunctionCall, offchain::OffchainMessage,
};
use defuse_wallet_evm_eip712::{
    Eip712Error, SignError, WalletEip712, WalletEip712Signer,
    crypto::{
        RecoverableSigner, Signer,
        secp256k1::{
            Secp256k1,
            k256::ecdsa::{RecoveryId, Signature, SigningKey, VerifyingKey},
        },
    },
};
use defuse_wallet_sdk::{GlobalContractId, Wallet, WalletSigner};
use hex_literal::hex;

const CODE: GlobalContractId = GlobalContractId::CodeHash([0; 32]);

fn signer() -> WalletEip712Signer<SigningKey> {
    WalletEip712Signer(
        SigningKey::from_bytes(
            &hex!("4c0883a69102937d6231471b5dbb6204fe5129617082792ae468d01a3f362318").into(),
        )
        .unwrap(),
    )
}

#[tokio::test]
async fn signer_proofs_verify_for_both_paths() {
    let wallet = Wallet::<WalletEip712>::new(CODE, signer());
    assert_eq!(
        wallet.public_key().to_string(),
        "0x2c7536e3605d9c16a7a3d7b1898e529396a65c23"
    );
    let (msg, proof) = wallet
        .sign(
            Request::new()
                .internal([WalletOp::add_extension(
                    "recovery.near".parse::<AccountId>().unwrap(),
                )])
                .external([NearPromise::new("bob.near".parse::<AccountId>().unwrap())
                    .function_call(FunctionCall::name("submit").args(b"{\"a\":1}"))]),
        )
        .await
        .unwrap();
    assert!(WalletEip712::verify_request_msg(
        &wallet.public_key(),
        &msg,
        &proof
    ));

    let auth = OffchainMessage {
        chain_id: msg.chain_id.clone(),
        signer_id: msg.signer_id.clone(),
        path: Vec::new(),
        timestamp: msg.created_at,
        payload: "Authorization, not a login".to_string(),
    };
    let proof = signer().sign_offchain_msg(&auth).await.unwrap();
    assert!(WalletEip712::verify_offchain_msg(
        &wallet.public_key(),
        &auth,
        &proof
    ));
    assert!(!WalletEip712::verify_request_msg(
        &wallet.public_key(),
        &msg,
        &proof
    ));
}

/// The signer refuses what the typed data cannot show safely.
#[tokio::test]
async fn signer_refuses_unsupported_requests() {
    let wallet = Wallet::<WalletEip712>::new(CODE, signer());
    let (msg, _) = wallet.sign(Request::new()).await.unwrap();
    let call = |name: &str, args: &[u8]| RequestMessage {
        request: NearPromise::new("bob.near".parse::<AccountId>().unwrap())
            .function_call(FunctionCall::name(name).args(args))
            .into(),
        ..msg.clone()
    };
    for (msg, unsupported) in [
        (call("w_execute_extension", br#"{"request":{}}"#), true),
        (call("submit", "{\"memo\":\"Привет\"}".as_bytes()), false),
        (call("submit", b"\x00\xff"), false),
    ] {
        let error = signer().sign_request_msg(&msg).await.unwrap_err();
        assert!(
            if unsupported {
                matches!(error, SignError::Message(Eip712Error::Unsupported))
            } else {
                matches!(error, SignError::Message(Eip712Error::FunctionArgs))
            },
            "{error:?}"
        );
    }
}

/// Returns the high-S form of each signature, which `RecoverableSigner` allows.
struct HighS(SigningKey);

impl Signer<Secp256k1> for HighS {
    type Error = <SigningKey as Signer<Secp256k1>>::Error;

    fn public_key(&self) -> VerifyingKey {
        Signer::<Secp256k1>::public_key(&self.0)
    }

    async fn sign(&self, msg: &[u8]) -> Result<Signature, Self::Error> {
        Ok(self.sign_recoverable(msg).await?.0)
    }
}

impl RecoverableSigner<Secp256k1> for HighS {
    async fn sign_recoverable(&self, msg: &[u8]) -> Result<(Signature, RecoveryId), Self::Error> {
        let (signature, recovery_id) =
            RecoverableSigner::<Secp256k1>::sign_recoverable(&self.0, msg).await?;
        let (r, s) = signature.split_scalars();
        let high_s = Signature::from_scalars(r, -s).unwrap();
        assert_ne!(high_s, signature);
        Ok((
            high_s,
            RecoveryId::new(!recovery_id.is_y_odd(), recovery_id.is_x_reduced()),
        ))
    }
}

/// A high-S signature from the signer is encoded as the equivalent low-S proof.
#[tokio::test]
async fn signer_normalizes_high_s_signatures() {
    let wallet = Wallet::<WalletEip712>::new(CODE, WalletEip712Signer(HighS(signer().0)));
    let (msg, proof) = wallet.sign(Request::new()).await.unwrap();
    assert!(WalletEip712::verify_request_msg(
        &wallet.public_key(),
        &msg,
        &proof
    ));
    assert_eq!(proof, signer().sign_request_msg(&msg).await.unwrap());
}
