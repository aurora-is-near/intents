use defuse_wallet::{
    AccountId, NearPromise, Request, SignatureSchema, WalletOp, actions::FunctionCall,
};
use defuse_wallet_evm_eip191::{
    EthAddress, MessageError, SignError, WalletEip191, WalletEip191Signer,
    crypto::{
        RecoverableSigner, Signer,
        secp256k1::{
            Secp256k1,
            k256::ecdsa::{RecoveryId, Signature, SigningKey, VerifyingKey},
        },
    },
    request_signing_message,
};
use defuse_wallet_sdk::{GlobalContractId, State, StateInit, StateInitV1, Wallet, WalletSigner};
use hex_literal::hex;

const CODE: GlobalContractId = GlobalContractId::CodeHash(hex!(
    "0000000000000000000000000000000000000000000000000000000000000000"
));

fn signer() -> WalletEip191Signer<SigningKey> {
    WalletEip191Signer(
        SigningKey::from_bytes(
            &hex!("4c0883a69102937d6231471b5dbb6204fe5129617082792ae468d01a3f362318").into(),
        )
        .unwrap(),
    )
}

#[tokio::test]
async fn signer_proofs_verify_for_both_paths() {
    let wallet = Wallet::<WalletEip191>::new(CODE, signer());
    // `w_public_key()` shows the address as lowercase `0x` hex.
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
    assert!(WalletEip191::verify_request_msg(
        &wallet.public_key(),
        &msg,
        &proof
    ));
    let message = request_signing_message(&wallet.public_key(), &msg).unwrap();
    assert!(message.contains(r#""evm_address": "0x2c7536e3605d9c16a7a3d7b1898e529396a65c23""#));
    assert!(message.contains(r#""account_id": "recovery.near""#));
    assert!(message.contains("\"a\": 1"));

    let auth = defuse_wallet::offchain::OffchainMessage {
        chain_id: msg.chain_id.clone(),
        signer_id: msg.signer_id.clone(),
        path: Vec::new(),
        timestamp: msg.created_at,
        payload: "Login to nothing: this is an authorization".to_string(),
    };
    let proof = signer().sign_offchain_msg(&auth).await.unwrap();
    assert!(WalletEip191::verify_offchain_msg(
        &wallet.public_key(),
        &auth,
        &proof
    ));
    assert!(!WalletEip191::verify_request_msg(
        &wallet.public_key(),
        &msg,
        &proof
    ));
}

/// The signer refuses what the readable format cannot show.
#[tokio::test]
async fn signer_refuses_unreadable_requests() {
    let wallet = Wallet::<WalletEip191>::new(CODE, signer());
    let token = "token.near".parse::<AccountId>().unwrap();
    let call = |name: &str, args: &[u8]| {
        Request::from(
            NearPromise::new(token.clone()).function_call(FunctionCall::name(name).args(args)),
        )
    };
    let (msg, _) = wallet.sign(Request::new()).await.unwrap();
    for (request, token_metadata) in [
        // a NEP-141 amount cannot be shown without the token's metadata
        (
            call("ft_transfer", br#"{"receiver_id":"bob.near","amount":"1"}"#),
            true,
        ),
        // binary and non-canonical (duplicate key) arguments cannot be shown exactly
        (call("submit", b"\x00\xff"), false),
        (call("submit", br#"{"a":1,"a":2}"#), false),
    ] {
        let msg = defuse_wallet::RequestMessage {
            request,
            ..msg.clone()
        };
        let error = signer().sign_request_msg(&msg).await.unwrap_err();
        assert!(
            if token_metadata {
                matches!(error, SignError::Message(MessageError::TokenMetadata))
            } else {
                matches!(error, SignError::Message(MessageError::FunctionArgs))
            },
            "{error:?}"
        );
    }
}

/// The NEAR `AccountId` of a wallet-contract instance is derived from its
/// initial state, which holds the signer's *address*: a client that only did
/// `eth_requestAccounts` (no signing ceremony) already knows its account.
#[test]
fn account_id_derivable_from_address_alone() {
    let address: EthAddress = "0x2c7536e3605d9c16a7a3d7b1898e529396a65c23"
        .parse()
        .unwrap();
    let derived = StateInit::V1(StateInitV1 {
        code: CODE,
        data: State::new(address).as_storage(),
    })
    .derive_account_id();
    assert_eq!(
        derived,
        *Wallet::<WalletEip191>::new(CODE, signer()).account_id()
    );
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
    let wallet = Wallet::<WalletEip191>::new(CODE, WalletEip191Signer(HighS(signer().0)));
    let (msg, proof) = wallet.sign(Request::new()).await.unwrap();
    assert!(WalletEip191::verify_request_msg(
        &wallet.public_key(),
        &msg,
        &proof
    ));
    assert_eq!(proof, signer().sign_request_msg(&msg).await.unwrap());
}

/// Frozen vectors computed outside this repository: `0s` and the last 20
/// bytes of `keccak256(borsh(StateInit))`. A change of the stored identity or
/// of the state layout changes every wallet address.
#[test]
fn derived_accounts_match_known_answers() {
    use std::time::Duration;
    let address: EthAddress = "0xd8da6bf26964af9d7eed9e03e53415d37aa96045"
        .parse()
        .unwrap();
    for (subwallet_id, timeout, expected) in [
        (0, 3600, "0s007ef5585c4ebc3d4c9b1a3f5e96c5aab644e13e"),
        (1, 3600, "0sc5b1f5988d922aa84e66bcd3d1d2b004312e64f7"),
        (0, 300, "0sfdbe3527cb209ad3ded2f02bc8c866b004e21ae9"),
    ] {
        let state = State::new(address)
            .subwallet_id(subwallet_id)
            .timeout(Duration::from_secs(timeout));
        let account = StateInit::V1(StateInitV1 {
            code: GlobalContractId::CodeHash([0; 32]),
            data: state.as_storage(),
        })
        .derive_account_id();
        assert_eq!(account.as_str(), expected);
    }
}
