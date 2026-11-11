use defuse_crypto::{RecoverableSigner, secp256k1::Secp256k1};
use defuse_erc191::Erc191;
use defuse_wallet::{RequestMessage, offchain::OffchainMessage};
use defuse_wallet_sdk::{Proof, WalletSigner};

use crate::{
    EthAddress, EvmProof, MessageError, WalletEip191, offchain_signing_message,
    request_signing_message,
};

/// Signs the readable message with `personal_sign` using a secp256k1 key.
#[derive(Debug, Clone, Copy)]
pub struct WalletEip191Signer<S>(pub S);

/// Message rendering or signer failure.
#[derive(Debug, thiserror::Error)]
pub enum SignError<E> {
    #[error(transparent)]
    Message(#[from] MessageError),
    #[error("signer: {0}")]
    Signer(E),
}

impl<S: RecoverableSigner<Secp256k1>> WalletEip191Signer<S> {
    async fn sign(
        &self,
        message: Result<String, MessageError>,
    ) -> Result<Proof, SignError<S::Error>> {
        EvmProof::sign(&self.0, &Erc191::prehash(message?))
            .await
            .map_err(SignError::Signer)
    }
}

impl<S: RecoverableSigner<Secp256k1>> WalletSigner<WalletEip191> for WalletEip191Signer<S> {
    type Error = SignError<S::Error>;

    fn public_key(&self) -> EthAddress {
        EthAddress::from(&self.0.public_key())
    }

    async fn sign_request_msg(&self, msg: &RequestMessage) -> Result<Proof, Self::Error> {
        self.sign(request_signing_message(&self.public_key(), msg))
            .await
    }

    async fn sign_offchain_msg(&self, msg: &OffchainMessage) -> Result<Proof, Self::Error> {
        self.sign(offchain_signing_message(&self.public_key(), msg))
            .await
    }
}
