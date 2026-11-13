use std::marker::PhantomData;

use crate::protocol::{SuiPublicKey, SuiScheme, crypto::Signer, personal_message_digest};
use defuse_wallet::{RequestMessage, offchain::OffchainMessage};
use defuse_wallet_sdk::{Proof, WalletSigner};

use crate::{MessageError, WalletSui, offchain_signing_message, request_signing_message};

/// Adapt an existing crypto signer to native Sui personal-message authorization.
pub struct WalletSuiSigner<C, S> {
    signer: S,
    curve: PhantomData<C>,
}

impl<C, S> WalletSuiSigner<C, S> {
    pub const fn new(signer: S) -> Self {
        Self {
            signer,
            curve: PhantomData,
        }
    }
}

impl<C, S: Clone> Clone for WalletSuiSigner<C, S> {
    fn clone(&self) -> Self {
        Self::new(self.signer.clone())
    }
}

/// Rendering or underlying signer failure.
#[derive(Debug, thiserror::Error)]
pub enum SignError<E> {
    #[error(transparent)]
    Message(#[from] MessageError),
    #[error("signer: {0}")]
    Signer(E),
}

impl<C: SuiScheme, S: Signer<C>> WalletSuiSigner<C, S> {
    async fn sign_message(&self, message: String) -> Result<Proof, SignError<S::Error>> {
        let digest = personal_message_digest(message.as_bytes()).ok_or(MessageError::TooLarge)?;
        let public_key = C::sui_public_key(self.signer.public_key());
        let signature = self
            .signer
            .sign(&C::signing_digest(digest))
            .await
            .map_err(SignError::Signer)?;
        Ok(public_key.encode_signature(&C::signature_bytes(signature)))
    }
}

impl<C: SuiScheme, S: Signer<C>> WalletSigner<WalletSui<C>> for WalletSuiSigner<C, S> {
    type Error = SignError<S::Error>;

    fn public_key(&self) -> SuiPublicKey {
        C::sui_public_key(self.signer.public_key())
    }

    async fn sign_request_msg(&self, msg: &RequestMessage) -> Result<Proof, Self::Error> {
        self.sign_message(request_signing_message(&self.public_key(), msg)?)
            .await
    }

    async fn sign_offchain_msg(&self, msg: &OffchainMessage) -> Result<Proof, Self::Error> {
        self.sign_message(offchain_signing_message(&self.public_key(), msg)?)
            .await
    }
}
