use defuse_wallet::{RequestMessage, offchain::OffchainMessage};
use defuse_wallet_evm_eip191::crypto::{RecoverableSigner, secp256k1::Secp256k1};
use defuse_wallet_sdk::{Proof, WalletSigner};

use crate::{
    Eip712Error, EthAddress, EvmProof, Hash, WalletEip712, offchain_digest, request_digest,
};

/// Signs EIP-712 typed data derived from the message using a secp256k1 key.
#[derive(Debug, Clone, Copy)]
pub struct WalletEip712Signer<S>(pub S);

/// Typed-data encoding or signer failure.
#[derive(Debug, thiserror::Error)]
pub enum SignError<E> {
    #[error(transparent)]
    Message(#[from] Eip712Error),
    #[error("signer: {0}")]
    Signer(E),
}

impl<S: RecoverableSigner<Secp256k1>> WalletEip712Signer<S> {
    async fn sign(&self, digest: Result<Hash, Eip712Error>) -> Result<Proof, SignError<S::Error>> {
        EvmProof::sign(&self.0, &digest?)
            .await
            .map_err(SignError::Signer)
    }
}

impl<S: RecoverableSigner<Secp256k1>> WalletSigner<WalletEip712> for WalletEip712Signer<S> {
    type Error = SignError<S::Error>;

    fn public_key(&self) -> EthAddress {
        EthAddress::from(&self.0.public_key())
    }

    async fn sign_request_msg(&self, msg: &RequestMessage) -> Result<Proof, Self::Error> {
        self.sign(request_digest(msg)).await
    }

    async fn sign_offchain_msg(&self, msg: &OffchainMessage) -> Result<Proof, Self::Error> {
        self.sign(offchain_digest(msg)).await
    }
}
