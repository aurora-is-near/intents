use core::str::FromStr;

use defuse_crypto::{
    RecoverableCurve,
    secp256k1::{
        Secp256k1, Secp256k1RecoverableSignature,
        k256::ecdsa::{RecoveryId, Signature},
    },
};

use crate::EthAddress;

/// Proof of EVM wallet variants: `secp256k1:<base58 of r || s || v>`.
///
/// `v` is the recovery id `0` or `1` (wallets return `27`/`28`). High-S
/// signatures are rejected, as in Ethereum transactions (EIP-2).
#[derive(Debug, Clone, Copy)]
pub struct EvmProof {
    signature: Signature,
    recovery_id: RecoveryId,
}

impl EvmProof {
    /// `secp256k1:` and base58 of 65 bytes.
    pub const MAX_LEN: usize = 100;

    /// Strict parse; `None` for any other encoding or recovery id.
    pub fn parse(proof: &str) -> Option<Self> {
        if proof.len() > Self::MAX_LEN || !proof.starts_with("secp256k1:") {
            return None;
        }
        let (signature, recovery_id) = <(Signature, RecoveryId)>::try_from(
            &Secp256k1RecoverableSignature::from_str(proof).ok()?,
        )
        .ok()?;
        (!recovery_id.is_x_reduced()).then_some(Self {
            signature,
            recovery_id,
        })
    }

    /// Address of the key that signed `prehash`, if the signature is valid and low-S.
    pub fn signer(&self, prehash: &[u8; 32]) -> Option<EthAddress> {
        Secp256k1::recover(prehash, &self.signature, self.recovery_id)
            .map(|public_key| EthAddress::from(&public_key))
    }

    /// Sign `prehash` and encode the proof.
    #[cfg(feature = "signer")]
    pub async fn sign<S>(signer: &S, prehash: &[u8; 32]) -> Result<String, S::Error>
    where
        S: defuse_crypto::RecoverableSigner<Secp256k1>,
    {
        let signature = signer.sign_recoverable(prehash).await?;
        Ok(Secp256k1RecoverableSignature::from(signature).to_string())
    }
}
