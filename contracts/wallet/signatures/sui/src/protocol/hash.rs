//! BLAKE2b-256 with its native 32-byte output parameter (not truncated BLAKE2b-512).
//! Uses the vetted `RustCrypto` backend on both NEAR/WASM and native targets.

/// Hash bytes using `BLAKE2b` with a 32-byte output parameter.
pub(super) fn blake2b256(data: impl AsRef<[u8]>) -> [u8; 32] {
    use ::blake2::{Blake2b, Digest, digest::consts::U32};
    Blake2b::<U32>::digest(data).into()
}
