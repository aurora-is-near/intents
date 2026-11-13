# Sui wallet contract

NEAR wallet contracts controlled by a **Sui account**. The account signs the
[readable signing format](../../README.md#readable-signing-format-v1) as a
native Sui personal message (Wallet Standard `sui:signPersonalMessage`), which
wallets show as text. The signature authorizes NEAR wallet operations, not Sui
transactions.

There are three contract variants, one per signature scheme: `ed25519/`,
`secp256k1/` and `p256/` (Sui `Secp256r1`). Each instantiates
`WalletSui<Algorithm>` and accepts only keys and proofs of its scheme; the
parent `defuse-wallet-sui` crate is a library. Each variant is its own global
contract, so the same key has a different wallet account in each.

## Identity

- Only direct key-derived Sui accounts are supported: flag 0 (Ed25519),
  1 (secp256k1) and 2 (secp256r1). Multisig, zkLogin, passkey, ML-DSA-65
  (flag 7) and other account authorities are rejected.
- The public key is 32 bytes for Ed25519 and a 33-byte compressed SEC1 point
  (tag `0x02` or `0x03`) for ECDSA. `w_public_key()` returns
  `sui:<base64(flag || public_key)>`; the wallet state stores
  `flag || public_key`.
- The signed text has two identity fields after `signer_id`: `sui_public_key`
  (base64 of `flag || public_key`) and `sui_address` (`0x` and the lowercase
  hex BLAKE2b-256 of `flag || public_key`).

Before showing the derived account as a deposit destination,
[verify control](../../README.md#verify-control-before-funding) of the key.

## Signature and proof

- The digest is BLAKE2b-256 of the intent `[3, 0, 0]` (`PersonalMessage`, V0,
  Sui) followed by the BCS `vector<u8>` of the text: its ULEB128 length and its
  bytes.
- Ed25519 signs the digest. secp256k1 and secp256r1 sign SHA-256 of the digest
  with ECDSA; signatures must be low-S.
- The proof is padded base64 of `flag || signature || public_key` with a
  64-byte signature: always 132 characters.
- Verification rejects other lengths, non-canonical base64, other flags, a key
  different from the stored one, invalid points, weak Ed25519 keys and high-S
  signatures. A rejected proof is never retried under another scheme.
- Ed25519 verification uses the NEAR host function, not ZIP-215 rules, so
  exceptional encodings that Sui accepts may be rejected.

The two text prefixes separate execution requests from NEP-641 authorizations,
and the `PersonalMessage` intent separates both from Sui transactions.

## Clear signing

The user reads in the wallet prompt the same text that the contract rebuilds
and verifies. What that text does not decode is listed with the
[format](../../README.md#readable-signing-format-v1).

Slush with a direct Ed25519 account signed five messages of this format (token
transfers, state init, a NEP-641 authorization, a nested `w_execute_extension`
request and a 16 KiB message); they are in `tests/fixtures/slush.json` with
the text copied from each prompt. The prompt shows the whole text, warnings
first. secp256k1 and secp256r1 accounts, other wallets, mobile and hardware
wallets are unverified.

## Build and test

```sh
make defuse-wallet-sui-ed25519 defuse-wallet-sui-secp256k1 defuse-wallet-sui-p256
cargo test -p defuse-wallet-sui --all-features
```

Build each variant on its own, as the `make` targets do: one `cargo build` of
several variants links all their verifiers into each WASM, which changes the
code hash and therefore every derived wallet account. The P-256 variant needs
the `p256_verify` host function.

`WalletSuiSigner::<Ed25519, _>::new(signer)` implements both SDK signing
paths; use `Secp256k1` or `P256` for the other schemes. The vectors in
`tests/fixtures/sui.json` are signed with the official `@mysten/sui` 2.39.0
SDK from a public test seed stored in the fixture; the Rust signers reproduce
its proofs byte for byte.

## References

- [Sui intent signing](https://www.docs.sui.io/develop/transactions/transaction-auth/intent-signing)
- [Sui authentication and signature requirements](https://www.docs.sui.io/develop/transactions/transaction-auth/auth-overview)
- [Official SDK cryptography](https://sdk.mystenlabs.com/sui/cryptography)
- [Wallet Standard personal messages](https://github.com/MystenLabs/ts-sdks/blob/main/packages/wallet-standard/src/features/suiSignPersonalMessage.ts)
