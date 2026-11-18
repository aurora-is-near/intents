# Solana wallet contract

NEAR wallet contract controlled by a **Solana Ed25519 account**. The account
signs the [readable signing format](../readable/README.md#format-v1) with the
wallet's `signMessage(bytes, "utf8")` API, which
[shows the UTF-8 text](https://docs.phantom.com/solana/signing-a-message) in
its prompt, so the user reads the same text that the contract rebuilds and
verifies. It is a separate variant from the digest-signing Ed25519 one and
uses neither Sign-In-With-Solana nor transaction signing.

## Identity and proof

- The wallet state stores the 32-byte Ed25519 public key; `w_public_key()`
  returns `ed25519:<base58>`. Weak (small-order) keys never verify.
- The signed text has one identity field after `signer_id`:
  `solana_public_key`, the raw base58 key as the Solana wallet reports it.
- The signature covers the text bytes as they are: no prefix, prehash, BOM or
  line-ending conversion.
- The proof is `ed25519:<base58 of the 64-byte signature>`.
- Proofs of execution requests, of NEP-641 authorizations and of the
  digest-signing variant are not interchangeable.

Before showing the derived account as a deposit destination,
[verify control](../readable/README.md#verify-control-before-funding) of the
key.

## Limitations

- The limits of the text are listed with the
  [format](../readable/README.md#format-v1).
- The display is confirmed for Phantom for Chrome. Other Solana wallets and
  hardware wallets are unverified.

## Build

```sh
make defuse-wallet-solana
```
