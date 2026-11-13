# Solana wallet contract

NEAR wallet contract controlled by a **Solana Ed25519 account**. The account
signs the [readable signing format](../../README.md#readable-signing-format-v1)
with the wallet's `signMessage(bytes, "utf8")` API, e.g. Phantom's
`window.phantom.solana.signMessage`, which
[shows the UTF-8 text](https://docs.phantom.com/solana/signing-a-message) in
its prompt. It is a separate variant from the digest-signing Ed25519 one and
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
[verify control](../../README.md#verify-control-before-funding) of the key.

## Clear signing

The user reads in the wallet prompt the same text that the contract rebuilds
and verifies. What that text does not decode is listed with the
[format](../../README.md#readable-signing-format-v1).

Phantom for Chrome signed four messages of this format, up to 4,200 bytes
(token transfers, state init, a NEP-641 authorization and a nested
`w_execute_extension` request); they are in
`tests/fixtures/phantom-extension.json`. Phantom does not allow copying its
prompt, so the display is recorded only as the signer's attestation that each
message was readable in full.

Limitations:

- Phantom refused a 16 KiB message without opening a prompt ("You cannot sign
  solana transactions using sign message"). Its bytes also deserialize as a
  Solana transaction, which the signed messages do not. Messages well below
  16 KiB may therefore be refused; the exact rule is unverified.
- Mobile Phantom, other Solana wallets and hardware wallets are unverified.

## Build and test

```sh
make defuse-wallet-solana
cargo test -p defuse-wallet-solana --all-features
```

`WalletSolanaSigner` implements both SDK signing paths. The vectors in
`tests/fixtures/solana.json` are signed with Node.js `crypto` (OpenSSL) from
the public RFC 8032 test key.

Sandbox tests use the Docker-backed NEAR sandbox. `SOLANA_SANDBOX_RPC_URL`
points them to an already running local sandbox instead
(`http://localhost:<port>` or `http://127.0.0.1:<port>` only).
