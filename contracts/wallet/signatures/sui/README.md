# Sui wallet contract

Wallet contract variants authorized by native Sui personal-message signatures.
There are three separate wallet/global-contract variants: `ed25519/`,
`secp256k1/` and `p256/` (Sui `Secp256r1`). Each instantiates
`WalletSui<Algorithm>` with one fixed scheme; the parent `defuse-wallet-sui`
crate is a library and does not build a contract. The signatures authorize NEAR
wallet operations, not Sui transactions.

Each variant has its own global contract ID, which participates in NEP-616
address derivation together with the signing key and the initial wallet state.

## Signing format (v1)

### Identity

- Only direct key-derived Sui identities are supported: flag 0 (Ed25519),
  1 (secp256k1) and 2 (secp256r1). Multisig, zkLogin, passkey, address aliases
  and other account-authority mechanisms are rejected.
- The public key is 32 bytes for Ed25519 and a 33-byte compressed SEC1 point for
  ECDSA. Its string form is `sui:<base64(flag || public_key)>`, and its Borsh
  form in the wallet state is `flag || public_key`.
- The Sui address is `0x` followed by the lowercase hex BLAKE2b-256 of
  `flag || public_key`.
- Each contract variant accepts only keys and proofs of its own scheme.

### Signed message

The contract reconstructs the message from the parsed request and the stored
key; no dApp-provided text, digest or address is trusted. The message is
the purpose header (`REQUEST_PREFIX` for `w_execute_signed()`, `OFFCHAIN_PREFIX`
for NEP-641 authorizations) followed by a JSON document and a trailing LF:

- The JSON contains every field of `RequestMessage` or `OffchainMessage`, plus
  `sui_public_key` (base64 of `flag || public_key`) and `sui_address`.
- Defaults are explicit: `pay_for_gas` is `false`, an absent `refund_to` is
  `null`, absent deposits and gas are `"0"`, and the default `gas_weight` is
  `"1"`.
- Each request action is rendered as `transfer` (`amount`), `function_call`
  (`function_name`, `args`, `deposit`, `gas`, `gas_weight`) or
  `deterministic_state_init` (`state_init`, `deposit`). Any other action is
  rejected.
- NEAR amounts and deposits are shown with 24 decimals and the `NEAR` symbol,
  for example `1.5 NEAR` or `0.000000000000000000000001 NEAR`: the decimal point
  is inserted into the yoctoNEAR value and trailing fractional zeros are
  removed.
- `args` shows the call arguments once, as JSON in their original key order.
  The arguments must be exactly the compact serialization of that JSON, the
  same in `serde_json::to_vec` and `JSON.stringify`: no insignificant
  whitespace, duplicate keys, optional escapes or alternative number forms.
  Numbers must be integers within ±(2^53 - 1); pass larger or fractional
  values as strings, as NEAR standards do. Strings must not contain unpaired
  surrogates, and integer keys (`"0"` to `"4294967294"`) must come first in
  ascending order, as in JavaScript objects. Other arguments, including empty,
  binary and BOM-prefixed ones, are rejected; call a method without parameters
  with `{}`. The message therefore determines the exact argument bytes.
- NEP-141 transfers (`ft_transfer`, `ft_transfer_call`) require one
  `require_ft_metadata` operation for the receiver token in the same request;
  otherwise the request is rejected. The contract rejects a checked promise if
  the sum of its call weights exceeds `u64::MAX`. Their `args.amount` must be a
  decimal `u128` string without leading zeros and is shown with the operation's
  `decimals` and `symbol` in the same way, for example `1.5 USDC`. The wallet
  creates promises to that token only after its `ft_metadata()` returns exactly
  these values (see [token metadata checks](../../README.md#token-metadata-checks)).
  Its arguments may be only the method's parameters (`receiver_id`, `amount`,
  `memo`, and `msg` for `ft_transfer_call`): keys the token ignores could
  imitate a shown amount.
- `StateInit.deposit` is a refundable budget for storage at that action, not
  funding for later calls; see [`StateInit` storage deposit and funding](../../README.md#stateinit-storage-deposit-and-funding).
- `nonce`, `timeout_secs` and `decimals` are JSON numbers; gas and
  `gas_weight` are decimal strings.
- Timestamps use RFC 3339 in UTC with a `Z` suffix. Fractional seconds keep up
  to nine digits with trailing zeros removed, and are omitted when zero, for
  example `2026-11-03T12:34:56.12Z`. They must fit unsigned 64-bit Unix
  nanoseconds; `timeout_secs` must fit `u32`.
- Fields have a fixed order: `chain_id`, `signer_id`, `sui_public_key`,
  `sui_address`, then `nonce`, `created_at`, `timeout_secs`, `pay_for_gas` and
  `request`, which lists `internal` wallet operations before `external`
  promises; a promise shows `receiver_id` and `refund_to` before its actions,
  and a call shows its method, deposit, gas and gas weight before `args`. Only
  state init is shown with sorted keys; arrays keep their order. The document
  is indented with two spaces, with `": "` after keys.
- Each `add_extension` adds `WARNING: add_extension gives <account> full
  control of this wallet.` before the JSON. Each promise whose
  attached NEAR (transfers and deposits) can be refunded to an account other
  than the executing wallet adds `WARNING: up to <amount> sent to <receiver>
  can be refunded to <refund_to>, not to this wallet.`
- A call of another wallet's `w_execute_extension` (this wallet as its
  extension) shows its `request` by the same rules, including warnings that
  name that wallet and metadata requirements for its token transfers.
  The arguments must be exactly the serde form of that request (the
  contract's field order, defaults omitted), so the message determines them;
  there `refund_to` `null` means the wallet that executes the request, and
  state-init keys must have the same order as bytes and as JavaScript object
  keys (array indices first).
- Before rendering, raw function-call arguments (a nested request with its
  base64 encoding), state data, token symbols and 64 bytes per operation,
  promise and action must fit 16 KiB; JSON arguments nest at most 127 levels.
  Fields that the contract does not define and duplicate state keys are
  rejected.
- Every UTF-16 code unit from U+007F upward is escaped as lowercase `\uXXXX`,
  so the message is ASCII. This includes bidi controls and line separators.
- The NEP-641 payload is never parsed or normalized. Call arguments are
  parsed only for display and are never normalized.

The complete message must not exceed 16 KiB (16384 bytes). A request with one
function call needs about 1.1 KB for fixed fields. An ASCII argument byte takes
one message byte, each displayed member adds a line break and two spaces per
nesting level, and each non-ASCII UTF-16 unit takes six bytes. One request
fits about 15 KB of flat ASCII JSON arguments.

### Native signature and proof

- The digest is BLAKE2b-256 of intent `[3, 0, 0]` (`PersonalMessage`, V0, Sui)
  followed by BCS `vector<u8>` of the message: a canonical ULEB128 length and
  the message bytes.
- Ed25519 signs the digest. secp256k1 and secp256r1 sign SHA-256 of the digest
  with ECDSA; signatures must be low-S.
- The proof is canonical padded base64 of `flag || signature || public_key`
  with a 64-byte signature, which is always 132 characters.
- Verification rejects other lengths, non-canonical base64, other flags, a
  public key different from the stored one, invalid points, weak Ed25519 keys,
  high-S ECDSA signatures and invalid signatures. A rejected proof is never
  retried under another scheme.
- Ed25519 verification uses the NEAR host function rather than ZIP-215 rules,
  so exceptional encodings that Sui accepts may be rejected.

### Domain separation

The two purpose headers separate execution requests from NEP-641
authorizations, and intent scope `PersonalMessage` separates both from Sui
transactions. The wallet core enforces the network, the wallet account, the
nonce and the validity interval of execution requests. NEP-641 one-time use and
expiration remain the consuming protocol's responsibility.

## Display and clear-signing status

Wallets receive the complete message bytes through Wallet Standard
`sui:signPersonalMessage`. Direct fields, including native transfers, deposits,
receivers, refund targets, extension changes, network, wallet account and
validity, appear as named JSON fields. NEAR amounts have decimals and the
`NEAR` symbol, NEP-141 transfer amounts have the decimals and symbol checked
against the token's metadata, and gas is in gas units.

Other function-call arguments are shown as JSON fields with their raw values.
The format does not decode them further:

- JSON nested inside a string value, such as `msg` of `ft_transfer_call`,
  remains an escaped string.
- Amounts in arguments of other methods, for example NEP-245 `mt_transfer`, are
  in base units without decimals and symbol.
- Non-ASCII text is shown as `\uXXXX` escapes.
- `deterministic_state_init` data is shown as base64 keys and values.

These parts are not clear-signed. Warning lines, amounts outside `args` and NEP-141 transfer
amounts are written by the contract; other text inside `args` comes from the
dApp and may imitate them. A displayed call also
says nothing about the called contract's behavior. The token symbol comes from the token contract's
own metadata, so it identifies the token only together with the receiver
account.

Slush (version not recorded) with a direct Ed25519 account signed all five
display-check messages of the current format: execution effects with token
transfers, state init, offchain, a nested `w_execute_extension` request and
the 16 KiB message. They are in `tests/fixtures/slush.json` with the text
copied from each prompt: after the page name, the origin and the shortened
signing address, it shows the whole signed message, warnings first. The
contract accepts every signature. Secp256k1 and P-256 accounts, other
wallets, mobile and hardware wallets are unverified.

## Trust boundaries

The dApp, relayer, RPC and third-party contracts are untrusted. Enabled
extensions retain full control of the wallet. Global contracts referenced by
an immutable code hash and by an updatable account ID have different update
authorities. Asynchronous promises can partially succeed.

## Test vectors

`tests/fixtures/sui.json` was generated with the official `@mysten/sui` 2.39.0
SDK (`signPersonalMessage`) from a deliberately public deterministic test seed
(`0x01..0x20`, also stored in the fixture). It covers all three schemes and
both purposes, including call arguments with unsorted keys and a nested JSON
string and NEP-141 transfers with required token metadata, and includes high-S and Sui-transaction-intent proofs for negative
tests. The Rust signers reproduce the SDK proofs byte for byte.

## Build and test

```sh
make defuse-wallet-sui-ed25519 defuse-wallet-sui-secp256k1 defuse-wallet-sui-p256
cargo test -p defuse-wallet-sui --all-features --locked
```

Sandbox tests use the standard Docker-backed NEAR sandbox and the contract
artifacts in `res/`.

Build each variant on its own, as the `make` targets do: one `cargo build` of
several variants links all their verifiers into each WASM, which changes the
code hash and therefore every derived wallet account. The P-256 variant needs
the `p256_verify` host function (NEAR protocol version 85 or later).

`WalletSuiSigner::<Ed25519, _>::new(signer)` adapts a shared crypto signer to
both SDK signing paths; use `Secp256k1` or `P256` for the other schemes.

## References

- [Sui intent signing](https://www.docs.sui.io/develop/transactions/transaction-auth/intent-signing)
- [Sui authentication and signature requirements](https://www.docs.sui.io/develop/transactions/transaction-auth/auth-overview)
- [Official SDK cryptography](https://sdk.mystenlabs.com/sui/cryptography)
- [Wallet Standard personal messages](https://github.com/MystenLabs/ts-sdks/blob/main/packages/wallet-standard/src/features/suiSignPersonalMessage.ts)

