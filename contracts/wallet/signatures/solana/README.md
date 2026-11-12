# Solana wallet contract

NEAR wallet contract controlled by a **Solana Ed25519 account** using the wallet
`signMessage(bytes, "utf8")` API, such as Phantom's
`window.phantom.solana.signMessage(bytes, "utf8")` (see below for what Phantom
for Chrome signed and refused). It uses the shared wallet core,
including deterministic accounts, extensions, timeout nonces and NEP-641.
It does not use Phantom EVM signing, SIWS login, or the digest-only Ed25519 variant.

## Signing format v1

Sign the entire output of `request_signing_message` or `offchain_signing_message`,
including the purpose-specific prefix, two-space pretty-printed JSON and final LF.
Fields have a fixed order: `chain_id`, `signer_id`, the identity fields, then
`nonce`, `created_at`, `timeout_secs`, `pay_for_gas` and `request`, which lists
`internal` wallet operations before `external` promises; a promise shows
`receiver_id` and `refund_to` before its ordered actions, and a call shows its
method, deposit, gas and gas weight before `args`. Only state init is shown with
sorted keys. Each `add_extension` adds `WARNING: add_extension gives <account>
full control of this wallet.` before the JSON. Each promise whose
attached NEAR (transfers and deposits) can be refunded to an account other
than the executing wallet adds `WARNING: up to <amount> sent to <receiver>
can be refunded to <refund_to>, not to this wallet.` Array order is preserved. DEL and all non-ASCII
UTF-16 units are escaped as lowercase `\uXXXX`. The output is ASCII and at most
16 KiB, with no BOM, CRLF conversion or prehash. Timestamps are normalized UTC
RFC3339 with insignificant fractional zeros removed; they must fit unsigned u64
Unix nanoseconds. Timeout is a whole u32 number of seconds.

The execution representation explicitly includes defaults and every request field.
Each promise includes receiver, refund target (null means the wallet), and ordered
actions. NEAR amounts and deposits are shown with 24 decimals and the `NEAR`
symbol, for example `1.5 NEAR`, with trailing fractional zeros removed. Calls
include method name, `args`, deposit, decimal-string gas and gas weight.

`args` shows the call arguments once, as JSON in their original key order. The
arguments must be exactly the compact serialization of that JSON, the same in
`serde_json::to_vec` and `JSON.stringify`, so the message determines their bytes.
Numbers must be integers within ±(2^53 - 1); pass larger or fractional values as
strings, as NEAR standards do. Strings must not contain unpaired surrogates, and
integer keys (`"0"` to `"4294967294"`) must come first in ascending order, as in
JavaScript objects. Empty, binary, BOM-prefixed and other non-canonical arguments
(extra whitespace, duplicate keys, optional escapes, alternative number forms) are
rejected; call a method without parameters with `{}`. Before rendering, raw
function-call arguments (a nested request with its base64 encoding), state
data, token symbols and 64 bytes per operation, promise and action must fit
16 KiB; JSON arguments nest at most 127 levels.

A call of another wallet's `w_execute_extension` (this wallet as its extension)
shows its `request` by the same rules, including warnings that name that wallet
and metadata requirements for its token transfers. The arguments must be
exactly the serde form of that request (the contract's field order, defaults
omitted), so the message determines them; there `refund_to` `null` means the
wallet that executes the request, and state-init keys must have the same order
as bytes and as JavaScript object keys (array indices first). Fields that the
contract does not define and duplicate state keys are rejected when the
message is parsed.

NEP-141 transfers (`ft_transfer`, `ft_transfer_call`) require one
`require_ft_metadata` operation for the receiver token in the same request;
otherwise the request is rejected. The contract rejects a checked promise if the
sum of its call weights exceeds `u64::MAX`. Their `args.amount` must be a decimal
`u128` string without leading zeros and is shown with the operation's `decimals` and
`symbol`, for example `1.5 USDC`. The wallet creates promises to that token only
after its `ft_metadata()` returns exactly these values (see
[token metadata checks](../../README.md#token-metadata-checks)).
Its arguments may be only the method's parameters (`receiver_id`, `amount`,
`memo`, and `msg` for `ft_transfer_call`): keys the token ignores could
imitate a shown amount. Warning lines, amounts outside `args` and NEP-141 transfer
amounts are written by the contract; other text inside `args` comes from the
dApp and may imitate them.

`StateInit.deposit` is a refundable budget for storage at that action, not
funding for later calls; see [`StateInit` storage deposit and funding](../../README.md#stateinit-storage-deposit-and-funding).

Deployments include the full serialized state initialization and deposit. Wallet operations
retain their standard tagged JSON encoding. Offchain messages include all five
NEP-641 fields and retain the payload as an exact string. Both representations
include the raw base58 Solana public key, in addition to the NEAR signer account.

The proof is only `ed25519:<base58-of-64-signature-bytes>`; it contains no
dApp-supplied display summary. The contract reconstructs the entire message,
so any semantic change to the message requires a different signature. State
identity is the existing 32-byte `Ed25519PublicKey`, exposed by `w_public_key()` as
`ed25519:<base58>`; the browser's public key is raw base58 without that prefix.

## Clear signing and limitations

[Phantom documents](https://docs.phantom.com/solana/signing-a-message) displaying
UTF-8 message bytes in its approval prompt and signing them with Ed25519. This
variant uses that readable path instead of signing an opaque hash. Request and
offchain authorization have distinct headers explaining what approval authorizes.

Native transfers, deposits, extension operations and call arguments have explicit
fields. NEAR amounts and NEP-141 transfer amounts have decimals and symbol. The
format does not decode further: JSON nested inside a string value (such as `msg`
of `ft_transfer_call`) remains an escaped string, amounts in arguments of other
methods (for example NEP-245 `mt_transfer`) are in base units, non-ASCII text is
shown as `\uXXXX` escapes, and deployment state is base64. These parts are not
clear-signed, and a readable call does not prove the behavior of a third-party
contract. The token symbol comes from the token contract's own metadata, so it
identifies the token only together with the receiver account.

No application summary is trusted. Large messages may require scrolling. Do not
claim full semantic clear signing for arbitrary methods or hardware-wallet support.
Actual Phantom extension/mobile version and display behavior must be recorded in
the integration evidence; documentation alone is not real-device verification.
Phantom for Chrome (version not recorded) signed four display-check messages
of the current format, up to 4,200 bytes: execution effects with token
transfers, state init, offchain and a nested `w_execute_extension` request.
They are in `tests/fixtures/phantom-extension.json`, and the contract accepts
them. Phantom does not allow copying its prompt, so the display is recorded
only as the signer's attestation that each message was readable in full.
Phantom refused the 16 KiB message without opening a prompt ("You cannot sign
solana transactions using sign message"). Its bytes also deserialize as a
Solana transaction (`@solana/web3.js` layout, trailing bytes ignored), which
the four signed messages do not. If Phantom refuses every message that
deserializes this way, it will usually refuse readable messages above about
5 KB; this limit is unverified.

## Security and trust model

The relayer, dApp and RPC are untrusted. The signer must review the Phantom prompt.
Network, NEAR account, nonce/times, gas-payment flag, nested calls/refunds and all
NEP-641 context are signed. Execution/offchain/raw-Ed25519 proofs are incompatible.
The shared core enforces nonces, network/account checks, extension permissions,
lockout and action restrictions. Extensions retain full wallet control. Offchain
messages have no transaction nonce/TTL; the consuming protocol defines their use.

No global contract is deployed by this implementation task. Selecting a global
contract by updatable account ID introduces trust in its update authority; a code
hash identifies immutable code. An independent audit is required before production.

## Build and test

```sh
cargo test -p defuse-wallet-solana --all-features
make defuse-wallet-solana
```

The Rust `WalletSolanaSigner` implements both SDK signing paths. Independent
fixtures and sandbox tests accompany the variant. Validation and audit status
must be established from actual results, not inferred from this document.
