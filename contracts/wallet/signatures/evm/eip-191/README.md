# EVM wallet contract: EIP-191

NEAR wallet contract controlled by an **Ethereum (secp256k1) account** that
signs the full readable message with `personal_sign`
([ERC-191](https://eips.ethereum.org/EIPS/eip-191) version `0x45`), e.g.
`ethereum.request({ method: "personal_sign", params: [message, address] })` in
`MetaMask`. It uses the shared wallet core: deterministic accounts, extensions,
timeout nonces and NEP-641. The [EIP-712 variant](../eip-712/README.md) is a
separate contract that reuses this crate's address and proof types.

## Signing format v1

Sign the entire output of `request_signing_message` or
`offchain_signing_message`: a purpose header, warning lines, then two-space
pretty-printed JSON and a final LF.

- Fields have a fixed order: `chain_id`, `signer_id`, `evm_address`, then
  `nonce`, `created_at`, `timeout_secs`, `pay_for_gas` and `request`, which
  lists `internal` wallet operations before `external` promises. Promises show
  `receiver_id`, `refund_to` (`null` means this wallet) and ordered `actions`;
  a call shows its method, deposit, gas and gas weight before `args`. Only
  state init is shown with sorted keys.
- Each `add_extension` adds `WARNING: add_extension gives <account> full
  control of this wallet.` before the JSON. Each promise whose
  attached NEAR (transfers and deposits) can be refunded to an account other
  than the executing wallet adds `WARNING: up to <amount> sent to <receiver>
  can be refunded to <refund_to>, not to this wallet.`
- Output is ASCII and at most 16 KiB: DEL and non-ASCII UTF-16 units are
  escaped as lowercase `\uXXXX`. Before rendering, raw function-call
  arguments (a nested request with its base64 encoding), state data, token
  symbols and 64 bytes per operation, promise and action must fit 16 KiB;
  JSON arguments nest at most 127 levels.
- Timestamps are normalized UTC RFC 3339 that fit u64 nanoseconds; the timeout
  is a whole u32 number of seconds.
- NEAR amounts have 24 decimals and the `NEAR` symbol, e.g. `1.5 NEAR`.
- `args` is shown once, as JSON in its original key order (except for
  `w_execute_extension`, below). It must be exactly
  its compact serialization, the same in `serde_json` and `JSON.stringify`:
  integers within ±(2^53 - 1), no unpaired surrogates, array-index keys first
  in ascending order, no duplicate keys, extra whitespace, optional escapes or
  alternative forms. Empty and binary arguments are rejected; call a method
  without parameters with `{}`.
- NEP-141 `ft_transfer(_call)` requires one `require_ft_metadata` operation for
  its token; `args.amount` (a canonical decimal `u128`) is shown with its
  decimals and symbol, e.g. `1.5 USDC`. The wallet calls the token only after
  its `ft_metadata()` returns exactly these values (see
  [token metadata checks](../../../README.md#token-metadata-checks)).
  Its arguments may be only the method's parameters (`receiver_id`, `amount`,
  `memo`, and `msg` for `ft_transfer_call`): keys the token ignores could
  imitate a shown amount.
- A call of another wallet's `w_execute_extension` (this wallet as its
  extension) shows its `request` by the same rules, including warnings that
  name that wallet and metadata requirements for its token transfers.
  The arguments must be exactly the serde form of that request (the
  contract's field order, defaults omitted), so the message determines them;
  there `refund_to` `null` means the wallet that executes the request, and
  state-init keys must have the same order as bytes and as JavaScript object
  keys (array indices first).
- Offchain messages show all five NEP-641 fields; the payload stays an exact
  string.

The wallet signs `keccak256("\x19Ethereum Signed Message:\n" || len || message)`
with the decimal byte length. Pass the message to `personal_sign` as `0x`-hex
of its UTF-8 bytes, so the wallet signs these bytes and shows them as text.

## Proof and identity

The proof is `secp256k1:<base58 of r || s || v>`: 65 bytes, low-S, `v` is `0`
or `1` (subtract `27` from wallet signatures). It carries no display summary.
The contract rebuilds the message, recovers the key and compares its address
with the stored one, so only externally owned accounts can sign (no ERC-1271).

The contract stores the 20-byte address (`w_public_key()` returns lowercase
`0x` hex). Wallets expose it without signing (`eth_requestAccounts`), so the
NEP-616 account can be derived as soon as the user connects.

## Clear signing and limitations

`MetaMask` shows `personal_sign` messages that decode as UTF-8 as text. Not
decoded: JSON inside string values (such as `msg` of `ft_transfer_call`),
amounts in other methods' arguments (e.g. NEP-245 `mt_transfer`, in base
units), non-ASCII text (`\uXXXX`) and state-init data (base64). A readable call
does not prove a third-party contract's behavior, and the token symbol comes
from the token's own metadata, so it identifies the token only with the
receiver account. Warning lines, amounts outside `args` and NEP-141 transfer
amounts are written by the contract; other text inside `args` comes from the
dApp and may imitate them. Long messages may need scrolling.

Real `MetaMask` signatures of all five display-check messages (execution
effects, state init, offchain, a nested `w_execute_extension` request and a
16 KiB message) are in `tests/fixtures/metamask.json`, with the text copied
from each prompt. After the account, an Ethereum network name (unrelated to
`chain_id`) and the request origin, it shows the whole signed message, warnings
first. The signer also marked each prompt as complete. They are from a software
account (extension version not recorded); hardware-wallet display is
unverified. The frozen vectors in `tests/fixtures/eip191.json` are signed by
an independent implementation (`@noble/curves`, `@noble/hashes`).

## Security model

The relayer, dApp and RPC are untrusted; the signer must review the wallet
prompt. Network, wallet account, nonce and times, gas payment, nested calls,
refunds and the NEP-641 context are signed; execution and offchain proofs are
incompatible. Fields that the contract does not define and duplicate state
keys are rejected. The
shared core enforces nonces, extension permissions, lockout and action
restrictions; extensions keep full wallet control.

`personal_sign` is also used by other applications. A signature over this
message is accepted only by this address's wallet on the network and account
it names; the header says it is not a login.

No global contract is deployed by this implementation. Selecting a global
contract by updatable account ID trusts its update authority. An independent
audit is required before production.

## Build and test

```sh
make defuse-wallet-evm-eip191
cargo test -p defuse-wallet-evm-eip191 --all-features
```
