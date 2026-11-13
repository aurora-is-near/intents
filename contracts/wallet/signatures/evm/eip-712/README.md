# EVM wallet contract: EIP-712

NEAR wallet contract controlled by an **Ethereum (secp256k1) account** that
signs [EIP-712](https://eips.ethereum.org/EIPS/eip-712) typed data with
`eth_signTypedData_v4`. It shares the wallet core, the stored Ethereum address
and the proof format with the [EIP-191 variant](../eip-191/README.md) and is a
separate contract.

## Typed data

The contract derives the typed data from the message and hashes it itself; no
typed data, summary or hash supplied by a dApp is trusted. The signed digest
is `keccak256(0x19 ‖ 0x01 ‖ hashStruct(domain) ‖ hashStruct(message))`.

```text
EIP712Domain(string name,string version)
  name = "NEAR Wallet Contract", version = "1"
ExecuteRequest(string[] warnings,string chain_id,string signer_id,uint32 nonce,
  string created_at,uint32 timeout_secs,bool pay_for_gas,Operation[] internal,Promise[] external)
Operation(string op,string account_id,string signature_mode,uint8 decimals,string symbol)
Promise(string receiver_id,string refund_to,Action[] actions)
Action(string action,uint128 yocto_near,string function_name,string args,uint64 gas,
  uint64 gas_weight,StateInit[] state_init)
StateInit(string code_hash,string code_account_id,StateEntry[] data)
StateEntry(bytes key,bytes value)
OffchainAuthorization(string chain_id,string signer_id,string[] path,string timestamp,string payload)
```

The domain has no `chainId` or `verifyingContract`: a NEAR network has no
EIP-155 chain ID and a NEAR account is not an `address`. `chain_id` and
`signer_id` (the wallet account, checked by the contract) are message fields.

Operations and actions are unions of one struct each, as EIP-712 arrays are
homogeneous. Members that do not apply are `""`, `0` or an empty array.

| Member | Value |
| --- | --- |
| `warnings` | `add_extension gives <account> full control of this wallet` for each `add_extension`, then `up to <amount> sent to <receiver> can be refunded to <refund_to>, not to this wallet` for each promise that attaches NEAR and whose `refund_to` is another account; `<amount>` is like `1.5 NEAR` |
| `created_at`, `timestamp` | RFC 3339 in UTC with `Z` and up to nine fractional digits without trailing zeros, e.g. `2026-11-03T12:34:56.12Z` |
| `timeout_secs` | whole seconds |
| `Operation.op` | `set_signature_mode`, `add_extension`, `remove_extension` or `require_ft_metadata` |
| `Operation.account_id` | the extension, or the token of `require_ft_metadata` |
| `Operation.signature_mode` | `enable` or `disable` |
| `Operation.decimals`, `symbol` | of `require_ft_metadata` |
| `Promise.refund_to` | `""` is this wallet |
| `Action.action` | `transfer`, `function_call` or `deterministic_state_init` |
| `Action.yocto_near` | transfer amount or attached deposit, in yoctoNEAR |
| `Action.args` | the exact argument string: compact JSON that serializes identically in Rust and JavaScript, as in the [readable format](../../../README.md#readable-signing-format-v1) |
| `Action.gas`, `gas_weight` | gas units (default `0`) and weight (default `1`) |
| `Action.state_init` | one item for `deterministic_state_init` |
| `StateInit.code_hash`, `code_account_id` | base58 code hash or account ID of the global contract; the other is `""` |
| `StateInit.data` | entries in ascending order of key bytes |

Rejected instead of signed:

- text members that are not printable ASCII (`0x20` to `0x7e`), so no hidden,
  bidirectional or look-alike characters are shown;
- more than 16 KiB of string and `bytes` members in total, or more than 128
  array items in total;
- `w_execute_extension` calls: their request would be an opaque argument
  string. Use the EIP-191 variant, which shows it decoded.

## Proof

`secp256k1:<base58 of r || s || v>`: 65 bytes, low-S, `v` is `0` or `1`
(subtract `27` from wallet signatures). The contract recovers the key and
compares its address with the stored one. The two primary types separate
execution and NEP-641 proofs, and the `0x01` version separates both from
EIP-191 proofs.

Only an address whose secp256k1 key signs can control the wallet; see the
[EIP-191 variant](../eip-191/README.md#identity-and-proof).

## Clear signing

Wallets show typed data as a tree of member names and values. Compared with
the readable format, this variant shows less:

- Amounts are in base units: NEAR in yoctoNEAR, token amounts inside `args`.
- `args` is one string and is not decoded; text inside it comes from the
  dApp and may imitate other members. NEP-141 `ft_transfer` and
  `ft_transfer_call` accept only the method's parameters and a decimal `u128`
  `amount` without leading zeros, but `require_ft_metadata` is not required
  for them.
- State data is `bytes`.
- Strings and the structure are shown as they are hashed. Integers and
  `pay_for_gas` are hashed by value, but a wallet may show them as the dApp
  wrote them: `MetaMask` hashes `"0x10"`, `" 16"` and `"016"` as `16` and any
  non-empty string, including `"false"`, as `true`. Clients must pass decimal
  integers and JSON booleans; a prompt that shows anything else is not from an
  honest client. The contract rejects `pay_for_gas` `true`.

`MetaMask` with a software account signed four messages (token transfers,
state init, a NEP-641 authorization and the whole 16 KiB text budget); they
are in `tests/fixtures/metamask.json` with the text copied from each prompt.
After the account, an Ethereum network name (unrelated to `chain_id`) and the
request origin, the prompt lists the primary type and every member: integers
in base units, `bytes` as hex. It does not show the domain. Other wallets and
hardware wallets are unverified.

## Build and test

```sh
make defuse-wallet-evm-eip712
cargo test -p defuse-wallet-evm-eip712 --all-features
```

`WalletEip712Signer` implements both SDK signing paths. The vectors in
`tests/fixtures/eip712.json` are hashed and signed with
`@metamask/eth-sig-util` 8.2.0; `tests/typed_data.rs` hashes every fixture's
typed data with a generic EIP-712 encoder and compares it with the contract's
digest.
