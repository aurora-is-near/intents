# EVM wallet contract: EIP-712

NEAR wallet contract controlled by an **Ethereum (secp256k1) account** that
signs [EIP-712](https://eips.ethereum.org/EIPS/eip-712) typed data with
`eth_signTypedData_v4`. It shares the wallet core, the stored Ethereum address
and the proof format with the [EIP-191 variant](../eip-191/README.md), and is a
separate contract variant (standard `wallet-evm-eip712`).

## Typed data

The contract derives the typed data from the execution message and hashes it
itself. No typed data, summary or hash supplied by a dApp is trusted.

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

The signed digest is `keccak256(0x19 ‖ 0x01 ‖ hashStruct(domain) ‖ hashStruct(message))`.
The two primary types separate execution and NEP-641 proofs; the `0x01`
version separates them from EIP-191 `personal_sign` proofs.

- The domain has no `chainId` or `verifyingContract`: a NEAR network has no
  EIP-155 chain ID, and a NEAR account is not an `address`. `chain_id` and
  `signer_id` (the wallet account) are message fields instead.
- `warnings` holds `add_extension gives <account> full control of this wallet`
  for each `add_extension`, then `up to <amount> sent to <receiver> can be
  refunded to <refund_to>, not to this wallet` for each promise whose attached
  NEAR (transfers and deposits) can be refunded to another account; the
  contract derives them.
- Operations and actions are unions of one struct type each, as EIP-712 arrays
  are homogeneous; `op` or `action` selects the fields that apply, and unused
  ones are empty or zero. `signature_mode` is `enable` or `disable`.
  `yocto_near` is a transfer amount or attached deposit. An empty `refund_to`
  means this wallet; `state_init` has one item only for state-init actions.
- Integers are typed atomic values: NEAR amounts are in yoctoNEAR and gas in
  gas units. EIP-712 has no decimal amount type, so wallets show base units.
- Timestamps are RFC 3339 UTC strings, as in JSON. Timeout is whole seconds.
- `args` is the exact argument string. It must be compact JSON that
  serializes identically in Rust and JavaScript (no duplicate keys, extra
  whitespace or alternative forms; integers within ±(2^53 - 1)).
- Text members (`chain_id`, `function_name`, `args`, `symbol`, `payload`) must
  be printable ASCII, so no hidden, bidirectional or look-alike characters
  are shown. Non-ASCII text is rejected.
- String and `bytes` members total at most 16 KiB (UTF-8 or raw length) and
  arrays hold at most 128 items in total (warnings, operations, promises,
  actions, state inits and entries, path entries), bounding gas and the wallet
  prompt. The contract counts them before parsing or hashing them.
- `w_execute_extension` calls are rejected: their request would be signed as an
  opaque argument string. Use the EIP-191 variant, which shows it decoded.
- Fields that the contract does not define and duplicate state keys are
  rejected when the message is parsed.

## Proof

`secp256k1:<base58 of r || s || v>`: 65 bytes, low-S, `v` is `0` or `1`
(subtract `27` from wallet signatures). The contract recovers the key and
compares its address with the stored one, so only externally owned accounts
can sign; ERC-1271 contract signatures are not supported.

## Clear signing and limitations

Wallets show EIP-712 typed data as a tree of field names and values; the
contract cannot prove what a wallet displays. Amounts are base units, nested
JSON inside `args` (such as `msg`) and state data (`bytes`) are not decoded,
and a readable call does not prove a third-party contract's behavior.

Real `MetaMask` signatures of four display-check messages (execution effects,
state init, offchain and the whole 16 KiB text budget) are in
`tests/fixtures/metamask.json`, with the text copied from each prompt. After
the account, an Ethereum network name (unrelated to `chain_id`) and the request
origin, it lists the primary type and every message field in order: `Name:`
and the value, `i:` for each array item, integers in base units, `bytes` as
hex and empty values blank. It does not include the domain's name or version,
so the primary type, `chain_id` and `signer_id` identify the request. The
signer also marked each prompt as complete. They are from a software account
(extension version not recorded); hardware-wallet display is unverified.

## Security model

The relayer, dApp and RPC are untrusted; the signer must review the wallet
prompt. Any site can request a signature with this domain, so `chain_id` and
`signer_id` (checked by the contract) bind the network and the wallet. NEP-641
authorizations have no nonce or expiry enforced by the wallet; the consuming
protocol defines one-time use and expiration. The shared core enforces nonces,
extension permissions, lockout and action restrictions; extensions keep full
wallet control. Selecting a global contract by updatable account ID trusts its
update authority. An independent audit is required before production.

## Build and test

```sh
make defuse-wallet-evm-eip712
cargo test -p defuse-wallet-evm-eip712 --all-features
```

Vectors in `tests/fixtures/eip712.json` are hashed and signed by
`@metamask/eth-sig-util`. This independently checks hashing and signing,
not the derivation of typed data from wallet requests.
