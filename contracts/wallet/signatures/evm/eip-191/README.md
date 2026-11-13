# EVM wallet contract: EIP-191

NEAR wallet contract controlled by an **Ethereum (secp256k1) account**. The
account signs the
[readable signing format](../../../README.md#readable-signing-format-v1) with
`personal_sign` ([ERC-191](https://eips.ethereum.org/EIPS/eip-191) version
`0x45`), which wallets such as `MetaMask` show as text. The
[EIP-712 variant](../eip-712/README.md) is a separate contract that reuses
this crate's address and proof types.

## Identity and proof

- The wallet state stores the 20-byte Ethereum address; `w_public_key()`
  returns it as lowercase `0x` hex.
- The signed text has one identity field after `signer_id`: `evm_address`,
  the same lowercase `0x` hex.
- The wallet signs
  `keccak256("\x19Ethereum Signed Message:\n" || len || text)` with the
  decimal byte length. Pass the text to `personal_sign` as `0x` hex of its
  UTF-8 bytes, so the wallet signs these bytes and shows them as text.
- The proof is `secp256k1:<base58 of r || s || v>`: 65 bytes, low-S, `v` is
  `0` or `1` (subtract `27` from wallet signatures).
- The contract recovers the key from the proof and compares its address with
  the stored one. Proofs of execution requests, of NEP-641 authorizations and
  of the EIP-712 variant are not interchangeable.

Only an address whose secp256k1 key signs can control the wallet. A contract
account (Safe, ERC-4337) or a watch-only address cannot: ERC-1271 is not
supported, and funds sent to a wallet derived from such an address may be
unrecoverable. Before showing the derived account as a deposit destination,
[verify control](../../../README.md#verify-control-before-funding) of the
address.

## Clear signing

The user reads in the wallet prompt the same text that the contract rebuilds
and verifies. What that text does not decode is listed with the
[format](../../../README.md#readable-signing-format-v1). `personal_sign` is
also used for logins by other applications; the text says that it is not one,
and the contract accepts it only for the network and wallet account it names.

`MetaMask` with a software account signed five messages of this format (token
transfers, state init, a NEP-641 authorization, a nested `w_execute_extension`
request and a 16 KiB message); they are in `tests/fixtures/metamask.json` with
the text copied from each prompt. After the account, an Ethereum network name
(unrelated to `chain_id`) and the request origin, the prompt shows the whole
text, warnings first. Other wallets and hardware wallets are unverified.

## Build and test

```sh
make defuse-wallet-evm-eip191
cargo test -p defuse-wallet-evm-eip191 --all-features
```

`WalletEip191Signer` implements both SDK signing paths. The vectors in
`tests/fixtures/eip191.json` are signed with `@noble/curves` and
`@noble/hashes`.
