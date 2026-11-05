# Sui wallet contract

## Adapter specification (v1)

This family contains three separate NEAR wallet/global-contract variants using
Sui personal-message signatures: `ed25519/`, `secp256k1/`, and `p256/` (Sui
`Secp256r1`). The parent `defuse-wallet-sui` crate is a library and does not build
a universal contract. Each leaf instantiates `WalletSui<Algorithm>` with one
fixed scheme; the protocol and crypto backends are selected by Cargo features.
It authorizes NEAR wallet operations, not Sui transactions, and reuses the wallet
core and its readable-message renderer. Each global contract ID participates in
NEP-616 address derivation: selecting a different ID changes derived addresses
even with the same key and initial state.
Changing from the old universal artifact to a new leaf global contract changes
derived NEAR addresses because the global contract ID changes. The old unified
source is retained as historical audit material, and old local artifacts are not
new build targets. No global contract publication, migration or live deployment
is performed here.

The shared readable-message formatter belongs to `contracts/wallet/src/readable_message.rs`
and is enabled by the wallet's `readable-message` feature. This Sui library owns
its native protocol implementation in `src/protocol/mod.rs` and its private
BLAKE2b-256 helper in `src/protocol/hash.rs`. The former standalone
`defuse-sui` and `defuse-wallet-message` workspace crates are removed. Existing
adapter re-exports, including `sui`, are retained; signed bytes and stored-state
encoding are unchanged. The general digest crate has no wallet-specific additions.

The [wallet-local architecture review](audit/wallet-local-20261105/REPORT.md) records
the relocation, feature boundaries and updated source/artifact identities.

The initial interoperability reference is `@mysten/sui` **2.39.0** and
`@mysten/wallet-standard` **0.21.37**. The browser API is Wallet Standard
`sui:signPersonalMessage({ message, account })`, which receives the complete
readable message bytes. A wallet's internal protocol hashing does not justify
giving it only a digest. Phantom's legacy Sui support is officially deprecated;
it is not assumed available merely because Phantom Solana works.

### Identity, bytes and proof

- Support direct key-derived Sui identities with flags 0 (Ed25519), 1
  (secp256k1), and 2 (secp256r1). Multisig, zkLogin, passkey, ML-DSA, address
  aliases and other account-authority mechanisms are not implemented and must
  not be accepted as an arbitrary Sui account's authority.
- The identity string is `sui:<base64(flag || public_key)>`. Keys have 32 bytes
  for Ed25519 and 33-byte compressed SEC1 encoding for ECDSA. The Sui address is
  `0x` plus the lowercase hex BLAKE2b-256 of `flag || public_key`. The key's
  Borsh discriminants remain those three flags after the refactor; they participate in NEP-616 address
  derivation, alongside the separate global contract ID and initial wallet state.
  Rust key variants now contain raw fixed arrays rather than crypto wrapper types;
  the complete state bytes remain identical for a fixed global contract ID, key
  and initial settings. Compatibility tests retain the previous representation
  as an oracle. Each contract rejects a key or proof for a different scheme even
  when all backends are compiled together.
- The readable representation includes `sui_address` and `sui_public_key`
  (base64 of flag plus key), instead of Solana's `solana_public_key`. Otherwise
  it follows the shared v1 format: purpose-specific headers, all request/NEP-641
  fields, sorted object keys, ordered arrays, two-space JSON, escaped DEL and
  non-ASCII UTF-16 units, trailing LF and a 16 KiB limit. Payload and call
  argument bytes are not parsed or normalized. Defaults are explicit.
- Native personal-message signing uses BCS `vector<u8>` (canonical ULEB128 u32
  length followed by bytes), prefixed with intent `[3, 0, 0]`, then BLAKE2b-256.
  Ed25519 signs that digest as a message. ECDSA signs its SHA-256 digest, matching
  the native SDK's ECDSA message hashing; signatures must be low-S.
- Proofs are canonical padded base64 of `flag || signature[64] || public_key`.
  Check exact lengths, supported flag, stored-key equality, valid keys/points,
  signatures and malleability. Never retry a rejected proof under another scheme.
  Reject weak Ed25519 keys using the existing crypto policy. This intentionally
  does not claim acceptance of all exceptional ZIP-215 key encodings.
- Separate execution/offchain headers and the native intent domain prevent
  cross-purpose, transaction-intent and raw Solana proof reuse. Core checks still
  enforce the NEAR network/account, execution nonces and validity interval.
  NEP-641 one-time use and expiry remain the consuming protocol's responsibility.

### Trust boundaries and clear signing

The dApp, relayer, RPC and third-party contracts are untrusted. The contract
reconstructs the display message from the execution request and stored key; no
client description or address is trusted. Enabled extensions retain full control.
Immutable global code hashes and updatable global account IDs have different
update-authority trust assumptions. Asynchronous promises can partially succeed.

Native transfers and extension changes have explicit fields. Function arguments
and deployment state may be opaque, even when shown as UTF-8/base64. A readable
JSON envelope cannot establish their full semantic meaning. Large messages require
scrolling. Actual wallet/version and visible fields must be recorded before any
real-wallet clear-signing claim. The current manual integration targets Slush
through Wallet Standard; trusted-display evidence must be recorded before
claiming it verified. A zkLogin/passkey/alias account must not be treated as a
direct Ed25519 account merely because an ephemeral key is returned by its API.
Existing Phantom Solana 26.37.0 display evidence applies only to its tested
messages; it is not evidence for Sui, mobile or hardware-wallet displays.

### Validation and delivery

Use official SDK vectors for all three schemes and both purposes, field/order
mutations, malformed keys/proofs, wrong domains/intents, exact-byte payloads,
resource boundaries, deterministic account derivation, and real WASM sandbox
execution/offchain/nonce rollback/rotation checks. The shared renderer must match
all frozen Sui vectors. Final audit must re-read the resulting code
from scratch and identify exact source/artifact checksums. No live deployment or
real funds are authorized by this implementation.

Local review is recorded in [the refactor audit](audit/refactor-20261104/REPORT.md)
and [the Slush integration follow-up](audit/slush-key-encoding-20261104/REPORT.md).
Actual execution and offchain signatures from Slush `26.22.0 [release]`
(user-reported version), using a direct Ed25519 account, passed Rust and OpenSSL
verification. User-supplied text from the trusted signing window contains the
tested message fields. The offchain display values match the captured signature's
message, including timestamp and exact payload; the execution display and capture
were separate requests, as confirmed by the user. These observations cover the
tested text-message format, not arbitrary call semantics or other devices/schemes.

The two native dependency findings are addressed by local NEAR dependency
patches described in [vendor/README.md](../../../../vendor/README.md): fixed
bigint/P-256 and AWS-LC/TLS versions, without the SDK 5.30 `AccountId` migration.
Four obsolete TLS exceptions were removed; no advisory exception was added.
The [dependency follow-up](audit/dependency-fix-20261105/REPORT.md) records final
validation and source/artifact identities. Existing native Wasmtime exceptions
and unmaintained-package warnings remain distinct from these resolved findings.

## Build and integration

```sh
make defuse-wallet-sui-ed25519 defuse-wallet-sui-secp256k1 defuse-wallet-sui-p256
cargo test -p defuse-wallet-sui --all-features --locked
```

Sandbox tests use the standard Docker-backed harness. Alternatively, start an
isolated official NEAR 2.13.4 sandbox and set `SUI_SANDBOX_RPC_URL` to its loopback
HTTP URL with a nonzero
port. The override uses only the official sandbox's public test key and rejects
remote hosts, credentials, paths and query strings. No real wallet seed is needed.

`WalletSuiSigner::<Ed25519, _>::new(signer)` adapts a shared crypto signer to both
SDK signing paths; use `Secp256k1` or `P256` for the other two native schemes.
`SuiPublicKey` retains the scheme in state; each `WalletSui<C>` also checks
`C::FLAG`, so another enabled backend cannot authorize its requests.

The optional local `client/` helper uses Node >=22, pinned npm dependencies and
Wallet Standard. Its manual page selects Slush explicitly. It uses the shared
wallet renderer in `contracts/wallet/client/readable-message.mjs` and verifies the returned
signature and exact message locally. It rejects unsupported account
identities and never silently selects another wallet or signing method.
Wallet account metadata may contain raw key bytes or native Sui flag-prefixed
bytes; both forms must derive the advertised direct account address before signing.

```sh
cd contracts/wallet/signatures/sui/client
npm ci --ignore-scripts
npm test
npm run build
python3 -m http.server 8766 --bind 127.0.0.1 --directory dist
```

Open `http://localhost:8766/display-check.html`, explicitly select/connect Slush,
then request each test signature. The messages use the fictional network
`sui-display-check-only` and are never relayed. Review the entire message in the
wallet, including recipient, amount/units, refund target, recovery extension,
network/account, validity, and the offchain path/payload. Record wallet version
and complete display evidence separately from the page's verification result.

`npm run fixtures` regenerates the official SDK vectors from the local
`client/fixture-messages.json` cases using a deliberately public deterministic
test secret. It does not require the Solana adapter or its fixtures. The test
secret must never be replaced with a real key.
Local client/audit helpers are separate from the production Rust contract and
have not been staged or published.

### Primary references

- [Sui intent signing](https://www.docs.sui.io/develop/transactions/transaction-auth/intent-signing)
- [Sui authentication and signature requirements](https://www.docs.sui.io/develop/transactions/transaction-auth/auth-overview)
- [Official SDK cryptography](https://sdk.mystenlabs.com/sui/cryptography)
- [Wallet Standard personal messages](https://github.com/MystenLabs/ts-sdks/blob/main/packages/wallet-standard/src/features/suiSignPersonalMessage.ts)
- [Phantom Sui deprecation](https://docs.phantom.com/sui/signing-a-message)
