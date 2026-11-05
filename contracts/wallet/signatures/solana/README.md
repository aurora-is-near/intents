# Solana wallet contract

NEAR wallet contract controlled by a Phantom **Solana Ed25519 account** using
`window.phantom.solana.signMessage(bytes, "utf8")`. It uses the shared wallet core,
including deterministic accounts, extensions, timeout nonces and NEP-641.
It does not use Phantom EVM signing, SIWS login, or the digest-only Ed25519 variant.

## Signing format v1

Sign the entire output of `request_signing_message` or `offchain_signing_message`,
including the purpose-specific prefix, two-space pretty-printed JSON and final LF.
All object keys are recursively sorted; array order is preserved. DEL and all non-ASCII
UTF-16 units are escaped as lowercase `\uXXXX`. The output is ASCII and at most
16 KiB, with no BOM, CRLF conversion or prehash. Timestamps are normalized UTC
RFC3339 with insignificant fractional zeros removed; they must fit unsigned u64
Unix nanoseconds. Timeout is a whole u32 number of seconds.

The execution representation explicitly includes defaults and every request field.
Each promise includes receiver, refund target (null means the wallet), and ordered
actions. Transfers use raw decimal `amount_yoctonear`. Calls include method name,
exact `args_base64`, `args_utf8` (null for non-UTF-8 bytes), decimal-string deposit,
gas and gas weight. Arguments are never parsed and reserialized. Deployments
include the full serialized state initialization and deposit. Wallet operations
retain their standard tagged JSON encoding. Offchain messages include all five
NEP-641 fields and retain the payload as an exact string. Both representations
include the raw base58 Solana public key, in addition to the NEAR signer account.

The proof is only `ed25519:<base58-of-64-signature-bytes>`; it contains no
client-supplied display summary. The contract reconstructs the entire message,
so any semantic change to the message requires a different signature. State
identity is the existing 32-byte `Ed25519PublicKey`, exposed by `w_public_key()` as
`ed25519:<base58>`; the browser's public key is raw base58 without that prefix.

## Clear signing and limitations

[Phantom documents](https://docs.phantom.com/solana/signing-a-message) displaying
UTF-8 message bytes in its approval prompt and signing them with Ed25519. This
variant uses that readable path instead of signing an opaque hash. Request and
offchain authorization have distinct headers explaining what approval authorizes.

Native transfers and extension operations have explicit fields. Arbitrary calls
and deployment state can still be opaque: readable raw UTF-8 arguments do not
prove the behavior of a third-party contract, and base64 is not decoded intent.
No application summary is trusted. Large messages may require scrolling. Do not
claim full semantic clear signing for arbitrary methods or hardware-wallet support.
Actual Phantom extension/mobile version and display behavior must be recorded in
the integration evidence; documentation alone is not real-device verification.

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

The Rust `WalletPhantomSigner` implements both SDK signing paths. Browser integration,
independent fixtures and sandbox tests accompany the variant. Validation and audit
status must be established from actual results, not inferred from this document.

## Browser integration

`client/phantom.mjs` uses the shared wallet renderer in
`contracts/wallet/client/readable-message.mjs` and has no npm dependencies.
It requires `BigInt`, `structuredClone`,
`TextEncoder`/`TextDecoder`, and `WebCrypto` Ed25519 in a secure context (HTTPS or
localhost). It targets Phantom's traditional injected Solana provider; embedded
SDK, deep-link and hardware-wallet flows need their own validation.

```javascript
import { signRequest, signOffchain } from './client/phantom.mjs';

// requestMessage is a validated RequestMessage for the wallet account derived
// from this Solana key, the chosen global code and initial state using the Rust SDK.
const signed = await signRequest(window.phantom.solana, requestMessage);
// Deliver only { msg: signed.msg, proof: signed.proof } to w_execute_signed
// through the application's relayer. The adapter itself never relays a transaction.

const auth = await signOffchain(window.phantom.solana, offchainMessage);
const authorization = JSON.stringify({ signature: { msg: auth.msg, proof: auth.proof } });
// authorization is the NEP-641 WalletAuthorization blob.
```

The adapter validates supported fields and integer ranges, rejects unknown fields,
requires canonical base64 and UTC timestamps, and locally verifies the returned
signature. It keeps private copies of the signed message and signature so provider
buffer mutation cannot substitute different bytes during asynchronous verification.
Explicit null is valid for `refund_to` only; defaulted non-optional fields must be
omitted or have their declared type. Raw transaction arguments and offchain payloads
are never interpreted as a trusted application summary.

Run the browser-adapter tests with:

```sh
node --test contracts/wallet/signatures/solana/client/phantom.test.mjs
```

For manual prompt verification, build and serve the **public dist directory only**, open
`display-check.html`, and review/approve its two test messages in Phantom:

```sh
node contracts/wallet/signatures/solana/client/build-display-check.mjs
python3 -m http.server 8765 --bind 127.0.0.1 --directory contracts/wallet/signatures/solana/client/dist
```

The manual test uses a fictional chain ID and never relays transactions. It does
not request a seed/private key, store signatures, or send them to a server. Record
the Phantom/platform version, actually visible fields, scrolling/truncation and
local signature-verification result. Do not replace this evidence with Node mocks.

## Sandbox prerequisites

Build `res/defuse-wallet-solana.wasm` with `make defuse-wallet-solana` before running
all package tests. By default, sandbox tests use the workspace's Docker-backed
`near-kit-sandbox` (NEAR 2.13.4). An isolated native sandbox with the official
near-sandbox 0.3.16 default `sandbox` genesis account may be used instead by setting
`PHANTOM_SANDBOX_RPC_URL=http://127.0.0.1:<port>`. The override rejects non-loopback
HTTP endpoints and uses only the package's publicly documented test key. No test
requires a user's Phantom seed or real funds.
