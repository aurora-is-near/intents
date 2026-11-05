# Temporary NEAR dependency security patches

The workspace stays on NEAR SDK 5.29.1 / nearcore libraries 0.37.3. Three
published crates are pinned locally through `[patch.crates-io]` so that native
signing/testing and TLS dependencies can use fixed releases without an AccountId
2.x/3.x migration. These are maintained local patches, not official NEAR releases.

| Local package | Change |
| --- | --- |
| near-sdk 5.29.1 | Native optional p256 0.13.2 -> 0.14.0. |
| near-vm-runner 0.37.3 | p256 0.13.2 -> 0.14.0. |
| near-crypto 0.37.3 | AWS-LC =1.16.2 -> ^1.19; use the equivalent stable ML-DSA import names. |

The root lockfile selects crypto-bigint 0.7.10, aws-lc-rs 1.19.0,
rustls 0.23.46 and rustls-webpki 0.103.16. This removes the old bigint dependency
rather than relabeling it, and actually installs the certificate-verifier fix.
No cryptographic arithmetic or signing rules were rewritten. The only Rust edit
moves deprecated AWS-LC aliases to their identical stable types/constants.
Onchain SDK Rust source and the wallet signing formats are unchanged.

`UPSTREAM.json` records the exact crates.io archive URLs/checksums and changed
files. Published nearcore VCS metadata has `dirty: true`; archive checksums, not
an assertion of a clean Git revision, identify the upstream inputs. `patches/`
contains focused diffs against those archives. All other source is retained.
Registry cache markers and nested Cargo.lock files are omitted: the root
Cargo.lock governs this workspace. Original MIT/Apache license texts are retained;
the SDK licenses were copied from its recorded upstream revision.

The SDK's `near-token` dependency is referenced by its ABI feature and its type
is re-exported through near-sdk-core. Its scoped cargo-machete annotation records
that false positive. Taplo excludes upstream formatting; project files and all
workspace Rust checks remain enabled. Vendored packages are not workspace members.

## Recheck and eventual removal

```sh
cargo tree --locked -i crypto-bigint
cargo tree --locked -i rustls-webpki
python3 scripts/cargo-audit-no-git.py --output-dir /tmp/intents-security-audit
make check-fmt
make check-unused-deps
make check
make doc
make all
DEFUSE_MIGRATE_FROM_LEGACY=true make test
```

The helper fetches the current RustSec snapshot through HTTPS and invokes
`cargo audit --no-fetch --deny unsound --deny yanked`; it performs no Git writes.
It retains the snapshot identity and audit output in a new evidence directory.
Four obsolete TLS exceptions were removed. Three pre-existing native Wasmtime
exceptions remain; a green configured scan does not mean that every dependency
has no known advisory.

Use the root workspace when building/testing these patches. Do not generate
independent lockfiles inside individual vendored crates. These patches are shared
by the independent wallet integration branches; they do not depend on either
signing adapter. Local audit evidence is preserved separately from this source.

Remove the three `[patch.crates-io]` entries when a compatible upstream NEAR release
uses the fixed libraries. Update the lockfile, confirm that the old bigint cannot
return, and repeat native compatibility, wallet, WASM and dependency checks.
Keep the patch provenance available when reviewing that replacement; do not remove
security fixes merely because an upstream version number increased.
