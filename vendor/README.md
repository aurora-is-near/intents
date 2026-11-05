# Temporary near-vm-runner 0.38 security patch

The merged upstream workspace uses NEAR SDK 5.30.0, nearcore libraries 0.38.0
and near-account-id 3.0.0. Only `near-vm-runner 0.38.0` still needs a local
patch: its published manifest selects p256 0.13.2, which brings crypto-bigint
0.5.5 and RUSTSEC-2026-0387.

The sole source-package change is `Cargo.toml`: p256 0.13.2 -> 0.14.0.
All Rust code and the original MIT/Apache license texts are preserved exactly.
`UPSTREAM.json` identifies the checksummed crates.io archive; `patches/` records
the complete diff. The workspace Cargo.lock is authoritative, so the package's
nested lockfile is omitted. These are local maintained changes, not an official
NEAR release. Vendored crates are not workspace members.

This replacement affects near-sdk's native unit-testing host dependency. It
does not update NEAR validator binaries or introduce a P-256 dependency into
the deployed wallet WASM.

The old near-sdk 5.29.1 / nearcore 0.37.3 patches are not used in this branch.
SDK 5.30 already selects p256 0.14; near-crypto 0.38 permits fixed AWS-LC/TLS
versions. Their published packages remain registry dependencies.

The configured unpatched audit passed only because RUSTSEC-2026-0387 was
ignored. An isolated audit of the same lock/database with no exceptions failed
on crypto-bigint 0.5.5. This patch removes that old dependency and the exception.
No new audit ignore is introduced. Unmaintained warnings are a separate category.

## Recheck

```sh
cargo tree --locked -i crypto-bigint
cargo tree --locked -i near-vm-runner
python3 scripts/cargo-audit-no-git.py --output-dir /tmp/intents-security-audit
make check-all
make all
DEFUSE_MIGRATE_FROM_LEGACY=true make test
```

Use the root workspace and its lockfile. The audit helper retrieves a fresh
RustSec archive over HTTPS and uses `--no-fetch`, without Git writes.

When a compatible upstream near-vm-runner release uses the fixed dependency,
remove this patch after verifying the resolved graph, audit without exceptions,
native P-256 compatibility and wallet/WASM tests. Keep SDK/account-id 3.x migration
changes from upstream; do not restore the older SDK/nearcore patches.
