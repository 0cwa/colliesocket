# Fresh local server verification — rebuild v2

This directory records a new verification run on 2026-11-10. It does not inherit
results from the earlier, unavailable workspace or from the initial debug-binary
integration run. Every command below ran against the formatted working tree
identified by `source-inputs.json`.

## Results

| Gate | Result | Evidence |
| --- | --- | --- |
| `cargo fmt --all` | PASS | `01-format.log` |
| `cargo fmt --all -- --check` | PASS | `02-format-check.log` |
| `cargo test --locked` | PASS: 56 passed, 0 failed, 2 ignored | `03-cargo-test.log` |
| `cargo build --release --locked` | PASS, Linux x86_64 | `04-release-build.log` |
| Actual release CLI and background worker | PASS: 14 scenario groups | `05-release-cli.log`, `cli-release.json` |
| Contract, crypto fixture, and generated protobuf preservation | PASS: hashes unchanged | `results.json` |
| Source stability between formatting and the end of verification | PASS | `source-inputs.json`, `results.json` |
| External Signal staging/public TLS probes | NOT RUN: explicitly ignored | `03-cargo-test.log` |
| Android connector, physical devices, lock states, and real distributor | NOT RUN | `results.json` |
| Real Signal credentials, production enrollment, and VAPID provider acceptance | NOT RUN | `results.json` |
| Container build/runtime, other architectures, and security audit | NOT RUN in this evidence pass | `results.json` |

The Rust test count covers the root server package. The separately locked sender
crate's standalone vector suite was not rerun by `cargo test --locked` at the
repository root. The release CLI suite independently decrypts actual randomized
Rust sender output using Python `cryptography`/OpenSSL and Python HMAC. It does
not invoke the Rust sender library as its decryption oracle.

The CLI suite covers protected file and pipe imports, size and file permission
checks, malformed keys, capability and downgrade refusal, atomic failure,
upstream schema migration, exact enrollment receipts, binary encrypted test and
wake events, fresh sender randomness, same-URL auth/epoch rotation, rejection of
old auth, stale endpoint recovery, account allowlist changes, receipt recovery
without current destination validation, bounded legacy mode, actual background
worker delivery attempts, private readiness, public enrollment refusal, trace
redaction, clean SIGTERM, and explicit local removal. A provider response does
not establish device delivery.

## Reproduction

Run on Linux from the repository root with the toolchain in
`rust-toolchain.toml`, a native C toolchain and OpenSSL development libraries,
and Python dependencies from
`crates/colliesocket-push/tools/requirements.txt`. The Python checker dependency
was already installed for this run; no package installation is claimed here.

```sh
cargo fmt --all
cargo fmt --all -- --check
cargo test --locked
cargo build --release --locked
python3 tests/server_cli.py --binary target/release/mollysocket
```

The recorded CLI command additionally used
`--output evidence/server-rebuild-v2/cli-release.json` to save its redacted
result. Use a different output path when preserving this evidence snapshot.
The harness creates private temporary directories and synthetic state, runs the
server with `push_only = true`, and binds its mock provider to loopback. A
writable `TMPDIR` can be supplied when the system temporary directory is absent.

`tool-versions.json` records the actual Rust, Cargo, rustfmt, Python, compiler,
linker, OpenSSL, and Python crypto versions. The observed release target was
`x86_64-unknown-linux-gnu`. Native dependency and toolchain differences can change
binary bytes; the hash below identifies the executable actually tested.

| Artifact | SHA-256 |
| --- | --- |
| `target/release/mollysocket` | `006311ec80e031bc6586110a441522f13e2dbf9f42562633c6c347486b91b887` |
| Root `Cargo.lock` | `9156abf0076451b56c5098acb0d1bf6f6e49800a3e6694f9bd33c0c7482c3243` |

## Source and evidence identity

`results.json` identifies the Git base commit and branch at execution. The base
commit is not represented as containing the tested uncommitted implementation.
`source-inputs.json` records SHA-256 values of the actual Rust sources, manifests,
test script, independent checker, contracts, and fixtures used by this run. The
server checkpoint can commit these exact bytes together with this evidence.
Later changes require their own verification record.

No contract or fixture was regenerated. The two generated protobuf modules were
excluded from formatting through their existing `#[rustfmt::skip]` annotations,
and their hashes were checked before and after the run.

Compiler output is preserved with only local absolute path normalization:
`<repo>` means the repository root, and `<toolchains>` means the local
toolchain/cache/temporary root. `results.json` describes the explicit environment
overrides. Logs contain no absolute scratch paths or runtime credentials. The
CLI result itself contains only synthetic test labels and aggregate results.

Check the committed evidence files from the repository root with:

```sh
sha256sum -c evidence/server-rebuild-v2/SHA256SUMS
```

`SHA256SUMS` covers every other file in this directory and intentionally does not
contain its own hash. The release executable is not committed in this evidence
directory; rebuild it using the recipe above.
