# Fresh candidate verification after logging hardening

This evidence records a new run on 2026-11-10 after restricting environment-controlled
logging to the server's `mollysocket` namespace. It does not reuse PASS results
from `evidence/server-rebuild-v2/`. That earlier evidence remains unchanged.

## Confirmed finding and change

The cached primary sources for `env_filter` 1.0.1 and `env_logger` 0.11.10 confirm
that the longest matching module prefix wins. A specific directive such as
`tungstenite::handshake::client=trace` therefore survives an appended
`tungstenite=off` rule. `logging-review.json` records the inspected source
commits, file hashes, and crate archive checksums verified against `Cargo.lock`.

The server now constructs `env_logger::Builder::new()` with a global Off default.
Its own parser accepts plain levels and validated `mollysocket` module selectors,
then inserts those directives through typed filter methods. Arbitrary environment
text never reaches env_logger's filter parser. A `log::Log` wrapper also enforces
the namespace boundary before checking or emitting records, including direct
calls to `log()` and lookalike targets such as `mollysocket_extra`.

Plain levels, application module filters, bare application module shorthand,
`-v`/`-vv`/`-vvv`, and `RUST_LOG_STYLE` remain supported. Verbosity adjusts the
application default; explicit application module filters retain their precedence.
Foreign module selectors, invalid directives, and regex filters are ignored
without echoing their contents. All dependency levels remain disabled.

## Fresh results

| Gate | Result | Record |
| --- | --- | --- |
| Format check | PASS | `01-format-check.log` |
| Full root server package tests | PASS: 60 passed, 0 failed, 2 ignored | `02-cargo-test.log` |
| Logger regressions within that full run | PASS: 4 tests | `logging-review.json`, `02-cargo-test.log` |
| Locked release rebuild | PASS, Linux x86_64 | `03-release-build.log` |
| Actual release CLI and worker | PASS: 14 scenario groups | `04-release-cli.log`, `cli-release.json` |
| Runtime/test source stability during the run | PASS | `results.json`, `source-inputs.json` |
| Contract, crypto fixture, generated protobuf, and prior evidence preservation | PASS | `results.json` |
| External Signal TLS probes | NOT RUN: explicitly ignored | `02-cargo-test.log` |
| Android, lock states, physical devices, real distributor, and real Signal authentication | NOT RUN | `results.json` |
| Production enrollment, VAPID provider acceptance, deployment, and security audit | NOT RUN | `results.json` |
| Container execution/build and other architectures | NOT RUN in this evidence pass | `results.json` |

The four regressions exercise specific dependency selectors at every logging
level, application filter and verbosity behavior, namespace lookalikes, and
actual writer output when dependency records are submitted directly. The release
CLI suite additionally supplies specific dependency trace selectors throughout
real loopback HTTP and worker operations, then checks all captured output for
synthetic endpoint, password, auth, and receiver-key canaries.

The 14 integration groups also cover protected imports, migrations, idempotency,
encryption and independently decrypted HTTP output, rotation, stale recovery,
allowlist revocation, private readiness, public enrollment refusal, legacy mode
bounds, clean shutdown, and local removal. Provider acceptance does not establish
device delivery. The root test command does not run the separately locked sender
crate's standalone vector tests; no additional vector-test claim is made here.

## Reproduction and identity

Run from the repository root on Linux with `rust-toolchain.toml`, the native C
toolchain/OpenSSL development libraries, and the Python verifier requirements in
`crates/colliesocket-push/tools/requirements.txt`:

```sh
cargo fmt --all -- --check
cargo test --locked
cargo build --release --locked
python3 tests/server_cli.py --binary target/release/mollysocket
```

The recorded integration invocation also saved `cli-release.json` through its
`--output` option. Use another output path when preserving this evidence. The
harness creates private temporary state and runs in `push_only` mode against a
loopback provider with public synthetic keys. Supply a writable `TMPDIR` if the
system temporary directory is absent. Actual tool versions and explicit
environment overrides are recorded; package installation is not claimed as a
step in this run.

| Input or output | SHA-256 |
| --- | --- |
| Tested release executable | `bdad2840cfd1d1b942b7560c66b2f96b688ba938061b1afe02de287b7d74dad7` |
| Root `Cargo.lock` | `9156abf0076451b56c5098acb0d1bf6f6e49800a3e6694f9bd33c0c7482c3243` |
| Source/input fingerprint file | `7c3352ed0fe96906c7355496b1d09c57161f7b53973375bfb74deebc990e8676` |

`results.json` identifies the published server-core base commit and states that
the tested working tree includes the subsequent logging fix. It does not claim
that the base commit already contains that fix. `source-inputs.json` binds the
tested runtime, tests, checker, contracts, and fixtures by SHA-256. Image recipes
and operator documentation are separately reviewed; this record makes no image
execution claim. Native build differences can change binary bytes, so the
executable digest identifies the particular output actually tested.

Logs replace local absolute roots with `<repo>` and `<toolchains>` as documented
in `results.json`. No absolute scratch paths or runtime credentials are included.
Check the evidence inventory from the repository root with:

```sh
sha256sum -c evidence/server-candidate-v2/SHA256SUMS
```

The inventory covers every other file in this directory and excludes its own
hash. The release executable is a local build output and is not committed here.
