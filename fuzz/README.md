# Security fuzzing pilot

The three targets call the production enrollment parser and control-frame decoder through the `fuzzing` feature. `control_raw` exercises arbitrary frames; `control_authenticated` wraps bounded input in a frame authenticated with synthetic test credentials, and can tamper with the resulting frame. The targets do not read configuration, databases, network services, or credentials.

The tool versions are pinned in `rust-toolchain.toml`, this workspace's `Cargo.lock`, and the advisory workflow. From the repository root, run each command with a writable discovery directory first so fuzzing never adds generated inputs to the committed seed corpus:

```sh
rustup toolchain install nightly-2025-09-15 --profile minimal
cargo install cargo-fuzz --version 0.12.0 --locked
mkdir -p target/fuzz-cache/enrollment_parse target/fuzz-cache/control_raw target/fuzz-cache/control_authenticated
rustup run nightly-2025-09-15 cargo fuzz run enrollment_parse target/fuzz-cache/enrollment_parse fuzz/corpus/enrollment_parse -- -max_total_time=60 -timeout=5 -rss_limit_mb=2048 -max_len=8192
rustup run nightly-2025-09-15 cargo fuzz run control_raw target/fuzz-cache/control_raw fuzz/corpus/control_raw -- -max_total_time=60 -timeout=5 -rss_limit_mb=2048 -max_len=8192
rustup run nightly-2025-09-15 cargo fuzz run control_authenticated target/fuzz-cache/control_authenticated fuzz/corpus/control_authenticated -- -max_total_time=60 -timeout=5 -rss_limit_mb=2048 -max_len=8192
```

Committed corpora under `fuzz/corpus/` are small seed and regression inputs. The advisory workflow writes newly discovered corpus entries to a separate runner cache; it never updates the committed seeds. Preserve any crash input from `fuzz/artifacts/` with the source commit, `cargo fuzz --version`, exact target command, and reproduction result. Ordinary Rust tests replay the committed parser and decoder seeds through production code.

## Crash reproduction and regression seeds

Cargo-fuzz writes a crashing input to `fuzz/artifacts/<target>/`. Keep that file byte-for-byte and record the source commit, `cargo fuzz --version`, the exact discovery command, and the replay result. Reproduce a specific artifact with:

```sh
rustup run nightly-2025-09-15 cargo fuzz run <target> fuzz/artifacts/<target>/<artifact> -- -runs=1 -timeout=5 -rss_limit_mb=2048 -max_len=8192
```

Minimize a reproduced crash with:

```sh
rustup run nightly-2025-09-15 cargo fuzz tmin <target> fuzz/artifacts/<target>/<artifact>
```

Keep both original and minimized crash bytes as evidence. After fixing a finding, copy the minimized input byte-for-byte to a descriptive file in `fuzz/corpus/<target>/`. The ordinary Rust tests enumerate committed seed files and pass them through the same production parser or decoder entry points, so added regression seeds stay covered without invoking the fuzz engine.
