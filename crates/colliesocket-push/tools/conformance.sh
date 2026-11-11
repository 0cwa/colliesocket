#!/bin/sh
# No network after Cargo/Python dependencies are provisioned.
set -eu
crate_dir=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
fixture_dir=$(mktemp -d "${TMPDIR:-/tmp}/colliesocket-push.XXXXXX")
trap 'rm -rf -- "$fixture_dir"' EXIT HUP INT TERM
cargo test --locked --manifest-path "$crate_dir/Cargo.toml"
python3 "$crate_dir/tools/check_fixtures.py" "$crate_dir/fixtures"
cargo run --locked --manifest-path "$crate_dir/Cargo.toml" --example generate_fixtures -- "$fixture_dir"
cmp "$crate_dir/fixtures/rfc8291.bin" "$fixture_dir/rfc8291.bin"
cmp "$crate_dir/fixtures/wake-v1.bin" "$fixture_dir/wake-v1.bin"
cmp "$crate_dir/fixtures/wake-v1.json" "$fixture_dir/wake-v1.json"
python3 "$crate_dir/tools/check_fixtures.py" "$fixture_dir"
