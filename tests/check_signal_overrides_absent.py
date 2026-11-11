#!/usr/bin/env python3
"""Verify a default or release executable contains no fake-Signal overrides.

Run against both `cargo build --locked` and
`cargo build --locked --release --all-features`, including releases with
`CARGO_PROFILE_RELEASE_DEBUG_ASSERTIONS=true`. No network is used.
"""

import argparse
import hashlib
import json
import os
from pathlib import Path
import subprocess
import tempfile


def check_binary(binary):
    executable = binary.read_bytes()
    markers = (
        b"test_signal_url", b"test_signal_ca", b"invalid_test_signal_configuration",
        b"MOLLY_TEST_SIGNAL_URL", b"MOLLY_TEST_SIGNAL_CA",
    )
    if any(marker in executable for marker in markers):
        raise ValueError("executable contains a test Signal override marker")
    checks = ["test URL, CA and validation markers absent from executable"]
    environment = {
        key: value for key, value in os.environ.items()
        if not key.startswith(("MOLLY_", "ROCKET_")) and key != "RUST_LOG"
    }
    with tempfile.TemporaryDirectory(prefix="colliesocket-signal-absent-") as temporary:
        directory = Path(temporary)
        config = directory / "config.toml"
        base = 'allowed_endpoints = ["http://127.0.0.1:9"]\n'
        for mode in ("config", "environment"):
            env = environment.copy()
            contents = base
            if mode == "config":
                # Wrong types must be ignored because these fields do not exist.
                contents += "test_signal_url = 7\ntest_signal_ca = true\n"
            else:
                env.update(
                    MOLLY_TEST_SIGNAL_URL="SYNTHETIC-INVALID-SIGNAL-URL",
                    MOLLY_TEST_SIGNAL_CA=str(directory / "SYNTHETIC-MISSING-CA.pem"),
                )
            config.write_text(contents)
            config.chmod(0o600)
            result = subprocess.run(
                [str(binary), "--config", str(config), "test", "endpoint", "http://127.0.0.1:9"],
                cwd=directory, env=env, capture_output=True, timeout=10, check=False,
            )
            if result.returncode != 0 or b"\nendpoint_valid\n" not in result.stdout:
                raise ValueError(f"test Signal {mode} settings affected normal configuration")
            if b"SYNTHETIC-" in result.stdout + result.stderr:
                raise ValueError("test configuration canary appeared in command output")
            checks.append(f"test Signal {mode} settings have no effect")
    return hashlib.sha256(executable).hexdigest(), checks


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--binary", required=True, type=Path)
    parser.add_argument("--output", type=Path, help="optional redacted JSON result path")
    arguments = parser.parse_args()
    result = {"result": "FAIL", "scope": "test Signal overrides absent", "checks": []}
    try:
        digest, checks = check_binary(arguments.binary.resolve())
        result.update(result="PASS", binary_sha256=digest, checks=checks, checks_passed=len(checks))
    except ValueError as failure:
        result["failure"] = str(failure)
    except (OSError, subprocess.SubprocessError) as failure:
        result["failure"] = type(failure).__name__
    rendered = json.dumps(result, indent=2) + "\n"
    if arguments.output:
        arguments.output.write_text(rendered)
        arguments.output.chmod(0o600)
    print(rendered, end="")
    return 0 if result["result"] == "PASS" else 1


if __name__ == "__main__":
    raise SystemExit(main())
