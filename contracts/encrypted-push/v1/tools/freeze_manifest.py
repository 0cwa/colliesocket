#!/usr/bin/env python3
"""Contract owner only, after review: create a new manifest; never overwrite it."""
import hashlib
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
DEST = ROOT / "fixtures/manifest.json"
REQUIRED = ["README.md", "protocol.md", "runtime.md", "source-audit.md",
            "enrollment.schema.json", "event.schema.json", "response.schema.json",
            "fixtures/cases.json", "fixtures/receiver-cases.json"]
REQUIRED += ["fixtures/crypto/" + p for p in
             ("metadata.json", "rfc8291.bin", "wake-v1.bin", "wake-v1.json", "sender-random.bin")]


def main():
    if DEST.exists():
        raise SystemExit("Refusing to overwrite an immutable manifest")
    for name in REQUIRED:
        if not (ROOT / name).is_file():
            raise SystemExit("Missing reviewed input: " + name)
    files = []
    for path in sorted(ROOT.rglob("*")):
        if path.is_symlink():
            raise SystemExit("Refusing symlink in contract")
        if path.is_file() and "__pycache__" not in path.parts and path.suffix != ".pyc":
            files.append({"path": path.relative_to(ROOT).as_posix(),
                          "sha256": hashlib.sha256(path.read_bytes()).hexdigest()})
    manifest = {"manifest_version": 1, "contract_version": "encrypted-push/v1",
                "checkpoint_kind": "reconstructed-replacement", "synthetic_only": True, "files": files}
    with DEST.open("x", encoding="utf-8") as output:
        output.write(json.dumps(manifest, indent=2) + "\n")
    print("Created " + str(DEST.relative_to(ROOT)))
    print("sha256 " + hashlib.sha256(DEST.read_bytes()).hexdigest())


if __name__ == "__main__":
    main()
