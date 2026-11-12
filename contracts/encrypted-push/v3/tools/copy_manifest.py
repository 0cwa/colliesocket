#!/usr/bin/env python3
"""Create deterministic v2/v3 copy manifests, excluding generated artifacts."""
import hashlib
import json
from pathlib import Path, PurePosixPath

ROOT = Path(__file__).resolve().parents[1]
BASE = ROOT.parent
TRANSIENT_DIRS = {
    "__pycache__", ".cache", ".pytest_cache", ".mypy_cache", ".ruff_cache",
    "tmp", "temp", ".tmp",
}
TRANSIENT_SUFFIXES = {".pyc", ".pyo", ".tmp", ".temp", ".swp", ".bak", ".orig"}
TRANSIENT_NAMES = {".ds_store", "thumbs.db"}


def canonical_paths(paths):
    """Return sorted POSIX paths after removing generated/cache/temp files."""
    result = []
    for path in paths:
        value = PurePosixPath(str(path).replace("\\", "/"))
        name = value.name.lower()
        if value.name == "copy-manifest.json":
            continue
        if any(part.lower() in TRANSIENT_DIRS for part in value.parts):
            continue
        if value.suffix.lower() in TRANSIENT_SUFFIXES or name in TRANSIENT_NAMES:
            continue
        if value.name.endswith("~") or (value.name.startswith("#") and value.name.endswith("#")):
            continue
        result.append(value.as_posix())
    return sorted(set(result))


def inventory(root):
    """List source and fixture files without cache or temporary artifacts."""
    root = Path(root)
    return canonical_paths(
        path.relative_to(root).as_posix()
        for path in root.rglob("*")
        if path.is_file()
    )


def make_manifest(version):
    root = BASE / f"v{version}"
    files = [
        {
            "path": relative,
            "sha256": hashlib.sha256((root / relative).read_bytes()).hexdigest(),
        }
        for relative in inventory(root)
    ]
    return {
        "manifest_version": 1,
        "contract_version": f"encrypted-push/v{version}",
        "files": files,
    }


def main():
    for version in (2, 3):
        root = BASE / f"v{version}"
        manifest = make_manifest(version)
        (root / "copy-manifest.json").write_text(
            json.dumps(manifest, indent=2) + "\n", encoding="utf-8"
        )
        print(f"wrote v{version} manifest with {len(manifest['files'])} files")


if __name__ == "__main__":
    main()
