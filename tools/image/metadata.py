#!/usr/bin/env python3
"""Emit selected, public build facts; never dump Docker environment or credentials."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess

ROOT = Path(__file__).resolve().parents[2]


def sha256(path):
    result = hashlib.sha256()
    with Path(path).open("rb") as source:
        for block in iter(lambda: source.read(1024 * 1024), b""):
            result.update(block)
    return result.hexdigest()


def docker(*arguments):
    environment = dict(os.environ)
    for name in ("DOCKER_HOST", "DOCKER_CONTEXT", "DOCKER_TLS", "DOCKER_TLS_VERIFY", "DOCKER_CERT_PATH"):
        environment.pop(name, None)
    return subprocess.check_output(
        ["docker", "--host=unix:///var/run/docker.sock", *arguments],
        env=environment, stderr=subprocess.PIPE, timeout=30,
    )


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ("image", "platform", "source-commit", "source-date-epoch", "build-metadata", "archive", "output"):
        parser.add_argument("--" + name, required=True)
    args = parser.parse_args()
    if re.fullmatch(r"[0-9a-f]{40}", args.source_commit) is None or not args.source_date_epoch.isdecimal():
        raise SystemExit("Invalid source identity")
    image = json.loads(docker("image", "inspect", args.image))[0]
    actual_platform = image["Os"] + "/" + image["Architecture"]
    if actual_platform != args.platform:
        raise SystemExit("Built image architecture differs from requested architecture")
    labels = image["Config"].get("Labels") or {}
    if labels.get("org.opencontainers.image.revision") != args.source_commit:
        raise SystemExit("Built image source label mismatch")
    handoff = json.loads((ROOT / "handoff/parallel-start-v2.json").read_text())
    fixture_digest = sha256(ROOT / handoff["fixture_manifest_path"])
    if fixture_digest != handoff["fixture_manifest_sha256"]:
        raise SystemExit("Contract manifest differs from the launch pin")
    build_metadata = json.loads(Path(args.build_metadata).read_text())
    expected_configuration = build_metadata.get("containerimage.config.digest")
    if expected_configuration is not None and expected_configuration != image["Id"]:
        raise SystemExit("Loaded image configuration differs from the build output")
    pins = json.loads((ROOT / "images/base-pins.json").read_text())
    recipes = ["Containerfile.colliesocket", ".dockerignore", "images/base-pins.json"]
    recipes.extend(str(path.relative_to(ROOT)) for path in sorted((ROOT / "tools/image").glob("*")) if path.is_file())
    config = image["Config"]
    result = {
        "schema_version": 1, "result": "PASS", "scope": "image build only; see image-smoke.json",
        "source_commit": args.source_commit, "source_date_epoch": int(args.source_date_epoch),
        "contract_commit": handoff["contract_commit"], "contract_version": handoff["contract_version"],
        "fixture_manifest_sha256": fixture_digest,
        "recipe_path": "Containerfile.colliesocket", "recipe_sha256": sha256(ROOT / "Containerfile.colliesocket"),
        "recipe_inputs": [{"path": name, "sha256": sha256(ROOT / name)} for name in recipes],
        "platform_built": actual_platform,
        "image_configuration_digest": image["Id"],
        "image_manifest_digest": build_metadata.get("containerimage.digest"),
        "registry_digest": None, "registry_publication": "NOT RUN; not requested",
        "archive": {"filename": Path(args.archive).name, "sha256": sha256(args.archive)},
        "runtime": {"user": config["User"], "entrypoint": config["Entrypoint"], "command": config["Cmd"],
                    "working_directory": config["WorkingDir"], "healthcheck": config.get("Healthcheck"),
                    "exposed_ports": sorted((config.get("ExposedPorts") or {}).keys())},
        "base_indexes": [{"role": pin["role"], "reference": pin["repository"] + "@" + pin["index_digest"]}
                         for pin in pins["images"]],
        "buildx": docker("buildx", "version").decode().strip(),
        "not_run": ["byte-for-byte repeated image build", "Android or lock-state acceptance",
                    "real Signal or distributor", "deployment/system tests", "shipping security review"],
    }
    with Path(args.output).open("x", encoding="utf-8") as output:
        output.write(json.dumps(result, indent=2) + "\n")
    print(json.dumps({"result": "PASS", "platform_built": actual_platform,
                      "image_configuration_digest": image["Id"], "metadata": Path(args.output).name}))


if __name__ == "__main__":
    main()
