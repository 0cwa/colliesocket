#!/usr/bin/env python3
"""Verify committed public registry evidence; --online also re-fetches exact pins."""
import argparse
import hashlib
import json
from pathlib import Path
import re
import urllib.parse
import urllib.request

ROOT = Path(__file__).resolve().parents[2]
ACCEPT = ", ".join([
    "application/vnd.oci.image.index.v1+json",
    "application/vnd.docker.distribution.manifest.list.v2+json",
])
EXPECTED = {
    "builder": "docker.io/library/rust",
    "runtime": "docker.io/library/debian",
    "frontend": "docker.io/docker/dockerfile",
    "buildkit": "docker.io/moby/buildkit",
}


def require(condition, message):
    if not condition:
        raise SystemExit("FAIL " + message)


def fetch(pin):
    repository = pin["repository"].removeprefix("docker.io/")
    query = urllib.parse.urlencode({"service": "registry.docker.io",
                                   "scope": "repository:" + repository + ":pull"})
    with urllib.request.urlopen("https://auth.docker.io/token?" + query, timeout=30) as response:
        token = json.load(response)["token"]
    request = urllib.request.Request(
        "https://registry-1.docker.io/v2/" + repository + "/manifests/" + pin["index_digest"],
        headers={"Authorization": "Bearer " + token, "Accept": ACCEPT},
    )
    with urllib.request.urlopen(request, timeout=30) as response:
        raw = response.read()
        require(response.headers.get("Docker-Content-Digest") == pin["index_digest"], "registry digest header")
    require("sha256:" + hashlib.sha256(raw).hexdigest() == pin["index_digest"], "registry body digest")
    return raw


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--online", action="store_true")
    args = parser.parse_args()
    pins = json.loads((ROOT / "images/base-pins.json").read_text())
    require({pin["role"] for pin in pins["images"]} == set(EXPECTED), "image roles")
    require(len(pins["images"]) == len(EXPECTED), "duplicate image role")
    recipe = (ROOT / "Containerfile.colliesocket").read_text()
    workflow = (ROOT / ".github/workflows/test.yml").read_text()
    for pin in pins["images"]:
        require(pin["repository"] == EXPECTED[pin["role"]], "official image repository")
        require(re.fullmatch(r"sha256:[0-9a-f]{64}", pin["index_digest"]) is not None, "digest syntax")
        path = ROOT / pin["manifest_file"]
        require(path.resolve().is_relative_to(ROOT / "images/registry-manifests"), "manifest path")
        raw = path.read_bytes()
        require("sha256:" + hashlib.sha256(raw).hexdigest() == pin["index_digest"], "committed registry body digest")
        document = json.loads(raw)
        expected_children = {
            item["platform"]["architecture"]: item["digest"] for item in pin["platforms"]
        }
        actual_children = {
            item["platform"]["architecture"]: item["digest"]
            for item in document["manifests"]
            if item.get("platform", {}).get("os") == "linux"
            and item["platform"].get("architecture") in ("amd64", "arm64")
        }
        require(set(expected_children) == {"amd64", "arm64"}, "intended architectures")
        require(expected_children == actual_children, "platform child pins")
        reference = pin["repository"] + ":" + pin["tag"] + "@" + pin["index_digest"]
        if pin["role"] == "frontend":
            reference = reference.removeprefix("docker.io/")
        require(reference in (workflow if pin["role"] == "buildkit" else recipe), "recipe image pin")
        if args.online:
            require(fetch(pin) == raw, "registry bytes differ from committed evidence")
    allowed_actions = {item["repository"]: item["commit"] for item in pins["actions"]}
    for repository, commit in re.findall(r"uses:\s+([A-Za-z0-9_./-]+)@([A-Za-z0-9_.-]+)", workflow):
        require(allowed_actions.get(repository) == commit, "unverified CI action pin")
        require(re.fullmatch("[0-9a-f]{40}", commit) is not None, "floating CI action")
    require(pins["buildx"]["version"] in workflow, "Buildx version pin")
    print(json.dumps({"result": "PASS", "registry_indexes": len(pins["images"]),
                      "architectures": ["linux/amd64", "linux/arm64"],
                      "online": args.online, "image_build": "NOT RUN"}, indent=2))


if __name__ == "__main__":
    main()
