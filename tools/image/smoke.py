#!/usr/bin/env python3
"""Image packaging smoke test only; no Signal, distributor, Android or deployment."""
import argparse
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import time
import uuid

NOT_RUN = ["real Signal or distributor", "Android/Keystore/lock acceptance",
           "deployment or combined-system tests", "shipping security review"]


class SmokeFailure(Exception):
    pass


def require(value, label):
    if not value:
        raise SmokeFailure(label)


def docker(*arguments, check=True, timeout=30):
    environment = dict(os.environ)
    for name in ("DOCKER_HOST", "DOCKER_CONTEXT", "DOCKER_TLS", "DOCKER_TLS_VERIFY", "DOCKER_CERT_PATH"):
        environment.pop(name, None)
    try:
        result = subprocess.run(["docker", "--host=unix:///var/run/docker.sock", *arguments],
                                env=environment, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                timeout=timeout, check=False)
    except subprocess.TimeoutExpired as error:
        raise SmokeFailure("local Docker operation timed out") from error
    if check:
        require(result.returncode == 0, "local Docker operation failed")
    return result


def inspect(kind, selector):
    return json.loads(docker(kind, "inspect", selector).stdout)[0]


def run(args, result):
    image = inspect("image", args.image)
    result["image_configuration_digest"] = image["Id"]
    actual_platform = image["Os"] + "/" + image["Architecture"]
    result["platform_tested"] = actual_platform
    require(actual_platform == args.platform, "requested image architecture")
    config = image["Config"]
    require(config["User"] == "10001:10001", "image UID/GID10001")
    require(config["Entrypoint"] == ["/usr/local/bin/mollysocket"], "compatible executable entrypoint")
    require(config["Cmd"] == ["server"], "default server command")
    require(not config.get("ExposedPorts"), "no declared public image ports")
    require(config.get("Healthcheck", {}).get("Test") == ["CMD", "/usr/local/bin/mollysocket", "ready"],
            "private CLI healthcheck")
    expected_env = {
        "MOLLY_DB": "/var/lib/colliesocket/mollysocket.db", "MOLLY_HOST": "127.0.0.1",
        "MOLLY_PORT": "8020", "MOLLY_WEBSERVER": "false", "MOLLY_READY_PORT": "8021",
    }
    actual_env = dict(item.split("=", 1) for item in config.get("Env", []) if "=" in item)
    require(all(actual_env.get(key) == value for key, value in expected_env.items()), "private image defaults")
    result["checks"].append("image metadata and private defaults")

    identifier = "colliesocket-smoke-" + uuid.uuid4().hex
    initializer = identifier + "-initialize"
    state = identifier + "-state"
    secrets = identifier + "-secrets"
    try:
        for volume in (state, secrets):
            docker("volume", "create", volume)
        base = ["--network", "none", "--read-only", "--cap-drop=ALL", "--security-opt=no-new-privileges"]
        state_mount = "type=volume,source=" + state + ",target=/var/lib/colliesocket"
        secrets_mount = "type=volume,source=" + secrets + ",target=/run/secrets/colliesocket"
        # Only synthetic, empty-account configuration is written. Both new
        # volumes inherit the image's UID10001-owned0700 mount directories.
        initialize = """set -eu
umask 077
test "$(id -u):$(id -g)" = 10001:10001
cat > /run/secrets/colliesocket/config.toml <<'CONFIG'
db = "/var/lib/colliesocket/mollysocket.db"
host = "127.0.0.1"
port = 8020
ready_port = 8021
webserver = false
push_only = true
signal_env = "Staging"
allowed_uuids = []
allowed_endpoints = []
legacy_wake_until = 0
CONFIG
test "$(stat -c '%a:%u:%g' /run/secrets/colliesocket/config.toml)" = 600:10001:10001
test "$(stat -c '%a:%u:%g' /var/lib/colliesocket)" = 700:10001:10001
mollysocket -c /run/secrets/colliesocket/config.toml migrate
test "$(stat -c '%a:%u:%g' /var/lib/colliesocket/mollysocket.db)" = 600:10001:10001
test "$(readlink /usr/local/bin/colliesocket)" = mollysocket
"""
        docker("run", "--rm", "--name", initializer, *base, "--mount", state_mount, "--mount", secrets_mount,
               "--entrypoint", "/bin/sh", args.image, "-ec", initialize)
        result["checks"].append("UID10001 migration, state0700, DB0600, protected config0600 and alias")
        docker("run", "--detach", "--rm", "--name", identifier, *base,
               "--mount", state_mount, "--mount", secrets_mount + ",readonly",
               "--env", "MOLLY_CONF=/run/secrets/colliesocket/config.toml",
               "--env", "MOLLY_PUSH_ONLY=true", "--env", "MOLLY_WEBSERVER=false", args.image)
        deadline = time.monotonic() + 35
        while time.monotonic() < deadline:
            probe = docker("exec", identifier, "/usr/local/bin/colliesocket", "ready", check=False, timeout=5)
            if probe.returncode == 0:
                require(json.loads(probe.stdout) == {"ready": True}, "private readiness JSON")
                break
            time.sleep(0.5)
        else:
            raise SmokeFailure("private readiness did not become healthy")
        result["checks"].append("default server starts on read-only rootfs without network access")
        docker("exec", identifier, "/bin/sh", "-ec", """set -eu
test "$(id -u):$(id -g)" = 10001:10001
test ! -w /run/secrets/colliesocket/config.toml
test "$(stat -c '%a:%u:%g' /var/lib/colliesocket)" = 700:10001:10001
test "$(stat -c '%a:%u:%g' /var/lib/colliesocket/mollysocket.db)" = 600:10001:10001
""")
        sockets = docker("exec", identifier, "/bin/cat", "/proc/net/tcp", "/proc/net/tcp6").stdout.decode()
        listeners = [line.split()[1] for line in sockets.splitlines()
                     if len(line.split()) > 3 and line.split()[3] == "0A"]
        require("0100007F:1F55" in listeners, "readiness listens on127.0.0.1:8021")
        require(all(address == "0100007F:1F55" for address in listeners), "no non-private or discovery listener")
        result["checks"].append("read-only secret mount and loopback-only readiness listener")
        while time.monotonic() < deadline:
            state_info = inspect("container", identifier)
            if state_info["State"].get("Health", {}).get("Status") == "healthy":
                break
            time.sleep(0.5)
        else:
            raise SmokeFailure("Docker healthcheck did not become healthy")
        require(not state_info["NetworkSettings"].get("Ports"), "no mapped host ports")
        require(state_info["HostConfig"]["NetworkMode"] == "none", "network isolation")
        require(state_info["HostConfig"]["ReadonlyRootfs"] is True, "read-only root filesystem")
        result["checks"].append("Docker healthcheck passes with no host port publication")
    finally:
        # A timed-out Docker CLI may already have created its object. Names are
        # unique to this invocation; attempt every cleanup even after a failure.
        cleanup_failed = False
        for kind, name in [("container", identifier), ("container", initializer),
                           ("volume", secrets), ("volume", state)]:
            try:
                remove = [kind, "rm"] + (["--force"] if kind == "container" else []) + [name]
                deleted = docker(*remove, check=False, timeout=10)
                if deleted.returncode != 0 and b"no such" not in deleted.stderr.lower():
                    cleanup_failed = True
            except (SmokeFailure, OSError):
                cleanup_failed = True
        result["cleanup"] = "FAIL" if cleanup_failed else "PASS"
        if cleanup_failed and sys.exc_info()[0] is None:
            raise SmokeFailure("temporary image test cleanup incomplete")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("image")
    parser.add_argument("--platform", required=True, choices=["linux/amd64", "linux/arm64"])
    parser.add_argument("--output", required=True)
    args = parser.parse_args()
    result = {"schema_version": 1, "result": "FAIL", "scope": "local image packaging smoke only",
              "checks": [], "not_run": NOT_RUN}
    exit_code = 1
    if shutil.which("docker") is None:
        result.update(result="NOT RUN", reason="Docker executable unavailable")
        exit_code = 77
    else:
        try:
            run(args, result)
            result["result"] = "PASS"
            exit_code = 0
        except (SmokeFailure, ValueError, KeyError, OSError) as error:
            result["reason"] = str(error) if isinstance(error, SmokeFailure) else "image smoke infrastructure failure"
    with Path(args.output).open("x", encoding="utf-8") as output:
        output.write(json.dumps(result, indent=2) + "\n")
    print(json.dumps(result, indent=2))
    sys.exit(exit_code)


if __name__ == "__main__":
    main()
