#!/usr/bin/env python3
"""Run the real CollieSocket CLI and worker against a synthetic loopback provider.

Build first with `cargo build --locked`, then run `python3 tests/server_cli.py`.
The independent Python/OpenSSL decryptor is shared with the sender conformance
check; no sender-library roundtrip or real Signal/Android/distributor is used.
Only public RFC test keys and unmistakably synthetic credentials are used.
"""

import argparse
import base64
import copy
import hashlib
import http.client
import http.server
import importlib.util
import json
import os
from pathlib import Path
import queue
import socket
import sqlite3
import stat
import subprocess
import sys
import tempfile
import threading
import time
import uuid

ROOT = Path(__file__).resolve().parents[1]
ACCOUNT = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa"
OTHER_ACCOUNT = "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb"
LEGACY_ACCOUNT = "cccccccc-cccc-4ccc-8ccc-cccccccccccc"
PASSWORD = "SYNTHETIC-CLI-PASSWORD-REDACTION-CANARY"
ENDPOINT_PATH = "/SYNTHETIC-ENDPOINT-CANARY?token=SYNTHETIC-QUERY-CANARY"
NOT_RUN = [
    "real Signal connection or linked-device credentials",
    "Android connector, physical device, or lock-state acceptance",
    "real UnifiedPush distributor or deployment acceptance",
    "production enrollment, VAPID acceptance, or security audit",
]


class CheckFailure(Exception):
    """All messages are redacted test labels, never subprocess output."""


def require(condition, message):
    if not condition:
        raise CheckFailure(message)


def encoded(value):
    return base64.urlsafe_b64encode(value).decode().rstrip("=")


def compact(value):
    return json.dumps(value, separators=(",", ":")).encode()


def private_file(path, data):
    path.write_bytes(data)
    path.chmod(0o600)
    return path


def identifier(number):
    return f"00000000-0000-4000-8000-{number:012x}"


def fresh_port():
    with socket.socket() as listener:
        listener.bind(("127.0.0.1", 0))
        return listener.getsockname()[1]


def json_line(data):
    for line in reversed(data.decode(errors="replace").splitlines()):
        try:
            value = json.loads(line)
        except ValueError:
            continue
        if isinstance(value, dict):
            return value
    return None


class Provider:
    def __init__(self):
        self.requests = queue.Queue()
        self.statuses = queue.Queue()
        self.count = 0
        provider = self

        class Handler(http.server.BaseHTTPRequestHandler):
            protocol_version = "HTTP/1.1"

            def do_POST(self):
                length = int(self.headers.get("Content-Length", "0"))
                if not 0 <= length <= 4096:
                    self.send_error(413)
                    return
                body = self.rfile.read(length)
                headers = {key.lower(): value for key, value in self.headers.items()}
                provider.count += 1
                provider.requests.put((self.path, headers, body))
                try:
                    status = provider.statuses.get_nowait()
                except queue.Empty:
                    status = 202
                self.send_response(status)
                self.send_header("Content-Length", "0")
                self.send_header("Connection", "close")
                self.end_headers()

            def log_message(self, *_):
                pass

        self.server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        self.server.daemon_threads = True
        self.origin = f"http://127.0.0.1:{self.server.server_port}"
        self.thread = threading.Thread(
            target=lambda: self.server.serve_forever(poll_interval=0.05), daemon=True
        )
        self.thread.start()

    def take(self, timeout=5):
        try:
            return self.requests.get(timeout=timeout)
        except queue.Empty as error:
            raise CheckFailure("expected a synthetic loopback provider request") from error

    def close(self):
        self.server.shutdown()
        self.server.server_close()
        self.thread.join(timeout=2)


class Harness:
    def __init__(self, directory, binary, provider, checker, metadata):
        self.directory = directory
        self.binary = binary
        self.provider = provider
        self.checker = checker
        self.metadata = metadata
        self.private = checker.secret(metadata["receiver_private"])
        self.auth = checker.b64(metadata["auth"])
        self.new_auth = bytes(range(16))
        self.recovered_auth = bytes([85] * 16)
        self.checks = []
        self.outputs = []
        self.stage = "initialization"
        self.worker = None
        self.worker_files = None
        self.db = directory / "state" / "mollysocket.db"
        self.config_serial = 0
        self.config = self.make_config()
        self.env = {
            key: value
            for key, value in os.environ.items()
            if not key.startswith(("MOLLY_", "ROCKET_")) and key != "RUST_LOG"
        }
        # Long dependency selectors used to override later base-module Off
        # rules. Exercise real HTTP/worker paths with that configuration too.
        self.env["RUST_LOG"] = ",".join([
            "trace", "mollysocket=trace", "reqwest::async_impl::client=trace",
            "reqwest::connect=trace", "hyper::proto::h1::io=trace",
            "hyper_util::client::legacy::connect::http=trace", "h2::proto::streams=trace",
            "rustls::client::hs=trace", "tungstenite::handshake::client=trace",
            "tungstenite::protocol=trace", "tokio_tungstenite::compat=trace",
            "trust_dns_resolver::name_server=trace", "rocket::server=trace",
        ])
        self.env["TMPDIR"] = str(directory)
        self.enrollment = json.loads(
            (ROOT / "contracts/encrypted-push/v1/fixtures/enrollment-valid.json").read_text()
        )
        self.enrollment.update(account_id=ACCOUNT, password=PASSWORD, request_id=identifier(1))
        self.enrollment["subscription"].update(
            endpoint=provider.origin + ENDPOINT_PATH,
            instance="cli-fixture-instance",
            p256dh=metadata["p256dh"],
            auth=metadata["auth"],
        )

    def mark(self, label):
        self.checks.append(label)

    def make_config(self, **overrides):
        values = {
            "db": str(self.db),
            "host": "127.0.0.1",
            "port": 8020,
            "ready_port": 8021,
            "webserver": False,
            "push_only": True,
            "signal_env": "Staging",
            "allowed_uuids": ["*"],
            "allowed_endpoints": [self.provider.origin],
            "legacy_wake_until": 0,
        }
        values.update(overrides)
        self.config_serial += 1
        path = self.directory / f"config-{self.config_serial}.toml"
        return private_file(
            path, "".join(f"{key} = {json.dumps(value)}\n" for key, value in values.items()).encode()
        )

    def cli(self, *arguments, config=None, data=None, error=None, plain_error=None, raw=False):
        command = [str(self.binary), "--config", str(config or self.config), *arguments]
        try:
            result = subprocess.run(
                command, input=data, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                cwd=self.directory, env=self.env, timeout=15, check=False,
            )
        except subprocess.TimeoutExpired as failure:
            raise CheckFailure(f"{self.stage}: CLI exceeded 15-second test bound") from failure
        self.outputs.extend([result.stdout, result.stderr])
        if error is not None:
            value = json_line(result.stderr)
            observed = value.get("error") if value else "no-json-error"
            require(result.returncode != 0, f"{self.stage}: rejected operation unexpectedly succeeded")
            require(observed == error, f"{self.stage}: expected {error}, received {observed}")
            return value
        if plain_error is not None:
            require(result.returncode != 0, f"{self.stage}: invalid configuration succeeded")
            require(plain_error.encode() in result.stderr, f"{self.stage}: missing fixed configuration error")
            return None
        require(result.returncode == 0, f"{self.stage}: CLI failed ({(json_line(result.stderr) or {}).get('error', 'no-json-error')})")
        if raw:
            return result.stdout
        value = json_line(result.stdout)
        require(value is not None, f"{self.stage}: missing JSON CLI response")
        return value

    def import_value(self, value, **options):
        return self.cli("enrollment", "import", "--stdin", data=compact(value), **options)

    def rows(self, query, parameters=(), database=None):
        with sqlite3.connect(database or self.db) as connection:
            return connection.execute(query, parameters).fetchall()

    def snapshot(self):
        with sqlite3.connect(self.db) as connection:
            tables = connection.execute(
                "SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%' ORDER BY name"
            ).fetchall()
            contents = [
                (name, connection.execute(f'SELECT * FROM "{name}" ORDER BY rowid').fetchall())
                for (name,) in tables
            ]
        return hashlib.sha256(repr(contents).encode()).hexdigest()

    def queued(self):
        return self.rows("SELECT count(*) FROM encrypted_push_queue")[0][0]

    def current(self):
        return self.cli("enrollment", "status", ACCOUNT)

    def drain(self):
        return self.cli("push", "drain", "--once")

    def capture_event(self, queued, kind, epoch, auth, timeout=5):
        path, headers, body = self.provider.take(timeout)
        require(path == ENDPOINT_PATH, "provider endpoint changed unexpectedly")
        require(len(body) == 4096 and int.from_bytes(body[16:20], "big") == 4096,
                "encrypted body must be binary4096 with standard rs4096")
        require(body[20] == 65 and body[21] == 4, "encrypted body has invalid sender-key framing")
        require(headers.get("content-type") == "application/octet-stream", "missing binary media type")
        require(headers.get("content-encoding") == "aes128gcm", "missing standard content encoding")
        require(headers.get("content-length") == "4096", "incorrect encrypted Content-Length")
        require(headers.get("urgency") == "normal", "unexpected clear urgency")
        require(1 <= int(headers.get("ttl", "0")) <= 300, "unbounded HTTP TTL")
        require("topic" not in headers, "encrypted events must not expose Topic")
        clear_headers = json.dumps(headers)
        for marker in [PASSWORD, self.metadata["auth"], self.metadata["p256dh"], ACCOUNT, "cli-fixture-instance"]:
            require(marker not in clear_headers, "sensitive event material appeared in a clear header")
        plaintext = self.checker.decrypt(body, self.private, auth)
        require(len(plaintext) == 3993, "application padding is not fixed length")
        compact_json = plaintext.rstrip(b" ")
        require(len(compact_json) <= 3072 and plaintext == compact_json.ljust(3993, b" "),
                "application JSON or trailing-space padding violates profile")
        event = json.loads(compact_json)
        require(set(event) == {"version", "event_id", "instance", "subscription_epoch", "kind", "issued_at", "expires_at"},
                "wake/test event contains unexpected fields")
        require(event["version"] == 1 and event["subscription_epoch"] == epoch, "event version or epoch mismatch")
        require(event["instance"] == "cli-fixture-instance" and event["kind"] == kind, "event kind or instance mismatch")
        require(event["event_id"] == queued["event_id"], "queue receipt and ciphertext event ID differ")
        event_id = uuid.UUID(event["event_id"])
        require(event_id.version == 4 and str(event_id) == event["event_id"], "event ID is not a canonical UUIDv4")
        require(type(event["issued_at"]) is int and type(event["expires_at"]) is int, "event times must be JSON integers")
        require(event["expires_at"] - event["issued_at"] == 300, "event lifetime is not bounded300 seconds")
        require(abs(event["issued_at"] - int(time.time())) <= 60, "event issuance clock exceeds profile tolerance")
        return body

    def migrations(self):
        self.stage = "migration and protected state modes"
        require(self.cli("migrate") == {"schema_version": 3}, "migration did not select schema3")
        require(stat.S_IMODE(self.db.parent.stat().st_mode) == 0o700, "state directory is not0700")
        require(stat.S_IMODE(self.db.stat().st_mode) == 0o600, "state database is not0600")
        require(self.rows("PRAGMA user_version") == [(3,)], "SQLite schema marker differs from CLI")
        require(self.cli("migrate") == {"schema_version": 3}, "migration is not idempotent")
        before = self.snapshot()
        self.db.chmod(0o644)
        try:
            self.cli("migrate", error="unsafe_file")
        finally:
            self.db.chmod(0o600)
        self.db.parent.chmod(0o755)
        try:
            self.cli("migrate", error="unsafe_file")
        finally:
            self.db.parent.chmod(0o700)
        link = self.db.parent / "symlink.db"
        link.symlink_to(self.db)
        self.cli("migrate", config=self.make_config(db=str(link)), error="unsafe_file")
        require(self.snapshot() == before, "mode rejection changed persistent state")
        self.mark("fresh/idempotent migration;0700directory0600database;unsafe modes and state symlink rejected")

        for version in [0, 1, 99]:
            directory = self.directory / f"old-schema-{version}"
            directory.mkdir(mode=0o700)
            database = private_file(directory / "state.db", b"")
            original = (OTHER_ACCOUNT, 2, PASSWORD, "https://fixture.example.invalid/legacy", 1, 123)
            with sqlite3.connect(database) as connection:
                connection.execute("CREATE TABLE connections(uuid TEXT UNIQUE ON CONFLICT REPLACE,device_id INTEGER,password TEXT,endpoint TEXT,forbidden BOOLEAN NOT NULL CHECK(forbidden IN(0,1)),last_registration INTEGER)")
                connection.execute("INSERT INTO connections VALUES(?,?,?,?,?,?)", original)
                connection.execute(f"PRAGMA user_version={version}")
            config = self.make_config(db=str(database))
            if version == 99:
                self.cli("migrate", config=config, error="state_unavailable")
                require(self.rows("PRAGMA user_version", database=database) == [(99,)], "future schema was downgraded")
            else:
                require(self.cli("migrate", config=config) == {"schema_version": 3}, "upstream schema migration failed")
            require(self.rows("SELECT * FROM connections", database=database) == [original], "migration changed legacy credentials or forbidden state")
        self.mark("upstream schemas0/1 preserve connection tuple and forbidden flag;future schema fails closed")

    def protected_imports(self):
        self.stage = "protected import and malformed enrollment"
        before = self.snapshot()
        path = private_file(self.directory / "enrollment.json", compact(self.enrollment))
        path.chmod(0o644)
        self.cli("enrollment", "import", "--file", str(path), error="unsafe_file")
        path.chmod(0o600)
        link = self.directory / "enrollment-link.json"
        link.symlink_to(path)
        self.cli("enrollment", "import", "--file", str(link), error="unsafe_file")
        hardlink = self.directory / "enrollment-hardlink.json"
        os.link(path, hardlink)
        self.cli("enrollment", "import", "--file", str(hardlink), error="unsafe_file")
        hardlink.unlink()
        fifo = self.directory / "enrollment-fifo"
        os.mkfifo(fifo, 0o600)
        self.cli("enrollment", "import", "--file", str(fifo), error="unsafe_file")
        for data, error in [(b"x" * 8193, "input_too_large"), (b"\xff", "invalid_json"), (b"{}", "invalid_enrollment")]:
            self.cli("enrollment", "import", "--stdin", data=data, error=error)
        oversized = private_file(self.directory / "oversize.json", b" " * 8193)
        self.cli("enrollment", "import", "--file", str(oversized), error="input_too_large")
        mutations = [
            ({"auth": encoded(bytes(15))}, "invalid_key"),
            ({"auth": self.metadata["auth"] + "="}, "invalid_key"),
            ({"p256dh": encoded(b"\4" + bytes(64))}, "invalid_key"),
            ({"p256dh": encoded(b"\3" + bytes(64))}, "invalid_key"),
            ({"p256dh": self.metadata["p256dh"][:-1]}, "invalid_key"),
            ({"supported_event_versions": [2]}, "unsupported_version"),
            ({"capabilities": ["wake", "test"]}, "capability_required"),
            ({"capabilities": ["test", "wake", "status"]}, "capability_required"),
            ({"encryption_required": False}, "encryption_required"),
        ]
        for changed, error in mutations:
            value = copy.deepcopy(self.enrollment)
            value["subscription"].update(changed)
            self.import_value(value, error=error)
            require(self.snapshot() == before, "invalid enrollment partially changed durable state")
        require(self.snapshot() == before, "unsafe import partially changed durable state")
        self.mark("file/stdin bounds;symlink/hardlink/FIFO/mode refusal;malformed keys/capabilities/downgrade leave no partial state")

        self.receipt = self.cli("enrollment", "import", "--file", str(path))
        expected = {
            "enrollment_version": 1, "request_id": self.enrollment["request_id"],
            "instance": "cli-fixture-instance", "subscription_epoch": 1,
            "selected_event_version": 1, "capabilities": ["wake", "test", "status"], "status": "accepted",
        }
        require(self.receipt == expected, "accepted enrollment receipt differs from contract")
        registered = self.snapshot()
        require(self.import_value(self.enrollment) == self.receipt, "identical request receipt changed")
        require(self.snapshot() == registered, "identical receipt replay changed state")
        conflict = copy.deepcopy(self.enrollment)
        conflict["subscription"]["auth"] = encoded(self.new_auth)
        self.import_value(conflict, error="idempotency_conflict")
        require(self.snapshot() == registered, "conflicting request reused its ID with partial state")
        require(self.current()["state"] == "active", "successful import is not active")
        self.mark("protected file acceptance and pipe replay;exact receipt/version/capabilities;request-ID conflict is atomic")

    def encrypted_events_and_rotation(self):
        self.stage = "real encrypted HTTP dispatch and same-URL rotation"
        self.provider.statuses.put(201)
        first = self.cli("push", "test", ACCOUNT)
        require(first.get("queued") is True and self.drain() == {"processed": True}, "test event was not processed")
        first_body = self.capture_event(first, "test", 1, self.auth)
        second = self.cli("push", "wake", ACCOUNT)
        require(self.drain() == {"processed": True}, "wake event was not processed")
        second_body = self.capture_event(second, "wake", 1, self.auth)
        require(first_body[:16] != second_body[:16] and first_body[21:86] != second_body[21:86], "sender reused salt or ephemeral public key")
        require(self.queued() == 0 and self.current()["state"] == "active", "provider acceptance changed registration state or retained delivered attempt")
        require(set(first) == {"event_id", "queued"}, "queue receipt incorrectly implies device delivery")
        self.mark("real test/wake POST binary4096;standard headers/noTopic;independent OpenSSL decrypt;fresh salt/key;no device-delivery claim")

        self.cli("push", "wake", ACCOUNT)
        require(self.queued() == 1, "rotation precondition did not create old-epoch queue")
        self.rotated = copy.deepcopy(self.enrollment)
        self.rotated["request_id"] = identifier(2)
        self.rotated["subscription"].update(subscription_epoch=2, auth=encoded(self.new_auth))
        self.rotated_receipt = self.import_value(self.rotated)
        require(self.rotated_receipt["subscription_epoch"] == 2 and self.queued() == 0, "same-URL auth rotation did not advance epoch and purge queue")
        require(self.drain() == {"processed": False}, "old epoch survived rotation")
        require(self.import_value(self.enrollment) == self.receipt, "old idempotency receipt was not retained")
        require(self.current()["subscription_epoch"] == 2, "old receipt reverted active epoch")
        stale_epoch = copy.deepcopy(self.rotated)
        stale_epoch["request_id"] = identifier(3)
        stale_epoch["subscription"]["subscription_epoch"] = 1
        self.import_value(stale_epoch, error="epoch_conflict")
        third = self.cli("push", "wake", ACCOUNT)
        self.drain()
        third_body = self.capture_event(third, "wake", 2, self.new_auth)
        self.checker.must_reject(lambda: self.checker.decrypt(third_body, self.private, self.auth), "old-auth-after-rotation")
        self.mark("same-URL auth/epoch rotation purges old queue;old receipt cannot roll back;old auth cannot decrypt new event")

    def stale_and_recovery(self):
        self.stage = "stale endpoint and authenticated recovery"
        original = self.rows("SELECT * FROM connections WHERE uuid=?", (ACCOUNT,))
        self.provider.statuses.put(410)
        queued = self.cli("push", "wake", ACCOUNT)
        self.drain()
        self.capture_event(queued, "wake", 2, self.new_auth)
        require(self.current()["state"] == "stale", "HTTP410 did not mark subscription stale")
        require(self.rows("SELECT * FROM connections WHERE uuid=?", (ACCOUNT,)) == original, "provider410 modified Signal connection")
        require(original[0][4] == 0 and self.queued() == 0, "provider410 forbade Signal credentials or retained queue")
        self.cli("push", "wake", ACCOUNT, error="subscription_inactive")
        require(self.import_value(self.rotated) == self.rotated_receipt, "stale request replay changed original receipt")
        require(self.current()["state"] == "stale", "old receipt reactivated stale subscription")
        same_epoch = copy.deepcopy(self.rotated)
        same_epoch["request_id"] = identifier(4)
        self.import_value(same_epoch, error="epoch_conflict")
        self.recovered = copy.deepcopy(self.rotated)
        self.recovered["request_id"] = identifier(5)
        self.recovered["subscription"].update(subscription_epoch=3, auth=encoded(self.recovered_auth))
        self.import_value(self.recovered)
        require(self.current()["state"] == "active" and self.current()["subscription_epoch"] == 3, "next-epoch protected import did not recover stale endpoint")
        require(self.rows("SELECT forbidden FROM connections WHERE uuid=?", (ACCOUNT,)) == [(0,)], "recovery changed unrelated Signal forbidden state")
        self.mark("HTTP410 stops push without unlink/forbid;old request/same epoch cannot reactivate;next epoch recovers")

    def authorization_and_receipts(self):
        self.stage = "account allowlist and receipt recovery without destination revalidation"
        self.cli("push", "wake", ACCOUNT)
        sent = self.provider.count
        narrow = self.make_config(allowed_uuids=[OTHER_ACCOUNT])
        require(self.cli("push", "drain", "--once", config=narrow) == {"processed": True}, "revoked queued item was not consumed")
        require(self.provider.count == sent and self.queued() == 0, "revoked account reached provider")
        self.cli("push", "wake", ACCOUNT, config=narrow, error="invalid_enrollment")
        self.cli("connection", "ping", ACCOUNT, config=narrow, error="invalid_enrollment")
        self.import_value(self.recovered, config=narrow, error="invalid_enrollment")
        require(self.provider.count == sent, "revoked new operation reached provider")
        self.mark("narrow account allowlist blocks existing queue,new wake/ping,and enrollment receipt access")

        receipt_only = copy.deepcopy(self.enrollment)
        receipt_only.update(account_id=OTHER_ACCOUNT, request_id=identifier(6))
        receipt_only["subscription"]["endpoint"] = "https://receipt.example.invalid/SYNTHETIC-RECEIPT-CANARY"
        initial_config = self.make_config(allowed_endpoints=["https://receipt.example.invalid/"])
        receipt = self.import_value(receipt_only, config=initial_config)
        # An explicit origin permits initial import without DNS. Empty current
        # policy rejects all new destinations, yet recovery of the same stored
        # receipt needs neither DNS nor endpoint authorization and changes no state.
        denied_config = self.make_config(allowed_endpoints=[])
        before = self.snapshot()
        require(self.import_value(receipt_only, config=denied_config) == receipt, "stored receipt depended on current destination availability/policy")
        require(self.snapshot() == before, "receipt-only recovery mutated state")
        receipt_only["request_id"] = identifier(7)
        self.import_value(receipt_only, config=denied_config, error="invalid_endpoint")
        self.cli("connection", "remove", OTHER_ACCOUNT)
        self.mark("stored receipt recovery bypasses unavailable .invalid destination/current destination policy;new request remains denied")

    def legacy_boundaries(self):
        self.stage = "explicit bounded legacy wake and downgrade refusal"
        arguments = ("connection", "add", LEGACY_ACCOUNT, "2", PASSWORD, self.provider.origin + ENDPOINT_PATH)
        self.cli(*arguments, error="legacy_disabled")
        expired = self.make_config(legacy_wake_until=int(time.time()) - 1)
        self.cli(*arguments, config=expired, error="legacy_disabled")
        too_long = self.make_config(legacy_wake_until=int(time.time()) + 90_000)
        self.cli("migrate", config=too_long, plain_error="invalid_legacy_deadline")
        allowed = self.make_config(legacy_wake_until=int(time.time()) + 60)
        self.cli("connection", "add", ACCOUNT, "2", PASSWORD, self.provider.origin + ENDPOINT_PATH,
                 config=allowed, error="encryption_required")
        require(self.cli(*arguments, config=allowed) == {"registered": True, "mode": "legacy_wake"}, "explicit legacy registration failed")
        _, headers, body = self.provider.take()
        require(body == b'{"urgent":true}' and headers.get("content-type") == "application/json", "legacy mode gained richer caller-selected content")
        require("content-encoding" not in headers and "topic" not in headers and int(headers["ttl"]) <= 300,
                "legacy mode falsely advertises encryption or has unbounded TTL")
        self.cli("connection", "remove", LEGACY_ACCOUNT)
        self.cli("qr-code", "airgapped", error="legacy_disabled")
        self.cli("qr-code", "url", "https://discovery.example.invalid/", config=allowed, error="legacy_disabled")
        self.mark("legacy disabled/expired/overlong gates;explicit fixed wake only;encrypted account cannot downgrade;edge QR enrollment refused")

    def http(self, port, method, path, body=None):
        connection = http.client.HTTPConnection("127.0.0.1", port, timeout=1)
        try:
            connection.request(method, path, body=body, headers={"Content-Type": "application/json"} if body else {})
            response = connection.getresponse()
            return response.status, response.read()
        finally:
            connection.close()

    def worker_and_discovery(self):
        self.stage = "push-only worker and private readiness/discovery"
        public_port, ready_port = fresh_port(), fresh_port()
        while ready_port == public_port:
            ready_port = fresh_port()
        config = self.make_config(webserver=True, port=public_port, ready_port=ready_port)
        stdout = (self.directory / "worker.stdout").open("w+b")
        stderr = (self.directory / "worker.stderr").open("w+b")
        self.worker_files = (stdout, stderr)
        self.worker = subprocess.Popen(
            [str(self.binary), "--config", str(config), "server"],
            cwd=self.directory, env=self.env, stdin=subprocess.DEVNULL, stdout=stdout, stderr=stderr,
        )
        deadline = time.monotonic() + 10
        ready = False
        while time.monotonic() < deadline:
            require(self.worker.poll() is None, "push-only worker exited before readiness")
            try:
                status, body = self.http(ready_port, "GET", "/readyz")
                public_status, _ = self.http(public_port, "GET", "/discover")
                ready = status == 200 and json.loads(body) == {"ready": True} and public_status == 200
                if ready:
                    break
            except (OSError, ValueError, http.client.HTTPException):
                pass
            time.sleep(0.05)
        require(ready, "private readiness and discovery did not become healthy")
        require(self.cli("ready", config=config) == {"ready": True}, "private CLI readiness probe failed")
        # Linux is the supported runtime. Verify the actual listening address,
        # not merely that a request to loopback happened to succeed.
        with open("/proc/net/tcp", encoding="ascii") as sockets:
            bound = [line.split()[1].split(":")[0] for line in sockets.readlines()[1:]
                     if line.split()[1].endswith(f":{ready_port:04X}") and line.split()[3] == "0A"]
        require(bound == ["0100007F"], "readiness listener is not exclusively127.0.0.1")
        require(self.http(public_port, "GET", "/readyz")[0] == 404, "readiness leaked to discovery listener")
        discovery_status, discovery = self.http(public_port, "GET", "/discover")
        require(discovery_status == 200 and json.loads(discovery)["colliesocket"]["enrollment"] == "private_import", "discovery does not advertise private enrollment")
        page_status, page = self.http(public_port, "GET", "/")
        require(page_status == 200 and b"protected private import" in page, "discovery page lacks private-import guidance")
        require(all(marker not in page.lower() for marker in [b"<svg", b"<img", b"mollysocket://", b"qrcode"]), "public discovery exposes QR enrollment")
        before = self.snapshot()
        require(self.http(public_port, "POST", "/", compact(self.enrollment))[0] == 404, "public HTTP accepted enrollment credentials")
        require(self.snapshot() == before, "public HTTP modified enrollment state")
        self.mark("real push-only server;readiness bound127.0.0.1;CLI probe;public ready404/POST404;discovery has no QR credential path")

        queued = self.cli("push", "wake", ACCOUNT)
        self.capture_event(queued, "wake", 3, self.recovered_auth, timeout=5)
        deadline = time.monotonic() + 5
        while self.queued() and time.monotonic() < deadline:
            time.sleep(0.02)
        require(self.queued() == 0, "worker did not complete provider acceptance")
        self.stop_worker()
        self.mark("actual background worker sends independently decrypted wake;SIGTERM exits cleanly")

    def stop_worker(self):
        if self.worker is None:
            return
        worker, self.worker = self.worker, None
        if worker.poll() is None:
            worker.terminate()
        try:
            returncode = worker.wait(timeout=5)
        except subprocess.TimeoutExpired:
            worker.kill()
            worker.wait(timeout=5)
            returncode = -1
        for stream in self.worker_files:
            stream.seek(0)
            self.outputs.append(stream.read())
            stream.close()
        self.worker_files = None
        require(returncode == 0, "push-only server did not shut down cleanly")

    def redaction_and_removal(self):
        self.stage = "trace redaction and explicit local removal"
        self.cli("connection", "list")
        self.cli("test", "endpoint", self.provider.origin + ENDPOINT_PATH, raw=True)
        joined = b"\n".join(self.outputs)
        canaries = [
            PASSWORD, "SYNTHETIC-ENDPOINT-CANARY", "SYNTHETIC-QUERY-CANARY",
            "SYNTHETIC-RECEIPT-CANARY", self.metadata["auth"], self.metadata["p256dh"],
            self.metadata["receiver_private"], encoded(self.new_auth), encoded(self.recovered_auth),
        ]
        require(all(marker.encode() not in joined for marker in canaries), "CLI or worker trace output exposed a synthetic secret canary")
        self.mark("trace plus specific dependency selectors cannot expose endpoint,password,auth,or receiver-key canaries in CLI/worker output")
        sent = self.provider.count
        require(self.cli("connection", "remove", ACCOUNT) == {"removed": True, "signal_unlinked": False}, "local removal implies Signal unlink")
        require(self.cli("connection", "remove", ACCOUNT) == {"removed": False, "signal_unlinked": False}, "local removal is not idempotent")
        require(self.rows("SELECT count(*) FROM connections") == [(0,)] and self.queued() == 0, "local removal retained account or queue")
        self.cli("enrollment", "status", ACCOUNT, error="not_found")
        require(self.provider.count == sent, "local removal unexpectedly contacted provider")
        self.mark("explicit idempotent local removal clears state and reports signal_unlinkedfalse")

    def run(self):
        self.migrations()
        self.protected_imports()
        self.encrypted_events_and_rotation()
        self.stale_and_recovery()
        self.authorization_and_receipts()
        self.legacy_boundaries()
        self.worker_and_discovery()
        self.redaction_and_removal()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--binary", type=Path, default=ROOT / "target/debug/mollysocket")
    parser.add_argument("--output", type=Path, help="optional redacted JSON result path")
    arguments = parser.parse_args()
    binary = arguments.binary.resolve()
    if not binary.is_file():
        parser.error("build the server first with cargo build --locked")
    checker_path = ROOT / "crates/colliesocket-push/tools/check_fixtures.py"
    module = importlib.util.spec_from_file_location("independent_push_checker", checker_path)
    checker = importlib.util.module_from_spec(module)
    module.loader.exec_module(checker)
    metadata = json.loads((ROOT / "crates/colliesocket-push/fixtures/metadata.json").read_text())
    require(metadata.get("synthetic") is True, "this test permits only public synthetic fixtures")
    previous_umask = os.umask(0o077)
    result = {
        "result": "FAIL", "scope": "synthetic server CLI and loopback worker; not device/deployment acceptance",
        "binary_sha256": hashlib.sha256(binary.read_bytes()).hexdigest(),
        "python": sys.version.split()[0], "cryptography": checker.cryptography.__version__,
        "openssl": checker.backend.openssl_version_text(), "checks": [], "not_run": NOT_RUN,
    }
    provider = Provider()
    try:
        with tempfile.TemporaryDirectory(prefix="colliesocket-cli-") as temporary:
            directory = Path(temporary)
            directory.chmod(0o700)
            harness = Harness(directory, binary, provider, checker, metadata)
            try:
                harness.run()
                result["result"] = "PASS"
            except CheckFailure as failure:
                result["failure"] = str(failure)
                result["stage"] = harness.stage
            except Exception as failure:
                result["failure"] = type(failure).__name__
                result["stage"] = harness.stage
            finally:
                try:
                    harness.stop_worker()
                except CheckFailure:
                    result["result"] = "FAIL"
                    result.setdefault("failure", "worker cleanup failed")
                result["checks"] = harness.checks
                result["checks_passed"] = len(harness.checks)
    finally:
        provider.close()
        os.umask(previous_umask)
    rendered = json.dumps(result, indent=2) + "\n"
    if arguments.output:
        private_file(arguments.output, rendered.encode())
    print(rendered, end="")
    return 0 if result["result"] == "PASS" else 1


if __name__ == "__main__":
    raise SystemExit(main())
