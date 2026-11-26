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
from concurrent.futures import ThreadPoolExecutor
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
LEGACY_SCHEMA = """CREATE TABLE connections(
    uuid TEXT UNIQUE ON CONFLICT REPLACE, device_id INTEGER, password TEXT, endpoint TEXT,
    forbidden BOOLEAN NOT NULL CHECK(forbidden IN(0,1)), last_registration INTEGER)"""
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
        self.respond_by_path = {}
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
                responder = provider.respond_by_path.get(self.path)
                if responder:
                    status = responder()
                else:
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

    def snapshot(self, database=None):
        with sqlite3.connect(database or self.db) as connection:
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

    def enrollment_status(self):
        self.stage = "read-only enrollment status with missing and empty databases"
        output_start = len(self.outputs)
        empty = {"enrollments": []}
        require(self.cli("enrollment", "status") == empty, "missing database should report no registrations")
        self.cli("enrollment", "status", ACCOUNT, error="not_found")
        require(not self.db.parent.exists(), "status created a state directory for a missing database")
        self.db.parent.mkdir(mode=0o700)
        require(self.cli("enrollment", "status") == empty, "missing file should report no registrations")
        require(not list(self.db.parent.iterdir()), "status created a missing database")
        database = private_file(self.db.parent / "status.db", b"")
        config = self.make_config(db=str(database))

        def snapshot_files():
            return {
                path.name: (path.read_bytes(), path.stat().st_mode, path.stat().st_mtime_ns)
                for path in database.parent.iterdir()
            }

        def report(config=config):
            before = snapshot_files()
            sent = self.provider.count
            result = self.cli("enrollment", "status", config=config)
            require(snapshot_files() == before, "status modified the database or its sidecars")
            require(self.provider.count == sent, "status contacted the provider")
            return result

        require(report() == empty, "empty SQLite database should report no registrations")
        self.mark("missing and empty enrollment status leaves database files and schema untouched")

        self.stage = "read-only enrollment status for legacy schemas"
        invalid_endpoint = "https:/SYNTHETIC-STATUS-INVALID-URL/redirect://example.invalid"
        legacy_url = (
            "https://SYNTHETIC-STATUS-USER:SYNTHETIC-STATUS-USERINFO@PUSH.example.invalid:443"
            "/SYNTHETIC-STATUS-PATH?key=SYNTHETIC-STATUS-QUERY#SYNTHETIC-STATUS-FRAGMENT"
        )
        legacy_password = "SYNTHETIC-STATUS-LEGACY-PASSWORD"
        invalid_account = identifier(10)
        for version in (0, 1):
            with sqlite3.connect(database) as connection:
                if version == 0:
                    connection.execute(LEGACY_SCHEMA)
                    connection.executemany("INSERT INTO connections VALUES(?,?,?,?,?,?)", [
                        (LEGACY_ACCOUNT, 7, legacy_password, legacy_url, 0, 123),
                        (invalid_account, 3, legacy_password, invalid_endpoint, 1, 123),
                    ])
                connection.execute(f"PRAGMA user_version={version}")
            legacy = {
                "account_id": LEGACY_ACCOUNT, "device_id": 7, "mode": "legacy_unkeyed", "receiver_id": None,
                "enrollment_version": None, "selected_event_version": None, "has_control_key": False,
                "subscription_epoch": None, "instance": None,
                "endpoint_origin": "https://push.example.invalid", "active": True,
            }
            invalid = dict(legacy, account_id=invalid_account, device_id=3, endpoint_origin=None, active=False)
            require(report() == {"enrollments": [invalid, legacy]}, "legacy status metadata or origin differs")
            self.cli("enrollment", "status", LEGACY_ACCOUNT, config=config, error="not_found")
            require(self.rows("PRAGMA user_version", database=database) == [(version,)],
                    "status migrated an upstream schema")
        legacy_report = {"enrollments": [invalid, legacy]}
        literal = private_file(self.directory / "file:status.db", database.read_bytes())
        alternate = private_file(self.directory / "status.db", b"")
        require(report(self.make_config(db=literal.name)) == legacy_report,
                "status interpreted a literal file: database name as a URI")
        require(alternate.read_bytes() == b"", "status modified the alternate URI database")
        ancestor = self.directory / "status-ancestor"
        ancestor.symlink_to(self.directory, target_is_directory=True)
        require(report(self.make_config(db=str(ancestor / "state" / database.name))) == legacy_report,
                "status rejected a database under a symlinked ancestor")
        self.mark("status reads upstream schemas 0 and 1, redacts valid origins and handles invalid endpoints")

        self.stage = "read-only enrollment status for encrypted protocol versions"
        password = "SYNTHETIC-STATUS-SIGNAL-PASSWORD"
        encrypted_path = "/SYNTHETIC-STATUS-ENCRYPTED-PATH?token=SYNTHETIC-STATUS-ENCRYPTED-QUERY"
        auth = encoded(b"status-auth-test")
        key = encoded(b"status-control-key-test-32-bytes")
        sequence = 7123498601742651
        expected = [invalid, legacy]
        for index, (version, keyed), in enumerate([(1, False), (2, False), (2, True), (3, True)], start=20):
            account = identifier(index)
            value = copy.deepcopy(self.enrollment)
            value.update(account_id=account, request_id=identifier(index + 10), device_id=4,
                         password=password, enrollment_version=version)
            event_version = version if keyed else 1
            value["subscription"].update(
                endpoint=self.provider.origin + encrypted_path, auth=auth,
                supported_event_versions=list(range(1, event_version + 1)),
            )
            if keyed:
                value["control_key"] = key
            if version == 3:
                value["import_seq"] = sequence
            self.import_value(value, config=config)
            if version == 3:
                with sqlite3.connect(database) as connection:
                    connection.execute(
                        "UPDATE encrypted_subscriptions SET state='provider_rejected' WHERE account_id=?",
                        (account,),
                    )
            expected.append({
                "account_id": account, "device_id": 4, "mode": f"encrypted_v{event_version}", "receiver_id": None,
                "enrollment_version": version if keyed else None, "selected_event_version": event_version,
                "has_control_key": keyed, "subscription_epoch": 1, "instance": "cli-fixture-instance",
                "endpoint_origin": self.provider.origin, "active": version != 3,
            })
        require(report() == {"enrollments": sorted(expected, key=lambda row: row["account_id"])},
                "mixed enrollment status fields differ")
        before = snapshot_files()
        require(self.cli("enrollment", "status", account, config=config) == {
            "instance": "cli-fixture-instance", "subscription_epoch": 1,
            "state": "provider_rejected", "event_version": 3,
        }, "positional status response changed")
        require(snapshot_files() == before, "positional status modified persistent state")
        database.chmod(0o400)
        database.parent.chmod(0o500)
        try:
            require(report() == {"enrollments": sorted(expected, key=lambda row: row["account_id"])},
                    "status could not read a protected database without write permissions")
        finally:
            database.parent.chmod(0o700)
            database.chmod(0o600)
        self.mark("imported encrypted v1, unkeyed/keyed v2 and v3 status use stored metadata and preserve positional output")

        self.stage = "read-only enrollment status errors under trace logging"
        invalid_json = "SYNTHETIC-STATUS-MALFORMED-JSON"
        with sqlite3.connect(database) as connection:
            connection.execute(
                "UPDATE encrypted_subscriptions SET subscription_json=? WHERE account_id=?",
                (invalid_json, account),
            )
        before = snapshot_files()
        self.cli("enrollment", "status", config=config, error="state_unavailable")
        self.cli("enrollment", "status", account, config=config, error="state_unavailable")
        require(snapshot_files() == before, "status changed state after an invalid SQLite row")
        with sqlite3.connect(database) as connection:
            require(connection.execute("PRAGMA journal_mode=WAL").fetchone() == ("wal",),
                    "could not create a WAL database fixture")
        connection.close()
        before = snapshot_files()
        self.cli("enrollment", "status", config=config, error="state_unavailable")
        require(snapshot_files() == before, "status modified SQLite WAL mode or sidecars")
        outputs = self.outputs[output_start:]
        markers = [
            password, legacy_password, auth, self.metadata["p256dh"], key, str(sequence), invalid_json,
            *[f"SYNTHETIC-STATUS-{suffix}" for suffix in (
                "INVALID-URL", "USER", "USERINFO", "PATH", "QUERY", "FRAGMENT",
                "ENCRYPTED-PATH", "ENCRYPTED-QUERY",
            )],
            '"password"', '"p256dh"', '"auth"', '"control_key"', '"import_seq"',
        ]
        require(all(marker.encode() not in output for marker in markers for output in outputs),
                "status CLI stdout or stderr exposed a secret marker under trace logging")
        self.mark("status leaves errors and WAL sidecars untouched and redacts stdout and stderr at trace level")

    def migrations(self):
        self.stage = "migration and protected state modes"
        require(self.cli("migrate") == {"schema_version": 7}, "migration did not select schema7")
        require(stat.S_IMODE(self.db.parent.stat().st_mode) == 0o700, "state directory is not0700")
        require(stat.S_IMODE(self.db.stat().st_mode) == 0o600, "state database is not0600")
        require(self.rows("PRAGMA user_version") == [(7,)], "SQLite schema marker differs from CLI")
        require(self.cli("migrate") == {"schema_version": 7}, "migration is not idempotent")
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
                connection.execute(LEGACY_SCHEMA)
                connection.execute("INSERT INTO connections VALUES(?,?,?,?,?,?)", original)
                connection.execute(f"PRAGMA user_version={version}")
            config = self.make_config(db=str(database))
            if version == 99:
                self.cli("migrate", config=config, error="state_unavailable")
                require(self.rows("PRAGMA user_version", database=database) == [(99,)], "future schema was downgraded")
            else:
                require(self.cli("migrate", config=config) == {"schema_version": 7}, "upstream schema migration failed")
            require(self.rows("SELECT * FROM connections", database=database) == [original], "migration changed legacy credentials or forbidden state")
        self.mark("upstream schemas0/1 preserve connection tuple and forbidden flag;future schema fails closed")

        alternate = self.directory / "uri-state.db"
        with sqlite3.connect(alternate) as connection:
            connection.execute(LEGACY_SCHEMA)
        alternate.chmod(0o644)
        original = alternate.read_bytes()
        literal = self.directory / "file:uri-state.db"
        config = self.make_config(db=literal.name, legacy_wake_until=int(time.time()) + 120)
        require(self.cli("migrate", config=config) == {"schema_version": 7}, "literal filename did not migrate")
        self.cli("connection", "add", LEGACY_ACCOUNT, "2", PASSWORD, self.provider.origin + ENDPOINT_PATH,
                 config=config)
        self.provider.take()
        require(self.rows("SELECT uuid FROM connections", database=literal) == [(LEGACY_ACCOUNT,)],
                "the second writable SQLite connection ignored the literal filename")
        require(alternate.read_bytes() == original, "writable SQLite opened an unchecked URI target")
        self.mark("both writable SQLite opens use the protected literal filename and leave the URI target untouched")


    def pairing(self):
        from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey

        self.stage = "protected pairing"
        contract = ROOT / "contracts/pairing/v1"
        spec = importlib.util.spec_from_file_location("pairing_conformance", contract / "tools/conformance.py")
        pairing = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(pairing)
        database = self.directory / "pairing-state" / "state.db"
        vapid_private = "DSqYuWchrB6yIMYJtidvqANeRQic4uWy34afzZRsZnI"
        vapid_public = "BOniQ9xHBPNY9gnQW4o-16vHqOb40pEIMifyUdFsxAgyzVkFMguxw0QrdbZcq8hRjN2zpeInRvKVPlkzABvuTnI"
        settings = {"db": str(database), "vapid_privkey": vapid_private}
        config = self.make_config(**settings)
        enrollment = json.loads((ROOT / "contracts/encrypted-push/v3/fixtures/enrollment-keyed-v3.json").read_text())
        enrollment.update(account_id=OTHER_ACCOUNT, password="SYNTHETIC-PAIRING-PASSWORD-CANARY")
        enrollment["subscription"]["endpoint"] = self.provider.origin + ENDPOINT_PATH

        def command(*args, active_config=config, **options):
            return self.cli("pairing", *args, config=active_config, **options)

        def offer(*args, **options):
            return command("create", "--host-label", "Collie lab", *args, **options)

        def seal(advertised, value):
            client = X25519PrivateKey.generate()
            request = pairing.seal_request(advertised, client, os.urandom(12), compact(value))
            return request, client

        def submit(request, **options):
            return command("submit", "--stdin", data=compact(request), **options)

        offered = offer("--qr")
        session = offered["session_id"]
        require(offered["provider_origin"] == self.provider.origin and offered["vapid_public_key"] == vapid_public,
                "QR offer does not display the configured origin and VAPID key")
        require("█".encode() in self.outputs[-1], "CLI did not render the offer QR")
        pairing.validate("offer", compact(offered), {"offer": pairing.schema(contract, "offer")})
        row = self.rows("SELECT expires_at-created_at,private_key FROM pairing_sessions WHERE session_id=?",
                        (session,), database)[0]
        require(row[0] == 300 and len(row[1]) == 32, "pairing defaults or private key storage differ")
        require(command("status", session)["state"] == "active", "new session is not active")
        request, client = seal(offered, enrollment)
        before = self.snapshot(database)
        offer("--intent", "add_receiver", error="invalid_offer")
        submit({**request, "intent": "add_receiver"}, error="invalid_envelope")
        submit({**request, "intent": "unknown"}, error="invalid_request")
        submit({**request, "intent": {"pair_bridge": None}}, error="invalid_request")
        submit([request[name] for name in ("pairing_version", "session_id", "intent", "client_public_key", "nonce", "ciphertext")],
               error="invalid_request")
        sub = enrollment["subscription"]
        positional_sub = [sub[name] for name in ("endpoint", "p256dh", "auth", "instance",
                          "subscription_epoch", "encryption_required", "supported_event_versions", "capabilities")]
        positional = [enrollment[name] for name in ("enrollment_version", "request_id", "import_seq",
                      "account_id", "device_id", "password", "control_key", "subscription")]
        submit(seal(offered, positional)[0], error="invalid_enrollment")
        submit(seal(offered, {**enrollment, "subscription": positional_sub})[0], error="invalid_enrollment")
        duplicate = b'{"password":"synthetic-duplicate",' + compact(enrollment)[1:]
        submit(pairing.seal_request(offered, client, os.urandom(12), duplicate), error="invalid_json")
        submit({**request, "pairing_version": 2}, error="unsupported_version")
        submit({**request, "session_id": identifier(270)}, error="invalid_session")
        command("submit", "--stdin", data=b" " * 11265, error="input_too_large")
        command("submit", "--stdin", data=b'{"pairing_version":1,' + compact(request)[1:],
                error="invalid_request")
        command("submit", "--file", str(self.directory / "no-pairing-file"), error="unsafe_file")
        for field, value in {"host_label": "Different host", "expires_at": offered["expires_at"] + 1,
                             "provider_origin": "https://different.example.test",
                             "vapid_public_key": self.metadata["p256dh"]}.items():
            tampered, _ = seal({**offered, field: value}, enrollment)
            submit(tampered, error="invalid_envelope")
        submit({**request, "ciphertext": pairing.flipped(request["ciphertext"], 17, 8208)},
               error="invalid_envelope")
        legacy = self.enrollment
        submit(seal(offered, legacy)[0], error="unsupported_version")
        no_encryption = copy.deepcopy(enrollment)
        no_encryption["subscription"]["encryption_required"] = False
        submit(seal(offered, no_encryption)[0], error="encryption_required")
        disallowed = self.make_config(**settings, allowed_uuids=[ACCOUNT])
        submit(request, active_config=disallowed, error="invalid_enrollment")
        require(self.snapshot(database) == before, "rejected pairing changed persistent state")
        self.mark("QR offer and TTL defaults; strict envelope and transcript checks; cross-intent and disallowed enrollment leave state untouched")

        other_origin = f"http://127.0.0.1:{fresh_port()}"
        multi = self.make_config(**settings, allowed_endpoints=[self.provider.origin, other_origin])
        other_endpoint = copy.deepcopy(enrollment)
        other_endpoint["subscription"]["endpoint"] = other_origin + ENDPOINT_PATH
        submit(seal(offered, other_endpoint)[0], active_config=multi, error="invalid_endpoint")
        query_policy = self.make_config(**settings, required_endpoint_queries=[self.provider.origin + "?required=token"])
        submit(request, active_config=query_policy, error="invalid_endpoint")
        wildcard = self.make_config(**settings, allowed_endpoints=["*"])
        unspecified = offer(active_config=wildcard)
        require("provider_origin" not in unspecified, "wildcard config advertised a specific provider")
        private_destination = copy.deepcopy(enrollment)
        private_destination["subscription"]["endpoint"] = "https://127.0.0.1:1/private"
        submit(seal(unspecified, private_destination)[0], active_config=wildcard, error="invalid_endpoint")
        command("cancel", unspecified["session_id"])
        require(self.rows("SELECT count(*) FROM encrypted_subscriptions", database=database) == [(0,)],
                "disallowed endpoint enrolled a registration")
        self.mark("pairing enforces scanned provider origin, configured query policy, and wildcard address restrictions")

        # Force a failure at the session update after enrollment has written its rows.
        with sqlite3.connect(database) as connection:
            connection.execute("""CREATE TRIGGER test_pairing_abort BEFORE UPDATE ON pairing_sessions
                                  WHEN NEW.state='consumed' BEGIN SELECT RAISE(ABORT,'synthetic'); END""")
        before = self.snapshot(database)
        submit(request, error="state_unavailable")
        require(self.snapshot(database) == before, "failed session update left partial enrollment")
        with sqlite3.connect(database) as connection:
            connection.execute("DROP TRIGGER test_pairing_abort")

        with ThreadPoolExecutor(max_workers=2) as executor:
            args = [str(self.binary), "--config", str(config), "pairing", "submit", "--stdin"]
            results = list(executor.map(lambda _: subprocess.run(
                args, input=compact(request), capture_output=True, timeout=20,
                cwd=self.directory, env=self.env, check=False), range(2)))
        self.outputs.extend(output for result in results for output in (result.stdout, result.stderr))
        require(sorted(result.returncode for result in results) == [0, 1],
                "concurrent sealed submission must yield one receipt")
        accepted = next(result for result in results if result.returncode == 0)
        failed = next(result for result in results if result.returncode == 1)
        require(json_line(failed.stderr) == {"error": "session_consumed"}, "race loser returned wrong error")
        # Receipt authentication is performed by the independent client.
        receipt = pairing.open_receipt(offered, request, json_line(accepted.stdout), client)
        pairing.schema(pairing.V3, "response").validate(receipt)
        require(receipt["request_id"] == enrollment["request_id"] and receipt["status"] == "accepted"
                and receipt["replayed"] is False, "receipt does not describe the installed v3 import")
        require(command("status", session)["state"] == "consumed", "consumed state did not survive CLI exit")
        submit(request, error="session_consumed")
        submit(seal(offered, enrollment)[0], error="session_consumed")
        require(self.rows("SELECT offer_json,private_key FROM pairing_sessions WHERE session_id=?",
                          (session,), database) == [(None, None)], "consumed session retained key material")
        require(self.rows("SELECT count(*) FROM encrypted_push_queue", database=database) == [(1,)],
                "accepted pairing must queue one enrollment confirmation")
        self.mark("session consumption and enrollment roll back together; two concurrent submissions yield one bound receipt and one replay error")

        manual = private_file(self.directory / "pairing-manual-enrollment.json", compact(enrollment))
        unchanged = self.cli("enrollment", "import", "--file", str(manual), config=config)
        require(unchanged["status"] == "unchanged" and unchanged["replayed"] is True,
                "manual import did not recognize the pairing enrollment")
        repeat = offer()
        repeat_request, repeat_client = seal(repeat, enrollment)
        sealed_file = private_file(self.directory / "sealed-pairing-request.json", compact(repeat_request))
        result = command("submit", "--file", str(sealed_file))
        require(pairing.open_receipt(repeat, repeat_request, result, repeat_client) == unchanged,
                "pairing and manual import receipts disagree for an exact v3 replay")
        self.mark("mode-0600 sealed file and stdin both work; v3 manual file import retains matching receipt semantics")

        offer("--ttl-seconds", "601", error="invalid_offer")
        expired = offer("--ttl-seconds", "1")
        exp_request, _ = seal(expired, enrollment)
        with sqlite3.connect(database) as connection:
            connection.execute("UPDATE pairing_sessions SET created_at=created_at-2,expires_at=expires_at-2 WHERE session_id=?",
                               (expired["session_id"],))
        submit(exp_request, error="session_expired")
        require(command("status", expired["session_id"])["state"] == "expired", "expired state missing")
        require(self.rows("SELECT private_key FROM pairing_sessions WHERE session_id=?", (expired["session_id"],),
                          database) == [(None,)], "expired session retained private key")
        cancelled = offer("--ttl-seconds", "600")
        cancel_request, _ = seal(cancelled, enrollment)
        require(command("cancel", cancelled["session_id"])["state"] == "cancelled", "cancel did not close session")
        command("cancel", cancelled["session_id"], error="invalid_session")
        submit(cancel_request, error="invalid_session")
        with sqlite3.connect(database) as connection:
            connection.execute("UPDATE pairing_sessions SET created_at=created_at-87000,expires_at=expires_at-87000 WHERE session_id=?",
                               (session,))
        submit(request, error="invalid_session")
        require(self.rows("SELECT count(*) FROM pairing_sessions WHERE session_id=?", (session,), database) == [(0,)],
                "terminal row survived its replay-retention window")
        for _ in range(8):
            offer()
        offer(error="capacity_exceeded")
        self.mark("TTL, expiry, cancellation and replay retention erase keys; active session cap is enforced")

        joined = b"\n".join(self.outputs)
        canaries = [vapid_private, enrollment["password"], enrollment["control_key"],
                    enrollment["subscription"]["endpoint"], encoded(row[1]), row[1].hex(),
                    encoded(client.private_bytes_raw())]
        require(all(canary.encode() not in joined for canary in canaries), "pairing trace exposed a secret")
        self.mark("QR, responses and trace logs exclude pairing key, VAPID key, enrollment and endpoint secrets")

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
        expired_session = identifier(271)
        now = int(time.time())
        with sqlite3.connect(self.db) as connection:
            connection.execute("INSERT INTO pairing_sessions VALUES (?,?,?,'active',?,?)",
                               (expired_session, now - 600, now - 300, "{}", bytes(32)))
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
                if ready and self.rows("SELECT state,private_key FROM pairing_sessions WHERE session_id=?",
                                       (expired_session,)) == [("expired", None)]:
                    break
                ready = False
            except (OSError, ValueError, http.client.HTTPException):
                pass
            time.sleep(0.05)
        require(ready, "server did not become ready, expose discovery, and reap the expired pairing")
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
        require(self.http(public_port, "POST", "/pairing/v1/submit", b"{}")[0] == 404,
                "public HTTP exposes a pairing submission path")
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

    def receiver_fanout(self):
        from cryptography.exceptions import InvalidTag
        from cryptography.hazmat.primitives.asymmetric import ec, x25519
        from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

        self.stage = "v4 active-bridge pairing and migration"
        contract = ROOT / "contracts/pairing/v1"
        spec = importlib.util.spec_from_file_location("pairing_v4_client", contract / "tools/conformance.py")
        pairing = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(pairing)
        fixtures = ROOT / "contracts/encrypted-push/v4/fixtures"
        database = self.directory / "receiver-state" / "state.db"
        config = self.make_config(db=str(database),
                                  vapid_privkey="DSqYuWchrB6yIMYJtidvqANeRQic4uWy34afzZRsZnI")

        def call(*args, **options):
            return self.cli(*args, config=config, **options)

        def offer(add=True, **options):
            args = ("--intent", "add_receiver", "--account-id", ACCOUNT) if add else ()
            return call("pairing", "create", "--host-label", "Receiver lab", *args, **options)

        def pair(offered, value, **options):
            client = x25519.X25519PrivateKey.generate()
            request = pairing.seal_request(offered, client, os.urandom(12), compact(value))
            receipt = call("pairing", "submit", "--stdin", data=compact(request), **options)
            if "error" not in options:
                return pairing.open_receipt(offered, request, receipt, client)

        def status(read_only=True):
            before = self.snapshot(database) if read_only else None
            result = call("enrollment", "status", ACCOUNT)["enrollments"]
            if read_only:
                require(self.snapshot(database) == before, "v4 status modified the database")
            return {row["receiver_id"]: row for row in result}

        def revoke(receiver, expected):
            require(call("enrollment", "revoke", "--account-id", ACCOUNT,
                         "--receiver-id", receiver["receiver_id"]) == {"revoked": expected},
                    "v4 revoke reported the wrong change")

        offer(error="not_found")
        legacy = json.loads((ROOT / "contracts/encrypted-push/v3/fixtures/enrollment-keyed-v3.json").read_text())
        legacy["password"] = "SYNTHETIC-V4-BRIDGE-PASSWORD"
        legacy["subscription"].update(endpoint=self.provider.origin + ENDPOINT_PATH,
                                      p256dh=self.metadata["p256dh"], auth=self.metadata["auth"])
        self.import_value(legacy, config=config)
        legacy_lease = self.rows("SELECT * FROM encrypted_push_queue", database=database)
        session = offer(add=False)["session_id"]
        pairing_rows = self.rows("SELECT * FROM pairing_sessions", database=database)
        with sqlite3.connect(database) as db:
            db.executescript("""
                DROP TABLE receiver_pairing_targets;
                DROP TABLE receiver_push_queue;
                DROP TABLE receiver_enrollment_requests;
                DROP TABLE receiver_bridges;
                DROP TABLE push_receivers;
                DROP TRIGGER receiver_bridge_insert_guard;
                DROP TRIGGER receiver_bridge_update_guard;
                DROP TRIGGER receiver_bridge_delete_guard;
                PRAGMA user_version=6;
            """)
        require(call("migrate") == {"schema_version": 7}, "schema 6 did not migrate")
        require(self.rows("SELECT * FROM encrypted_push_queue", database=database) == legacy_lease and
                self.rows("SELECT * FROM pairing_sessions", database=database) == pairing_rows,
                "schema 7 migration changed legacy queue or pairing sessions")
        call("pairing", "cancel", session)
        with sqlite3.connect(database) as db:
            db.execute("UPDATE connections SET forbidden=1")
        offer(error="not_found")
        with sqlite3.connect(database) as db:
            db.execute("UPDATE connections SET forbidden=0")
        self.mark("schema6 migration preserves pending v3 event and pairing session; add_receiver requires a non-forbidden encrypted bridge")

        paths = ["/SYNTHETIC-V4-SECONDARY-PATH", "/SYNTHETIC-V4-THIRD-PATH"]
        receivers, keys = [], []
        for index, path in enumerate(paths, 1):
            receiver = json.loads((fixtures / "receiver.json").read_text())
            private = ec.generate_private_key(ec.SECP256R1())
            auth = bytes([220 + index] * 16)
            public = private.public_key().public_bytes(Encoding.X962, PublicFormat.UncompressedPoint)
            receiver.update(receiver_id=identifier(460 + index), request_id=identifier(470 + index),
                            control_key=encoded(bytes([136 + index] * 32)), label=f"Phone {index}")
            receiver["subscription"].update(endpoint=self.provider.origin + path,
                                            p256dh=encoded(public), auth=encoded(auth))
            receivers.append(receiver)
            keys.append((private, auth))
        a, b = receivers
        invite = offer()
        before = self.snapshot(database)
        pair(invite, {**a, "account_id": OTHER_ACCOUNT}, error="invalid_enrollment")
        pair(invite, {**a, "device_id": a["device_id"] + 1}, error="invalid_session")
        pair(invite, {**a, "password": legacy["password"]}, error="invalid_enrollment")
        require(self.snapshot(database) == before, "rejected receiver import changed state")
        bridge_only = offer(add=False)
        pair(bridge_only, a, error="invalid_enrollment")
        call("pairing", "cancel", bridge_only["session_id"])
        require(call("pairing", "status", invite["session_id"])["state"] == "active",
                "invalid receiver import consumed its invitation")
        require(self.rows("SELECT count(*) FROM push_receivers", database=database) == [(0,)],
                "invalid receiver import created a route")
        receipt = pair(invite, a)
        require(receipt["receiver_id"] == a["receiver_id"] and receipt["request_id"] == a["request_id"]
                and receipt["replayed"] is False, "add_receiver did not return its authenticated v4 receipt")
        pair(invite, b, error="session_consumed")
        extra_invite = offer()
        pair(extra_invite, {**b, "receiver_id": a["receiver_id"]}, error="epoch_conflict")
        pair(extra_invite, {**b, "control_key": a["control_key"]}, error="invalid_enrollment")
        bad_endpoint = copy.deepcopy(b)
        bad_endpoint["subscription"]["endpoint"] = "https://other.example.invalid/private"
        pair(extra_invite, bad_endpoint, error="invalid_endpoint")
        pair(extra_invite, b)
        statuses = status()
        require(list(statuses) == [None, a["receiver_id"], b["receiver_id"]]
                and statuses[None]["mode"] == "encrypted_v3"
                and statuses[a["receiver_id"]]["label"] == a["label"]
                and statuses[b["receiver_id"]]["mode"] == "encrypted_v4",
                "status lost a legacy or v4 route")
        self.mark("sealed add_receiver binds account, device, intent and provider; receiver IDs and control keys are independent")

        def capture(expected, kind, code=None):
            events = {}
            for _ in expected:
                path, headers, body = self.provider.take(timeout=5)
                require(path in expected and path not in events, "fan-out missed or repeated a route")
                require(headers.get("content-encoding") == "aes128gcm" and len(body) == 4096,
                        "fan-out route did not use encrypted Web Push")
                if path == ENDPOINT_PATH:
                    event = json.loads(self.checker.decrypt(body, self.private, self.auth))
                    require(event["version"] == 3 and event["import_id"] == legacy["request_id"],
                            "v3 primary lost its legacy event identity")
                else:
                    index = paths.index(path)
                    private, auth = keys[index]
                    event = json.loads(self.checker.decrypt(body, private, auth))
                    target = receivers[index]
                    require(event["version"] == 4 and event["receiver_id"] == target["receiver_id"]
                            and event["import_id"] == target["request_id"]
                            and event["instance"] == target["subscription"]["instance"]
                            and event["subscription_epoch"] == 1,
                            "v4 ciphertext has the wrong receiver state")
                    wrong_private, wrong_auth = keys[1 - index]
                    try:
                        self.checker.decrypt(body, wrong_private, wrong_auth)
                    except InvalidTag:
                        pass
                    else:
                        raise CheckFailure("v4 ciphertext authenticated under the other receiver's keys")
                require(event["kind"] == kind and event.get("code") == code,
                        "fan-out produced an unexpected event")
                events[path] = event["event_id"]
            require(len(set(events.values())) == len(events), "fan-out reused event IDs")
            return events

        for _ in range(3):
            call("push", "drain", "--once")
        capture([ENDPOINT_PATH, *paths], "status", "enrollment_imported")
        self.stage = "concurrent v4 provider attempts and failure isolation"
        ready_port = fresh_port()
        worker_config = self.make_config(db=str(database), ready_port=ready_port)
        self.worker_files = tuple((self.directory / f"v4-worker.{name}").open("w+b")
                                  for name in ("stdout", "stderr"))
        self.worker = subprocess.Popen(
            [str(self.binary), "--config", str(worker_config), "server"],
            cwd=self.directory, env=self.env, stdin=subprocess.DEVNULL,
            stdout=self.worker_files[0], stderr=self.worker_files[1],
        )
        release = threading.Event()

        def slow_rejection():
            release.wait(8)
            return 410

        self.provider.respond_by_path[paths[0]] = slow_rejection
        try:
            queue_receipt = call("push", "wake", ACCOUNT)
            events = capture([ENDPOINT_PATH, *paths], "wake")
            require(set(events.values()) == set(queue_receipt["event_ids"]), "fan-out receipt mismatched ciphertext")
            deadline = time.monotonic() + 3
            while time.monotonic() < deadline:
                queued = self.rows("SELECT (SELECT count(*) FROM encrypted_push_queue) + "
                                   "(SELECT count(*) FROM receiver_push_queue)", database=database)
                if queued == [(1,)]:
                    break
                time.sleep(0.02)
            require(queued == [(1,)], "slow provider blocked another receiver")
        finally:
            release.set()
            del self.provider.respond_by_path[paths[0]]
        deadline = time.monotonic() + 5
        while status(read_only=False)[a["receiver_id"]]["state"] == "active" and time.monotonic() < deadline:
            time.sleep(0.02)
        self.stop_worker()
        require(status()[a["receiver_id"]]["state"] == "stale"
                and status()[b["receiver_id"]]["state"] == "active" and status()[None]["active"],
                "provider failure changed the bridge or another receiver")
        self.mark("three concurrent routes decrypt with only their own keys; slow HTTP410 does not block or retire healthy routes")

        self.stage = "v4 primary upgrade and target-only revocation"
        invite = offer()
        new_primary = json.loads((fixtures / "bridge.json").read_text())
        new_primary["password"] = legacy["password"]
        new_primary["subscription"].update(
            subscription_epoch=2, endpoint=self.provider.origin + "/SYNTHETIC-V4-PRIMARY-PATH")
        bridge_offer = offer(add=False)
        pair(bridge_offer, {**new_primary, "device_id": legacy["device_id"] + 1}, error="epoch_conflict")
        pair(bridge_offer, new_primary)
        pending = json.loads((fixtures / "receiver.json").read_text())
        pending["subscription"]["endpoint"] = self.provider.origin + paths[1]
        pair(invite, pending, error="invalid_session")
        require(status()[b["receiver_id"]]["subscription_epoch"] == 1 and None not in status(),
                "primary upgrade disturbed a sibling or kept the legacy route live")
        require(self.rows("SELECT device_id,password FROM connections", database=database)
                == [(legacy["device_id"], legacy["password"])], "primary upgrade re-linked Signal")
        require(self.import_value(legacy, config=config)["replayed"], "primary upgrade discarded a v3 receipt")
        call("push", "wake", ACCOUNT)
        revoke(b, True)
        revoke(b, False)
        require(status()[b["receiver_id"]]["state"] == "revoked"
                and not status()[b["receiver_id"]]["has_control_key"]
                and status()[new_primary["receiver_id"]]["active"],
                "revocation affected a sibling or retained the target key")
        require(self.rows("SELECT count(*) FROM receiver_push_queue WHERE receiver_id=?",
                          (b["receiver_id"],), database) == [(0,)], "revoked queue was retained")
        pair(offer(), {**b, "request_id": identifier(490)}, error="epoch_conflict")
        # Replacing a revoked primary requires an unused receiver identity.
        revoke(new_primary, True)
        replacement = copy.deepcopy(new_primary)
        replacement.update(receiver_id=identifier(491), request_id=identifier(492),
                           control_key=encoded(bytes([211] * 32)), password="SYNTHETIC-V4-NEW-PASSWORD")
        replacement["subscription"]["subscription_epoch"] = 1
        pair(offer(add=False), replacement)
        require(status()[new_primary["receiver_id"]]["state"] == "revoked"
                and status()[replacement["receiver_id"]]["active"], "primary replacement revived a revoked UUID")
        require(call("connection", "remove", ACCOUNT) == {"removed": True, "signal_unlinked": False},
                "account removal did not clear its v4 routes")
        self.mark("v4 pair_bridge upgrades v3 without re-linking; old invitations cannot submit; revoke and primary replacement preserve sibling state")

        canaries = [legacy["password"], replacement["password"], replacement["control_key"],
                    "SYNTHETIC-V4-PRIMARY-PATH", *paths]
        for receiver in receivers:
            canaries += [receiver["control_key"], receiver["subscription"]["auth"],
                         receiver["subscription"]["p256dh"]]
        require(all(canary.encode() not in output for canary in canaries for output in self.outputs),
                "v4 CLI or worker trace exposed a credential")
        self.mark("v4 worker and pairing trace redact receiver endpoints, keys, auth secrets and bridge passwords")

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
        self.enrollment_status()
        self.migrations()
        self.pairing()
        self.protected_imports()
        self.encrypted_events_and_rotation()
        self.stale_and_recovery()
        self.authorization_and_receipts()
        self.legacy_boundaries()
        self.worker_and_discovery()
        self.redaction_and_removal()
        self.receiver_fanout()


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
