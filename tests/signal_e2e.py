#!/usr/bin/env python3
"""Exercise a real Signal envelope -> encrypted HTTP push using loopback fakes.

Build with `cargo build --locked --features test-signal`, then run
`python3 tests/signal_e2e.py`. The existing independent Python/OpenSSL verifier
decrypts the captured push. No CLI wake command or direct queue insert is used.
Only temporary TLS keys and public synthetic enrollment keys are used.
"""

import argparse
import base64
import hashlib
import hmac
import importlib.util
import json
import os
from pathlib import Path
import queue
import subprocess
import sys
import tempfile
import time
import uuid

from fake_signal import FakeSignal, FakeSignalError, create_tls_material, signal_envelope
from server_cli import (
    ACCOUNT, ENDPOINT_PATH, NOT_RUN, PASSWORD, ROOT, CheckFailure, Harness, Provider,
    fresh_port, private_file, require,
)


def event_key_id(enrollment):
    """Independently derive the canonical v3 control-key identity."""
    account = uuid.UUID(enrollment["account_id"]).bytes
    device = enrollment["device_id"].to_bytes(4, "big")
    instance = enrollment["subscription"]["instance"].encode("ascii")
    control_key = base64.urlsafe_b64decode(
        enrollment["control_key"] + "=" * (-len(enrollment["control_key"]) % 4)
    )
    message = (
        b"COLLIESOCKET-EVENT-KEY-ID\0\x03"
        + account
        + device
        + len(instance).to_bytes(2, "big")
        + instance
    )
    digest = hmac.new(control_key, message, hashlib.sha256).digest()
    return base64.urlsafe_b64encode(digest).rstrip(b"=").decode("ascii")


class SignalHarness(Harness):
    """Trace synthetic envelopes through the real worker to independently decrypted pushes."""

    def start_signal_worker(self, signal, ca_path=None):
        """Launch the real worker against the fake WSS peer with captured trace logs."""
        config = self.make_config(
            push_only=False, webserver=False, ready_port=fresh_port(),
            test_signal_url=signal.url, test_signal_ca=str(ca_path or signal.ca_path),
        )
        stdout = (self.directory / f"worker-{self.config_serial}.stdout").open("w+b")
        stderr = (self.directory / f"worker-{self.config_serial}.stderr").open("w+b")
        self.worker_files = (stdout, stderr)
        self.worker = subprocess.Popen(
            [str(self.binary), "--config", str(config), "server"],
            cwd=self.directory, env=self.env, stdin=subprocess.DEVNULL,
            stdout=stdout, stderr=stderr,
        )

    def require_no_push(self, timeout=1.25):
        """Observe a quiet provider window, an empty queue and a live server process."""
        try:
            self.provider.requests.get(timeout=timeout)
        except queue.Empty:
            pass
        else:
            raise CheckFailure("unexpected push from a non-waking Signal input")
        require(self.queued() == 0, "non-waking input left a queued encrypted push")
        require(self.worker.poll() is None, "Signal worker exited unexpectedly")

    def event_ids(self):
        """Read the durable ledger, whose IDs survive removal from the send queue."""
        return {row[0] for row in self.rows("SELECT event_id FROM encrypted_push_event_ids")}

    @staticmethod
    def barrier(signal):
        """Wait for a later nonurgent ACK to establish ordered processing of earlier input."""
        # The server processes requests in order. ACKing this later nonurgent
        # envelope proves processing of the preceding input has completed.
        signal.wait_ack(signal.send_envelope(signal_envelope(urgent=False)))

    def require_suppressed(self, signal, envelope):
        """Prove an acknowledged input creates neither a durable event nor a provider POST."""
        previous = self.event_ids()
        signal.wait_ack(signal.send_envelope(envelope))
        self.barrier(signal)
        self.require_no_push()
        # The durable ID ledger outlives queue consumption, so a worker cannot
        # hide an incorrectly enqueued event by discarding it before inspection.
        require(self.event_ids() == previous, "non-waking input recorded a durable event ID")

    def send_wake(self, signal, envelope, request_id=None):
        """Correlate one envelope with one new ledger ID and its decrypted provider event."""
        previous = self.event_ids()
        sent_at = int(time.time())
        signal.wait_ack(signal.send_envelope(envelope, request_id=request_id))
        self.barrier(signal)
        created = self.event_ids() - previous
        require(len(created) == 1, "Signal envelope did not record exactly one new durable event")
        event_id = created.pop()
        return event_id, self.capture_signal_wake(sent_at, event_id)

    def capture_signal_wake(self, sent_at, expected_event_id):
        """Verify encrypted transport, v1 event fields and bounded provider acceptance."""
        path, headers, body = self.provider.take(timeout=5)
        require(path == ENDPOINT_PATH, "Signal wake reached the wrong provider endpoint")
        require(len(body) == 4096, "Signal wake is not a fixed-size encrypted push")
        require(headers.get("content-type") == "application/octet-stream", "Signal wake lacks binary media type")
        require(headers.get("content-encoding") == "aes128gcm", "Signal wake lacks encrypted content encoding")
        require(headers.get("content-length") == "4096", "Signal wake has incorrect Content-Length")
        require(headers.get("urgency") == "normal" and "topic" not in headers,
                "Signal wake exposed unexpected clear routing metadata")
        require(1 <= int(headers.get("ttl", "0")) <= 300, "Signal wake has unbounded provider TTL")
        for marker in [PASSWORD, self.metadata["auth"], self.metadata["p256dh"], ACCOUNT,
                       "cli-fixture-instance", "SYNTHETIC-SIGNAL-CONTENT-CANARY"]:
            require(marker not in json.dumps(headers) and marker.encode() not in body,
                    "Signal wake exposed private material outside encryption")
        # This verifier derives RFC 8291 keys with Python/OpenSSL, independently
        # of the Rust sender. It checks the record framing and AES-GCM tag too.
        plaintext = self.checker.decrypt(body, self.private, self.auth)
        encoded_event = plaintext.rstrip(b" ")
        require(len(plaintext) == 3993 and len(encoded_event) <= 3072
                and plaintext == encoded_event.ljust(3993, b" "),
                "Signal wake violated fixed application padding")
        event = json.loads(encoded_event)
        require(set(event) == {"version", "event_id", "instance", "subscription_epoch", "kind", "issued_at", "expires_at"},
                "Signal wake has an unexpected event schema")
        require(type(event["version"]) is int and event["version"] == 1
                and type(event["subscription_epoch"]) is int and event["subscription_epoch"] == 1,
                "Signal wake has the wrong contract version or enrollment epoch")
        require(event["instance"] == "cli-fixture-instance" and event["kind"] == "wake",
                "Signal envelope did not produce the enrolled instance's wake event")
        require(event["event_id"] == expected_event_id,
                "captured Signal wake does not match the newly recorded durable event")
        event_id = uuid.UUID(event["event_id"])
        require(event_id.version == 4 and str(event_id) == event["event_id"],
                "Signal wake event ID is not canonical UUIDv4")
        require(type(event["issued_at"]) is int and type(event["expires_at"]) is int,
                "Signal wake timestamps are not JSON integers")
        require(sent_at <= event["issued_at"] <= int(time.time()),
                "wake timestamp is outside the Signal envelope delivery window")
        require(event["expires_at"] - event["issued_at"] == 300,
                "Signal wake lifetime differs from the contract")
        deadline = time.monotonic() + 5
        while self.queued() and time.monotonic() < deadline:
            time.sleep(0.02)
        require(self.queued() == 0 and self.current()["state"] == "active",
                "provider acceptance did not finish the encrypted wake attempt")
        return body

    def capture_v3_provider_request(
        self, enrollment, sent_at, expected_event_id, expected_kind, expected_code=None
    ):
        """Decrypt one actual provider POST and verify its v3 import/key identity."""
        path, headers, body = self.provider.take(timeout=5)
        require(path == ENDPOINT_PATH, "v3 event reached the wrong provider endpoint")
        require(len(body) == 4096, "v3 event is not a fixed-size encrypted push")
        require(body[20] == 65 and body[21] == 4, "v3 event has invalid sender-key framing")
        require(headers.get("content-type") == "application/octet-stream",
                "v3 event lacks binary media type")
        require(headers.get("content-encoding") == "aes128gcm",
                "v3 event lacks encrypted content encoding")
        require(headers.get("content-length") == "4096", "v3 event has incorrect Content-Length")
        require(headers.get("urgency") == "normal" and "topic" not in headers,
                "v3 event exposed unexpected clear routing metadata")
        require(1 <= int(headers.get("ttl", "0")) <= 300,
                "v3 event has unbounded provider TTL")
        clear_headers = json.dumps(headers)
        expected_key_id = event_key_id(enrollment)
        for marker in [
            PASSWORD,
            enrollment["account_id"],
            enrollment["password"],
            enrollment["subscription"]["instance"],
            enrollment["subscription"]["p256dh"],
            enrollment["subscription"]["auth"],
            enrollment["control_key"],
            expected_key_id,
        ]:
            require(marker not in clear_headers and marker.encode() not in body,
                    "v3 event exposed private material outside encryption")

        auth = self.checker.b64(enrollment["subscription"]["auth"])
        plaintext = self.checker.decrypt(body, self.private, auth)
        encoded_event = plaintext.rstrip(b" ")
        require(len(plaintext) == 3993 and len(encoded_event) <= 3072
                and plaintext == encoded_event.ljust(3993, b" "),
                "v3 event violated fixed application padding")
        event = json.loads(encoded_event)
        required = {
            "version", "event_id", "instance", "subscription_epoch", "kind",
            "issued_at", "expires_at", "key_id", "import_id",
        }
        if expected_kind == "status":
            required.add("code")
        require(set(event) == required, "v3 event has an unexpected schema")
        require(type(event["version"]) is int and event["version"] == 3
                and type(event["subscription_epoch"]) is int
                and event["subscription_epoch"] == enrollment["subscription"]["subscription_epoch"],
                "v3 event has the wrong version or enrollment epoch")
        require(event["instance"] == enrollment["subscription"]["instance"]
                and event["kind"] == expected_kind,
                "v3 event has the wrong instance or kind")
        require(event["event_id"] == expected_event_id,
                "decrypted v3 event differs from its durable event ID")
        event_uuid = uuid.UUID(event["event_id"])
        import_uuid = uuid.UUID(event["import_id"])
        require(event_uuid.version == 4 and str(event_uuid) == event["event_id"],
                "v3 event ID is not canonical UUIDv4")
        require(import_uuid.version == 4
                and event["import_id"] == enrollment["request_id"],
                "v3 event does not identify the imported request")
        require(event["key_id"] == expected_key_id,
                "v3 event key identity does not match the imported control key/context")
        if expected_code is not None:
            require(event["code"] == expected_code, "v3 status code differs from expectation")
        require(type(event["issued_at"]) is int and type(event["expires_at"]) is int,
                "v3 event timestamps are not JSON integers")
        require(sent_at <= event["issued_at"] <= int(time.time()),
                "v3 event timestamp is outside the import/wake window")
        require(event["expires_at"] - event["issued_at"] == 300,
                "v3 event lifetime differs from the contract")

        deadline = time.monotonic() + 5
        while self.queued() and time.monotonic() < deadline:
            time.sleep(0.02)
        require(self.queued() == 0 and self.current()["state"] == "active",
                "provider acceptance did not finish the v3 event attempt")
        self.captured_v3_bodies.append({
            "kind": expected_kind,
            "code": event.get("code"),
            "body_base64": base64.b64encode(body).decode("ascii"),
            "body_length": len(body),
            "body_sha256": hashlib.sha256(body).hexdigest(),
            "event": event,
            "transport": {
                "headers": {
                    name: headers[name]
                    for name in ("content-type", "content-encoding", "content-length", "urgency", "ttl")
                    if name in headers
                },
            },
        })
        return body, event

    def send_v3_wake(self, signal, enrollment):
        """Have the real Signal worker queue and deliver one identity-bound v3 wake."""
        previous = self.event_ids()
        sent_at = int(time.time())
        signal.wait_ack(signal.send_envelope(
            signal_envelope(urgent=True), request_id=(1 << 40) + 3
        ))
        self.barrier(signal)
        created = self.event_ids() - previous
        require(len(created) == 1, "v3 Signal wake did not record exactly one event ID")
        event_id = created.pop()
        return self.capture_v3_provider_request(
            enrollment, sent_at, event_id, "wake"
        )

    def v3_private_import_and_worker_events(self):
        """Exercise import status and Signal wake through real encrypted HTTP sends."""
        self.stage = "synthetic v3 private import and worker delivery"
        current = self.current()
        require(current["state"] == "active" and current["subscription_epoch"] == 1,
                "v3 test did not begin from the active v1 fixture")
        enrollment = json.loads(json.dumps(self.enrollment))
        control_key = bytes(range(32))
        enrollment.update(
            enrollment_version=3,
            request_id=str(uuid.uuid4()),
            import_seq=1,
            control_key=base64.urlsafe_b64encode(control_key).rstrip(b"=").decode("ascii"),
        )
        enrollment["subscription"].update(
            subscription_epoch=current["subscription_epoch"] + 1,
            supported_event_versions=[1, 2, 3],
        )
        expected_key_id = event_key_id(enrollment)
        self.captured_v3_bodies = []
        self.v3_control_key = enrollment["control_key"]
        self.stage = "v3 private import receipt and enrollment_imported queue"
        sent_at = int(time.time())
        receipt = self.import_value(enrollment)
        require(receipt["enrollment_version"] == 3
                and receipt["request_id"] == enrollment["request_id"]
                and receipt["subscription_epoch"] == 2
                and receipt["selected_event_version"] == 3
                and receipt["status"] == "accepted"
                and receipt["replayed"] is False,
                "v3 private import returned an unexpected receipt")
        require("key_id" not in receipt and "import_seq" not in receipt,
                "v3 import receipt exposed internal key or sequence metadata")
        queued_events = self.rows(
            "SELECT event_id FROM encrypted_push_queue WHERE account_id=?", (ACCOUNT,)
        )
        ledger_count = self.rows(
            "SELECT count(*) FROM encrypted_push_event_ids WHERE account_id=?", (ACCOUNT,)
        )[0][0]
        require(len(queued_events) == 1 and self.current()["event_version"] == 3,
                f"v3 import did not activate a single v3 status event (queued={len(queued_events)}, ledger={ledger_count})")
        credentials = f"{ACCOUNT}.{enrollment['device_id']}:{PASSWORD}"

        with FakeSignal(self.directory / "v3-signal-tls", credentials) as signal:
            try:
                self.start_signal_worker(signal)
                signal.wait_connected()
                self.mark("real worker authenticates the synthetic Signal device after v3 private import")
                queued = self.rows(
                    "SELECT event_id FROM encrypted_push_queue WHERE account_id=?",
                    (ACCOUNT,),
                )
                require(len(queued) == 1, "v3 enrollment_imported event was not queued exactly once")
                self.capture_v3_provider_request(
                    enrollment, sent_at, queued[0][0], "status", "enrollment_imported"
                )
                self.mark("real worker sends encrypted enrollment_imported; independent decrypt matches import_id and HMAC key_id")
                self.require_no_push()

                self.stage = "authenticated Signal wake produces v3 encrypted provider request"
                _, wake_event = self.send_v3_wake(signal, enrollment)
                require(wake_event["key_id"] == expected_key_id
                        and wake_event["import_id"] == enrollment["request_id"],
                        "v3 wake did not retain the active import identity")
                self.mark("urgent Signal envelope produces an independently decrypted v3 wake with the active import identity")
                self.require_no_push()
            finally:
                self.stop_worker()

    def run(self):
        """Exercise dispatch, suppression, TLS verification and redaction with synthetic peers."""
        self.stage = "test-signal build preflight (cargo build --locked --features test-signal)"
        # Ordinary/release binaries ignore the compiled-out fields. Refuse them
        # before starting a server, so a mistaken test invocation cannot connect
        # to real Signal using the synthetic enrollment.
        probe = self.make_config(
            test_signal_url="wss://127.0.0.1:1/v1/websocket/",
            test_signal_ca=str(self.directory / "missing-test-ca.pem"),
        )
        self.cli("migrate", config=probe, plain_error="invalid_test_signal_configuration")
        self.stage = "synthetic enrollment"
        receipt = self.import_value(self.enrollment)
        require(receipt["status"] == "accepted" and self.queued() == 0,
                "synthetic enrollment did not start with an empty push queue")
        credentials = f"{ACCOUNT}.{self.enrollment['device_id']}:{PASSWORD}"
        self.stage = "authenticated TLS websocket and Signal envelope dispatch"
        with FakeSignal(self.directory / "signal-tls", credentials) as signal:
            try:
                self.start_signal_worker(signal)
                signal.wait_connected()
                self.mark("real server connects through TLS and authenticates the synthetic linked device")

                self.require_suppressed(signal, signal_envelope(urgent=False))
                self.mark("nonurgent Signal envelope and later ACK barrier leave no durable event or provider push")

                self.require_suppressed(signal, b"\xff")
                self.mark("malformed Signal envelope and later ACK barrier leave no durable event or provider push")

                first_id, first_body = self.send_wake(
                    signal, signal_envelope(urgent=True), request_id=(1 << 40) + 1
                )
                self.mark("urgent envelope and matching uint64 ACK produce a durable event and matching encrypted provider POST")
                self.mark("independent RFC 8291 decryption verifies wake schema, instance, epoch, UUID, timestamps and padding")
                self.require_no_push()

                # The no-extra-push observation above also clears the real
                # one-second wake throttle; no test-only clock is needed.
                second_id, second_body = self.send_wake(signal, signal_envelope(urgent=None))
                require(first_id != second_id and first_body[:16] != second_body[:16]
                        and first_body[21:86] != second_body[21:86],
                        "separate Signal wakes reused event ID, encryption salt or sender key")
                self.mark("omitted urgent field preserves proto2 default true with a fresh encrypted wake")
                self.require_no_push()
            finally:
                self.stop_worker()

        self.stage = "untrusted Signal CA rejection"
        unrelated_ca, _, _ = create_tls_material(self.directory / "unrelated-ca")
        with FakeSignal(self.directory / "untrusted-signal", credentials) as signal:
            try:
                self.start_signal_worker(signal, ca_path=unrelated_ca)
                signal.wait_tls_rejection()
                self.require_no_push(timeout=0.1)
                self.mark("wrong CA causes an observed TLS rejection before credentials or websocket upgrade")
            finally:
                self.stop_worker()

        self.stage = "Signal hostname verification"
        with FakeSignal(self.directory / "wrong-host", credentials,
                        certificate_name="wrong-host.example.invalid") as signal:
            try:
                self.start_signal_worker(signal)
                signal.wait_tls_rejection()
                self.require_no_push(timeout=0.1)
                self.mark("trusted certificate for another hostname is rejected before websocket upgrade")
            finally:
                self.stop_worker()

        self.v3_private_import_and_worker_events()

        self.stage = "Signal transport log redaction"
        joined = b"\n".join(self.outputs)
        for marker in [PASSWORD, base64.b64encode(credentials.encode()).decode(),
                       "SYNTHETIC-SIGNAL-CONTENT-CANARY", "SYNTHETIC-ENDPOINT-CANARY",
                       "SYNTHETIC-QUERY-CANARY", self.metadata["auth"],
                       self.metadata["p256dh"], self.metadata["receiver_private"],
                       self.v3_control_key]:
            require(marker.encode() not in joined, "Signal transport logs exposed a synthetic secret canary")
        self.mark("trace logging keeps Signal credentials, frame content and push secrets redacted")


def main():
    """Run the isolated synthetic suite and emit a redacted, nonempty result record."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--binary", type=Path, default=ROOT / "target/debug/mollysocket")
    parser.add_argument("--output", type=Path, help="optional redacted JSON result path")
    parser.add_argument(
        "--capture-v3-body", type=Path,
        help="optional private base64 artifact with synthetic v3 provider ciphertext bodies",
    )
    arguments = parser.parse_args()
    binary = arguments.binary.resolve()
    if not binary.is_file():
        parser.error("build first with cargo build --locked --features test-signal")
    checker_path = ROOT / "crates/colliesocket-push/tools/check_fixtures.py"
    spec = importlib.util.spec_from_file_location("independent_push_checker", checker_path)
    checker = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(checker)
    metadata = json.loads((ROOT / "crates/colliesocket-push/fixtures/metadata.json").read_text())
    require(metadata.get("synthetic") is True, "only public synthetic enrollment fixtures are permitted")
    previous_umask = os.umask(0o077)
    result = {
        "result": "FAIL", "scope": "fake Signal TLS websocket to encrypted loopback provider; not device delivery",
        "binary_sha256": hashlib.sha256(binary.read_bytes()).hexdigest(),
        "python": sys.version.split()[0], "cryptography": checker.cryptography.__version__,
        "openssl": checker.backend.openssl_version_text(), "checks": [], "not_run": NOT_RUN,
    }
    provider = Provider()
    harness = None
    try:
        with tempfile.TemporaryDirectory(prefix="colliesocket-signal-") as temporary:
            directory = Path(temporary)
            directory.chmod(0o700)
            harness = SignalHarness(directory, binary, provider, checker, metadata)
            try:
                harness.run()
                require(harness.checks, "zero Signal integration checks ran")
                result["result"] = "PASS"
            except (CheckFailure, FakeSignalError) as failure:
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
                    result.setdefault("failure", "Signal worker cleanup failed")
                result["checks"] = harness.checks
                result["checks_passed"] = len(harness.checks)
    finally:
        provider.close()
        os.umask(previous_umask)
    if arguments.capture_v3_body and result["result"] == "PASS":
        try:
            require(harness is not None and len(harness.captured_v3_bodies) == 2,
                    "v3 body capture did not observe both status and wake")
            artifact_path = arguments.capture_v3_body.resolve()
            artifact_path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
            artifact = {
                "synthetic_only": True,
                "scope": "captured loopback provider POST bodies; not device delivery",
                "events": harness.captured_v3_bodies,
            }
            private_file(artifact_path, json.dumps(artifact, indent=2).encode() + b"\n")
            result["v3_capture_artifact"] = str(artifact_path)
            result["v3_captured_bodies"] = [
                {key: event[key] for key in ("kind", "code", "body_length", "body_sha256")}
                for event in harness.captured_v3_bodies
            ]
        except (CheckFailure, OSError) as failure:
            result["result"] = "FAIL"
            result["failure"] = str(failure) if isinstance(failure, CheckFailure) else type(failure).__name__
            result["stage"] = "v3 body artifact capture"
    rendered = json.dumps(result, indent=2) + "\n"
    if arguments.output:
        private_file(arguments.output, rendered.encode())
    print(rendered, end="")
    return 0 if result["result"] == "PASS" else 1


if __name__ == "__main__":
    raise SystemExit(main())
