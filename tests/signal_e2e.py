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

        self.stage = "Signal transport log redaction"
        joined = b"\n".join(self.outputs)
        for marker in [PASSWORD, base64.b64encode(credentials.encode()).decode(),
                       "SYNTHETIC-SIGNAL-CONTENT-CANARY", "SYNTHETIC-ENDPOINT-CANARY",
                       "SYNTHETIC-QUERY-CANARY", self.metadata["auth"],
                       self.metadata["p256dh"], self.metadata["receiver_private"]]:
            require(marker.encode() not in joined, "Signal transport logs exposed a synthetic secret canary")
        self.mark("trace logging keeps Signal credentials, frame content and push secrets redacted")


def main():
    """Run the isolated synthetic suite and emit a redacted, nonempty result record."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--binary", type=Path, default=ROOT / "target/debug/mollysocket")
    parser.add_argument("--output", type=Path, help="optional redacted JSON result path")
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
    rendered = json.dumps(result, indent=2) + "\n"
    if arguments.output:
        private_file(arguments.output, rendered.encode())
    print(rendered, end="")
    return 0 if result["result"] == "PASS" else 1


if __name__ == "__main__":
    raise SystemExit(main())
