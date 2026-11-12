"""Small loopback-only TLS Signal websocket fixture for integration tests.

The wire fields follow proto/WebSocketResources.proto and proto/SignalService.proto.
This deliberately implements only the websocket/protobuf subset used by the server.
Certificates and their private keys are generated in the test's temporary directory;
no key or CA is installed into the machine's trust store.

FakeSignal(directory, credentials) exposes url and ca_path for the test-signal
configuration. wait_connected() verifies the HTTP upgrade and Basic credentials.
send_envelope(bytes) accepts an arbitrary serialized Signal Envelope, including
custom content needed by control-message tests, and returns the request ID used by
wait_ack(id). signal_envelope() constructs ordinary urgent/nonurgent envelopes.
"""

import base64
from datetime import datetime, timedelta, timezone
import hashlib
import ipaddress
from pathlib import Path
import queue
import socket
import socketserver
import ssl
import struct
import threading
import time

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID


class FakeSignalError(Exception):
    """Fixed, redacted fixture failure; never contains wire bytes or credentials."""


def _require(condition, label):
    """Fail with a fixed label so assertions never expose credentials or frames."""
    if not condition:
        raise FakeSignalError(label)


def _private_file(path, data):
    """Write temporary TLS material with owner-only read/write permissions."""
    path.write_bytes(data)
    path.chmod(0o600)
    return path


def create_tls_material(directory, certificate_name="127.0.0.1"):
    """Return (CA, certificate, key) PEM paths; override the name for TLS tests."""
    directory = Path(directory)
    directory.mkdir(mode=0o700, parents=True, exist_ok=True)
    now = datetime.now(timezone.utc)
    ca_key = ec.generate_private_key(ec.SECP256R1())
    # Distinct issuer names make an unrelated CA fail as an unknown issuer,
    # rather than a signature failure against a different key with the same name.
    ca_id = f"{x509.random_serial_number():x}"[:32]
    ca_name = x509.Name([x509.NameAttribute(
        NameOID.COMMON_NAME, f"Synthetic Signal test CA {ca_id}"
    )])
    ca = (
        x509.CertificateBuilder()
        .subject_name(ca_name).issuer_name(ca_name).public_key(ca_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(days=1)).not_valid_after(now + timedelta(days=2))
        .add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)
        .add_extension(x509.KeyUsage(False, False, False, False, False, True, True, None, None), critical=True)
        .sign(ca_key, hashes.SHA256())
    )
    server_key = ec.generate_private_key(ec.SECP256R1())
    try:
        san = x509.IPAddress(ipaddress.ip_address(certificate_name))
    except ValueError:
        san = x509.DNSName(certificate_name)
    certificate = (
        x509.CertificateBuilder()
        .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, certificate_name)]))
        .issuer_name(ca_name).public_key(server_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(days=1)).not_valid_after(now + timedelta(days=2))
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .add_extension(x509.SubjectAlternativeName([san]), critical=False)
        .add_extension(x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH]), critical=False)
        .add_extension(x509.KeyUsage(True, False, False, False, False, False, False, None, None), critical=True)
        .sign(ca_key, hashes.SHA256())
    )
    ca_path = _private_file(directory / "ca.pem", ca.public_bytes(serialization.Encoding.PEM))
    certificate_path = _private_file(directory / "server.pem", certificate.public_bytes(serialization.Encoding.PEM))
    key_path = _private_file(directory / "server-key.pem", server_key.private_bytes(
        serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()
    ))
    return ca_path, certificate_path, key_path


def _varint(number):
    """Encode an unsigned protobuf integer, rejecting values outside uint64."""
    _require(0 <= number <= (1 << 64) - 1, "protobuf integer outside uint64 range")
    result = bytearray()
    while number >= 128:
        result.append((number & 127) | 128)
        number >>= 7
    result.append(number)
    return bytes(result)


def _integer(field, number):
    """Encode a protobuf varint field with its wire-type-zero tag."""
    return _varint(field << 3) + _varint(number)


def _bytes(field, value):
    """Encode a length-delimited protobuf field, converting text to UTF-8."""
    if isinstance(value, str):
        value = value.encode()
    return _varint((field << 3) | 2) + _varint(len(value)) + value


def signal_envelope(*, urgent=True, content=b"SYNTHETIC-SIGNAL-CONTENT-CANARY",
                    source_service_id=None, destination_service_id=None):
    """Encode a ciphertext Envelope; content may be any synthetic per-device blob."""
    envelope = _integer(1, 1) + _integer(5, int(time.time() * 1000)) + _bytes(8, content)
    if source_service_id is not None:
        envelope += _bytes(11, source_service_id)
    if destination_service_id is not None:
        envelope += _bytes(13, destination_service_id)
    if urgent is not None:
        envelope += _integer(14, int(urgent))
    return envelope


def _fields(data):
    """Decode varint/length-delimited fixture messages without a protobuf dependency."""
    offset = 0

    def integer():
        """Consume at most ten varint bytes and reject truncated input."""
        nonlocal offset
        value = 0
        for shift in range(0, 70, 7):
            _require(offset < len(data), "truncated protobuf integer")
            octet = data[offset]
            offset += 1
            value |= (octet & 127) << shift
            if not octet & 128:
                return value
        raise FakeSignalError("oversize protobuf integer")

    result = {}
    while offset < len(data):
        tag = integer()
        _require(tag >> 3 != 0, "invalid protobuf field")
        if tag & 7 == 0:
            value = integer()
        elif tag & 7 == 2:
            length = integer()
            _require(length <= len(data) - offset, "truncated protobuf bytes")
            value = data[offset:offset + length]
            offset += length
        else:
            raise FakeSignalError("unsupported fixture protobuf wire type")
        result[tag >> 3] = value
    return result


def _response(request_id):
    """Encode a WebSocketMessage containing a matching 200/OK response."""
    response = _integer(1, request_id) + _integer(2, 200) + _bytes(3, "OK")
    return _integer(1, 2) + _bytes(3, response)


class FakeSignal:
    """One synthetic device's websocket server, with bounded waits and clean shutdown."""

    def __init__(self, directory, credentials, *, certificate_name="127.0.0.1"):
        """Start an ephemeral loopback TLS listener with synthetic device credentials."""
        self.ca_path, certificate, key = create_tls_material(directory, certificate_name)
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.minimum_version = ssl.TLSVersion.TLSv1_2
        context.load_cert_chain(certificate, key)
        self._authorization = "Basic " + base64.b64encode(credentials.encode()).decode()
        self._connected = queue.Queue()
        self._acks = queue.Queue()
        self._failures = queue.Queue()
        self._tls_failures = queue.Queue()
        self._connections = []
        self._connection = None
        self._send_lock = threading.Lock()
        self._stopping = threading.Event()
        self._pending_acks = {}
        self._serial = 0
        self.connection_count = 0
        fixture = self

        class Handler(socketserver.BaseRequestHandler):
            """Handle one TLS peer and record only redacted protocol failures."""

            def handle(self):
                """Bound the TLS handshake, verify the upgrade, then collect client ACKs."""
                connection = None
                try:
                    self.request.settimeout(5)
                    connection = context.wrap_socket(self.request, server_side=True, do_handshake_on_connect=False)
                    fixture._connections.append(connection)
                    try:
                        connection.do_handshake()
                    except ssl.SSLError as error:
                        _require(error.reason in {
                            "TLSV1_ALERT_UNKNOWN_CA", "SSLV3_ALERT_BAD_CERTIFICATE",
                            "SSLV3_ALERT_CERTIFICATE_UNKNOWN", "TLS_ALERT_CERTIFICATE_UNKNOWN",
                        }, "TLS handshake failed without a certificate rejection alert")
                        fixture._tls_failures.put("client rejected synthetic TLS certificate")
                        return
                    connection.settimeout(30)
                    with connection.makefile("rb") as stream:
                        fixture._handshake(stream, connection)
                        fixture._connection = connection
                        fixture.connection_count += 1
                        fixture._connected.put(True)
                        fixture._read_frames(stream, connection)
                except FakeSignalError as error:
                    fixture._failures.put(str(error))
                except (ValueError, UnicodeError, KeyError, TypeError):
                    fixture._failures.put("malformed synthetic websocket handshake or message")
                except (OSError, EOFError):
                    if not fixture._stopping.is_set():
                        fixture._failures.put("synthetic websocket connection closed")
                finally:
                    if connection is not None:
                        connection.close()

        class Server(socketserver.ThreadingTCPServer):
            """Keep fixture connection threads from delaying interpreter shutdown."""

            daemon_threads = True
            allow_reuse_address = True

        self.server = Server(("127.0.0.1", 0), Handler)
        self.url = f"wss://127.0.0.1:{self.server.server_address[1]}/v1/websocket/"
        self.thread = threading.Thread(
            target=lambda: self.server.serve_forever(poll_interval=0.05), daemon=True
        )
        self.thread.start()

    def _handshake(self, stream, connection):
        """Validate the path, credentials and RFC6455 upgrade within 8192 header bytes."""
        request = stream.readline(8193)
        _require(request == b"GET /v1/websocket/ HTTP/1.1\r\n", "unexpected websocket request target")
        headers, length = {}, len(request)
        while True:
            line = stream.readline(8193)
            length += len(line)
            _require(line and length <= 8192, "invalid websocket upgrade headers")
            if line == b"\r\n":
                break
            name, separator, value = line.partition(b":")
            _require(separator, "malformed websocket upgrade header")
            headers[name.decode("ascii").lower()] = value.decode("ascii").strip()
        _require(headers.get("authorization") == self._authorization, "wrong synthetic linked-device credentials")
        _require(headers.get("upgrade", "").lower() == "websocket", "missing websocket upgrade")
        _require("upgrade" in headers.get("connection", "").lower(), "missing upgrade connection token")
        _require(headers.get("sec-websocket-version") == "13", "unexpected websocket version")
        key = headers.get("sec-websocket-key", "")
        _require(len(base64.b64decode(key, validate=True)) == 16, "invalid websocket handshake key")
        accept = base64.b64encode(hashlib.sha1(
            (key + "258EAFA5-E914-47DA-95CA-C5AB0DC85B11").encode()
        ).digest()).decode()
        connection.sendall((
            "HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\n"
            f"Connection: Upgrade\r\nSec-WebSocket-Accept: {accept}\r\n\r\n"
        ).encode())

    @staticmethod
    def _read_exact(stream, length):
        """Read a complete frame component or fail if the peer closes early."""
        value = stream.read(length)
        if len(value) != length:
            raise EOFError
        return value

    def _read_frames(self, stream, connection):
        """Read masked frames up to 64 KiB, answer keepalives and retain protobuf ACKs."""
        while not self._stopping.is_set():
            first, second = self._read_exact(stream, 2)
            _require(first & 0xF0 == 0x80 and second & 0x80, "invalid or unmasked client websocket frame")
            opcode, length = first & 15, second & 127
            if length == 126:
                length = struct.unpack("!H", self._read_exact(stream, 2))[0]
            elif length == 127:
                length = struct.unpack("!Q", self._read_exact(stream, 8))[0]
            _require(length <= 65536, "oversize synthetic websocket frame")
            mask = self._read_exact(stream, 4)
            masked = self._read_exact(stream, length)
            payload = bytes(octet ^ mask[index % 4] for index, octet in enumerate(masked))
            if opcode == 8:
                self._send_frame(connection, payload, opcode=8)
                return
            if opcode == 9:
                self._send_frame(connection, payload, opcode=10)
                continue
            if opcode == 10:
                continue
            _require(opcode == 2, "unexpected nonbinary Signal websocket message")
            message = _fields(payload)
            if message.get(1) == 1:
                request = _fields(message.get(2, b""))
                _require(request.get(1) == b"GET" and request.get(2) == b"/v1/keepalive",
                         "unexpected request from Signal websocket client")
                self._send_frame(connection, _response(request[4]))
            else:
                _require(message.get(1) == 2, "unexpected Signal websocket message type")
                self._acks.put(_fields(message.get(3, b"")))

    def _send_frame(self, connection, payload, opcode=2):
        """Serialize unmasked server frames under a lock to prevent interleaved writes."""
        length = len(payload)
        if length < 126:
            header = bytes([0x80 | opcode, length])
        elif length <= 65535:
            header = bytes([0x80 | opcode, 126]) + struct.pack("!H", length)
        else:
            header = bytes([0x80 | opcode, 127]) + struct.pack("!Q", length)
        with self._send_lock:
            connection.sendall(header + payload)

    def _take(self, source, timeout, label):
        """Wait for a fixture observation, surfacing a recorded failure on timeout."""
        try:
            return source.get(timeout=timeout)
        except queue.Empty as error:
            try:
                failure = self._failures.get_nowait()
            except queue.Empty:
                failure = label
            raise FakeSignalError(failure) from error

    def wait_connected(self, timeout=10):
        """Require an authenticated TLS websocket upgrade within the time bound."""
        self._take(self._connected, timeout, "synthetic Signal websocket did not connect")

    def wait_tls_rejection(self, timeout=10):
        """Require a certificate rejection alert without any completed websocket upgrade."""
        self._take(self._tls_failures, timeout, "expected TLS rejection was not observed")
        _require(self.connection_count == 0, "untrusted TLS connection reached websocket upgrade")

    def send_envelope(self, envelope, *, request_id=None, path="/api/v1/message", verb="PUT"):
        """Send arbitrary envelope bytes in a binary request and return its uint64 ID."""
        _require(self._connection is not None, "send requires a connected synthetic websocket")
        if request_id is None:
            self._serial += 1
            request_id = self._serial
        request = _bytes(1, verb) + _bytes(2, path) + _bytes(3, envelope) + _integer(4, request_id)
        self._send_frame(self._connection, _integer(1, 1) + _bytes(2, request))
        return request_id

    def wait_ack(self, request_id, timeout=5):
        """Require the matching 200/OK ACK by a deadline, retaining other request IDs."""
        deadline = time.monotonic() + timeout
        while request_id not in self._pending_acks:
            response = self._take(self._acks, max(0, deadline - time.monotonic()),
                                  "Signal envelope acknowledgement did not arrive")
            _require(1 in response, "Signal acknowledgement omitted its request ID")
            self._pending_acks[response[1]] = response
        response = self._pending_acks.pop(request_id)
        _require(response.get(2) == 200 and response.get(3) == b"OK", "Signal envelope was not acknowledged OK")
        return response

    def close(self):
        """Stop accepting peers and close active sockets to release blocked readers."""
        self._stopping.set()
        self.server.shutdown()
        for connection in self._connections:
            try:
                connection.shutdown(socket.SHUT_RDWR)
            except OSError:
                pass
            connection.close()
        self.server.server_close()
        self.thread.join(timeout=2)

    def __enter__(self):
        """Expose the running fixture to a context-managed test."""
        return self

    def __exit__(self, *_):
        """Close the fixture even when an integration assertion fails."""
        self.close()
