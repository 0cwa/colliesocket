#!/usr/bin/env python3
"""Independent RFC 8291 check using Python HMAC and cryptography/OpenSSL.

This is deliberately not a RustCrypto/web-push-native roundtrip. Only public
RFC/synthetic fixtures are processed. No network or production endpoint is used.
Passing this check is not Android, enrollment, lock, or security acceptance.
"""

import argparse
import base64
import hashlib
import hmac
import json
import pathlib
import sys

import cryptography
from cryptography.exceptions import InvalidTag
from cryptography.hazmat.backends.openssl.backend import backend
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat


def b64(value):
    return base64.urlsafe_b64decode(value + "=" * (-len(value) % 4))


def mac(key, value):
    return hmac.new(key, value, hashlib.sha256).digest()


def public_bytes(key):
    return key.public_bytes(Encoding.X962, PublicFormat.UncompressedPoint)


def secret(value):
    return ec.derive_private_key(int.from_bytes(b64(value), "big"), ec.SECP256R1())


def derive(salt, shared, auth, receiver, sender):
    ikm = mac(mac(auth, shared), b"WebPush: info\0" + receiver + sender + b"\1")
    prk = mac(salt, ikm)
    return (mac(prk, b"Content-Encoding: aes128gcm\0\1")[:16],
            mac(prk, b"Content-Encoding: nonce\0\1")[:12], ikm)


def decrypt(frame, private, auth):
    if not 103 <= len(frame) <= 4096:
        raise ValueError("invalid_body_length")
    if len(auth) != 16:
        raise ValueError("invalid_auth_length")
    rs = int.from_bytes(frame[16:20], "big")
    if rs != 4096 or rs <= len(frame) - 86:
        raise ValueError("invalid_record_size")
    if frame[20] != 65 or frame[21] != 4:
        raise ValueError("invalid_sender_key_format")
    sender = frame[21:86]
    sender_key = ec.EllipticCurvePublicKey.from_encoded_point(ec.SECP256R1(), sender)
    receiver = public_bytes(private.public_key())
    shared = private.exchange(ec.ECDH(), sender_key)
    cek, nonce, _ = derive(frame[:16], shared, auth, receiver, sender)
    record = AESGCM(cek).decrypt(nonce, frame[86:], None)
    unpadded = record.rstrip(b"\0")
    if not unpadded or unpadded[-1] != 2:
        raise ValueError("invalid_final_delimiter")
    return unpadded[:-1]


def deterministic_frame(record, metadata):
    """Independent test encryption, including explicit delimiter/padding bytes."""
    sender = secret(metadata["sender_private"])
    receiver_bytes = b64(metadata["p256dh"])
    receiver = ec.EllipticCurvePublicKey.from_encoded_point(ec.SECP256R1(), receiver_bytes)
    sender_bytes = public_bytes(sender.public_key())
    salt = b64(metadata["salt"])
    shared = sender.exchange(ec.ECDH(), receiver)
    cek, nonce, ikm = derive(salt, shared, b64(metadata["auth"]), receiver_bytes, sender_bytes)
    assert shared == b64("kyrL1jIIOHEzg3sM2ZWRHDRB62YACZhhSlknJ672kSs")
    assert ikm == b64("S4lYMb_L0FxCeq0WhDx813KgSYqU26kOyzWUdsXYyrg")
    assert cek == b64("oIhVW04MRdy2XN9CiKLxTg")
    assert nonce == b64("4h_95klXJ5E_qnoN")
    return salt + (4096).to_bytes(4, "big") + bytes([65]) + sender_bytes + AESGCM(cek).encrypt(nonce, record, None)


def must_reject(operation, label):
    try:
        operation()
    except (ValueError, InvalidTag):
        return 1
    raise AssertionError(f"accepted invalid input: {label}")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("fixture_dir", nargs="?", type=pathlib.Path,
                        default=pathlib.Path(__file__).resolve().parents[1] / "fixtures")
    args = parser.parse_args()
    metadata = json.loads((args.fixture_dir / "metadata.json").read_text())
    if metadata.get("synthetic") is not True:
        raise ValueError("only_synthetic_fixture_data_allowed")
    private = secret(metadata["receiver_private"])
    auth = b64(metadata["auth"])
    rfc = (args.fixture_dir / "rfc8291.bin").read_bytes()
    wake = (args.fixture_dir / "wake-v1.bin").read_bytes()
    random = (args.fixture_dir / "sender-random.bin").read_bytes()
    event = (args.fixture_dir / "wake-v1.json").read_bytes()
    expected = event.ljust(3993, b" ")
    assert len(event) <= 3072
    assert public_bytes(private.public_key()) == b64(metadata["p256dh"])
    assert len(rfc) == 144
    assert hashlib.sha256(rfc).hexdigest() == "f976e174457c5111a0b05234e648bc012cb1e2b37949afce4d7b1e84752953c7"
    assert decrypt(rfc, private, auth) == b"When I grow up, I want to be a watermelon"
    assert decrypt(wake, private, auth) == expected
    assert decrypt(random, private, auth) == expected
    assert json.loads(decrypt(wake, private, auth)) == json.loads(event)
    assert len(wake) == len(random) == 4096
    assert deterministic_frame(b"When I grow up, I want to be a watermelon\2", metadata) == rfc
    assert deterministic_frame(expected + b"\2", metadata) == wake
    for item in metadata["files"]:
        assert hashlib.sha256((args.fixture_dir / item["path"]).read_bytes()).hexdigest() == item["sha256"]

    negative_count = 0
    invalid = {f"truncated-{n}": rfc[:n] for n in [0, 1, 20, 21, 85, 86, 102, 143]}
    invalid["oversize"] = wake + b"\0"
    for idlen in [0, 1, 64, 66, 255]:
        invalid[f"keyid-length-{idlen}"] = rfc[:20] + bytes([idlen]) + rfc[21:]
    for rs in [0, 1, 16, len(rfc) - 86, 4095, 4097]:
        invalid[f"record-size-{rs}"] = rfc[:16] + rs.to_bytes(4, "big") + rfc[20:]
    invalid["compressed-key-prefix"] = rfc[:21] + b"\3" + rfc[22:]
    invalid["off-curve-key"] = rfc[:21] + b"\4" + bytes(64) + rfc[86:]
    invalid["extra-record"] = rfc + rfc[86:]
    for offset in [0, 15, 86, len(rfc) - 1]:
        invalid[f"tampered-{offset}"] = rfc[:offset] + bytes([rfc[offset] ^ 1]) + rfc[offset + 1:]
    for label, frame in invalid.items():
        negative_count += must_reject(lambda f=frame: decrypt(f, private, auth), label)
    negative_count += must_reject(lambda: decrypt(wake, private, bytes(16)), "wrong-auth")
    negative_count += must_reject(lambda: decrypt(wake, private, bytes(15)), "short-auth")
    wrong_private = ec.derive_private_key(1, ec.SECP256R1())
    negative_count += must_reject(lambda: decrypt(wake, wrong_private, auth), "wrong-receiver-private")
    for delimiter in [b"\0", b"\1", b"\3", b"\xff"]:
        frame = deterministic_frame(b"invalid-final-padding" + delimiter, metadata)
        negative_count += must_reject(lambda f=frame: decrypt(f, private, auth), "bad-final-delimiter")
    zeros = deterministic_frame(bytes(32), metadata)
    negative_count += must_reject(lambda: decrypt(zeros, private, auth), "all-zero-record")
    padded = deterministic_frame(b"padding-test\2" + bytes(20), metadata)
    assert decrypt(padded, private, auth) == b"padding-test"

    print(json.dumps({
        "result": "PASS",
        "scope": "Independent Python/OpenSSL check of actual Rust-generated output; not Android acceptance",
        "python": sys.version.split()[0], "cryptography": cryptography.__version__,
        "openssl": backend.openssl_version_text(),
        "positive_checks": ["published-vector-and-intermediates", "deterministic-rust-byte-match", "random-production-sender-decrypt", "json-whitespace-padding", "fixture-hashes", "valid-rfc-padding"],
        "negative_checks_passed": negative_count,
        "not_run": ["physical-android", "lock-behavior", "real-distributor", "production-enrollment", "security-audit"]
    }, indent=2))


if __name__ == "__main__":
    main()
