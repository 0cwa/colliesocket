#!/usr/bin/env python3
"""Offline v2 schemas and independent synthetic AES-256-GCM wire checks.

No real credentials, Signal service, device, or provider are used. Stateful
server acceptance is covered by Rust and fake-websocket integration tests.
"""
import base64
import copy
import importlib.util
import json
from pathlib import Path
import uuid

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from jsonschema import Draft202012Validator, ValidationError

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location(
    "contract_v1", ROOT.parent / "v1/tools/conformance.py")
v1 = importlib.util.module_from_spec(spec)
spec.loader.exec_module(v1)

MAGIC = b"COLLIESOCKET-CTRL"
MAX_FRAME = 3146
SCHEMAS = {
    kind: v1.parse((ROOT / f"{kind}.schema.json").read_bytes())
    for kind in ("enrollment", "response", "event", "control")
}


def encoded(data):
    return base64.urlsafe_b64encode(data).decode().rstrip("=")


def decoded(value):
    return base64.urlsafe_b64decode(value + "=" * (-len(value) % 4))


def serialized(value):
    return json.dumps(value, separators=(",", ":")).encode()


def fixture(name):
    return v1.parse((ROOT / "fixtures" / name).read_bytes())


def validate(kind, data, allowed_endpoints=()):
    if len(data) > (3072 if kind == "control" else 8192):
        raise v1.ContractError("input_too_large")
    value = v1.parse(data)
    v1.no_floats(value, "invalid_enrollment")
    try:
        Draft202012Validator(SCHEMAS[kind]).validate(value)
    except ValidationError as error:
        raise v1.ContractError("invalid_enrollment") from error
    if kind == "enrollment":
        if "control_key" in value:
            v1.b64(value["control_key"], 32)
        # Existing keys and endpoints must continue to pass unchanged v1 rules.
        original = copy.deepcopy(value)
        original.pop("control_key", None)
        original["enrollment_version"] = 1
        original["subscription"]["supported_event_versions"] = [1]
        v1.validate("enrollment", serialized(original), 0, allowed_endpoints)
    elif kind == "control":
        original = fixture("enrollment-unkeyed.json")
        original["enrollment_version"] = 1
        original["subscription"].update(value)
        v1.validate("enrollment", serialized(original), 0, allowed_endpoints)
    elif kind == "event":
        original = copy.deepcopy(value)
        original["version"] = 1
        if original.get("code") == "subscription_updated":
            original["code"] = "connection_unavailable"
        v1.validate("event", serialized(original), 1800000000)
    return value


def header(account, device, epoch):
    return (MAGIC + b"\x02" + uuid.UUID(account).bytes
            + device.to_bytes(4, "big") + epoch.to_bytes(8, "big"))


def decrypt(frame, key, account, device):
    if not 75 <= len(frame) <= MAX_FRAME:
        raise ValueError("invalid_frame")
    if frame[:17] != MAGIC or frame[17] != 2:
        raise ValueError("invalid_frame")
    epoch = int.from_bytes(frame[38:46], "big")
    if not 1 <= epoch <= 9007199254740991:
        raise ValueError("invalid_epoch")
    aad = header(account, device, epoch)
    if aad != frame[:46]:
        raise ValueError("wrong_destination")
    plaintext = AESGCM(key).decrypt(frame[46:58], frame[58:], aad)
    return validate("control", plaintext)


def must_reject(operation, name):
    try:
        operation()
    except (ValueError, InvalidTag, v1.ContractError):
        return 1
    raise AssertionError(f"accepted invalid synthetic case: {name}")


def main():
    for schema in SCHEMAS.values():
        Draft202012Validator.check_schema(schema)
    keyed = fixture("enrollment-keyed.json")
    unkeyed = fixture("enrollment-unkeyed.json")
    status = fixture("status-updated.json")
    vector = fixture("control-v2.json")
    assert vector["synthetic_only"] is True
    payload = v1.parse(vector["plaintext_utf8"])
    positives = 0
    for kind, value in [("enrollment", keyed), ("enrollment", unkeyed),
                        ("event", status), ("control", payload)]:
        validate(kind, serialized(value))
        positives += 1
    for selected in [1, 2]:
        validate("response", serialized({
            "enrollment_version": 2, "request_id": keyed["request_id"],
            "instance": keyed["subscription"]["instance"],
            "subscription_epoch": 1, "selected_event_version": selected,
            "capabilities": ["wake", "test", "status"], "status": "accepted",
        }))
        positives += 1
    wake = dict(status, kind="wake")
    wake.pop("code")
    validate("event", serialized(wake))
    positives += 1

    negatives = 0
    invalid_key_values = [None, "", encoded(bytes(31)), encoded(bytes(33)),
                          encoded(bytes(32)) + "=", "!" * 43,
                          encoded(bytes(32))[:-1] + "B"]
    for value in invalid_key_values:
        bad = dict(keyed, control_key=value)
        negatives += must_reject(lambda b=bad: validate("enrollment", serialized(b)),
                                 "control-key")
    for source, versions in [(keyed, [1]), (keyed, [2]),
                             (keyed, [2, 1]), (unkeyed, [1, 2])]:
        bad = copy.deepcopy(source)
        bad["subscription"]["supported_event_versions"] = versions
        negatives += must_reject(lambda b=bad: validate("enrollment", serialized(b)),
                                 "event-negotiation")
    bad = dict(keyed, enrollment_version=2.0)
    negatives += must_reject(lambda: validate("enrollment", serialized(bad)),
                             "float-enrollment-version")
    bad_v1 = dict(keyed, enrollment_version=1)
    negatives += must_reject(lambda: v1.validate("enrollment", serialized(bad_v1), 0),
                             "v1-control-key")
    bad_event = dict(status, version=1)
    negatives += must_reject(lambda: v1.validate("event", serialized(bad_event), 1800000000),
                             "v1-new-status")
    for name, value in [("code", None), ("code", "arbitrary"),
                        ("version", 1), ("kind", "wake"), ("expires_at", 1800000400)]:
        bad = dict(status, **{name: value})
        negatives += must_reject(lambda b=bad: validate("event", serialized(b)),
                                 "invalid-v2-event")
    for field in ["password", "control_key", "instance", "account_id",
                  "device_id", "subscription_epoch", "supported_event_versions"]:
        bad = dict(payload, **{field: "private-only"})
        negatives += must_reject(lambda b=bad: validate("control", serialized(b)),
                                 "control-private-field")
    for field, value in [("auth", None), ("auth", encoded(bytes(15))),
                         ("p256dh", encoded(b"\x04" + bytes(64))),
                         ("endpoint", "https://push.example.invalid/#"),
                         ("endpoint", "http://push.example.invalid/push")]:
        bad = dict(payload, **{field: value})
        negatives += must_reject(lambda b=bad: validate("control", serialized(b)),
                                 "invalid-control-value")
    for raw in [b'{"auth":"a","auth":"b"}', b"\xef\xbb\xbf{}",
                b"\xff{}", b"null", b"{}{}", b" " * 3073]:
        negatives += must_reject(lambda r=raw: validate("control", r),
                                 "invalid-control-json")
    http_payload = dict(payload, endpoint="http://push.example.invalid/push")
    validate("control", serialized(http_payload), ["http://push.example.invalid"])
    positives += 1

    frame = decoded(vector["frame_base64url"])
    key = v1.b64(vector["control_key"], 32)
    nonce = v1.b64(vector["nonce"], 12)
    account, device = vector["account_id"], vector["device_id"]
    aad = header(account, device, vector["subscription_epoch"])
    assert len(MAGIC) == 17 and len(aad) == 46
    assert aad.hex() == vector["aad_hex"]
    assert frame == aad + nonce + AESGCM(key).encrypt(
        nonce, vector["plaintext_utf8"].encode(), aad)
    assert decrypt(frame, key, account, device) == payload
    positives += 2

    for offset in [0, 16, 17, 18, 33, 34, 37, 38, 45, 46, 57, 58, len(frame) - 1]:
        modified = bytearray(frame)
        modified[offset] ^= 1
        negatives += must_reject(lambda b=bytes(modified): decrypt(b, key, account, device),
                                 "tampered-frame")
    for size in [0, 16, 17, 18, 45, 46, 57, 58, 73, len(frame) - 1]:
        negatives += must_reject(lambda n=size: decrypt(frame[:n], key, account, device),
                                 "truncated-frame")
    negatives += must_reject(lambda: decrypt(frame + bytes(MAX_FRAME), key, account, device),
                             "oversize-frame")
    negatives += must_reject(lambda: decrypt(frame, bytes(32), account, device), "wrong-key")
    negatives += must_reject(lambda: decrypt(frame, key, "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb", device),
                             "wrong-account")
    negatives += must_reject(lambda: decrypt(frame, key, account, device + 1), "wrong-device")
    for epoch in [0, 9007199254740992]:
        invalid_aad = header(account, device, epoch)
        invalid_frame = invalid_aad + nonce + AESGCM(key).encrypt(
            nonce, vector["plaintext_utf8"].encode(), invalid_aad)
        negatives += must_reject(lambda b=invalid_frame: decrypt(b, key, account, device),
                                 "authenticated-invalid-epoch")
    assert positives and negatives
    print(json.dumps({"result": "PASS", "positive_checks": positives,
                      "negative_checks": negatives,
                      "scope": "offline v2 schemas and independent synthetic AES-256-GCM vector"},
                     indent=2))


if __name__ == "__main__":
    main()
