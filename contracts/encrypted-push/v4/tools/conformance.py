#!/usr/bin/env python3
"""Offline v4 schema, semantic, and authenticated control-vector checks."""
import importlib.util
import json
import uuid
from pathlib import Path

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from jsonschema import Draft202012Validator, ValidationError

ROOT = Path(__file__).resolve().parents[1]
FIXTURES = ROOT / "fixtures"
SPEC = importlib.util.spec_from_file_location("encrypted_push_v1", ROOT.parent / "v1/tools/conformance.py")
V1 = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(V1)
NOW = 1_800_000_000


def fixture(name):
    return V1.parse((FIXTURES / f"{name}.json").read_bytes())


def compact(value):
    return json.dumps(value, separators=(",", ":"), ensure_ascii=True).encode("ascii")


def validate(kind, raw):
    limits = {"enrollment": 8192, "receiver-enrollment": 8192, "event": 3993,
              "control": 3072, "receipt": 1024}
    if len(raw) > limits[kind]:
        raise ValueError("input_too_large")
    value = V1.parse(raw)
    V1.no_floats(value, "integer tokens required")
    schema = V1.parse((ROOT / f"{kind}.schema.json").read_bytes())
    Draft202012Validator.check_schema(schema)
    Draft202012Validator(schema).validate(value)
    if kind in ("enrollment", "receiver-enrollment", "control"):
        sub = value if kind == "control" else value["subscription"]
        point = V1.b64(sub["p256dh"], 65)
        if point[0] != 4:
            raise ValueError("invalid_key")
        ec.EllipticCurvePublicKey.from_encoded_point(ec.SECP256R1(), point)
        V1.b64(sub["auth"], 16)
        if V1.origin(sub["endpoint"])[0] != "https":
            raise ValueError("explicit HTTP origin required")
        if kind != "control":
            V1.b64(value["control_key"], 32)
    elif kind == "event":
        issued, expires = value["issued_at"], value["expires_at"]
        if not 1 <= expires - issued <= 300 or issued > NOW + 60 or expires <= NOW:
            raise ValueError("invalid event time")
        if len(raw.rstrip(b" ")) > 3072:
            raise ValueError("input_too_large")
    return value


def control_header(account, device, receiver, epoch):
    return (b"COLLIESOCKET-CTRL\x04" + uuid.UUID(account).bytes + device.to_bytes(4, "big")
            + uuid.UUID(receiver).bytes + epoch.to_bytes(8, "big"))


def open_control(frame, key, account, device, receiver):
    if not 91 <= len(frame) <= 3162:
        raise ValueError("invalid control size")
    epoch = int.from_bytes(frame[54:62], "big")
    identity = uuid.UUID(receiver)
    if (str(identity) != receiver or identity.version != 4 or not 1 <= epoch <= 9007199254740991
            or frame[:62] != control_header(account, device, receiver, epoch)):
        raise ValueError("invalid control context")
    return validate("control", AESGCM(key).decrypt(frame[62:74], frame[74:], frame[:62]))


def must_reject(operation):
    try:
        operation()
    except (ValueError, ValidationError, InvalidTag):
        return
    raise AssertionError("negative fixture unexpectedly accepted")


def main():
    positives = {
        "bridge": "enrollment", "receiver": "receiver-enrollment", "wake": "event",
        "imported": "event", "updated": "event", "receipt": "receipt",
        "control-plaintext": "control",
    }
    for name, kind in positives.items():
        validate(kind, (FIXTURES / f"{name}.json").read_bytes())
    validate("event", compact(fixture("wake")).ljust(3993, b" "))
    negatives = fixture("invalid")
    for case in negatives:
        value = fixture(case["source"])
        if "remove" in case:
            del value[case["remove"]]
        else:
            fields = case["field"].split(".")
            target = value
            for field in fields[:-1]:
                target = target[field]
            target[fields[-1]] = case["value"]
        must_reject(lambda: validate(case["schema"], compact(value)))
    raw = compact(fixture("receiver"))
    extra = [b"\xef\xbb\xbf" + raw, b'{"label":"duplicate",' + raw[1:], raw + b"{}",
             raw + b" " * 8192, b"\xff" + raw]
    for malformed in extra:
        must_reject(lambda: validate("receiver-enrollment", malformed))

    vector = fixture("control-vector")
    key = V1.b64(vector["control_key"], 32)
    frame = bytes.fromhex(vector["frame_hex"])
    context = vector["account_id"], vector["device_id"], vector["receiver_id"]
    header = control_header(*context, vector["epoch"])
    nonce = bytes.fromhex(vector["nonce_hex"])
    plaintext = compact(fixture("control-plaintext"))
    assert header.hex() == vector["aad_hex"]
    assert header + nonce + AESGCM(key).encrypt(nonce, plaintext, header) == frame
    assert open_control(frame, key, *context) == fixture("control-plaintext")
    mutations = [0, 17, 18, 34, 38, 61, 62, 74, len(frame) - 1]
    for offset in mutations:
        changed = bytearray(frame)
        changed[offset] ^= 1
        must_reject(lambda: open_control(bytes(changed), key, *context))
    must_reject(lambda: open_control(frame, bytes(32), *context))
    must_reject(lambda: open_control(frame[:-1], key, *context))
    print(f"PASS v4: {len(positives) + 1} JSON cases, {len(negatives) + len(extra)} rejected JSON cases, "
          f"1 control vector and {len(mutations) + 2} rejected control cases")


if __name__ == "__main__":
    main()
