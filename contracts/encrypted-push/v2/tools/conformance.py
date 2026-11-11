#!/usr/bin/env python3
"""Offline v2 schema/AEAD checks; no Signal, Android or provider traffic."""
import base64
import copy
import importlib.util
import json
import uuid
from pathlib import Path

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from jsonschema import Draft202012Validator, ValidationError

ROOT = Path(__file__).resolve().parents[1]
MAGIC = b"CollieSocket-Control\0"
MAX_EPOCH = 9007199254740991
spec = importlib.util.spec_from_file_location(
    "frozen_v1_conformance", ROOT.parent / "v1/tools/conformance.py"
)
v1 = importlib.util.module_from_spec(spec)
spec.loader.exec_module(v1)
ContractError = v1.ContractError


def encoded(value):
    return json.dumps(value, separators=(",", ":")).encode()


def validate(kind, data, now=1700000000, allowed_endpoints=()):
    if kind not in ("enrollment", "control", "event", "response"):
        raise ValueError("unknown schema")
    limit = 3072 if kind == "control" else (3993 if kind == "event" else 8192)
    if len(data) > limit:
        raise ContractError("input_too_large")
    value = v1.parse(data)
    v1.no_floats(value, "invalid_data")
    schema = v1.parse((ROOT / f"{kind}.schema.json").read_bytes())
    try:
        Draft202012Validator(schema).validate(value)
    except ValidationError as error:
        raise ContractError("invalid_data") from error
    if kind == "enrollment":
        legacy = copy.deepcopy(value)
        if "control_key" in legacy:
            v1.b64(legacy.pop("control_key"), 32)
        legacy["enrollment_version"] = 1
        legacy["subscription"]["supported_event_versions"] = [1]
        v1.validate("enrollment", encoded(legacy), now, allowed_endpoints)
    elif kind == "control":
        point = v1.b64(value["p256dh"], 65)
        if point[0] != 4:
            raise ContractError("invalid_key")
        try:
            ec.EllipticCurvePublicKey.from_encoded_point(ec.SECP256R1(), point)
        except ValueError as error:
            raise ContractError("invalid_key") from error
        v1.b64(value["auth"], 16)
        origin = v1.origin(value["endpoint"])
        allowed = {item for entry in allowed_endpoints
                   if (item := v1.allowed_origin(entry)) is not None}
        if origin[0] != "https" and origin not in allowed:
            raise ContractError("invalid_endpoint")
    elif kind == "event":
        if len(data.rstrip(b" ")) > 3072:
            raise ContractError("input_too_large")
        legacy = copy.deepcopy(value)
        legacy["version"] = 1
        if legacy.get("code") == "subscription_updated":
            legacy["code"] = "connection_unavailable"
        v1.validate("event", encoded(legacy), now)
    elif kind == "response":
        legacy = copy.deepcopy(value)
        legacy["enrollment_version"] = 1
        legacy["selected_event_version"] = 1
        v1.validate("response", encoded(legacy), now)
    return value


def decrypt(blob, key, account, device):
    if not 58 <= len(blob) <= 4096 or blob[:21] != MAGIC or blob[21] != 2:
        raise ContractError("invalid_control")
    epoch = int.from_bytes(blob[22:30], "big")
    if not 1 <= epoch <= MAX_EPOCH:
        raise ContractError("invalid_control")
    aad = blob[:30] + uuid.UUID(account).bytes + device.to_bytes(4, "big")
    try:
        plaintext = AESGCM(key).decrypt(blob[30:42], blob[42:], aad)
    except (InvalidTag, ValueError) as error:
        raise ContractError("invalid_control") from error
    return epoch, validate("control", plaintext)


def expect_rejection(call, label):
    try:
        call()
    except ContractError:
        return
    raise SystemExit("FAIL accepted " + label)


def check_crypto():
    vector = v1.parse((ROOT / "fixtures/control-vector.json").read_bytes())
    if vector["synthetic_only"] is not True:
        raise SystemExit("FAIL non-synthetic vector")
    blob = (ROOT / "fixtures/control-update.bin").read_bytes()
    key = v1.b64(vector["control_key"], 32)
    account, device = vector["account_id"], vector["device_id"]
    plaintext = vector["plaintext_utf8"].encode()
    header = MAGIC + b"\x02" + vector["target_epoch"].to_bytes(8, "big")
    aad = header + uuid.UUID(account).bytes + device.to_bytes(4, "big")
    nonce = bytes.fromhex(vector["nonce_hex"])
    ciphertext = AESGCM(key).encrypt(nonce, plaintext, aad)
    assert len(MAGIC) == 21 and len(header) == 30 and len(aad) == 50
    assert aad.hex() == vector["aad_hex"]
    assert ciphertext[:-16].hex() == vector["ciphertext_hex"]
    assert ciphertext[-16:].hex() == vector["tag_hex"]
    assert header + nonce + ciphertext == blob
    assert base64.urlsafe_b64encode(blob).decode().rstrip("=") == vector["blob_base64url"]
    epoch, update = decrypt(blob, key, account, device)
    assert epoch == 2 and update == v1.parse((ROOT / "fixtures/control-update.json").read_bytes())

    cases = 1
    for name, bad_key, bad_account, bad_device in [
        ("wrong key", bytes([255]) * 32, account, device),
        ("wrong account", key, "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb", device),
        ("wrong device", key, account, device + 1),
    ]:
        expect_rejection(lambda: decrypt(blob, bad_key, bad_account, bad_device), name)
        cases += 1
    for name, index in [("magic", 0), ("version", 21), ("epoch", 29),
                        ("nonce", 30), ("ciphertext", 42), ("tag", len(blob) - 1)]:
        mutated = bytearray(blob)
        mutated[index] ^= 1
        expect_rejection(lambda: decrypt(bytes(mutated), key, account, device), name)
        cases += 1
    for length in (0, 20, 21, 29, 30, 41, 42, 57, len(blob) - 1):
        expect_rejection(lambda: decrypt(blob[:length], key, account, device), "truncated blob")
        cases += 1
    expect_rejection(lambda: decrypt(blob + b"\x00" * 4096, key, account, device), "oversized blob")
    cases += 1
    for bad_plaintext in [b"", b"null", b"{}", b"\xff", b"\xef\xbb\xbf" + plaintext,
                          plaintext + b"null", b" " * 3073,
                          plaintext[:-1] + b',"password":"never-in-band"}',
                          plaintext[:-1] + b',"auth":"duplicate"}']:
        authenticated = header + nonce + AESGCM(key).encrypt(nonce, bad_plaintext, aad)
        expect_rejection(lambda: decrypt(authenticated, key, account, device), "authenticated invalid plaintext")
        cases += 1
    return cases


def main():
    for kind in ("enrollment", "control", "event", "response"):
        Draft202012Validator.check_schema(v1.parse((ROOT / f"{kind}.schema.json").read_bytes()))
    corpus = v1.parse((ROOT / "fixtures/cases.json").read_bytes())
    if corpus["synthetic_only"] is not True or not corpus["cases"]:
        raise SystemExit("FAIL missing synthetic cases")
    for case in corpus["cases"]:
        data = case["json"].encode()
        try:
            validate(case["schema"], data, allowed_endpoints=case.get("allowed_endpoints", ()))
            accepted = True
        except ContractError:
            accepted = False
        if accepted != case["valid"]:
            raise SystemExit("FAIL " + case["name"])
    print(json.dumps({"result": "PASS", "schema_cases": len(corpus["cases"]),
                      "crypto_cases": check_crypto(),
                      "not_run": ["Android/device delivery", "Signal service",
                                  "DNS/address policy", "server durable state"]}, indent=2))


if __name__ == "__main__":
    main()
