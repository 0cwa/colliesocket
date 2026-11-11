#!/usr/bin/env python3
"""Offline synthetic v1 checks. Not an Android or network-policy implementation."""
import argparse
import base64
import copy
import hashlib
import json
import re
from pathlib import Path
from urllib.parse import urlsplit

from cryptography.hazmat.primitives.asymmetric import ec
from jsonschema import Draft202012Validator, ValidationError

ROOT = Path(__file__).resolve().parents[1]


class ContractError(ValueError):
    """Fixed diagnostics intentionally contain no request data."""


def unique(pairs):
    value = {}
    for key, item in pairs:
        if key in value:
            raise ContractError("invalid_json")
        value[key] = item
    return value


def reject_constant(_):
    raise ContractError("invalid_json")


def parse(data):
    try:
        text = data.decode("utf-8", errors="strict") if isinstance(data, bytes) else data
        if text.startswith("\ufeff"):
            raise ContractError("invalid_json")
        return json.loads(text, object_pairs_hook=unique, parse_constant=reject_constant)
    except (UnicodeError, json.JSONDecodeError, RecursionError) as error:
        raise ContractError("invalid_json") from error


def no_floats(value, code):
    if isinstance(value, float):
        raise ContractError(code)
    if isinstance(value, dict):
        for item in value.values():
            no_floats(item, code)
    if isinstance(value, list):
        for item in value:
            no_floats(item, code)


def b64(value, size):
    if not isinstance(value, str) or re.fullmatch(r"[A-Za-z0-9_-]+", value) is None:
        raise ContractError("invalid_key")
    try:
        decoded = base64.urlsafe_b64decode(value + "=" * (-len(value) % 4))
    except ValueError as error:
        raise ContractError("invalid_key") from error
    if len(decoded) != size or base64.urlsafe_b64encode(decoded).decode().rstrip("=") != value:
        raise ContractError("invalid_key")
    return decoded


def origin(endpoint):
    if not isinstance(endpoint, str) or not endpoint.isascii() or not 1 <= len(endpoint) <= 2048:
        raise ContractError("invalid_endpoint")
    if any(ord(c) <= 32 or ord(c) == 127 for c in endpoint) or "#" in endpoint or "\\" in endpoint:
        raise ContractError("invalid_endpoint")
    try:
        url = urlsplit(endpoint)
        if url.scheme not in ("https", "http") or not url.hostname or "@" in url.netloc or url.username is not None or url.password is not None:
            raise ContractError("invalid_endpoint")
        port = url.port if url.port is not None else (443 if url.scheme == "https" else 80)
        if port == 0:
            raise ContractError("invalid_endpoint")
        return url.scheme, url.hostname.lower(), port
    except ValueError as error:
        raise ContractError("invalid_endpoint") from error


def allowed_origin(entry):
    """Malformed/non-origin config entries authorize nothing; retain other entries."""
    try:
        result = origin(entry)
        url = urlsplit(entry)
        if url.path not in ("", "/") or "?" in entry:
            return None
        return result
    except ContractError:
        return None


def validate(kind, data, now, allowed_endpoints=()):
    if kind not in ("enrollment", "event", "response"):
        raise ValueError("unknown fixture schema")
    if len(data) > (3993 if kind == "event" else 8192):
        raise ContractError("input_too_large")
    value = parse(data)
    code = "invalid_event" if kind == "event" else "invalid_enrollment"
    no_floats(value, code)
    schema = parse((ROOT / (kind + ".schema.json")).read_bytes())
    try:
        Draft202012Validator(schema).validate(value)
    except ValidationError as error:
        raise ContractError(code) from error
    if kind == "enrollment":
        sub = value["subscription"]
        point = b64(sub["p256dh"], 65)
        if point[0] != 4:
            raise ContractError("invalid_key")
        try:
            ec.EllipticCurvePublicKey.from_encoded_point(ec.SECP256R1(), point)
        except ValueError as error:
            raise ContractError("invalid_key") from error
        b64(sub["auth"], 16)
        endpoint_origin = origin(sub["endpoint"])
        explicit = {result for item in allowed_endpoints
                    if (result := allowed_origin(item)) is not None}
        if endpoint_origin[0] != "https" and endpoint_origin not in explicit:
            raise ContractError("invalid_endpoint")
    if kind == "event":
        if not 1 <= value["expires_at"] - value["issued_at"] <= 300:
            raise ContractError("invalid_event")
        if value["issued_at"] > now + 60 or value["expires_at"] <= now:
            raise ContractError("invalid_event")
        # Only the profile's trailing ASCII-space padding is excluded here.
        if len(data.rstrip(b" ")) > 3072:
            raise ContractError("input_too_large")
    return value


def receiver_decision(case, data):
    """Pure reference state transition, not durable storage or Android evidence."""
    state = copy.deepcopy(case["state"])
    if case.get("locked", False):
        return "drop_locked", state
    if not case["decrypted"]:
        return "drop_not_decrypted", state
    try:
        event = validate("event", data, case["now"])
    except ContractError:
        return "drop_invalid", state
    if event["instance"] != case["active_instance"] or event["subscription_epoch"] != case["active_epoch"]:
        return "drop_enrollment_mismatch", state
    if case["now"] < state["clock_high_water"]:
        return "drop_clock_rollback", state
    retained = [entry for entry in state["seen"] if entry["expires_at"] + 60 > case["now"]]
    if any(entry["event_id"] == event["event_id"] for entry in retained):
        return "drop_duplicate", state
    if len(retained) >= 512:
        return "drop_replay_capacity", state
    if case.get("lock_before_commit", False):
        return "drop_locked", state
    state["clock_high_water"] = case["now"]
    state["seen"] = retained + [{"event_id": event["event_id"], "expires_at": event["expires_at"]}]
    return "accept_" + event["kind"], state


def contained_file(relative):
    path = ROOT / relative
    if path.is_symlink() or not path.resolve().is_relative_to(ROOT):
        raise ValueError("unsafe fixture path")
    return path


def check_manifest():
    path = ROOT / "fixtures/manifest.json"
    if not path.is_file():
        raise SystemExit("FAIL missing immutable fixture manifest (use --draft only before freeze)")
    manifest = parse(path.read_bytes())
    listed = set()
    for entry in manifest["files"]:
        if entry["path"] in listed:
            raise SystemExit("FAIL duplicate manifest path")
        listed.add(entry["path"])
        if hashlib.sha256(contained_file(entry["path"]).read_bytes()).hexdigest() != entry["sha256"]:
            raise SystemExit("FAIL digest " + entry["path"])
    actual = {p.relative_to(ROOT).as_posix() for p in ROOT.rglob("*")
              if p.is_file() and p != path and "__pycache__" not in p.parts and p.suffix != ".pyc"}
    if listed != actual:
        raise SystemExit("FAIL manifest file-set mismatch")
    return len(listed)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--draft", action="store_true", help="Before C0 only: do not claim immutable hashes")
    args = parser.parse_args()
    for name in ("enrollment", "event", "response"):
        Draft202012Validator.check_schema(parse((ROOT / (name + ".schema.json")).read_bytes()))
    spec = parse((ROOT / "fixtures/cases.json").read_bytes())
    if spec["synthetic_only"] is not True:
        raise SystemExit("FAIL non-synthetic fixtures")
    for case in spec["cases"]:
        data = contained_file("fixtures/" + case["path"]).read_bytes()
        try:
            validate(case["schema"], data, case.get("now", spec["validation_time"]), case.get("allowed_endpoints", []))
            valid = True
        except ContractError:
            valid = False
        if valid != case["valid"]:
            raise SystemExit("FAIL " + case["name"])
    receiver = parse((ROOT / "fixtures/receiver-cases.json").read_bytes())
    for case in receiver["cases"]:
        data = contained_file("fixtures/" + case["path"]).read_bytes()
        outcome, after = receiver_decision(case, data)
        if outcome != case["expected"]:
            raise SystemExit("FAIL receiver " + case["name"])
        if outcome.startswith("drop_") and after != case["state"]:
            raise SystemExit("FAIL rejected event mutated replay state")
        if outcome.startswith("accept_"):
            if after["clock_high_water"] != case["now"] or len(after["seen"]) > 512:
                raise SystemExit("FAIL accepted-event state")
    count = 0 if args.draft else check_manifest()
    print(json.dumps({"result": "DRAFT PASS" if args.draft else "PASS",
                      "schema_cases": len(spec["cases"]), "reference_receiver_cases": len(receiver["cases"]),
                      "immutable_file_hashes": count,
                      "not_run": ["Android", "device/Keystore", "DNS/address validation", "server durable state"]}, indent=2))


if __name__ == "__main__":
    main()
