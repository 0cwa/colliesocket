#!/usr/bin/env python3
"""Offline checks for v3 schemas and deterministic synthetic key-id vectors."""
import base64
import hashlib
import hmac
import json
from pathlib import Path
import re
import uuid

ROOT = Path(__file__).resolve().parents[1]
V1 = ROOT.parent / "v1"
V2 = ROOT.parent / "v2"
DOMAIN = b"COLLIESOCKET-EVENT-KEY-ID"
B64URL_32 = re.compile(r"^[A-Za-z0-9_-]{42}[AEIMQUYcgkosw048]$")
UUID4 = re.compile(r"^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$")
UUID = re.compile(r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$")
INSTANCE = re.compile(r"^[A-Za-z0-9._:-]{1,128}$")
NEGATIVE_CHECKS = 0


def _pairs(pairs):
    value = {}
    for key, item in pairs:
        if key in value:
            raise ValueError("duplicate_json_member")
        value[key] = item
    return value


def parse_bytes(data):
    return json.loads(
        data,
        object_pairs_hook=_pairs,
        parse_float=lambda _: (_ for _ in ()).throw(ValueError("float_not_allowed")),
        parse_constant=lambda _: (_ for _ in ()).throw(ValueError("constant_not_allowed")),
    )


def read_json(path):
    return parse_bytes(path.read_bytes())


def encoded(data):
    return base64.urlsafe_b64encode(data).decode("ascii").rstrip("=")


def decoded32(value):
    if not isinstance(value, str) or not B64URL_32.fullmatch(value):
        raise ValueError("invalid_key_id_encoding")
    raw = base64.urlsafe_b64decode(value + "=")
    if len(raw) != 32 or encoded(raw) != value:
        raise ValueError("noncanonical_key_id")
    return raw


def derive(control_key, account_id, device_id, instance):
    key = decoded32(control_key)
    if not UUID.fullmatch(account_id) or str(uuid.UUID(account_id)) != account_id:
        raise ValueError("invalid_account_id")
    if type(device_id) is not int or not 2 <= device_id <= 2147483647:
        raise ValueError("invalid_device_id")
    if not isinstance(instance, str) or not INSTANCE.fullmatch(instance):
        raise ValueError("invalid_instance")
    instance_bytes = instance.encode("ascii")
    message = (
        DOMAIN
        + bytes((0x00, 0x03))
        + uuid.UUID(account_id).bytes
        + device_id.to_bytes(4, "big")
        + len(instance_bytes).to_bytes(2, "big")
        + instance_bytes
    )
    digest = hmac.new(key, message, hashlib.sha256).digest()
    return message, digest, encoded(digest)


def exact_keys(value, expected, label):
    if not isinstance(value, dict) or set(value) != set(expected):
        raise ValueError(f"invalid_{label}_members")


def validate_enrollment(value):
    exact_keys(value, {
        "enrollment_version", "request_id", "import_seq", "account_id", "device_id",
        "password", "control_key", "subscription",
    }, "enrollment")
    if type(value["enrollment_version"]) is not int or value["enrollment_version"] != 3:
        raise ValueError("invalid_enrollment_version")
    if not UUID4.fullmatch(value["request_id"]) or not UUID.fullmatch(value["account_id"]):
        raise ValueError("invalid_enrollment_id")
    sequence = value["import_seq"]
    if type(sequence) is not int or not 1 <= sequence <= 9223372036854775807:
        raise ValueError("invalid_import_seq")
    if type(value["device_id"]) is not int or not 2 <= value["device_id"] <= 2147483647:
        raise ValueError("invalid_device_id")
    if (not isinstance(value["password"], str) or not 16 <= len(value["password"]) <= 256
            or not all(0x20 <= ord(char) <= 0x7e for char in value["password"])):
        raise ValueError("invalid_password_shape")
    decoded32(value["control_key"])
    sub = value["subscription"]
    exact_keys(sub, {
        "endpoint", "p256dh", "auth", "instance", "subscription_epoch",
        "encryption_required", "supported_event_versions", "capabilities",
    }, "subscription")
    if (not isinstance(sub["endpoint"], str) or not 1 <= len(sub["endpoint"]) <= 2048
            or not all(0x21 <= ord(char) <= 0x7e for char in sub["endpoint"])):
        raise ValueError("invalid_endpoint_shape")
    if not re.fullmatch(r"[A-Za-z0-9_-]{87}", sub["p256dh"]):
        raise ValueError("invalid_p256dh_shape")
    if not re.fullmatch(r"[A-Za-z0-9_-]{22}", sub["auth"]):
        raise ValueError("invalid_auth_shape")
    if not isinstance(sub["instance"], str) or not INSTANCE.fullmatch(sub["instance"]):
        raise ValueError("invalid_instance")
    epoch = sub["subscription_epoch"]
    if type(epoch) is not int or not 1 <= epoch <= 9007199254740991:
        raise ValueError("invalid_epoch")
    if sub["encryption_required"] is not True:
        raise ValueError("encryption_required")
    if sub["supported_event_versions"] != [1, 2, 3]:
        raise ValueError("invalid_event_negotiation")
    if sub["capabilities"] != ["wake", "test", "status"]:
        raise ValueError("invalid_capabilities")
    return value


def validate_response(value):
    exact_keys(value, {
        "enrollment_version", "request_id", "instance", "subscription_epoch",
        "selected_event_version", "capabilities", "status",
    }, "response")
    if type(value["enrollment_version"]) is not int or value["enrollment_version"] != 3:
        raise ValueError("invalid_enrollment_version")
    if not UUID4.fullmatch(value["request_id"]):
        raise ValueError("invalid_request_id")
    if not isinstance(value["instance"], str) or not INSTANCE.fullmatch(value["instance"]):
        raise ValueError("invalid_instance")
    epoch = value["subscription_epoch"]
    if type(epoch) is not int or not 1 <= epoch <= 9007199254740991:
        raise ValueError("invalid_epoch")
    if type(value["selected_event_version"]) is not int or value["selected_event_version"] != 3:
        raise ValueError("invalid_event_version")
    if value["capabilities"] != ["wake", "test", "status"]:
        raise ValueError("invalid_capabilities")
    if value["status"] not in ("accepted", "unchanged"):
        raise ValueError("invalid_status")
    return value


def validate_event(value):
    required = {
        "version", "event_id", "instance", "subscription_epoch", "kind",
        "issued_at", "expires_at", "key_id", "import_id",
    }
    allowed = required | {"code"}
    if not isinstance(value, dict) or not required <= set(value) or set(value) - allowed:
        raise ValueError("invalid_event_members")
    if type(value["version"]) is not int or value["version"] != 3:
        raise ValueError("invalid_event_version")
    if not UUID4.fullmatch(value["event_id"]) or not UUID4.fullmatch(value["import_id"]):
        raise ValueError("invalid_event_id")
    if not isinstance(value["instance"], str) or not INSTANCE.fullmatch(value["instance"]):
        raise ValueError("invalid_instance")
    epoch = value["subscription_epoch"]
    if type(epoch) is not int or not 1 <= epoch <= 9007199254740991:
        raise ValueError("invalid_epoch")
    if value["kind"] not in ("wake", "test", "status"):
        raise ValueError("invalid_kind")
    issued = value["issued_at"]
    expires = value["expires_at"]
    if type(issued) is not int or not 0 <= issued <= 9007199254740991:
        raise ValueError("invalid_issued_at")
    if type(expires) is not int or not 1 <= expires <= 9007199254740991 or expires <= issued:
        raise ValueError("invalid_expires_at")
    if value["kind"] == "status":
        if value.get("code") not in (
            "connection_conflict", "connection_unavailable",
            "subscription_updated", "enrollment_imported",
        ):
            raise ValueError("invalid_status_code")
    elif "code" in value:
        raise ValueError("unexpected_code")
    decoded32(value["key_id"])
    return value


def check_schema_shapes():
    enrollment = read_json(ROOT / "enrollment.schema.json")
    response = read_json(ROOT / "response.schema.json")
    event = read_json(ROOT / "event.schema.json")
    assert enrollment["additionalProperties"] is False
    assert set(enrollment["required"]) == {
        "enrollment_version", "request_id", "import_seq", "account_id", "device_id",
        "password", "subscription", "control_key",
    }
    assert enrollment["properties"]["import_seq"]["minimum"] == 1
    assert enrollment["properties"]["import_seq"]["maximum"] == 9223372036854775807
    assert enrollment["properties"]["enrollment_version"]["const"] == 3
    assert enrollment["properties"]["subscription"]["properties"]["supported_event_versions"]["const"] == [1, 2, 3]
    assert response["additionalProperties"] is False
    assert response["properties"]["enrollment_version"]["const"] == 3
    assert response["properties"]["selected_event_version"]["const"] == 3
    assert "key_id" not in response["properties"] and "import_id" not in response["properties"]
    assert event["additionalProperties"] is False
    assert event["properties"]["version"]["const"] == 3
    assert set(event["required"]) >= {"key_id", "import_id"}
    assert event["properties"]["key_id"]["minLength"] == 43
    assert event["properties"]["key_id"]["maxLength"] == 43
    assert "import_seq" not in event["properties"]
    assert "enrollment_imported" in event["properties"]["code"]["enum"]
    for old_path, version in [
        (V1 / "event.schema.json", 1),
        (V2 / "event.schema.json", 2),
    ]:
        old = read_json(old_path)
        assert old["properties"]["version"]["const"] == version
        assert old["additionalProperties"] is False
        assert "key_id" not in old["properties"] and "import_id" not in old["properties"]


def check_copy_manifest(directory, version):
    manifest_path = directory / "copy-manifest.json"
    manifest = read_json(manifest_path)
    assert manifest == {
        "manifest_version": 1,
        "contract_version": f"encrypted-push/v{version}",
        "files": manifest["files"],
    }
    entries = manifest["files"]
    paths = [entry["path"] for entry in entries]
    assert paths == sorted(paths) and len(paths) == len(set(paths))
    actual = sorted(
        path.relative_to(directory).as_posix()
        for path in directory.rglob("*")
        if path.is_file() and path != manifest_path
    )
    assert paths == actual
    for entry in entries:
        assert set(entry) == {"path", "sha256"}
        digest = hashlib.sha256((directory / entry["path"]).read_bytes()).hexdigest()
        assert digest == entry["sha256"], f"copy manifest mismatch: {entry['path']}"
    return len(entries)


def must_reject(operation, label):
    global NEGATIVE_CHECKS
    try:
        operation()
    except (ValueError, KeyError, TypeError):
        NEGATIVE_CHECKS += 1
        return
    raise AssertionError(f"accepted invalid synthetic case: {label}")


def main():
    check_schema_shapes()
    v2_manifest_files = check_copy_manifest(V2, 2)
    v3_manifest_files = check_copy_manifest(ROOT, 3)
    vector = read_json(ROOT / "fixtures/key-id-v3.json")
    assert vector["synthetic_only"] is True
    message, digest, key_id = derive(
        vector["control_key"], vector["account_id"],
        vector["device_id"], vector["instance"],
    )
    assert message.hex() == vector["message_hex"]
    assert digest.hex() == vector["digest_hex"]
    assert key_id == vector["key_id"] and len(key_id) == 43

    enrollment = validate_enrollment(read_json(ROOT / "fixtures/enrollment-keyed-v3.json"))
    validate_enrollment(dict(enrollment, import_seq=9223372036854775807))
    response = validate_response(read_json(ROOT / "fixtures/response-v3.json"))
    events = [
        validate_event(read_json(ROOT / "fixtures" / name))
        for name in (
            "event-enrollment-imported-v3.json",
            "event-subscription-updated-v3.json",
            "event-wake-v3.json",
            "event-test-v3.json",
        )
    ]
    assert all(event["key_id"] == key_id for event in events)
    assert all(event["import_id"] == enrollment["request_id"] for event in events)
    assert response["request_id"] == enrollment["request_id"]
    assert "key_id" not in response and "import_id" not in response
    assert events[0]["code"] == "enrollment_imported"

    changed = {
        derive(vector["control_key"], "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb", vector["device_id"], vector["instance"])[2],
        derive(vector["control_key"], vector["account_id"], vector["device_id"] + 1, vector["instance"])[2],
        derive(vector["control_key"], vector["account_id"], vector["device_id"], "fixture-instance-2")[2],
    }
    assert len(changed) == 3 and key_id not in changed

    bad_events = [
        {key: value for key, value in events[0].items() if key != "key_id"},
        {key: value for key, value in events[0].items() if key != "import_id"},
        dict(events[0], key_id=events[0]["key_id"] + "="),
        dict(events[0], key_id=events[0]["key_id"][:-1] + "B"),
        dict(events[0], key_id="A" * 42),
        dict(events[0], version=2),
        dict(events[2], code="enrollment_imported"),
        dict(events[0], unknown="field"),
    ]
    for index, bad in enumerate(bad_events):
        must_reject(lambda b=bad: validate_event(b), f"invalid event {index}")

    bad_enrollment = dict(enrollment)
    bad_enrollment.pop("control_key")
    must_reject(lambda: validate_enrollment(bad_enrollment), "missing control key")
    bad_enrollment = dict(enrollment)
    bad_enrollment.pop("import_seq")
    must_reject(lambda: validate_enrollment(bad_enrollment), "missing import sequence")
    for invalid_sequence in [0, 9223372036854775808, True, 1.0]:
        bad_enrollment = dict(enrollment, import_seq=invalid_sequence)
        must_reject(lambda b=bad_enrollment: validate_enrollment(b), "invalid import sequence")
    bad_enrollment = dict(enrollment)
    bad_enrollment["subscription"] = dict(enrollment["subscription"], supported_event_versions=[1, 2])
    must_reject(lambda: validate_enrollment(bad_enrollment), "v3 negotiation")
    bad_enrollment = dict(enrollment, control_key=enrollment["control_key"] + "=")
    must_reject(lambda: validate_enrollment(bad_enrollment), "padded control key")
    bad_response = dict(response, key_id=key_id)
    must_reject(lambda: validate_response(bad_response), "operator receipt key id")

    invalid_cases = read_json(ROOT / "fixtures/invalid-cases-v3.json")
    for case in invalid_cases["schema_invalid"]:
        value = read_json(ROOT / "fixtures" / case["fixture"])
        validator = {
            "enrollment": validate_enrollment,
            "event": validate_event,
        }[case["schema"]]
        must_reject(lambda v=value, fn=validator: fn(v), case["id"])
    runtime_cases = read_json(ROOT / "fixtures/runtime-cases-v3.json")["cases"]
    required_runtime_cases = {
        "stale-sequence-unseen-request-id", "equal-sequence-nonidentical",
        "same-epoch-different-key", "conflicting-repeated-request-id",
        "reaffirm-same-epoch-fresh-id", "delayed-old-same-epoch-event",
        "old-file-reimport-after-newer-same-epoch", "rerender-existing-no-slot",
        "restart-retains-pending-intents",
        "legacy-unknown-intent", "explicit-lower-epoch-recovery",
        "lost-status-later-wake", "ordinary-lower-epoch-before-later-candidate",
        "cap-refusal-rerender-restart", "unknown-legacy-migration",
    }
    assert {case["id"] for case in runtime_cases} == required_runtime_cases
    assert all(case["expected"] in {"accept", "reject", "no_promotion", "recover"}
               for case in runtime_cases)
    assert NEGATIVE_CHECKS > 0

    # Recheck every committed fixture with duplicate-key and float rejection.
    for path in (ROOT / "fixtures").glob("*.json"):
        read_json(path)
    print(json.dumps({
        "result": "PASS",
        "v2_copy_manifest_files": v2_manifest_files,
        "v3_copy_manifest_files": v3_manifest_files,
        "event_fixtures": len(events),
        "runtime_transition_vectors": len(runtime_cases),
        "key_id_digest_bytes": len(digest),
        "negative_cases_rejected": NEGATIVE_CHECKS,
        "scope": "offline schema/fixture shape, manifest hashes, HMAC vector and encoding; runtime transitions remain required implementation tests",
    }, indent=2))


if __name__ == "__main__":
    main()
