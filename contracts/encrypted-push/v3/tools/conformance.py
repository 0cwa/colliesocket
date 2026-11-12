#!/usr/bin/env python3
"""Offline checks for v3 schemas and deterministic synthetic key-id vectors."""
import base64
import copy
import hashlib
import hmac
import json
from pathlib import Path
from copy_manifest import canonical_paths, inventory
import re
import uuid
from jsonschema import Draft202012Validator

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


def exact_keys(value, expected, label, error_code=None):
    if not isinstance(value, dict) or set(value) != set(expected):
        raise ValueError(error_code or f"invalid_{label}_members")


def exact_v3_negotiation(versions):
    return (
        type(versions) is list
        and len(versions) == 3
        and all(type(version) is int for version in versions)
        and versions == [1, 2, 3]
    )


def validate_enrollment(value):
    exact_keys(value, {
        "enrollment_version", "request_id", "import_seq", "account_id", "device_id",
        "password", "control_key", "subscription",
    }, "enrollment", "invalid_enrollment")
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
    }, "subscription", "invalid_enrollment")
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
    versions = sub["supported_event_versions"]
    if type(versions) is not list or any(type(version) is not int for version in versions):
        raise ValueError("invalid_enrollment")
    if not exact_v3_negotiation(versions):
        raise ValueError("unsupported_version")
    capabilities = sub["capabilities"]
    if type(capabilities) is not list or any(
        type(capability) is not str for capability in capabilities
    ):
        raise ValueError("invalid_enrollment")
    if capabilities != ["wake", "test", "status"]:
        raise ValueError("capability_required")
    return value


def validate_response(value):
    exact_keys(value, {
        "enrollment_version", "request_id", "instance", "subscription_epoch",
        "selected_event_version", "capabilities", "status", "replayed",
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
    if type(value["replayed"]) is not bool:
        raise ValueError("invalid_replay_flag")
    if value["status"] == "unchanged" and not value["replayed"]:
        raise ValueError("unchanged_must_be_replayed")
    if not value["replayed"] and value["status"] != "accepted":
        raise ValueError("new_import_must_be_accepted")
    return value


ERROR_CODES = {
    "invalid_json", "input_too_large", "unsafe_file", "invalid_enrollment",
    "invalid_endpoint", "unsupported_version", "capability_required",
    "encryption_required", "invalid_key", "idempotency_conflict",
    "epoch_conflict", "capacity_exceeded", "queue_full", "state_unavailable",
}


def validate_error_response(value):
    exact_keys(value, {"error"}, "error_response")
    if type(value["error"]) is not str or value["error"] not in ERROR_CODES:
        raise ValueError("invalid_error_code")
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


def first_v3_adoption_matches(legacy, incoming, row_state="active"):
    """Reference predicate: same-epoch keyed adoption changes negotiation only."""
    if (row_state != "active" or legacy.get("enrollment_version") != 2
            or "control_key" not in legacy or legacy.get("control_key") is None):
        return False
    incoming_subscription = incoming.get("subscription")
    if (not isinstance(incoming_subscription, dict)
            or not exact_v3_negotiation(incoming_subscription.get("supported_event_versions"))):
        return False
    if incoming.get("request_id") == legacy.get("request_id"):
        return False
    sequence = incoming.get("import_seq")
    if type(sequence) is not int or not 1 <= sequence <= 9223372036854775807:
        return False
    expected = copy.deepcopy(legacy)
    expected["enrollment_version"] = 3
    expected["request_id"] = incoming["request_id"]
    expected["import_seq"] = sequence
    expected["subscription"]["supported_event_versions"] = [1, 2, 3]
    return incoming == expected


def set_path(value, dotted_path, replacement):
    keys = dotted_path.split(".")
    target = value
    for key in keys[:-1]:
        target = target[key]
    target[keys[-1]] = replacement


def check_schema_shapes():
    enrollment = read_json(ROOT / "enrollment.schema.json")
    response = read_json(ROOT / "response.schema.json")
    event = read_json(ROOT / "event.schema.json")
    error = read_json(ROOT / "error.schema.json")
    assert enrollment["additionalProperties"] is False
    assert set(enrollment["required"]) == {
        "enrollment_version", "request_id", "import_seq", "account_id", "device_id",
        "password", "subscription", "control_key",
    }
    assert enrollment["properties"]["import_seq"]["minimum"] == 1
    assert enrollment["properties"]["import_seq"]["maximum"] == 9223372036854775807
    assert enrollment["properties"]["enrollment_version"]["const"] == 3
    subscription_schema = enrollment["properties"]["subscription"]
    assert "capabilities" in subscription_schema["required"]
    versions_schema = subscription_schema["properties"]["supported_event_versions"]
    assert versions_schema["const"] == [1, 2, 3]
    assert versions_schema["items"]["type"] == "integer"
    assert response["additionalProperties"] is False
    assert response["properties"]["enrollment_version"]["const"] == 3
    assert response["properties"]["selected_event_version"]["const"] == 3
    assert "key_id" not in response["properties"] and "import_id" not in response["properties"]
    assert response["properties"]["replayed"]["type"] == "boolean"
    response_constraints = response["allOf"]
    assert any(
        constraint.get("if", {}).get("properties", {}).get("status", {}).get("const") == "unchanged"
        and constraint.get("then", {}).get("properties", {}).get("replayed", {}).get("const") is True
        for constraint in response_constraints
    )
    assert event["additionalProperties"] is False
    assert event["properties"]["version"]["const"] == 3
    assert set(event["required"]) >= {"key_id", "import_id"}
    assert event["properties"]["key_id"]["minLength"] == 43
    assert event["properties"]["key_id"]["maxLength"] == 43
    assert "import_seq" not in event["properties"]
    assert "enrollment_imported" in event["properties"]["code"]["enum"]
    assert error["additionalProperties"] is False
    assert error["properties"]["error"]["type"] == "string"
    assert set(error["properties"]["error"]["enum"]) == ERROR_CODES
    for old_path, version in [
        (V1 / "event.schema.json", 1),
        (V2 / "event.schema.json", 2),
    ]:
        old = read_json(old_path)
        assert old["properties"]["version"]["const"] == version
        assert old["additionalProperties"] is False
        assert "key_id" not in old["properties"] and "import_id" not in old["properties"]


def check_schema_instances():
    validators = {
        name: Draft202012Validator(read_json(ROOT / f"{name}.schema.json"))
        for name in ("enrollment", "response", "event", "error")
    }
    for validator in validators.values():
        validator.check_schema(validator.schema)
    fixtures = {
        "enrollment": [
            "enrollment-keyed-v3.json",
            "enrollment-first-v3-adoption-v3.json",
            "enrollment-independent-account-b-v3.json",
            "enrollment-absent-account-b-epoch2-v3.json",
            "enrollment-historical-request-v3.json",
        ],
        "response": [
            "response-v3.json",
            "response-first-v3-adoption-v3.json",
            "response-reaffirm-v3.json",
            "response-current-v3-replay.json",
            "response-historical-v3-replay.json",
        ],
        "event": [
            "event-enrollment-imported-v3.json",
            "event-first-v3-adoption-v3.json",
            "event-independent-account-b-v3.json",
            "event-subscription-updated-v3.json",
            "event-wake-v3.json",
            "event-test-v3.json",
        ],
        "error": [
            "error-epoch-conflict.json",
            "error-idempotency-conflict.json",
            "error-invalid-enrollment.json",
            "error-capability-required.json",
            "error-unsupported-version.json",
        ],
    }
    valid_count = 0
    for schema_name, fixture_names in fixtures.items():
        for fixture_name in fixture_names:
            value = read_json(ROOT / "fixtures" / fixture_name)
            errors = list(validators[schema_name].iter_errors(value))
            assert not errors, (fixture_name, errors)
            valid_count += 1
    response = read_json(ROOT / "fixtures/response-current-v3-replay.json")
    assert not validators["response"].is_valid(dict(response, status="unchanged", replayed=False))
    invalid_count = 0
    for case in read_json(ROOT / "fixtures/invalid-cases-v3.json")["schema_invalid"]:
        value = read_json(ROOT / "fixtures" / case["fixture"])
        assert not validators[case["schema"]].is_valid(value), case["id"]
        invalid_count += 1
    return valid_count, invalid_count


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
    actual = inventory(directory)
    assert paths == actual
    for entry in entries:
        assert set(entry) == {"path", "sha256"}
        digest = hashlib.sha256((directory / entry["path"]).read_bytes()).hexdigest()
        assert digest == entry["sha256"], f"copy manifest mismatch: {entry['path']}"
    return len(entries)


def check_transient_artifact_exclusion():
    sample = [
        "README.md",
        "tools/conformance.py",
        "tools/__pycache__/conformance.cpython-314.pyc",
        "tools/conformance.pyc",
        "tools/.conformance.tmp",
        ".cache/generated.json",
        "tmp/partial.json",
    ]
    assert canonical_paths(sample) == ["README.md", "tools/conformance.py"]
    assert "tools/__pycache__/conformance.cpython-314.pyc" not in canonical_paths(sample)
    cache_dir = ROOT / "tools" / "__pycache__"
    directory_preexisted = cache_dir.exists()
    cache_dir.mkdir(parents=True, exist_ok=True)
    generated = cache_dir / f"inventory-regression-{uuid.uuid4().hex}.pyc"
    try:
        generated.write_bytes(b"synthetic generated bytecode")
        assert generated.relative_to(ROOT).as_posix() not in inventory(ROOT)
    finally:
        generated.unlink(missing_ok=True)
        if not directory_preexisted and not any(cache_dir.iterdir()):
            cache_dir.rmdir()
    return len(sample) - 2 + 1


def must_reject(operation, label):
    global NEGATIVE_CHECKS
    try:
        operation()
    except (ValueError, KeyError, TypeError):
        NEGATIVE_CHECKS += 1
        return
    raise AssertionError(f"accepted invalid synthetic case: {label}")


def must_reject_with(operation, label, expected):
    global NEGATIVE_CHECKS
    try:
        operation()
    except ValueError as error:
        assert str(error) == expected, (label, str(error), expected)
        NEGATIVE_CHECKS += 1
        return
    raise AssertionError(f"accepted or misclassified synthetic case: {label}")


def main():
    check_schema_shapes()
    schema_fixture_count, schema_invalid_fixture_count = check_schema_instances()
    excluded_transient_paths = check_transient_artifact_exclusion()
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
    current_replay = validate_response(read_json(ROOT / "fixtures/response-current-v3-replay.json"))
    historical_replay = validate_response(read_json(ROOT / "fixtures/response-historical-v3-replay.json"))
    assert response["status"] == "accepted" and response["replayed"] is False
    assert current_replay["status"] == "unchanged" and current_replay["replayed"] is True
    assert historical_replay["status"] == "accepted" and historical_replay["replayed"] is True
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
    assert all("import_seq" not in event for event in events)
    assert response["request_id"] == enrollment["request_id"]
    assert "key_id" not in response and "import_id" not in response and "import_seq" not in response
    assert events[0]["code"] == "enrollment_imported"

    adoption_cases = read_json(ROOT / "fixtures/first-v3-adoption-cases-v3.json")
    legacy = read_json(V2 / "fixtures/enrollment-keyed.json")
    legacy_unkeyed = read_json(V2 / "fixtures/enrollment-unkeyed.json")
    adoption = validate_enrollment(read_json(ROOT / "fixtures/enrollment-first-v3-adoption-v3.json"))
    adoption_response = validate_response(read_json(ROOT / "fixtures/response-first-v3-adoption-v3.json"))
    adoption_event = validate_event(read_json(ROOT / "fixtures/event-first-v3-adoption-v3.json"))
    assert adoption_cases["legacy_row"]["import_seq"] is None
    assert adoption_cases["legacy_row"]["import_id"] is None
    assert adoption_cases["legacy_row"]["state"] == "active"
    assert adoption_cases["legacy_row"]["has_old_queued_work"] is True
    assert adoption_cases["adoption_expectation"]["requires_existing_state"] == "active"
    assert adoption_cases["adoption_expectation"]["active_row_claimable"] is True
    assert adoption_cases["adoption_expectation"]["durable_generation_rotates"] is True
    assert adoption_cases["adoption_expectation"]["old_queued_work_invalidated"] is True
    assert adoption_cases["adoption_expectation"]["enrollment_imported_enqueued_atomically"] is True
    assert adoption_cases["adoption_expectation"]["generation_after"] > adoption_cases["adoption_expectation"]["generation_before"]
    assert adoption_cases["adoption_expectation"]["resulting_state"] == "active"
    assert first_v3_adoption_matches(legacy, adoption, row_state=adoption_cases["legacy_row"]["state"])
    assert adoption["request_id"] != legacy["request_id"]
    assert adoption["subscription"]["subscription_epoch"] == legacy["subscription"]["subscription_epoch"]
    assert adoption_response["request_id"] == adoption["request_id"]
    assert adoption_response["subscription_epoch"] == legacy["subscription"]["subscription_epoch"]
    assert adoption_response["status"] == "accepted" and adoption_response["replayed"] is False
    assert "import_seq" not in adoption_response and "key_id" not in adoption_response
    assert "import_id" not in adoption_response
    unkeyed_case = adoption_cases["legacy_unkeyed_same_epoch_case"]
    assert unkeyed_case["legacy_row"] == {
        "state": "active", "import_seq": None, "control_key": None,
    }
    assert unkeyed_case["expected_error"] == "epoch_conflict"
    assert validate_error_response(unkeyed_case["expected_response"]) == {"error": "epoch_conflict"}
    assert all(unkeyed_case[field] is False for field in (
        "row_mutation", "generation_mutation", "outbox_mutation", "receipt_ledger_mutation",
    ))
    assert unkeyed_case["recovery_path"] == "exact_next_epoch_with_fresh_control_key"
    assert not first_v3_adoption_matches(legacy_unkeyed, adoption, row_state="active")
    reaffirm = adoption_cases["active_reaffirmation_case"]
    reaffirm_response = validate_response(read_json(ROOT / "fixtures" / reaffirm["response_fixture"]))
    assert reaffirm["row"]["state"] == "active" and reaffirm["row"]["claimable"] is True
    assert reaffirm["incoming"]["epoch"] == reaffirm["row"]["epoch"]
    assert reaffirm["incoming"]["key_id"] == reaffirm["row"]["key_id"]
    assert reaffirm["incoming"]["import_seq"] > reaffirm["row"]["import_seq"]
    assert reaffirm["incoming"]["fresh_request_id"] is True
    assert reaffirm["incoming"]["context_unchanged"] is True
    assert reaffirm["generation_after"] > reaffirm["row"]["generation"]
    assert reaffirm["old_queued_work_invalidated"] is True
    assert reaffirm["enrollment_imported_enqueued_atomically"] is True
    assert reaffirm["resulting_state"] == "active" and reaffirm["queued_status_claimable"] is True
    assert reaffirm_response["request_id"] == reaffirm["incoming"]["import_id"]
    assert reaffirm_response["subscription_epoch"] == reaffirm["incoming"]["epoch"]
    assert reaffirm_response["status"] == "accepted" and reaffirm_response["replayed"] is False
    assert not ({"key_id", "import_id", "import_seq"} & set(reaffirm_response))
    assert adoption_event["import_id"] == adoption["request_id"]
    assert adoption_event["subscription_epoch"] == legacy["subscription"]["subscription_epoch"]
    assert adoption_event["key_id"] == key_id
    assert "import_seq" not in adoption_event
    for case in adoption_cases["rejected_adoption_mutations"]:
        bad = copy.deepcopy(adoption)
        set_path(bad, case["path"], case["value"])
        assert not first_v3_adoption_matches(legacy, bad), case["id"]
        if case["expected_error"] in (
            "invalid_enrollment", "unsupported_version", "capability_required",
        ):
            must_reject_with(
                lambda b=bad: validate_enrollment(b), case["id"], case["expected_error"],
            )
        else:
            validate_enrollment(bad)
            assert case["expected_error"] == "epoch_conflict"
        assert validate_error_response(case["expected_response"]) == {
            "error": case["expected_error"],
        }
        assert all(case[field] is False for field in (
            "row_mutation", "generation_mutation", "outbox_mutation",
            "queue_mutation", "receipt_ledger_mutation",
        ))
    assert len(adoption_cases["rejected_adoption_mutations"]) >= 10
    assert len(adoption_cases["inactive_same_epoch_cases"]) == 4
    for case in adoption_cases["inactive_same_epoch_cases"]:
        assert case["expected_error"] == "epoch_conflict"
        assert validate_error_response(case["expected_response"]) == {"error": "epoch_conflict"}
        assert case["row_mutation"] is False and case["generation_mutation"] is False
        assert case["outbox_mutation"] is False and case["receipt_ledger_mutation"] is False
        assert case["confirmation_queued"] is False and case["activation"] is False
        assert not first_v3_adoption_matches(legacy, adoption, row_state=case["row_state"])
    assert adoption_cases["inactive_recovery_case"] == {
        "row_state": "stale", "operation": "exact_next_epoch",
        "fresh_control_key": True, "expected": "accept_and_activate",
        "resulting_state": "active",
    }
    legacy_replay = read_json(ROOT / "fixtures/response-legacy-replay-v2.json")
    exact_keys(legacy_replay, {
        "enrollment_version", "request_id", "instance", "subscription_epoch",
        "selected_event_version", "capabilities", "status",
    }, "legacy_replay_response")
    assert legacy_replay["request_id"] == legacy["request_id"]
    assert "replayed" not in legacy_replay
    assert "key_id" not in legacy_replay and "import_seq" not in legacy_replay
    assert all(case["expected_error"] == "epoch_conflict" and case["row_mutation"] is False
               for case in adoption_cases["legacy_floor_cases"] if "expected_error" in case)
    assert next(case for case in adoption_cases["legacy_floor_cases"]
                if case["id"] == "legacy-known-exact-replay")["expected"] == "saved_receipt_no_mutation"
    assert next(case for case in adoption_cases["legacy_floor_cases"]
                if case["id"] == "legacy-known-exact-replay")["historical_receipt_is_current_confirmation"] is False
    for case in adoption_cases["legacy_floor_cases"]:
        if "expected_error" in case:
            assert validate_error_response(case["expected_response"]) == {"error": "epoch_conflict"}
            assert case["row_mutation"] is False and case["generation_mutation"] is False
            assert case["outbox_mutation"] is False and case["receipt_ledger_mutation"] is False
    for name, expected in (
        ("error-epoch-conflict.json", "epoch_conflict"),
        ("error-idempotency-conflict.json", "idempotency_conflict"),
        ("error-invalid-enrollment.json", "invalid_enrollment"),
        ("error-capability-required.json", "capability_required"),
        ("error-unsupported-version.json", "unsupported_version"),
    ):
        error_response = read_json(ROOT / "fixtures" / name)
        validate_error_response(error_response)
        assert error_response["error"] == expected
        assert not ({"request_id", "import_id", "import_seq", "key_id"} & set(error_response))
    conflict = adoption_cases["conflicting_id_cases"][0]
    assert validate_error_response(conflict["expected_response"]) == {
        "error": "idempotency_conflict",
    }
    assert all(conflict[field] is False for field in (
        "row_mutation", "generation_mutation", "outbox_mutation", "receipt_ledger_mutation",
    ))
    operator_status = read_json(ROOT / "fixtures/status-operator-v3.json")
    exact_keys(operator_status, {"instance", "subscription_epoch", "state", "event_version"}, "operator_status")
    assert not ({"import_seq", "import_id", "key_id"} & set(operator_status))
    same_key_candidate = next(case for case in adoption_cases["phone_candidate_cases"]
                              if case["id"] == "same-key-adoption-binds-import-intent")
    assert same_key_candidate["lookup_order"] == ["import_id", "key_id"]
    assert same_key_candidate["active_key_id"] == same_key_candidate["candidate_key_id"]
    assert same_key_candidate["candidate_import_id"] == same_key_candidate["event_import_id"]
    assert same_key_candidate["candidate_import_seq"] == adoption["import_seq"]
    assert same_key_candidate["expected"] == "bind_candidate_sequence_and_intent"
    context_case = next(case for case in adoption_cases["phone_candidate_cases"]
                        if case["id"] == "receiver-binds-to-current-live-context")
    assert context_case["event_contains_account_id"] is False
    assert context_case["binding_source"] == "live_signal_store_aci_device_and_current_instance"
    assert context_case["stored_export_context_sufficient"] is False
    assert context_case["current_live_registration_context"] != context_case["candidate_registration_context"]
    assert context_case["current_live_registration_context"] != context_case["active_v3_registration_context"]
    assert context_case["both_active_v3_and_candidates_checked"] is True
    assert context_case["expected"] == "no_promotion"

    account_cases = adoption_cases["account_selection_cases"]
    assert len(account_cases) == 2
    a_keyed = read_json(V2 / "fixtures/enrollment-keyed.json")
    for case in account_cases:
        assert case["existing_account_a"] == {
            "account_id": a_keyed["account_id"],
            "source_fixture": "contracts/encrypted-push/v2/fixtures/enrollment-keyed.json",
            "state": "active",
            "subscription_epoch": a_keyed["subscription"]["subscription_epoch"],
            "import_seq": None,
        }
        assert case["selected_account_id"] != case["existing_account_a"]["account_id"]
        assert case["receipt_lookup_scope"] == ["account_id", "request_id"]
        assert case["server_cross_account_key_guard"] is False
        assert case["row_comparisons"] == "selected_account_only"
        assert case["legacy_a_unchanged"] is True
        selected = validate_enrollment(read_json(ROOT / "fixtures" / case["enrollment_fixture"]))
        assert selected["account_id"] == case["selected_account_id"]
        assert selected["request_id"] == case["request_id"]
        assert case["request_id_state_in_selected_account"] == "unseen"
        if case["id"] == "independent-account-b-epoch1-create":
            assert case["selected_row_before"] == "absent"
            assert selected["subscription"]["subscription_epoch"] == 1
            assert selected["control_key"] == a_keyed["control_key"]
            assert case["same_control_key_bytes_as_a"] is True
            assert case["server_oracle_probe_reuses_key_for_boundary_only"] is True
            assert case["client_requires_fresh_control_key_for_new_registration"] is True
            assert case["expected"] == "create_b"
            independent_response = validate_response(
                read_json(ROOT / "fixtures" / case["expected_response_fixture"])
            )
            assert independent_response["request_id"] == selected["request_id"]
            assert independent_response["status"] == "accepted"
            assert independent_response["replayed"] is False
            assert not ({"import_seq", "import_id", "key_id"} & set(independent_response))
            b_event = validate_event(read_json(ROOT / "fixtures" / case["expected_event_fixture"]))
            a_id = derive(
                a_keyed["control_key"], a_keyed["account_id"], a_keyed["device_id"],
                a_keyed["subscription"]["instance"],
            )[2]
            b_id = derive(
                selected["control_key"], selected["account_id"], selected["device_id"],
                selected["subscription"]["instance"],
            )[2]
            assert a_id != b_id and b_event["key_id"] == b_id
            assert b_event["import_id"] == selected["request_id"]
            assert "account_id" not in b_event and "import_seq" not in b_event
            assert case["new_b_active_and_claimable"] is True
            assert case["new_b_enrollment_imported_queued_atomically"] is True
            assert case["key_id_is_account_context_bound"] is True
            assert case["shared_secret_compromise_couples_accounts"] is True
        else:
            assert case["id"] == "absent-account-b-epoch-above-one-rejected"
            assert case["selected_row_before"] == "absent"
            assert selected["subscription"]["subscription_epoch"] > 1
            assert case["expected"] == "reject"
            assert validate_error_response(case["expected_response"]) == {"error": "epoch_conflict"}
            assert case["expected_error_fixture"] == "error-epoch-conflict.json"
            assert all(case[field] is False for field in (
                "row_mutation", "generation_mutation", "queue_mutation", "receipt_ledger_mutation",
            ))

    retry_cases = adoption_cases["idempotence_and_status_retry_cases"]
    assert len(retry_cases) == 6
    for case in retry_cases:
        assert case["row_before"] == case["row_after"]
        assert case["row_mutation"] is False and case["generation_mutation"] is False
        assert case["receipt_ledger_mutation"] is False
        assert case["context_unchanged"] is True
        assert case["outbox_limits"] == {
            "max_status_events_per_intent_per_30_seconds": 1,
            "duplicate_claimable_statuses_after": 0,
            "unclaimable_statuses_after": 0,
        }
        expected_status_count = 1 if case["expected_queue_action"] in ("coalesce", "enqueue_one") else 0
        assert case["claimable_status_count_after"] == expected_status_count
        assert case["queue_count_after"] - case["queue_count_before"] in (0, 1)
        if case["state"] == "active":
            assert case["row_is_claimable"] is True
            if case["current_import_id_matches"]:
                assert all(case[field] is True for field in (
                    "current_epoch_matches", "current_key_matches", "current_context_matches",
                    "current_import_seq_matches", "current_import_id_matches",
                    "current_generation_matches",
                ))
            else:
                assert case["id"] == "historical-v3-replay-is-not-current"
        else:
            assert case["row_is_claimable"] is False
            assert case["expected_queue_action"] == "none"
            assert case["queue_count_after"] == 0
        if case["expected_queue_action"] == "coalesce":
            assert case["claimable_status_pending"] is True
            assert case["queue_count_before"] == case["queue_count_after"] == 1
        elif case["expected_queue_action"] == "enqueue_one":
            assert case["state"] == "active" and case["row_is_claimable"] is True
            assert case["seconds_since_last_status_enqueue"] >= 30
            assert case["queue_count_before"] == 0 and case["queue_count_after"] == 1
        else:
            assert case["queue_count_after"] == 0
        retry_response = validate_response(read_json(ROOT / "fixtures" / case["response_fixture"]))
        assert retry_response["replayed"] is True
        if case["id"] == "historical-v3-replay-is-not-current":
            assert case["historical_replay_is_current_confirmation"] is False
            assert retry_response["status"] == "accepted"
            assert case["current_import_id_matches"] is False
            assert case["expected_queue_action"] == "none"
        elif case["state"] == "active" and case["current_import_id_matches"]:
            assert retry_response["status"] == "unchanged"
        if case["state"] != "active":
            assert case["historical_replay_is_current_confirmation"] is False
    for replay in (current_replay, historical_replay):
        assert "import_seq" not in replay and "key_id" not in replay and "import_id" not in replay

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
    must_reject_with(lambda: validate_enrollment(bad_enrollment), "v3 negotiation", "unsupported_version")
    precedence = adoption_cases["validation_precedence_cases"]
    assert len(precedence) == 1
    precedence_case = precedence[0]
    assert precedence_case["validation_order"] == ["supported_event_versions", "capabilities"]
    assert validate_error_response(precedence_case["expected_response"]) == {
        "error": "unsupported_version",
    }
    assert all(precedence_case[field] is False for field in (
        "row_mutation", "generation_mutation", "queue_mutation", "receipt_ledger_mutation",
    ))
    both_invalid = copy.deepcopy(enrollment)
    both_invalid["subscription"] = dict(
        enrollment["subscription"],
        supported_event_versions=precedence_case["supported_event_versions"],
        capabilities=precedence_case["capabilities"],
    )
    must_reject_with(
        lambda: validate_enrollment(both_invalid),
        precedence_case["id"],
        precedence_case["expected_error"],
    )
    bad_enrollment = dict(enrollment, control_key=enrollment["control_key"] + "=")
    must_reject(lambda: validate_enrollment(bad_enrollment), "padded control key")
    bad_response = dict(response, key_id=key_id)
    must_reject(lambda: validate_response(bad_response), "operator receipt key id")

    invalid_cases = read_json(ROOT / "fixtures/invalid-cases-v3.json")
    assert {case["id"] for case in invalid_cases["public_error_cases"]} == {
        "missing-capabilities-valid-negotiation-is-invalid-enrollment",
        "missing-capabilities-unsupported-negotiation-is-invalid-enrollment",
    }
    for case in invalid_cases["schema_invalid"]:
        value = read_json(ROOT / "fixtures" / case["fixture"])
        validator = {
            "enrollment": validate_enrollment,
            "event": validate_event,
        }[case["schema"]]
        must_reject(lambda v=value, fn=validator: fn(v), case["id"])
    for case in invalid_cases["public_error_cases"]:
        value = read_json(ROOT / "fixtures" / case["fixture"])
        must_reject_with(
            lambda v=value: validate_enrollment(v),
            case["id"], case["expected_error"],
        )
    runtime_cases = read_json(ROOT / "fixtures/runtime-cases-v3.json")["cases"]
    required_runtime_cases = {
        "stale-sequence-unseen-request-id", "equal-sequence-nonidentical",
        "same-epoch-different-key", "conflicting-repeated-request-id",
        "reaffirm-same-epoch-fresh-id", "delayed-old-same-epoch-event",
        "old-file-recorded-reimport-after-newer-same-epoch",
        "old-file-unseen-reimport-after-newer-same-epoch", "rerender-existing-no-slot",
        "restart-retains-pending-intents",
        "legacy-unknown-intent", "explicit-lower-epoch-recovery",
        "lost-status-later-wake", "ordinary-lower-epoch-before-later-candidate",
        "cap-refusal-rerender-restart", "unknown-legacy-migration",
    }
    assert {case["id"] for case in runtime_cases} == required_runtime_cases
    for case in runtime_cases:
        if "expected_error" in case:
            assert validate_error_response(case["expected_response"]) == {
                "error": case["expected_error"],
            }
            assert all(case[field] is False for field in (
                "row_mutation", "generation_mutation", "queue_mutation",
                "outbox_mutation", "receipt_ledger_mutation",
            ))
        if case["id"] == "conflicting-repeated-request-id":
            assert case["expected_error"] == "idempotency_conflict"
        if case["id"] == "old-file-recorded-reimport-after-newer-same-epoch":
            assert case["receipt_state"] == "recorded_exact"
            assert case["expected"] == "saved_historical_receipt"
            recorded_request = validate_enrollment(
                read_json(ROOT / "fixtures" / case["recorded_request_fixture"])
            )
            incoming = case["incoming"]
            assert case["selected_account_id"] == recorded_request["account_id"]
            assert incoming["account_id"] == recorded_request["account_id"]
            assert incoming["device_id"] == recorded_request["device_id"]
            assert recorded_request["request_id"] == incoming["request_id"]
            assert recorded_request["request_id"] == incoming["import_id"]
            assert recorded_request["import_seq"] == incoming["import_seq"]
            assert recorded_request["subscription"]["subscription_epoch"] == incoming["epoch"]
            assert recorded_request["subscription"]["instance"] == incoming["instance"]
            recorded_key_id = derive(
                recorded_request["control_key"], recorded_request["account_id"],
                recorded_request["device_id"], recorded_request["subscription"]["instance"],
            )[2]
            assert incoming["key_id"] == recorded_key_id
            assert case["retained"]["key_id"] == recorded_key_id
            historical = validate_response(
                read_json(ROOT / "fixtures" / case["expected_response_fixture"])
            )
            assert historical["request_id"] == incoming["request_id"]
            assert historical["subscription_epoch"] == recorded_request["subscription"][
                "subscription_epoch"
            ]
            assert historical["instance"] == recorded_request["subscription"]["instance"]
            assert historical["status"] == "accepted" and historical["replayed"] is True
            assert case["replayed"] is True
            assert case["request_digest_match"] is True
            assert case["status_retry"] is False
            assert case["historical_receipt_is_current_confirmation"] is False
            assert case["row_mutation"] is False and case["queue_mutation"] is False
            assert case["receipt_ledger_mutation"] is False
        if case["id"] == "old-file-unseen-reimport-after-newer-same-epoch":
            assert case["receipt_state"] == "unseen"
            assert case["expected_error"] == "epoch_conflict"
            assert case["request_digest_match"] is False
        if case["id"] == "reaffirm-same-epoch-fresh-id":
            assert case["row_state"] == "active" and case["row_claimable"] is True
            assert case["old_queued_work_invalidated"] is True
            assert case["confirmation_queued_atomically"] is True
            assert case["confirmation_claimable"] is True
    assert all(case["expected"] in {
        "accept", "reject", "no_promotion", "recover", "saved_historical_receipt",
    }
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
        "schema_valid_fixture_instances": schema_fixture_count,
        "schema_invalid_fixtures_rejected": schema_invalid_fixture_count,
        "runtime_transition_vectors": len(runtime_cases),
        "first_v3_adoption_mutations_rejected": len(adoption_cases["rejected_adoption_mutations"]),
        "legacy_unkeyed_same_epoch_rejected": 1,
        "inactive_adoption_cases_rejected": len(adoption_cases["inactive_same_epoch_cases"]),
        "current_historical_replay_cases": 2,
        "idempotence_and_status_retry_cases": len(retry_cases),
        "key_id_digest_bytes": len(digest),
        "negative_cases_rejected": NEGATIVE_CHECKS,
        "transient_paths_excluded": excluded_transient_paths,
        "scope": "offline schema/fixture shape, manifest hashes, HMAC vector and encoding; runtime transitions remain required implementation tests",
    }, indent=2))


if __name__ == "__main__":
    main()
