#!/usr/bin/env python3
"""Verify public synthetic pairing wire data with independent primitives."""
import base64
import copy
import hashlib
import ipaddress
import json
from pathlib import Path
import re
from unicodedata import bidirectional
from urllib.parse import urlsplit

import idna
from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec, x25519
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from jsonschema import Draft202012Validator, ValidationError

ROOT = Path(__file__).resolve().parents[1]
V3 = ROOT.parent.parent / "encrypted-push/v3"
INTENTS = {"pair_bridge": 1, "add_receiver": 2}
LIMITS = {"offer": 1024, "request": 11264, "response": 2048}


def encode(value):
    return base64.urlsafe_b64encode(value).decode("ascii").rstrip("=")


def decode(value, minimum, maximum=None):
    raw = base64.urlsafe_b64decode(value + "=" * (-len(value) % 4))
    if not minimum <= len(raw) <= (maximum if maximum is not None else minimum):
        raise ValueError("wrong binary length")
    if encode(raw) != value:
        raise ValueError("noncanonical base64url")
    return raw


def compact(value):
    return json.dumps(value, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


def read_json(data):
    def fields(pairs):
        value = dict(pairs)
        if len(value) != len(pairs):
            raise ValueError("duplicate JSON member")
        return value

    def reject_number(_):
        raise ValueError("non-integer JSON number")

    return json.loads(data.decode("utf-8"), object_pairs_hook=fields,
                      parse_float=reject_number, parse_constant=reject_number)


def schema(directory, kind):
    result = read_json((directory / f"{kind}.schema.json").read_bytes())
    Draft202012Validator.check_schema(result)
    return Draft202012Validator(result)


def length_prefix(value):
    payload = value.encode("ascii")
    return len(payload).to_bytes(2, "big") + payload


def transcript(offer, client_public):
    return (b"COLLIESOCKET-PAIRING\0"
            + bytes([offer["pairing_version"]])
            + offer["session_id"].encode("ascii")
            + bytes([INTENTS[offer["intent"]]])
            + offer["expires_at"].to_bytes(8, "big")
            + length_prefix(offer["host_label"])
            + length_prefix(offer.get("provider_origin", ""))
            + decode(offer["vapid_public_key"], 65)
            + decode(offer["server_public_key"], 32)
            + client_public)


def public_key(raw):
    if int.from_bytes(raw, "little") >= 2**255 - 19:
        raise ValueError("noncanonical X25519 coordinate")
    return x25519.X25519PublicKey.from_public_bytes(raw)


def key(shared, aad, direction):
    return HKDF(algorithm=hashes.SHA256(), length=32, salt=hashlib.sha256(aad).digest(),
                info=b"COLLIESOCKET-PAIRING-V1 " + direction).derive(shared)


def seal_request(offer, client, nonce, plaintext):
    client_public = client.public_key().public_bytes_raw()
    aad = transcript(offer, client_public)
    shared = client.exchange(public_key(decode(offer["server_public_key"], 32)))
    ciphertext = AESGCM(key(shared, aad, b"request")).encrypt(nonce, plaintext, aad)
    return {"pairing_version": 1, "session_id": offer["session_id"], "intent": offer["intent"],
            "client_public_key": encode(client_public), "nonce": encode(nonce),
            "ciphertext": encode(ciphertext)}


def open_request(offer, request, server):
    if any(request[field] != offer[field] for field in ("pairing_version", "session_id", "intent")):
        raise ValueError("offer/request mismatch")
    client_public = decode(request["client_public_key"], 32)
    aad = transcript(offer, client_public)
    shared = server.exchange(public_key(client_public))
    return AESGCM(key(shared, aad, b"request")).decrypt(
        decode(request["nonce"], 12), decode(request["ciphertext"], 17, 8208), aad)


def receipt_aad(aad, request):
    return aad + hashlib.sha256(decode(request["nonce"], 12)
                                + decode(request["ciphertext"], 17, 8208)).digest()


def open_receipt(offer, request, response, client):
    if any(response[field] != offer[field] for field in ("pairing_version", "session_id", "intent")):
        raise ValueError("offer/receipt mismatch")
    aad = transcript(offer, client.public_key().public_bytes_raw())
    shared = client.exchange(public_key(decode(offer["server_public_key"], 32)))
    plaintext = AESGCM(key(shared, aad, b"receipt")).decrypt(
        decode(response["nonce"], 12), decode(response["ciphertext"], 17, 1040),
        receipt_aad(aad, request))
    return read_json(plaintext)


def decode_origin_label(label):
    if not label.startswith("xn--"):
        return label
    encoded = label[4:]
    decoded = encoded.encode("ascii").decode("punycode")
    if (decoded.isascii() or "." in decoded
            or idna.uts46_remap(decoded, std3_rules=False) != decoded
            or decoded.encode("punycode").decode("ascii") != encoded):
        raise ValueError("invalid IDNA label")
    idna.core.check_initial_combiner(decoded)
    for index, character in enumerate(decoded):
        if character in ("\u200c", "\u200d") and not idna.core.valid_contextj(decoded, index):
            raise ValueError("invalid IDNA joiner")
    return decoded


def canonical_origin(origin):
    if not all(33 <= ord(character) <= 126 for character in origin):
        raise ValueError("invalid ASCII provider origin")
    parsed = urlsplit(origin)
    host = parsed.hostname
    if not host or any(character in "%<>^|" for character in host):
        raise ValueError("invalid provider host")
    if ":" in host:
        ip = ipaddress.IPv6Address(host)
        if ip.ipv4_mapped is not None:
            # WHATWG serializes mapped addresses as hex, even when the
            # Python runtime prefers a dotted IPv4 tail.
            tail = int(ip.ipv4_mapped)
            host = f"[::ffff:{tail >> 16:x}:{tail & 0xffff:x}]"
        else:
            host = f"[{ip.compressed}]"
    else:
        labels = host.removesuffix(".").split(".")
        if re.fullmatch(r"(?:[0-9]+|0x[0-9a-f]*)", labels[-1]):
            host = str(ipaddress.IPv4Address(host))
        else:
            decoded = [decode_origin_label(label) for label in labels]
            # The UTS 46 bidi rule applies to every label in a bidi domain,
            # including its ASCII labels.
            if any(bidirectional(c) in ("R", "AL", "AN") for label in decoded for c in label):
                for label in filter(None, decoded):
                    idna.core.check_bidi(label, check_ltr=True)
    port = parsed.port
    if port == 0:
        raise ValueError("invalid provider port")
    suffix = f":{port}" if port not in (None, {"http": 80, "https": 443}[parsed.scheme]) else ""
    if origin != f"{parsed.scheme}://{host}{suffix}":
        raise ValueError("noncanonical provider origin")


def validate(kind, data, validators):
    if len(data) > LIMITS[kind]:
        raise ValueError("wire size")
    value = read_json(data)
    validators[kind].validate(value)
    if kind == "offer":
        public_key(decode(value["server_public_key"], 32))
        vapid = decode(value["vapid_public_key"], 65)
        if vapid[0] != 4:
            raise ValueError("VAPID key format")
        ec.EllipticCurvePublicKey.from_encoded_point(ec.SECP256R1(), vapid)
        if "provider_origin" in value:
            canonical_origin(value["provider_origin"])
    elif "ciphertext" in value:
        decode(value["nonce"], 12)
        decode(value["ciphertext"], 17, 8208 if kind == "request" else 1040)
        if kind == "request":
            public_key(decode(value["client_public_key"], 32))
    return value


def rejects(operation, label):
    try:
        operation()
    except (ValueError, ValidationError, InvalidTag):
        return 1
    raise AssertionError(f"accepted invalid synthetic case {label}")


def run_vector(vector, validators):
    offer, request, response = (
        validate(kind, compact(vector[kind]), validators) for kind in ("offer", "request", "response")
    )
    server = x25519.X25519PrivateKey.from_private_bytes(decode(vector["server_private_key"], 32))
    client = x25519.X25519PrivateKey.from_private_bytes(decode(vector["client_private_key"], 32))
    assert encode(server.public_key().public_bytes_raw()) == offer["server_public_key"]
    aad = transcript(offer, client.public_key().public_bytes_raw())
    shared = server.exchange(client.public_key())
    assert aad.hex() == vector["transcript_hex"]
    assert shared.hex() == vector["shared_secret_hex"]
    for direction in ("request", "receipt"):
        assert key(shared, aad, direction.encode()).hex() == vector[f"{direction}_key_hex"]
    plaintext = vector["enrollment_json"].encode()
    assert seal_request(offer, client, decode(request["nonce"], 12), plaintext) == request
    assert open_request(offer, request, server) == plaintext
    schema(V3, "enrollment").validate(read_json(plaintext))
    receipt = open_receipt(offer, request, response, client)
    assert receipt == read_json(vector["receipt_json"].encode())
    schema(V3, "response").validate(receipt)
    return offer, request, response, server, client


def flipped(value, minimum, maximum):
    raw = decode(value, minimum, maximum)
    return encode(raw[:-1] + bytes([raw[-1] ^ 1]))


def main():
    validators = {kind: schema(ROOT, kind) for kind in ("offer", "request", "response")}
    fixture = lambda name: read_json((ROOT / "fixtures" / name).read_bytes())
    count = 0
    vectors = fixture("sealed-vectors.json")
    offer, request, response, server, client = run_vector(vectors[0], validators)
    for vector in vectors[1:]:
        run_vector(vector, validators)

    negative = fixture("negative-cases.json")
    for case in negative["schema"]:
        kind = case["kind"]
        value = copy.deepcopy({"offer": offer, "request": request, "response": response}[kind])
        value.update(case.get("replace", {}))
        for field in case.get("remove", []):
            del value[field]
        count += rejects(lambda: validate(kind, compact(value), validators), case["name"])
    for case in negative["crypto"]:
        envelope = dict(offer)
        envelope.update(case.get("offer", {}))
        proposed = dict(request)
        proposed.update(case.get("request", {}))
        if case.get("flip_tag"):
            proposed["ciphertext"] = flipped(proposed["ciphertext"], 17, 8208)
        count += rejects(lambda: open_request(envelope, proposed, server), case["name"])
    count += rejects(lambda: open_receipt(
        offer, {**request, "ciphertext": flipped(request["ciphertext"], 17, 8208)}, response, client),
        "receipt transplant across different request bytes")
    count += rejects(lambda: validate("request", b" " * 11265, validators), "oversize input")
    count += rejects(lambda: validate(
        "request", b'{"pairing_version":1,' + compact(request)[1:], validators), "duplicate member")
    count += rejects(lambda: validate("request", compact({**request, "pairing_version": 1.0}), validators),
                     "float version")
    count += rejects(lambda: validate("request", compact(list(request.values())), validators),
                     "positional request")
    origin_cases = fixture("origin-cases.json")
    for case in origin_cases:
        value = compact({**offer, "provider_origin": case["origin"]})
        if case["valid"]:
            validate("offer", value, validators)
        else:
            count += rejects(lambda: validate("offer", value, validators), case["name"])
    states = fixture("status-and-errors.json")
    for value in states:
        validate("response", compact(value), validators)
    print(f"PASS pairing/v1 ({len(vectors)} sealed vectors, {len(states)} responses, "
          f"{len(origin_cases)} shared origin cases, {count} negative cases total)")


if __name__ == "__main__":
    main()
