# CollieSocket single-use QR pairing v1

Pairing transports an [encrypted-push v3 enrollment](../../encrypted-push/v3/README.md)
to a trusted CollieSocket operator. The phone scans the offer, displays its
host and provider for explicit approval, and seals its enrollment only after
approval. The existing protected `enrollment import --file` flow also supports
manual and air-gapped provisioning.

## Offer and trust

The QR payload is UTF-8 JSON conforming to `offer.schema.json`, up to 1024
bytes, with `pairing_version: 1`. It carries only public data. Use a fresh
random lowercase UUIDv4 and a fresh X25519 key pair for each offer. The expiry
is an integer Unix second. The server permits 1–600 seconds and defaults to
300. A phone should reject expired offers before displaying or sealing them.

- `host_label` is an operator-supplied label for the server. Show the full label.
- `provider_origin`, when available, is the canonical ASCII HTTP(S) origin
  with lowercase host, no default port, no slash, path, query, fragment, or
  userinfo. For IPv6 use bracketed, compressed lowercase form. The enrollment
  endpoint must have that exact origin. If the field is absent, show that the
  provider is unspecified by the host and require approval of the phone's
  selected provider before sealing.
- `vapid_public_key` is the server's uncompressed SEC 1 P-256 public key
  (65 bytes, first byte `0x04`). The phone validates the point and uses this
  key for the push subscription. Replacing the configured VAPID key invalidates
  offers created under the earlier key while the replacement is in effect.
- `server_public_key` is the server's ephemeral raw 32-byte X25519 public key.

`pair_bridge` grants a primary phone's authorized import of a v3 enrollment
for a Signal bridge device. `add_receiver` is reserved for a future linked
device joining an existing bridge. Both intent strings are part of the v1
format. A single-receiver server rejects a well-formed `add_receiver` create
or sealed request with `unsupported_intent` before looking up or changing a
session or registration. Unknown intent strings are invalid requests.

The operator obtains the offer through trusted local control and authorizes
its holder or the transport separately. X25519 authenticates the response
to the private key corresponding to the scanned offer. Anyone who sees the
offer can construct a fresh encrypted request. A relay must authenticate
and authorize the submitting phone before invoking the local import path.
The public discovery listener has no pairing or enrollment route. This
contract defines QR bytes, messages, and the protected host-side entry
point. Collie Pack and phone transport are outside this contract.

## Sealing a request

All outer JSON is strict UTF-8, with no BOM, unknown or duplicate members,
or trailing data except JSON whitespace. Integer fields use integer JSON
tokens. Binary JSON fields use canonical RFC 4648 base64url without padding
or nonzero unused bits. Raw X25519 public keys follow RFC 7748 little-endian
encoding with one additional restriction: the coordinate must be less than
`2^255 - 19`. Reject any exchange yielding an all-zero secret, including
when the crypto provider rejects the exchange directly.

The phone generates an ephemeral X25519 key pair and computes
`shared = X25519(client_private, server_public)`. Use the following exact
transcript `T`, with no JSON serialization or platform-specific UUID encoding.

| In order | Bytes |
| --- | --- |
| Protocol | ASCII `COLLIESOCKET-PAIRING` followed by `00` hex |
| Version | One byte `01` hex |
| Session | 36 ASCII bytes of the canonical lowercase UUID, including hyphens |
| Intent | One byte `01` for `pair_bridge`, `02` for `add_receiver` |
| Expiry | `expires_at` as unsigned 8-byte big-endian |
| Host | Two-byte unsigned big-endian length followed by `host_label` ASCII bytes |
| Provider | Two-byte unsigned big-endian length followed by `provider_origin` ASCII bytes, length zero if absent |
| VAPID | 65 decoded public key bytes |
| Server, then phone | Decoded 32-byte X25519 public key of each, in that order |

Both sides derive two 32-byte keys with RFC 5869 HKDF-SHA256,
`IKM = shared`, `salt = SHA256(T)`, with exact ASCII info strings
`COLLIESOCKET-PAIRING-V1 request` and `COLLIESOCKET-PAIRING-V1 receipt`
respectively. The info strings have no terminator.

Encrypt the exact strict v3 enrollment JSON with the request key and
AES-256-GCM, using `T` as AAD, a fresh independent cryptographic 12-byte
nonce, and a full 16-byte tag. The base64url `ciphertext` field encodes
ciphertext followed by tag. The envelope includes `pairing_version`,
`session_id`, `intent`, `client_public_key`, `nonce`, and `ciphertext`.
Version, session, and intent must match the offer. The plaintext is at most
8192 bytes, the ciphertext with tag is 17–8208 bytes, and the outer JSON is
at most 11264 bytes. Never reuse a nonce with the same key for different bytes.
Application, destination, address, redirect, and encrypted-only rules follow
the protected v3 import and dispatch paths.

## Receipt and session lifecycle

A successful submission yields the frozen v3 receipt JSON inside an
AES-256-GCM envelope using the receipt key and a fresh independent 12-byte
nonce. Use AAD `T || SHA256(request_nonce || request_ciphertext_with_tag)`
with decoded bytes. The response echoes `pairing_version`, `session_id`, and
`intent`, and carries `nonce` and `ciphertext` encoded as in the request.
Verify the echo and AEAD tag before accepting the v3 receipt. The receipt
plaintext is at most 1024 bytes, and the outer response is at most 2048 bytes.
The receipt describes the import. Device confirmation still requires a
matching v3 event.

The session starts `active`. The server checks its clock again under the
SQLite writer lock before enrollment. Expiry is inclusive
(`now >= expires_at`). Cancellation and a successful import each close the
session and erase its stored ephemeral private key. Enrollment, its durable
receipt and queued confirmation, and session consumption commit together.
An authenticated request rejected by validation or storage leaves the live
session available for another submission. At most one concurrent submission
can succeed. A lost success response can be diagnosed with local status.
Submitting the same or a different well-formed request to the consumed
session returns `session_consumed`.

| State when submitting a well-formed `pair_bridge` request | Result |
| --- | --- |
| Active and valid | Authenticated receipt, session becomes `consumed` |
| Active with invalid authentication | `invalid_envelope` |
| Expired before successful import | `session_expired` |
| Consumed | `session_consumed` |
| Cancelled, unknown, or outside retention | `invalid_session` |

Terminal states persist across ordinary process restarts. Status reports the
state and original deadline. Retain terminal records for up to 24 hours
after the original deadline to make rejections predictable. After retention,
an ID is unknown. There are at most eight active sessions and 1024 total
records. Use the current service clock and database history. Restore into
a new pairing lifecycle by discarding pending pairing sessions before
accepting submissions. Do not back up live sessions for later resumption.

Errors are one-field JSON objects from `response.schema.json`. Outer shape,
encodings, size, authentication and reserved intent have fixed errors.
The v3 import rejection codes pass through after successful decryption.
Errors never echo values. The QR, command arguments, URLs and logs must
never carry enrollment credentials or any private key.

## Local operation and conformance

Run with the CollieSocket service account and its usual configuration. JSON
goes to stdout, with an optional terminal QR on stderr. When the configuration
lists exactly one explicit allowed origin, `create` uses that origin by
default. With multiple origins, supply `--provider-origin` to advertise and
bind the selected provider. The configured VAPID key must be usable.

```sh
mollysocket pairing create --host-label "Home bridge" --qr
mollysocket pairing status SESSION_ID
mollysocket pairing submit --stdin < sealed-request.json
mollysocket pairing cancel SESSION_ID
```

`submit --file` also accepts a mode-0600 regular file owned by the service
account, with no symbolic or extra hard links. Keep the service database
private. The service and the pairing commands clean up expired keys and
records.

Run the independent Python checker with the
[pairing conformance dependencies](tools/requirements.txt)
installed.

```sh
python3 contracts/pairing/v1/tools/conformance.py
```

`fixtures/sealed-vectors.json` contains synthetic raw private keys, exact
transcripts, derived keys, sealed v3 enrollments and authenticated receipts
for offers with and without a provider origin. The negative cases cover
wire bounds, strict input, changed transcript fields and receipt binding.
Rust and Python both check the origin spelling cases.
The CLI integration test covers persistent session transitions.
