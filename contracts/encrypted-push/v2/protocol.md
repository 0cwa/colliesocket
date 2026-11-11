# Enrollment v2 and Signal endpoint updates

This contract extends [v1](../v1/protocol.md). All v1 validation, private-import
authorization, destination checks, encrypted-push framing, queue limits, expiry,
replay protection and lock behavior still apply unless explicitly changed here.
The v1 files are immutable. MUST, MUST NOT and MAY are normative requirements.

## Private enrollment and migration

`enrollment_version: 2` adds one optional top-level field, `control_key`.
It is canonical unpadded base64url encoding of exactly 32 random bytes, generated
on the phone using a cryptographically secure random generator. It is an
AES-256 key, independent of the Signal password, Web Push `auth` and receiver
private key. Only the existing protected private import can establish, replace
or remove it. Never put it in discovery, Signal plaintext, push events, URLs,
logs, or an import receipt.

With a key, `subscription.supported_event_versions` MUST be exactly `[2]`;
without a key it MUST be exactly `[1]`. Capabilities remain exactly
`["wake","test","status"]`. A keyless v2 import has v1 runtime behavior:
there are no authenticated in-band updates and generated events use version 1.
V1 imports retain their exact v1 structure and behavior; a `control_key` in a
v1 import is invalid. An explicit null key is invalid in either version.

Initial enrollment is epoch 1. Enabling control for an existing enrollment,
changing or removing a control key, and changing the negotiated event version require a
private import at exactly the next epoch. The receipt echoes the accepted
enrollment version and selected event version; it never returns the key. The
existing request-id/digest rules apply, including unchanged serialization of
v1 requests when the optional field is absent. An otherwise identical keyless
v2 import may be unchanged at the current epoch. An idempotent old private import
cannot restore an old epoch, endpoint, key, or active state.

The account, linked-device ID and password, instance, control key, event-version
negotiation and capabilities are private-import-only values. A control update
can change only endpoint, `p256dh`, `auth` and subscription epoch. Replacing a
registration or restoring a backup must revoke obsolete socket callbacks and
old control authority. On recovery, use fresh receiver keys, a fresh instance
and a fresh control key through private import before sending resumes.

## Exact Signal message format

The phone sends a dedicated sync message to its own Signal account with
`urgent=false`. For every linked device except the enrolled CollieSocket device,
send the normal encrypted Signal sync message. For the CollieSocket device only,
replace that per-device encrypted content with the following raw binary blob.
The substitution MUST also be applied when rebuilding per-device messages after
a mismatched-device response. It must not depend on a device's position in the
recipient list. Do not replace a different device's message if the enrolled
device is absent. Normal messages and normal sync sends remain unchanged.

The exact blob is carried as `Envelope.content`; it is not JSON-wrapped,
base64-wrapped, Signal-decrypted by CollieSocket, or a separate websocket route.
The outer Signal message type, sender and source-device fields are transport
metadata, not authentication. Anyone able to message the account may put bytes
on that linked device. Only successful AES-GCM authentication with the imported
control key authorizes any endpoint update.

| Offset | Length | Bytes |
| --- | --- | --- |
| 0 | 21 | ASCII `CollieSocket-Control` followed by `0x00` |
| 21 | 1 | Contract version `0x02` |
| 22 | 8 | Target subscription epoch, unsigned big-endian integer |
| 30 | 12 | AES-GCM nonce |
| 42 | N | AES-256-GCM ciphertext of the plaintext below |
| 42 + N | 16 | AES-GCM authentication tag |

The target epoch is in `1..9007199254740991`. The nonce is exactly 12 random
bytes and MUST NOT be reused for different plaintext/AAD under the same key.
Generate a blob once and persist its exact bytes on the phone before sending;
retries retransmit those same bytes, including nonce and tag. Never encrypt
changed data with that nonce. A fresh endpoint change uses a fresh nonce and
the next epoch. Keep at most one unconfirmed change in flight per enrollment.

The authenticated additional data (AAD) is exactly the following 50 bytes,
concatenated without separators, text conversion or length prefixes:

1. The blob's 30-byte magic/version/epoch header.
2. The 16 raw bytes of the enrolled account UUID, in canonical UUID byte order
   (the hex digits of its canonical text with hyphens removed).
3. The enrolled device ID as an unsigned 32-bit big-endian integer.

The plaintext is strict UTF-8 JSON with exactly three required string fields:

```json
{"endpoint":"https://push.example.test/new","p256dh":"<canonical base64url P-256 point>","auth":"<canonical base64url 16 bytes>"}
```

Each field has the same validation and destination policy as in v1. Unknown
fields, duplicate names, nulls, invalid UTF-8, a BOM, trailing non-whitespace
data and invalid key material fail closed. Maximum plaintext size is 3072 bytes;
maximum blob size is 4096 bytes, checked before decryption or allocating
plaintext. The
minimum syntactically possible blob size is 58 bytes (header, nonce and tag);
empty plaintext still fails JSON validation. AES-GCM authentication must succeed
before any decrypted value affects durable state or starts endpoint validation.
Failure messages must not echo decrypted bytes, endpoint URLs or key material.

## Receive, commit and acknowledge

For an enrollment with a control key, CollieSocket inspects `Envelope.content`
for the complete 21-byte magic before deciding whether an envelope should cause
a wake. A matching prefix reserves the content as control traffic, even when
the remaining blob is malformed, unsupported, forged, or incorrectly marked
urgent. Such content MUST NOT fall through to ordinary wake handling.

The receiver authenticates with the durable enrolled account/device/key, then
validates the plaintext, exact epoch transition and destination policy. It
atomically verifies the current enrollment generation, updates endpoint/keys/
epoch, marks the subscription active, deletes old-epoch queued events, records
the SHA-256 digest of the exact accepted blob, and queues a version-2
`status`/`subscription_updated` event for the new epoch. A stale or
provider-rejected subscription can be revived only by an accepted next-epoch
update or private import. Signal credentials remain unchanged.

Commit this transaction before acknowledging the websocket frame. A permanent
invalid/forged/replayed-conflicting control is discarded and may be acknowledged
without any state change or wake. If durable storage or required queue capacity
is temporarily unavailable, do not acknowledge successful acceptance or perform
a partial update. Retrying the exact blob must remain safe after interruption
at any point. On a private-import race, reject the obsolete operation instead
of applying it to the replacement enrollment. A delayed provider result or old
socket callback cannot mutate the new enrollment.

On successful in-band rotation, subsequent ordinary messages must use the new
subscription even when the Signal socket stays connected. Updating a push
endpoint is not a Signal credential change and never authorizes unlinking,
re-registration, or legacy/plaintext fallback.

### Epochs and identical retries

An update is new only when its target epoch equals the current epoch plus one.
Skipped or lower epochs fail. At the current epoch, only the exact accepted
blob (same SHA-256 digest) is an identical retry; different bytes, even if they
decrypt to equal fields, fail. Current-epoch retries never change the
subscription, control digest, active/stale state, connection credentials or
old event replay state. In particular, an identical retry cannot revive a
subscription that became inactive after the original acceptance.

There is one narrowly scoped confirmation exception to this state no-op: while
the current subscription is active, ensure a bounded `subscription_updated`
confirmation is pending. Reuse an existing unexpired matching queued status,
including its event ID and retry state. If no such status remains after provider
acceptance, discard, or expiry, a retry may queue a fresh status with a new event
ID and normal lifetime, at most once per 30 seconds per subscription. Persist
the last confirmation ID and issuance time so restart cannot reset that bound;
a clock rollback does not permit early refresh. Never create duplicates alongside an existing matching
confirmation, exceed v1 queue/ledger caps, reset an in-flight lease, or reset
an existing confirmation's attempt count. Queue exhaustion has no enrollment
effect. This permits recovery when the provider accepted a status that the
phone did not receive. It is not a second subscription update.

## Version-2 push events and phone confirmation

Key-enabled v2 enrollments emit all wake, test and status events with
`version: 2`. Their field set, RFC 8291/8188 encryption, padding, maximum lifetime,
headers, retry rules and receiver protections are the same as v1. The status
code enum adds `subscription_updated` to `connection_conflict` and
`connection_unavailable`; no other schema extension is accepted. Keyless v2 and
v1 enrollments continue to emit only v1 events and v1 status codes.

The phone retains the pending new endpoint/key/epoch and exact control blob
durably, and keeps resending the same blob through the dedicated non-urgent sync
path until it receives and decrypts a valid version-2 `status` with code
`subscription_updated`, matching instance and pending epoch, through the pending
new subscription. Apply the ordinary unlocked-state, time and replay gates
before recording confirmation. Neither Signal send success, a websocket ACK,
local queue insertion, nor provider HTTP 2xx establishes phone receipt.

The phone must be able to decrypt using the pending new receiver key while it
waits; only that authenticated new-epoch confirmation completes the pending
change. An unrelated status, wrong instance/epoch, old endpoint, forged push,
or duplicate event never confirms it. Persist confirmation before clearing the
pending retry record. A lost receipt after a process restart is recovered by
resending the persisted blob, not by incrementing the epoch again. Locked phones
retain pending work and resume after unlock; v1's initial lock gate is preserved.

## Compatibility and fixed errors

V1 schemas and fixtures remain byte-for-byte unchanged. This is an additive
private import version; it creates no public enrollment endpoint and requires no
open inbound server port. Existing account allowlists, address/redirect checks,
secret file protections, queue bounds and no-plaintext guarantees remain in
force. An older server may reject v2 imports with `unsupported_version`.

The server's SQLite schema advances from 2 to 3, adding protected control-key,
private-import generation, accepted-blob digest and confirmation metadata.
Migration preserves v1 registrations and their receipt digests. Keep a complete
owner-only backup of a cleanly stopped database before upgrading. There is no
automatic down migration: rollback pairs the old binary with its matching
pre-upgrade backup, then follows the fresh-enrollment recovery rule above.
An old binary must not open the upgraded live database. Existing private CLI
commands and `MOLLY_` configuration names remain unchanged.

The private import continues to expose only the fixed v1 error vocabulary.
Control failures need no caller-visible diagnostic beyond a transport ACK;
internal errors must be fixed secret-free codes. Contract JSON schemas validate
structure only: crypto, canonical encodings, endpoint policy, exact epochs,
durable transactions and phone receipt require the semantic rules above.
