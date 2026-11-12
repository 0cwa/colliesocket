# CollieSocket encrypted-push contract v3

V3 adds ordered private-import intent and event identity so a phone can match a
notification to one specific export, including after a server restore. This is
a protocol contract for future implementations. It does not claim that the
current server or phone ships v3. The v1 contract remains frozen and v2 remains
byte-for-byte unchanged; see the [v1](../v1/README.md) and
[v2](../v2/README.md) contracts.

## Explicit negotiation and compatibility

Enrollment and event versions are negotiated exactly. Implementations MUST NOT
infer v3 from an event field, treat an unknown enrollment version as v2, or add
`key_id`, `import_id`, or `import_seq` to a v1/v2 schema or event.

| Private enrollment | Control key | Advertised event versions | Selected event version |
| --- | --- | --- | --- |
| Version 1 | Absent | Exactly `[1]` | 1 |
| Version 2 | Absent | Exactly `[1]` | 1 |
| Version 2 | Present | Exactly `[1,2]` | 2 |
| Version 3 | Required | Exactly `[1,2,3]` | 3 |

V3 requires a canonical unpadded base64url 32-byte `control_key`, a UUIDv4
`request_id`, and `import_seq`. V3 events are selected only for a v3 keyed
enrollment. Capabilities remain exactly `["wake", "test", "status"]`. V3 adds
no public enrollment endpoint. The v2 Signal control
frame and its validation rules remain unchanged. V3 keeps encrypted enrollment
mandatory, has no plaintext fallback, and retains v2's strict parsing,
destination and redirect checks, key validation, and secret redaction.

Existing v1/v2 behavior is unchanged for rows that have no retained v3 sequence
floor. Once a row has a v3 floor, a state-changing v1/v2 import for that row is
rejected; v1/v2 cannot express a sequence value or new import identity and MUST
NOT reset the v3 floor. An exact replay of a previously recorded v1/v2 request
may return its existing receipt without changing the row or floor. Removing and
reprovisioning the registration is the explicit lifecycle reset. V1/v2 events
never promote a pending v3 key or reset a v3 intent based on epoch alone.

## Ordered import intent

`import_seq` is a positive signed-64-bit-compatible integer from 1 through
`9223372036854775807`. It increases strictly for each newly committed logical
import intent within the registration instance. The phone MUST fail visibly
instead of wrapping at the maximum. It is required in v3 enrollment and is
retained in the server row. It MUST NOT appear in events, enrollment receipts,
operator receipts, logs, or diagnostics.

`request_id` is the UUIDv4 identifier for one logical intent. The v3 event field
`import_id` is that same `request_id`, echoed on every event for the current
v3 import generation. It is distinct from control-frame IDs and `event_id`.
The server persists the active `import_id` and sequence with the registration.

For a v3 row, the server applies these rules atomically:

1. With no row, only epoch 1 can create the row; its accepted sequence becomes
   the initial floor.
2. An exact replay of the current row, including request ID, sequence, key,
   credentials, subscription and negotiation, is idempotent. An exact replay
   of any previously recorded request may return its stored receipt without
   changing the row. A request ID already recorded with different parameters
   is rejected.
3. A sequence greater than the retained floor may import exactly the next
   subscription epoch. A state-changing next-epoch import follows the v2
   requirement to use a fresh control key.
4. A greater sequence may also reaffirm the current epoch only when the key and
   all subscription and registration context are identical and the request ID
   is fresh. This changes intent metadata only: rotate the durable generation,
   invalidate queued work from older generations, and atomically queue a new
   `status/enrollment_imported` event for the new `import_id`.
5. Same-epoch reaffirmation with a different key is rejected. A repeated
   `request_id` with conflicting parameters is rejected. Lower or equal
   sequence with any non-identical state is rejected without mutation.

The active sequence is a floor, not an inference from UUID ordering. An unseen
old request ID cannot rebind a row when its sequence is stale; an exact replay
of an old recorded request returns its old receipt without rebinding the row.
A later import must use a sequence above the retained floor. Queue or persistence failure
leaves the prior row, intent and queued work unchanged and returns no accepted
receipt. Status enqueue and generation update commit in the same transaction;
no provider request is needed before commit. A provider 2xx means the provider
accepted the message, not that a device received it.

## Key identity and events

Every v3 `wake`, `test`, and `status` event MUST contain both `key_id` and
`import_id`. Status codes include the v2 codes plus `enrollment_imported`.
Events retain the v2 instance, epoch, UUID, issue/expiry and replay rules.
Events carry neither `import_seq` nor registration secrets. Receipts echo the
existing `request_id` and contain no key identity or sequence. Operator status
output contains no event identity or sequence.

`key_id` is a stable context-bound identifier for the control key. It is not an
event MAC, signature, import identifier, or proof of phone receipt. Derive it
as follows:

1. Decode canonical unpadded base64url `control_key` to exactly 32 bytes.
2. Build the exact message:

   ```text
   ASCII("COLLIESOCKET-EVENT-KEY-ID")
   || 0x00 || 0x03
   || account_uuid_16
   || device_id_u32_be
   || instance_len_u16_be
   || instance_ascii
   ```

   `account_uuid_16` is the 16 bytes obtained by removing hyphens from the
   canonical lowercase account UUID and decoding hexadecimal pairs in order;
   do not use a platform-specific GUID byte layout. `device_id_u32_be` is the
   unsigned 32-bit big-endian device ID. `instance_ascii` is the exact validated
   v2 instance (`[A-Za-z0-9._:-]`, 1–128 bytes); its length is a two-byte
   unsigned big-endian integer. There is no trailing terminator.
3. Calculate HMAC-SHA-256 with the decoded key and message.
4. Encode all 32 digest bytes as canonical unpadded base64url. The result is
   exactly 43 characters. Padding, non-URL-safe bytes, noncanonical trailing
   bits, truncation, and alternate encodings are invalid.

The deterministic vector [`key-id-v3.json`](fixtures/key-id-v3.json) includes
the key, exact message bytes, complete 32-byte digest, and output string. Rust
and Kotlin implementations must match it and reject altered account, device,
instance, and noncanonical encodings. Receivers recompute the ID from each
locally held candidate key and local account/device/instance context. Event
authenticity still comes from encrypted-push delivery and the existing replay
checks; the identifier alone proves neither authenticity nor phone receipt.

## Phone intent and promotion rules

The phone keeps the current registration instance stable. It distinguishes a
re-render of a saved export from a new logical intent. Re-render reuses the
persisted UUID, sequence, key, target and immutable parameters and consumes no
pending-intent slot. A new logical export allocates and durably commits a UUID
and next sequence before publishing bytes. If a candidate already exists for
that target, the API/UI requires an explicit mode; a second call must not guess
whether it means re-render or new intent. The same epoch reuses its existing
control key and `key_id`.

Compare the resulting export epoch (entered server epoch plus one) with
remembered state. A lower or equal resulting epoch requires explicit recovery
acknowledgement. Ordinary exports cannot be rejected solely by a lower-bound
check. A new intent supersedes prior eligible intents at the same or a higher
target epoch. Lower-epoch intents that remain valid in ordinary sequence order
stay usable until a later sequence is confirmed. Full recovery may explicitly
supersede all pending confirmations. Persist those exclusions before export
bytes leave the phone. If target identity disagrees, retain an unknown safe
state; do not silently evict or select a candidate.

Promotion requires the exact eligible registration instance, `import_id`,
`key_id`, and contract epoch, and a sequence newer than the currently active
intent. Explicit recovery permits a lower server epoch. A delayed event for a
superseded ID never promotes. A later wake or status event can recover a lost
`enrollment_imported` event because all v3 events carry both identities. An
event proves handling of that intent only; it does not prove perpetual server
liveness or rule out a later restore. Do not use elapsed time as proof.

Retire lower sequences only after a higher sequence is confirmed, when the
retained server row rejects those old files. If the server is later restored,
the phone needs a fresh recovery export. V1/v2 events cannot promote a key,
clear unknown intent, or supply missing import identity. A migrated legacy
pending record is unconfirmed with UNKNOWN intent; there is no first-event bind
and no epoch-only confirmation. Preserve any active known key. A fresh v3
logical export may safely reuse that key to establish explicit identity.

The pending logical-intent limit is four, counting superseded entries and
distinct IDs that share a key. Re-rendering is free. Before publishing, check
the cap and durably commit the new intent. A fifth intent refuses visibly and
retains existing records. A user-confirmed forget can free a slot after warning
that old files may still exist. Sequence allocation never rolls back after
publication failure. Backup counter regression fails closed; explicit
registration removal/reprovision is the recovery escape hatch, with no hidden
override that decreases the retained floor.

## Fixtures, manifests, and required implementation evidence

The fixture set contains a keyed v3 enrollment, secret-free response, all-event
examples, the full HMAC vector, invalid encoding/schema examples, and runtime
transition cases for stale sequence, conflicting repeated ID, ambiguous
legacy migration, delayed old same-epoch intent, and lower-epoch recovery.
These fixtures define expected inputs and outcomes; they do not claim the
current runtime passes the transition rules. `K1` and `K2` in the transition
vectors are symbolic key labels, not wire-format `key_id` values.

`copy-manifest.json` in each v2/v3 directory hashes the exact contract source
and fixture bytes. The manifest excludes itself; the full commit pin is kept
separately by consumers. V1 remains untouched and retains its existing frozen
manifest.

Run:

```sh
python3 contracts/encrypted-push/v3/tools/conformance.py
python3 contracts/encrypted-push/v2/tools/conformance.py
python3 contracts/encrypted-push/v1/tools/conformance.py
```

The v3 checker validates strict fixture shapes, the exact key-ID derivation,
the v2/v3 copy manifests, and nonzero invalid examples. It does not prove
server state transitions, transactional queue behavior, Android intent
handling, provider delivery, or real Signal/phone behavior. Before claiming
runtime support, server and phone tests must cover: delayed K1 event after a
new recovery intent; old-file reimport after a newer same-epoch intent; lost
status followed by a later wake; ordinary lower-epoch candidate imported
before a later candidate; cap/refusal/re-render/restart; lower-epoch recovery;
and unknown legacy migration. These are required implementation tests, not
results established by this document.
