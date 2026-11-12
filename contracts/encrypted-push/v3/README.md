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
NOT reset the v3 floor. The only no-mutation legacy operation allowed after a
v3 floor exists is an exact replay of an already-recorded v1/v2 request with
the same `request_id` and request digest. It returns the saved receipt and
changes no row, floor, generation, queue, or receipt record. A fresh legacy
request is rejected with the fixed `epoch_conflict` error even if its
subscription appears state-identical. The error contains no sequence, key, or
row values. Removing and reprovisioning the registration is the explicit
lifecycle reset. V1/v2 events never promote a pending v3 key or invent an
`import_id`.

The incoming `account_id` selects the registration row before receipt,
sequence, epoch, adoption, or key-freshness comparisons. Those comparisons are
against that selected account only. The existing receipt table is account
scoped: `encrypted_enrollment_requests` has primary key
`(account_id, request_id)`, and receipt lookup filters on both columns. A
`request_id` recorded for account A is unseen in account B unless B has its
own matching receipt. With no B row, only epoch 1 can create B; a higher epoch
returns `epoch_conflict` without changing either account or any receipt.

The server does not impose cross-account control-key uniqueness. Trusted
provisioning must generate a fresh control key for every new registration.
Account-bound key identity and the existing control-frame authenticated data
bind a key operation to its account/device context, but they do not make a
reused secret cryptographically independent: compromise of a key shared by
two accounts affects both.

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
2. Receipt lookup is scoped to the selected `account_id` and `request_id`.
   A previously recorded request in that scope with the same request digest
   is a replay; it does not apply a new import. A request ID already recorded
   in that scope with a different digest is rejected with fixed
   `idempotency_conflict` and no mutation. A v3 replay is current only when
   epoch, key, full registration and subscription context, `import_id`,
   `import_seq`, and durable generation still match. A current replay changes
   none of those values. An exact recorded request whose row is no longer
   current returns its saved historical receipt with `replayed: true`; it
   does not retry status delivery or confirm current state. An unseen stale
   request is rejected and cannot bind backward.
3. A sequence greater than the retained floor may import exactly the next
   subscription epoch. A state-changing next-epoch import follows the v2
   requirement to use a fresh control key.
4. A greater sequence may also reaffirm the current epoch only when the row is
   active, the key and all subscription and registration context are identical,
   and the request ID is fresh. This changes intent metadata only: rotate the
   durable generation, invalidate queued work from older generations, and
   atomically queue a new `status/enrollment_imported` event for the new
   `import_id`.
5. Same-epoch reaffirmation with a different key is rejected. A repeated
   `request_id` with conflicting parameters is rejected. Lower or equal
   sequence with any non-identical state is rejected without mutation.

The active sequence is a floor, not an inference from UUID ordering. An unseen
old request ID cannot rebind a row when its sequence is stale. Any rejected
adoption, downgrade, conflicting-ID, or stale-sequence request changes nothing:
not the row, floor, generation, queue, or receipt ledger. A later import must
use a sequence above the retained floor. Queue or persistence failure during a
new import leaves prior state unchanged and returns no accepted receipt.
Status enqueue and generation update commit in the same transaction; no
provider request is needed before commit. A provider 2xx means the provider
accepted the message, not that a device received it.

V3 receipts include a boolean `replayed`. A newly applied request returns
`status: "accepted", replayed: false`. An exact replay returns
`status: "unchanged", replayed: true` only when epoch, key, full context,
`import_id`, `import_seq`, and durable generation still match the current row.
A previously recorded request whose row is no longer current returns its saved
request ID, epoch, and original status with `replayed: true`; this historical
receipt does not assert that the intent is current or active. The response
schema permits `accepted/replayed: true` for that historical case and requires
`unchanged/replayed: true` for exact current idempotence. Neither form confirms
registration state: only a matching v3 event with persisted `import_id` and
`key_id` can confirm an intent. V1/v2 receipts remain byte-for-byte as defined
by their frozen schemas and keep their prior cached-receipt replay behavior; a
historical v1/v2 receipt is not current registration confirmation.

For an exact current v3 replay, outbox recovery is allowed only while the row
is `active` and claimable. If an unexpired claimable
`status/enrollment_imported` for the current epoch and `import_id` is already
queued, retain that one item and do not add a duplicate. Otherwise, enqueue at
most one replacement event for that intent when at least 30 seconds have
elapsed since its last status enqueue (`CONTROL_STATUS_RETRY_SECONDS`). Before
then, do not enqueue. This coalescing or retry may change outbox state only; it
does not change row identity, key, epoch, `import_id`, `import_seq`, durable
generation, or receipt bookkeeping. Every queued item must remain claimable;
never accept an import whose confirmation cannot be claimed. If queue capacity
prevents a retry, return fixed `queue_full` without a partial mutation. If the
row is inactive, do not queue a status retry and do not reactivate the row. A
previously saved receipt may still be returned with `replayed: true`, but it
does not claim current liveness.

### First v3 adoption of a legacy keyed row

A pre-v3 row has `import_seq = NULL` and no v3 `import_id`. If it already has a
control key and `encrypted_subscriptions.state = 'active'`, it may adopt v3 at
the same epoch only when `control_key`, account,
device, password, endpoint, `p256dh`, `auth`, instance, encryption requirement,
and capabilities are unchanged. The only subscription difference is the exact
negotiation change from `[1,2]` to `[1,2,3]`. The v3 request must supply a fresh
UUIDv4 `request_id` and a valid positive `import_seq`; the server records that
sequence as the initial floor and the request ID as the new `import_id`.

Adoption rotates the durable generation, invalidates old queued work, and
atomically queues `status/enrollment_imported` for the same epoch, existing
control key and new import ID. Its receipt is `accepted/replayed: false`,
echoes the new request ID and epoch, and contains no sequence or key identity.
Exact request replay keeps epoch, key/context, import ID, sequence and
generation unchanged and returns `unchanged/replayed: true`. It may use the
active-row outbox retry rule above. Reuse of the request ID with different
parameters returns the fixed one-field error
`{"error":"idempotency_conflict"}` without changing row, queue, generation or
receipt bookkeeping. Rejected adoption and downgrade requests return their
fixed generic error (for example, `{"error":"epoch_conflict"}`) and mutate
nothing, including the receipt ledger.

A legacy unkeyed row cannot use same-epoch adoption because it has no existing
control key to match. It must use the normal exact-next-epoch import with a new
control key. Any other changed state on a legacy keyed row also requires the
exact next epoch and a fresh control key. A `stale` or `provider_rejected` row
cannot use same-epoch adoption or reaffirmation: reject it with fixed
`epoch_conflict` and no mutation, because its queued confirmation cannot be
claimed. Recovery requires the exact-next-epoch import with a fresh control
key, which returns the row to `active`. For the selected legacy row, changing
device, password, endpoint, control key, `p256dh`, `auth`, instance,
encryption requirement or capabilities is not adoption. Supported
event-version negotiation is the sole permitted subscription difference. A
different `account_id` selects a different row and follows its own creation
or transition rules.

This same-account adoption rule does not constrain a different registration.
For example, if legacy account A exists and B is absent, a valid B epoch-1
request with an ID unseen in B creates B and leaves A unchanged. This remains
true if a synthetic request reuses A's control-key bytes: the server has no
cross-account key-uniqueness check. The client still generates a fresh key for
B as normal provisioning hygiene. A request for absent B at epoch greater
than 1 is rejected with `epoch_conflict`.

Errors are one-field, value-redacted responses described by
[`error.schema.json`](error.schema.json). Validation preserves the existing
stable categories: malformed enrollment shape (including boolean values
where integer version elements are required, or a missing required
`capabilities` member) is `invalid_enrollment`; unsupported event-version
negotiation is `unsupported_version`; a present but different capabilities
array is `capability_required`; stale or incompatible row state is
`epoch_conflict`; and a recorded request ID with a different digest in the
selected account is `idempotency_conflict`. Required fields must first
deserialize successfully. After the encryption-required check, supported event
versions are checked before the present capabilities array value. Thus
unsupported negotiation plus changed capabilities returns
`unsupported_version`. A missing required field fails typed decoding as
`invalid_enrollment`, including when the version list would also be
unsupported.

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
The v3 `key_id` input includes the account UUID, and the existing control
frame's authenticated data includes the account UUID and linked-device ID.
These context bindings distinguish accounts; equal control-key bytes still
share compromise risk.

## Phone intent and promotion rules

The phone keeps the current registration instance stable. It distinguishes a
re-render of a saved export from a new logical intent. Re-render reuses the
persisted UUID, sequence, key, target and immutable parameters and consumes no
pending-intent slot. A new logical export allocates and durably commits a UUID
and next sequence before publishing bytes. If a candidate already exists for
that target, the API/UI requires an explicit mode; a second call must not guess
whether it means re-render or new intent. The same epoch reuses its existing
control key and `key_id` only within the same account/device/instance
registration context. A new account or device is a new registration and must
get a fresh control key and intent.

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

When deciding whether an event completes pending work, the phone first looks
up the persisted candidate by exact `import_id`, then verifies its recomputed
`key_id`, epoch and sequence. It MUST NOT choose a candidate by `key_id` alone
or skip a same-key candidate because its `key_id` equals the active key. In
first-v3 adoption the key and epoch intentionally remain the same; the matching
`import_id` binds the new sequence and intent to the already-known key. A v2
event cannot supply that missing identity. Before promotion, the receiver binds
both active v3 state and candidate exports to its current local registration
context: the live SignalStore ACI/device plus current instance. The event has
no `account_id` wire field. Stored export context alone is insufficient after
the active account or device changes.

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

The fixture set contains keyed v3 enrollments, an independent account-selection
pair, secret-free responses, all-event examples, the full HMAC vector, invalid
encoding/schema examples, and runtime transition cases for stale sequence,
conflicting repeated ID, first-v3 adoption, retained-floor legacy
replay/rejection, recorded and unseen old-file reimports, ambiguous legacy
migration, delayed old same-epoch intent, and lower-epoch recovery.
These fixtures define expected inputs and outcomes; they do not claim the
current runtime passes the transition rules. `K1` and `K2` in the transition
vectors are symbolic key labels, not wire-format `key_id` values.

`copy-manifest.json` in each v2/v3 directory hashes the exact contract source
and fixture bytes. `tools/copy_manifest.py` generates both manifests in sorted
path order and excludes the manifest itself, bytecode, cache directories, and
temporary files. The full commit pin is kept separately by consumers. V1
remains untouched and retains its existing frozen manifest.

Regenerate from the repository root with:

```sh
python3 contracts/encrypted-push/v3/tools/copy_manifest.py
```

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
