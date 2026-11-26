# CollieSocket encrypted push v4

One Signal bridge can wake multiple receivers. The bridge holds the Signal
linked-device ID and password. Each v4 receiver holds its own subscription
endpoint, P-256 push key and auth secret, instance, control key, import identity,
subscription epoch, and queue. Existing encrypted-push v1–v3 and pairing/v1
wire formats remain available. Public discovery advertises v4 support and
accepts no enrollment traffic.

## Enrollment and migration

- `enrollment.schema.json` is the protected bridge import. Use
  `mollysocket enrollment import --file FILE` or `--stdin`, or seal the
  import in a pairing/v1 `pair_bridge` offer. The first import establishes
  the account's v4 primary. The password is the bridge's Signal password.
- `receiver-enrollment.schema.json` is the protected receiver-only import.
  Its `device_id` identifies the bridge's Signal device, and the phone obtains
  that ID and the account ID from the bridge operator. The request omits
  `password`. Use `mollysocket pairing create --intent add_receiver
  --account-id ACCOUNT --host-label LABEL`, followed by a sealed
  `mollysocket pairing submit --stdin`. A valid offer requires an encrypted
  bridge with usable, non-forbidden Signal credentials. Provider rejection
  of a push subscription does not disable the bridge's other routes.
- The offer and the sealed request and response envelopes use pairing/v1's
  exact transcript, limits and cryptography. The host binds an add-receiver
  session to the account and its private bridge generation in SQLite. The
  account and bridge device in the request must still match at commit. A
  changed bridge import generation, removal, or Signal credential rejection
  invalidates outstanding invitations. The offer's JSON has no new fields.
  Submit uses the same endpoint and advertised provider-origin checks for
  both intents, then commits session consumption, enrollment, receipt and
  encrypted confirmation together. A rejected import leaves the session
  available until expiry or cancellation. No public enrollment route exists.
- All requests are strict UTF-8 JSON objects, bounded to 8192 bytes. Reject
  BOM, unknown or duplicate members, null for optional fields, non-integer
  version/epoch/counter tokens and trailing data except JSON whitespace.
  `receiver_id` and `request_id` are canonical lowercase UUIDv4 strings.
  `label`, if supplied, is 1–64 printable ASCII bytes (including space).
  Use the v1 subscription rules, exact event negotiation `[1,2,3,4]` and
  exact capabilities `["wake","test","status"]`. The v4 control key is 32
  random bytes in canonical unpadded base64url. Generate a fresh key for
  each receiver or state-changing private import. The server rejects a key
  used by any earlier v4 import or the current legacy primary of that account.
- A new receiver starts at epoch 1 with a positive import sequence. An
  add-receiver invitation can create a fresh UUID and recover an exact receipt.
  It cannot replace an existing receiver or change bridge credentials.
  Receivers use Signal control to rotate their own subscriptions.
- When upgrading the legacy primary, use a fresh receiver UUID and control
  key, the current legacy epoch plus one, and a positive v4 import sequence.
  Reuse the linked-device ID and password to upgrade without re-linking.
  The legacy primary stops receiving when the v4 primary takes over. Legacy
  receipts remain available, its pending queue is cancelled, and new legacy
  private imports fail for that bridge. Secondary receivers retain their
  queues, keys, credentials, generations, sequences and epochs.
- A private v4 primary update requires the same receiver UUID, exactly the
  next epoch, an increased sequence and a new control key. It can change the
  bridge password. A protected bridge import can replace a revoked primary
  with a previously unused UUID starting at epoch 1. A linked-device ID
  change requires revoking any non-primary v4 receivers first, because
  controls are bound to the old device ID.
- Receipt replay is scoped to the account, receiver and request ID. Reusing
  that ID with different data yields `idempotency_conflict`. Replaying exact
  data returns a historical `receipt.schema.json` response with
  `replayed: true` and changes no receiver state or queue. The receipt's
  status is `accepted` even for historical requests. Confirm the current
  import on the receiver with a matching encrypted event.
- SQLite schema 7 adds receiver, bridge, queue, receipt and pairing-target
  tables in one transaction. Existing rows and leases are preserved during
  migration. Back up the private database before upgrading. Older binaries
  reject the new schema. A v3 primary can stay in place while up to 15 v4
  receivers join. A v4 bridge can have 16 non-revoked receivers. Up to 64
  receiver UUIDs per account, including revocation tombstones, and 1024
  import receipts per receiver are retained until local account removal.

## Signal subscription control

Use raw Signal envelope content beginning with ASCII `COLLIESOCKET-CTRL`.
As in v2, envelope sender metadata and urgency do not authorize control.
Recognized control content never becomes a wake. Version 4 uses AES-256-GCM
with the selected receiver's control key, a fresh cryptographic 12-byte
nonce, a 16-byte tag and the following layout. Offsets are zero-based.

| Offsets | Bytes |
| --- | --- |
| 0–16 | ASCII `COLLIESOCKET-CTRL` |
| 17 | `04` hex |
| 18–33 | Account UUID in network byte order |
| 34–37 | Signal bridge device ID, unsigned big-endian |
| 38–53 | Receiver UUIDv4 in network byte order |
| 54–61 | Target subscription epoch, unsigned big-endian |
| 62–73 | Nonce |
| 74 onward | Ciphertext then its 16-byte tag |

AAD is the exact first 62 bytes. UUID bytes are the decoded hex pairs in
string order. Verify the account and device against the current Signal
bridge and require the target receiver and tag to match. Only then decode
the 1–3072 bytes of plaintext as a strict JSON object conforming to
`control.schema.json`. The endpoint and Web Push keys must pass the same
structural and destination policy checks as enrollment.

The epoch is in 1–9007199254740991. Any authenticated higher epoch replaces
the endpoint, P-256 key and auth secret for that receiver. It retains the
instance, control key and import identity, replaces the receiver generation,
clears older queued work, and enqueues a `subscription_updated` event.
A byte-identical current-epoch replay can recover a missing confirmation
for an active route, at most once every 30 seconds with at most one pending
confirmation. Older epochs, different frames at the current epoch,
wrong keys, obsolete bridge generations and revoked receivers are ignored.
Never reuse a nonce under a control key for different plaintext.

## Encrypted events and operator actions

Each eligible route gets its own event ID and RFC 8291 `aes128gcm` body
using its own subscription. V4 events identify the receiver, instance,
epoch, import ID and event ID. They carry neither a v3 `key_id` nor a
label, account ID, sequence, Signal credentials or message data. Validate
the full event schema, replay and time bounds from v1, and match the
receiver ID, instance, epoch and import ID against local state before
accepting an event. On import or control confirmation, validate these
fields against the pending intent before promoting it. A wake requests the
normal authenticated Signal fetch. Provider 2xx means provider acceptance.

The queue allows up to 16 events per route and 4096 globally. One route's
full queue cannot prevent enqueueing on other routes with capacity. Delivery
permits one outstanding lease per route and runs up to 32 attempts in
parallel. It retains the bounded attempt, expiry, backoff and Retry-After
rules. Provider 404/410 or 401/403 clears only that route's pending work and
marks it stale or provider-rejected, respectively. An authenticated higher
epoch can recover that route. Every send retains address policy, DNS
pinning, no redirects and the encrypted-only transport.

`mollysocket enrollment revoke --account-id ACCOUNT --receiver-id RECEIVER`
erases a receiver's subscription and control key, deletes its queued work
and retains a tombstone. Repeated revocation reports `{"revoked":false}`.
The worker rechecks the claim and receiver generation after resolving the
destination and before authorizing the HTTP attempt. A request already
authorized for dispatch can finish in flight. A stale completion cannot
change the receiver or any other queue. Revocation does not unlink the
Signal bridge or remove other receivers. `connection remove` removes all
local state for the account.

`mollysocket enrollment status` reads all registrations without migrating
or writing the database. Legacy rows have `receiver_id: null` and keep
their existing modes. V4 rows have `mode: "encrypted_v4"`, a receiver ID,
state and an optional label. A revoked row retains its public identity,
instance and last epoch. Account-scoped status returns the same list for
accounts with v4 receivers. Legacy-only account status retains its compact
response. Status reports only endpoint origins for non-revoked routes.
Label and instance are operator-visible metadata and should contain no
secrets. Service and trace logs carry no endpoint tokens, passwords or keys.

## Conformance

Run `python3 contracts/encrypted-push/v4/tools/conformance.py` with the
same dependencies as the v1 checker. The synthetic fixtures include
both enrollment shapes, a receipt, wake and status events, strict JSON
rejections and a deterministic Signal control frame with an independently
checkable AES-256-GCM tag. Runtime tests cover migration, pairing,
fan-out, endpoint rotation, revocation and provider failure isolation.
