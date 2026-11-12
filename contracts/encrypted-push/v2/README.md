# CollieSocket enrollment and endpoint control v2

This additive contract lets a phone rotate its encrypted push subscription over
Signal without exposing a CollieSocket HTTP enrollment port. It applies to
`0cwa/colliesocket` and `0cwa/collieim-android`. The
[v1 contract](../v1/README.md) remains frozen. Unless explicitly changed below,
its private-import authorization, strict JSON, destination policy, event
lifetimes, replay/lock rules, RFC 8291 push encryption, queue bounds and fixed
secret-free errors continue to apply.

## Private import and migration

`enrollment.schema.json` defines enrollment version 2. It adds one optional
top-level field, `control_key`: canonical unpadded base64url for exactly 32
cryptographically random bytes generated and durably stored by the phone. The
key is unique to this account and CollieSocket linked-device enrollment and is
carried only in the authenticated private import. An omitted key means the
existing v1 behavior; an explicit `null`, an empty string or a malformed key is
invalid. Enrollment version 1 MUST reject this new field.

| Enrollment | Event negotiation | Selected event version | Signal control |
| --- | --- | --- | --- |
| Version 1, no key | Exactly `[1]` | 1 | Disabled |
| Version 2, no key | Exactly `[1]` | 1 | Disabled |
| Version 2 with key | Exactly `[1,2]` | 2 | Enabled |

Capabilities remain exactly `["wake","test","status"]`. All pushes for a
keyed v2 enrollment use event version 2, including ordinary wake/test/status
events. The receipt reports the import's `enrollment_version` and the selected
event version. A receipt contains no key or endpoint. Initial private import
still requires epoch 1; private changes still require exactly the next epoch.
Moving an existing v1 enrollment to v2 therefore requires a new private import
and the next epoch. Private import may rotate or remove a control key, with a
corresponding event-version negotiation. A state-changing private import clears
the old control replay receipt; an idempotent import retains it. A keyed private
import that changes the Signal password, linked-device ID or instance MUST use
a fresh control key; the server rejects reuse of the current key for those
changes with `invalid_enrollment`. A new enrollment lifecycle, including
removal/reprovisioning or backup recovery, MUST also generate a fresh control
key on the phone. The server cannot
detect reuse of a key from state that has already been deleted. Every keyed
private import that changes state, including an import limited to
endpoint/push keys/auth, MUST use a fresh control key; the server rejects reuse
of the current key for any state-changing import with `invalid_enrollment`. Only
the idempotent import (identical subscription, credentials and key, active
state) may repeat the current key. The reason is that the phone allocates
control epochs above anything it has already built, while a private import must
be exactly the server epoch + 1: a pre-built higher-epoch frame under a reused
key would remain authentic and could roll back the newer private import.
Accepted control frames keep the key, so earlier frames stay obsolete by epoch.

The existing password, account, device, instance, encryption requirement,
capabilities, event negotiation and control key remain private-import-only.
Signal control can change only `endpoint`, `p256dh`, `auth` and the epoch. It
does not create a registration or change the Signal linked-device credential.
Neither a provider response nor an untrusted sender/Signal envelope identifier
authorizes a change.

## Exact control wire format

The bytes below are the **entire `Envelope.content`** for CollieSocket's copy
of a dedicated Signal sync send. They are not ordinary Signal session
ciphertext and are not embedded in a protobuf `Content` or JSON/base64 wrapper.
Integers use unsigned big-endian encoding. UUID bytes are the 16 bytes obtained
by removing the hyphens from the canonical lowercase account UUID and decoding
the remaining hexadecimal digits in order (not a platform-specific GUID layout).

| Byte offsets | Length | Value |
| --- | --- | --- |
| 0–16 | 17 | ASCII `COLLIESOCKET-CTRL`, **no NUL terminator** |
| 17 | 1 | Contract version `0x02` |
| 18–33 | 16 | Account UUID bytes |
| 34–37 | 4 | CollieSocket destination linked-device ID |
| 38–45 | 8 | New `subscription_epoch` |
| 46–57 | 12 | AES-GCM nonce |
| 58 onward | Variable | Ciphertext followed by the 16-byte GCM tag |

Use AES-256-GCM with the imported 32-byte key, a 12-byte nonce, and a full
16-byte authentication tag. **AAD is exactly bytes 0–45**, including magic,
contract version, account, destination device and epoch. The receiver requires
that the header account/device match its current enrollment and version is 2;
it does not choose a different account based on the frame. The epoch must be in
1..9007199254740991. A new update uses a fresh cryptographically random nonce;
never reuse a nonce with different plaintext under the same key. Retries reuse
the entire original blob byte for byte, including nonce, ciphertext and tag.

The decrypted plaintext is strict UTF-8 JSON, at most 3072 bytes, with exactly
the three string fields described by `control.schema.json`:

```json
{"endpoint":"https://push.example.invalid/new","p256dh":"<canonical P-256 public key>","auth":"<canonical 16-byte auth secret>"}
```

Object member order is irrelevant on input. Duplicate members, unknown fields,
nulls, invalid UTF-8, a BOM, trailing non-whitespace data and oversized plaintext
are rejected. `p256dh` and `auth` obey the v1 key rules, including an actual
non-infinite P-256 point. The endpoint obeys the unchanged v1 URL, exact-origin,
DNS/address and redirect rules. The complete frame is at most 3146 bytes
(46-byte header + 12-byte nonce + 3072-byte plaintext + 16-byte tag). Reject
truncated or oversized frames without allocating unbounded decrypted data.

Placing the blob in the Signal send. The phone sends to its own account with
authenticated (not sealed-sender) `PUT /v1/messages/{own ACI}`, a dedicated
request with `urgent=false`, whose `messages` array has one entry per linked
device, each with `type`, `destinationDeviceId`, `destinationRegistrationId` and
`content`. CollieSocket's entry uses `type` 1 (`DOUBLE_RATCHET`, named
`CIPHERTEXT` in older Signal protocol definitions and the project spec; not 3
`PREKEY_MESSAGE` and not 6 sealed sender), `destinationDeviceId` equal to the
enrolled CollieSocket device ID, and `content` equal to the standard padded
base64 (RFC 4648, with `=`) of the frame bytes above, with no second encryption
and no extra padding; CollieSocket never reads the envelope type. The Signal
server accepts an entry only if `destinationRegistrationId` equals the
registration ID of that linked device and otherwise answers 410 (stale
devices). CollieSocket is never told that ID, and the enrollment file does not
carry it: the phone generated it when it created the linked device
(`KeyHelper.generateRegistrationId` in `MollySocketRepository.createDevice`) and
reads it back as the remote registration ID of its Signal session with
CollieSocket's device, exactly as an ordinary send fills this field. That
session is created from the device's pre-key bundle (`GET /v2/keys/{ACI}/{device
ID}`, whose `registrationId` is the value), which the Collie IM link code does
at creation; if the session is missing, fetch the bundle and use its
`registrationId`, and never encrypt anything to that session. Every other linked
device gets an ordinary entry built from its own session: its own registration
ID and a normal Signal ciphertext (type 1, or 3 for a new session) of an
ordinary padded `Content` carrying a harmless sync message. The client omits
devices with no session, so the server's 409 (mismatched devices) lists them.
On 409, archive sessions for extra devices, fetch pre-key bundles for missing
devices and rebuild all entries. On 410, archive the sessions of the stale
devices, refetch their bundles to learn the new registration IDs and rebuild all
entries; if CollieSocket's device was stale, its registration ID changed (the
device was re-linked), so reread it as above and, if the device ID no longer
matches the enrollment, stop and recover through private import. In both retries
CollieSocket's entry keeps `urgent=false`, type 1 and the identical blob; only
its `destinationRegistrationId` may change.

Only successful authenticated decryption establishes control authority.
Envelope source account/device, envelope type, timestamps and `urgent` are not
authentication: anyone who can message the account can deliver arbitrary bytes
to this device. Never log keys, blobs, plaintext, endpoint tokens or auth
secrets. Missing keys and authentication/schema/policy failures have no
subscription or wake effect.

## Receive, commit and acknowledgment

Recognize the 17-byte magic before making any wake decision, independent of the
untrusted urgent flag. A magic-prefixed message is a control candidate even if
its remaining bytes are malformed or have an unsupported version. It MUST NOT
fall back to an ordinary urgent wake after failure. Ordinary content that does
not have this marker retains the existing handling.

Authenticate, validate the complete update and destination policy, and then use
one durable transaction to recheck the current enrollment/key and epoch; replace
the endpoint/key/auth; update the connection's endpoint; mark the subscription
active; discard obsolete queued pushes; record the accepted frame's SHA-256
digest; and enqueue its version-2 `status/subscription_updated` confirmation.
The digest is private durable replay state, not a public identifier. Password,
control key, account, device, instance and negotiation are unchanged. A stale
or provider-rejected subscription may be revived by a **newer authenticated
epoch**. A Signal-forbidden/removed registration is not revived by this path.

Control updates accept any epoch **strictly greater** than the current epoch,
within the JSON-safe bound. This differs from private import's exact-next rule:
the phone can supersede an update that never reached the server. Current-epoch
updates succeed only when their full frame digest is identical to the latest
accepted control frame. Lower epochs, different frames at the current epoch,
or epochs already occupied by a private import are rejected. The comparison
and mutation must be atomic against other control messages and private imports.

An identical current-epoch replay is a subscription no-op: it changes no
credentials, endpoint, keys, epoch or active/stale state and never revives an
inactive subscription. For an active subscription it may coalesce or enqueue a
bounded confirmation so that a lost status push does not leave the phone
retrying forever. There must be at most one live update-confirmation queue item
per account/epoch; retransmission obeys the normal queue and attempt bounds.
After an earlier confirmation leaves the queue, a replay may enqueue another
only when at least 30 seconds have elapsed since the last confirmation enqueue.
This acknowledgment recovery is the only permitted replay effect. Rejected or
forged frames change neither subscription nor acknowledgment state.

Commit accepted state and its confirmation **before acknowledging the Signal
websocket frame**. A persistence/queue-capacity failure leaves the entire old
state intact and leaves the frame unacknowledged so delivery may retry. After
commit, an interrupted acknowledgment is harmless because the replay is
idempotent. Malformed, forged, obsolete or policy-rejected control messages may
be acknowledged and discarded; they must not poison the websocket indefinitely.
No provider network request is needed before the Signal acknowledgment.

Sockets retain the same Signal account/device/password through an endpoint
update. Subsequent wakes and status checks must use the newly committed
subscription, including when the control frame and following message arrive on
the same socket. A callback from an actually replaced private credential tuple
must retain the existing protection against modifying its successor. The server
also assigns a durable random generation to each encrypted enrollment and
replaces it on every state-changing private import, including keyless imports.
The connection manager binds this generation before opening a Signal socket and
includes it in the socket's fingerprint. Control acceptance, ordinary wake and
status enqueue, and Signal-authentication rejection must recheck that captured
generation atomically with their effects. An obsolete socket cannot adopt a new
generation by reading the replacement's key. This remains true when a later
import restores an earlier key or credential tuple. Controls and idempotent
imports retain the generation. It is private local state, not a wire field, and
does not replace the requirement to generate fresh control keys.

Database schema 4 adds this generation state without changing existing
enrollments, import receipts, control replay receipts, queued events or leases.
Migration from schema 3 is atomic and assigns one generation per existing
encrypted enrollment. Before upgrading, stop the service and back up its private
database. Older server binaries reject schema 4; rollback requires restoring the
matching pre-upgrade database together with the older binary. Preserve the latest
database for recovery: restoring a backup discards subsequent local enrollment
and queue changes and may require private import to reconcile the phone's epoch.

## Confirmation event and phone state machine

`event.schema.json` defines event version 2. It preserves all v1 event fields
and bounds and adds `subscription_updated` to the status code enumeration.
This code reports durable acceptance of a control update at the event's
instance and epoch. It conveys no endpoint, account, password or key. The
confirmation is encrypted with the **new** `p256dh`/`auth` and sent to the
**new** endpoint. Provider 2xx means provider acceptance only and must never be
treated by the phone as receipt of this confirmation.

Before sending, the phone durably records the target endpoint/keys/epoch and
the exact encrypted control blob. It uses an epoch greater than all epochs it
has already allocated, including unsent or unconfirmed updates. It sends to its
own Signal account using a dedicated `urgent=false` sync message. For every
recipient device except the registered CollieSocket device, the send contains
a normal encrypted Signal sync message. Only CollieSocket's per-device content
is substituted with this control blob. Never substitute a primary-device copy,
broadcast the blob to other devices, or splice it into an unrelated user send.

The substitution must run when building the initial per-device request and
again whenever a mismatched-device (409) or stale-device (410) retry rebuilds recipients. Preserve the
same CollieSocket ID, exact blob and `urgent=false` flag through that retry;
newly discovered other devices get the ordinary encrypted sync copy. If the
CollieSocket device is absent, retain pending state for recovery rather than
treating a send to the remaining devices as confirmation.

The phone retries the same persisted blob, with bounded/backed-off sending,
until an unlocked authenticated receiver accepts `status/subscription_updated`
for the pending instance and epoch through the new endpoint's subscription.
The normal event time, replay, lock and durable-commit rules still apply. A
Signal send success, websocket acknowledgment, provider 2xx, status from an old
epoch/endpoint or unrelated status does not clear pending state. A subsequent
endpoint rotation may supersede the pending update using a newer epoch and a
fresh nonce/blob; delayed old confirmations cannot clear that newer operation.

A missing confirmation does not always mean lost delivery. An authenticated
update whose endpoint fails the server's destination allow-list or a temporary
DNS lookup is acknowledged to Signal and dropped without a confirmation, so the
phone should treat prolonged silence as possibly a policy rejection, not only
a lost message. Retrying the identical blob later (DNS) or sending a new epoch
with a different endpoint (allow-list) recovers.

## Files and executable checks

| File | Purpose |
| --- | --- |
| `enrollment.schema.json` | Version-2 protected import and conditional event negotiation |
| `response.schema.json` | Secret-free private import receipt |
| `control.schema.json` | Exact AES-GCM plaintext object |
| `event.schema.json` | Version-2 push events and confirmation status |
| `fixtures/` | Public synthetic enrollment and deterministic AES-GCM vector |
| `tools/conformance.py` | Offline schema/semantic and independent AES-GCM checks |

Run from the repository root:

```sh
python3 contracts/encrypted-push/v2/tools/conformance.py
```

The checker uses the same `cryptography` and `jsonschema` requirements as the
v1 checker. Its synthetic vectors establish byte-level interoperability, not
Android acceptance or real Signal delivery. The server integration tests must
exercise a fake Signal websocket, capture/decrypt the new-endpoint status and
next wake, and verify replay, forgery, stale recovery and commit-before-ACK.
Existing v1 conformance and server regression checks remain required.
