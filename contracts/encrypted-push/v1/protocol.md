# Normative enrollment and event behavior

MUST, MUST NOT and MAY describe accepted behavior. JSON is strict UTF-8, with
an object at its root. Reject duplicate property names at every depth, unknown
fields, unexpected null, non-finite numbers, floats in integer fields (including
`1.0`/`1e0`), invalid UTF-8, a byte-order mark, and trailing non-whitespace data.
Field names are case-sensitive. Never echo input, endpoints or secrets in errors.
Protected enrollment input is at most 8192 bytes.

## Private authenticated enrollment

`enrollment.schema.json` contains exactly `enrollment_version`, `request_id`,
`account_id`, `device_id`, `password`, and `subscription`. Subscription fields
are `endpoint`, `p256dh`, confidential `auth`, `instance`,
`subscription_epoch`, `encryption_required`, `supported_event_versions`, and
`capabilities`.

An authorized local operator imports a regular file owned by the effective
service user with mode 0600, or pipes bytes to stdin over a directly authenticated
private channel such as SSH to the service host. Reject symbolic links,
non-regular files, files with group/world permissions, wrong ownership, terminal
stdin, and oversized input. State directory mode is 0700. OS authorization to
that service account/state directory is the initial enrollment authority.
Validate the entire request before atomically storing connection credentials,
subscription, epoch, acceptance and request-id record. Import performs no Signal
or provider request; DNS policy validation is separate from sending credentials.

**There is no v1 HTTP enrollment route.** Credentials, auth secrets and receiver
key establishment MUST NOT traverse an untrusted TLS-terminating edge, even if
it re-encrypts the backend hop. Public discovery carries no enrollment secrets.
A provider callback, VAPID token, or successful push does not authorize
enrollment. A future HTTP/pairing design needs separate review and versioning.

`password` is an existing linked-device credential, not a Signal decryption key.
Imports neither create nor unlink Signal devices. An accepted receipt means
durable local acceptance, not Signal credential acceptance or device delivery.

### Exact field validation

- `enrollment_version` is integer 1. `supported_event_versions` is exactly `[1]`;
  every other list fails without fallback.
- `capabilities` is exactly `["wake","test","status"]`, in that order. Acceptance
  is explicit and cannot be inferred from an endpoint or provider response.
- `encryption_required` is boolean `true`. Missing/incomplete keys never select
  plaintext or legacy mode through this schema.
- `request_id` and `event_id` are canonical lowercase UUIDv4 strings.
  `account_id` is a canonical lowercase UUID string. No surrounding whitespace.
- `device_id` is integer 2..2147483647. `password` is 16..256 printable ASCII
  bytes (0x20..0x7e), with no control characters.
- `instance` is 1..128 ASCII characters from `[A-Za-z0-9._:-]`. The connector's
  existing `default` value is valid. The server does not invent/rewrite it.
- `subscription_epoch` is integer 1..9007199254740991. V1 has one active
  subscription per account.
- `p256dh` is canonical unpadded base64url decoding to 65 bytes: prefix 0x04
  and a valid, non-infinite P-256 point. `auth` is canonical unpadded base64url
  decoding to exactly 16 bytes. `auth` stays confidential despite the connector
  class name `PublicKeySet`.
- `endpoint` is an absolute HTTPS URL, at most 2048 ASCII bytes, with a host,
  no whitespace/control characters, no backslash, no userinfo (including an
  empty userinfo `@`), no port 0, and no fragment delimiter
  (including a bare trailing `#`). An HTTP endpoint is accepted only if its
  exact scheme/host/effective-port origin is explicitly allowed in
  `allowed_endpoints`. This supports deliberately authorized private providers
  and synthetic test infrastructure. `*` authorizes neither HTTP nor private
  addresses. Paths/query strings are secret and are not an allowlist boundary.
- Explicit `allowed_endpoints` entries are origins only: an empty or root `/`
  path, no query delimiter (even an empty `?`), and the same scheme, host,
  port, userinfo, fragment, backslash and control-character validation as above.
  Invalid or non-origin entries authorize nothing; other valid entries remain
  effective. An endpoint itself may contain a path and query.
- Account allowlists and the existing destination/address validation still
  apply. Re-resolve and validate addresses on every send; an enrollment-time
  lookup is insufficient. Never follow redirects. Ignore implicit transport
  proxy configuration that could bypass the allowed-address resolver.

### Idempotency, rotation and interrupted imports

Initial enrollment requires epoch 1. Store a digest of the validated request
with `(account_id, request_id)`; request-id idempotency is scoped to the account,
so reuse of a UUID by independent accounts does not conflict. For digest
equality, serialize validated fields recursively
with object keys sorted, no insignificant whitespace, UTF-8, and unchanged
array order/string values; hash those bytes with SHA-256. Do not store/log this
digest as a public identifier. An identical request ID/digest returns the
original receipt. The same ID with different data fails `idempotency_conflict`.

An identical active subscription/credential tuple under a new request ID at the
same epoch returns `unchanged`, without resetting retries or replay state.
Same-data refresh at exactly the next epoch is allowed. Any endpoint/key/auth,
instance or credential change requires exactly the previous epoch plus one,
including same-URL rotation. Lower/skipped epochs or changed data at the current
epoch fail `epoch_conflict`.

Stale/provider-rejected subscriptions require a fresh private import at the
next epoch to reactivate; old idempotent requests cannot reactivate them.
Subscription/credential changes and deletion of old queued events form one
transaction. Interruption exposes either the old complete registration or the
new complete registration. A provider's delayed old ciphertext may still arrive:
the consumer rejects wrong instance/epoch or failed decryption. Rotation never
invokes a Signal unlink/remove-device API.

Keep request-id records for the account registration lifetime, bounded to
1024 accepted request IDs per account and 4096 registrations globally. Exhaustion
fails `capacity_exceeded` before mutation. Explicit local removal clears local
records and starts a new local enrollment lifecycle; it does not unlink a Signal
device. A backup restore requires fresh private enrollment before sending.

## Encrypted event schema and acceptance

Every event has `version`, `event_id`, `instance`, `subscription_epoch`, `kind`,
`issued_at`, and `expires_at`. `version` is integer 1. `kind` is `wake`, `test`,
or `status`. `code` exists only for status and is `connection_conflict` or
`connection_unavailable`. Missing status code and an explicit null code are
invalid. Unknown versions/kinds/fields/codes produce no effect. There is no
arbitrary data field, account ID, credential, message preview or rich payload.

Times are integer Unix seconds in the JSON-safe integer range. The sender sets
`expires_at = issued_at + 300`. Consumers permit lifetimes 1..300 seconds,
`issued_at <= now + 60`, and `expires_at > now`. They use their local wall clock,
not the sender's issued time, to advance replay time. Uncertain time fails closed.

Before any effect, an unlocked receiver requires successful connector
decryption, valid schema/semantics, matching active durable instance/epoch,
valid time and no duplicate ID. It atomically commits
`(instance, subscription_epoch, event_id, expires_at)` before scheduling work.
A duplicate remains a no-op across process restarts. Retain IDs through
`expires_at + 60`, with at most 512 retained IDs per active subscription,
including the retention grace period. If all 512 are retained, drop a new event;
never evict a live record to accept one.

Persist a receiver `clock_high_water` integer independently of the active epoch;
initialize it from the local clock during private enrollment acceptance. Before
accepting an event or pruning replay records, require `now >= clock_high_water`.
Otherwise reject without effects, pruning or replay mutation. In the same durable
transaction as acceptance/pruning, advance it to `now`. Do not lower it across
restart, key rotation or subscription changes. Prune only records satisfying
`expires_at + 60 <= now` after that check. This prevents a wall-clock rollback
from reviving an ID already removed after expiry. Restoration of old persistent
state is a separate recovery event requiring fresh keys/instance and enrollment.

- `wake` schedules the existing authenticated Signal fetch.
- `test` records and displays only a generic test success when unlocked.
- `status` records only the enumerated generic condition. It cannot authorize
  credential replacement, unlinking, new server trust or rich message handling.

**Initial lock gate:** while `KeyCachingService.isLocked()` is true, including
its locking transition, drop all v1 events with no SignalStore access, fetch,
notification, plaintext buffering or replay-state/clock mutation. Connector
decryption may already have occurred. Recheck and exclude lock transitions
around state commit/effect scheduling; observing the lock means no application
effect. After unlock, normal authenticated Signal recovery retrieves missed
work. V1 deliberately defers the old locked generic urgent notification UX.
Adding lock-safe notification metadata requires a later reviewed version.

### Binary wire profile

Serialize event JSON to at most 3072 UTF-8 bytes. Append ASCII spaces inside the
plaintext until it is 3993 bytes, then encrypt. The actual RFC 8188 body is
4096 bytes: salt 16, network-order `rs=4096` 4, `idlen=65` 1, uncompressed sender
point 65, and one AES-128-GCM ciphertext record. Standard final delimiter 0x02
and a 16-byte tag complete the record. Fresh salt and ephemeral sender key are
required on every attempt; the event ID/JSON remains unchanged for retries.
No custom version byte is added to the RFC frame.

Use `Content-Type: application/octet-stream`, `Content-Encoding: aes128gcm`,
`Urgency: normal`, and `TTL` equal to the remaining whole lifetime in seconds,
clamped to 1..300. Never send an expired event. VAPID Authorization is separate.
Do not set Topic or put event type/IDs, account data, keys, credentials or status
in clear headers. Do not log provider response bodies or secret URLs.

### Durable queue and provider recovery

Bound queues to 16 live events per account and 4096 globally; purge expired
events first. Full queues fail `queue_full`. Retain the server's event-ID ledger
until expiry, bounded to 8192 entries globally; its exhaustion also fails
`queue_full`. An identical event-ID/JSON enqueue is a no-op; reuse of an event
ID with different data fails `invalid_event`. IDs cannot change on retries.

At most four attempts per event. Claim with a 30-second durable lease and
increment the attempt count before network I/O. Network timeout is 10 seconds.
Abandoned leases can be retried after 30 seconds within attempt/expiry limits.
For network errors, HTTP 408, 429 and 5xx, retry after 5, 30 and 120 seconds.
An integer Retry-After may increase delay up to 120 seconds; ignore non-integer
values. Never extend event expiry.

A 2xx removes the queue item and means provider accepted, not device delivery.
Redirects and other 4xx discard that event. HTTP 404/410 additionally mark the
subscription `stale`; 401/403 mark `provider_rejected`. Both stop future sends
and purge pending events until private next-epoch import. Neither unlinks a
Signal device nor marks its Signal credential invalid solely from provider HTTP.

## Errors and compatibility

Machine errors are exactly `{"error":"CODE"}` without raw context. Successful
CLI JSON exits zero; failure exits nonzero. HTTP enrollment mappings are absent.

| Codes | Meaning/action |
| --- | --- |
| `invalid_json` | Invalid UTF-8/JSON, duplicate fields or disallowed JSON encoding |
| `invalid_enrollment`, `invalid_event` | Invalid structure, unknown fields or semantic data |
| `invalid_key`, `invalid_endpoint` | Invalid key material or forbidden destination |
| `unsupported_version`, `capability_required`, `encryption_required` | Explicit v1 negotiation failed; never downgrade |
| `epoch_conflict`, `idempotency_conflict` | Repair local enrollment request; do not retry different data under the same ID |
| `not_found`, `subscription_inactive` | No active local subscription; private enrollment/recovery needed |
| `queue_full`, `capacity_exceeded` | Bounded storage exhausted; no partial mutation |
| `unsafe_file`, `input_too_large`, `state_unavailable` | Protected input/state unavailable or invalid; fix local conditions |
| `legacy_disabled` | Explicit bounded legacy opt-in absent or expired |

When several fields are invalid, consumers must accept any applicable fixed
error code above; error precedence carries no protocol meaning. Error messages
must never contain offending values. Same-ID conflict checks take precedence
over changing any existing enrollment.

Retain useful upstream binary/config/CLI names. Legacy wake-only sending needs
explicit `legacy_wake_until` Unix seconds, at most 24 hours ahead at startup;
the fixed deadline also expires in a continuously running process. Its only
payload is `{"urgent":true}` with JSON content type and no aes128gcm header.
It never receives test/status/richer content. Legacy paths cannot overwrite or
downgrade encrypted accounts. Legacy HTTP registration is disabled; protected
local import is the only new-registration authority. Existing configuration and
operator command names remain recognized with this explicit gate.

Standards: [RFC 8291](https://www.rfc-editor.org/rfc/rfc8291),
[RFC 8188](https://www.rfc-editor.org/rfc/rfc8188),
[RFC 8030](https://www.rfc-editor.org/rfc/rfc8030).
