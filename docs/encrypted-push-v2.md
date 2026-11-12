# Operating enrollment v2 and endpoint updates

This guide covers the enrollment-v2 implementation on CollieSocket `main`,
introduced by [PR #11](https://github.com/0cwa/colliesocket/pull/11). It extends
the [v1 operator guide](encrypted-push-server-v1.md). The authoritative wire
format, schemas and interoperability vector are in the
[v2 contract](../contracts/encrypted-push/v2/README.md); the frozen v1 contract
continues to govern behavior that v2 does not change.

## What changes

A compatible phone can update its push endpoint, receiver public key (`p256dh`)
and Web Push secret (`auth`) through CollieSocket's existing outgoing Signal
connection. The server needs no public enrollment port. The phone sends a
dedicated, non-urgent message to its own account: only CollieSocket's linked-device
copy contains the authenticated control frame; other devices receive an ordinary
Signal sync message.

The phone generates and durably stores an independent 32-byte control key. Only
the protected private import establishes that key. The account, linked-device ID,
Signal password, receiver instance and event-version negotiation remain
private-import-only values. Destination restrictions and encrypted push delivery
still apply to every update and subsequent push attempt.

## Enroll or migrate

1. Stop the server and concurrent CLI writers. Preserve the exact previous binary
   or image, configuration and a complete protected database backup before the
   new binary first opens state. Follow the ownership, sidecar and backup steps
   in the [v1 migration procedure](encrypted-push-server-v1.md#migration-and-rollback).
2. Run `mollysocket migrate` with the service account and its configuration.
   Current v2 reports `{"schema_version":3}`. Migration preserves existing v1
   subscriptions, queued events and private-import receipts. The schema-2 result
   in the older v1 guide applies to that earlier binary.
3. Export enrollment v2 from a compatible phone. A new enrollment starts at epoch
   1; enabling control on an existing enrollment requires a private import at the
   server's next epoch. A keyed v2 import uses `enrollment_version: 2`, a
   `control_key`, and `supported_event_versions: [1,2]`. The receipt selects event
   version 2. V1 and keyless v2 imports retain version-1 behavior.
4. Import using the protected file or directly authenticated private-channel
   procedure, then start the service. For a file, use mode `0600`:

   ```sh
   mollysocket enrollment import --file /private/path/enrollment-v2.json
   ```

The export contains the Signal password, endpoint, Web Push secret and control
key. Keep it out of URLs, issues, logs and command-line arguments. Every
state-changing keyed private import, even an endpoint-only change, needs a fresh
control key. Only an idempotent import of unchanged active state may reuse the
current key. Restoring or replacing phone state also requires fresh receiver
keys, instance and control key through private enrollment before sending resumes.

Older binaries must use their matching pre-migration backup. Do not lower
SQLite's `user_version` or remove columns to make an old binary open current
state. The alternative proposal in [PR #15](https://github.com/0cwa/colliesocket/pull/15)
also uses schema number 3 but defines a different database layout and wire
protocol. It is not an interchangeable binary or a supported migration from
current main.

## Confirmation, retries and a second endpoint change

Before sending, the phone persists the new subscription, its epoch and the exact
encrypted control frame. The server authenticates the frame, validates the
destination and commits the subscription and encrypted confirmation together,
before acknowledging Signal. The next wake on that socket uses the new
subscription.

The phone finishes the change only when its unlocked, authenticated receiver
accepts a version-2 `status` event with code `subscription_updated`, matching the
pending instance and epoch, through the new subscription. A successful Signal
send or provider HTTP 2xx does not establish phone receipt. Until confirmation,
the phone retries the persisted frame byte for byte with bounded backoff.

If the endpoint changes again before confirmation, the phone can supersede the
pending update. It allocates an epoch greater than every epoch it has already
allocated, including unsent or unconfirmed operations, and creates a fresh
nonce/frame. The server accepts any authenticated control epoch strictly greater
than its current epoch. A delayed confirmation for the earlier operation cannot
complete the newer pending update. Private imports still require exactly the
next server epoch and a fresh control key when state changes.

An exact current-epoch retry does not change subscription data or reactivate
inactive state. For an active subscription, it can recover a lost confirmation:
there is at most one live confirmation per account/epoch, and replacement
confirmations are limited to one enqueue per 30 seconds. Conflicting same-epoch,
older, malformed and forged frames have no subscription or wake effect.

A newer authenticated update can recover a stale or provider-rejected
subscription. Signal credential rejection is separate and still requires
private credential recovery. If confirmation stays missing, check the server's
destination policy and DNS as well as delivery: a rejected destination produces
no confirmation. An identical retry after temporary DNS recovery or a newer
update to an allowed endpoint can recover without an inbound enrollment port.

## Verification and scope

Run the checks in `AGENTS.md` and the v2 conformance check:

```sh
python3 contracts/encrypted-push/v2/tools/conformance.py
```

The server tests include a loopback Signal websocket and HTTP push provider.
They verify durable state before ACK, status and next-wake decryption at the new
endpoint, forged and replayed frames, skipped-epoch stale recovery, and rollback
without ACK when persistence fails. These synthetic checks do not establish
real Signal delivery, physical Android receipt or deployment acceptance.

This version retains one active push subscription per account on a server.
Independent receivers for multiple phones require a separate versioned design.
