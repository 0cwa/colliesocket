# Operating CollieSocket encrypted push

This guide covers common server operations and v1 private enrollment. Use the
[v2 operator guide](encrypted-push-v2.md) for Signal endpoint updates and the
[v3 contract](../contracts/encrypted-push/v3/README.md) for ordered private-import
intent and confirmation. The current server supports all three versions;
database migration preserves each enrollment's negotiated event version.

The frozen [v1 protocol](../contracts/encrypted-push/v1/protocol.md),
[runtime contract](../contracts/encrypted-push/v1/runtime.md), and
[schemas and fixtures](../contracts/encrypted-push/v1/README.md) remain the
authoritative v1 interfaces. Later behavior uses separately versioned contracts.

## What the server does

V1 sends `wake`, `test`, and generic `status` events using the frozen RFC 8291
`aes128gcm` format. HTTP POST, optional VAPID authorization, and payload
encryption remain separate. No Topic header or clear event/account metadata is
added. A provider's 2xx response records provider acceptance; it does not prove
device receipt, decryption, or application work.

V1 carries no message previews, sender/conversation identifiers, Signal message
bodies, or new Signal decryption keys. Richer content has no enabling flag.
Receiver and deployment acceptance require their own evidence; local sender
checks establish only the behavior they exercise.

## Prepare an isolated local check

Use the selected source commit and the Rust toolchain pinned in
[`rust-toolchain.toml`](../rust-toolchain.toml). From the repository root:

```sh
cargo build --locked
cargo test --locked
python3 -m pip install -r contracts/encrypted-push/v1/tools/requirements.txt
python3 contracts/encrypted-push/v1/tools/conformance.py
sh crates/colliesocket-push/tools/conformance.sh
python3 tests/server_cli.py
```

[`tests/server_cli.py`](../tests/server_cli.py) creates protected temporary state
and a synthetic loopback provider, invokes the real CLI/worker with
`push_only=true`, and independently decrypts captured bodies with the
Python/OpenSSL checker. Its credentials and receiver keys are public synthetic
test material. Do not reuse them for a real subscription. The sender's
[conformance tool](../crates/colliesocket-push/tools/conformance.sh) records
published-vector and independent-check evidence; a same-library roundtrip is
not independent interoperability evidence.

For manual operator work, run as the service account and set `umask 077` before
creating files. A configuration for isolated checks should use a dedicated
0700 state directory, `push_only=true`, `webserver=false`, and
`legacy_wake_until=0`. Set `allowed_uuids` to the selected synthetic account and
`allowed_endpoints` to the synthetic provider's exact origin. The automated CLI
check supplies this setup without requiring a public provider. Configuration
names and precedence are implemented in [`src/config.rs`](../src/config.rs).

### Fake Signal websocket

[`tests/signal_e2e.py`](../tests/signal_e2e.py) runs the real server with
`push_only=false` against a local TLS websocket and push provider. It checks
Signal envelope acknowledgements and independently decrypts the resulting pushes.
The test creates protected state, synthetic enrollment and a temporary CA.

```sh
cargo test --locked --features test-signal
cargo build --locked --features test-signal
python3 tests/signal_e2e.py --binary target/debug/mollysocket
CARGO_PROFILE_RELEASE_DEBUG_ASSERTIONS=true cargo build --locked --release --all-features
python3 tests/check_signal_overrides_absent.py --binary target/release/mollysocket
```

Only development-profile builds with `test-signal` and debug assertions accept
the paired loopback `test_signal_url` and protected `test_signal_ca` settings.
Normal debug and all release-profile builds exclude those overrides. The
[absence checker](../tests/check_signal_overrides_absent.py) verifies this boundary;
[`src/config.rs`](../src/config.rs) defines the exact restrictions.

## Configure state and destinations

The image interface uses UID/GID `10001:10001`, state directory
`/var/lib/colliesocket` with mode 0700, and
`/var/lib/colliesocket/mollysocket.db` with mode 0600. Config and optional VAPID
key files belong to the service account, use mode 0600, and are mounted read-only
under `/run/secrets/colliesocket`. Protect backups and SQLite sidecars as secrets
too. Back up and restore the VAPID key together with the database, never on
its own: the phone treats a known key as a server that still holds its
registration (see the [README](../README.md#one-key-per-server-and-a-new-key-with-a-new-database)). The store rejects unsafe ownership, permissions, symlinks, and hard links;
it does not silently widen permissions or downgrade a future schema. See
[`src/push_store.rs`](../src/push_store.rs) and the
[state and migration contract](../contracts/encrypted-push/v1/runtime.md#state-secret-permissions-and-migrations).

Existing `mollysocket`, `-c/--config`, and `MOLLY_` configuration names remain.
Environment fields override config-file fields. Prefer `vapid_key_file` when a
provider requires VAPID; it is unrelated to the receiver's confidential `auth`
secret and P-256 key. Inspect configurations without dumping secret values.
The project name is CollieSocket; the retained binary name is intentional
upstream compatibility, not a second protocol.

Logging controls apply only to the server's `mollysocket` namespace. Plain
`RUST_LOG=info`/`debug`/`trace`, application module filters such as
`mollysocket::push=debug`, and `-v`/`-vv`/`-vvv` remain available. Foreign module
selectors and regex filters are ignored without echoing them. Dependency
logging stays disabled even when a more-specific trace selector is supplied,
because transport diagnostics can expose credentials or endpoint tokens.

`allowed_endpoints` entries must be origins: scheme, host, and effective port,
with an empty or root path and no query, fragment, or userinfo. Invalid entries
authorize nothing. Endpoint paths and queries remain confidential subscription
data; they are not an allowlist boundary. HTTPS public destinations may use
`*`; HTTP or private addresses require an explicit origin allowance. A wildcard
does not grant those exceptions. Send-time resolution filters and pins public
addresses, redirects are disabled, and implicit proxy environment settings
cannot bypass those checks. See [`src/config.rs`](../src/config.rs) and
[`src/utils/post_allowed.rs`](../src/utils/post_allowed.rs).

## Import through a private authenticated channel

The examples use an installed executable named `mollysocket`. For a
local debug build, invoke `./target/debug/mollysocket` instead; building with
Cargo does not install the executable onto PATH.

Obtain the subscription tuple from the receiver and the existing linked-device
credential through the approved private provisioning flow. The receiver owns
its private key. Neither a provider response nor a VAPID token establishes
enrollment trust. Do not send enrollment credentials through a public HTTP
endpoint, pairing page, reverse proxy, or TLS-terminating edge. V1 has no HTTP
registration route. Public discovery does not carry a registration QR or key
material. See [`src/enrollment.rs`](../src/enrollment.rs) and
[`src/server/web.rs`](../src/server/web.rs).

The protected v1 JSON export must match the frozen
[`enrollment.schema.json`](../contracts/encrypted-push/v1/enrollment.schema.json).
A new local registration starts at epoch 1. Use the receiver's export rather than
editing credentials, keys or negotiated versions by hand.

Unknown fields, duplicate property names, unexpected nulls, invalid UTF-8,
floating-point spellings in integer fields, malformed keys, and inputs over
8192 bytes are rejected. Use the protected file option for a local file. The
following commands refer to files already provisioned for the service account;
they do not create or approve an enrollment:

```sh
collie_config=/run/secrets/colliesocket/config.toml
collie_enrollment=/run/secrets/colliesocket/enrollment.json
mollysocket -c "$collie_config" enrollment import --file "$collie_enrollment"
```

Alternatively, feed stdin from a directly authenticated private channel or an
already authorized local process. Stdin must not be a terminal. Its bytes still
undergo size, JSON, key, and semantic checks; stdin itself does not authenticate
the remote source. Do not place passwords or auth secrets in argv, chat, logs,
or shell command history. A local redirection example is:

```sh
mollysocket -c "$collie_config" enrollment import --stdin < "$collie_enrollment"
```

Success emits the exact [receipt schema](../contracts/encrypted-push/v1/response.schema.json)
and means the registration was durably accepted locally. Import sends no Signal
or push-provider request. Destination policy may perform DNS validation. If the
receipt was lost, retry the identical request: its account-scoped request ID
returns the original receipt without reactivation or another DNS requirement.
Reusing that ID with different data returns `idempotency_conflict`. See
[`src/enrollment.rs`](../src/enrollment.rs) and
[`src/push_store.rs`](../src/push_store.rs).

## Queue an encrypted test and inspect local state

Use the account ID from the privately provisioned request as the local operator
selector. This example reads only that selector into a shell variable:

```sh
collie_account_id=$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["account_id"])' "$collie_enrollment")
mollysocket -c "$collie_config" enrollment status "$collie_account_id"
mollysocket -c "$collie_config" push test "$collie_account_id"
mollysocket -c "$collie_config" push drain --once
```

The test command returns `{event_id,queued:true}`. It uses the same encrypted
profile as wake/status events. `push drain --once` handles at most one due event;
it may find no work if the running worker already claimed it. The long-running
`server` command drains the outbox on a one-second polling interval.
`connection ping` also queues an encrypted test for an enrolled account.
Local state `active` means the subscription is eligible for attempts, not that
Signal credentials or device delivery have been verified. See
[`src/cli/push.rs`](../src/cli/push.rs),
[`src/cli/connection.rs`](../src/cli/connection.rs), and
[`src/push.rs`](../src/push.rs).

Run `mollysocket -c "$collie_config" ready` from the same network namespace as
the service. Readiness binds only `127.0.0.1:ready_port` and checks the local
worker heartbeat and database/migration availability. Do not expose it through
a public port mapping or reverse proxy. A successful readiness check does not
test Signal, Android, the distributor, or delivery. See
[`src/server/ready.rs`](../src/server/ready.rs).

## Rotation, stale endpoints, and bounded recovery

For a v1 enrollment, an endpoint, P-256 key, auth secret, instance, or credential
change requires a new request ID and exactly the current epoch plus one. This
includes same-URL key rotation. Obtain the new tuple from the receiver's durable enrollment flow;
do not arbitrarily choose or skip epochs. The store changes credentials,
subscription, and pending-event state in one transaction. Late old ciphertext
can still arrive and must fail the receiver's key/instance/epoch checks. Signal
workers poll private registration updates every five seconds; database
contention can delay application. See
[`src/push_store.rs`](../src/push_store.rs) and
[`src/server/connections.rs`](../src/server/connections.rs).

| Observation | Operator action |
| --- | --- |
| Provider 2xx | Treat as provider acceptance only; obtain device-side evidence separately |
| Provider 404/410; state `stale` | Obtain a current receiver subscription and import it privately at the next epoch |
| Provider 401/403; state `provider_rejected` | Resolve provider authorization/configuration and perform the private next-epoch recovery import |
| `epoch_conflict` | Compare the durable receiver/server state and prepare the exact next-epoch request; do not edit SQLite or jump epochs |
| `idempotency_conflict` | Recover the original request or use a new request ID for a genuinely new operation |
| `queue_full` | Allow bounded dispatch/expiry to free capacity; do not add unbounded queues or change event IDs on retry |
| `capacity_exceeded` | Review the registration/request-history bound; do not silently evict lifetime idempotency records |
| Signal credentials rejected | Verify the existing linked-device credentials privately; key-only rotation does not clear that independent condition |

Stale/provider-rejected recovery requires next-epoch acceptance even if the URL
is unchanged. Replaying an old accepted request never reactivates it. Only an
authenticated next-epoch change to the Signal device/password clears a local
Signal-forbidden flag; a key-only change preserves that flag. Provider errors
cannot set it or unlink a device. Explicit `connection remove` deletes local
registration, receipt, and queue state without calling a Signal unlink API.
Use removal only as an intentional lifecycle operation, not routine retry.
See [`src/push_store.rs`](../src/push_store.rs) and [`src/db.rs`](../src/db.rs).

Queue capacity, event lifetime, attempts and retry timing are bounded by the
[frozen queue and recovery rules](../contracts/encrypted-push/v1/protocol.md#durable-queue-and-provider-recovery).
These limits can deliberately drop work during outages. The receiver recovers
through its normal authenticated Signal fetch.

## Migration and rollback

The current store uses **schema 5**, defined by
[`SCHEMA_VERSION` in `src/push_store.rs`](../src/push_store.rs). Migration preserves
existing connections and v1/v2 enrollments; it does not negotiate v3 or enable
Signal control for an unkeyed enrollment. Legacy wake sending remains disabled
unless explicitly enabled for a bounded period.

Server startup and CLI commands can apply migrations when opening state.
Complete the backup before the new binary first opens an existing database:

1. Stop the server and any concurrent CLI drain/import processes. Confirm they
   have exited before handling state files.
2. Retain the exact old executable/image reference, config, ownership, and a
   complete private database backup. Use SQLite's backup API or a cleanly
   stopped database. Do not copy only the main file from an active WAL database.
3. Verify service ownership, parent mode 0700, and DB/sidecar mode 0600. Existing
   unsafe paths fail closed; migration is not a permission-repair command.
4. Run the selected binary's `migrate` command under the service account.
   Check the successful `{"schema_version":5}` response, then private readiness
   and the selected revision's synthetic smoke checks before considering real use.

The implementation rejects future schema versions and rolls back interrupted
transactions. It offers no destructive down migration. Rollback is an offline
operation: stop all writers, quarantine the failed upgrade state privately,
and restore the previous binary **and its matching pre-migration backup**.
Never let the old binary open the upgraded live DB. Do not treat changing
`user_version` or dropping tables as rollback. These requirements come from
[`src/push_store.rs`](../src/push_store.rs) and the
[frozen rollback rules](../contracts/encrypted-push/v1/runtime.md#state-secret-permissions-and-migrations).

A restore can revive old epochs, request receipts, queued events, or replay
clocks. Keep affected sends disabled. Before resuming encrypted sends, privately
establish fresh receiver keys/auth and a fresh instance, then follow the
restored store's valid enrollment lifecycle: epoch 1 only for a new local
registration, otherwise exactly its next epoch. For keyed enrollments, these
state-changing imports also require a fresh control key; v3 recovery must follow
its retained import-sequence rules. Coordinate receiver acceptance with the
server; do not reuse an old receipt as recovery evidence. An older binary that
cannot enforce v1 must not resume these subscriptions in plaintext.

## Legacy compatibility

Legacy wake mode is explicit and expires at a fixed `legacy_wake_until` deadline
no more than 24 hours ahead at startup. It sends only `{"urgent":true}` with
JSON content type. It cannot carry test/status/richer data or overwrite an
encrypted registration. An encrypted worker never falls back after removal or
rotation. The HTTP-registration route and URL QR flow remain disabled. See
[`src/cli/qrcode.rs`](../src/cli/qrcode.rs),
[`src/ws/signalwebsocket.rs`](../src/ws/signalwebsocket.rs), and the
[compatibility policy](../contracts/encrypted-push/v1/protocol.md#errors-and-compatibility).

For pinned image builds, runtime permissions and packaging checks, use the
[image guide](IMAGE.md). Record actual test and image results in the PR or release
evidence for the exact source revision.
