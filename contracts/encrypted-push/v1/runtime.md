# CollieSocket v1 runtime interface

This fixed interface lets consumers implement before the full server exists.
Candidate manifests separately record implemented commands, tests and gaps.

## Executable and configuration

CollieSocket derives from MollySocket with upstream history/AGPL attribution
retained. Cargo package and executable remain `mollysocket`; the image provides
a `colliesocket` alias. Existing `server`, `connection`, `vapid`, `test`, `qrcode`,
`-c/--config` and `-v` names remain. No engineering repository is renamed.

Config-file search order is CLI path, `MOLLY_CONF`, XDG
`mollysocket/config.toml`, local `mollysocket.toml`, then
`/etc/mollysocket/config.toml`. `MOLLY_` environment fields override file fields.
Retain `host`, `port`, `webserver`, `vapid_privkey`, `vapid_key_file`, `signal_env`,
`allowed_endpoints`, `allowed_uuids`, and `db`. Use protected `vapid_key_file`;
never pass enrollment credentials as argv or publish environment/config dumps.
Any configuration debug output must redact secrets and secret endpoint data.

| Field / environment | Default | Fixed meaning |
| --- | --- | --- |
| `legacy_wake_until` / `MOLLY_LEGACY_WAKE_UNTIL` | 0 | Fixed Unix deadline, at most 24h ahead at process startup |
| `push_only` / `MOLLY_PUSH_ONLY` | false | Queue/readiness without Signal network connections |
| `ready_port` / `MOLLY_READY_PORT` | 8021 | Readiness port, always bound to 127.0.0.1 |

Queue/retry/TTL/capability limits in protocol.md are fixed. Richer content has
no enabling flag in v1. Synthetic tests use `push_only=true`, `webserver=false`
and public synthetic credentials, never production Signal identities.

## Commands

```sh
mollysocket -c /run/secrets/colliesocket/config.toml enrollment import --file /run/secrets/colliesocket/enrollment.json
mollysocket -c /run/secrets/colliesocket/config.toml enrollment import --stdin
mollysocket -c /run/secrets/colliesocket/config.toml enrollment status ACCOUNT_UUID
mollysocket -c /run/secrets/colliesocket/config.toml push test ACCOUNT_UUID
mollysocket -c /run/secrets/colliesocket/config.toml push wake ACCOUNT_UUID
mollysocket -c /run/secrets/colliesocket/config.toml push drain --once
mollysocket -c /run/secrets/colliesocket/config.toml migrate
mollysocket -c /run/secrets/colliesocket/config.toml ready
mollysocket -c /run/secrets/colliesocket/config.toml server
```

Import requires exactly one input option. Stdin is a non-terminal pipe, not
interactive input. Success emits response.schema.json and performs no Signal or
provider request. Running Signal loops poll for private registration updates
at a fixed five-second interval. Database contention or reconnect work can delay
application; this is not a five-second availability guarantee. Late in-flight
old events remain subject to epoch checks.

Status emits exactly `{instance,subscription_epoch,state,event_version}` for
the selected account, without endpoint/keys. State is `active`, `stale`, or
`provider_rejected`. This is local registration state, not delivery evidence.
Push test/wake enqueue a fresh event and emit `{event_id,queued:true}`.
`connection ping ACCOUNT_UUID` uses encrypted test for an enrolled account;
explicitly enabled legacy mode sends only the bounded generic wake.
Drain handles at most one due event. The long-running worker polls every second.
No interactive secret prompt is used.

Migrate validates directory/DB protection and applies transactional changes.
Ready probes `http://127.0.0.1:ready_port/readyz`, exits zero only for a healthy
private worker, and prints no secrets.

## Listeners

Compatibility discovery uses existing `host`/`port`, default 127.0.0.1:8020,
controlled by `webserver`. Mount no HTTP enrollment. Public edges must not expose
operational identifiers or metrics.

Readiness binds only 127.0.0.1 on `ready_port`; configuration cannot select a
remote bind address. Only GET `/readyz` is accepted. It returns 200
`{"ready":true}` if DB/migration is valid and the worker heartbeat is less than
10 seconds old, otherwise 503 `{"ready":false}`. It is not a Signal or Android
delivery probe. Do not map 8021 to a public host. Probe inside the same container
network namespace.

## State, secret permissions and migrations

Image UID/GID is 10001:10001. Writable state `/var/lib/colliesocket` is 0700.
`MOLLY_DB=/var/lib/colliesocket/mollysocket.db` is 0600. Credentials and auth
secrets are stored there: protect DB, journal/WAL, backups and import files
equivalently. Config/VAPID files are service-owned 0600 and read-only mounted
under `/run/secrets/colliesocket`. Process umask is 077. No shared-readable state
volume, raw SQL/HTTP Debug output, or account/event/endpoint details in logs.
Local account IDs are operator selectors and never clear push metadata.

SQLite schema version 2 adds subscriptions, idempotency records, event ledger
and the bounded queue to the existing connection table. Preserve upstream
columns. Versions 0/1 migrate transactionally; refuse future versions. Upstream
REPLACE/legacy updates must not overwrite encrypted registrations. No automatic
destructive down migration is supported.

Before migration, stop the service and preserve a complete owner-only backup.
Rollback restores the previous binary and matching pre-migration backup
together. The old binary must not open the upgraded live DB. A restore can
roll back epochs/replay clocks: disable sends and privately re-enroll with fresh
receiver keys and a fresh instance before resuming. Never silently fall back to
plaintext. Use SQLite backup API or a cleanly stopped DB, not part of an active
WAL. Keep upstream history/license and historical releases.

## Reproducible candidate image interface

```sh
docker buildx build --load --platform linux/amd64 \
  -f Containerfile.colliesocket \
  --build-arg SOURCE_COMMIT="$(git rev-parse HEAD)" \
  --build-arg SOURCE_DATE_EPOCH="$(git show -s --format=%ct HEAD)" \
  -t colliesocket:test .
docker image inspect colliesocket:test --format '{{.Id}}'
```

`Containerfile.colliesocket` is the build interface. Intended targets are
`linux/amd64` and `linux/arm64`; arm/v7 is not promised. Each candidate distinguishes
targets from architectures actually tested. Use pinned Rust 1.90.0, Cargo.lock,
`--locked`, and verified digest-pinned builder/runtime images recorded by the
recipe/candidate. No registry publication is required. A recipe SHA-256 is not
a built-image digest; record the latter as unavailable if a build did not run.

Server CI runs local unit/conformance/negative tests and an image build with no
push. Guard inherited release/cron publication jobs to upstream ownership so a
fork cannot publish inadvertently. Commit redacted candidate manifests with
source pin, contract pin, recipe digest, actual test results, NOT RUN gates,
known gaps and commands. Neither candidate nor handoff contains its own hash.
