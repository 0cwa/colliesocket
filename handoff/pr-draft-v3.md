ChatGPT prepared this draft for user review. **UNPOSTED: no PR or review request has been created.**

# Proposed title

ChatGPT: add encrypted UnifiedPush server support and separate Collie Pack

## Proposed body

ChatGPT prepared this change to give Collie a shared encrypted-push interface
and a tested local server path. Android and application work can use pinned
contracts while their own integration checks proceed separately.

This PR belongs inside `0cwa/colliesocket`, from `work/encrypted-push-v1` to
`main`. It is not an upstream MollySocket PR. This draft supersedes
`pr-draft-v2.md` for the current branch; the older file remains part of the
published server candidate's historical record.

### What changes

- Adds canonical enrollment, event, receipt, replay, rotation and runtime
  contracts, synthetic fixtures and executable conformance checks under
  [contracts/encrypted-push/v1](../contracts/encrypted-push/v1/README.md).
- Adds RFC 8291 encryption to the allowed-destination HTTP transport, with
  bounded binary `aes128gcm` messages, optional VAPID, send-time destination
  validation and disabled redirects. Endpoint and key material stay out of
  application diagnostics and clear metadata.
- Adds protected file/stdin enrollment, transactional schema 2 storage,
  idempotent receipts, exact next-epoch rotation, stale-provider recovery and
  a durable bounded outbox. Provider failures cannot unlink a Signal device.
- Keeps public HTTP limited to discovery and readiness on private loopback.
  Encrypted registrations cannot fall back to legacy. Explicitly enabled
  legacy wake mode remains time-bounded and generic.
- Establishes the Rust library boundary while preserving the `mollysocket`
  CLI. `run_cli()` remains CLI-only; a restartable embedding API is future
  server work, with its own tests.
- Adds the pinned [server image recipe and CI interface](../docs/IMAGE.md).
  Actual image builds and runtime execution remain separate acceptance gates.
- Moves all four existing app/product records to
  [Collie Pack](https://github.com/0cwa/collie-pack/tree/d4dc22dfe1917e3a4d599e7d3b4d4e1215fffefd).
  The GUI, provider/distributor integration, native notifications,
  local/LAN/tunnel modes, app packaging, deployment and combined tests belong
  there. The [split receipt](repository-split-v1.json) records the source and
  destination hashes. This cleanup changes documentation only.

MollySocket history, attribution, executable/configuration compatibility and
source licenses are retained. Existing Collie IM Android recipient code and
release-engineering ownership are unchanged. This branch does not implement
the Tauri app or a new provider/distributor, and does not add message previews
or Signal decryption keys.

### Published inputs and evidence

| Record | Immutable commit | Scope |
| --- | --- | --- |
| C0 contract | [0bb7a6c](https://github.com/0cwa/colliesocket/commit/0bb7a6c1e1cc66c83b366117e0ceb9b9934aeb8f) | Frozen protocol/runtime and fixtures |
| H0 READY handoff | [a58a46e](https://github.com/0cwa/colliesocket/commit/a58a46e278efdb89f9e6fd46d6b9556189a636eb) | Shared inputs for parallel implementation |
| C1 server source | [172ab2f](https://github.com/0cwa/colliesocket/commit/172ab2f378c9bd5a6d2fa9df94c3506414320339) | Server candidate and image recipe |
| M1 candidate manifest | [84f4313](https://github.com/0cwa/colliesocket/blob/84f43137358a93a8d973a594514443c54da3f76f/handoff/server-candidate-v2.json) | Exact C1 build/test results and remaining gates |
| Library source and evidence | [d75308e](https://github.com/0cwa/colliesocket/blob/d75308e4669aedc62b5d4b9b855071cd5b918689/evidence/library-boundary-v1/results.json) | Subsequent structural library extraction and fresh local checks |

The fixture-manifest SHA-256 remains
`226bff31ca34b23e411929812ab86105ee970d0aab84848b1b53b18edff21568`.
The split does not change these records or force consumers to adopt a new pin.
Historical collie-fetch references are preserved; current application routing
is `0cwa/collie-pack`.

The library extraction record reports 60 passing unit tests, two ignored
external probes, a passing Linux debug build, 14 passing actual CLI/worker
scenario groups and passing contract checks (76 schema cases, 14 reference
receiver cases and 80 immutable file hashes). Those results were executed for
the linked source, not newly run by this documentation move. The earlier
optimized build applies to C1; no optimized build of the library delta is
claimed. A provider 2xx does not establish device delivery.

The split checks compare transferred content and published trees, parse JSON,
resolve local document links and verify unchanged server source, dependencies,
fixtures, build recipe and evidence. See the split receipt for the exact scope.

### Remaining acceptance

Image builds on each architecture, native GUI builds, real Android devices,
Keystore/lock transitions, live Signal/provider/distributor behavior, KDE
notifications, tunnels, combined deployment tests and shipping security review
remain NOT RUN unless their own later evidence records execution. No CodeRabbit
review has been requested by this change, and its repository access has not
been validated here. The separate
[Collie Pack PR draft](https://github.com/0cwa/collie-pack/blob/d4dc22dfe1917e3a4d599e7d3b4d4e1215fffefd/handoff/pr-draft-v1.md)
covers the application planning.

### Migration and rollback

The repository split adds no runtime or database migration. The encrypted
server candidate already introduces schema 2: stop all writers and preserve a
complete private backup before first use against an existing database, including
startup or CLI commands that open state. Follow the
[operator guide](../docs/encrypted-push-server-v1.md#migration-and-rollback).

Rollback restores the matching old binary and pre-migration backup while sends
remain disabled. The old binary must not open the upgraded live database.
Fresh receiver keys/auth, a fresh instance and private enrollment are required
before resuming encrypted sends according to the restored lifecycle. Do not
downgrade encrypted registrations to plaintext.

### Review focus

Please review private enrollment authority, secret handling, transactional
rotation/receipts, stale-worker and downgrade guards, destination validation,
the CLI library boundary and the separation of server evidence from native app
acceptance. The app documents should be reviewed in Collie Pack. Published
contract changes need a new version and consumer-selected pins.

This is an unposted draft. It does not open a PR, request CodeRabbit review,
merge, release or deploy anything.
