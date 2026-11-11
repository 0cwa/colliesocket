ChatGPT-assisted draft for user review. **UNPOSTED: this text has not been approved or posted to GitHub.**

# Proposed PR: Add encrypted UnifiedPush v1 contracts and the CollieSocket server candidate

Collie needs a shared encrypted-push interface so Android and deployment work
can proceed independently. This change establishes that interface in
CollieSocket and adds the server path for confidential, bounded wake/test/status
events. Consumers can pin published contract fixtures and runtime commands
without waiting for full shipping acceptance.

## What changes

- Adds the canonical enrollment, event, receipt, replay, rotation, and runtime
  contracts under [`contracts/encrypted-push/v1/`](../contracts/encrypted-push/v1/README.md),
  with synthetic valid/invalid fixtures, sender/vector evidence, and executable
  conformance commands.
- Adds real RFC 8291 encryption to the allowed-destination HTTP transport.
  Requests carry 4096-byte binary `aes128gcm` bodies; HTTP POST and optional VAPID
  remain separate. Redirects remain disabled, address validation is repeated
  at send time, and secret endpoint/key data stays out of clear metadata and
  application diagnostics. See [`src/push.rs`](../src/push.rs) and
  [`src/utils/post_allowed.rs`](../src/utils/post_allowed.rs).
- Adds protected file/stdin enrollment, transactional schema 2 storage,
  account-scoped idempotency, exact next-epoch rotation, stale-provider recovery,
  and a durable bounded outbox. Same-URL key changes work without dropping the
  Signal connection. Provider failures cannot unlink a Signal device. See
  [`src/enrollment.rs`](../src/enrollment.rs) and
  [`src/push_store.rs`](../src/push_store.rs).
- Keeps public HTTP limited to discovery and readiness on a private loopback
  listener. Encryption-required registrations cannot fall back to legacy.
  Any explicitly enabled legacy mode has a fixed deadline and sends only the
  generic wake. See [`src/server/web.rs`](../src/server/web.rs),
  [`src/server/ready.rs`](../src/server/ready.rs), and
  [`src/ws/signalwebsocket.rs`](../src/ws/signalwebsocket.rs).
- Retains MollySocket history, attribution, executable/configuration names,
  and CLI compatibility where it fits the v1 trust boundary. CollieSocket is
  the project name; this does not rename release engineering or transfer
  ownership of the other workstreams.
- Adds the pinned [image build and CI interface](../docs/IMAGE.md), with native
  amd64/arm64 jobs, local archive output and private packaging smoke checks.
  The workflow does not push a registry image or publish a release. Actual
  image execution remains a separately reported gate.

The scope excludes message previews, Signal plaintext, new Signal decryption
keys, richer event content, HTTP pairing, production rollout, and automatic
device unlinking. Android plus engineering patches remain Orchestrator 2's
work; deployment and combined-test reporting remain Orchestrator 3's work.

## Pins and review evidence

The published contract C0 is
[`0bb7a6c1e1cc66c83b366117e0ceb9b9934aeb8f`](https://github.com/0cwa/colliesocket/commit/0bb7a6c1e1cc66c83b366117e0ceb9b9934aeb8f).
READY handoff H0 is
[`a58a46e278efdb89f9e6fd46d6b9556189a636eb`](https://github.com/0cwa/colliesocket/commit/a58a46e278efdb89f9e6fd46d6b9556189a636eb),
with fixture-manifest SHA-256
`226bff31ca34b23e411929812ab86105ee970d0aab84848b1b53b18edff21568`.
Both are available from the non-main `work/encrypted-push-v1` branch.

[`handoff/parallel-start-v2.json`](parallel-start-v2.json) is the launch record
for the exact contract pin, fixture-manifest hash, inputs, executed tests, and
NOT RUN gates. The separately published server candidate manifest under
`handoff/` records its implementation source pin, build recipe/digest, test
results, and remaining gaps. Review those committed records rather than a
moving branch tip, a chat summary, or a local image tag. An absent candidate
manifest means server candidate acceptance has not been recorded.

The reconstruction uses new immutable hashes. The earlier unpublished local
objects were unavailable and were not relabeled or recreated under their old
identifiers. Historical test results are not reused as evidence. See
[`handoff/reconstruction-v1.json`](reconstruction-v1.json).

Authored source bundles preserve `0cwa <0@none.org>` and original upstream
attribution. Canonical API transport commits record the actual GitHub-returned
identity, which may differ. Their provenance records provide the source/bundle
digest and mapping; no signatures, signoffs, or author identities are invented.
See the [contract](../provenance/encrypted-push/contract-v1-reconstructed.json)
and [handoff](../provenance/encrypted-push/parallel-start-v2.json) provenance records.

## Validation and limits

Reproduction commands and operator guidance are in
[`docs/encrypted-push-server-v1.md`](../docs/encrypted-push-server-v1.md).
The principal local commands are:

```sh
cargo test --locked
python3 contracts/encrypted-push/v1/tools/conformance.py
sh crates/colliesocket-push/tools/conformance.sh
cargo build --locked
python3 tests/server_cli.py
```

The synthetic server CLI check exercises the actual binary against a loopback
provider and uses independent Python/OpenSSL decryption. The committed manifests
carry the actual results for their exact pins. Same-library roundtrips are not
presented as independent interoperability, and a provider 2xx is not device
delivery evidence.

Real Android connector behavior, physical device/Keystore and lock-transition
acceptance, live Signal/distributor behavior, deployment, and shipping security
review require their own evidence. Image builds and each architecture remain
NOT RUN unless the candidate manifest records an executed build and digest.
READY means parallel implementation can start against shared inputs; it does
not mean these remaining gates have passed.

## Migration and rollback

Stop the service and preserve a complete private pre-migration backup before
running `migrate`. Schema 0/1 connections are retained; schema 2 adds encrypted
registration, request history, replay ledger, and queue state. Future schemas
are refused. The old binary must not open the upgraded live database.

Rollback restores the matching old binary and pre-migration backup while sends
remain disabled. Because restored state can roll back epochs/replay clocks,
fresh receiver keys/auth, a fresh instance, and private enrollment are required
before resuming encrypted sends. Use the exact next epoch of an existing local
registration, or epoch 1 for an intentionally new lifecycle. Do not downgrade
encrypted subscriptions to plaintext. The complete procedure is in the
[operator guide](../docs/encrypted-push-server-v1.md#migration-and-rollback).

## Review focus

Please review the private enrollment authority and secret handling, the
transactional rotation/receipt behavior, stale worker and downgrade guards,
destination validation, and the distinction between executed local evidence
and remaining device/deployment gates. Contract changes after publication need
a new version and consumer-selected pins; implementation fixes can follow the
frozen contract without changing it.

This file is a draft only. Posting it, opening a PR, merging, publishing a
release, or deploying is not performed by this document.
