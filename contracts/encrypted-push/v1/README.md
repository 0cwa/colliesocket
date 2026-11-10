# CollieSocket encrypted push contract v1

This is the canonical shared contract for `0cwa/colliesocket`,
`0cwa/collieim-android`, and `0cwa/collie-fetch`. Orchestrator 1 owns the
contract and server. Orchestrator 2 owns Android and its engineering
representation in `0cwa/collie-release-engineering`. Orchestrator 3 owns
deployment and combined-test reporting. There is no fourth protocol repository.

## Reconstructed checkpoint

This is a freshly reconstructed replacement for the unavailable, unpublished
earlier local contract commit `9bf0d9cab4f01873617f7ad22fa1a98a6a2ec5b7`.
It is not a byte-identical recovery and inherits no earlier PASS results.
The new C0 and `handoff/parallel-start-v2.json` identify this checkpoint. Consumers
must fetch and pin the new full C0 and fixture-manifest SHA-256; a chat transcript,
old local tag, or planned merge is not a substitute.

READY means consumers can start implementation against shared schemas,
fixtures, runtime interfaces, and freshly executed sender evidence. It does not
mean shipping security acceptance, physical Android acceptance, or deployment.
The handoff records executed and NOT RUN gates separately. A HOLD is not a
launch receipt.

## Scope

V1 accepts only `wake`, `test`, and two bounded `status` codes. It carries no
message preview, sender/conversation identifier, Signal message body, or new
Signal decryption key. A wake requests the usual authenticated Signal fetch
after unlock. Another linked device's Signal ciphertext is not plaintext that
Collie can consume.

RFC 8291/8188 framing remains standard. `version` and `enrollment_version`
version JSON application data only. VAPID, HTTP transport, content encryption,
and enrollment authorization are distinct. The HTTP body is actual binary
`aes128gcm`, never a base64/JSON wrapper or a clear payload with a fake header.

| File | Purpose |
| --- | --- |
| `enrollment.schema.json` | Exact protected import request |
| `event.schema.json` | Exact decrypted application event |
| `response.schema.json` | Accepted enrollment receipt |
| `protocol.md` | Normative semantic, trust, lifecycle, error, replay and retry rules |
| `runtime.md` | Executable, configuration, import, image and migration interface |
| `source-audit.md` | Fresh source/dependency/overlap inspection and limits |
| `fixtures/cases.json` | Synthetic structural/semantic validation cases |
| `fixtures/receiver-cases.json` | Synthetic reference replay/lock decisions |
| `fixtures/crypto/` | Public-vector and synthetic Rust ciphertext fixtures |
| `fixtures/manifest.json` | Frozen hashes of this contract and its fixtures |

The schemas and semantic rules are both required. JSON Schema alone does not
validate an EC point, enrollment authorization, DNS/address policy, replay,
local file permissions, or Android lock behavior.

## Reproduce from repository root

```sh
python3 -m pip install -r contracts/encrypted-push/v1/tools/requirements.txt
python3 contracts/encrypted-push/v1/tools/conformance.py
cargo test --locked --manifest-path crates/colliesocket-push/Cargo.toml
python3 crates/colliesocket-push/tools/check_fixtures.py contracts/encrypted-push/v1/fixtures/crypto
sh crates/colliesocket-push/tools/conformance.sh
```

The Python contract checker validates public synthetic inputs offline. It
supports explicit HTTP-origin allowance context in fixture cases; actual DNS,
rebindings, private-address policy, durable SQLite and Android behavior require
their owner-specific tests. Its replay model is a reference decision model,
not an Android implementation. Independent Python/OpenSSL decryption is evidence
separate from Rust, but does not establish Android/Keystore/device acceptance.

During reconstruction only, `conformance.py --draft` runs cases without claiming
an immutable manifest. The default command requires and verifies the manifest.
The contract owner creates the manifest once using `tools/freeze_manifest.py`
after review and the final crypto fixture copy. That tool refuses an existing
manifest. Consumers must not regenerate hashes to hide a changed fixture.

## Change control

After this new C0 is published, do not mutate the v1 contract, fixtures, or
runtime interface. Changed accepted behavior requires a sibling contract
version, new immutable pin, migration notes and a new handoff. Never rewrite a
READY manifest. Consumers choose when to adopt; server work cannot force pins.
Implementation changes bringing the server into compliance may follow C0.
Record remaining deviations in candidate manifests, not by rewriting v1.
