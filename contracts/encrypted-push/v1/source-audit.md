# Fresh source and integration audit

Inspection began 2026-11-10 at 20:16:56 UTC. The following are source snapshots,
not floating promises about later branch heads. GitHub authenticated read APIs
were used for the Android, engineering and connector sources. This reconstructed
checkpoint inherits no executed-test claims from the unavailable earlier local
checkpoint. No Android, engineering or deployment implementation was edited.

## Exact input pins

| Input | Inspected revision | What was verified |
| --- | --- | --- |
| `mollyim/mollysocket` | `f1e10c97d4644df4d326b9d7dedb160b297d41ca` | Reconstructed server base, preserving upstream history |
| `0cwa/collieim-android` main | [`3614d9880ecc1e3a183cec669e09e3ac0226078a`](https://github.com/0cwa/collieim-android/commit/3614d9880ecc1e3a183cec669e09e3ac0226078a) | Receiver, registration, stored values, lock service, build and verification instructions |
| `0cwa/collie-release-engineering` main | [`f6db071230624445ab870f69a65d362e32a5eefb`](https://github.com/0cwa/collie-release-engineering/commit/f6db071230624445ab870f69a65d362e32a5eefb) | Current ownership contract, source layer and attribution conventions |
| `UnifiedPush/android-connector` tag `3.0.10` | [`948299041d5c86e69882c148e6b5f8c12e31387d`](https://github.com/UnifiedPush/android-connector/commit/948299041d5c86e69882c148e6b5f8c12e31387d) | Public callback data, key manager, decryption failure handling and declared dependencies |
| `0cwa/collie-fetch` | Unavailable | Authenticated repository lookup returned 404; no source pin or deployment compatibility claim is made |

Android's pinned [version catalog](https://github.com/0cwa/collieim-android/blob/3614d9880ecc1e3a183cec669e09e3ac0226078a/gradle/libs.versions.toml)
selects connector 3.0.10 and connector-ui 1.1.0-rc3. Its tracked
[dependency verification metadata](https://github.com/0cwa/collieim-android/blob/3614d9880ecc1e3a183cec669e09e3ac0226078a/gradle/verification-metadata.xml)
records connector AAR SHA-256
`8c72adba1bfb230bc823b19badbafe21d18a5db3c5f4e6da5b5305b4ec815717`
and module SHA-256
`d23909376a7b6abd7c680b3862dcef71bcc2e773bd5152b40ed5bc5f24127c7b`.
These were read from source; the AAR was not independently downloaded or rebuilt.
The connector's pinned [build file](https://github.com/UnifiedPush/android-connector/blob/948299041d5c86e69882c148e6b5f8c12e31387d/connector/build.gradle)
declares Tink 1.17.0 and its local `fixed_webpush` implementation. The application's
effective resolved Gradle dependency graph was NOT RUN; multiple Tink versions
in verification metadata do not establish the selected runtime version.

The Rust sender slice pins `web-push-native = 0.5.0` with default features off,
and its vector helper pins `ece-native = 0.5.0`. Fresh downloaded release
archives' `.cargo_vcs_info.json` identify source commit
[`6b0a3f10377af3c9401a7c1a60b1e34d41155c5d`](https://github.com/leotaku/web-push-native/commit/6b0a3f10377af3c9401a7c1a60b1e34d41155c5d)
for both. Archive SHA-256 values are respectively
`7628c93e39aeee4c0bca50ae333052b4f174c653e8fca1d0a8e34f9bc4879c0c`
and `6911cc97c62febd8cbcb2cb49ed21c58ccd418a80c43f20df4973ee08484e65d`.
The narrow wrapper validates key lengths before native Auth construction,
uses existing RustCrypto primitives, pads plaintext to the fixed profile and
normalizes the sender's record-size field to 4096. HTTP, VAPID and destination
validation remain separate server concerns. It does not copy a UnifiedPush
client stack. Full Cargo lockfiles, provenance, limitations and fresh execution
evidence are in `crates/colliesocket-push/` at the new checkpoint.

## Existing APIs and the required application changes

| Contract data or gate | Existing connector API | Current application gap |
| --- | --- | --- |
| `endpoint` | `PushEndpoint.url` | Already saved, but compared only by URL |
| `p256dh` | Nullable `PushEndpoint.pubKeySet?.pubKey` | Not included in existing registration or saved subscription tuple |
| Confidential `auth` | Nullable `PushEndpoint.pubKeySet?.auth` | Not included in existing registration; do not treat the class name `PublicKeySet` as permission to expose this secret |
| `instance` | Callback `instance: String`; connector registration defaults to `default` | Must bind the callback to the accepted durable subscription |
| Successful RFC 8291 decryption | `PushMessage.decrypted` with plaintext `content: ByteArray` | Existing receiver ignores the flag; v1 must reject false before effects |
| Epoch, explicit capabilities, durable replay/clock | New application state defined by this contract | Absent from current UnifiedPush values and registration model |

API evidence: [PushEndpoint](https://github.com/UnifiedPush/android-connector/blob/948299041d5c86e69882c148e6b5f8c12e31387d/connector/src/main/java/org/unifiedpush/android/connector/data/PushEndpoint.kt),
[PublicKeySet](https://github.com/UnifiedPush/android-connector/blob/948299041d5c86e69882c148e6b5f8c12e31387d/connector/src/main/java/org/unifiedpush/android/connector/data/PublicKeySet.kt),
[PushMessage](https://github.com/UnifiedPush/android-connector/blob/948299041d5c86e69882c148e6b5f8c12e31387d/connector/src/main/java/org/unifiedpush/android/connector/data/PushMessage.kt).

The current [application receiver](https://github.com/0cwa/collieim-android/blob/3614d9880ecc1e3a183cec669e09e3ac0226078a/app/src/main/java/im/molly/unifiedpush/receiver/UnifiedPushReceiver.kt)
uses `refreshEndpoint(endpoint.url)` in `onNewEndpoint` (lines 34–52), and compares
only that URL (lines 130–137). Same-URL key rotation therefore needs new tuple
comparison and private epoch acceptance. `onMessage` (lines 79–100) decodes
content and checks legacy text without using `message.decrypted`; the locked
branch can show a generic urgent notification. Those behaviors do not implement
this contract. V1 requires schema/time/epoch/replay checks and the stricter lock
gate before application effects.

[UnifiedPushValues](https://github.com/0cwa/collieim-android/blob/3614d9880ecc1e3a183cec669e09e3ac0226078a/app/src/main/java/org/thoughtcrime/securesms/keyvalue/UnifiedPushValues.kt)
stores the endpoint, device credentials, VAPID-related state and last-received
time in SignalStore, without an encrypted subscription tuple/epoch.
[ConnectionRequest](https://github.com/0cwa/collieim-android/blob/3614d9880ecc1e3a183cec669e09e3ac0226078a/app/src/main/java/im/molly/unifiedpush/model/ConnectionRequest.kt)
contains legacy `uuid`, `device_id`, `password`, `endpoint`, and `ping` fields.
[UnifiedPushRefreshJob](https://github.com/0cwa/collieim-android/blob/3614d9880ecc1e3a183cec669e09e3ac0226078a/app/src/main/java/org/thoughtcrime/securesms/jobs/UnifiedPushRefreshJob.kt)
uses direct legacy registration; its airgap status is not capability acceptance.
Some disabled/VAPID-change paths remove a linked device. V1 rotation and stale
provider recovery must not reuse those unlink paths.

## Reuse decryption; enforce the lock boundary separately

The pinned connector [MessagingReceiver](https://github.com/UnifiedPush/android-connector/blob/948299041d5c86e69882c148e6b5f8c12e31387d/connector/src/main/java/org/unifiedpush/android/connector/MessagingReceiver.kt)
looks up the instance from its registration token and obtains the public key
set for endpoint callbacks. On message receipt it invokes decryption. Success
produces `PushMessage(plaintext, true)`; a missing decrypt result or
`GeneralSecurityException` produces the original bytes with `decrypted=false`
(lines 139–146). The callback still runs after failure. The application must
not infer authenticity from receipt of the callback or attempt a plaintext
fallback for an encryption-required subscription.

[DefaultKeyManager](https://github.com/UnifiedPush/android-connector/blob/948299041d5c86e69882c148e6b5f8c12e31387d/connector/src/main/java/org/unifiedpush/android/connector/keys/DefaultKeyManager.kt)
uses the connector's existing RFC 8291 decryptor; reuse it instead of importing
a second UnifiedPush client stack.
[WebPushKeysEntries23](https://github.com/UnifiedPush/android-connector/blob/948299041d5c86e69882c148e6b5f8c12e31387d/connector/src/main/java/org/unifiedpush/android/connector/keys/WebPushKeysEntries23.kt)
uses Android Keystore protection and separate preferences, not the application's
passphrase master secret. Thus connector decryption can precede the application
lock decision; successful cryptography does not mean the Signal database is open.

[KeyCachingService](https://github.com/0cwa/collieim-android/blob/3614d9880ecc1e3a183cec669e09e3ac0226078a/app/src/main/java/org/thoughtcrime/securesms/service/KeyCachingService.java)
defines `isLocked()` as `masterSecret == null || locking` (lines 85–87).
The contract deliberately includes the transition flag. While locked, drop all
v1 events without SignalStore access, notification, fetch, plaintext buffering,
or replay/clock mutation. Race exclusion around commit/effect scheduling is
required; one early boolean check is insufficient. Normal authenticated recovery
after unlock handles missed wake events. The earlier generic locked notification
UX remains deferred until a later reviewed contract.

Orchestrator 2's first gate is actual connector decryption of the supplied Rust
fixture and actual receipt/failure behavior, followed by lock-transition,
restart/replay, clock rollback, same-URL rotation and unlock recovery checks.
Constructing `PushMessage(..., true)` manually is not decryption interoperability.
The Python reference receiver is executable contract guidance, not an Android
implementation or device acceptance result.

## Overlapping work and source ownership

Fresh Android branch enumeration returned 70 branches and no encrypted-push
work branch. Open PR [78](https://github.com/0cwa/collieim-android/pull/78), head
`13f86f9c0c0cfeb016d46d57f689ef4440a65756`, changes only `gradle.properties`.
Open PR [76](https://github.com/0cwa/collieim-android/pull/76), head
`947176da5db937fa0bea2de1a2e0dcd937039ea7`, changes only `AGENTS.md`.
There is no `AGENTS.md` at the inspected main pin; pending instructions are not
silently applied. Historical branches include `agent/8.35.1-3-push-storage`
at `7b7ec2cd4fd706e2fde3b1a50b0633a97488c4fa`,
`t3/investigate-mollysocket-logs` at `b3108fdcf36be00e6ceeeabc597596d4e75f2bd3`,
and `poc/molly-827-unifiedpush` at `b8d5375b3fb6013f7939935ce73e250b53515381`.
They remain owned by their existing workstreams; their names alone do not imply
the new contract is implemented.

Fresh engineering enumeration returned 28 branches and no encrypted-push work
branch. Its only open PR was [27](https://github.com/0cwa/collie-release-engineering/pull/27),
head `cd8c0283eb0621ffe2d7658a80e537eb4ee4725c`, concerning release/feed
publication. No release or publication changes are required to launch consumers.
Branch and PR inventories are time-bounded observations, not ownership locks.

Android [BUILD](https://github.com/0cwa/collieim-android/blob/3614d9880ecc1e3a183cec669e09e3ac0226078a/docs/BUILD.md)
and [VERIFY](https://github.com/0cwa/collieim-android/blob/3614d9880ecc1e3a183cec669e09e3ac0226078a/docs/VERIFY.md),
together with engineering's [migration ownership contract](https://github.com/0cwa/collie-release-engineering/blob/f6db071230624445ab870f69a65d362e32a5eefb/docs/migration/CONTRACTS.md),
make the application checkout the reviewed source. Android changes are later
exported into engineering's reconstruction layers and verified against the full
reviewed tree. Older patch-pipeline notes must not be used to erase that current
ownership. Orchestrator 2 owns both sides of that work.

The existing engineering [MollySocket layer](https://github.com/0cwa/collie-release-engineering/blob/f6db071230624445ab870f69a65d362e32a5eefb/source/layers/mollysocket.json)
describes TLS fix `6f2595515d8466da725c1dda65f252ef02d05456`, parent
`8b119e357d1c9c6863eff31756660bc07d6cfb8b`, patch SHA-256
`1eb301e0d92a22e69da5d42aecff0ac081f9520afb2236612dc0241a4e805b72`.
It does not provide payload encryption. Exported authored patches retain
`0cwa <0@none.org>` and upstream attribution. Recent ordinary engineering commits
use the authenticated account's noreply identity. Preserve original reviewed
attribution and record actual publication metadata; do not fabricate signatures,
signoffs or API author identities. See the pinned
[commit-message policy](https://github.com/0cwa/collie-release-engineering/blob/f6db071230624445ab870f69a65d362e32a5eefb/source/COMMIT-MESSAGES.md)
and [patch pipeline](https://github.com/0cwa/collie-release-engineering/blob/f6db071230624445ab870f69a65d362e32a5eefb/docs/PATCH-PIPELINE.md).

## Evidence limits

Fresh Rust sender/vector evidence and independent Python/OpenSSL checks are
recorded by the sender fixtures and checkpoint manifest. They do not establish
Android acceptance. NOT RUN here: Android compilation or resolved dependency
graph; connector AAR reproduction; Java/Android decrypt execution; physical
device or Keystore behavior; passphrase/lock-transition integration; real
distributor delivery; production Signal credentials; deployment/system tests;
and a shipping security review. Provider 2xx is never device delivery evidence.
