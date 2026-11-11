# Native GUI host direction

ChatGPT prepared this architecture record from the user's product direction on
2026-11-11. It is a reviewable design record, not a native-app implementation or
a change to the frozen encrypted-push/v1 contract.

## Framework decision update

The user selected **Tauri 2** on 2026-11-11. The current framework and native
boundary are recorded in [Tauri host decision](tauri-host-v1.md) and
[product-direction v2](../../handoff/product-direction-v2.json). The initial
Android OS floor for this choice is Android 7 / API 24; actual device, ABI and
WebView acceptance remains unverified. The framework comparison below records
the earlier assessment and is superseded by that explicit choice.

## Product direction

The primary product should be an installable GUI application that can run a
UnifiedPush host on a desktop or an Android phone, including older Android
devices selected for support. The app should support local CollieSocket linking,
deliberate LAN access, and optional access through the user's tunnel.

A normal installation must not require Docker, a Linux VM, root access, or a
separate always-on Linux machine. A headless executable and container can remain
optional hosting and test formats. Container acceptance does not establish
native desktop or Android acceptance.

The product can present one application while keeping the following roles
separate internally. No product or repository rename is decided here.

## Roles and data flow

| Role | Responsibility | Current position |
| --- | --- | --- |
| CollieSocket sender | Observe its authorized Signal connection and send encrypted wake/test/status events | Implemented as a service candidate; native GUI embedding remains work |
| Push server | Issue push resources, accept encrypted POST bodies, and route or retain them for distributors | New provider work; not implemented by the CollieSocket candidate |
| Distributor | Register local applications and deliver original push bytes over platform IPC | Android and Linux adapters needed, or compatible existing distributors |
| Recipient app and connector | Own receiver keys, decrypt, enforce identity/epoch/replay/expiry/lock rules, and decide effects | Existing Android owner and gates remain relevant |
| Notification presentation | Show the recipient app's approved notification or the host's own service status | Separate from push transport; integrate with the native OS |

UnifiedPush explicitly allows the distributor to act as its push server.
Combining both in one app is therefore compatible with the documented topology.
The provider-to-distributor protocol is implementation-specific: adding a Web
Push receiving endpoint alone does not make a new provider compatible with every
existing distributor. Choose and verify a matching protocol or adapter. [1][2]

The host must forward opaque encrypted bodies to the intended app. General
UnifiedPush delivery must not parse all applications' payloads as Collie events.
Keep provider registration/state and queues separate from CollieSocket's
account-specific enrollment and sender outbox. The current five-minute event
lifetime and other Collie v1 policy limits are not a newly invented policy for
all third-party apps.

A proposed installation may run its provider, local distributor and optional
CollieSocket sender together, or connect to a CollieSocket sender on another
host. An external distributor may connect to this host if their protocols match.
The presence of a shared GUI does not grant its provider access to recipient
decryption keys.

## Three reachability modes

| Mode shown in setup | Intended behavior | Required validation |
| --- | --- | --- |
| On this device | Host provider/distributor locally; optionally embed CollieSocket | Authenticated local IPC/control; if loopback is used, explicit origin allowance plus independent caller/capability checks; no tunnel required for this path |
| On my network | Use a selected reachable LAN host | Authenticated pairing, explicit interface/origin selection, and sender-to-endpoint reachability |
| Through my tunnel | Reach the same host across networks | A compatible tunnel route, stable advertised endpoint, identity verification, and reconnect behavior |

Local linking does not create network reachability. A loopback address identifies
the sender's own host. A remote CollieSocket cannot POST to another device's
127.0.0.1. A private phone behind NAT needs a reachable route, a suitable reverse
tunnel, or a relay when its sender is elsewhere. UnifiedPush describes gateways
that can provide this reachability. [2]

CollieSocket's existing Signal connection and push POSTs are outbound. The new
push provider's receiving endpoint is what needs to be reachable from senders;
there is no reason to expose CollieSocket administration merely to enable push.

The tunnel adapter should accept the user's existing tunnel. No provider,
commercial service, Android VPN, or bundled tunnel daemon is selected here.
Other application servers that cannot route to a private network will still need
a reachable endpoint; selecting LAN-only mode cannot promise delivery from the
public Internet.

Bind locally by default. Enable additional interfaces deliberately. Preserve
send-time address validation, explicit private-origin allowances, disabled
redirects, and protection against DNS rebinding. Do not replace those controls
with a broad private-network exception.

## Pairing and encryption boundary

The user-facing goal is simple local linking, with an optional remote route.
The existing candidate's initial enrollment authority is a protected local file
or stdin import. It deliberately has no HTTP enrollment route. [3]

A first native host should wrap or reuse that validated import path within an
authenticated local authority. A future GUI pairing flow can use a short-lived
code or QR bootstrap, but needs a separately versioned protocol and review before
implementation. A QR code by itself does not authenticate the channel. Do not
put Signal credentials, receiver auth secrets, or long-lived capability endpoints
in pairing-link query strings, logs, screenshots, or a public discovery page.

Keep management/key establishment separate from ciphertext ingress. If an
optional tunnel terminates TLS at an intermediary, RFC 8291 encryption protects
event contents, but it does not authenticate enrollment or prevent replacement
of receiver keys during an unprotected pairing exchange. Remote management needs
an authenticated end-to-end path to the selected host, independently of that
edge. Adding a tunnel cannot enable plaintext fallback.

Changing advertised endpoints follows a deliberate subscription update and
epoch lifecycle; do not silently rewrite an enrolled URL. Each recipient device
owns its own receiver identity and keys. Multi-device support must not copy an
Android receiver's secrets to a desktop or imply that another Signal linked
device's ciphertext becomes readable. The current account/subscription model
must be reviewed before promising simultaneous independent recipients.

## Portable core and platform hosts

Recommended next implementation boundary:

1. Extract an embeddable Rust service library from the command-driven process.
   The CLI becomes a host of that library. Preserve the existing sender,
   registration transactions, retries, migrations and redaction checks.
2. Give the host explicit configuration, private state access, startup/shutdown,
   cancellation, network-change handling and redacted status events.
   Avoid making process-wide globals or a CLI signal handler the app lifecycle.
3. Supply platform adapters for private storage and enrollment authority, TLS
   trust and native crypto dependencies, IPC, startup, and notifications.
4. Add a provider module and one verified matching distributor path. Prefer reuse
   where its actual protocol, license and Android hosting fit are established.
   Existing ntfy/KUnifiedPush interoperability is a useful reference, not proof
   that an upstream server can simply be embedded in an Android APK.
5. Make the GUI a client of the host lifecycle, so closing the window does not
   mean stopping a service the user deliberately enabled. Provide a clear Stop
   action and observable paused/offline/reconnecting states.

This is not only a GUI wrapper task. At the inspected C1 source, there is no
src/lib.rs; the binary owns modules and startup. Protected file import and state
path validation fail closed on non-Unix platforms. Dependencies include
native-tls and OpenSSL. Windows ACL handling, Android app-private storage, native
TLS/crypto packaging, and lifecycle behavior therefore need real platform work
and tests. Do not remove safety checks to make a build succeed. [4][5][6]

Rust supplies Android targets including ARMv7 and ARM64. Their availability
supports investigating a shared core; it does not establish that this dependency
graph works on a particular API level or CPU. Record the selected NDK, Rust,
minimum API, ABI, native dependencies, and actual device results. [7]

Desktop targets under consideration are Linux, Windows and macOS. Android is a
phone-host target. iOS hosting is not inferred from a general cross-platform
request and has no support claim in this record. A portable hosting GUI also
does not imply a standardized UnifiedPush inter-app distributor API on Windows
or macOS; the documented Android and Linux/D-Bus delivery paths need their own
adapters. [1]

## Older Android is a design input

The oldest required Android version and phone model are still unknown.
Do not select the shared renderer or declare a supported minimum before that is
resolved. ARMv7/32-bit support may matter independently of Android version.

The current official documentation checked on 2026-11-11 lists:

| Option | Documented Android floor | Design consequence |
| --- | --- | --- |
| Flutter | API 24 / Android 7 for current supported deployments | A shared GUI is an option if this floor fits the user's devices |
| Tauri 2 | API 24 / Android 7 | Also needs validation against the device's actual WebView |
| Current Qt 6 matrix | API 28 / Android 9 | Useful desktop option; cannot assume it meets older-phone goals |
| New AndroidX releases | Default minSdk 24, with artifact-specific requirements | Native Android also requires a deliberate dependency audit |

These are current documented support floors, not a claim that every historical
release has the same limit. Do not choose an unmaintained toolkit solely to lower
the number without an explicit support and security plan. [8][9][10][11]

Two viable paths to evaluate:

- If Android 5/6 or older is required, start with a small native Android host/UI
  and a separately chosen desktop shell around the shared Rust core. Platform
  Views avoid committing to a current cross-platform renderer's floor, but all
  Android/native dependencies and real hardware still need validation.
- If Android 7+ is sufficient, a shared Flutter GUI becomes an option. Native
  service, secure-state, IPC and notification adapters are still required.

No GUI framework or Android minimum is selected by this record.

## Android availability

An Android host should be a normal app with a deliberately enabled ongoing
service, a visible service-status notification and an explicit stop control.
The service, rather than an open Activity, owns networking and durable state.

Foreground service operation does not promise uninterrupted networking.
Android 6+ Doze can defer CPU and network activity. Newer target versions also
restrict foreground-service starts and some service types; dataSync is not an
unlimited background daemon (Android 15+ targeting adds a six-hour budget per 24 hours while
backgrounded). Choose the service type based on the actual operation and verify
its applicable requirements. [12][13][14]

Test a charging spare-phone host and a carried phone separately. Screen off,
Doze, process death, reboot, Wi-Fi/mobile changes, tunnel loss and explicit user
stop must produce recoverable, truthful states. Do not revive a user-stopped
host by hiding its operation. The tunnel and any long-lived connections also
need battery and memory measurements on the selected old hardware.

Host liveness and the recipient's app-lock policy are different. An opaque
provider may handle ciphertext while the recipient is locked. It must not turn
that into recipient notifications or bypass Collie's current app-lock gate.
The generic ongoing host-service notice must not reveal incoming event content.

## KDE and other desktop integration

On Linux, use the UnifiedPush D-Bus contract and evaluate KUnifiedPush reuse.
KUnifiedPush already provides a distributor and connector, with provider adapters
including ntfy, Gotify, NextPush and Autopush. Compatibility depends on the chosen
provider protocol and pinned implementation, not just using the same name. [15][16]

Use the desktop's existing notification service for UI presentation.
org.freedesktop.Notifications is distinct from org.unifiedpush distributor IPC.
The receiving app decrypts and applies its policy before presenting a message.
Host status notices can use the desktop API without reading other apps' payloads.
KDE's notification daemon must not be replaced to add UnifiedPush support. [17]

Displaying real Signal message content on a desktop requires an appropriately
authorized recipient/client. The current CollieSocket wake/test/status contract
does not supply message previews or Signal decryption keys. Keep that boundary,
including the initial Collie app-lock exclusion, until a separately reviewed
feature adds richer behavior. [3]

## Implementation sequence and acceptance

| Next slice | Evidence required before claiming it works |
| --- | --- |
| Embeddable sender core and native Linux host | Existing conformance and CLI checks remain valid; lifecycle cancellation/restart and protected local control verified |
| Provider and local distributor path | Registration and exact encrypted-byte delivery through a real supported connector; app isolation, expiry, queue bounds and revocation checked |
| Oldest Android target | Install/run on selected API and ABI; close GUI; process death, Doze, lock/unlock and reboot recovery; battery/memory measurements |
| LAN and tunnel modes | Real sender-to-endpoint reachability, authenticated pairing, network changes, endpoint rotation and reconnect behavior |
| KDE integration | Real D-Bus delivery; recipient-approved test/status notification; no payload or lock-policy bypass |
| Windows/macOS hosting | Native builds, private-state/IPC protections, lifecycle and notification adapter evidence on each platform |

For the first integrated demonstration, aim for a native host receiving an
actual encrypted CollieSocket test push and delivering the unchanged bytes to a
real recipient. Then demonstrate it with the GUI closed. A provider 2xx remains
provider acceptance, not proof that the recipient processed or displayed it.

No native GUI, provider, Android-host, KDE, Windows/macOS-host or tunnel acceptance
test was executed as part of this documentation change. Prior candidate evidence
remains scoped to its published Linux service source and synthetic gates.

## Versioning, migration and ownership

C0 remains 0bb7a6c1e1cc66c83b366117e0ceb9b9934aeb8f.
H0 remains a58a46e278efdb89f9e6fd46d6b9556189a636eb.
C1 remains 172ab2f378c9bd5a6d2fa9df94c3506414320339.
M1 remains 84f43137358a93a8d973a594514443c54da3f76f.

The frozen v1 runtime remains the existing service deployment profile. Native
host and pairing interfaces will need separately versioned profiles, explicit
compatibility notes and their own acceptance evidence. A new native runtime
does not by itself require changing the encrypted payload format. Changed
accepted event/enrollment behavior does require a new appropriate contract
version; do not silently reinterpret v1.

This record changes product priorities, not implementation or database state.
No migration or rollback action is required for this documentation change.
Retain the existing binary-plus-backup rollback procedure for the current server.
Future GUI imports must use validated migration and fresh enrollment behavior,
not copy stale databases/keys between devices and assume they are portable.

Orchestrator 1 remains the CollieSocket server and shared-contract owner.
Orchestrator 2 retains Android and engineering patch ownership. Orchestrator 3
retains deployment and combined-test reporting. This record recommends adding
native/local/tunnel acceptance to that combined view; it does not edit their
repositories, force their pins, or silently assign new GUI implementation work.

Container build completion is optional packaging evidence for this product
direction, not the next native-product milestone. Existing C0/H0 remain valid
inputs for encryption/receiver work; READY never meant native product acceptance.

Open decisions: oldest Android/device/ABI; preferred desktop support order;
existing tunnel's actual protocol and trust boundary; shared GUI versus native
Android UI; provider/distributor protocol and reuse choice. Continue the portable
core boundary and reuse assessment while these are resolved.

## Sources

Primary specifications, official platform documentation, and inspected source.
External platform matrices are snapshots checked on 2026-11-11 and should be
rechecked when dependencies are pinned.

1. [UnifiedPush developer introduction](https://unifiedpush.org/developers/intro/)
2. [UnifiedPush definitions, including combined distributor/server and gateways](https://unifiedpush.org/developers/spec/definitions/)
3. [Frozen CollieSocket protocol](https://github.com/0cwa/colliesocket/blob/0bb7a6c1e1cc66c83b366117e0ceb9b9934aeb8f/contracts/encrypted-push/v1/protocol.md)
4. [C1 startup](https://github.com/0cwa/colliesocket/blob/172ab2f378c9bd5a6d2fa9df94c3506414320339/src/main.rs)
5. [C1 protected imports](https://github.com/0cwa/colliesocket/blob/172ab2f378c9bd5a6d2fa9df94c3506414320339/src/enrollment.rs) and [state protection](https://github.com/0cwa/colliesocket/blob/172ab2f378c9bd5a6d2fa9df94c3506414320339/src/push_store.rs)
6. [C1 native dependencies](https://github.com/0cwa/colliesocket/blob/172ab2f378c9bd5a6d2fa9df94c3506414320339/Cargo.toml)
7. [Rust Android targets and NDK policy](https://doc.rust-lang.org/rustc/platform-support/android.html)
8. [Flutter supported platforms](https://docs.flutter.dev/reference/supported-platforms)
9. [Tauri Android distribution and minimum SDK](https://v2.tauri.app/distribute/google-play/)
10. [Qt supported platforms](https://doc.qt.io/qt-6/supported-platforms.html)
11. [AndroidX minimum SDK policy](https://developer.android.com/jetpack/androidx/versions)
12. [Android foreground services](https://developer.android.com/develop/background-work/services/fgs)
13. [Android Doze and App Standby](https://developer.android.com/training/monitoring-device-state/doze-standby)
14. [Android foreground-service timeouts](https://developer.android.com/develop/background-work/services/fgs/timeout)
15. [UnifiedPush D-Bus specification](https://unifiedpush.org/developers/spec/dbus/)
16. [KUnifiedPush upstream](https://github.com/KDE/kunifiedpush)
17. [Desktop notification service](https://specifications.freedesktop.org/notification/latest/basic-design.html)
