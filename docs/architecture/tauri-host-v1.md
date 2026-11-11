# Tauri 2 host decision

ChatGPT prepared this record from the user's explicit Tauri choice on
2026-11-11. Tauri 2 is the selected GUI framework. The earlier comparison of
Flutter, Qt and separate native GUIs is superseded.

## Selected architecture

The installed app uses Tauri for the desktop/mobile window and bundled GUI.
Rust owns the service logic, durable state, payload encryption and network
policy. A narrow native command boundary connects the GUI to the host.
Android service/IPC integration remains a native platform adapter.

The product keeps the previously selected same-device, LAN and optional-tunnel
modes. Containers remain optional headless packaging. No tunnel provider,
desktop-only requirement or mandatory remote server is introduced.

Tauri supports a Rust library entry point for the app, with a desktop binary
calling it and a mobile entry-point annotation for mobile builds. The service
library stays independent of Tauri so CLI/server verification does not inherit
WebKitGTK, a WebView or frontend dependencies. [1]

## Version and Android baseline

The initial framework baseline is Tauri 2. The following v2 release inputs were
inspected in official source, rather than taking an unconstrained latest tag:

| Component | Reviewed scaffold pin |
| --- | --- |
| tauri | 2.12.5 |
| tauri-build | 2.7.4 |
| tauri-cli | 2.12.4 |
| Upstream release source | 993038c49185307dfc895ab7657d77ca0d5ed7c7 |
| Rust declared by that source | 1.90 |

These are reviewed inputs for the forthcoming GUI scaffold, not dependencies
already added to this repository or a resolved GUI lockfile. Recheck applicable
upstream fixes when creating the actual app dependency graph. [2]

The selected Tauri path has an initial Android OS floor of Android 7 / API 24.
Set minSdkVersion explicitly in the eventual app configuration. Android 5/6 are
outside this selected baseline. Device support still requires installation and
runtime verification, including the required ARMv7 or ARM64 build. [3]

Tauri uses the selected system Android WebView, so API level alone does not
establish frontend compatibility. Record the WebView provider/version with each
old-device acceptance result. Keep the initial frontend small and avoid relying
on an untested modern browser feature set. [4]

## What the Rust UnifiedPush library provides

The official unifiedpush-rs project publishes the unifiedpush crate. The
inspected 0.1.0 release is a Linux/D-Bus recipient connector: it registers with
a distributor, obtains endpoint/key material, and receives/decrypts messages.
The official implementations list places it under Linux. It is not a push
server or an Android distributor. [5][6]

Use this library for the role it implements. A Linux recipient adapter can sit
inside the Rust side of Tauri. It must be target-specific, rather than an
unconditional Android/Windows/macOS dependency. A general push provider, local
distributor and their matching transport remain separate implementation work.

The existing colliesocket-push crate is a different reusable component: it
supplies the sender's reviewed RFC 8291 encryption using web-push-native 0.5.0.
Selecting Tauri does not require rewriting that encryption in JavaScript or
changing its frozen dependency pin. The inspected unifiedpush 0.1.0 manifest
uses web-push-native 0.4.0; do not treat its decoder as the sender's already
verified dependency graph. [7]

Before integrating the Linux recipient connector:

- Accept authenticated Decrypted messages for Collie v1; reject Raw messages
  instead of interpreting them as plaintext legacy events.
- Implement a reviewed private storage adapter. The example preferences backend
  explicitly stores receiver keys unencrypted in the user's home directory.
- Enforce the receiver's lock/replay/epoch/expiry rules in native code. The crate
  decrypts before invoking EventSink; a JavaScript callback is not a lock gate.
  The frozen Android policy permits connector decryption before the application
  gate, but excludes application effects and replay/clock mutation while locked.
  Any stricter desktop key-access policy needs a separately reviewed native
  storage/connector boundary.
- Do not copy examples that print endpoint URLs, auth secrets or message bodies.
  Send only purpose-built redacted operational status to the generic GUI.

These are source-review findings and integration requirements, not a claim that
the connector has passed Collie interoperability or lock acceptance. [6][7][8]

## Native command and service boundary

The Tauri GUI should communicate through small commands with typed results.
Its initial read-only status command must not open/migrate a database or start a
network listener merely to render a screen. Never expose the existing CLI
parser, arbitrary shell execution, unrestricted paths/URLs, credentials or a
raw configuration dump as frontend commands.

Application commands registered with invoke_handler are broadly available to
app windows by default. Use AppManifest::commands to generate explicit
permissions, and grant only the needed commands to the local main window.
Use bundled assets, an explicit content security policy, no remote command
capability and no unnecessary shell/filesystem/HTTP plugins. [9]

The engine must expose explicit construction, start, stop/cancellation, bounded
status events and durable recovery. It must not own the process's global logger,
environment, signal handling or process exit in the embeddable path.

On Android, the native service owns the engine lifetime. Tauri mobile startup
and a spawned Rust task do not establish background hosting. The platform
adapter must handle user-visible service status, user stop, process death,
reboot and network changes. Keep blocking work off Android's main thread.
This remains Android implementation work, coordinated with its existing owner. [10]

## First source step in this update

The current change adds src/lib.rs and moves the existing private module
declarations into the package's library. The executable now calls
mollysocket::run_cli(). The library name remains mollysocket, preserving existing
log namespaces; Cargo dependencies and lockfiles are unchanged.

run_cli() is explicitly a CLI-only compatibility entry point. It still parses
process arguments, initializes global configuration/logging and may exit the
process. The executable retains the Tokio runtime and restrictive Unix umask.
Do not call run_cli() from a Tauri command.

This small change establishes a library boundary while preserving the working
service. It does not yet provide the restartable host API, a native GUI, an
embedded provider/distributor, or Android background service.

The next source slice is to replace the embedding path's process-wide
configuration and exits with explicit host configuration and typed errors, then
add lifecycle cancellation and redacted status. The CLI remains a client of
that service API. Only then should a Tauri command start/stop the engine.

## Acceptance and change control

The existing regression suite must continue to pass through the library-backed
CLI. Record fresh unit/build/CLI results for this structural change separately
from the previously pinned server candidate.

Tauri native window/build, Android API 24/WebView/ABI, Linux D-Bus connector,
provider/distributor, KDE presentation and tunnel acceptance remain NOT RUN.
A passing headless library/CLI build does not establish any of those gates.

C0/H0 and the encrypted-push/v1 files are unchanged. New host and pairing
interfaces still require their own versioned acceptance; this UI framework
choice does not alter enrollment trust, wire format, downgrade prevention,
receiver lock policy or another owner's pins. No database migration is introduced
by the module extraction.

The current decision record is handoff/product-direction-v2.json. Its v1
predecessor remains available as the earlier undecided-framework snapshot.

## Sources

1. [Tauri project structure](https://v2.tauri.app/start/project-structure/)
2. [Tauri v2.12.5 release](https://github.com/tauri-apps/tauri/releases/tag/tauri-v2.12.5), [workspace](https://github.com/tauri-apps/tauri/blob/993038c49185307dfc895ab7657d77ca0d5ed7c7/Cargo.toml), [tauri-build](https://github.com/tauri-apps/tauri/blob/993038c49185307dfc895ab7657d77ca0d5ed7c7/crates/tauri-build/Cargo.toml), [CLI](https://github.com/tauri-apps/tauri/blob/993038c49185307dfc895ab7657d77ca0d5ed7c7/crates/tauri-cli/Cargo.toml)
3. [Tauri Android minimum](https://v2.tauri.app/distribute/google-play/)
4. [Tauri WebView versions](https://v2.tauri.app/reference/webview-versions/)
5. [UnifiedPush implementations](https://unifiedpush.org/developers/implementations/)
6. [unifiedpush 0.1.0 API](https://docs.rs/unifiedpush/0.1.0/unifiedpush/)
7. [unifiedpush 0.1.0 manifest and source](https://docs.rs/crate/unifiedpush/0.1.0/source/)
8. [Preferences storage documentation](https://docs.rs/unifiedpush_storage_preferences/0.1.0/unifiedpush_storage_preferences/)
9. [Tauri command capabilities](https://v2.tauri.app/security/capabilities/) and [CSP](https://v2.tauri.app/security/csp/)
10. [Tauri mobile plugins](https://v2.tauri.app/develop/plugins/develop-mobile/)

