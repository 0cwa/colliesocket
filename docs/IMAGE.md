# CollieSocket test image and CI

`Containerfile.colliesocket` implements the frozen
[`encrypted-push/v1` runtime](../contracts/encrypted-push/v1/runtime.md).
It preserves MollySocket's executable/configuration interface and upstream
AGPL attribution. This is a reproducible candidate build recipe, not a
production release or evidence of Android delivery.

## Current evidence

Local Docker and podman executables are unavailable. **Image build, image
execution, and both architecture smoke tests are NOT RUN in this workspace.**
No built-image digest is claimed. The committed
[`local-validation.json`](../images/local-validation.json) records source,
syntax, workflow and registry-pin checks separately. No Actions execution was
observed when the checkpoint was published; later CI results must be assessed
at their actual source commit.

[`base-pins.json`](../images/base-pins.json) and `images/registry-manifests/`
contain public, exact registry index bytes and their SHA-256 values. The raw
bytes were fetched from Docker's registry over verified HTTPS and matched its
`Docker-Content-Digest` header. Linux amd64/arm64 child entries were inspected;
this does not establish that either image was pulled, built or executed.

| Input | Fixed selection |
| --- | --- |
| Rust builder | `rust:1.90.0-bookworm`, digest pinned in the recipe |
| Runtime | `debian:bookworm-slim`, digest pinned in the recipe |
| Dockerfile frontend | `docker/dockerfile:1.7.1`, digest pinned |
| BuildKit daemon | `moby/buildkit:v0.34.2`, digest pinned in CI |
| Buildx | `v0.38.2`; official release digest metadata recorded |
| Source/dependencies | Exact Git source commit, Rust 1.90.0, Cargo.lock and `--locked` |
| Intended platforms | `linux/amd64`, `linux/arm64`; no arm/v7 promise |

The builder's reviewed non-glibc linked libraries are copied under their
SONAMEs into `/usr/local/lib/colliesocket`. The runtime retains its complete
glibc/loader/NSS family. The allowlist permits required OpenSSL, libgcc,
libstdc++ and zlib libraries; an unexpected dependency fails for review.
`/usr/share/colliesocket/runtime-libraries.sha256` records the actual copied
file hashes. `ldconfig` and a build-time `mollysocket --version` check validate
runtime linking when a real build runs. The pinned builder supplies the CA
bundle and OpenSSL configuration. No floating apt install or full-upgrade is
used. Pinned inputs require reviewed maintenance; this is not a vulnerability
audit or shipping-security approval.

The image's `AGPL-3.0-or-later` label matches the upstream Cargo manifest at
`f1e10c97d4644df4d326b9d7dedb160b297d41ca`; `LICENSE.txt` and the adapted
sender-helper MIT attribution are included. OCI labels identify the canonical
source repository and exact source commit.

## Reproduce a local candidate

Use the source commit named by the candidate manifest on a Linux host with
Docker/Buildx and Python 3. The build script requires a clean committed checkout,
archives that exact commit, and executes the recipe and evidence helpers from
the archive. Working-tree changes made during a build cannot silently change
its recorded recipe. Output must be outside the checkout and cannot overwrite
an existing candidate.

```sh
python3 tools/image/check-pins.py
python3 tools/image/check-pins.py --online

# Use the standard local Docker socket; do not select a remote daemon.
env -u DOCKER_HOST -u DOCKER_CONTEXT -u DOCKER_TLS \
  -u DOCKER_TLS_VERIFY -u DOCKER_CERT_PATH \
  docker --host=unix:///var/run/docker.sock buildx create \
  --name colliesocket-test-builder --driver docker-container \
  --driver-opt image=docker.io/moby/buildkit:v0.34.2@sha256:c5f8862f52499773af85bc07695b2379ef08e8002352b0df2c4864c91d78dabe \
  --buildkitd-flags '--oci-worker=true' --use

candidate_output=$(mktemp -d)
COLLIESOCKET_BUILDER=colliesocket-test-builder \
  bash tools/image/build.sh linux/amd64 colliesocket:test-amd64 "$candidate_output"
```

Run `linux/arm64` with an arm64 Docker host for the corresponding native build.
The CI matrix uses native runners; it does not require installing emulators.
If a managed build proxy needs an additional trusted CA, set
`COLLIESOCKET_BUILD_CA_BUNDLE` to the path of its combined trusted CA bundle.
The script passes it as the optional BuildKit secret `build_ca`, used only by
Cargo's network step. TLS verification remains enabled, and this CA is not
copied into the image. Registry pulls still use the local daemon's configured
network and trust settings.

The underlying interface remains:

```sh
docker buildx build --load --platform linux/amd64 \
  -f Containerfile.colliesocket \
  --build-arg SOURCE_COMMIT="$(git rev-parse HEAD)" \
  --build-arg SOURCE_DATE_EPOCH="$(git show -s --format=%ct HEAD)" \
  -t colliesocket:test .
```

The helper additionally exports a local Docker archive with timestamp rewriting,
loads it locally, writes selected build metadata, and runs the isolated smoke
test by immutable image ID. It never pushes an image. `SOURCE_DATE_EPOCH` is the
source commit's timestamp, gzip suppresses its own timestamp, and the build
context comes from `git archive`. These controls make reproduction actionable;
byte-for-byte repeated image reproduction remains NOT RUN until two actual
builds are compared. See BuildKit's pinned
[reproducibility documentation](https://github.com/moby/buildkit/blob/v0.34.2/docs/build-repro.md).

Successful output contains:

- `image.tar.gz`: loadable local Docker image archive, without a registry dependency.
- `image-build.json`: actual source/contract pins, recipe hashes, built platform,
  image configuration digest, available exporter manifest digest, archive
  SHA-256, selected runtime metadata and explicit NOT RUN gates.
- `image-smoke.json`: actual packaging checks and cleanup result for that platform.

The image configuration digest, exporter manifest digest, archive SHA-256 and
recipe SHA-256 identify different objects. A recipe hash is not a built-image
digest; there is no registry digest when nothing was published. A source
candidate manifest must copy actual observed results, not infer them from this
recipe or a local tag.

```sh
docker load --input "$candidate_output/image.tar.gz"
python3 tools/image/smoke.py colliesocket:test-amd64 \
  --platform linux/amd64 --output "$candidate_output/recheck-smoke.json"
```

## Private runtime and smoke scope

The image entry point is `/usr/local/bin/mollysocket`, default command `server`.
`/usr/local/bin/colliesocket` is a symlink to that executable. UID/GID is
10001:10001. `/var/lib/colliesocket` is 0700, and the server creates
`mollysocket.db` as 0600 with umask 077. The build context allowlist excludes
state, credentials, protected imports and Git metadata.

Config and secrets belong under `/run/secrets/colliesocket`, service-owned and
0600, mounted read-only. `MOLLY_CONF` or `-c` selects a mounted config. The
image does not bake enrollment or VAPID secrets into layers. Preserve those
permissions when providing a state volume or bind mount; a mismatched host
owner must be repaired explicitly by the operator, not by a root startup step.

The image defaults to `MOLLY_HOST=127.0.0.1`, port 8020, `webserver=false`, and
private readiness on 127.0.0.1:8021. It declares no exposed ports. Its Docker
healthcheck invokes `mollysocket ready` inside the container; neither discovery
nor health is evidence of Signal authentication or device delivery. The main
application sets umask 077. No root entrypoint changes ownership of mounted
files.

The packaging smoke test creates only unique disposable Docker volumes and
containers. Its config has no accounts, `push_only=true`, `webserver=false`,
empty destination allowances and staging Signal selection. Containers use
`--network none`, a read-only root filesystem, dropped capabilities and
`no-new-privileges`. It verifies UID, private directory/database/config modes,
the alias, migration, read-only secrets, loopback readiness, Docker health, and
absence of mapped host ports. It attempts cleanup of all its named objects even
after a timed-out CLI call. It does not create production identities or run
Orchestrator 3's deployment/combined-system tests.

Migration and rollback remain governed by the frozen runtime: stop before a
complete protected backup; upgrade transactionally; roll back the binary and
matching database backup together. An old binary must not open an upgraded live
database. After restore, disable sending and privately re-enroll with fresh
receiver keys/instance before resuming. Never use the image workflow as an
automatic database rollback mechanism.

## CI and ownership

The original C0 `contract` job remains intact. Added `server` and `image` jobs
run on work-branch pushes, pull requests and manual workflow dispatches. The
server job checks formatting, locked unit tests, public image pins and the real
synthetic CLI/loopback-provider test with independent decryption. The image jobs
build and smoke-test both architectures, then retain local archives and redacted
results for one day. They have read-only repository permissions, no registry
login/push, no secrets, and no release/deployment step.

The added jobs run only for a public repository and use the standard
`ubuntu-24.04` and `ubuntu-24.04-arm` labels. GitHub documents these as
[standard public-repository runners](https://docs.github.com/en/actions/reference/runners/github-hosted-runners#standard-github-hosted-runners-for-public-repositories),
whose use is free; no larger runner is selected. All used actions are full
commit pins recorded in `images/base-pins.json`. The inherited release/cron jobs
remain guarded to `github.repository == 'mollyim/mollysocket'`.

An absent Actions run is NOT RUN, not PASS. This lane does not change repository
settings to enable workflows. Orchestrator 1 owns the image and server CI;
Orchestrator 3 chooses deployment and combined-system checks against explicit
candidate pins.
