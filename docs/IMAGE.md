# CollieSocket test image and CI

[`Containerfile.colliesocket`](../Containerfile.colliesocket) builds CollieSocket
with MollySocket's executable/configuration interface and upstream AGPL
attribution. It produces a local candidate; building it does not establish
production readiness or Android delivery.

## Pinned build inputs

[`base-pins.json`](../images/base-pins.json) records the builder, runtime,
Dockerfile frontend, BuildKit, Buildx and action pins. The retained registry
manifests bind the index digests and intended `linux/amd64` and `linux/arm64`
platforms. Pin checks verify those inputs; they do not build or execute an image.

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

The image includes `LICENSE.txt` and the sender-helper MIT attribution. OCI
labels identify the AGPL license, canonical repository and exact source commit.

## Reproduce a local candidate

Check out the reviewed source commit on a Linux host with Docker/Buildx and
Python 3. The build script requires a clean committed checkout,
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

The helper exports a local Docker archive with timestamp rewriting,
loads it locally, writes selected build metadata, and runs the isolated smoke
test by immutable image ID. It never pushes an image. `SOURCE_DATE_EPOCH` is the
source commit's timestamp, gzip suppresses its own timestamp, and the build
context comes from `git archive`. Byte-for-byte reproducibility requires
comparing two actual builds. See BuildKit's pinned
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
after a timed-out CLI call. It does not create production identities or test
real Signal, provider or device delivery.

Migration and rollback follow the frozen
[runtime contract](../contracts/encrypted-push/v1/runtime.md): stop before a
complete protected backup; upgrade transactionally; roll back the binary and
matching database backup together. An old binary must not open an upgraded live
database. After restore, disable sending and privately re-enroll with fresh
receiver keys/instance before resuming. Never use the image workflow as an
automatic database rollback mechanism.

## CI

[`test.yml`](../.github/workflows/test.yml) runs on pull requests, manual
workflow dispatches and pushes to `work/encrypted-push-v1`. Its contract job
checks the versioned contracts and independent sender fixtures. The server job
checks formatting, locked unit tests, image pins and synthetic CLI/provider
behavior; the Signal job checks fake-TLS websocket delivery and the absence of
test URL/CA overrides from release builds.

The server, Signal and image jobs require a public repository. Image builds wait
for both server and Signal checks, use native amd64/arm64 runners, and retain
local archives and redacted results for one day. They have read-only repository
permissions and no registry login, image push, release or deployment step.
The inherited release and cron workflows remain restricted to
`mollyim/mollysocket`.

Assess each run at its actual source commit. A missing run supplies no build or
smoke evidence, and passing image checks do not replace deployment or device
acceptance.
