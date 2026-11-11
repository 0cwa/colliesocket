#!/usr/bin/env bash
# Build a reviewable local image/archive from one clean committed source tree.
set -euo pipefail
umask 077
if [[ $# != 3 ]]; then
    echo 'Usage: bash tools/image/build.sh linux/amd64|linux/arm64 IMAGE_TAG OUTPUT_DIRECTORY' >&2
    exit 2
fi
platform=$1
image_tag=$2
output_directory=$3
case "$platform" in linux/amd64|linux/arm64) ;; *) echo 'Unsupported platform' >&2; exit 2 ;; esac
case "$image_tag" in ''|-*|*$'\n'*) echo 'Invalid image tag' >&2; exit 2 ;; esac
repo=$(git -C "$(dirname "$0")/../.." rev-parse --show-toplevel)
if [[ -n $(git -C "$repo" status --porcelain --untracked-files=normal) ]]; then
    echo 'Commit the reviewed source before producing an image candidate.' >&2
    exit 1
fi
if ! command -v docker >/dev/null; then
    echo 'NOT RUN: Docker executable unavailable.' >&2
    exit 77
fi
docker_local() {
    env -u DOCKER_HOST -u DOCKER_CONTEXT -u DOCKER_TLS -u DOCKER_TLS_VERIFY -u DOCKER_CERT_PATH \
        docker --host=unix:///var/run/docker.sock "$@"
}
docker_local info >/dev/null
source_commit=$(git -C "$repo" rev-parse HEAD)
source_epoch=$(git -C "$repo" show -s --format=%ct "$source_commit")
mkdir -p "$output_directory"
output_directory=$(realpath "$output_directory")
case "$output_directory/" in "$repo/"*) echo 'Output directory must be outside the checkout.' >&2; exit 2 ;; esac
if [[ -e "$output_directory/image.tar.gz" || -e "$output_directory/image-build.json" ]]; then
    echo 'Refusing to overwrite an existing candidate.' >&2
    exit 1
fi
context=$(mktemp -d)
trap 'rm -rf "$context"' EXIT
git -C "$repo" archive --format=tar "$source_commit" | tar -xf - -C "$context"
python3 "$context/tools/image/check-pins.py"
options=()
if [[ -n ${COLLIESOCKET_BUILDER:-} ]]; then options+=(--builder "$COLLIESOCKET_BUILDER"); fi
if [[ -n ${COLLIESOCKET_BUILD_CA_BUNDLE:-} ]]; then
    [[ -f "$COLLIESOCKET_BUILD_CA_BUNDLE" && -r "$COLLIESOCKET_BUILD_CA_BUNDLE" ]]
    options+=(--secret "id=build_ca,src=$COLLIESOCKET_BUILD_CA_BUNDLE")
fi
docker_local buildx build "${options[@]}" \
    --platform "$platform" --file "$context/Containerfile.colliesocket" \
    --build-arg "SOURCE_COMMIT=$source_commit" \
    --build-arg "SOURCE_DATE_EPOCH=$source_epoch" \
    --provenance=false --sbom=false \
    --tag "$image_tag" --metadata-file "$context/buildx-metadata.json" \
    --output "type=docker,dest=$context/image.tar,rewrite-timestamp=true" \
    "$context"
docker_local image load --input "$context/image.tar"
gzip -n -c "$context/image.tar" > "$output_directory/image.tar.gz"
python3 "$context/tools/image/metadata.py" \
    --image "$image_tag" --platform "$platform" --source-commit "$source_commit" \
    --source-date-epoch "$source_epoch" --build-metadata "$context/buildx-metadata.json" \
    --archive "$output_directory/image.tar.gz" --output "$output_directory/image-build.json"
image_id=$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["image_configuration_digest"])' "$output_directory/image-build.json")
python3 "$context/tools/image/smoke.py" "$image_id" \
    --platform "$platform" --output "$output_directory/image-smoke.json"
