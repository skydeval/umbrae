#!/bin/sh
# Build atproto-crates' atproto-pds as a Docker image for the interop
# harness (PDS_IMPL=crates sh scripts/interop.sh). Run it on the build
# machine:
#   sh scripts/build-atproto-pds.sh
#
# The commit is pinned here and moved by hand. The image is tagged
# atproto-pds:interop-<first 10 characters of PIN>; an existing one is kept
# unless REBUILD=1. The clone is a scratch directory, removed afterwards.
# The Rust toolchain is the one in the image's own Dockerfile.
set -u

REPO=https://tangled.org/ngerakines.me/atproto-crates
PIN=4a8b9a4a94454b4a9816963de74c39266bc26b94
short=$(printf '%.10s' "$PIN")
tag=atproto-pds:interop-$short

if [ "${REBUILD:-0}" != 1 ] && docker image inspect "$tag" >/dev/null 2>&1; then
	echo "== $tag exists (REBUILD=1 to build it again)"
	exit 0
fi

tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT
git clone -q "$REPO" "$tmp/src" || exit 1
git -C "$tmp/src" checkout -q "$PIN" || exit 1
echo "== building $tag $(date -u +%FT%TZ)"
DOCKER_BUILDKIT=1 docker build -f "$tmp/src/crates/atproto-pds/Dockerfile" \
	--build-arg BUILD_REV="$short" -t "$tag" "$tmp/src" >"$tmp/build.log" 2>&1
status=$?
tail -5 "$tmp/build.log"
echo "== build exit $status $(date -u +%FT%TZ)"
exit $status
