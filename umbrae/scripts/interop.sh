#!/bin/sh
# Interop run: the reference spaces PDS against a syncer built on
# umbrae-core. Run it on the build machine from the workspace root:
#   sh scripts/interop.sh
#
# Everything runs on a private Docker network with no host ports. The PDS
# resolves DIDs through a mock PLC directory inside the harness, never the
# public one. Containers and the network are removed afterwards; the PDS log
# is kept in interop-pds.log.
set -u

NET=umbrae-interop
PDS=umbrae-interop-pds
HARNESS=umbrae-interop-harness
IMAGE=ghcr.io/bluesky-social/atproto:pds-spaces-alpha
RUST=rust:1.90-bookworm
# The PDS wants a hostname with at least two segments; it gets one as a
# network alias.
PDS_HOST=pds.interop.test
here=$(cd "$(dirname "$0")/.." && pwd)

cleanup() {
	docker rm -f "$PDS" "$HARNESS" >/dev/null 2>&1
	docker network rm "$NET" >/dev/null 2>&1
	return 0
}
cleanup

docker network create "$NET" >/dev/null || exit 1
echo "== image $(docker image inspect --format '{{index .Config.Labels "org.opencontainers.image.revision"}}' "$IMAGE")"

docker run -d --name "$PDS" --network "$NET" --network-alias "$PDS_HOST" \
	-e PDS_HOSTNAME="$PDS_HOST" \
	-e PDS_PORT=3000 \
	-e PDS_DATA_DIRECTORY=/app/data \
	-e PDS_BLOBSTORE_DISK_LOCATION=/app/data/blocks \
	-e PDS_DID_PLC_URL="http://$HARNESS:2582" \
	-e PDS_JWT_SECRET="$(openssl rand -hex 16)" \
	-e PDS_DPOP_SECRET="$(openssl rand -hex 32)" \
	-e PDS_ADMIN_PASSWORD="$(openssl rand -hex 16)" \
	-e PDS_PLC_ROTATION_KEY_K256_PRIVATE_KEY_HEX="$(openssl rand -hex 32)" \
	-e PDS_DEV_MODE=true \
	-e PDS_INVITE_REQUIRED=false \
	-e PDS_SERVICE_HANDLE_DOMAINS=.test \
	-e PDS_RATE_LIMITS_ENABLED=false \
	-e LOG_ENABLED=true \
	"$IMAGE" >/dev/null || { cleanup; exit 1; }

echo "== harness"
docker run --rm --name "$HARNESS" --network "$NET" \
	-v "$here":/w -w /w \
	-v umbrae-interop-cargo:/usr/local/cargo/registry \
	-v umbrae-interop-target:/w/target \
	-e PDS_URL="http://$PDS_HOST:3000" \
	"$RUST" cargo run --locked -q -p umbrae-interop
status=$?

docker logs "$PDS" >"$here/interop-pds.log" 2>&1
cleanup
echo "== interop exit $status (PDS log: interop-pds.log)"
exit $status
