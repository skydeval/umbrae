#!/bin/sh
# Interop run: the reference spaces PDS against a syncer built on
# umbrae-core. Run it on the build machine from the workspace root:
#   sh scripts/interop.sh
#
# Everything runs on a private Docker network with no host ports. The PDS
# resolves DIDs through a mock PLC directory inside the harness, never the
# public one. OAuth client metadata (for client attestations) is served over
# TLS by a static server, with a throwaway CA the PDS is told to trust.
# Containers, the network and the CA are removed afterwards; the PDS log is
# kept in interop-pds.log.
set -u

NET=umbrae-interop
PDS=umbrae-interop-pds
HARNESS=umbrae-interop-harness
CLIENT=umbrae-interop-client
IMAGE=ghcr.io/bluesky-social/atproto:pds-spaces-alpha
RUST=rust:1.90-bookworm
NGINX=nginx:1.27-alpine
# The PDS wants a hostname with at least two segments; it gets one as a
# network alias.
PDS_HOST=pds.interop.test
CLIENT_HOST=client.interop.test
here=$(cd "$(dirname "$0")/.." && pwd)
tmp=$(mktemp -d)

cleanup() {
	docker rm -f "$PDS" "$HARNESS" "$CLIENT" >/dev/null 2>&1
	docker network rm "$NET" >/dev/null 2>&1
	return 0
}
cleanup

# A CA for this run only, and a certificate for the client host.
openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 -nodes \
	-keyout "$tmp/ca.key" -out "$tmp/ca.pem" -days 1 -subj "/CN=interop CA" 2>/dev/null || exit 1
openssl req -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 -nodes \
	-keyout "$tmp/client.key" -out "$tmp/client.csr" -subj "/CN=$CLIENT_HOST" 2>/dev/null || exit 1
printf 'subjectAltName=DNS:%s\n' "$CLIENT_HOST" >"$tmp/ext"
openssl x509 -req -in "$tmp/client.csr" -CA "$tmp/ca.pem" -CAkey "$tmp/ca.key" -CAcreateserial \
	-out "$tmp/client.pem" -days 1 -extfile "$tmp/ext" 2>/dev/null || exit 1
mkdir -m 755 "$tmp/client"
cat >"$tmp/nginx.conf" <<EOF
server {
	listen 443 ssl;
	server_name $CLIENT_HOST;
	ssl_certificate /certs/client.pem;
	ssl_certificate_key /certs/client.key;
	root /client;
}
EOF

docker network create "$NET" >/dev/null || exit 1
echo "== image $(docker image inspect --format '{{index .Config.Labels "org.opencontainers.image.revision"}}' "$IMAGE")"

docker run -d --name "$CLIENT" --network "$NET" --network-alias "$CLIENT_HOST" \
	-v "$tmp/nginx.conf":/etc/nginx/conf.d/default.conf:ro \
	-v "$tmp/client.pem":/certs/client.pem:ro \
	-v "$tmp/client.key":/certs/client.key:ro \
	-v "$tmp/client":/client:ro \
	"$NGINX" >/dev/null || { cleanup; exit 1; }

docker run -d --name "$PDS" --network "$NET" --network-alias "$PDS_HOST" \
	-v "$tmp/ca.pem":/interop-ca.pem:ro \
	-e NODE_EXTRA_CA_CERTS=/interop-ca.pem \
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
	-v "$tmp/client":/client \
	-e CLIENT_DIR=/client \
	-e PDS_URL="http://$PDS_HOST:3000" \
	"$RUST" cargo run --locked -q -p umbrae-interop
status=$?

docker logs "$PDS" >"$here/interop-pds.log" 2>&1
cleanup
# The harness wrote client metadata as root.
docker run --rm -v "$tmp":/t "$NGINX" rm -rf /t/client >/dev/null 2>&1
rm -rf "$tmp"
echo "== interop exit $status (PDS log: interop-pds.log)"
exit $status
