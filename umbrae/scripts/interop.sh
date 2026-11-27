#!/bin/sh
# Interop run: a spaces PDS against a syncer built on umbrae-core. Run it on
# the build machine from the workspace root:
#   sh scripts/interop.sh                   # the reference PDS
#   PDS_IMPL=crates sh scripts/interop.sh   # atproto-pds (atproto-crates)
#
# PDS_IMPL=crates needs the image scripts/build-atproto-pds.sh builds, at
# the commit pinned there.
#
# Everything runs on a private Docker network with no host ports. The PDS
# resolves DIDs through a mock PLC directory inside the harness, never the
# public one. OAuth client metadata (for client attestations) is served over
# TLS by a static server, with a throwaway CA the PDS is told to trust.
# atproto-pds speaks plain HTTP only for a loopback URL, so the same server
# fronts it as pds.interop.test, over TLS and on plain port 3000. Containers,
# the network and the CA are removed afterwards; the PDS log is kept in
# interop-pds.log.
set -u

PDS_IMPL=${PDS_IMPL:-reference}
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
BACKEND=umbrae-interop-pds-backend
here=$(cd "$(dirname "$0")/.." && pwd)
case "$PDS_IMPL" in
reference) ;;
crates)
	pin=$(sed -n 's/^PIN=//p' "$here/scripts/build-atproto-pds.sh")
	IMAGE=atproto-pds:interop-$(printf '%.10s' "$pin")
	;;
*)
	echo "PDS_IMPL must be reference or crates"
	exit 2
	;;
esac
tmp=$(mktemp -d)
# Read by the harness for the host takedown scenario; this run only.
ADMIN_PW=$(openssl rand -hex 16)

cleanup() {
	docker rm -f "$PDS" "$HARNESS" "$CLIENT" >/dev/null 2>&1
	docker network rm "$NET" >/dev/null 2>&1
	return 0
}
cleanup

# A CA for this run only, and a certificate for the client host (and, for
# atproto-pds, the PDS host).
names="DNS:$CLIENT_HOST"
[ "$PDS_IMPL" = crates ] && names="$names,DNS:$PDS_HOST"
openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 -nodes \
	-keyout "$tmp/ca.key" -out "$tmp/ca.pem" -days 1 -subj "/CN=interop CA" 2>/dev/null || exit 1
openssl req -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 -nodes \
	-keyout "$tmp/client.key" -out "$tmp/client.csr" -subj "/CN=$CLIENT_HOST" 2>/dev/null || exit 1
printf 'subjectAltName=%s\n' "$names" >"$tmp/ext"
openssl x509 -req -in "$tmp/client.csr" -CA "$tmp/ca.pem" -CAkey "$tmp/ca.key" -CAcreateserial \
	-out "$tmp/client.pem" -days 1 -extfile "$tmp/ext" 2>/dev/null || exit 1
chmod 644 "$tmp/ca.pem" "$tmp/client.pem" "$tmp/client.key"
mkdir -m 755 "$tmp/client"
cat >"$tmp/nginx.conf" <<EOF
server {
	listen 443 ssl;
	server_name $CLIENT_HOST;
	ssl_certificate /certs/client.pem;
	ssl_certificate_key /certs/client.key;
	root /client;
	# Space notifications, to the harness. Resolved per request, as the
	# harness starts after this server does.
	resolver 127.0.0.11 valid=10s;
	set \$harness http://$HARNESS:2583;
	location /xrpc/ {
		proxy_pass \$harness;
	}
}
EOF
if [ "$PDS_IMPL" = crates ]; then
	cat >>"$tmp/nginx.conf" <<EOF
server {
	listen 443 ssl;
	listen 3000;
	server_name $PDS_HOST;
	ssl_certificate /certs/client.pem;
	ssl_certificate_key /certs/client.key;
	client_max_body_size 100m;
	resolver 127.0.0.11 valid=10s;
	set \$pds http://$BACKEND:4800;
	location / {
		proxy_pass \$pds;
		proxy_set_header Host $PDS_HOST;
		proxy_set_header X-Forwarded-Proto https;
		proxy_http_version 1.1;
		proxy_set_header Upgrade \$http_upgrade;
		proxy_set_header Connection "upgrade";
	}
}
EOF
fi

docker network create "$NET" >/dev/null || exit 1
if [ "$PDS_IMPL" = crates ]; then
	echo "== atproto-pds $IMAGE, built from $pin"
	front_alias="--network-alias $PDS_HOST"
else
	echo "== image $(docker image inspect --format '{{index .Config.Labels "org.opencontainers.image.revision"}}' "$IMAGE")"
	front_alias=
fi

# shellcheck disable=SC2086
docker run -d --name "$CLIENT" --network "$NET" --network-alias "$CLIENT_HOST" $front_alias \
	-v "$tmp/nginx.conf":/etc/nginx/conf.d/default.conf:ro \
	-v "$tmp/client.pem":/certs/client.pem:ro \
	-v "$tmp/client.key":/certs/client.key:ro \
	-v "$tmp/client":/client:ro \
	"$NGINX" >/dev/null || { cleanup; exit 1; }

if [ "$PDS_IMPL" = crates ]; then
	docker run -d --name "$PDS" --network "$NET" --network-alias "$BACKEND" \
		-v "$tmp/ca.pem":/interop-ca.pem:ro \
		-e SSL_CERT_FILE=/interop-ca.pem \
		-e PDS_SERVICE_DID="did:web:$PDS_HOST" \
		-e PDS_HOSTNAME="$PDS_HOST" \
		-e PDS_JWT_SECRET="$(openssl rand -hex 32)" \
		-e PDS_ADMIN_PASSWORD="$ADMIN_PW" \
		-e PDS_DID_PLC_URL="http://$HARNESS:2582" \
		-e PDS_INVITE_REQUIRED=false \
		-e PDS_SERVICE_HANDLE_DOMAINS=.test \
		-e PDS_RATE_LIMIT=0 \
		-e PDS_RATE_LIMIT_AUTH=0 \
		-e PDS_RATE_LIMIT_SPACE_WRITE_HOUR=0 \
		-e PDS_RATE_LIMIT_SPACE_WRITE_DAY=0 \
		-e PDS_RATE_LIMIT_NOTIFY_REPO_UPDATE_HOUR=0 \
		-e PDS_RATE_LIMIT_NOTIFY_REPO_UPDATE_DAY=0 \
		-e PDS_TRUSTED_PROXY_HOPS=1 \
		-e RUST_LOG=info \
		"$IMAGE" >/dev/null || { cleanup; exit 1; }
else
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
		-e PDS_ADMIN_PASSWORD="$ADMIN_PW" \
		-e PDS_PLC_ROTATION_KEY_K256_PRIVATE_KEY_HEX="$(openssl rand -hex 32)" \
		-e PDS_DEV_MODE=true \
		-e PDS_INVITE_REQUIRED=false \
		-e PDS_SERVICE_HANDLE_DOMAINS=.test \
		-e PDS_RATE_LIMITS_ENABLED=false \
		-e LOG_ENABLED=true \
		"$IMAGE" >/dev/null || { cleanup; exit 1; }
fi

echo "== harness ($PDS_IMPL)"
docker run --rm --name "$HARNESS" --network "$NET" \
	-v "$here":/w -w /w \
	-v umbrae-interop-cargo:/usr/local/cargo/registry \
	-v umbrae-interop-target:/w/target \
	-v "$tmp/client":/client \
	-e CLIENT_DIR=/client \
	-e PDS_URL="http://$PDS_HOST:3000" \
	-e PDS_IMPL="$PDS_IMPL" \
	-e ADMIN_PW="$ADMIN_PW" \
	"$RUST" cargo run --locked -q -p umbrae-interop
status=$?

docker logs "$PDS" >"$here/interop-pds.log" 2>&1
cleanup
# The harness wrote client metadata as root.
docker run --rm -v "$tmp":/t "$NGINX" rm -rf /t/client >/dev/null 2>&1
rm -rf "$tmp"
echo "== interop ($PDS_IMPL) exit $status (PDS log: interop-pds.log)"
exit $status
