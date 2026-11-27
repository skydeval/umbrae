#!/bin/sh
# A reference spaces PDS for testing a real managing app (prism) live.
# Run on the build machine from the workspace root:
#   PRISM_UPSTREAM=http://<prism container>:<port> sh scripts/prism-harness.sh up
#   sh scripts/prism-harness.sh down
#
# `up` starts, on the private Docker network umbrae-prism:
# - the reference PDS at http://pds.interop.test:3000;
# - the mock PLC directory at http://umbrae-prism-harness:2582, which the
#   app under test must use too;
# - a TLS front at https://$PRISM_HOST, signed by a throwaway CA the PDS
#   trusts, that proxies everything to $PRISM_UPSTREAM. The PDS fetches the
#   app's did:web document and its OAuth client metadata (JWKS) through it,
#   and sends checkAccess there.
# It then creates a writer, a member and an outsider. The writer gets a
# community space naming did:web:$PRISM_HOST#$PRISM_SERVICE with one post,
# and the fixture is printed and kept in $STATE_DIR/prism-fixture.json.
#
# The app under test joins the network itself, for example:
#   docker network connect umbrae-prism <prism container>
# Everything stays up until `down`. Never point this at a public service.
set -u

NET=umbrae-prism
PDS=umbrae-prism-pds
HARNESS=umbrae-prism-harness
FRONT=umbrae-prism-front
IMAGE=ghcr.io/bluesky-social/atproto:pds-spaces-alpha
RUST=rust:1.90-bookworm
NGINX=nginx:1.27-alpine
PDS_HOST=pds.interop.test
PRISM_HOST=${PRISM_HOST:-prism.interop.test}
PRISM_SERVICE=${PRISM_SERVICE:-umbrae_app}
PRISM_KEY=${PRISM_KEY:-interop}
STATE_DIR=${STATE_DIR:-$HOME/umbrae-prism-harness}
here=$(cd "$(dirname "$0")/.." && pwd)

down() {
	docker rm -f "$PDS" "$HARNESS" "$FRONT" >/dev/null 2>&1
	docker network rm "$NET" >/dev/null 2>&1
	# The harness wrote the fixture as root.
	[ -d "$STATE_DIR" ] && docker run --rm -v "$STATE_DIR":/s "$NGINX" rm -rf /s/out >/dev/null 2>&1
	rm -rf "$STATE_DIR"
	return 0
}

case "${1:-}" in
down)
	down
	echo "== down"
	exit 0
	;;
up) ;;
*)
	echo "usage: PRISM_UPSTREAM=http://host:port sh scripts/prism-harness.sh up | down" >&2
	exit 2
	;;
esac

if [ -z "${PRISM_UPSTREAM:-}" ]; then
	echo "PRISM_UPSTREAM is required, e.g. http://prism-under-test:8080" >&2
	exit 2
fi

down
mkdir -p "$STATE_DIR/out" || exit 1
chmod 777 "$STATE_DIR/out"

# A CA for this run only, and a certificate for the app's host.
openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 -nodes \
	-keyout "$STATE_DIR/ca.key" -out "$STATE_DIR/ca.pem" -days 7 -subj "/CN=prism harness CA" 2>/dev/null || exit 1
openssl req -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 -nodes \
	-keyout "$STATE_DIR/front.key" -out "$STATE_DIR/front.csr" -subj "/CN=$PRISM_HOST" 2>/dev/null || exit 1
printf 'subjectAltName=DNS:%s\n' "$PRISM_HOST" >"$STATE_DIR/ext"
openssl x509 -req -in "$STATE_DIR/front.csr" -CA "$STATE_DIR/ca.pem" -CAkey "$STATE_DIR/ca.key" \
	-CAcreateserial -out "$STATE_DIR/front.pem" -days 7 -extfile "$STATE_DIR/ext" 2>/dev/null || exit 1
cat >"$STATE_DIR/nginx.conf" <<EOF
server {
	listen 443 ssl;
	server_name $PRISM_HOST;
	ssl_certificate /certs/front.pem;
	ssl_certificate_key /certs/front.key;
	# Resolved per request, as the app may join the network later.
	resolver 127.0.0.11 valid=10s;
	set \$upstream $PRISM_UPSTREAM;
	location / {
		proxy_pass \$upstream;
		proxy_set_header Host $PRISM_HOST;
		proxy_set_header X-Forwarded-Proto https;
	}
}
EOF

docker network create "$NET" >/dev/null || exit 1
echo "== image $(docker image inspect --format '{{index .Config.Labels "org.opencontainers.image.revision"}}' "$IMAGE")"

docker run -d --name "$FRONT" --network "$NET" --network-alias "$PRISM_HOST" \
	-v "$STATE_DIR/nginx.conf":/etc/nginx/conf.d/default.conf:ro \
	-v "$STATE_DIR/front.pem":/certs/front.pem:ro \
	-v "$STATE_DIR/front.key":/certs/front.key:ro \
	"$NGINX" >/dev/null || { down; exit 1; }

docker run -d --name "$PDS" --network "$NET" --network-alias "$PDS_HOST" \
	-v "$STATE_DIR/ca.pem":/interop-ca.pem:ro \
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
	"$IMAGE" >/dev/null || { down; exit 1; }

echo "== fixture"
docker run -d --name "$HARNESS" --network "$NET" \
	-v "$here":/w -w /w \
	-v umbrae-interop-cargo:/usr/local/cargo/registry \
	-v umbrae-interop-target:/w/target \
	-v "$STATE_DIR/out":/out \
	-e HARNESS_MODE=prism \
	-e OUT_DIR=/out \
	-e PRISM_APP="did:web:$PRISM_HOST#$PRISM_SERVICE" \
	-e PRISM_KEY="$PRISM_KEY" \
	-e PDS_URL="http://$PDS_HOST:3000" \
	"$RUST" cargo run --locked -q -p umbrae-interop >/dev/null || { down; exit 1; }

# Wait for the fixture: the first run compiles, so allow a while.
i=0
while [ ! -s "$STATE_DIR/out/prism-fixture.json" ]; do
	if ! docker ps -q -f name="^$HARNESS\$" | grep -q .; then
		echo "fixture failed:" >&2
		docker logs "$HARNESS" 2>&1 | tail -20 >&2
		down
		exit 1
	fi
	i=$((i + 1))
	if [ "$i" -gt 600 ]; then
		echo "fixture not ready after 600 s" >&2
		exit 1
	fi
	sleep 1
done
cat "$STATE_DIR/out/prism-fixture.json"
echo
echo "== up: network $NET, PDS http://$PDS_HOST:3000, PLC http://$HARNESS:2582, front https://$PRISM_HOST -> $PRISM_UPSTREAM"
echo "== CA for the app to trust, if it calls its own front: $STATE_DIR/ca.pem; PDS log: docker logs $PDS"
