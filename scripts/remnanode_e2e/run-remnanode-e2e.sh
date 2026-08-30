#!/usr/bin/env bash
# Stage 8D-L: RemnaNode 3.3.2 live E2E (Linux + Docker required).
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
REMNANODE_IMAGE="${REMNANODE_IMAGE:-ghcr.io/remnawave/node:3.3.2}"
RUST_XRAY_BIN="${RUST_XRAY_BIN:-$ROOT/target/release/rust-xray}"
REPORT_DIR="${REPORT_DIR:-/tmp/rust-xray-remnanode-e2e}"
CONTAINER_NAME="${CONTAINER_NAME:-rust-xray-remnanode-e2e}"
NODE_PORT="${NODE_PORT:-2222}"
SECRET_KEY="${SECRET_KEY:-}"

fail() {
  echo "FAIL: $*" >&2
  exit 1
}

require_linux_docker() {
  [[ "$(uname -s)" == "Linux" ]] || fail "RemnaNode abstract-unix E2E requires Linux (got $(uname -s))"
  command -v docker >/dev/null 2>&1 || fail "docker not available"
  docker info >/dev/null 2>&1 || fail "docker daemon not running"
}

mkdir -p "$REPORT_DIR"
RUST_SHA="$(git -C "$ROOT" rev-parse HEAD)"
echo "rust_xray_sha=$RUST_SHA" >"$REPORT_DIR/report.env"

require_linux_docker

echo "== build rust-xray =="
cargo build --release --manifest-path "$ROOT/Cargo.toml" -q
[[ -x "$RUST_XRAY_BIN" ]] || fail "missing binary: $RUST_XRAY_BIN"
echo "rust_xray_bin=$RUST_XRAY_BIN" >>"$REPORT_DIR/report.env"

echo "== pull RemnaNode 3.3.2 =="
docker pull "$REMNANODE_IMAGE" | tee "$REPORT_DIR/docker-pull.log"
docker image inspect "$REMNANODE_IMAGE" >"$REPORT_DIR/image-inspect.json"
DIGEST="$(python3 - <<'PY' "$REPORT_DIR/image-inspect.json"
import json, sys
data = json.load(open(sys.argv[1]))
print((data[0].get("RepoDigests") or ["unknown"])[0])
PY
)"
echo "remnanode_image=$REMNANODE_IMAGE" >>"$REPORT_DIR/report.env"
echo "remnanode_digest=$DIGEST" >>"$REPORT_DIR/report.env"

if [[ -z "$SECRET_KEY" ]]; then
  fail "SECRET_KEY env required (valid Remna node payload JWT)"
fi

docker rm -f "$CONTAINER_NAME" >/dev/null 2>&1 || true

echo "== start RemnaNode with rust-xray mounted over /usr/local/bin/xray =="
docker run -d \
  --name "$CONTAINER_NAME" \
  --network host \
  --cap-add NET_ADMIN \
  --ulimit nofile=1048576:1048576 \
  -e NODE_PORT="$NODE_PORT" \
  -e SECRET_KEY="$SECRET_KEY" \
  -v "$RUST_XRAY_BIN:/usr/local/bin/xray:ro" \
  "$REMNANODE_IMAGE" >/dev/null

cleanup() {
  docker rm -f "$CONTAINER_NAME" >/dev/null 2>&1 || true
}
trap cleanup EXIT

echo "== wait for Node/xray startup =="
sleep 15
docker logs "$CONTAINER_NAME" >"$REPORT_DIR/node.log" 2>&1 || true

echo "== verify rust-xray is the active core =="
docker exec "$CONTAINER_NAME" sh -lc 'ls -l /usr/local/bin/xray /usr/local/bin/rw-core; /usr/local/bin/rw-core version | head -1' \
  | tee "$REPORT_DIR/core-version.log"

echo "== capture runtime env/socket names =="
docker exec "$CONTAINER_NAME" sh -lc 'cat /run/s6/container_environment/INTERNAL_SOCKET_PATH /run/s6/container_environment/XTLS_API_SOCKET_PATH' \
  | tee "$REPORT_DIR/socket-names.txt"

INTERNAL_SOCKET="$(sed -n '1p' "$REPORT_DIR/socket-names.txt")"
XTLS_SOCKET="$(sed -n '2p' "$REPORT_DIR/socket-names.txt")"
echo "internal_socket_name=$INTERNAL_SOCKET" >>"$REPORT_DIR/report.env"
echo "xtls_api_socket_name=$XTLS_SOCKET" >>"$REPORT_DIR/report.env"

echo "== capture generated config via internal HTTP (inside container) =="
docker exec "$CONTAINER_NAME" sh -lc "
  TOKEN=\$(cat /run/s6/container_environment/INTERNAL_REST_TOKEN)
  printf 'GET /internal/get-config?token=%s HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n' \"\$TOKEN\" \
    | socat - UNIX-CONNECT:@\${INTERNAL_SOCKET_PATH} \
    | awk 'found{print} /^\\r$/{found=1}' \
" >"$REPORT_DIR/generated-config.json" || true
CONFIG_HASH="$(sha256sum "$REPORT_DIR/generated-config.json" | awk '{print $1}')"
echo "generated_config_hash=$CONFIG_HASH" >>"$REPORT_DIR/report.env"

echo "== socket proofs =="
docker exec "$CONTAINER_NAME" sh -lc 'ss -xlpn' >"$REPORT_DIR/ss-xlpn.txt" 2>&1 || true
docker exec "$CONTAINER_NAME" sh -lc 'ss -ltnp' >"$REPORT_DIR/ss-ltnp.txt" 2>&1 || true
if grep -q ':61000' "$REPORT_DIR/ss-ltnp.txt" && grep -q 'xray\|rw-core\|rust-xray' "$REPORT_DIR/ss-ltnp.txt"; then
  fail "rust-xray API listener found on TCP 61000"
fi
echo "tcp_61000_listener=false" >>"$REPORT_DIR/report.env"
grep -F "@${XTLS_SOCKET}" "$REPORT_DIR/ss-xlpn.txt" >/dev/null \
  || fail "abstract XTLS API socket @${XTLS_SOCKET} not found in ss -xlpn"

echo "== Node health (requires reachable panel TLS + SECRET_KEY) =="
# TODO: invoke Node REST health once SECRET_KEY/profile wiring is documented for CI.
echo "get_sys_stats=manual_followup" >>"$REPORT_DIR/report.env"

python3 - <<'PY' "$REPORT_DIR/report.env" "$REPORT_DIR/report.json"
import json, sys
report = {}
for line in open(sys.argv[1]):
    line = line.strip()
    if not line or "=" not in line:
        continue
    k, v = line.split("=", 1)
    report[k] = v
json.dump(report, open(sys.argv[2], "w"), indent=2)
print(json.dumps(report, indent=2))
PY

echo "report_dir=$REPORT_DIR"
echo "Stage 8D-L harness finished (extend with Handler/Stats/Routing Node REST proofs)"
