#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/../.." && pwd)"

# shellcheck source=scripts/live_reality_smoke/smoke-lib.sh
source "${REPO_ROOT}/scripts/live_reality_smoke/smoke-lib.sh"

XRAY_COMPAT_BASELINE="${XRAY_COMPAT_BASELINE:-cd4ce973e9f6ef3a7acf9a7030927b4143f9ea47}"
TEST_PUBLIC_KEY="${TEST_PUBLIC_KEY:-oU1MbEgszawWQJa0S_DxLsNt9G2zyE4rF-CrqvJjTmg}"

SMOKE_SERVER_PORT="${SMOKE_ENC_0RTT_SERVER_PORT:-25443}"
SMOKE_SOCKS_PORT="${SMOKE_ENC_0RTT_SOCKS_PORT:-10818}"
SMOKE_WORK_DIR="${SMOKE_ENC_0RTT_WORK_DIR:-${SMOKE_WORK_DIR:-/tmp/rust-xray-vless-enc-0rtt-smoke-$$}}"
SMOKE_RUST_XRAY_BIN="${SMOKE_RUST_XRAY_BIN:-${RUST_XRAY_BIN:-${REPO_ROOT}/target/release/rust-xray}}"
SMOKE_SKIP_BUILD="${SMOKE_SKIP_BUILD:-0}"
SMOKE_XRAY_BIN="${SMOKE_XRAY_BIN:-${XRAY_BIN:-xray}}"
SMOKE_LOCAL_HTTP_PORT="${SMOKE_ENC_0RTT_HTTP_PORT:-28080}"

SERVER_LOG="${SMOKE_WORK_DIR}/server.log"
CLIENT_LOG="${SMOKE_WORK_DIR}/client.log"
HTTP_LOG="${SMOKE_WORK_DIR}/http.log"
HTTP_PID=""
SERVER_PID=""
CLIENT_PID=""

cleanup() {
  smoke_stop_process "${CLIENT_PID}"
  smoke_stop_process "${SERVER_PID}"
  smoke_stop_process "${HTTP_PID}"
}
trap cleanup EXIT

mkdir -p "${SMOKE_WORK_DIR}"

smoke_require_commands cargo "${SMOKE_XRAY_BIN}" curl python3

if [[ "${SMOKE_SKIP_BUILD}" != "1" ]]; then
  echo "Building release rust-xray..."
  (cd "${REPO_ROOT}" && cargo build --release --bin rust-xray)
fi

smoke_print_binary_identity
echo "xray-core compatibility baseline: ${XRAY_COMPAT_BASELINE}"

python3 -m http.server "${SMOKE_LOCAL_HTTP_PORT}" --bind 127.0.0.1 >"${HTTP_LOG}" 2>&1 &
HTTP_PID=$!
smoke_wait_port 127.0.0.1 "${SMOKE_LOCAL_HTTP_PORT}" "local http echo" 20

CLIENT_CFG="${SMOKE_WORK_DIR}/xray-client-0rtt.json"
SMOKE_TEMPLATE="${SCRIPT_DIR}/xray-client-encryption.fixture.json" \
  SMOKE_OUTPUT="${CLIENT_CFG}" \
  SMOKE_PUBLIC_KEY="${TEST_PUBLIC_KEY}" \
  python3 - <<'PY'
import json
import os
from pathlib import Path

cfg = json.loads(Path(os.environ["SMOKE_TEMPLATE"]).read_text())
cfg["outbounds"][0]["streamSettings"]["realitySettings"]["publicKey"] = os.environ["SMOKE_PUBLIC_KEY"]
enc = cfg["outbounds"][0]["settings"]["vnext"][0]["users"][0]["encryption"]
cfg["outbounds"][0]["settings"]["vnext"][0]["users"][0]["encryption"] = enc.replace(".1rtt.", ".0rtt.", 1)
Path(os.environ["SMOKE_OUTPUT"]).write_text(json.dumps(cfg, indent=2) + "\n")
PY

echo "--- VLESS encryption live 0-RTT: connection 1 (expect 1-RTT) ---"
RUST_LOG="${SMOKE_RUST_LOG:-info}" "${SMOKE_RUST_XRAY_BIN}" \
  "${SCRIPT_DIR}/rust-xray-server.encryption.fixture.json" >"${SERVER_LOG}" 2>&1 &
SERVER_PID=$!
smoke_wait_port 127.0.0.1 "${SMOKE_SERVER_PORT}" "encrypted server" 40
sleep 1

"${SMOKE_XRAY_BIN}" run -config "${CLIENT_CFG}" >"${CLIENT_LOG}" 2>&1 &
CLIENT_PID=$!
smoke_wait_port 127.0.0.1 "${SMOKE_SOCKS_PORT}" "xray client" 40
sleep 1

TARGET="http://127.0.0.1:${SMOKE_LOCAL_HTTP_PORT}/"
HTTP1="$(curl -sS -o "${SMOKE_WORK_DIR}/curl1.body" -w '%{http_code}' \
  -x "socks5h://127.0.0.1:${SMOKE_SOCKS_PORT}" -m 30 "${TARGET}" || echo 000)"
echo "curl1 http=${HTTP1}"

if ! grep -q "1-RTT handshake complete" "${SERVER_LOG}"; then
  echo "FAIL: server log missing 1-RTT evidence" >&2
  tail -n 40 "${SERVER_LOG}" >&2
  exit 1
fi

echo "--- VLESS encryption live 0-RTT: connection 2 (expect 0-RTT resume, same xray process) ---"
HTTP2="$(curl -sS -o "${SMOKE_WORK_DIR}/curl2.body" -w '%{http_code}' \
  -x "socks5h://127.0.0.1:${SMOKE_SOCKS_PORT}" -m 30 "${TARGET}" || echo 000)"
echo "curl2 http=${HTTP2}"

smoke_stop_process "${CLIENT_PID}"
smoke_stop_process "${SERVER_PID}"
CLIENT_PID=""
SERVER_PID=""

if [[ "${HTTP1}" != "200" || "${HTTP2}" != "200" ]]; then
  echo "FAIL: HTTP not 200 (http1=${HTTP1} http2=${HTTP2})" >&2
  tail -n 20 "${CLIENT_LOG}" >&2 || true
  exit 1
fi

if grep -q "0-RTT resume accepted" "${SERVER_LOG}"; then
  echo "PASS: server log proves 0-RTT resume branch"
else
  echo "FAIL: server log missing '0-RTT resume accepted'" >&2
  tail -n 40 "${SERVER_LOG}" >&2
  exit 1
fi

echo "VLESS encryption live 0-RTT native TCP (REALITY): PASS"
exit 0
