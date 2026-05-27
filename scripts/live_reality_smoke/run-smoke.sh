#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/../.." && pwd)"

CLIENT_TEMPLATE="${SCRIPT_DIR}/xray-client.template.json"
SERVER_CONFIG="${SERVER_CONFIG:-${SCRIPT_DIR}/rust-xray-server.fixture.json}"
GENERATED_CLIENT="/tmp/rust-xray-live-xray-client.json"

if [[ ! -f "${CLIENT_TEMPLATE}" ]]; then
  echo "error: missing client template: ${CLIENT_TEMPLATE}" >&2
  exit 1
fi

if [[ ! -f "${SERVER_CONFIG}" ]]; then
  echo "error: missing server config: ${SERVER_CONFIG}" >&2
  exit 1
fi

if [[ -z "${TEST_PUBLIC_KEY:-}" ]]; then
  echo "error: TEST_PUBLIC_KEY is not set" >&2
  echo >&2
  echo "Export the REALITY public key that matches privateKey in" >&2
  echo "scripts/live_reality_smoke/rust-xray-server.fixture.json, then rerun:" >&2
  echo "  TEST_PUBLIC_KEY='<public key>' bash scripts/live_reality_smoke/run-smoke.sh" >&2
  echo >&2
  echo "For the committed smoke fixture, see scripts/live_reality_smoke/README.md." >&2
  exit 1
fi

require_command() {
  local name="$1"
  if ! command -v "${name}" >/dev/null 2>&1; then
    echo "error: required command not found in PATH: ${name}" >&2
    exit 1
  fi
}

require_command cargo
require_command xray
require_command curl

sed "s/__TEST_PUBLIC_KEY__/${TEST_PUBLIC_KEY}/g" "${CLIENT_TEMPLATE}" > "${GENERATED_CLIENT}"

cat <<EOF

Live REALITY smoke test — run these commands manually in separate terminals.

For the automated compatibility/stress suite (recommended before merge):
  bash ${SCRIPT_DIR}/run-live-smoke.sh

Generated client config:
  ${GENERATED_CLIENT}

WARNING: Manual local smoke test only. Test keys only. Not for production.

Terminal 1 — rust-xray server (from repo root):
  cd ${REPO_ROOT}
  RUST_LOG=debug cargo run --bin rust-xray -- ${SERVER_CONFIG}

Optional: use the Xray-compatible server fixture instead:
  SERVER_CONFIG=${SCRIPT_DIR}/xray-compatible-server.fixture.json \\
    TEST_PUBLIC_KEY='${TEST_PUBLIC_KEY}' bash ${SCRIPT_DIR}/run-smoke.sh

Terminal 2 — Xray client:
  xray run -config ${GENERATED_CLIENT}

Terminal 3 — trigger traffic through SOCKS:
  curl -x socks5h://127.0.0.1:10808 https://example.com/ -m 10 -v

REALITY client fields must match the server config:
  - publicKey  ↔ privateKey in rust-xray-server.fixture.json
  - shortId    ↔ server shortIds
  - serverName ↔ server serverNames

EOF
