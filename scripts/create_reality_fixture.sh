#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"

CASE_NAME="${CASE_NAME:-basic-xray}"
SNI="${SNI:-www.microsoft.com}"
LISTEN="${LISTEN:-127.0.0.1:24443}"
USER_ID="${USER_ID:-00000000-0000-0000-0000-000000000001}"

missing=()
[[ -z "${PRIVATE_KEY:-}" ]] && missing+=("PRIVATE_KEY")
[[ -z "${PUBLIC_KEY:-}" ]] && missing+=("PUBLIC_KEY")
[[ -z "${SHORT_ID:-}" ]] && missing+=("SHORT_ID")

if ((${#missing[@]} > 0)); then
  echo "error: required environment variable(s) not set: ${missing[*]}" >&2
  echo >&2
  echo "Generate a REALITY key pair:" >&2
  echo "  xray x25519" >&2
  echo >&2
  echo "Then export variables, for example:" >&2
  echo "  export PRIVATE_KEY='<private key>'" >&2
  echo "  export PUBLIC_KEY='<public key>'" >&2
  echo "  export SHORT_ID='0123456789abcdef'" >&2
  echo "  export CASE_NAME='basic-xray'    # optional, default: basic-xray" >&2
  echo "  export SNI='www.microsoft.com'   # optional, default: www.microsoft.com" >&2
  echo "  export LISTEN='127.0.0.1:24443'  # optional, default: 127.0.0.1:24443" >&2
  echo "  bash scripts/create_reality_fixture.sh" >&2
  exit 1
fi

TEMPLATE="${REPO_ROOT}/tests/fixtures/reality/xray-client-fixture.template.json"
CASE_DIR="${REPO_ROOT}/tests/fixtures/reality/${CASE_NAME}"
CLIENT_HELLO_OUT="${CASE_DIR}/client_hello.bin"
XRAY_CONFIG="/tmp/xray-client-fixture-${CASE_NAME}.json"
CAPTURE_SCRIPT="${REPO_ROOT}/scripts/capture_reality_clienthello.py"

if [[ ! -f "${TEMPLATE}" ]]; then
  echo "error: missing Xray client template: ${TEMPLATE}" >&2
  exit 1
fi

if [[ ! -f "${CAPTURE_SCRIPT}" ]]; then
  echo "error: missing capture script: ${CAPTURE_SCRIPT}" >&2
  exit 1
fi

mkdir -p "${CASE_DIR}"

printf '%s\n' "${PRIVATE_KEY}" > "${CASE_DIR}/server_private_key.txt"

sed \
  -e "s/__SNI__/${SNI}/g" \
  -e "s/__PUBLIC_KEY__/${PUBLIC_KEY}/g" \
  -e "s/__SHORT_ID__/${SHORT_ID}/g" \
  -e "s/__USER_ID__/${USER_ID}/g" \
  "${TEMPLATE}" > "${XRAY_CONFIG}"

cat <<EOF

REALITY fixture setup prepared.

Fixture directory:
  ${CASE_DIR}

Written:
  ${CASE_DIR}/server_private_key.txt
  ${XRAY_CONFIG}

WARNING: Do not commit private keys to a public repository.
         Use throwaway keys for local captures only.

The captor is not a TLS server. Connection failure after capture is expected.

Run these commands manually in separate terminals (from repo root):

Terminal 1 — start the ClientHello captor:
  python3 scripts/capture_reality_clienthello.py \\
    --listen ${LISTEN} \\
    --out ${CLIENT_HELLO_OUT}

Terminal 2 — start the Xray client:
  xray run -config ${XRAY_CONFIG}

Terminal 3 — trigger a connection through SOCKS:
  curl -x socks5h://127.0.0.1:10808 https://example.com/ -m 5 -v

After ${CLIENT_HELLO_OUT} exists, decode expected metadata:
  cargo run --bin decode_reality_fixture -- \\
    tests/fixtures/reality/${CASE_NAME} \\
    --write-expected \\
    --force

Then run the fixture test:
  cargo test --test reality_fixture -- --nocapture

EOF
