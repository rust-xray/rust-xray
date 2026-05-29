#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/../.." && pwd)"

ADDR="${1:-127.0.0.1:61000}"
PORT="${ADDR##*:}"
LIST_RPC="xray.app.stats.command.StatsService/GetSysStats"
GRPCURL_PROTO_ARGS=(
  -import-path "${REPO_ROOT}/proto"
  -proto app/stats/command/command.proto
)

fail() {
  echo "FAIL $1"
  echo "RESULT=${2:-PLAINTEXT_GRPC_FAILED}"
  exit 1
}

warn() {
  echo "WARN $1"
}

pass() {
  echo "PASS $1"
}

if ! command -v grpcurl >/dev/null 2>&1; then
  echo "FAIL grpcurl not found in PATH"
  echo "Install: https://github.com/fullstorydev/grpcurl"
  echo "RESULT=GRPCURL_MISSING"
  exit 2
fi

port_hex() {
  printf '%04X' "${PORT}"
}

listener_present() {
  if command -v ss >/dev/null 2>&1; then
    ss -lnt 2>/dev/null | grep -qE ":${PORT}\\b"
    return
  fi
  if command -v netstat >/dev/null 2>&1; then
    netstat -lnt 2>/dev/null | grep -qE ":${PORT}\\b"
    return
  fi
  local hex
  hex="$(port_hex)"
  if [[ -r /proc/net/tcp ]]; then
    grep -qE ":${hex}" /proc/net/tcp 2>/dev/null && return
  fi
  if [[ -r /proc/net/tcp6 ]]; then
    grep -qE ":${hex}" /proc/net/tcp6 2>/dev/null && return
  fi
  return 1
}

is_tls_wire_error() {
  grep -Eiq 'wrong version number|tls_validate_record_header|first record does not look like a TLS handshake|context deadline exceeded' <<<"$1"
}

is_cert_error() {
  grep -Eiq 'certificate|cert verify|unknown authority|bad certificate|tls: handshake failure|certificate required|authentication handshake failed' <<<"$1"
}

echo "Checking Xray-compatible API at ${ADDR}..."

if listener_present; then
  pass "listener present on port ${PORT}"
else
  fail "no TCP listener on ${PORT}" "API_NOT_LISTENING"
fi

PLAINTEXT_ERR="$(mktemp)"
TLS_INSECURE_ERR="$(mktemp)"
MTLS_ERR="$(mktemp)"
trap 'rm -f "${PLAINTEXT_ERR}" "${TLS_INSECURE_ERR}" "${MTLS_ERR}"' EXIT

PLAINTEXT_OK=0
TLS_OK=0
MTLS_OK=0
TLS_CLIENTHELLO_TO_PLAINTEXT=0

if grpcurl -plaintext -max-time 3 "${GRPCURL_PROTO_ARGS[@]}" -d '{}' "${ADDR}" "${LIST_RPC}" 2>"${PLAINTEXT_ERR}"; then
  PLAINTEXT_OK=1
  pass "grpcurl -plaintext GetSysStats"
  echo "PLAINTEXT_OK"
else
  PL_MSG="$(cat "${PLAINTEXT_ERR}")"
  if is_tls_wire_error "${PL_MSG}"; then
    TLS_CLIENTHELLO_TO_PLAINTEXT=1
    warn "plaintext client saw TLS wire (API likely TLS/mTLS enabled)"
    echo "TLS_CLIENTHELLO_TO_PLAINTEXT"
  elif grep -Eiq 'connection refused|ECONNREFUSED|failed to dial' <<<"${PL_MSG}"; then
    fail "${PL_MSG}" "API_NOT_LISTENING"
  else
    warn "grpcurl -plaintext GetSysStats: ${PL_MSG}"
  fi
fi

if grpcurl -insecure -max-time 3 "${GRPCURL_PROTO_ARGS[@]}" -d '{}' "${ADDR}" "${LIST_RPC}" 2>"${TLS_INSECURE_ERR}"; then
  TLS_OK=1
  pass "grpcurl -insecure GetSysStats (TLS without client cert)"
  echo "TLS_OK"
else
  TLS_MSG="$(cat "${TLS_INSECURE_ERR}")"
  if is_cert_error "${TLS_MSG}"; then
    if grep -Eiq 'certificate required|bad certificate|no client certificate|tls: bad certificate' <<<"${TLS_MSG}"; then
      warn "TLS server requires client certificate"
      echo "CERT_REQUIRED"
    else
      warn "TLS certificate verification failed: ${TLS_MSG}"
      echo "CERT_VERIFY_FAILED"
    fi
  elif is_tls_wire_error "${TLS_MSG}"; then
    warn "TLS client failed against plaintext API: ${TLS_MSG}"
  fi
fi

if [[ -n "${RUST_XRAY_API_TLS_CA:-}" && -n "${RUST_XRAY_API_CLIENT_CERT:-}" && -n "${RUST_XRAY_API_CLIENT_KEY:-}" ]]; then
  if grpcurl \
    -cacert "${RUST_XRAY_API_TLS_CA}" \
    -cert "${RUST_XRAY_API_CLIENT_CERT}" \
    -key "${RUST_XRAY_API_CLIENT_KEY}" \
    -authority internal.remnawave.local \
    -max-time 3 \
    "${GRPCURL_PROTO_ARGS[@]}" -d '{}' "${ADDR}" "${LIST_RPC}" 2>"${MTLS_ERR}"; then
    MTLS_OK=1
    pass "grpcurl mTLS GetSysStats"
    echo "MTLS_OK"
  else
    MT_MSG="$(cat "${MTLS_ERR}")"
    if is_cert_error "${MT_MSG}"; then
      echo "CERT_VERIFY_FAILED"
    fi
    warn "grpcurl mTLS GetSysStats: ${MT_MSG}"
  fi
else
  warn "skip mTLS check (set RUST_XRAY_API_TLS_CA, RUST_XRAY_API_CLIENT_CERT, RUST_XRAY_API_CLIENT_KEY)"
fi

if (( PLAINTEXT_OK )); then
  echo "RESULT=PLAINTEXT_OK"
  exit 0
fi
if (( MTLS_OK )); then
  echo "RESULT=MTLS_OK"
  exit 0
fi
if (( TLS_OK )); then
  echo "RESULT=TLS_OK"
  exit 0
fi
if (( TLS_CLIENTHELLO_TO_PLAINTEXT )); then
  echo "RESULT=TLS_CLIENTHELLO_TO_PLAINTEXT"
  echo "HINT API is TLS/mTLS; Remnawave XTLS-SDK uses ChannelCredentials.createSsl."
  echo "HINT bash scripts/remna_compat/inspect-remna-mtls.sh"
  exit 1
fi

fail "GetSysStats failed for plaintext/TLS/mTLS probes" "API_CHECK_FAILED"
