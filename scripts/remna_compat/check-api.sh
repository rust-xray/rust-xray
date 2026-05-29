#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/../.." && pwd)"

ADDR="${1:-127.0.0.1:61000}"
HOST="${ADDR%:*}"
PORT="${ADDR##*:}"
LIST_RPC="xray.app.stats.command.StatsService/GetSysStats"
GRPCURL_PROTO_ARGS=(
  -import-path "${REPO_ROOT}/proto"
  -proto app/stats/command/command.proto
)

fail() {
  echo "FAIL $1"
  exit 1
}

pass() {
  echo "PASS $1"
}

warn() {
  echo "WARN $1"
}

if ! command -v grpcurl >/dev/null 2>&1; then
  fail "grpcurl not found in PATH"
fi

echo "Checking Xray-compatible API at ${ADDR} (plaintext gRPC)..."

echo "Listener check (${ADDR})..."
if command -v ss >/dev/null 2>&1; then
  if ss -lntp 2>/dev/null | grep -E ":${PORT}\\b" >/dev/null; then
    pass "ss shows a listener on port ${PORT}"
    ss -lntp 2>/dev/null | grep -E ":${PORT}\\b" || true
  else
    warn "no listener on port ${PORT} in ss -lntp (API may not be running yet)"
  fi
elif command -v netstat >/dev/null 2>&1; then
  if netstat -lntp 2>/dev/null | grep -E ":${PORT}\\b" >/dev/null; then
    pass "netstat shows a listener on port ${PORT}"
    netstat -lntp 2>/dev/null | grep -E ":${PORT}\\b" || true
  else
    warn "no listener on port ${PORT} in netstat -lntp"
  fi
else
  warn "ss/netstat not available; skipping local listener probe"
fi

LIST_OUT="$(mktemp)"
LIST_ERR="$(mktemp)"
TLS_ERR="$(mktemp)"
trap 'rm -f "${LIST_OUT}" "${LIST_ERR}" "${TLS_ERR}"' EXIT

if grpcurl -plaintext -max-time 3 "${ADDR}" list >"${LIST_OUT}" 2>"${LIST_ERR}"; then
  pass "grpcurl -plaintext list"
  if grep -Fq "xray.app.stats.command.StatsService" "${LIST_OUT}"; then
    pass "StatsService registered (reflection)"
  else
    warn "StatsService not listed (ReflectionService may be disabled in api.services)"
  fi
else
  LIST_MSG="$(cat "${LIST_ERR}")"
  if grep -Eiq 'wrong version number|tls_validate_record_header|SSL|TLS' <<<"${LIST_MSG}"; then
    fail "port is open but not plaintext gRPC; API inbound may have been started as normal proxy inbound (${ADDR})"
  fi
  if grep -Eiq 'connection refused|connect: connection|failed to dial|No connection established|ECONNREFUSED' <<<"${LIST_MSG}"; then
    fail "API listener is not running; check CLI http+unix config loading and Xray-style API inbound detection (${ADDR})"
  fi
  if grep -Eiq 'does not support the reflection API' <<<"${LIST_MSG}"; then
    warn "reflection unavailable, but this is not fatal if GetSysStats works"
  else
    fail "grpcurl -plaintext list — ${LIST_MSG}"
  fi
fi

if command -v grpcurl >/dev/null 2>&1; then
  if grpcurl -max-time 2 "${ADDR}" list >/dev/null 2>"${TLS_ERR}"; then
    warn "grpcurl without -plaintext succeeded; API may be TLS-enabled (unexpected for Xray internal API)"
  elif grep -Eiq 'wrong version number|tls_validate_record_header' "${TLS_ERR}"; then
    echo "HINT: grpcurl without -plaintext failed with TLS record error — likely TLS/plaintext mismatch (Remna client TLS vs plaintext API)"
  fi
fi

SYS_OUT="$(mktemp)"
SYS_ERR="$(mktemp)"
trap 'rm -f "${LIST_OUT}" "${LIST_ERR}" "${TLS_ERR}" "${SYS_OUT}" "${SYS_ERR}"' EXIT

if grpcurl -plaintext -max-time 3 "${GRPCURL_PROTO_ARGS[@]}" -d '{}' "${ADDR}" "${LIST_RPC}" >"${SYS_OUT}" 2>"${SYS_ERR}"; then
  pass "GetSysStats"
  if grep -Fq 'uptime' "${SYS_OUT}" || grep -Fq 'Uptime' "${SYS_OUT}"; then
    pass "GetSysStats response shape"
  else
    warn "GetSysStats returned unexpected body: $(cat "${SYS_OUT}")"
  fi
else
  SYS_MSG="$(cat "${SYS_ERR}")"
  if grep -Eiq 'wrong version number|tls_validate_record_header|SSL|TLS' <<<"${SYS_MSG}"; then
    fail "port is open but not plaintext gRPC; API inbound may have been started as normal proxy inbound (${ADDR})"
  fi
  if grep -Eiq 'connection refused|connect: connection|failed to dial|No connection established|ECONNREFUSED' <<<"${SYS_MSG}"; then
    fail "API listener is not running; check CLI http+unix config loading and Xray-style API inbound detection (${ADDR})"
  fi
  if grep -Eiq 'Unimplemented|not implemented' <<<"${SYS_MSG}"; then
    fail "GetSysStats — UNIMPLEMENTED (enable StatsService in api.services)"
  fi
  fail "GetSysStats — ${SYS_MSG}"
fi

echo "All API checks passed for ${ADDR}"
