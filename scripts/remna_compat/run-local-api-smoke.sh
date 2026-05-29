#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/../.." && pwd)"
cd "${REPO_ROOT}"

FIXTURE="${REPO_ROOT}/tests/fixtures/remna/remnawave_node_minimal_61000.json"
ADDR="127.0.0.1:61000"
PORT="61000"
RPC="xray.app.stats.command.StatsService/GetSysStats"
PROTO_ARGS=(
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

BIN="${CARGO_BIN_EXE_rust_xray:-${REPO_ROOT}/target/release/xray}"
if [[ ! -x "${BIN}" ]]; then
  BIN="${REPO_ROOT}/target/debug/xray"
fi
if [[ ! -x "${BIN}" ]]; then
  echo "Building xray binary..."
  cargo build --bin xray --release
  BIN="${REPO_ROOT}/target/release/xray"
fi

echo "Starting local API smoke: ${BIN} -config ${FIXTURE}"
"${BIN}" -config "${FIXTURE}" -format json &
PID=$!
trap 'kill "${PID}" 2>/dev/null || true' EXIT

deadline=$((SECONDS + 15))
while (( SECONDS < deadline )); do
  if command -v ss >/dev/null 2>&1 && ss -lnt 2>/dev/null | grep -q ":${PORT}\\b"; then
    break
  fi
  if (echo >/dev/tcp/127.0.0.1/"${PORT}") 2>/dev/null; then
    break
  fi
  if ! kill -0 "${PID}" 2>/dev/null; then
    fail "rust-xray exited before port ${PORT} was ready (check stderr above)"
  fi
  sleep 0.2
done

if ! (echo >/dev/tcp/127.0.0.1/"${PORT}") 2>/dev/null; then
  fail "port ${PORT} did not become ready within 15s"
fi
pass "listener ready on ${ADDR}"

if ! command -v grpcurl >/dev/null 2>&1; then
  echo "SKIP grpcurl GetSysStats (install grpcurl for full smoke; cargo tests cover tonic client)"
  pass "local API smoke (listener only)"
  exit 0
fi

if grpcurl -plaintext -max-time 5 "${PROTO_ARGS[@]}" -d '{}' "${ADDR}" "${RPC}" >/dev/null; then
  pass "GetSysStats via grpcurl"
else
  fail "GetSysStats via grpcurl on ${ADDR}"
fi

echo "All local API smoke checks passed"
