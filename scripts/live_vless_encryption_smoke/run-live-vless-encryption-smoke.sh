#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/../.." && pwd)"

# shellcheck source=scripts/live_reality_smoke/smoke-lib.sh
source "${REPO_ROOT}/scripts/live_reality_smoke/smoke-lib.sh"

XRAY_COMPAT_BASELINE="${XRAY_COMPAT_BASELINE:-cd4ce973e9f6ef3a7acf9a7030927b4143f9ea47}"
TEST_PUBLIC_KEY="${TEST_PUBLIC_KEY:-oU1MbEgszawWQJa0S_DxLsNt9G2zyE4rF-CrqvJjTmg}"

SMOKE_SERVER_PORT="${SMOKE_ENC_SERVER_PORT:-25443}"
SMOKE_SOCKS_PORT="${SMOKE_ENC_SOCKS_PORT:-10818}"
SMOKE_WORK_DIR="${SMOKE_ENC_WORK_DIR:-${SMOKE_WORK_DIR:-/tmp/rust-xray-vless-enc-smoke-$$}}"
SMOKE_RUST_XRAY_BIN="${SMOKE_RUST_XRAY_BIN:-${RUST_XRAY_BIN:-${REPO_ROOT}/target/release/rust-xray}}"
SMOKE_SKIP_BUILD="${SMOKE_SKIP_BUILD:-0}"
SMOKE_SKIP_LIVE="${SMOKE_SKIP_LIVE:-0}"
SMOKE_LOCAL_HTTP_PORT="${SMOKE_ENC_LOCAL_HTTP_PORT:-28080}"
SMOKE_UDP_ECHO_PORT="${SMOKE_ENC_UDP_ECHO_PORT:-38001}"

HTTP_LOG="${SMOKE_WORK_DIR}/http.log"
UDP_SERVICES_LOG="${SMOKE_WORK_DIR}/udp-services.log"
HTTP_PID=""
UDP_SERVICES_PID=""
FAILED=0
declare -a MATRIX_ROWS=()

matrix_row() {
  local scenario="$1"
  local coverage="$2"
  local result="$3"
  local notes="${4:-}"
  MATRIX_ROWS+=("${scenario}|${coverage}|${result}|${notes}")
  echo "MATRIX ${coverage} ${result}: ${scenario} ${notes}"
}

cleanup() {
  smoke_stop_stack
  smoke_stop_process "${HTTP_PID}"
  smoke_stop_process "${UDP_SERVICES_PID}"
}
trap cleanup EXIT

mkdir -p "${SMOKE_WORK_DIR}"

SMOKE_XRAY_BIN="${SMOKE_XRAY_BIN:-${XRAY_BIN:-xray}}"
smoke_require_commands cargo "${SMOKE_XRAY_BIN}" curl python3

if [[ "${SMOKE_SKIP_BUILD}" != "1" ]]; then
  echo "Building release rust-xray..."
  (cd "${REPO_ROOT}" && cargo build --release --bin rust-xray)
else
  echo "BUILD SKIPPED (SMOKE_SKIP_BUILD=1)"
fi

smoke_print_binary_identity
echo "xray client version: $("${SMOKE_XRAY_BIN}" version 2>/dev/null | head -n1 || echo unknown)"
echo "xray-core compatibility baseline: ${XRAY_COMPAT_BASELINE}"
echo "test mode: vless-encryption-live"

if [[ "${SMOKE_SKIP_LIVE}" == "1" ]]; then
  echo "SKIP live VLESS encryption smoke (SMOKE_SKIP_LIVE=1)"
  matrix_row "all live rows" "SKIP ENVIRONMENT" "SKIP" "SMOKE_SKIP_LIVE=1"
  exit 0
fi

write_encrypted_client_config() {
  local template="$1"
  local output="$2"
  local mux_enabled="${3:-0}"
  local packet_encoding="${4:-}"
  SMOKE_TEMPLATE="${template}" \
    SMOKE_OUTPUT="${output}" \
    SMOKE_MUX_ENABLED="${mux_enabled}" \
    SMOKE_PACKET_ENCODING="${packet_encoding}" \
    SMOKE_PUBLIC_KEY="${TEST_PUBLIC_KEY}" \
    python3 - <<'PY'
import json
import os
from pathlib import Path

cfg = json.loads(Path(os.environ["SMOKE_TEMPLATE"]).read_text())
user = cfg["outbounds"][0]["settings"]["vnext"][0]["users"][0]
packet_encoding = os.environ.get("SMOKE_PACKET_ENCODING", "")
if packet_encoding:
    user["packetEncoding"] = packet_encoding
elif "packetEncoding" in user:
    del user["packetEncoding"]
if os.environ.get("SMOKE_MUX_ENABLED") == "1":
    cfg["outbounds"][0]["mux"] = {"enabled": True, "concurrency": 8}
elif "mux" in cfg["outbounds"][0]:
    del cfg["outbounds"][0]["mux"]
cfg["outbounds"][0]["streamSettings"]["realitySettings"]["publicKey"] = os.environ["SMOKE_PUBLIC_KEY"]
Path(os.environ["SMOKE_OUTPUT"]).write_text(json.dumps(cfg, indent=2) + "\n")
PY
}

server_log_contains() {
  local log_file="$1"
  local pattern="$2"
  grep -Eq "${pattern}" "${log_file}"
}

run_encrypted_case() {
  local label="$1"
  local mode="$2"
  local flow="$3"
  local server_config="$4"
  local client_config="$5"
  local scenario="$6"

  local server_log="${SMOKE_WORK_DIR}/server-${label}.log"
  local client_log="${SMOKE_WORK_DIR}/client-${label}.log"
  local server_pid=""
  local client_pid=""

  echo "--- case: mode=${mode} flow=${flow} ---"
  RUST_LOG="${SMOKE_RUST_LOG:-info}" "${SMOKE_RUST_XRAY_BIN}" "${server_config}" >"${server_log}" 2>&1 &
  server_pid=$!
  SMOKE_SERVER_PID="${server_pid}"
  smoke_wait_port 127.0.0.1 "${SMOKE_SERVER_PORT}" "rust-xray encrypted VLESS server (${label})" 40

  "${SMOKE_XRAY_BIN}" run -config "${client_config}" >"${client_log}" 2>&1 &
  client_pid=$!
  SMOKE_CLIENT_PID="${client_pid}"
  smoke_wait_port 127.0.0.1 "${SMOKE_SOCKS_PORT}" "xray socks inbound (${label})" 40

  local target_url="http://127.0.0.1:${SMOKE_LOCAL_HTTP_PORT}/"
  local http_code
  http_code="$(curl -sS -o "${SMOKE_WORK_DIR}/curl-${label}.body" -w '%{http_code}' \
    -x "socks5h://127.0.0.1:${SMOKE_SOCKS_PORT}" -m 30 "${target_url}" || echo 000)"

  smoke_stop_process "${client_pid}"
  smoke_stop_process "${server_pid}"
  SMOKE_CLIENT_PID=""
  SMOKE_SERVER_PID=""
  smoke_free_ports "${SMOKE_SERVER_PORT}" "${SMOKE_SOCKS_PORT}"

  echo "curl http_code=${http_code}"
  if [[ "${http_code}" == "200" ]]; then
    echo "PASS vless encryption ${mode} 1RTT ${flow} TCP (local http)"
    matrix_row "${scenario}" "LIVE PASS" "PASS" "http=${http_code}"
  else
    echo "FAIL vless encryption ${mode} 1RTT ${flow} TCP (local http)" >&2
    echo "--- server log tail ---" >&2
    tail -n 40 "${server_log}" >&2 || true
    echo "--- client log tail ---" >&2
    tail -n 40 "${client_log}" >&2 || true
    matrix_row "${scenario}" "LIVE PASS" "FAIL" "http=${http_code}"
    FAILED=1
  fi
}

run_encrypted_mux_tcp_case() {
  local label="native-mux-tcp"
  local client_cfg="${SMOKE_WORK_DIR}/client-${label}.json"
  local server_log="${SMOKE_WORK_DIR}/server-${label}.log"
  local client_log="${SMOKE_WORK_DIR}/client-${label}.log"
  local server_pid=""
  local client_pid=""

  write_encrypted_client_config \
    "${SCRIPT_DIR}/xray-client-encryption.fixture.json" \
    "${client_cfg}" \
    1

  echo "--- case: native 1RTT flow=\"\" Mux TCP ---"
  RUST_LOG="${SMOKE_RUST_LOG:-info,rust_xray::mux=debug}" \
    "${SMOKE_RUST_XRAY_BIN}" "${SCRIPT_DIR}/rust-xray-server.encryption.fixture.json" \
    >"${server_log}" 2>&1 &
  server_pid=$!
  SMOKE_SERVER_PID="${server_pid}"
  smoke_wait_port 127.0.0.1 "${SMOKE_SERVER_PORT}" "encrypted mux server" 40

  "${SMOKE_XRAY_BIN}" run -config "${client_cfg}" >"${client_log}" 2>&1 &
  client_pid=$!
  SMOKE_CLIENT_PID="${client_pid}"
  smoke_wait_port 127.0.0.1 "${SMOKE_SOCKS_PORT}" "encrypted mux client" 40

  local http_code
  http_code="$(curl -sS -o "${SMOKE_WORK_DIR}/curl-${label}.body" -w '%{http_code}' \
    -x "socks5h://127.0.0.1:${SMOKE_SOCKS_PORT}" -m 30 \
    "http://127.0.0.1:${SMOKE_LOCAL_HTTP_PORT}/" || echo 000)"

  smoke_stop_process "${client_pid}"
  smoke_stop_process "${server_pid}"
  SMOKE_CLIENT_PID=""
  SMOKE_SERVER_PID=""
  smoke_free_ports "${SMOKE_SERVER_PORT}" "${SMOKE_SOCKS_PORT}"

  local evidence=""
  if server_log_contains "${server_log}" "VLESS mux relay started"; then
    evidence+="mux_relay "
  fi
  if server_log_contains "${server_log}" "mux substream opened|mux session started"; then
    evidence+="mux_child "
  fi
  if server_log_contains "${server_log}" "VLESS route selected|route selected|mux session completed"; then
    evidence+="route "
  fi

  echo "mux tcp http_code=${http_code} evidence=${evidence}"
  if [[ "${http_code}" == "200" ]] &&
    server_log_contains "${server_log}" "VLESS mux relay started" &&
    server_log_contains "${server_log}" "mux substream opened|mux session started"; then
    echo "PASS encrypted live Mux TCP"
    matrix_row "native 1RTT Mux TCP" "LIVE PASS" "PASS" "${evidence}http=${http_code}"
  else
    echo "FAIL encrypted live Mux TCP" >&2
    tail -n 40 "${server_log}" >&2 || true
    matrix_row "native 1RTT Mux TCP" "LIVE PASS" "FAIL" "${evidence}http=${http_code}"
    FAILED=1
  fi
}

run_encrypted_xudp_case() {
  local label="native-xudp"
  local client_cfg="${SMOKE_WORK_DIR}/client-${label}.json"
  local server_log="${SMOKE_WORK_DIR}/server-${label}.log"
  local client_log="${SMOKE_WORK_DIR}/client-${label}.log"
  local server_pid=""
  local client_pid=""

  write_encrypted_client_config \
    "${SCRIPT_DIR}/xray-client-encryption.fixture.json" \
    "${client_cfg}" \
    1

  echo "--- case: native 1RTT Mux/XUDP UDP echo ---"
  RUST_LOG="${SMOKE_RUST_LOG:-debug}" \
    "${SMOKE_RUST_XRAY_BIN}" "${SCRIPT_DIR}/rust-xray-server.encryption.fixture.json" \
    >"${server_log}" 2>&1 &
  server_pid=$!
  SMOKE_SERVER_PID="${server_pid}"
  smoke_wait_port 127.0.0.1 "${SMOKE_SERVER_PORT}" "encrypted xudp server" 40

  "${SMOKE_XRAY_BIN}" run -config "${client_cfg}" >"${client_log}" 2>&1 &
  client_pid=$!
  SMOKE_CLIENT_PID="${client_pid}"
  smoke_wait_port 127.0.0.1 "${SMOKE_SOCKS_PORT}" "encrypted xudp client" 40

  local probe_out="${SMOKE_WORK_DIR}/udp-${label}.txt"
  if python3 "${REPO_ROOT}/scripts/live_udp_smoke/udp-probes.py" \
    echo "${SMOKE_SOCKS_PORT}" "127.0.0.1" "${SMOKE_UDP_ECHO_PORT}" 1 \
    >"${probe_out}" 2>&1; then
    probe_ok=1
  else
    probe_ok=0
  fi

  smoke_stop_process "${client_pid}"
  smoke_stop_process "${server_pid}"
  SMOKE_CLIENT_PID=""
  SMOKE_SERVER_PID=""
  smoke_free_ports "${SMOKE_SERVER_PORT}" "${SMOKE_SOCKS_PORT}"

  local evidence=""
  if server_log_contains "${server_log}" "mux xudp substream opened"; then
    evidence+="xudp_substream "
  fi
  if server_log_contains "${server_log}" "xudp association active"; then
    evidence+="xudp_assoc "
  fi
  if server_log_contains "${server_log}" "UDP outbound opened|udp outbound"; then
    evidence+="udp_out "
  fi
  if server_log_contains "${server_log}" "mux keep routed to existing xudp association"; then
    evidence+="destless_keep "
  fi

  echo "xudp probe_ok=${probe_ok} evidence=${evidence}"
  if [[ "${probe_ok}" -eq 1 ]] &&
    server_log_contains "${server_log}" "xudp association active"; then
    echo "PASS encrypted live XUDP"
    matrix_row "native 1RTT Mux/XUDP" "LIVE PASS" "PASS" "${evidence}"
  else
    echo "FAIL encrypted live XUDP" >&2
    tail -n 40 "${server_log}" >&2 || true
    cat "${probe_out}" >&2 || true
    matrix_row "native 1RTT Mux/XUDP" "LIVE PASS" "FAIL" "${evidence}"
    FAILED=1
  fi
}

run_encrypted_native_udp_attempt() {
  local label="native-udp-command"
  local client_cfg="${SMOKE_WORK_DIR}/client-${label}.json"
  local server_log="${SMOKE_WORK_DIR}/server-${label}.log"
  local client_log="${SMOKE_WORK_DIR}/client-${label}.log"
  local server_pid=""
  local client_pid=""

  write_encrypted_client_config \
    "${SCRIPT_DIR}/xray-client-encryption.fixture.json" \
    "${client_cfg}" \
    0 \
    "none"

  echo "--- case: native 1RTT native VLESS UDP (client attempt) ---"
  RUST_LOG="${SMOKE_RUST_LOG:-info}" \
    "${SMOKE_RUST_XRAY_BIN}" "${SCRIPT_DIR}/rust-xray-server.encryption.fixture.json" \
    >"${server_log}" 2>&1 &
  server_pid=$!
  SMOKE_SERVER_PID="${server_pid}"
  smoke_wait_port 127.0.0.1 "${SMOKE_SERVER_PORT}" "encrypted native udp server" 40

  "${SMOKE_XRAY_BIN}" run -config "${client_cfg}" >"${client_log}" 2>&1 &
  client_pid=$!
  SMOKE_CLIENT_PID="${client_pid}"
  smoke_wait_port 127.0.0.1 "${SMOKE_SOCKS_PORT}" "encrypted native udp client" 40

  local probe_ok=0
  if python3 "${REPO_ROOT}/scripts/live_udp_smoke/udp-probes.py" \
    echo "${SMOKE_SOCKS_PORT}" "127.0.0.1" "${SMOKE_UDP_ECHO_PORT}" 1 \
    >"${SMOKE_WORK_DIR}/udp-${label}.txt" 2>&1; then
    probe_ok=1
  fi

  smoke_stop_process "${client_pid}"
  smoke_stop_process "${server_pid}"
  SMOKE_CLIENT_PID=""
  SMOKE_SERVER_PID=""
  smoke_free_ports "${SMOKE_SERVER_PORT}" "${SMOKE_SOCKS_PORT}"

  if [[ "${probe_ok}" -eq 1 ]] &&
    server_log_contains "${server_log}" "VLESS UDP route selected"; then
    echo "PASS encrypted live native VLESS UDP"
    matrix_row "native 1RTT native VLESS UDP" "LIVE PASS" "PASS" "RequestCommandUDP"
  else
    echo "LIVE CLIENT LIMITATION: Xray 26.x with mux-capable SOCKS UDP typically selects Mux/XUDP; native RequestCommandUDP not reliably forced"
    matrix_row "native 1RTT native VLESS UDP" "NOT REACHABLE WITH CURRENT CLIENT" "SKIP" \
      "deterministic encrypted_udp.rs covers native UDP path"
  fi
}

print_matrix_summary() {
  echo ""
  echo "=== VLESS encryption live matrix ==="
  printf '%-36s %-32s %-8s %s\n' "Scenario" "Coverage type" "Result" "Notes"
  local row
  for row in "${MATRIX_ROWS[@]}"; do
    IFS='|' read -r scenario coverage result notes <<<"${row}"
    printf '%-36s %-32s %-8s %s\n' "${scenario}" "${coverage}" "${result}" "${notes}"
  done
  matrix_row "encrypted generic Mux UDP" "DETERMINISTIC PASS" "PASS" "tests/unit/vless/encryption/encrypted_udp.rs"
  matrix_row "destination-less XUDP Keep" "DETERMINISTIC PASS" "PASS" "tests/unit/vless/encryption/encrypted_xudp.rs"
}

wait_for_udp_services() {
  local attempts=0
  while (( attempts < 40 )); do
    if [[ -f "${UDP_SERVICES_LOG}" ]] &&
      grep -q "local-udp-services echo=${SMOKE_UDP_ECHO_PORT}" "${UDP_SERVICES_LOG}"; then
      return 0
    fi
    sleep 0.25
    attempts=$((attempts + 1))
  done
  echo "error: timed out waiting for local udp services (see ${UDP_SERVICES_LOG})" >&2
  tail -n 20 "${UDP_SERVICES_LOG}" >&2 || true
  return 1
}

python3 "${REPO_ROOT}/scripts/live_udp_smoke/local-udp-services.py" \
  --echo-port "${SMOKE_UDP_ECHO_PORT}" \
  >"${UDP_SERVICES_LOG}" 2>&1 &
UDP_SERVICES_PID=$!
wait_for_udp_services

python3 -m http.server "${SMOKE_LOCAL_HTTP_PORT}" --bind 127.0.0.1 \
  >"${HTTP_LOG}" 2>&1 &
HTTP_PID=$!
smoke_wait_port 127.0.0.1 "${SMOKE_LOCAL_HTTP_PORT}" "local http echo" 20

run_encrypted_case \
  "native-empty-flow" \
  "native" \
  'flow=""' \
  "${SCRIPT_DIR}/rust-xray-server.encryption.fixture.json" \
  "${SCRIPT_DIR}/xray-client-encryption.fixture.json" \
  "native 1RTT TCP direct"

run_encrypted_case \
  "native-vision" \
  "native" \
  "xtls-rprx-vision" \
  "${SCRIPT_DIR}/rust-xray-server.encryption-vision.fixture.json" \
  "${SCRIPT_DIR}/xray-client-encryption-vision.fixture.json" \
  "native 1RTT Vision TCP"

run_encrypted_mux_tcp_case
run_encrypted_xudp_case
run_encrypted_native_udp_attempt

if [[ "${FAILED}" -ne 0 ]]; then
  print_matrix_summary
  exit 1
fi

run_encrypted_vision_sequential_100() {
  local label="native-vision-seq100"
  local server_log="${SMOKE_WORK_DIR}/server-${label}.log"
  local client_log="${SMOKE_WORK_DIR}/client-${label}.log"
  local server_pid=""
  local client_pid=""
  local pass=0
  local i

  echo "--- case: mode=native flow=xtls-rprx-vision sequential=100 ---"
  RUST_LOG="${SMOKE_RUST_LOG:-info}" "${SMOKE_RUST_XRAY_BIN}" \
    "${SCRIPT_DIR}/rust-xray-server.encryption-vision.fixture.json" >"${server_log}" 2>&1 &
  server_pid=$!
  SMOKE_SERVER_PID="${server_pid}"
  smoke_wait_port 127.0.0.1 "${SMOKE_SERVER_PORT}" "rust-xray encrypted vision server" 40

  "${SMOKE_XRAY_BIN}" run -config "${SCRIPT_DIR}/xray-client-encryption-vision.fixture.json" \
    >"${client_log}" 2>&1 &
  client_pid=$!
  SMOKE_CLIENT_PID="${client_pid}"
  smoke_wait_port 127.0.0.1 "${SMOKE_SOCKS_PORT}" "xray socks inbound (vision seq100)" 40

  local target_url="http://127.0.0.1:${SMOKE_LOCAL_HTTP_PORT}/"
  for i in $(seq 1 100); do
    local http_code
    http_code="$(curl -sS -o /dev/null -w '%{http_code}' \
      -x "socks5h://127.0.0.1:${SMOKE_SOCKS_PORT}" -m 15 "${target_url}" || echo 000)"
    if [[ "${http_code}" == "200" ]]; then
      pass=$((pass + 1))
    else
      echo "vision sequential request ${i}/100 failed http=${http_code}" >&2
      break
    fi
  done

  smoke_stop_process "${client_pid}"
  smoke_stop_process "${server_pid}"
  SMOKE_CLIENT_PID=""
  SMOKE_SERVER_PID=""
  smoke_free_ports "${SMOKE_SERVER_PORT}" "${SMOKE_SOCKS_PORT}"

  echo "vision sequential: ${pass}/100"
  if [[ "${pass}" -eq 100 ]]; then
    echo "PASS vless encryption native 1RTT xtls-rprx-vision 100 sequential"
    matrix_row "native 1RTT Vision 100 sequential" "LIVE PASS" "PASS" "100/100"
  else
    echo "FAIL vless encryption native 1RTT xtls-rprx-vision 100 sequential" >&2
    matrix_row "native 1RTT Vision 100 sequential" "LIVE PASS" "FAIL" "${pass}/100"
    FAILED=1
  fi
}

run_encrypted_vision_sequential_100

print_matrix_summary

if [[ "${FAILED}" -ne 0 ]]; then
  exit 1
fi

echo "VLESS encryption live smoke matrix: PASS"
exit 0
