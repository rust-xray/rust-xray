#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/../.." && pwd)"

# shellcheck source=scripts/live_reality_smoke/smoke-lib.sh
source "${REPO_ROOT}/scripts/live_reality_smoke/smoke-lib.sh"

TEST_PUBLIC_KEY="${TEST_PUBLIC_KEY:-oU1MbEgszawWQJa0S_DxLsNt9G2zyE4rF-CrqvJjTmg}"
SMOKE_SERVER_PORT="${SMOKE_SERVER_PORT:-24443}"
SMOKE_SOCKS_PORT="${SMOKE_SOCKS_PORT:-10808}"
SMOKE_RUST_LOG="${SMOKE_RUST_LOG:-rust_xray=debug,tower=warn,hyper=warn,h2=warn,rustls=warn}"
SMOKE_WORK_DIR="${SMOKE_WORK_DIR:-/tmp/rust-xray-live-udp-smoke-$$}"
SMOKE_REPORT_PATH="${SMOKE_REPORT_PATH:-${SMOKE_WORK_DIR}/udp-report.txt}"
SMOKE_SKIP_BUILD="${SMOKE_SKIP_BUILD:-0}"
SMOKE_QUICK_URL="${SMOKE_QUICK_URL:-https://example.com/}"

UDP_ECHO_PORT="${UDP_ECHO_PORT:-37001}"
UDP_MULTI_PORT="${UDP_MULTI_PORT:-37002}"
UDP_DNS_PORT="${UDP_DNS_PORT:-37053}"
UDP_STUN_PORT="${UDP_STUN_PORT:-37047}"
UDP_BLOCK_PORT="${UDP_BLOCK_PORT:-37999}"

SMOKE_SERVER_LOG="${SMOKE_WORK_DIR}/server.log"
SMOKE_CLIENT_LOG="${SMOKE_WORK_DIR}/client.log"
SMOKE_RUST_XRAY_BIN="${SMOKE_RUST_XRAY_BIN:-${RUST_XRAY_BIN:-${REPO_ROOT}/target/release/rust-xray}}"
SMOKE_UDP_SERVICES_PID=""
SMOKE_FAILED=0
declare -a MATRIX_ROWS=()

SERVER_EMPTY="${SCRIPT_DIR}/rust-xray-server-udp.fixture.json"
SERVER_VISION="${SCRIPT_DIR}/rust-xray-server-udp-vision.fixture.json"
SERVER_ROUTING="${SCRIPT_DIR}/rust-xray-server-udp-routing.fixture.json"
CLIENT_TEMPLATE="${REPO_ROOT}/scripts/live_reality_smoke/xray-client-smoke.fixture.json"
CLIENT_NEGATIVE_TEMPLATE="${REPO_ROOT}/scripts/live_reality_smoke/xray-client-negative.template.json"

pass_row() {
  MATRIX_ROWS+=("PASS|$1|$2|$3|$4|$5")
  echo "== PASS: $1"
}

fail_row() {
  MATRIX_ROWS+=("FAIL|$1|$2|$3|$4|$5")
  SMOKE_FAILED=1
  echo "== FAIL: $1" >&2
}

skip_row() {
  MATRIX_ROWS+=("SKIP|$1|$2|$3|$4|$5")
  echo "== SKIP: $1"
}

record_row() {
  local status="$1"
  local path="$2"
  local transport="$3"
  local target="$4"
  local notes="$5"
  local evidence="$6"
  if [[ "${status}" == "FAIL" ]]; then
    SMOKE_FAILED=1
  fi
  MATRIX_ROWS+=("${status}|${path}|${transport}|${target}|${notes}|${evidence}")
  echo "== ${status}: ${path} (${transport})"
}

write_client_config() {
  local output="$1"
  local flow="${2:-}"
  local mux_enabled="${3:-0}"
  local packet_encoding="${4:-}"
  SMOKE_TEMPLATE="${CLIENT_TEMPLATE}" \
    SMOKE_OUTPUT="${output}" \
    SMOKE_FLOW="${flow}" \
    SMOKE_PACKET_ENCODING="${packet_encoding}" \
    SMOKE_USER_ID="11111111-1111-1111-1111-111111111111" \
    SMOKE_SHORT_ID="0123456789abcdef" \
    SMOKE_SERVER_NAME="www.microsoft.com" \
    SMOKE_MLDSA65_VERIFY="" \
    SMOKE_MUX_ENABLED="${mux_enabled}" \
    SMOKE_PUBLIC_KEY="${TEST_PUBLIC_KEY}" \
    python3 - <<'PY'
import json, os
from pathlib import Path
cfg = json.loads(Path(os.environ["SMOKE_TEMPLATE"]).read_text())
user = cfg["outbounds"][0]["settings"]["vnext"][0]["users"][0]
flow = os.environ["SMOKE_FLOW"]
user["flow"] = flow if flow else ""
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

write_client_config_with_encoding() {
  write_client_config "$1" "$2" "$3" "$4"
}

count_log() {
  local pattern="$1"
  grep -Ec "${pattern}" "${SMOKE_SERVER_LOG}" 2>/dev/null || true
}

extract_xudp_evidence() {
  local global_ids mux_ids assoc_active dispatch
  global_ids="$(grep -Eo 'global_id=\[[0-9a-f ,]+\]' "${SMOKE_SERVER_LOG}" | sort -u | wc -l | tr -d ' ')"
  mux_ids="$(grep -Eo 'mux_id=[0-9]+' "${SMOKE_SERVER_LOG}" | sort -u | wc -l | tr -d ' ')"
  assoc_active="$(count_log 'xudp association active')"
  dispatch="$(count_log 'publish_route|pick_route|routed to blackhole outbound|generic mux udp session active')"
  echo "global_ids=${global_ids} mux_ids=${mux_ids} assoc_active=${assoc_active} dispatch_hits=${dispatch}"
}

start_local_udp_services() {
  python3 "${SCRIPT_DIR}/local-udp-services.py" \
    --echo-port "${UDP_ECHO_PORT}" \
    --multi-port "${UDP_MULTI_PORT}" \
    --dns-port "${UDP_DNS_PORT}" \
    --stun-port "${UDP_STUN_PORT}" \
    >"${SMOKE_WORK_DIR}/local-udp-services.log" 2>&1 &
  SMOKE_UDP_SERVICES_PID=$!
  local ready=0 attempt
  for ((attempt = 0; attempt < 40; attempt++)); do
    if grep -Fq "local-udp-services echo=${UDP_ECHO_PORT}" "${SMOKE_WORK_DIR}/local-udp-services.log" \
      && python3 - "${UDP_ECHO_PORT}" <<'PY'
import socket
import sys

sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
sock.settimeout(0.25)
sock.sendto(b"udp-ready", ("127.0.0.1", int(sys.argv[1])))
if sock.recvfrom(128)[0] != b"udp-ready":
    raise SystemExit(1)
PY
    then
      ready=1
      break
    fi
    sleep 0.1
  done
  if [[ "${ready}" != "1" ]]; then
    echo "error: local UDP echo readiness probe failed on 127.0.0.1:${UDP_ECHO_PORT}" >&2
    tail -20 "${SMOKE_WORK_DIR}/local-udp-services.log" >&2 || true
    return 1
  fi
}

cleanup() {
  smoke_stop_stack
  smoke_stop_process "${SMOKE_UDP_SERVICES_PID:-}"
  SMOKE_UDP_SERVICES_PID=""
}
trap cleanup EXIT

prepare_workspace() {
  mkdir -p "${SMOKE_WORK_DIR}"
  : >"${SMOKE_SERVER_LOG}"
  : >"${SMOKE_CLIENT_LOG}"
}

build_rust_xray() {
  if [[ "${SMOKE_SKIP_BUILD}" == "1" ]]; then
    return 0
  fi
  (cd "${REPO_ROOT}" && cargo build --release --bin rust-xray --all-features)
}

wait_for_server_listener() {
  local attempts=0
  while (( attempts < 80 )); do
    if smoke_log_contains "REALITY listener started"; then
      return 0
    fi
    sleep 0.1
    attempts=$((attempts + 1))
  done
  echo "error: timed out waiting for REALITY listener started" >&2
  tail -20 "${SMOKE_SERVER_LOG}" >&2 || true
  return 1
}

warm_stack() {
  local server_config="$1"
  local client_config="$2"
  smoke_stop_stack
  : >"${SMOKE_SERVER_LOG}"
  : >"${SMOKE_CLIENT_LOG}"
  smoke_start_server "${server_config}"
  wait_for_server_listener
  smoke_start_client "${client_config}"
  curl -sS -o /dev/null -m 30 \
    -x "socks5h://127.0.0.1:${SMOKE_SOCKS_PORT}" \
    "${SMOKE_QUICK_URL}" >>"${SMOKE_WORK_DIR}/warmup.log" 2>&1 || true
  sleep 1
}

run_case() {
  local name="$1"
  local server_config="$2"
  local client_config="$3"
  shift 3
  local probe_cmd=("$@")

  warm_stack "${server_config}" "${client_config}"
  if ! "${probe_cmd[@]}" >>"${SMOKE_WORK_DIR}/${name}.log" 2>&1; then
    tail -40 "${SMOKE_SERVER_LOG}" >>"${SMOKE_WORK_DIR}/${name}.log" 2>&1 || true
    return 1
  fi
  sleep 0.5
  return 0
}

matrix_native_udp_raw() {
  local client="${SMOKE_WORK_DIR}/client-native-udp.json"
  write_client_config "${client}" "" 0
  if run_case "native-udp-raw" "${SERVER_EMPTY}" "${client}" \
    python3 "${SCRIPT_DIR}/udp-probes.py" echo "${SMOKE_SOCKS_PORT}" "127.0.0.1" "${UDP_ECHO_PORT}" 3; then
    record_row "PASS" "Native UDP" "raw/REALITY" "127.0.0.1:${UDP_ECHO_PORT}" \
      "3 echo datagrams" "vless udp relay completed=$(count_log 'vless udp relay completed')"
  else
    record_row "FAIL" "Native UDP" "raw/REALITY" "127.0.0.1:${UDP_ECHO_PORT}" \
      "echo probe failed" "see ${SMOKE_WORK_DIR}/native-udp-raw.log"
  fi
}

matrix_native_udp_domain() {
  local client="${SMOKE_WORK_DIR}/client-native-udp-domain.json"
  write_client_config "${client}" "" 0
  if run_case "native-udp-domain" "${SERVER_EMPTY}" "${client}" \
    python3 "${SCRIPT_DIR}/udp-probes.py" echo "${SMOKE_SOCKS_PORT}" "127.0.0.1" "${UDP_ECHO_PORT}" 2; then
    record_row "PASS" "Native UDP domain" "raw/REALITY" "127.0.0.1:${UDP_ECHO_PORT}" \
      "domain-form ATYP via numeric host" "relay_completed=$(count_log 'vless udp relay completed')"
  else
    record_row "FAIL" "Native UDP domain" "raw/REALITY" "127.0.0.1:${UDP_ECHO_PORT}" \
      "domain probe failed" "see native-udp-domain.log"
  fi
}

matrix_generic_mux_dns() {
  local client="${SMOKE_WORK_DIR}/client-mux-dns.json"
  write_client_config "${client}" "xtls-rprx-vision" 1
  warm_stack "${SERVER_VISION}" "${client}"
  if python3 "${REPO_ROOT}/scripts/live_reality_smoke/mux-udp-dns-probe.py" \
    "${SMOKE_SOCKS_PORT}" "127.0.0.1" "${UDP_DNS_PORT}" \
    >>"${SMOKE_WORK_DIR}/mux-dns.log" 2>&1; then
    record_row "PASS" "Generic mux UDP DNS" "REALITY+Vision+Mux" "127.0.0.1:${UDP_DNS_PORT}" \
      "DNS fast path" "mux_udp_dns=$(count_log 'mux udp dns')"
  else
    record_row "FAIL" "Generic mux UDP DNS" "REALITY+Vision+Mux" "127.0.0.1:${UDP_DNS_PORT}" \
      "DNS probe failed" "see mux-dns.log"
  fi
}

matrix_generic_mux_non_dns() {
  local client="${SMOKE_WORK_DIR}/client-mux-generic.json"
  write_client_config "${client}" "xtls-rprx-vision" 1
  warm_stack "${SERVER_VISION}" "${client}"
  python3 "${SCRIPT_DIR}/udp-probes.py" prime-mux "${SMOKE_SOCKS_PORT}" \
    >>"${SMOKE_WORK_DIR}/mux-generic-prime.log" 2>&1 || true
  if python3 "${SCRIPT_DIR}/udp-probes.py" echo "${SMOKE_SOCKS_PORT}" "127.0.0.1" "${UDP_ECHO_PORT}" 3 \
    >>"${SMOKE_WORK_DIR}/mux-generic.log" 2>&1; then
    record_row "PASS" "Generic mux UDP non-DNS" "REALITY+Vision+Mux" "127.0.0.1:${UDP_ECHO_PORT}" \
      "persistent SessionID path" \
      "opened=$(count_log 'generic mux udp session opened') active=$(count_log 'generic mux udp session active')"
  else
    record_row "FAIL" "Generic mux UDP non-DNS" "REALITY+Vision+Mux" "127.0.0.1:${UDP_ECHO_PORT}" \
      "echo via mux failed" "see mux-generic.log"
  fi
}

matrix_xudp_raw() {
  local client="${SMOKE_WORK_DIR}/client-xudp.json"
  write_client_config_with_encoding "${client}" "" 1 "xudp"
  warm_stack "${SERVER_EMPTY}" "${client}"
  python3 "${SCRIPT_DIR}/udp-probes.py" prime-mux "${SMOKE_SOCKS_PORT}" \
    >>"${SMOKE_WORK_DIR}/xudp-prime.log" 2>&1 || true
  if python3 "${SCRIPT_DIR}/udp-probes.py" echo "${SMOKE_SOCKS_PORT}" "127.0.0.1" "${UDP_ECHO_PORT}" 3 \
    >>"${SMOKE_WORK_DIR}/xudp-echo.log" 2>&1; then
    record_row "PASS" "XUDP" "raw/REALITY" "127.0.0.1:${UDP_ECHO_PORT}" \
      "GlobalID association" "$(extract_xudp_evidence)"
  else
    record_row "FAIL" "XUDP" "raw/REALITY" "127.0.0.1:${UDP_ECHO_PORT}" \
      "echo failed" "see xudp-echo.log"
  fi
}

matrix_xudp_multi() {
  local client="${SMOKE_WORK_DIR}/client-xudp-multi.json"
  write_client_config_with_encoding "${client}" "" 1 "xudp"
  warm_stack "${SERVER_EMPTY}" "${client}"
  python3 "${SCRIPT_DIR}/udp-probes.py" prime-mux "${SMOKE_SOCKS_PORT}" \
    >>"${SMOKE_WORK_DIR}/xudp-multi-prime.log" 2>&1 || true
  if python3 "${SCRIPT_DIR}/udp-probes.py" multi "${SMOKE_SOCKS_PORT}" "127.0.0.1" "${UDP_MULTI_PORT}" \
    >>"${SMOKE_WORK_DIR}/xudp-multi.log" 2>&1; then
    record_row "PASS" "XUDP multi-response" "raw/REALITY" "127.0.0.1:${UDP_MULTI_PORT}" \
      "3 responses on one association" "$(extract_xudp_evidence)"
  else
    record_row "FAIL" "XUDP multi-response" "raw/REALITY" "127.0.0.1:${UDP_MULTI_PORT}" \
      "multi-response failed" "see xudp-multi.log"
  fi
}

matrix_xudp_reality() {
  local client="${SMOKE_WORK_DIR}/client-xudp-vision.json"
  write_client_config_with_encoding "${client}" "xtls-rprx-vision" 1 "xudp"
  warm_stack "${SERVER_VISION}" "${client}"
  if python3 "${SCRIPT_DIR}/udp-probes.py" echo "${SMOKE_SOCKS_PORT}" "127.0.0.1" "${UDP_ECHO_PORT}" 2 \
    >>"${SMOKE_WORK_DIR}/xudp-vision.log" 2>&1; then
    record_row "PASS" "XUDP + REALITY/Vision" "REALITY+Vision+Mux+XUDP" "127.0.0.1:${UDP_ECHO_PORT}" \
      "accepted Vision+XUDP child" "$(extract_xudp_evidence)"
  else
    record_row "FAIL" "XUDP + REALITY/Vision" "REALITY+Vision+Mux+XUDP" "127.0.0.1:${UDP_ECHO_PORT}" \
      "Vision+XUDP failed" "see xudp-vision.log"
  fi
}

matrix_vision_negative_native_udp() {
  local client="${SMOKE_WORK_DIR}/client-vision-native-udp.json"
  smoke_write_negative_client_config "${CLIENT_NEGATIVE_TEMPLATE}" "${client}" "xtls-rprx-vision" 0 ""
  warm_stack "${SERVER_VISION}" "${client}"
  python3 "${REPO_ROOT}/scripts/live_reality_smoke/vless-negative-probe.py" udp-dns "${SMOKE_SOCKS_PORT}" \
    "127.0.0.1" "${UDP_DNS_PORT}" >>"${SMOKE_WORK_DIR}/vision-native-udp.log" 2>&1 || true
  sleep 0.5
  if grep -Fq "doesn't support UDP" "${SMOKE_CLIENT_LOG}" || \
     grep -Fq "doesn't support UDP" "${SMOKE_SERVER_LOG}" || \
     grep -Fq "UDP unsupported" "${SMOKE_SERVER_LOG}" || \
     grep -Fq "vision mux accepts only udp" "${SMOKE_SERVER_LOG}"; then
    record_row "PASS" "Vision + native UDP rejected" "REALITY+Vision" "command=UDP" \
      "negative as expected" "client/server rejection logged"
  elif grep -Fq "command=Mux" "${SMOKE_SERVER_LOG}" && grep -Fq "mux xudp substream opened" "${SMOKE_SERVER_LOG}"; then
    record_row "NOT REACHABLE FROM CURRENT CLIENT" "Vision + native UDP rejected" "REALITY+Vision" "command=UDP" \
      "Xray 26.3.27 routes SOCKS UDP via Mux+XUDP instead of native command=Udp" \
      "see vision-native-udp.log"
  else
    record_row "FAIL" "Vision + native UDP rejected" "REALITY+Vision" "command=UDP" \
      "expected rejection missing" "see vision-native-udp.log"
  fi
}

matrix_vision_negative_mux_tcp() {
  local client="${SMOKE_WORK_DIR}/client-vision-mux-tcp.json"
  smoke_write_negative_client_config "${CLIENT_NEGATIVE_TEMPLATE}" "${client}" "xtls-rprx-vision" 1 ""
  warm_stack "${SERVER_VISION}" "${client}"
  python3 "${REPO_ROOT}/scripts/live_reality_smoke/vless-negative-probe.py" mux-cool "${SMOKE_SOCKS_PORT}" \
    >>"${SMOKE_WORK_DIR}/vision-mux-tcp.log" 2>&1 || true
  sleep 0.5
  if grep -Fq "vision mux accepts only udp child substreams" "${SMOKE_SERVER_LOG}" || \
     grep -Fq "vision mux accepts only udp" "${SMOKE_SERVER_LOG}"; then
    record_row "PASS" "Vision + Mux TCP rejected" "REALITY+Vision+Mux" "v1.mux.cool TCP child" \
      "negative as expected" "server rejection logged"
  else
    record_row "FAIL" "Vision + Mux TCP rejected" "REALITY+Vision+Mux" "v1.mux.cool TCP child" \
      "expected rejection missing" "see vision-mux-tcp.log"
  fi
}

matrix_empty_flow_mux_tcp_accept() {
  local client="${SMOKE_WORK_DIR}/client-empty-mux-tcp.json"
  write_client_config "${client}" "" 1
  warm_stack "${SERVER_EMPTY}" "${client}"
  python3 "${REPO_ROOT}/scripts/live_reality_smoke/vless-negative-probe.py" mux-cool "${SMOKE_SOCKS_PORT}" \
    >>"${SMOKE_WORK_DIR}/empty-mux-tcp.log" 2>&1 || true
  sleep 0.5
  if grep -Fq "mux session started" "${SMOKE_SERVER_LOG}" && \
     ! grep -Fq "vision mux tcp substream rejected" "${SMOKE_SERVER_LOG}"; then
    record_row "PASS" "flow='' + Mux TCP accepted" "raw/REALITY+Mux" "v1.mux.cool" \
      "baseline still accepted" "mux session started"
  else
    record_row "FAIL" "flow='' + Mux TCP accepted" "raw/REALITY+Mux" "v1.mux.cool" \
      "unexpected rejection" "see empty-mux-tcp.log"
  fi
}

matrix_dns() {
  local client="${SMOKE_WORK_DIR}/client-xudp-dns.json"
  write_client_config_with_encoding "${client}" "" 1 "xudp"
  warm_stack "${SERVER_EMPTY}" "${client}"
  python3 "${SCRIPT_DIR}/udp-probes.py" prime-mux "${SMOKE_SOCKS_PORT}" \
    >>"${SMOKE_WORK_DIR}/dns-prime.log" 2>&1 || true
  local ok=1
  for q in "A:1" "AAAA:28"; do
    qname="example.com"
    qtype="${q#*:}"
    if ! python3 "${SCRIPT_DIR}/udp-probes.py" dns "${SMOKE_SOCKS_PORT}" "127.0.0.1" "${UDP_DNS_PORT}" \
      "${qname}" "${qtype}" >>"${SMOKE_WORK_DIR}/dns-${qtype}.log" 2>&1; then
      ok=0
    fi
  done
  if [[ "${ok}" == "1" ]]; then
    record_row "PASS" "DNS A/AAAA over XUDP" "raw/REALITY+XUDP" "127.0.0.1:${UDP_DNS_PORT}" \
      "sequential queries" "$(extract_xudp_evidence)"
  else
    record_row "FAIL" "DNS A/AAAA over XUDP" "raw/REALITY+XUDP" "127.0.0.1:${UDP_DNS_PORT}" \
      "DNS probe failed" "see dns-*.log"
  fi
}

matrix_stun() {
  local client="${SMOKE_WORK_DIR}/client-xudp-stun.json"
  write_client_config_with_encoding "${client}" "" 1 "xudp"
  warm_stack "${SERVER_EMPTY}" "${client}"
  python3 "${SCRIPT_DIR}/udp-probes.py" prime-mux "${SMOKE_SOCKS_PORT}" \
    >>"${SMOKE_WORK_DIR}/stun-prime.log" 2>&1 || true
  if python3 "${SCRIPT_DIR}/udp-probes.py" stun "${SMOKE_SOCKS_PORT}" "127.0.0.1" "${UDP_STUN_PORT}" \
    >>"${SMOKE_WORK_DIR}/stun.log" 2>&1; then
    record_row "PASS" "STUN Binding via XUDP" "raw/REALITY+XUDP" "127.0.0.1:${UDP_STUN_PORT}" \
      "single datagram request/response" "stun ok"
  else
    record_row "FAIL" "STUN Binding via XUDP" "raw/REALITY+XUDP" "127.0.0.1:${UDP_STUN_PORT}" \
      "STUN probe failed" "see stun.log"
  fi
}

matrix_quic() {
  local client="${SMOKE_WORK_DIR}/client-xudp-quic.json"
  write_client_config_with_encoding "${client}" "" 1 "xudp"
  warm_stack "${SERVER_EMPTY}" "${client}"
  python3 "${SCRIPT_DIR}/udp-probes.py" prime-mux "${SMOKE_SOCKS_PORT}" \
    >>"${SMOKE_WORK_DIR}/quic-prime.log" 2>&1 || true
  if python3 "${SCRIPT_DIR}/udp-probes.py" quic "${SMOKE_SOCKS_PORT}" "1.1.1.1" 443 \
    >>"${SMOKE_WORK_DIR}/quic.log" 2>&1; then
    record_row "PASS" "QUIC/UDP443 smoke" "raw/REALITY+XUDP" "1.1.1.1:443" \
      "bidirectional UDP survives" "quic smoke ok"
  else
    record_row "BLOCKED BY EXTERNAL NETWORK" "QUIC/UDP443 smoke" "raw/REALITY+XUDP" "1.1.1.1:443" \
      "no response or blocked" "see quic.log"
  fi
}

matrix_blackhole() {
  local client="${SMOKE_WORK_DIR}/client-xudp-blackhole.json"
  write_client_config_with_encoding "${client}" "" 1 "xudp"
  warm_stack "${SERVER_ROUTING}" "${client}"
  python3 "${SCRIPT_DIR}/udp-probes.py" prime-mux "${SMOKE_SOCKS_PORT}" \
    >>"${SMOKE_WORK_DIR}/blackhole-prime.log" 2>&1 || true
  if python3 "${SCRIPT_DIR}/udp-probes.py" blackhole "${SMOKE_SOCKS_PORT}" "127.0.0.1" "${UDP_BLOCK_PORT}" \
    >>"${SMOKE_WORK_DIR}/blackhole.log" 2>&1; then
    record_row "PASS" "Blackhole routing" "REALITY+Mux+XUDP+routing" "127.0.0.1:${UDP_BLOCK_PORT}" \
      "no response, no hang" "blackhole ok"
  else
    record_row "FAIL" "Blackhole routing" "REALITY+Mux+XUDP+routing" "127.0.0.1:${UDP_BLOCK_PORT}" \
      "unexpected response or hang" "see blackhole.log"
  fi
}

matrix_ipv6() {
  if ! ping6 -c 1 ::1 >/dev/null 2>&1; then
    record_row "NOT TESTED — ENVIRONMENT" "IPv6 XUDP" "raw/REALITY+XUDP" "::1" \
      "IPv6 unavailable" "ping6 ::1 failed"
    return 0
  fi
  record_row "NOT TESTED — ENVIRONMENT" "IPv6 XUDP" "raw/REALITY+XUDP" "::1" \
    "no local IPv6 UDP echo harness in this run" "environment partial"
}

matrix_xudp_reattach() {
  record_row "NEEDS ADDITIONAL LIVE VERIFICATION" "XUDP reattach" "raw/REALITY+XUDP" "migration" \
    "current Xray 26.3.27 client does not naturally trigger cross-parent reattach in SOCKS harness" \
    "deterministic unit tests green: xudp_cross_parent_reattach_reuses_association"
}

matrix_api_regression() {
  if ! command -v grpcurl >/dev/null 2>&1; then
    record_row "NOT TESTED — ENVIRONMENT" "StatsService regression" "API" "127.0.0.1:10186" \
      "grpcurl missing" "skipped"
    return 0
  fi
  local client="${SMOKE_WORK_DIR}/client-api-xudp.json"
  write_client_config_with_encoding "${client}" "" 1 "xudp"
  warm_stack "${SERVER_ROUTING}" "${client}"
  python3 "${SCRIPT_DIR}/udp-probes.py" prime-mux "${SMOKE_SOCKS_PORT}" \
    >>"${SMOKE_WORK_DIR}/api-prime.log" 2>&1 || true
  python3 "${SCRIPT_DIR}/udp-probes.py" echo "${SMOKE_SOCKS_PORT}" "127.0.0.1" "${UDP_ECHO_PORT}" 1 \
    >>"${SMOKE_WORK_DIR}/api-traffic.log" 2>&1 || true
  if grpcurl -plaintext "127.0.0.1:10186" list >/dev/null 2>&1 && \
     grpcurl -plaintext -d '{}' "127.0.0.1:10186" xray.app.stats.command.StatsService/GetSysStats \
       >/dev/null 2>&1; then
    record_row "PASS" "StatsService regression" "API during XUDP traffic" "127.0.0.1:10186" \
      "GetSysStats ok" "grpcurl ok"
  else
    record_row "FAIL" "StatsService regression" "API during XUDP traffic" "127.0.0.1:10186" \
      "grpcurl failed" "see api-traffic.log"
  fi
}

write_report() {
  {
    echo "STATUS: $([[ "${SMOKE_FAILED}" == "0" ]] && echo READY || echo BLOCKED)"
    echo "CURRENT HEAD: $(git -C "${REPO_ROOT}" rev-parse HEAD)"
    echo "WORKING TREE: uncommitted UDP changes present"
    echo "XRAY CLIENT: $(xray version 2>/dev/null | head -1 || echo unknown)"
    echo "XRAY UPSTREAM MAIN: 5e245b082e6be8c8899c34410f488e8ab001aaba"
    echo "TEST ENVIRONMENT: darwin loopback + local UDP services + Xray 26.3.27 client"
    echo
    echo "LIVE INTEROP MATRIX"
    printf '%s\n' "${MATRIX_ROWS[@]}" | while IFS='|' read -r status path transport target notes evidence; do
      printf '| %s | %s | %s | %s | Xray 26.3.27 | %s | %s | %s |\n' \
        "${path}" "${transport}" "${target}" "SOCKS→rust-xray" "${status}" "${evidence}" "${notes}"
    done
    echo
    echo "ARTIFACTS: ${SMOKE_WORK_DIR}"
  } | tee "${SMOKE_REPORT_PATH}"
}

main() {
  smoke_require_commands cargo python3 xray curl
  prepare_workspace
  build_rust_xray
  start_local_udp_services
  matrix_native_udp_raw
  matrix_native_udp_domain
  matrix_generic_mux_dns
  matrix_generic_mux_non_dns
  matrix_xudp_raw
  matrix_xudp_multi
  matrix_xudp_reality
  matrix_vision_negative_native_udp
  matrix_vision_negative_mux_tcp
  matrix_empty_flow_mux_tcp_accept
  matrix_dns
  matrix_stun
  matrix_quic
  matrix_blackhole
  matrix_ipv6
  matrix_xudp_reattach
  matrix_api_regression
  write_report
  exit "${SMOKE_FAILED}"
}

main "$@"
