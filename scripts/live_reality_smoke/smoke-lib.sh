#!/usr/bin/env bash
# Shared helpers for live REALITY smoke scripts.

smoke_require_commands() {
  local name
  for name in "$@"; do
    if ! command -v "${name}" >/dev/null 2>&1; then
      echo "error: required command not found in PATH: ${name}" >&2
      exit 1
    fi
  done
}

smoke_wait_port() {
  local host="$1"
  local port="$2"
  local label="$3"
  local timeout="${4:-60}"
  local elapsed=0

  while (( elapsed < timeout )); do
    if (echo >/dev/tcp/"${host}"/"${port}") >/dev/null 2>&1; then
      return 0
    fi
    sleep 0.25
    elapsed=$((elapsed + 1))
  done

  echo "error: timed out waiting for ${label} on ${host}:${port}" >&2
  return 1
}

smoke_wait_port_closed() {
  local host="$1"
  local port="$2"
  local label="$3"
  local timeout="${4:-60}"
  local elapsed=0

  while (( elapsed < timeout )); do
    if ! (echo >/dev/tcp/"${host}"/"${port}") >/dev/null 2>&1; then
      return 0
    fi
    sleep 0.25
    elapsed=$((elapsed + 1))
  done

  echo "error: timed out waiting for ${label} to close on ${host}:${port}" >&2
  return 1
}

smoke_free_port() {
  local port="$1"
  if command -v fuser >/dev/null 2>&1; then
    fuser -k "${port}/tcp" >/dev/null 2>&1 || true
  fi
}

smoke_free_ports() {
  local port
  for port in "$@"; do
    smoke_free_port "${port}"
  done
}

smoke_stop_process() {
  local pid="${1:-}"
  if [[ -n "${pid}" ]] && kill -0 "${pid}" >/dev/null 2>&1; then
    kill "${pid}" >/dev/null 2>&1 || true
    local waited=0
    while kill -0 "${pid}" >/dev/null 2>&1 && (( waited < 40 )); do
      sleep 0.1
      waited=$((waited + 1))
    done
    if kill -0 "${pid}" >/dev/null 2>&1; then
      kill -9 "${pid}" >/dev/null 2>&1 || true
    fi
    wait "${pid}" 2>/dev/null || true
  fi
}

smoke_stop_stack() {
  smoke_stop_process "${SMOKE_CLIENT_PID:-}"
  smoke_stop_process "${SMOKE_SERVER_PID:-}"
  SMOKE_CLIENT_PID=""
  SMOKE_SERVER_PID=""
  smoke_free_port "${SMOKE_SOCKS_PORT}"
  smoke_free_port "${SMOKE_SERVER_PORT}"
  smoke_wait_port_closed 127.0.0.1 "${SMOKE_SERVER_PORT}" "rust-xray server" 20 || true
}

smoke_verify_server_started() {
  if ! kill -0 "${SMOKE_SERVER_PID}" >/dev/null 2>&1; then
    echo "error: rust-xray server process exited during startup" >&2
    tail -20 "${SMOKE_SERVER_LOG}" >&2 || true
    return 1
  fi
  if ! smoke_log_contains "REALITY listener started"; then
    echo "error: rust-xray server log missing REALITY listener started" >&2
    tail -20 "${SMOKE_SERVER_LOG}" >&2 || true
    return 1
  fi
  return 0
}

smoke_start_server() {
  local server_config="$1"
  smoke_stop_process "${SMOKE_SERVER_PID:-}"
  smoke_free_port "${SMOKE_SERVER_PORT}"
  smoke_wait_port_closed 127.0.0.1 "${SMOKE_SERVER_PORT}" "rust-xray server" 20 || true
  : >>"${SMOKE_SERVER_LOG}"
  RUST_LOG="${SMOKE_RUST_LOG:-info}" "${SMOKE_RUST_XRAY_BIN}" "${server_config}" >>"${SMOKE_SERVER_LOG}" 2>&1 &
  SMOKE_SERVER_PID=$!
  sleep 0.1
  smoke_verify_server_started &&
    smoke_wait_port 127.0.0.1 "${SMOKE_SERVER_PORT}" "rust-xray server"
}

smoke_start_client() {
  local client_config="$1"
  smoke_stop_process "${SMOKE_CLIENT_PID:-}"
  : >>"${SMOKE_CLIENT_LOG}"
  xray run -config "${client_config}" >>"${SMOKE_CLIENT_LOG}" 2>&1 &
  SMOKE_CLIENT_PID=$!
  smoke_wait_port 127.0.0.1 "${SMOKE_SOCKS_PORT}" "xray client SOCKS"
}

smoke_start_stack() {
  local server_config="$1"
  local client_config="$2"
  smoke_start_server "${server_config}"
  smoke_start_client "${client_config}"
}

smoke_expect_server_reject() {
  local name="$1"
  local server_config="$2"
  local pattern="$3"
  local log="${SMOKE_WORK_DIR}/reject-${name}.log"
  smoke_stop_stack
  if RUST_LOG="${SMOKE_RUST_LOG:-info}" "${SMOKE_RUST_XRAY_BIN}" "${server_config}" >"${log}" 2>&1; then
    echo "error: expected ${name} config to be rejected during startup" >&2
    cat "${log}" >&2
    return 1
  fi
  if ! grep -Fq "${pattern}" "${log}"; then
    echo "error: ${name} reject log missing pattern: ${pattern}" >&2
    cat "${log}" >&2
    return 1
  fi
  return 0
}

smoke_write_client_config() {
  local template_path="$1"
  local output_path="$2"
  local flow="${3:-}"
  local user_id="${4:-11111111-1111-1111-1111-111111111111}"
  local short_id="${5:-0123456789abcdef}"
  local server_name="${6:-www.microsoft.com}"
  local mldsa65_verify="${7:-}"
  local mux_enabled="${8:-0}"

  SMOKE_TEMPLATE="${template_path}" \
    SMOKE_OUTPUT="${output_path}" \
    SMOKE_FLOW="${flow}" \
    SMOKE_USER_ID="${user_id}" \
    SMOKE_SHORT_ID="${short_id}" \
    SMOKE_SERVER_NAME="${server_name}" \
    SMOKE_MLDSA65_VERIFY="${mldsa65_verify}" \
    SMOKE_MUX_ENABLED="${mux_enabled}" \
    SMOKE_PUBLIC_KEY="${TEST_PUBLIC_KEY}" \
    python3 - <<'PY'
import json
import os
from pathlib import Path

template = Path(os.environ["SMOKE_TEMPLATE"])
output = Path(os.environ["SMOKE_OUTPUT"])
cfg = json.loads(template.read_text())

user = cfg["outbounds"][0]["settings"]["vnext"][0]["users"][0]
user["id"] = os.environ["SMOKE_USER_ID"]
flow = os.environ["SMOKE_FLOW"]
if flow:
    user["flow"] = flow
else:
    user.pop("flow", None)
    user["flow"] = ""

reality = cfg["outbounds"][0]["streamSettings"]["realitySettings"]
reality["publicKey"] = os.environ["SMOKE_PUBLIC_KEY"]
reality["shortId"] = os.environ["SMOKE_SHORT_ID"]
reality["serverName"] = os.environ["SMOKE_SERVER_NAME"]
mldsa65_verify = os.environ.get("SMOKE_MLDSA65_VERIFY", "")
if mldsa65_verify:
    reality["mldsa65Verify"] = mldsa65_verify

if os.environ.get("SMOKE_MUX_ENABLED") == "1":
    cfg["outbounds"][0]["mux"] = {"enabled": True, "concurrency": 8}
elif "mux" in cfg["outbounds"][0]:
    del cfg["outbounds"][0]["mux"]

output.write_text(json.dumps(cfg, indent=2) + "\n")
PY
}

smoke_write_negative_client_config() {
  local template_path="$1"
  local output_path="$2"
  local flow="${3:-}"
  local mux_enabled="${4:-0}"
  local packet_encoding="${5:-}"

  SMOKE_TEMPLATE="${template_path}" \
    SMOKE_OUTPUT="${output_path}" \
    SMOKE_FLOW="${flow}" \
    SMOKE_MUX_ENABLED="${mux_enabled}" \
    SMOKE_PACKET_ENCODING="${packet_encoding}" \
    SMOKE_PUBLIC_KEY="${TEST_PUBLIC_KEY}" \
    python3 - <<'PY'
import json
import os
from pathlib import Path

template = Path(os.environ["SMOKE_TEMPLATE"])
output = Path(os.environ["SMOKE_OUTPUT"])
cfg = json.loads(template.read_text())

user = cfg["outbounds"][0]["settings"]["vnext"][0]["users"][0]
flow = os.environ["SMOKE_FLOW"]
if flow:
    user["flow"] = flow
else:
    user["flow"] = ""

packet_encoding = os.environ.get("SMOKE_PACKET_ENCODING", "")
if packet_encoding:
    user["packetEncoding"] = packet_encoding
elif "packetEncoding" in user:
    del user["packetEncoding"]

if os.environ.get("SMOKE_MUX_ENABLED") == "1":
    cfg["outbounds"][0]["mux"] = {"enabled": True, "concurrency": 8}
elif "mux" in cfg["outbounds"][0]:
    del cfg["outbounds"][0]["mux"]

cfg["outbounds"][0]["streamSettings"]["realitySettings"]["publicKey"] = os.environ[
    "SMOKE_PUBLIC_KEY"
]

output.write_text(json.dumps(cfg, indent=2) + "\n")
PY
}

smoke_decrypt_failure_count() {
  grep -Ec 'AES-(128|256)-GCM decrypt failed|ChaCha20-Poly1305 decrypt failed|TLS application-stream record decrypt failed' \
    "${SMOKE_SERVER_LOG}" || true
}

smoke_expect_happ_mux_udp_dns_baseline() {
  local pattern
  local required_patterns=(
    "mux udp dns query forwarded"
    "mux udp dns response received"
    "mux udp response frame sent"
  )
  local forbidden_patterns=(
    "UDP mux substream is not implemented"
    "UDP mux packet is not implemented"
  )

  for pattern in "${required_patterns[@]}"; do
    if ! smoke_log_contains "${pattern}"; then
      echo "error: Happ mux UDP DNS baseline missing required log: ${pattern}" >&2
      return 1
    fi
  done

  for pattern in "${forbidden_patterns[@]}"; do
    if smoke_log_contains "${pattern}"; then
      echo "error: Happ mux UDP DNS baseline saw forbidden regression log: ${pattern}" >&2
      return 1
    fi
  done

  return 0
}

smoke_log_matches_any() {
  local pattern
  for pattern in "$@"; do
    if smoke_log_contains "${pattern}"; then
      return 0
    fi
  done
  return 1
}

smoke_expect_vless_negative() {
  local name="$1"
  local decrypt_before="$2"
  shift 2
  local patterns=("$@")

  if ! kill -0 "${SMOKE_SERVER_PID}" 2>/dev/null; then
    echo "error: ${name} rust-xray server is not running" >&2
    return 1
  fi

  if smoke_log_contains "panicked at"; then
    echo "error: ${name} rust-xray panicked" >&2
    return 1
  fi

  local decrypt_after
  decrypt_after="$(smoke_decrypt_failure_count)"
  if [[ "${decrypt_after}" -gt "${decrypt_before}" ]]; then
    echo "error: ${name} saw new AES-GCM decrypt failures" >&2
    return 1
  fi

  if ! smoke_log_matches_any "${patterns[@]}"; then
    echo "error: ${name} missing expected server log patterns: ${patterns[*]}" >&2
    return 1
  fi

  if [[ -n "${SMOKE_REGRESSION_SERVER_CONFIG:-}" ]]; then
    smoke_stop_stack
    smoke_start_stack \
      "${SMOKE_REGRESSION_SERVER_CONFIG}" \
      "${SMOKE_CLIENT_CONFIG_FOR_REGRESSION:-}"
  else
    smoke_stop_process "${SMOKE_CLIENT_PID:-}"
    smoke_start_client "${SMOKE_CLIENT_CONFIG_FOR_REGRESSION:-}"
  fi
  sleep 1

  smoke_record_curl "${name}-tcp-regression" -m 20 "${SMOKE_QUICK_URL}"
}

smoke_curl_socks() {
  curl -sS -o /dev/null -w '%{http_code}' \
    -x "socks5h://127.0.0.1:${SMOKE_SOCKS_PORT}" \
    "$@"
}

smoke_record_curl() {
  local name="$1"
  shift
  local http_code exit_code
  set +e
  http_code="$(smoke_curl_socks "$@")"
  exit_code=$?
  set -e
  SMOKE_CURL_NAMES+=("${name}")
  SMOKE_CURL_EXIT_CODES+=("${exit_code}")
  SMOKE_CURL_HTTP_CODES+=("${http_code}")
  if [[ "${exit_code}" -eq 0 && "${http_code}" =~ ^2 ]]; then
    SMOKE_CURL_PASSED=$((SMOKE_CURL_PASSED + 1))
    return 0
  fi
  SMOKE_CURL_FAILED=$((SMOKE_CURL_FAILED + 1))
  return 1
}

smoke_expect_curl_fail() {
  local name="$1"
  shift
  local http_code exit_code
  set +e
  http_code="$(smoke_curl_socks "$@")"
  exit_code=$?
  set -e
  SMOKE_CURL_NAMES+=("${name}")
  SMOKE_CURL_EXIT_CODES+=("${exit_code}")
  SMOKE_CURL_HTTP_CODES+=("${http_code}")
  if [[ "${exit_code}" -ne 0 ]]; then
    SMOKE_CURL_PASSED=$((SMOKE_CURL_PASSED + 1))
    return 0
  fi
  SMOKE_CURL_FAILED=$((SMOKE_CURL_FAILED + 1))
  echo "error: expected curl failure for ${name}, got exit=${exit_code} http=${http_code}" >&2
  return 1
}

smoke_log_contains() {
  local pattern="$1"
  grep -Fq "${pattern}" "${SMOKE_SERVER_LOG}"
}

smoke_log_line_count() {
  local log_path="$1"
  if [[ ! -f "${log_path}" ]]; then
    echo 0
    return 0
  fi
  wc -l <"${log_path}" | tr -d ' '
}

smoke_log_contains_since() {
  local log_path="$1"
  local start_line="$2"
  local pattern="$3"
  if [[ ! -f "${log_path}" ]]; then
    return 1
  fi
  tail -n +"$((start_line + 1))" "${log_path}" | grep -Fq "${pattern}"
}

smoke_extract_server_negotiated_cipher() {
  local log_path="$1"
  local line suite_name suite_id
  line="$(grep -F 'REALITY TLS 1.3 server state created' "${log_path}" | tail -1 || true)"
  if [[ -z "${line}" ]]; then
    echo "missing"
    return 0
  fi

  suite_name="$(
    printf '%s\n' "${line}" |
      sed -n 's/.*cipher_suite="\([^"]*\)".*/\1/p' |
      tail -1
  )"
  suite_id="$(
    printf '%s\n' "${line}" |
      sed -n 's/.*cipher_suite_id="\([^"]*\)".*/\1/p' |
      tail -1
  )"

  if [[ -z "${suite_name}" ]]; then
    suite_name="$(
      printf '%s\n' "${line}" |
        grep -oE 'cipher_suite=[^[:space:]]+' |
        tail -1 |
        cut -d= -f2- |
        tr -d '"'
    )"
  fi
  if [[ -z "${suite_id}" ]]; then
    suite_id="$(
      printf '%s\n' "${line}" |
        grep -oE 'cipher_suite_id=0x[0-9a-fA-F]+' |
        tail -1 |
        cut -d= -f2-
    )"
  fi

  if [[ -n "${suite_name}" && -n "${suite_id}" ]]; then
    echo "${suite_name} (${suite_id})"
    return 0
  fi
  if [[ -n "${suite_name}" ]]; then
    echo "${suite_name} (unknown-id)"
    return 0
  fi
  echo "unparsed"
}

smoke_extract_dest_negotiated_cipher() {
  local log_path="$1"
  local start_line="$2"
  local dest_port="$3"
  local line
  if [[ ! -f "${log_path}" ]]; then
    echo "missing"
    return 0
  fi
  line="$(
    tail -n +"$((start_line + 1))" "${log_path}" |
      grep -F "negotiated_cipher port=${dest_port} " |
      tail -1 || true
  )"
  if [[ -z "${line}" ]]; then
    echo "missing"
    return 0
  fi
  if [[ "${line}" =~ suite=([^[:space:]]+) ]]; then
    local suite_name="${BASH_REMATCH[1]}"
    if [[ "${line}" =~ suite_id=(0x[0-9a-fA-F]+) ]]; then
      echo "${suite_name} (${BASH_REMATCH[1]})"
      return 0
    fi
    echo "${suite_name} (unknown-id)"
    return 0
  fi
  echo "unparsed"
}

smoke_count_log() {
  local pattern="$1"
  grep -Fc "${pattern}" "${SMOKE_SERVER_LOG}" || true
}

smoke_write_report() {
  local report_path="$1"
  local accepted_complete accepted_failed relay_completed vision_direct decrypt_failed

  accepted_complete="$(smoke_count_log 'REALITY accepted path complete')"
  accepted_failed="$(smoke_count_log 'REALITY accepted path failed')"
  relay_completed="$(smoke_count_log 'VLESS TCP relay completed')"
  vision_direct="$(smoke_count_log 'vision direct command received')"
  decrypt_failed="$(
    grep -Ec 'AES-(128|256)-GCM decrypt failed|ChaCha20-Poly1305 decrypt failed|TLS application-stream record decrypt failed' \
      "${SMOKE_SERVER_LOG}" || true
  )"
  local mux_query mux_response mux_frame mux_forbidden_substream mux_forbidden_packet
  mux_query="$(smoke_count_log 'mux udp dns query forwarded')"
  mux_response="$(smoke_count_log 'mux udp dns response received')"
  mux_frame="$(smoke_count_log 'mux udp response frame sent')"
  mux_forbidden_substream="$(smoke_count_log 'UDP mux substream is not implemented')"
  mux_forbidden_packet="$(smoke_count_log 'UDP mux packet is not implemented')"

  {
    echo "rust-xray live smoke report"
    echo "generated_at: $(date -u +%Y-%m-%dT%H:%M:%SZ)"
    echo "server_log: ${SMOKE_SERVER_LOG}"
    echo "client_log: ${SMOKE_CLIENT_LOG}"
    echo
    echo "[server metrics]"
    echo "accepted_path_complete: ${accepted_complete}"
    echo "accepted_path_failed: ${accepted_failed}"
    echo "vless_tcp_relay_completed: ${relay_completed}"
    echo "vision_direct_command_received: ${vision_direct}"
    echo "aes_gcm_decrypt_failed: ${decrypt_failed}"
    echo
    echo "[happ mux baseline]"
    echo "mux_udp_dns_query_forwarded: ${mux_query}"
    echo "mux_udp_dns_response_received: ${mux_response}"
    echo "mux_udp_response_frame_sent: ${mux_frame}"
    echo "forbidden_udp_mux_substream_not_implemented: ${mux_forbidden_substream}"
    echo "forbidden_udp_mux_packet_not_implemented: ${mux_forbidden_packet}"
    echo
    echo "[curl summary]"
    echo "curl_checks_passed: ${SMOKE_CURL_PASSED}"
    echo "curl_checks_failed: ${SMOKE_CURL_FAILED}"
    echo
    echo "[curl cases]"
    local idx
    for idx in "${!SMOKE_CURL_NAMES[@]}"; do
      echo "${SMOKE_CURL_NAMES[$idx]}: exit=${SMOKE_CURL_EXIT_CODES[$idx]} http=${SMOKE_CURL_HTTP_CODES[$idx]}"
    done
    echo
    if ((${#SMOKE_CIPHER_DETAILS[@]} > 0)); then
      echo "[cipher validation]"
      echo "cipher_tls_log: ${SMOKE_CIPHER_TLS_LOG:-n/a}"
      local cipher_idx
      for cipher_idx in "${!SMOKE_CIPHER_DETAILS[@]}"; do
        echo "${SMOKE_CIPHER_DETAILS[$cipher_idx]}"
      done
      echo
    fi
    echo "[phase results]"
    local phase
    for phase in "${SMOKE_PHASE_NAMES[@]}"; do
      echo "${phase}"
    done
    echo
    echo "[mldsa65 summary]"
    echo "mldsa65_checks_passed: ${SMOKE_MLDSA65_PASSED:-0}"
    echo "mldsa65_checks_failed: ${SMOKE_MLDSA65_FAILED:-0}"
    local mldsa65_detail
    if [[ -n "${SMOKE_MLDSA65_DETAILS+x}" ]]; then
      for mldsa65_detail in "${SMOKE_MLDSA65_DETAILS[@]}"; do
        echo "${mldsa65_detail}"
      done
    fi
  } >"${report_path}"

  cat "${report_path}"
}
