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

smoke_stop_process() {
  local pid="${1:-}"
  if [[ -n "${pid}" ]] && kill -0 "${pid}" >/dev/null 2>&1; then
    kill "${pid}" >/dev/null 2>&1 || true
    wait "${pid}" 2>/dev/null || true
  fi
}

smoke_stop_stack() {
  smoke_stop_process "${SMOKE_CLIENT_PID:-}"
  smoke_stop_process "${SMOKE_SERVER_PID:-}"
  SMOKE_CLIENT_PID=""
  SMOKE_SERVER_PID=""
}

smoke_start_server() {
  local server_config="$1"
  smoke_stop_process "${SMOKE_SERVER_PID:-}"
  : >>"${SMOKE_SERVER_LOG}"
  RUST_LOG="${SMOKE_RUST_LOG:-info}" "${SMOKE_RUST_XRAY_BIN}" "${server_config}" >>"${SMOKE_SERVER_LOG}" 2>&1 &
  SMOKE_SERVER_PID=$!
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

smoke_write_client_config() {
  local template_path="$1"
  local output_path="$2"
  local flow="${3:-}"
  local user_id="${4:-11111111-1111-1111-1111-111111111111}"
  local short_id="${5:-0123456789abcdef}"
  local server_name="${6:-www.microsoft.com}"

  SMOKE_TEMPLATE="${template_path}" \
    SMOKE_OUTPUT="${output_path}" \
    SMOKE_FLOW="${flow}" \
    SMOKE_USER_ID="${user_id}" \
    SMOKE_SHORT_ID="${short_id}" \
    SMOKE_SERVER_NAME="${server_name}" \
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

output.write_text(json.dumps(cfg, indent=2) + "\n")
PY
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
    echo "[phase results]"
    local phase
    for phase in "${SMOKE_PHASE_NAMES[@]}"; do
      echo "${phase}"
    done
  } >"${report_path}"

  cat "${report_path}"
}
