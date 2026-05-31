#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/../.." && pwd)"

TEST_PUBLIC_KEY="${TEST_PUBLIC_KEY:-oU1MbEgszawWQJa0S_DxLsNt9G2zyE4rF-CrqvJjTmg}"
XHTTP_SERVER_PORT="${XHTTP_SERVER_PORT:-24443}"
XHTTP_SOCKS_PORT="${XHTTP_SOCKS_PORT:-10808}"
XHTTP_HTTP_PORT="${XHTTP_HTTP_PORT:-10809}"
XHTTP_TARGET_URL="${XHTTP_TARGET_URL:-https://example.com/}"
XHTTP_WORK_DIR="${XHTTP_WORK_DIR:-/tmp/rust-xray-live-xhttp-smoke-$$}"
XHTTP_REPORT_PATH="${XHTTP_REPORT_PATH:-${XHTTP_WORK_DIR}/report.txt}"
XHTTP_SKIP_BUILD="${XHTTP_SKIP_BUILD:-0}"
XHTTP_MODE_TIMEOUT="${XHTTP_MODE_TIMEOUT:-90}"
XHTTP_RUST_LOG="${XHTTP_RUST_LOG:-rust_xray::transport::xhttp=debug,rust_xray::xhttp_diagnostics=warn,rust_xray::xhttp_bridge=debug,rust_xray::app=debug,rust_xray::vless=debug,warn}"
XHTTP_RUST_XRAY_BIN="${REPO_ROOT}/target/debug/rust-xray"

SERVER_TEMPLATE="${SCRIPT_DIR}/rust-xray-server-xhttp.json"
CLIENT_TEMPLATE="${SCRIPT_DIR}/xray-client-xhttp.json"

SERVER_PID=""
CLIENT_PID=""

declare -A MODE_RESULT=()
declare -A MODE_CLASSIFICATION=()
declare -A MODE_HTTP_VERSION=()

CURL_CHECKS_PASSED=0
CURL_CHECKS_FAILED=0
XHTTP_REQUEST_RECEIVED=0
XHTTP_BRIDGE_STARTED=0
XHTTP_BRIDGE_COMPLETED=0
XHTTP_UNSUPPORTED_MODE=0
HTTP_VERSIONS=()
SUPPORTED_PASS=0
PACKET_UP_SHAPE_LINES=()

extract_packet_up_shapes() {
  local server_log="$1"
  grep -F 'xhttp packet-up request shape' "${server_log}" 2>/dev/null || true
}

require_command() {
  if ! command -v "$1" >/dev/null 2>&1; then
    echo "error: required command not found in PATH: $1" >&2
    exit 1
  fi
}

stop_process() {
  local pid="${1:-}"
  if [[ -n "${pid}" ]] && kill -0 "${pid}" >/dev/null 2>&1; then
    kill "${pid}" >/dev/null 2>&1 || true
    local waited=0
    while kill -0 "${pid}" >/dev/null 2>&1 && (( waited < 50 )); do
      sleep 0.1
      waited=$((waited + 1))
    done
    if kill -0 "${pid}" >/dev/null 2>&1; then
      kill -9 "${pid}" >/dev/null 2>&1 || true
    fi
    wait "${pid}" 2>/dev/null || true
  fi
}

free_tcp_port() {
  if command -v fuser >/dev/null 2>&1; then
    fuser -k "$1/tcp" >/dev/null 2>&1 || true
  fi
}

wait_port() {
  local host="$1"
  local port="$2"
  local label="$3"
  local timeout="${4:-80}"
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

stop_stack() {
  stop_process "${CLIENT_PID}"
  stop_process "${SERVER_PID}"
  CLIENT_PID=""
  SERVER_PID=""
  free_tcp_port "${XHTTP_SOCKS_PORT}"
  free_tcp_port "${XHTTP_HTTP_PORT}"
  free_tcp_port "${XHTTP_SERVER_PORT}"
}

cleanup() {
  stop_stack
}
trap cleanup EXIT

build_rust_xray() {
  if [[ "${XHTTP_SKIP_BUILD}" == "1" ]]; then
    echo "Skipping cargo build (XHTTP_SKIP_BUILD=1)"
    return 0
  fi
  (
    cd "${REPO_ROOT}"
    cargo build --bin rust-xray
  )
}

mode_config_value() {
  local mode_key="$1"
  case "${mode_key}" in
    default) printf '' ;;
    auto) printf 'auto' ;;
    stream_one) printf 'stream-one' ;;
    packet_up) printf 'packet-up' ;;
    stream_up) printf 'stream-up' ;;
    packet_down) printf 'packet-down' ;;
    *) echo "error: unknown mode key: ${mode_key}" >&2; return 1 ;;
  esac
}

mode_log_label() {
  local mode_key="$1"
  case "${mode_key}" in
    default) printf 'default' ;;
    auto) printf 'auto' ;;
    stream_one) printf 'stream-one' ;;
    packet_up) printf 'packet-up' ;;
    stream_up) printf 'stream-up' ;;
    packet_down) printf 'packet-down' ;;
    *) printf '%s' "${mode_key}" ;;
  esac
}

is_expected_unsupported_mode() {
  case "$1" in
    packet_up|stream_up|packet_down) return 0 ;;
    *) return 1 ;;
  esac
}

write_configs() {
  local mode_key="$1"
  local mode_value
  mode_value="$(mode_config_value "${mode_key}")"
  local label
  label="$(mode_log_label "${mode_key}")"
  local server_config="${XHTTP_WORK_DIR}/server-${label}.json"
  local client_config="${XHTTP_WORK_DIR}/client-${label}.json"

  MODE="${mode_value}" \
  SERVER_PORT="${XHTTP_SERVER_PORT}" \
  SOCKS_PORT="${XHTTP_SOCKS_PORT}" \
  HTTP_PORT="${XHTTP_HTTP_PORT}" \
  PUBLIC_KEY="${TEST_PUBLIC_KEY}" \
  SERVER_TEMPLATE="${SERVER_TEMPLATE}" \
  CLIENT_TEMPLATE="${CLIENT_TEMPLATE}" \
  SERVER_OUT="${server_config}" \
  CLIENT_OUT="${client_config}" \
  python3 - <<'PY'
import json
import os
from pathlib import Path

mode = os.environ["MODE"]
server = json.loads(Path(os.environ["SERVER_TEMPLATE"]).read_text())
client = json.loads(Path(os.environ["CLIENT_TEMPLATE"]).read_text())

server["inbounds"][0]["port"] = int(os.environ["SERVER_PORT"])
client["inbounds"][0]["port"] = int(os.environ["SOCKS_PORT"])
client["inbounds"][1]["port"] = int(os.environ["HTTP_PORT"])
client["outbounds"][0]["settings"]["vnext"][0]["port"] = int(os.environ["SERVER_PORT"])
client["outbounds"][0]["streamSettings"]["realitySettings"]["publicKey"] = os.environ["PUBLIC_KEY"]

server_xhttp = server["inbounds"][0]["streamSettings"]["xhttpSettings"]
client_xhttp = client["outbounds"][0]["streamSettings"]["xhttpSettings"]
if mode:
    server_xhttp["mode"] = mode
    client_xhttp["mode"] = mode
else:
    server_xhttp.pop("mode", None)
    client_xhttp.pop("mode", None)

Path(os.environ["SERVER_OUT"]).write_text(json.dumps(server, indent=2) + "\n")
Path(os.environ["CLIENT_OUT"]).write_text(json.dumps(client, indent=2) + "\n")
PY

  printf '%s\n%s\n' "${server_config}" "${client_config}"
}

count_log() {
  local pattern="$1"
  local file="$2"
  grep -Ec "${pattern}" "${file}" 2>/dev/null || true
}

detect_http_version() {
  local server_log="$1"
  if grep -Eq 'version=HTTP/1\.1|version="HTTP/1\.1"' "${server_log}"; then
    printf 'HTTP/1.1'
  elif grep -Eq 'HTTP/2|PRI \* HTTP/2\.0' "${server_log}"; then
    printf 'HTTP/2'
  else
    printf 'unknown'
  fi
}

classify_failure() {
  local server_log="$1"
  local client_log="$2"
  local curl_exit="$3"
  local http_code="$4"
  local timed_out="$5"

  if [[ "${timed_out}" == "1" ]]; then
    printf 'timeout'
    return
  fi
  if grep -Fq "xhttp mode unsupported" "${server_log}" \
    && grep -Fq "REALITY listener started" "${server_log}"; then
    printf 'unsupported_mode'
    return
  fi
  if [[ "${curl_exit}" == "0" && "${http_code}" == "200" ]] \
    && grep -Fq "xhttp request received" "${server_log}" \
    && grep -Fq "VLESS client authenticated" "${server_log}"; then
    printf 'pass'
    return
  fi
  if grep -Fq "not supported in this MVP" "${server_log}" \
    || grep -Fq "xhttp mode unsupported" "${server_log}"; then
    printf 'unsupported_mode'
  elif grep -Fq "failed to load config" "${server_log}" \
    || grep -Fq "failed to load REALITY runtime" "${server_log}"; then
    if grep -Fq "not supported in this MVP" "${server_log}"; then
      printf 'unsupported_mode'
    else
      printf 'config_parse_failure'
    fi
  elif grep -Fq "failed to bind inbound" "${server_log}" \
    || ! grep -Fq "REALITY listener started" "${server_log}"; then
    printf 'server_start_failure'
  elif grep -Fq "failed to start" "${client_log}"; then
    printf 'client_start_failure'
  elif grep -Fq "xhttp path rejected" "${server_log}" \
    || grep -Fq "xhttp method rejected" "${server_log}"; then
    printf 'http_path_mismatch'
  elif grep -Fq "VLESS flow mismatch" "${server_log}" \
    || grep -Fq "unknown vless client id" "${server_log}"; then
    printf 'vless_auth_failure'
  elif grep -Fq "REALITY accepted path failed" "${server_log}" \
    || grep -Fq "REALITY inspect failed" "${server_log}"; then
    printf 'reality_failure'
  elif grep -Fq "xhttp bridge failed" "${server_log}"; then
    printf 'bridge_failure'
  elif [[ "${curl_exit}" != "0" || "${http_code}" != "200" ]]; then
    printf 'curl_failure'
  else
    printf 'curl_failure'
  fi
}

finalize_mode_result() {
  local mode_key="$1"
  local outcome="$2"
  local classification="$3"
  local http_version="${4:-unknown}"

  MODE_RESULT["${mode_key}"]="${outcome}"
  MODE_CLASSIFICATION["${mode_key}"]="${classification}"
  MODE_HTTP_VERSION["${mode_key}"]="${http_version}"

  case "${outcome}" in
    PASS)
      SUPPORTED_PASS=1
      ;;
  esac
}

run_mode_impl() {
  local mode_key="$1"
  local label
  label="$(mode_log_label "${mode_key}")"
  local configs
  configs="$(write_configs "${mode_key}")"
  local server_config client_config
  server_config="$(printf '%s\n' "${configs}" | sed -n '1p')"
  client_config="$(printf '%s\n' "${configs}" | sed -n '2p')"
  local server_log="${XHTTP_WORK_DIR}/server-${label}.log"
  local client_log="${XHTTP_WORK_DIR}/client-${label}.log"
  local curl_socks_log="${XHTTP_WORK_DIR}/curl-socks-${label}.log"
  local curl_http_log="${XHTTP_WORK_DIR}/curl-http-${label}.log"

  stop_stack
  : >"${server_log}"
  : >"${client_log}"
  : >"${curl_socks_log}"
  : >"${curl_http_log}"

  RUST_LOG="${XHTTP_RUST_LOG}" "${XHTTP_RUST_XRAY_BIN}" "${server_config}" >"${server_log}" 2>&1 &
  SERVER_PID=$!
  sleep 0.3

  local server_start=PASS
  local timed_out=0
  if ! kill -0 "${SERVER_PID}" >/dev/null 2>&1; then
    server_start=FAIL
  elif ! wait_port 127.0.0.1 "${XHTTP_SERVER_PORT}" "rust-xray xhttp server" 40; then
    server_start=FAIL
    if kill -0 "${SERVER_PID}" >/dev/null 2>&1; then
      timed_out=1
    fi
  fi

  local curl_exit=1
  local http_code="000"
  local curl_http_exit=1
  local http_http_code="000"
  local client_start=SKIP

  if [[ "${server_start}" == "PASS" ]]; then
    xray run -config "${client_config}" >"${client_log}" 2>&1 &
    CLIENT_PID=$!
    if wait_port 127.0.0.1 "${XHTTP_SOCKS_PORT}" "official xray client SOCKS" 40 \
      && wait_port 127.0.0.1 "${XHTTP_HTTP_PORT}" "official xray client HTTP" 40; then
      client_start=PASS
      set +e
      http_code="$(curl -sS -o /dev/null -w '%{http_code}' -m 30 \
        -x "socks5h://127.0.0.1:${XHTTP_SOCKS_PORT}" \
        "${XHTTP_TARGET_URL}" 2>"${curl_socks_log}")"
      curl_exit=$?
      http_http_code="$(curl -sS -o /dev/null -w '%{http_code}' -m 30 \
        -x "http://127.0.0.1:${XHTTP_HTTP_PORT}" \
        "${XHTTP_TARGET_URL}" 2>"${curl_http_log}")"
      curl_http_exit=$?
      set -e
    else
      client_start=FAIL
      if kill -0 "${CLIENT_PID}" >/dev/null 2>&1; then
        timed_out=1
      fi
    fi
  fi

  sleep 0.2
  stop_stack

  local received bridge_started bridge_completed unsupported_mode
  received="$(count_log 'xhttp request received' "${server_log}")"
  bridge_started="$(count_log 'xhttp bridge started' "${server_log}")"
  bridge_completed="$(count_log 'xhttp bridge completed' "${server_log}")"
  unsupported_mode="$(count_log 'xhttp mode unsupported' "${server_log}")"
  if [[ "${unsupported_mode}" == "0" ]] && grep -Fq "not supported in this MVP" "${server_log}"; then
    unsupported_mode=1
  fi

  XHTTP_REQUEST_RECEIVED=$((XHTTP_REQUEST_RECEIVED + received))
  XHTTP_BRIDGE_STARTED=$((XHTTP_BRIDGE_STARTED + bridge_started))
  XHTTP_BRIDGE_COMPLETED=$((XHTTP_BRIDGE_COMPLETED + bridge_completed))
  XHTTP_UNSUPPORTED_MODE=$((XHTTP_UNSUPPORTED_MODE + unsupported_mode))

  local observed_version
  observed_version="$(detect_http_version "${server_log}")"
  if [[ "${observed_version}" != "unknown" ]]; then
    HTTP_VERSIONS+=("${observed_version}")
  fi

  local classification
  classification="$(classify_failure "${server_log}" "${client_log}" "${curl_exit}" "${http_code}" "${timed_out}")"

  local outcome=FAIL
  if [[ "${classification}" == "unsupported_mode" ]]; then
    outcome=UNSUPPORTED
  elif is_expected_unsupported_mode "${mode_key}" \
    && [[ "${server_start}" == "PASS" ]] \
    && [[ "${bridge_started}" == "0" ]] \
    && [[ "${timed_out}" != "1" ]]; then
    outcome=UNSUPPORTED
    classification="unsupported_mode"
  elif [[ "${curl_exit}" == "0" && "${http_code}" == "200" \
    && "${curl_http_exit}" == "0" && "${http_http_code}" == "200" \
    && "${server_start}" == "PASS" && "${client_start}" == "PASS" ]]; then
    outcome=PASS
    CURL_CHECKS_PASSED=$((CURL_CHECKS_PASSED + 2))
  elif [[ "${curl_exit}" == "0" && "${http_code}" == "200" \
    && "${server_start}" == "PASS" && "${client_start}" == "PASS" ]]; then
    outcome=PASS
    CURL_CHECKS_PASSED=$((CURL_CHECKS_PASSED + 1))
    CURL_CHECKS_FAILED=$((CURL_CHECKS_FAILED + 1))
  elif [[ "${server_start}" != "PASS" || "${client_start}" == "SKIP" ]]; then
    :
  else
    CURL_CHECKS_FAILED=$((CURL_CHECKS_FAILED + 2))
  fi

  finalize_mode_result "${mode_key}" "${outcome}" "${classification}" "${observed_version}"

  local packet_up_shapes=""
  if [[ "${mode_key}" == "packet_up" ]]; then
    packet_up_shapes="$(extract_packet_up_shapes "${server_log}")"
    if [[ -n "${packet_up_shapes}" ]]; then
      while IFS= read -r shape_line; do
        [[ -n "${shape_line}" ]] && PACKET_UP_SHAPE_LINES+=("${shape_line}")
      done <<<"${packet_up_shapes}"
    fi
  fi

  {
    echo "[mode ${label}]"
    echo "result: ${outcome}"
    echo "classification: ${classification}"
    echo "server_start: ${server_start}"
    echo "client_start: ${client_start}"
    echo "curl_socks_exit: ${curl_exit}"
    echo "curl_socks_http: ${http_code}"
    echo "curl_http_exit: ${curl_http_exit}"
    echo "curl_http_http: ${http_http_code}"
    echo "http_version: ${observed_version}"
    echo "xhttp_request_received: ${received}"
    echo "xhttp_bridge_started: ${bridge_started}"
    echo "xhttp_bridge_completed: ${bridge_completed}"
    echo "xhttp_unsupported_mode: ${unsupported_mode}"
    if [[ "${mode_key}" == "packet_up" ]]; then
      echo "packet_up_observed_request_shapes:"
      if [[ -n "${packet_up_shapes}" ]]; then
        printf '%s\n' "${packet_up_shapes}"
      else
        echo "(none captured)"
      fi
    fi
    echo
    if [[ "${outcome}" != "PASS" ]]; then
      echo "[mode_${label} server.log tail]"
      tail -50 "${server_log}" || true
      echo
      echo "[mode_${label} client.log tail]"
      tail -50 "${client_log}" || true
      echo
    fi
  } >>"${XHTTP_REPORT_PATH}"

  echo "mode ${label}: ${outcome} classification=${classification} socks=${http_code} http=${http_http_code} version=${observed_version}"
}

run_mode() {
  local mode_key="$1"
  local label
  label="$(mode_log_label "${mode_key}")"
  local mode_started
  mode_started="$(date +%s)"

  run_mode_impl "${mode_key}"

  local mode_elapsed=$(( $(date +%s) - mode_started ))
  if (( mode_elapsed > XHTTP_MODE_TIMEOUT )); then
    echo "mode ${label}: FAIL classification=timeout (mode exceeded ${XHTTP_MODE_TIMEOUT}s)" >&2
    MODE_RESULT["${mode_key}"]=FAIL
    MODE_CLASSIFICATION["${mode_key}"]=timeout
    CURL_CHECKS_FAILED=$((CURL_CHECKS_FAILED + 2))
    {
      echo "[mode ${label} timeout]"
      echo "result: FAIL"
      echo "classification: timeout"
      echo
    } >>"${XHTTP_REPORT_PATH}"
  fi
}

write_summary() {
  local versions=""
  if ((${#HTTP_VERSIONS[@]} > 0)); then
    versions="$(printf '%s\n' "${HTTP_VERSIONS[@]}" | sort -u | paste -sd, -)"
  else
    versions="none"
  fi

  {
    echo
    echo "[xhttp summary]"
    echo "mode_default: ${MODE_RESULT[default]:-FAIL}"
    echo "mode_auto: ${MODE_RESULT[auto]:-FAIL}"
    echo "mode_stream_one: ${MODE_RESULT[stream_one]:-FAIL}"
    echo "mode_packet_up: ${MODE_RESULT[packet_up]:-FAIL}"
    echo "mode_stream_up: ${MODE_RESULT[stream_up]:-FAIL}"
    echo "mode_packet_down: ${MODE_RESULT[packet_down]:-FAIL}"
    echo "curl_checks_passed: ${CURL_CHECKS_PASSED}"
    echo "curl_checks_failed: ${CURL_CHECKS_FAILED}"
    echo "http_version_observed: ${versions}"
    echo "xhttp_request_received: ${XHTTP_REQUEST_RECEIVED}"
    echo "xhttp_bridge_started: ${XHTTP_BRIDGE_STARTED}"
    echo "xhttp_bridge_completed: ${XHTTP_BRIDGE_COMPLETED}"
    echo "xhttp_unsupported_mode: ${XHTTP_UNSUPPORTED_MODE}"
    echo
    echo "[packet-up diagnostics]"
    if ((${#PACKET_UP_SHAPE_LINES[@]} > 0)); then
      printf '%s\n' "${PACKET_UP_SHAPE_LINES[@]}"
    else
      echo "packet_up_observed_request_shapes: (none captured)"
    fi
    echo
    echo "[failure classifications]"
    echo "mode_default: ${MODE_CLASSIFICATION[default]:-unknown}"
    echo "mode_auto: ${MODE_CLASSIFICATION[auto]:-unknown}"
    echo "mode_stream_one: ${MODE_CLASSIFICATION[stream_one]:-unknown}"
    echo "mode_packet_up: ${MODE_CLASSIFICATION[packet_up]:-unknown}"
    echo "mode_stream_up: ${MODE_CLASSIFICATION[stream_up]:-unknown}"
    echo "mode_packet_down: ${MODE_CLASSIFICATION[packet_down]:-unknown}"
    echo
    echo "known classifications:"
    echo "- config_parse_failure"
    echo "- server_start_failure"
    echo "- client_start_failure"
    echo "- reality_failure"
    echo "- http_path_mismatch"
    echo "- unsupported_mode"
    echo "- vless_auth_failure"
    echo "- bridge_failure"
    echo "- curl_failure"
    echo "- timeout"
    echo
    echo "server_logs: ${XHTTP_WORK_DIR}/server-*.log"
    echo "client_logs: ${XHTTP_WORK_DIR}/client-*.log"
  } >>"${XHTTP_REPORT_PATH}"
}

assert_acceptance() {
  local failures=0

  for required_mode in default auto stream_one; do
    if [[ "${MODE_RESULT[${required_mode}]:-FAIL}" != "PASS" ]]; then
      echo "acceptance failed: mode_${required_mode} must PASS" >&2
      failures=1
    fi
  done

  for unsupported_mode in packet_up stream_up packet_down; do
    case "${MODE_RESULT[${unsupported_mode}]:-FAIL}" in
      PASS|UNSUPPORTED) ;;
      *)
        echo "acceptance failed: mode_${unsupported_mode} must be PASS or UNSUPPORTED, got ${MODE_RESULT[${unsupported_mode}]:-FAIL}" >&2
        failures=1
        ;;
    esac
    if [[ "${MODE_CLASSIFICATION[${unsupported_mode}]:-}" == "timeout" ]]; then
      echo "acceptance failed: mode_${unsupported_mode} hung (timeout)" >&2
      failures=1
    fi
  done

  if [[ ! -f "${XHTTP_REPORT_PATH}" ]]; then
    echo "acceptance failed: report.txt missing" >&2
    failures=1
  fi

  return "${failures}"
}

main() {
  require_command cargo
  require_command xray
  require_command curl
  require_command python3
  mkdir -p "${XHTTP_WORK_DIR}"
  : >"${XHTTP_REPORT_PATH}"

  build_rust_xray

  {
    echo "rust-xray live XHTTP smoke report"
    echo "generated_at: $(date -u +%Y-%m-%dT%H:%M:%SZ)"
    echo "target_url: ${XHTTP_TARGET_URL}"
    echo "server_port: ${XHTTP_SERVER_PORT}"
    echo "socks_port: ${XHTTP_SOCKS_PORT}"
    echo "http_port: ${XHTTP_HTTP_PORT}"
    echo "mode_timeout_sec: ${XHTTP_MODE_TIMEOUT}"
    echo
  } >>"${XHTTP_REPORT_PATH}"

  run_mode default
  run_mode auto
  run_mode stream_one
  run_mode packet_up
  run_mode stream_up
  run_mode packet_down

  write_summary
  cat "${XHTTP_REPORT_PATH}"

  if ! assert_acceptance; then
    echo "live XHTTP smoke failed; report written to ${XHTTP_REPORT_PATH}" >&2
    return 1
  fi
  echo "live XHTTP smoke passed; report written to ${XHTTP_REPORT_PATH}"
}

if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
  main "$@"
fi
