#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/../.." && pwd)"

# shellcheck source=scripts/live_reality_smoke/smoke-lib.sh
source "${SCRIPT_DIR}/smoke-lib.sh"

TEST_PUBLIC_KEY="${TEST_PUBLIC_KEY:-oU1MbEgszawWQJa0S_DxLsNt9G2zyE4rF-CrqvJjTmg}"
SMOKE_SERVER_PORT="${SMOKE_SERVER_PORT:-24443}"
SMOKE_SOCKS_PORT="${SMOKE_SOCKS_PORT:-10808}"
SMOKE_RUST_LOG="${SMOKE_RUST_LOG:-info}"
SMOKE_WORK_DIR="${SMOKE_WORK_DIR:-/tmp/rust-xray-live-smoke-$$}"
SMOKE_REPORT_PATH="${SMOKE_REPORT_PATH:-${SMOKE_WORK_DIR}/report.txt}"
SMOKE_QUICK_URL="${SMOKE_QUICK_URL:-https://example.com/}"
SMOKE_DOWNLOAD_10MB_URL="${SMOKE_DOWNLOAD_10MB_URL:-https://speed.cloudflare.com/__down?bytes=10485760}"
SMOKE_DOWNLOAD_100MB_URL="${SMOKE_DOWNLOAD_100MB_URL:-https://proof.ovh.net/files/100Mb.dat}"
SMOKE_SKIP_BUILD="${SMOKE_SKIP_BUILD:-0}"
SMOKE_SKIP_LIVE="${SMOKE_SKIP_LIVE:-0}"

SMOKE_SERVER_LOG="${SMOKE_WORK_DIR}/server.log"
SMOKE_CLIENT_LOG="${SMOKE_WORK_DIR}/client.log"
SMOKE_FALLBACK_HIT_DIR="${SMOKE_WORK_DIR}/fallback-hits"
SMOKE_RUST_XRAY_BIN="${REPO_ROOT}/target/debug/rust-xray"

SMOKE_SERVER_PID=""
SMOKE_CLIENT_PID=""
SMOKE_FAILED=0
SMOKE_CURL_PASSED=0
SMOKE_CURL_FAILED=0
SMOKE_CURL_NAMES=()
SMOKE_CURL_EXIT_CODES=()
SMOKE_CURL_HTTP_CODES=()
SMOKE_PHASE_NAMES=()

SERVER_EMPTY="${SCRIPT_DIR}/rust-xray-server.fixture.json"
SERVER_VISION="${SCRIPT_DIR}/rust-xray-server.vision.fixture.json"
SERVER_RAW="${SCRIPT_DIR}/rust-xray-server.raw.fixture.json"
SERVER_FALLBACKS="${SCRIPT_DIR}/rust-xray-server.fallbacks.fixture.json"
SERVER_CIPHER_AES128="${SCRIPT_DIR}/rust-xray-server.cipher-aes128.fixture.json"
SERVER_CIPHER_AES256="${SCRIPT_DIR}/rust-xray-server.cipher-aes256.fixture.json"
SERVER_CIPHER_CHACHA="${SCRIPT_DIR}/rust-xray-server.cipher-chacha.fixture.json"
CLIENT_TEMPLATE="${SCRIPT_DIR}/xray-client-smoke.fixture.json"
SMOKE_FALLBACK_TCP_PID=""
SMOKE_CIPHER_TLS_PID=""

pass_phase() {
  SMOKE_PHASE_NAMES+=("PASS ${1}")
  echo "== PASS: ${1}"
}

fail_phase() {
  SMOKE_PHASE_NAMES+=("FAIL ${1}")
  SMOKE_FAILED=1
  echo "== FAIL: ${1}" >&2
}

run_phase() {
  local name="$1"
  shift
  if "$@"; then
    pass_phase "${name}"
  else
    fail_phase "${name}"
  fi
}

cleanup() {
  smoke_stop_stack
  smoke_stop_process "${SMOKE_FALLBACK_TCP_PID:-}"
  smoke_stop_process "${SMOKE_CIPHER_TLS_PID:-}"
  SMOKE_FALLBACK_TCP_PID=""
  SMOKE_CIPHER_TLS_PID=""
}
trap cleanup EXIT

prepare_workspace() {
  mkdir -p "${SMOKE_WORK_DIR}"
  : >"${SMOKE_SERVER_LOG}"
  : >"${SMOKE_CLIENT_LOG}"
}

build_rust_xray() {
  if [[ "${SMOKE_SKIP_BUILD}" == "1" ]]; then
    echo "Skipping cargo build (SMOKE_SKIP_BUILD=1)"
    return 0
  fi
  (
    cd "${REPO_ROOT}"
    cargo build --bin rust-xray --all-features
  )
}

client_config() {
  local suffix="$1"
  local flow="${2:-}"
  local user_id="${3:-11111111-1111-1111-1111-111111111111}"
  local short_id="${4:-0123456789abcdef}"
  local server_name="${5:-www.microsoft.com}"
  local output="${SMOKE_WORK_DIR}/client-${suffix}.json"
  smoke_write_client_config \
    "${CLIENT_TEMPLATE}" \
    "${output}" \
    "${flow}" \
    "${user_id}" \
    "${short_id}" \
    "${server_name}"
  printf '%s\n' "${output}"
}

phase_regression_empty_flow() {
  local client
  client="$(client_config empty "" )"
  smoke_start_stack "${SERVER_EMPTY}" "${client}"
  smoke_record_curl "regression-flow-empty" -m 30 "${SMOKE_QUICK_URL}"
}

phase_regression_vision_flow() {
  local client
  client="$(client_config vision "xtls-rprx-vision")"
  smoke_start_stack "${SERVER_VISION}" "${client}"
  smoke_record_curl "regression-flow-vision" -m 30 "${SMOKE_QUICK_URL}"
}

phase_regression_10mb_download() {
  local client
  client="$(client_config vision-10mb "xtls-rprx-vision")"
  smoke_start_stack "${SERVER_VISION}" "${client}"
  smoke_record_curl "regression-download-10mb" -m 180 "${SMOKE_DOWNLOAD_10MB_URL}"
}

phase_regression_bad_short_id_fallback() {
  local client
  client="$(client_config bad-short-id "" "11111111-1111-1111-1111-111111111111" "0000000000000000")"
  smoke_start_stack "${SERVER_EMPTY}" "${client}"
  smoke_expect_curl_fail "regression-bad-short-id-fallback" -m 20 "${SMOKE_QUICK_URL}"
  smoke_log_contains "REALITY fallback" || smoke_log_contains "fallback relay started"
}

phase_regression_bad_sni_fallback() {
  local client
  client="$(client_config bad-sni "" "11111111-1111-1111-1111-111111111111" "0123456789abcdef" "example.com")"
  smoke_start_stack "${SERVER_EMPTY}" "${client}"
  smoke_expect_curl_fail "regression-bad-sni-fallback" -m 20 "${SMOKE_QUICK_URL}"
  smoke_log_contains "REALITY fallback" || smoke_log_contains "fallback relay started"
}

phase_regression_openssl_fallback() {
  local client
  client="$(client_config openssl "" )"
  smoke_start_stack "${SERVER_EMPTY}" "${client}"
  set +e
  echo | timeout 20 openssl s_client \
    -connect "127.0.0.1:${SMOKE_SERVER_PORT}" \
    -servername www.microsoft.com \
    -brief >/dev/null 2>&1
  local openssl_exit=$?
  set -e
  SMOKE_CURL_NAMES+=("regression-openssl-fallback")
  SMOKE_CURL_EXIT_CODES+=("${openssl_exit}")
  SMOKE_CURL_HTTP_CODES+=("n/a")
  if [[ "${openssl_exit}" -eq 0 ]] && smoke_log_contains "fallback relay started"; then
    SMOKE_CURL_PASSED=$((SMOKE_CURL_PASSED + 1))
    return 0
  fi
  SMOKE_CURL_FAILED=$((SMOKE_CURL_FAILED + 1))
  return 1
}

phase_vision_sequential_100() {
  local client success=0 i http_code
  client="$(client_config vision-seq100 "xtls-rprx-vision")"
  smoke_start_stack "${SERVER_VISION}" "${client}"
  for i in $(seq 1 100); do
    set +e
    http_code="$(smoke_curl_socks -m 30 "${SMOKE_QUICK_URL}")"
    set -e
    if [[ "${http_code}" =~ ^2 ]]; then
      success=$((success + 1))
    fi
  done
  SMOKE_CURL_NAMES+=("vision-sequential-100")
  SMOKE_CURL_EXIT_CODES+=("0")
  SMOKE_CURL_HTTP_CODES+=("${success}/100")
  [[ "${success}" -eq 100 ]]
}

phase_vision_parallel_50() {
  local client tmp success=0 line
  client="$(client_config vision-par50 "xtls-rprx-vision")"
  smoke_start_stack "${SERVER_VISION}" "${client}"
  tmp="$(mktemp)"
  seq 1 50 | xargs -P 50 -I{} bash -c \
    "curl -sS -o /dev/null -w '%{http_code}\n' -x socks5h://127.0.0.1:${SMOKE_SOCKS_PORT} -m 60 '${SMOKE_QUICK_URL}' || echo fail" \
    >"${tmp}"
  while IFS= read -r line; do
    if [[ "${line}" =~ ^2 ]]; then
      success=$((success + 1))
    fi
  done <"${tmp}"
  rm -f "${tmp}"
  SMOKE_CURL_NAMES+=("vision-parallel-50")
  SMOKE_CURL_EXIT_CODES+=("0")
  SMOKE_CURL_HTTP_CODES+=("${success}/50")
  [[ "${success}" -eq 50 ]]
}

phase_download_100mb() {
  local client
  client="$(client_config vision-100mb "xtls-rprx-vision")"
  smoke_start_stack "${SERVER_VISION}" "${client}"
  smoke_record_curl "vision-download-100mb" -m 900 "${SMOKE_DOWNLOAD_100MB_URL}"
}

phase_wrong_uuid() {
  local client
  client="$(client_config wrong-uuid "xtls-rprx-vision" "22222222-2222-2222-2222-222222222222")"
  smoke_start_stack "${SERVER_VISION}" "${client}"
  smoke_expect_curl_fail "negative-wrong-uuid" -m 20 "${SMOKE_QUICK_URL}"
  smoke_log_contains "unknown vless client id" || smoke_log_contains "REALITY accepted path failed"
}

phase_flow_mismatch_empty_account_vision_client() {
  local client
  client="$(client_config mismatch-empty-account "xtls-rprx-vision")"
  smoke_start_stack "${SERVER_EMPTY}" "${client}"
  smoke_expect_curl_fail "flow-mismatch-empty-account-vision-client" -m 20 "${SMOKE_QUICK_URL}"
  smoke_log_contains "account flow does not match request flow xtls-rprx-vision"
}

phase_flow_mismatch_vision_account_empty_client() {
  local client
  client="$(client_config mismatch-vision-account "" )"
  smoke_start_stack "${SERVER_VISION}" "${client}"
  smoke_expect_curl_fail "flow-mismatch-vision-account-empty-client" -m 20 "${SMOKE_QUICK_URL}"
  smoke_log_contains "account requires xtls-rprx-vision but client request flow is empty"
}

phase_network_raw_alias() {
  local client
  client="$(client_config network-raw "xtls-rprx-vision")"
  smoke_start_stack "${SERVER_RAW}" "${client}"
  smoke_record_curl "network-alias-raw" -m 30 "${SMOKE_QUICK_URL}"
}

phase_network_tcp_regression() {
  local client
  client="$(client_config network-tcp "xtls-rprx-vision")"
  smoke_start_stack "${SERVER_VISION}" "${client}"
  smoke_record_curl "network-alias-tcp-regression" -m 30 "${SMOKE_QUICK_URL}"
}

phase_http_modes() {
  local client
  client="$(client_config http-modes "xtls-rprx-vision")"
  smoke_start_stack "${SERVER_VISION}" "${client}"
  smoke_record_curl "http-mode-http1.1" --http1.1 -m 30 "${SMOKE_QUICK_URL}" &&
    smoke_record_curl "http-mode-http2" --http2 -m 30 "${SMOKE_QUICK_URL}"
}

phase_tls_modes() {
  local client
  client="$(client_config tls-modes "xtls-rprx-vision")"
  smoke_start_stack "${SERVER_VISION}" "${client}"
  smoke_record_curl "tls-mode-default-1.3" -m 30 "${SMOKE_QUICK_URL}" &&
    smoke_record_curl "tls-mode-max-1.2" --tls-max 1.2 --tlsv1.2 -m 30 "${SMOKE_QUICK_URL}"
}

start_fallback_tcp_servers() {
  smoke_stop_process "${SMOKE_FALLBACK_TCP_PID:-}"
  mkdir -p "${SMOKE_FALLBACK_HIT_DIR}"
  rm -f "${SMOKE_FALLBACK_HIT_DIR}/"*
  SMOKE_FALLBACK_HIT_DIR="${SMOKE_FALLBACK_HIT_DIR}" \
    python3 "${SCRIPT_DIR}/fallback-tcp-servers.py" >>"${SMOKE_WORK_DIR}/fallback-tcp.log" 2>&1 &
  SMOKE_FALLBACK_TCP_PID=$!
  smoke_wait_port 127.0.0.1 19501 "fallback default tcp server"
}

fallback_trigger_tls() {
  local server_name="$1"
  timeout 5 openssl s_client \
    -connect "127.0.0.1:${SMOKE_SERVER_PORT}" \
    -servername "${server_name}" \
    </dev/null >/dev/null 2>&1 || true
}

fallback_expect_hit() {
  local name="$1"
  local port="$2"
  local extra="${3:-}"
  local hit_file="${SMOKE_FALLBACK_HIT_DIR}/${port}${extra}"
  SMOKE_CURL_NAMES+=("${name}")
  if [[ -f "${hit_file}" ]] && smoke_log_contains "dest_addr=127.0.0.1:${port}"; then
    SMOKE_CURL_EXIT_CODES+=("0")
    SMOKE_CURL_HTTP_CODES+=("hit")
    SMOKE_CURL_PASSED=$((SMOKE_CURL_PASSED + 1))
    return 0
  fi
  SMOKE_CURL_EXIT_CODES+=("1")
  SMOKE_CURL_HTTP_CODES+=("missing-hit-${port}${extra}")
  SMOKE_CURL_FAILED=$((SMOKE_CURL_FAILED + 1))
  echo "error: ${name} missing hit file or server log for port ${port}" >&2
  return 1
}

fallback_tls_probe() {
  local server_name="$1"
  python3 "${SCRIPT_DIR}/fallback-probe.py" "${server_name}" "${SMOKE_SERVER_PORT}" 2>/dev/null || true
}

record_fallback_probe() {
  local name="$1"
  local expected="$2"
  local actual="$3"
  SMOKE_CURL_NAMES+=("${name}")
  if [[ "${actual}" == "${expected}" ]]; then
    SMOKE_CURL_EXIT_CODES+=("0")
    SMOKE_CURL_HTTP_CODES+=("match")
    SMOKE_CURL_PASSED=$((SMOKE_CURL_PASSED + 1))
    return 0
  fi
  SMOKE_CURL_EXIT_CODES+=("1")
  SMOKE_CURL_HTTP_CODES+=("expected=${expected},actual=${actual}")
  SMOKE_CURL_FAILED=$((SMOKE_CURL_FAILED + 1))
  echo "error: ${name} expected '${expected}', got '${actual}'" >&2
  return 1
}

phase_fallback_default() {
  smoke_stop_stack
  rm -f "${SMOKE_FALLBACK_HIT_DIR}/"*
  smoke_start_server "${SERVER_FALLBACKS}"
  fallback_trigger_tls www.microsoft.com
  fallback_expect_hit "fallback-default" 19501
}

phase_fallback_by_name() {
  smoke_stop_stack
  rm -f "${SMOKE_FALLBACK_HIT_DIR}/"*
  smoke_start_server "${SERVER_FALLBACKS}"
  fallback_trigger_tls name-fallback.test
  fallback_expect_hit "fallback-by-name" 19502
}

phase_fallback_by_http_path() {
  smoke_stop_stack
  rm -f "${SMOKE_FALLBACK_HIT_DIR}/"*
  smoke_start_server "${SERVER_FALLBACKS}"
  local response
  response="$(
    printf 'GET /smoke-path HTTP/1.1\r\nHost: smoke.local\r\n\r\n' |
      timeout 5 nc "127.0.0.1" "${SMOKE_SERVER_PORT}"
  )"
  response="${response//$'\r'/}"
  response="${response%%$'\n'*}"
  record_fallback_probe "fallback-by-http-path" "FB-PATH" "${response}" &&
    fallback_expect_hit "fallback-by-http-path-hit" 19503
}

phase_fallback_xver_proxy_v1() {
  smoke_stop_stack
  rm -f "${SMOKE_FALLBACK_HIT_DIR}/"*
  smoke_start_server "${SERVER_FALLBACKS}"
  fallback_trigger_tls proxy-fallback.test
  fallback_expect_hit "fallback-xver-proxy-v1" 19504 ".proxy" &&
    smoke_log_contains "PROXY protocol v1 header forwarded"
}

run_fallback_phases() {
  start_fallback_tcp_servers
  run_phase "fallback default" phase_fallback_default
  run_phase "fallback by SNI/name" phase_fallback_by_name
  run_phase "fallback by HTTP path" phase_fallback_by_http_path
  run_phase "fallback xver=1 PROXY v1" phase_fallback_xver_proxy_v1
  smoke_stop_process "${SMOKE_FALLBACK_TCP_PID:-}"
  SMOKE_FALLBACK_TCP_PID=""
}

start_cipher_tls_servers() {
  smoke_stop_process "${SMOKE_CIPHER_TLS_PID:-}"
  SMOKE_CIPHER_WORK_DIR="${SMOKE_WORK_DIR}/cipher-tls" \
    python3 "${SCRIPT_DIR}/cipher-tls-servers.py" >>"${SMOKE_WORK_DIR}/cipher-tls.log" 2>&1 &
  SMOKE_CIPHER_TLS_PID=$!
  smoke_wait_port 127.0.0.1 19601 "cipher TLS AES128 dest"
  smoke_wait_port 127.0.0.1 19602 "cipher TLS AES256 dest"
  smoke_wait_port 127.0.0.1 19603 "cipher TLS ChaCha20 dest"
}

phase_cipher_suite() {
  local name="$1"
  local server_config="$2"
  local suite_id="$3"
  local client
  client="$(client_config "cipher-${name}" "")"
  smoke_start_stack "${server_config}" "${client}"
  smoke_record_curl "cipher-${name}" -m 30 "${SMOKE_QUICK_URL}" &&
    smoke_log_contains "cipher_suite_id=\"${suite_id}\""
}

run_cipher_phases() {
  start_cipher_tls_servers
  run_phase "cipher force AES128" phase_cipher_suite aes128 "${SERVER_CIPHER_AES128}" "0x1301"
  run_phase "cipher force AES256" phase_cipher_suite aes256 "${SERVER_CIPHER_AES256}" "0x1302"
  run_phase "cipher force CHACHA20" phase_cipher_suite chacha "${SERVER_CIPHER_CHACHA}" "0x1303"
  smoke_stop_process "${SMOKE_CIPHER_TLS_PID:-}"
  SMOKE_CIPHER_TLS_PID=""
}

main() {
  if [[ "${SMOKE_SKIP_LIVE}" == "1" ]]; then
    echo "Skipping live smoke (SMOKE_SKIP_LIVE=1)"
    exit 0
  fi

  smoke_require_commands cargo xray curl python3 timeout
  if ! command -v openssl >/dev/null 2>&1; then
    echo "warning: openssl not found; openssl fallback phase will be skipped" >&2
  fi

  prepare_workspace
  build_rust_xray

  echo "Live smoke workspace: ${SMOKE_WORK_DIR}"

  run_phase "regression flow=\"\"" phase_regression_empty_flow
  run_phase "regression flow=xtls-rprx-vision" phase_regression_vision_flow
  run_phase "regression 10MB download" phase_regression_10mb_download
  run_phase "regression bad shortId fallback" phase_regression_bad_short_id_fallback
  run_phase "regression bad SNI fallback" phase_regression_bad_sni_fallback
  if command -v openssl >/dev/null 2>&1; then
    run_phase "regression openssl fallback" phase_regression_openssl_fallback
  else
    SMOKE_PHASE_NAMES+=("SKIP regression openssl fallback")
  fi

  run_phase "vision 100 sequential requests" phase_vision_sequential_100
  run_phase "vision 50 parallel requests" phase_vision_parallel_50
  run_phase "vision 100MB download" phase_download_100mb
  run_phase "negative wrong UUID" phase_wrong_uuid
  run_phase "flow mismatch empty account + vision client" phase_flow_mismatch_empty_account_vision_client
  run_phase "flow mismatch vision account + empty client" phase_flow_mismatch_vision_account_empty_client
  run_phase "network alias raw" phase_network_raw_alias
  run_phase "network alias tcp regression" phase_network_tcp_regression
  run_phase "HTTP mode http1.1/http2" phase_http_modes
  run_phase "TLS mode 1.3/1.2" phase_tls_modes

  run_fallback_phases

  run_cipher_phases

  echo
  smoke_write_report "${SMOKE_REPORT_PATH}"

  if [[ "${SMOKE_FAILED}" -ne 0 || "${SMOKE_CURL_FAILED}" -ne 0 ]]; then
    echo "live smoke failed; see ${SMOKE_REPORT_PATH}" >&2
    exit 1
  fi

  echo "live smoke passed; report written to ${SMOKE_REPORT_PATH}"
}

main "$@"
