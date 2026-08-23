#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/../.." && pwd)"

# shellcheck source=scripts/live_reality_smoke/smoke-lib.sh
source "${SCRIPT_DIR}/smoke-lib.sh"

TEST_PUBLIC_KEY="${TEST_PUBLIC_KEY:-oU1MbEgszawWQJa0S_DxLsNt9G2zyE4rF-CrqvJjTmg}"
TEST_MLDSA65_VERIFY="${TEST_MLDSA65_VERIFY:-$(tr -d '\n' <"${SCRIPT_DIR}/mldsa65-verify.fixture.txt")}"
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
SMOKE_CIPHER_DETAILS=()
SMOKE_MLDSA65_PASSED=0
SMOKE_MLDSA65_FAILED=0
SMOKE_MLDSA65_DETAILS=()

SERVER_EMPTY="${SCRIPT_DIR}/rust-xray-server.fixture.json"
SERVER_VISION="${SCRIPT_DIR}/rust-xray-server.vision.fixture.json"
SERVER_RAW="${SCRIPT_DIR}/rust-xray-server.raw.fixture.json"
SERVER_MLDSA65_RAW="${SCRIPT_DIR}/rust-xray-server-mldsa65.raw.fixture.json"
SERVER_MLDSA65_INVALID_SEED="${SCRIPT_DIR}/rust-xray-server-mldsa65.invalid-seed.fixture.json"
SERVER_FALLBACKS="${SCRIPT_DIR}/rust-xray-server.fallbacks.fixture.json"
SERVER_CIPHER_AES128="${SCRIPT_DIR}/rust-xray-server.cipher-aes128.fixture.json"
SERVER_CIPHER_AES256="${SCRIPT_DIR}/rust-xray-server.cipher-aes256.fixture.json"
SERVER_CIPHER_CHACHA="${SCRIPT_DIR}/rust-xray-server.cipher-chacha.fixture.json"
SERVER_CUSTOM_ID="${SCRIPT_DIR}/rust-xray-server.custom-id.fixture.json"
SERVER_XHTTP="${SCRIPT_DIR}/rust-xray-server.xhttp.fixture.json"
SERVER_GRPC="${SCRIPT_DIR}/rust-xray-server.grpc.fixture.json"
SERVER_WS="${SCRIPT_DIR}/rust-xray-server.ws.fixture.json"
CLIENT_TEMPLATE="${SCRIPT_DIR}/xray-client-smoke.fixture.json"
CLIENT_NEGATIVE_TEMPLATE="${SCRIPT_DIR}/xray-client-negative.template.json"
SMOKE_FALLBACK_TCP_PID=""
SMOKE_CIPHER_TLS_PID=""
SMOKE_CIPHER_TLS_LOG="${SMOKE_WORK_DIR}/cipher-tls.log"

pass_phase() {
  SMOKE_PHASE_NAMES+=("PASS ${1}")
  echo "== PASS: ${1}"
}

fail_phase() {
  SMOKE_PHASE_NAMES+=("FAIL ${1}")
  SMOKE_FAILED=1
  echo "== FAIL: ${1}" >&2
}

skip_phase() {
  SMOKE_PHASE_NAMES+=("SKIP ${1}")
  echo "== SKIP: ${1}"
}

mldsa65_pass() {
  SMOKE_MLDSA65_PASSED=$((SMOKE_MLDSA65_PASSED + 1))
  SMOKE_MLDSA65_DETAILS+=("PASS ${1}")
}

mldsa65_fail() {
  SMOKE_MLDSA65_FAILED=$((SMOKE_MLDSA65_FAILED + 1))
  SMOKE_MLDSA65_DETAILS+=("FAIL ${1}")
}

mldsa65_note() {
  SMOKE_MLDSA65_DETAILS+=("NOTE ${1}")
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
  local mldsa65_verify="${6:-}"
  local output="${SMOKE_WORK_DIR}/client-${suffix}.json"
  smoke_write_client_config \
    "${CLIENT_TEMPLATE}" \
    "${output}" \
    "${flow}" \
    "${user_id}" \
    "${short_id}" \
    "${server_name}" \
    "${mldsa65_verify}"
  printf '%s\n' "${output}"
}

happ_mux_vision_client_config() {
  local output="${SMOKE_WORK_DIR}/client-happ-mux-vision.json"
  smoke_write_client_config \
    "${CLIENT_TEMPLATE}" \
    "${output}" \
    "xtls-rprx-vision" \
    "11111111-1111-1111-1111-111111111111" \
    "0123456789abcdef" \
    "www.microsoft.com" \
    "" \
    "1"
  printf '%s\n' "${output}"
}

negative_client_config() {
  local suffix="$1"
  local flow="${2:-}"
  local mux_enabled="${3:-0}"
  local packet_encoding="${4:-}"
  local output="${SMOKE_WORK_DIR}/client-negative-${suffix}.json"
  smoke_write_negative_client_config \
    "${CLIENT_NEGATIVE_TEMPLATE}" \
    "${output}" \
    "${flow}" \
    "${mux_enabled}" \
    "${packet_encoding}"
  printf '%s\n' "${output}"
}

run_unsupported_vless_phase() {
  local name="$1"
  local server_config="$2"
  local client_config_path="$3"
  local probe_mode="$4"
  local regression_client="${5}"
  shift 5
  local patterns=("$@")
  local decrypt_before

  smoke_stop_stack
  decrypt_before="$(smoke_decrypt_failure_count)"
  smoke_start_stack "${server_config}" "${client_config_path}"
  if [[ "${probe_mode}" == "curl-tcp" ]]; then
    curl -sS -o /dev/null -m 10 \
      -x "socks5h://127.0.0.1:${SMOKE_SOCKS_PORT}" \
      "${SMOKE_QUICK_URL}" >>"${SMOKE_WORK_DIR}/unsupported-${name}.log" 2>&1 || true
  elif [[ "${probe_mode}" == "mux-cool" ]]; then
    # Xray opens the mux carrier only after at least one proxied TCP request.
    curl -sS -o /dev/null -m 10 \
      -x "socks5h://127.0.0.1:${SMOKE_SOCKS_PORT}" \
      "${SMOKE_QUICK_URL}" >>"${SMOKE_WORK_DIR}/unsupported-${name}.log" 2>&1 || true
    python3 "${SCRIPT_DIR}/vless-negative-probe.py" "${probe_mode}" "${SMOKE_SOCKS_PORT}" \
      >>"${SMOKE_WORK_DIR}/unsupported-${name}.log" 2>&1 || true
  elif [[ "${probe_mode}" == "mux-udp" ]]; then
    curl -sS -o /dev/null -m 10 \
      -x "socks5h://127.0.0.1:${SMOKE_SOCKS_PORT}" \
      "${SMOKE_QUICK_URL}" >>"${SMOKE_WORK_DIR}/unsupported-${name}.log" 2>&1 || true
    python3 "${SCRIPT_DIR}/vless-negative-probe.py" mux-udp "${SMOKE_SOCKS_PORT}" "1.1.1.1" 54 \
      >>"${SMOKE_WORK_DIR}/unsupported-${name}.log" 2>&1 || true
  else
    python3 "${SCRIPT_DIR}/vless-negative-probe.py" "${probe_mode}" "${SMOKE_SOCKS_PORT}" \
      >>"${SMOKE_WORK_DIR}/unsupported-${name}.log" 2>&1 || true
  fi
  sleep 0.5
  SMOKE_CLIENT_CONFIG_FOR_REGRESSION="${regression_client}"
  smoke_expect_unsupported_vless_probe "${name}" "${decrypt_before}" "${patterns[@]}"
  unset SMOKE_CLIENT_CONFIG_FOR_REGRESSION
  unset SMOKE_REGRESSION_SERVER_CONFIG
}

phase_unsupported_udp_dns() {
  local client
  client="$(negative_client_config udp-dns "" 0 "")"
  run_unsupported_vless_phase \
    "udp-dns-unsupported" \
    "${SERVER_EMPTY}" \
    "${client}" \
    "udp-dns" \
    "${client}" \
    "UDP unsupported" \
    "unsupported vless command"
}

phase_unsupported_udp_quic() {
  local client
  client="$(negative_client_config udp-quic "" 0 "")"
  run_unsupported_vless_phase \
    "udp-quic-unsupported" \
    "${SERVER_EMPTY}" \
    "${client}" \
    "udp-quic" \
    "${client}" \
    "UDP unsupported" \
    "unsupported vless command"
}

phase_unsupported_udp_vision() {
  local client regression_client
  client="$(negative_client_config udp-vision "xtls-rprx-vision" 0 "")"
  regression_client="$(client_config udp-vision-regression "xtls-rprx-vision")"
  SMOKE_REGRESSION_SERVER_CONFIG="${SERVER_VISION}"
  run_unsupported_vless_phase \
    "udp-vision-unsupported" \
    "${SERVER_VISION}" \
    "${client}" \
    "udp-dns" \
    "${regression_client}" \
    "doesn't support UDP" \
    "UDP unsupported"
}

phase_unsupported_mux_non_dns_udp() {
  local client regression_client
  client="$(negative_client_config mux-non-dns "xtls-rprx-vision" 1 "")"
  regression_client="$(client_config mux-non-dns-regression "xtls-rprx-vision")"
  SMOKE_REGRESSION_SERVER_CONFIG="${SERVER_VISION}"
  run_unsupported_vless_phase \
    "mux-non-dns-udp-unsupported" \
    "${SERVER_VISION}" \
    "${client}" \
    "mux-udp" \
    "${regression_client}" \
    "mux session started"
}

phase_happ_reality_vision_mux_udp_dns() {
  local client saved_rust_log
  client="$(happ_mux_vision_client_config)"
  smoke_stop_stack
  saved_rust_log="${SMOKE_RUST_LOG}"
  SMOKE_RUST_LOG="rust_xray=debug,tower=warn,hyper=warn,h2=warn,rustls=warn"
  smoke_start_stack "${SERVER_VISION}" "${client}"
  curl -sS -o /dev/null -m 10 \
    -x "socks5h://127.0.0.1:${SMOKE_SOCKS_PORT}" \
    "${SMOKE_QUICK_URL}" >>"${SMOKE_WORK_DIR}/happ-mux-udp-dns.log" 2>&1 || true
  if ! python3 "${SCRIPT_DIR}/mux-udp-dns-probe.py" "${SMOKE_SOCKS_PORT}" "1.1.1.1" 53 \
    >>"${SMOKE_WORK_DIR}/happ-mux-udp-dns.log" 2>&1; then
    SMOKE_RUST_LOG="${saved_rust_log}"
    fail_phase "happ reality vision mux udp dns"
    fail_phase "vless mux udp dns 1.1.1.1:53"
    return 1
  fi
  sleep 0.5
  if ! smoke_expect_happ_mux_udp_dns_baseline; then
    SMOKE_RUST_LOG="${saved_rust_log}"
    fail_phase "happ reality vision mux udp dns"
    fail_phase "vless mux udp dns 1.1.1.1:53"
    return 1
  fi
  SMOKE_RUST_LOG="${saved_rust_log}"
  pass_phase "happ reality vision mux udp dns"
  pass_phase "vless mux udp dns 1.1.1.1:53"
}

phase_unsupported_mux() {
  phase_unsupported_mux_non_dns_udp
}

phase_unsupported_xudp() {
  local client
  client="$(negative_client_config xudp "" 0 "xudp")"
  run_unsupported_vless_phase \
    "xudp-unsupported" \
    "${SERVER_EMPTY}" \
    "${client}" \
    "udp-dns" \
    "${client}" \
    "XUDP unsupported" \
    "UDP unsupported" \
    "unsupported vless command"
}

run_unsupported_vless_phases() {
  run_phase "UDP DNS unsupported via SOCKS + TCP regression" phase_unsupported_udp_dns
  run_phase "UDP 443 / QUIC unsupported + TCP regression" phase_unsupported_udp_quic
  run_phase "UDP + Vision unsupported + TCP regression" phase_unsupported_udp_vision
  run_phase "Mux non-DNS UDP unsupported + TCP regression" phase_unsupported_mux
  run_phase "XUDP unsupported + TCP regression" phase_unsupported_xudp
}

phase_regression_empty_flow() {
  local client
  client="$(client_config empty "" )"
  smoke_start_stack "${SERVER_EMPTY}" "${client}"
  smoke_record_curl "regression-flow-empty" -m 30 "${SMOKE_QUICK_URL}"
}

phase_regression_custom_string_id() {
  local client
  client="$(client_config custom-id "" "670892c1-5d1c-5856-b808-9f882e6f364e")"
  smoke_start_stack "${SERVER_CUSTOM_ID}" "${client}"
  smoke_record_curl "regression-custom-string-id" -m 30 "${SMOKE_QUICK_URL}"
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
  smoke_log_contains "REALITY fallback" ||
    smoke_log_contains "fallback relay started" ||
    smoke_log_contains "fallback relay completed"
}

phase_regression_bad_sni_fallback() {
  local client
  client="$(client_config bad-sni "" "11111111-1111-1111-1111-111111111111" "0123456789abcdef" "example.com")"
  smoke_start_stack "${SERVER_EMPTY}" "${client}"
  smoke_expect_curl_fail "regression-bad-sni-fallback" -m 20 "${SMOKE_QUICK_URL}"
  smoke_log_contains "REALITY fallback" ||
    smoke_log_contains "fallback relay started" ||
    smoke_log_contains "fallback relay completed"
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
  if [[ "${openssl_exit}" -eq 0 ]] &&
    { smoke_log_contains "fallback relay started" ||
      smoke_log_contains "fallback relay completed"; }; then
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
  smoke_expect_curl_fail "wrong-uuid-rejected" -m 20 "${SMOKE_QUICK_URL}"
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

phase_mldsa65_seed_raw_vision() {
  local client http_code curl_exit log_before
  local removed_feature_marker="reality-mldsa65"
  local removed_feature_error="requires "
  removed_feature_marker+="-crypto"
  removed_feature_error+="feature"
  client="$(client_config mldsa65-raw-vision "xtls-rprx-vision" "11111111-1111-1111-1111-111111111111" "0123456789abcdef" "www.microsoft.com" "${TEST_MLDSA65_VERIFY}")"

  smoke_stop_stack

  if ! smoke_start_stack "${SERVER_MLDSA65_RAW}" "${client}"; then
    mldsa65_fail "valid mldsa65Seed server/client startup"
    return 1
  fi
  mldsa65_pass "valid mldsa65Seed accepted by normal build"

  if smoke_log_contains "${removed_feature_marker}" || smoke_log_contains "${removed_feature_error}"; then
    mldsa65_fail "valid mldsa65Seed did not require removed cargo feature"
    return 1
  fi
  mldsa65_pass "valid mldsa65Seed does not require removed cargo feature"

  log_before="$(smoke_log_line_count "${SMOKE_SERVER_LOG}")"
  set +e
  http_code="$(smoke_curl_socks -m 30 "${SMOKE_QUICK_URL}")"
  curl_exit=$?
  set -e

  if [[ "${curl_exit}" -eq 0 && "${http_code}" =~ ^2 ]]; then
    mldsa65_pass "full mldsa65 raw vision curl succeeded"
    return 0
  fi

  if smoke_log_contains_since "${SMOKE_SERVER_LOG}" "${log_before}" "REALITY certificate DER too short for ML-DSA-65 extension patch"; then
    mldsa65_fail "full mldsa65 live curl still blocked by missing certificate placeholder"
    return 0
  fi

  mldsa65_fail "mldsa65 raw vision curl failed without expected ML-DSA-65 patch error: exit=${curl_exit} http=${http_code}"
  return 1
}

phase_mldsa65_invalid_seed_rejected() {
  if smoke_expect_server_reject \
    "mldsa65-invalid-seed" \
    "${SERVER_MLDSA65_INVALID_SEED}" \
    "invalid mldsa65Seed length"; then
    smoke_wait_port_closed 127.0.0.1 "${SMOKE_SERVER_PORT}" "mldsa65 invalid seed server" 20 || {
      mldsa65_fail "invalid mldsa65Seed left server port open"
      return 1
    }
    mldsa65_pass "invalid mldsa65Seed rejected during startup"
    return 0
  fi

  mldsa65_fail "invalid mldsa65Seed was not rejected during startup"
  return 1
}

phase_network_tcp_regression() {
  local client
  client="$(client_config network-tcp "xtls-rprx-vision")"
  smoke_start_stack "${SERVER_VISION}" "${client}"
  smoke_record_curl "network-alias-tcp-regression" -m 30 "${SMOKE_QUICK_URL}"
}

phase_transport_xhttp_starts() {
  smoke_stop_stack
  smoke_start_server "${SERVER_XHTTP}" || return 1
  if ! smoke_log_contains 'transport="xhttp"'; then
    echo "error: XHTTP startup log missing transport=xhttp" >&2
    tail -50 "${SMOKE_SERVER_LOG}" >&2 || true
    return 1
  fi
  smoke_stop_stack
}

phase_transport_grpc_unsupported() {
  smoke_expect_server_reject \
    "transport-grpc" \
    "${SERVER_GRPC}" \
    "REALITY over gRPC runtime is not implemented yet"
}

phase_transport_websocket_rejected() {
  smoke_expect_server_reject \
    "transport-websocket" \
    "${SERVER_WS}" \
    "REALITY over WebSocket transport (network=ws) is not supported"
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
  smoke_free_ports 19501 19502 19503 19504 19505 19506 19507
  mkdir -p "${SMOKE_FALLBACK_HIT_DIR}"
  rm -f "${SMOKE_FALLBACK_HIT_DIR}/"*
  SMOKE_FALLBACK_HIT_DIR="${SMOKE_FALLBACK_HIT_DIR}" \
    python3 "${SCRIPT_DIR}/fallback-tcp-servers.py" >>"${SMOKE_WORK_DIR}/fallback-tcp.log" 2>&1 &
  SMOKE_FALLBACK_TCP_PID=$!
  smoke_wait_port 127.0.0.1 19501 "fallback default tcp server" &&
    smoke_wait_port 127.0.0.1 19502 "fallback name tcp server" &&
    smoke_wait_port 127.0.0.1 19503 "fallback path tcp server" &&
    smoke_wait_port 127.0.0.1 19504 "fallback proxy v1 tcp server" &&
    smoke_wait_port 127.0.0.1 19505 "fallback alpn http/1.1 tcp server" &&
    smoke_wait_port 127.0.0.1 19506 "fallback alpn h2 tcp server" &&
    smoke_wait_port 127.0.0.1 19507 "fallback proxy v2 tcp server"
}

fallback_prepare_phase() {
  smoke_stop_stack
  rm -f "${SMOKE_FALLBACK_HIT_DIR}/"*
  : >"${SMOKE_SERVER_LOG}"
  smoke_start_server "${SERVER_FALLBACKS}"
  smoke_log_contains "vless_fallback_count=7" ||
    smoke_log_contains "VLESS fallback entry" ||
    {
      echo "error: fallback server started without expected fallback config" >&2
      tail -30 "${SMOKE_SERVER_LOG}" >&2 || true
      return 1
    }
  sleep 0.25
}

fallback_trigger_tls() {
  local server_name="$1"
  fallback_tls_probe "${server_name}" >/dev/null || true
}

fallback_trigger_tls_alpn() {
  local server_name="$1"
  local alpn="$2"
  fallback_tls_probe "${server_name}" "${alpn}" >/dev/null || true
}

fallback_expect_hit() {
  local name="$1"
  local port="$2"
  local extra="${3:-}"
  local hit_file="${SMOKE_FALLBACK_HIT_DIR}/${port}${extra}"
  SMOKE_CURL_NAMES+=("${name}")
  if [[ -f "${hit_file}" ]] &&
    smoke_log_contains "dest_addr=127.0.0.1:${port}" &&
    { smoke_log_contains "fallback relay completed" ||
      smoke_log_contains "initial bytes forwarded"; }; then
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
  local alpn="${2:-}"
  if [[ -n "${alpn}" ]]; then
    python3 "${SCRIPT_DIR}/fallback-probe.py" "${server_name}" "${SMOKE_SERVER_PORT}" "${alpn}" \
      2>/dev/null || true
  else
    python3 "${SCRIPT_DIR}/fallback-probe.py" "${server_name}" "${SMOKE_SERVER_PORT}" \
      2>/dev/null || true
  fi
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
  fallback_prepare_phase
  fallback_trigger_tls www.microsoft.com
  fallback_expect_hit "fallback-default" 19501
}

phase_fallback_by_name() {
  fallback_prepare_phase
  fallback_trigger_tls name-fallback.test
  fallback_expect_hit "fallback-by-name" 19502
}

phase_fallback_by_http_path() {
  fallback_prepare_phase
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
  fallback_prepare_phase
  fallback_trigger_tls proxy-fallback.test
  fallback_expect_hit "fallback-xver-proxy-v1" 19504 ".proxy" &&
    smoke_log_contains "PROXY protocol header written" &&
    smoke_log_contains "xver=1"
}

phase_fallback_by_alpn_http11() {
  fallback_prepare_phase
  fallback_trigger_tls_alpn www.microsoft.com "http/1.1"
  fallback_expect_hit "fallback-by-alpn-http11" 19505
}

phase_fallback_by_alpn_h2() {
  if ! openssl s_client -help 2>&1 | grep -q -- '-alpn'; then
    SMOKE_PHASE_NAMES+=("SKIP fallback by ALPN h2")
    echo "Skipping fallback by ALPN h2 (openssl without -alpn support)"
    return 0
  fi

  fallback_prepare_phase
  fallback_trigger_tls_alpn www.microsoft.com "h2"
  fallback_expect_hit "fallback-by-alpn-h2" 19506
}

phase_fallback_by_alpn_h2_curl() {
  if ! curl --help all 2>&1 | grep -q -- '--http2'; then
    SMOKE_PHASE_NAMES+=("SKIP fallback by ALPN h2 curl")
    echo "Skipping fallback by ALPN h2 curl (curl without --http2 support)"
    return 0
  fi

  fallback_prepare_phase
  curl -sk --http2 --max-time 5 "https://127.0.0.1:${SMOKE_SERVER_PORT}/" >/dev/null 2>&1 || true
  fallback_expect_hit "fallback-by-alpn-h2-curl" 19506
}

phase_fallback_xver_proxy_v2() {
  fallback_prepare_phase
  fallback_trigger_tls proxy-v2-fallback.test
  fallback_expect_hit "fallback-xver-proxy-v2" 19507 ".proxyv2" &&
    smoke_log_contains "PROXY protocol header written" &&
    smoke_log_contains "xver=2"
}

run_fallback_phases() {
  smoke_stop_stack
  start_fallback_tcp_servers
  run_phase "fallback default" phase_fallback_default
  run_phase "fallback by SNI/name" phase_fallback_by_name
  run_phase "fallback by HTTP path" phase_fallback_by_http_path
  run_phase "fallback by ALPN http/1.1" phase_fallback_by_alpn_http11
  run_phase "fallback by ALPN h2" phase_fallback_by_alpn_h2
  run_phase "fallback by ALPN h2 curl" phase_fallback_by_alpn_h2_curl
  run_phase "fallback xver=1 PROXY v1" phase_fallback_xver_proxy_v1
  run_phase "fallback xver=2 PROXY v2" phase_fallback_xver_proxy_v2
  smoke_stop_process "${SMOKE_FALLBACK_TCP_PID:-}"
  SMOKE_FALLBACK_TCP_PID=""
}

start_cipher_tls_servers() {
  smoke_stop_process "${SMOKE_CIPHER_TLS_PID:-}"
  : >"${SMOKE_CIPHER_TLS_LOG}"
  SMOKE_CIPHER_WORK_DIR="${SMOKE_WORK_DIR}/cipher-tls" \
    python3 "${SCRIPT_DIR}/cipher-tls-servers.py" >>"${SMOKE_CIPHER_TLS_LOG}" 2>&1 &
  SMOKE_CIPHER_TLS_PID=$!
  smoke_wait_port 127.0.0.1 19601 "cipher TLS AES128 dest" &&
    smoke_wait_port 127.0.0.1 19602 "cipher TLS AES256 dest" &&
    smoke_wait_port 127.0.0.1 19603 "cipher TLS ChaCha20 dest"
}

cipher_prepare_phase() {
  local server_config="$1"
  local client_config="$2"
  smoke_stop_stack
  : >"${SMOKE_SERVER_LOG}"
  smoke_start_stack "${server_config}" "${client_config}"
  sleep 0.25
}

cipher_record_validation() {
  local name="$1"
  local curl_ok="$2"
  local http_code="$3"
  local server_cipher="$4"
  local dest_cipher="$5"
  local expected_cipher="$6"
  local phase_result="$7"
  local validation_reason="$8"
  SMOKE_CIPHER_DETAILS+=(
    "${name}: phase=${phase_result} curl_http=${http_code} expected=${expected_cipher} dest_tls=${dest_cipher} server=${server_cipher} reason=${validation_reason}"
  )
}

phase_cipher_suite() {
  local name="$1"
  local server_config="$2"
  local suite_id="$3"
  local suite_name="$4"
  local dest_port="$5"
  local client
  local tls_log_before server_cipher dest_cipher expected_cipher curl_ok=false
  local http_code="000"
  local validation_reason="unknown"

  if [[ ! -f "${server_config}" ]]; then
    echo "error: cipher fixture missing: ${server_config}" >&2
    cipher_record_validation "${name}" false "${http_code}" "missing" "missing" "${suite_name} (${suite_id})" "FAIL" "fixture_missing"
    return 1
  fi

  client="$(client_config "cipher-${name}" "")"
  tls_log_before="$(smoke_log_line_count "${SMOKE_CIPHER_TLS_LOG}")"
  cipher_prepare_phase "${server_config}" "${client}"

  expected_cipher="${suite_name} (${suite_id})"
  set +e
  http_code="$(smoke_curl_socks -m 30 "${SMOKE_QUICK_URL}")"
  local curl_exit=$?
  set -e
  SMOKE_CURL_NAMES+=("cipher-${name}")
  SMOKE_CURL_EXIT_CODES+=("${curl_exit}")
  SMOKE_CURL_HTTP_CODES+=("${http_code}")
  if [[ "${curl_exit}" -eq 0 && "${http_code}" =~ ^2 ]]; then
    curl_ok=true
    SMOKE_CURL_PASSED=$((SMOKE_CURL_PASSED + 1))
  else
    SMOKE_CURL_FAILED=$((SMOKE_CURL_FAILED + 1))
  fi

  server_cipher="$(smoke_extract_server_negotiated_cipher "${SMOKE_SERVER_LOG}")"
  dest_cipher="$(smoke_extract_dest_negotiated_cipher "${SMOKE_CIPHER_TLS_LOG}" "${tls_log_before}" "${dest_port}")"

  if [[ "${curl_ok}" != true ]]; then
    validation_reason="curl_not_http_2xx"
    cipher_record_validation "${name}" false "${http_code}" "${server_cipher}" "${dest_cipher}" "${expected_cipher}" "FAIL" "${validation_reason}"
    echo "error: cipher-${name} validation failed (curl_http=${http_code}, expected=${expected_cipher})" >&2
    return 1
  fi

  if [[ "${dest_cipher}" != "${expected_cipher}" ]]; then
    validation_reason="dest_tls_mismatch"
    cipher_record_validation "${name}" true "${http_code}" "${server_cipher}" "${dest_cipher}" "${expected_cipher}" "FAIL" "${validation_reason}"
    echo "error: cipher-${name} validation failed (curl_http=${http_code}, server=${server_cipher}, dest_tls=${dest_cipher}, expected=${expected_cipher})" >&2
    return 1
  fi

  if [[ "${server_cipher}" == "${expected_cipher}" ]]; then
    validation_reason="curl_http_200_and_dest_tls_match_and_server_marker_match"
  else
    validation_reason="curl_http_200_and_dest_tls_match"
  fi

  cipher_record_validation "${name}" true "${http_code}" "${server_cipher}" "${dest_cipher}" "${expected_cipher}" "PASS" "${validation_reason}"
  return 0
}

run_cipher_suite_phase() {
  local phase_name="$1"
  local name="$2"
  local server_config="$3"
  local suite_id="$4"
  local suite_name="$5"
  local dest_port="$6"

  if [[ "${SMOKE_CIPHER_DEST_UNAVAILABLE:-0}" == "1" ]]; then
    skip_phase "${phase_name} (cipher dest servers unavailable)"
    cipher_record_validation "${name}" false "000" "skipped" "skipped" "${suite_name} (${suite_id})" "SKIP" "cipher_dest_servers_unavailable"
    return 0
  fi

  if phase_cipher_suite "${name}" "${server_config}" "${suite_id}" "${suite_name}" "${dest_port}"; then
    pass_phase "${phase_name}"
  else
    fail_phase "${phase_name}"
  fi
}

run_cipher_phases() {
  SMOKE_CIPHER_DEST_UNAVAILABLE=0
  if ! start_cipher_tls_servers; then
    SMOKE_CIPHER_DEST_UNAVAILABLE=1
    echo "warning: cipher TLS dest servers unavailable; cipher phases will be skipped" >&2
  fi

  run_cipher_suite_phase "cipher force AES128" aes128 "${SERVER_CIPHER_AES128}" "0x1301" "TLS_AES_128_GCM_SHA256" 19601
  run_cipher_suite_phase "cipher force AES256" aes256 "${SERVER_CIPHER_AES256}" "0x1302" "TLS_AES_256_GCM_SHA384" 19602
  run_cipher_suite_phase "cipher force CHACHA20" chacha "${SERVER_CIPHER_CHACHA}" "0x1303" "TLS_CHACHA20_POLY1305_SHA256" 19603

  smoke_stop_process "${SMOKE_CIPHER_TLS_PID:-}"
  SMOKE_CIPHER_TLS_PID=""
}

smoke_assert_report_contains() {
  local needle="$1"
  if ! grep -Fq -- "${needle}" "${SMOKE_REPORT_PATH}"; then
    echo "error: live smoke report missing required guard: ${needle}" >&2
    return 1
  fi
}

smoke_assert_report_metric_at_least() {
  local key="$1"
  local min="$2"
  local line value

  line="$(grep -E "^${key}:" "${SMOKE_REPORT_PATH}" || true)"
  if [[ -z "${line}" ]]; then
    echo "error: live smoke report missing metric: ${key}" >&2
    return 1
  fi
  value="${line##*: }"
  if [[ "${value}" -lt "${min}" ]]; then
    echo "error: live smoke report metric ${key}=${value} expected >= ${min}" >&2
    return 1
  fi
}

smoke_validate_final_report() {
  smoke_assert_report_contains "curl_checks_failed: 0" &&
    smoke_assert_report_contains "aes_gcm_decrypt_failed: 0" &&
    smoke_assert_report_contains "mldsa65_checks_failed: 0" &&
    smoke_assert_report_contains "PASS full mldsa65 raw vision curl succeeded" &&
    smoke_assert_report_contains "PASS invalid mldsa65Seed rejected during startup" &&
    smoke_assert_report_contains "PASS fallback default" &&
    smoke_assert_report_contains "PASS fallback by SNI/name" &&
    smoke_assert_report_contains "PASS fallback by HTTP path" &&
    smoke_assert_report_contains "PASS fallback by ALPN http/1.1" &&
    smoke_assert_report_contains "PASS fallback by ALPN h2" &&
    smoke_assert_report_contains "PASS fallback xver=1 PROXY v1" &&
    smoke_assert_report_contains "PASS fallback xver=2 PROXY v2" &&
    smoke_assert_report_contains "PASS cipher force AES128" &&
    smoke_assert_report_contains "PASS cipher force AES256" &&
    smoke_assert_report_contains "PASS cipher force CHACHA20" &&
    smoke_assert_report_contains "PASS happ reality vision mux udp dns" &&
    smoke_assert_report_contains "PASS vless mux udp dns 1.1.1.1:53" &&
    smoke_assert_report_metric_at_least "mux_udp_dns_query_forwarded" 1 &&
    smoke_assert_report_metric_at_least "mux_udp_dns_completed" 1 &&
    smoke_assert_report_metric_at_least "forbidden_udp_mux_substream_not_implemented" 0 &&
    smoke_assert_report_contains "forbidden_udp_mux_substream_not_implemented: 0" &&
    smoke_assert_report_contains "forbidden_udp_mux_packet_not_implemented: 0"
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

  run_phase "regression flow=\"\" (default minClientVer)" phase_regression_empty_flow
  run_phase "regression custom string VLESS id" phase_regression_custom_string_id
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
  run_phase "wrong UUID rejected" phase_wrong_uuid
  run_phase "flow mismatch empty account + vision client" phase_flow_mismatch_empty_account_vision_client
  run_phase "flow mismatch vision account + empty client" phase_flow_mismatch_vision_account_empty_client
  run_phase "network alias raw" phase_network_raw_alias
  run_phase "mldsa65 reality raw vision" phase_mldsa65_seed_raw_vision
  run_phase "mldsa65 invalid seed rejected" phase_mldsa65_invalid_seed_rejected
  run_phase "network alias tcp regression" phase_network_tcp_regression
  run_phase "transport xhttp starts" phase_transport_xhttp_starts
  run_phase "transport grpc unsupported" phase_transport_grpc_unsupported
  run_phase "transport websocket+reality rejected" phase_transport_websocket_rejected
  run_phase "HTTP mode http1.1/http2" phase_http_modes
  run_phase "TLS mode 1.3/1.2" phase_tls_modes

  run_fallback_phases

  run_cipher_phases

  run_phase "happ reality vision mux udp dns baseline" phase_happ_reality_vision_mux_udp_dns

  run_unsupported_vless_phases

  echo
  smoke_write_report "${SMOKE_REPORT_PATH}"

  if ! smoke_validate_final_report; then
    echo "live smoke failed final report guards; see ${SMOKE_REPORT_PATH}" >&2
    exit 1
  fi

  if [[ "${SMOKE_FAILED}" -ne 0 || "${SMOKE_CURL_FAILED}" -ne 0 || "${SMOKE_MLDSA65_FAILED}" -ne 0 ]]; then
    echo "live smoke failed; see ${SMOKE_REPORT_PATH}" >&2
    exit 1
  fi

  echo "live smoke passed; report written to ${SMOKE_REPORT_PATH}"
}

main "$@"
