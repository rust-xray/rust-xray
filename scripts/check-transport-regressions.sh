#!/usr/bin/env bash
set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"

GATE_WORK_DIR="${GATE_WORK_DIR:-/tmp/rust-xray-transport-regression-gate-$$}"
GATE_REPORT_PATH="${GATE_REPORT_PATH:-${GATE_WORK_DIR}/regression-gate-report.txt}"
GATE_SKIP_BUILD="${GATE_SKIP_BUILD:-0}"
GATE_SKIP_LIVE="${GATE_SKIP_LIVE:-0}"

REALITY_SMOKE_SCRIPT="${SCRIPT_DIR}/live_reality_smoke/run-live-smoke.sh"
XHTTP_SMOKE_SCRIPT="${SCRIPT_DIR}/live_xhttp_smoke/run-live-xhttp-smoke.sh"
REMNA_API_SMOKE_SCRIPT="${SCRIPT_DIR}/remna_compat/run-local-api-smoke.sh"

REALITY_REPORT="${GATE_WORK_DIR}/reality-smoke-report.txt"
XHTTP_REPORT="${GATE_WORK_DIR}/xhttp-smoke-report.txt"

RESULT_CARGO_FMT="SKIP"
RESULT_CARGO_TEST="SKIP"
RESULT_REALITY_RAW_TCP="SKIP"
RESULT_XHTTP_SMOKE="SKIP"
RESULT_MUX_UDP_DNS="SKIP"
RESULT_REMNAWAVE_API="SKIP"

GATE_HARD_FAILED=0

require_command() {
  if ! command -v "$1" >/dev/null 2>&1; then
    echo "error: required command not found in PATH: $1" >&2
    exit 1
  fi
}

set_result() {
  local var_name="$1"
  local value="$2"
  printf -v "${var_name}" '%s' "${value}"
}

hard_fail() {
  GATE_HARD_FAILED=1
  echo "regression gate hard fail: $*" >&2
}

report_contains() {
  local file="$1"
  local pattern="$2"
  [[ -f "${file}" ]] && grep -Fq "${pattern}" "${file}"
}

report_metric_at_least() {
  local file="$1"
  local key="$2"
  local min="$3"
  local line value

  line="$(grep -E "^${key}:" "${file}" 2>/dev/null || true)"
  if [[ -z "${line}" ]]; then
    return 1
  fi
  value="${line##*: }"
  [[ "${value}" =~ ^[0-9]+$ ]] && (( value >= min ))
}

run_cargo_fmt() {
  echo "== regression gate: cargo fmt --check"
  if (cd "${REPO_ROOT}" && cargo fmt --check); then
    set_result RESULT_CARGO_FMT PASS
  else
    set_result RESULT_CARGO_FMT FAIL
    hard_fail "cargo fmt --check"
  fi
}

run_cargo_test() {
  echo "== regression gate: cargo test"
  if (cd "${REPO_ROOT}" && cargo test); then
    set_result RESULT_CARGO_TEST PASS
  else
    set_result RESULT_CARGO_TEST FAIL
    hard_fail "cargo test"
  fi
}

build_rust_xray_once() {
  if [[ "${GATE_SKIP_BUILD}" == "1" ]]; then
    echo "Skipping cargo build (GATE_SKIP_BUILD=1)"
    return 0
  fi
  echo "== regression gate: cargo build --bin rust-xray --bin xray"
  (cd "${REPO_ROOT}" && cargo build --bin rust-xray --bin xray)
}

run_reality_smoke() {
  echo "== regression gate: live REALITY smoke"
  mkdir -p "${GATE_WORK_DIR}"
  if SMOKE_SKIP_BUILD=1 \
    SMOKE_WORK_DIR="${GATE_WORK_DIR}/reality-smoke" \
    SMOKE_REPORT_PATH="${REALITY_REPORT}" \
    bash "${REALITY_SMOKE_SCRIPT}"; then
    :
  else
    echo "warning: live REALITY smoke runner exited non-zero; parsing report for hard gates" >&2
  fi
}

evaluate_reality_raw_tcp() {
  local ok=1
  if ! report_contains "${REALITY_REPORT}" 'PASS regression flow=""'; then
    echo "missing: PASS regression flow=\"\"" >&2
    ok=0
  fi
  if ! report_contains "${REALITY_REPORT}" 'PASS regression flow=xtls-rprx-vision'; then
    echo "missing: PASS regression flow=xtls-rprx-vision" >&2
    ok=0
  fi
  if (( ok )); then
    set_result RESULT_REALITY_RAW_TCP PASS
  else
    set_result RESULT_REALITY_RAW_TCP FAIL
    hard_fail "raw/tcp REALITY or Vision raw/tcp regression"
  fi
}

evaluate_mux_udp_dns() {
  local ok=1
  if ! report_contains "${REALITY_REPORT}" 'PASS happ reality vision mux udp dns baseline'; then
    echo "missing: PASS happ reality vision mux udp dns baseline" >&2
    ok=0
  fi
  if ! report_metric_at_least "${REALITY_REPORT}" mux_udp_dns_query_forwarded 1; then
    echo "missing or low: mux_udp_dns_query_forwarded" >&2
    ok=0
  fi
  if ! report_metric_at_least "${REALITY_REPORT}" mux_udp_dns_completed 1; then
    echo "missing or low: mux_udp_dns_completed" >&2
    ok=0
  fi
  if (( ok )); then
    set_result RESULT_MUX_UDP_DNS PASS
  else
    set_result RESULT_MUX_UDP_DNS FAIL
    hard_fail "mux UDP DNS regression"
  fi
}

run_xhttp_smoke() {
  echo "== regression gate: live XHTTP smoke"
  if XHTTP_SKIP_BUILD=1 \
    XHTTP_WORK_DIR="${GATE_WORK_DIR}/xhttp-smoke" \
    XHTTP_REPORT_PATH="${XHTTP_REPORT}" \
    bash "${XHTTP_SMOKE_SCRIPT}"; then
    :
  else
    echo "warning: live XHTTP smoke runner exited non-zero; parsing report for hard gates" >&2
  fi
}

evaluate_xhttp_smoke() {
  local ok=1
  local mode

  if [[ ! -f "${XHTTP_REPORT}" ]]; then
    set_result RESULT_XHTTP_SMOKE FAIL
    hard_fail "XHTTP smoke report missing"
    return
  fi

  for mode in default auto stream_one; do
    if ! grep -Eq "^mode_${mode}: PASS" "${XHTTP_REPORT}"; then
      echo "missing or failing: mode_${mode}: PASS" >&2
      ok=0
    fi
  done

  for mode in packet_up stream_up packet_down; do
    if grep -Eq "^mode_${mode}: timeout" "${XHTTP_REPORT}"; then
      echo "xhttp mode_${mode} hung (timeout)" >&2
      ok=0
    fi
  done

  if (( ok )); then
    set_result RESULT_XHTTP_SMOKE PASS
  else
    set_result RESULT_XHTTP_SMOKE FAIL
    hard_fail "XHTTP stream-one/default/auto regression"
  fi
}

run_remnawave_api_smoke() {
  if [[ ! -x "${REMNA_API_SMOKE_SCRIPT}" && ! -f "${REMNA_API_SMOKE_SCRIPT}" ]]; then
    set_result RESULT_REMNAWAVE_API SKIP
    echo "remnawave API smoke script unavailable; skipping"
    return 0
  fi

  if ! command -v grpcurl >/dev/null 2>&1; then
    set_result RESULT_REMNAWAVE_API SKIP
    echo "grpcurl unavailable; skipping remnawave API StatsService smoke"
    return 0
  fi

  echo "== regression gate: remnawave API StatsService smoke"
  if bash "${REMNA_API_SMOKE_SCRIPT}"; then
    set_result RESULT_REMNAWAVE_API PASS
  else
    set_result RESULT_REMNAWAVE_API FAIL
    hard_fail "remnawave API StatsService smoke"
  fi
}

write_report() {
  mkdir -p "${GATE_WORK_DIR}"
  {
    echo "rust-xray transport regression gate"
    echo "generated_at: $(date -u +%Y-%m-%dT%H:%M:%SZ)"
    echo "work_dir: ${GATE_WORK_DIR}"
    echo
    echo "[regression gate]"
    echo "cargo_fmt: ${RESULT_CARGO_FMT}"
    echo "cargo_test: ${RESULT_CARGO_TEST}"
    echo "reality_raw_tcp_smoke: ${RESULT_REALITY_RAW_TCP}"
    echo "xhttp_smoke: ${RESULT_XHTTP_SMOKE}"
    echo "mux_udp_dns_regression: ${RESULT_MUX_UDP_DNS}"
    echo "remnawave_api_regression: ${RESULT_REMNAWAVE_API}"
    echo
    echo "[hard fail policy]"
    echo "- raw/tcp REALITY (flow=\"\") must PASS"
    echo "- Vision raw/tcp (flow=xtls-rprx-vision) must PASS"
    echo "- mux UDP DNS baseline must PASS"
    echo "- remnawave StatsService smoke must PASS when grpcurl is available"
    echo "- XHTTP default/auto/stream-one must PASS"
    echo
    echo "[soft/expected xhttp modes]"
    if [[ -f "${XHTTP_REPORT}" ]]; then
      grep -E '^mode_(packet_up|stream_up|packet_down): (PASS|UNSUPPORTED|FAIL)$' \
        "${XHTTP_REPORT}" || echo "(no xhttp unsupported-mode summary lines)"
    else
      echo "(xhttp report unavailable)"
    fi
    echo
    echo "reality_smoke_report: ${REALITY_REPORT}"
    echo "xhttp_smoke_report: ${XHTTP_REPORT}"
    echo "gate_hard_failed: ${GATE_HARD_FAILED}"
  } >"${GATE_REPORT_PATH}"
  cat "${GATE_REPORT_PATH}"
}

main() {
  require_command cargo
  mkdir -p "${GATE_WORK_DIR}"

  run_cargo_fmt
  build_rust_xray_once
  run_cargo_test

  if [[ "${GATE_SKIP_LIVE}" == "1" ]]; then
    echo "Skipping live smokes (GATE_SKIP_LIVE=1)"
    set_result RESULT_REALITY_RAW_TCP SKIP
    set_result RESULT_XHTTP_SMOKE SKIP
    set_result RESULT_MUX_UDP_DNS SKIP
    set_result RESULT_REMNAWAVE_API SKIP
  else
    require_command xray
    require_command curl
    require_command python3

    run_reality_smoke
    evaluate_reality_raw_tcp
    evaluate_mux_udp_dns

    run_xhttp_smoke
    evaluate_xhttp_smoke

    run_remnawave_api_smoke
  fi

  write_report

  if [[ "${GATE_HARD_FAILED}" != "0" ]]; then
    echo "transport regression gate FAILED; report: ${GATE_REPORT_PATH}" >&2
    exit 1
  fi

  echo "transport regression gate PASSED; report: ${GATE_REPORT_PATH}"
}

main "$@"
