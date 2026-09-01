#!/usr/bin/env bash
# Canonical, serial live-smoke orchestrator. Compatible with macOS Bash 3.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/../.." && pwd)"

SMOKE_SKIP_BUILD="${SMOKE_SKIP_BUILD:-0}"
SMOKE_KEEP_TMP="${SMOKE_KEEP_TMP:-0}"
SMOKE_VERBOSE="${SMOKE_VERBOSE:-0}"
SMOKE_TIMEOUT="${SMOKE_TIMEOUT:-900}"
RUST_XRAY_BIN="${RUST_XRAY_BIN:-${REPO_ROOT}/target/release/rust-xray}"
XRAY_BIN="${XRAY_BIN:-xray}"
SMOKE_ROOT_DIR="${SMOKE_ROOT_DIR:-$(mktemp -d "${TMPDIR:-/tmp}/rust-xray-live-smoke.XXXXXX")}"
SUMMARY_JSON="${SMOKE_SUMMARY_JSON:-${SMOKE_ROOT_DIR}/summary.json}"
SMOKE_STARTED_AT="$(date -u +%Y-%m-%dT%H:%M:%SZ)"

SUITE_NAMES=()
SUITE_RESULTS=()
SUITE_REASONS=()
OWNED_CHILD_PID=""
SMOKE_ENVIRONMENT_READY=1

sha256() {
  if command -v shasum >/dev/null 2>&1; then
    shasum -a 256 "$1" | awk '{print $1}'
  elif command -v sha256sum >/dev/null 2>&1; then
    sha256sum "$1" | awk '{print $1}'
  else
    printf 'unavailable'
  fi
}

stop_owned_child() {
  local pid="${OWNED_CHILD_PID:-}"
  if [[ -n "${pid}" ]] && kill -0 "${pid}" >/dev/null 2>&1; then
    kill "${pid}" >/dev/null 2>&1 || true
    local waited=0
    while kill -0 "${pid}" >/dev/null 2>&1 && [[ "${waited}" -lt 50 ]]; do
      sleep 0.1
      waited=$((waited + 1))
    done
    if kill -0 "${pid}" >/dev/null 2>&1; then
      kill -9 "${pid}" >/dev/null 2>&1 || true
    fi
    wait "${pid}" 2>/dev/null || true
  fi
  OWNED_CHILD_PID=""
}

cleanup() {
  stop_owned_child
  if [[ "${SMOKE_KEEP_TMP}" == "1" || "${SMOKE_VERBOSE}" == "1" ]]; then
    echo "live-smoke artifacts preserved: ${SMOKE_ROOT_DIR}"
  else
    rm -rf "${SMOKE_ROOT_DIR}"
  fi
}
trap cleanup EXIT INT TERM

require_command() {
  if ! command -v "$1" >/dev/null 2>&1; then
    echo "SKIP ENVIRONMENT: required command missing: $1" >&2
    return 1
  fi
}

build_once() {
  if [[ "${SMOKE_SKIP_BUILD}" == "1" ]]; then
    echo "BUILD SKIPPED (SMOKE_SKIP_BUILD=1)"
  else
    (cd "${REPO_ROOT}" && cargo build --release --bin rust-xray --all-features)
  fi
  if [[ ! -x "${RUST_XRAY_BIN}" ]]; then
    echo "error: rust-xray binary missing or not executable: ${RUST_XRAY_BIN}" >&2
    exit 1
  fi
  RUST_XRAY_BIN="$(cd "$(dirname "${RUST_XRAY_BIN}")" && pwd)/$(basename "${RUST_XRAY_BIN}")"
  echo "git HEAD: $(git -C "${REPO_ROOT}" rev-parse HEAD)"
  echo "rust-xray binary: ${RUST_XRAY_BIN}"
  echo "rust-xray sha256: $(sha256 "${RUST_XRAY_BIN}")"
  if command -v "${XRAY_BIN}" >/dev/null 2>&1; then
    echo "xray client: $(command -v "${XRAY_BIN}")"
    "${XRAY_BIN}" version 2>/dev/null | head -1 || true
  else
    echo "xray client: unavailable (${XRAY_BIN})"
    SMOKE_ENVIRONMENT_READY=0
  fi
}

skip_suite_environment() {
  local name="$1"
  SUITE_NAMES+=("${name}")
  SUITE_RESULTS+=("SKIP_ENVIRONMENT")
  SUITE_REASONS+=("required Xray client unavailable: ${XRAY_BIN}")
  echo "=== SKIP ENVIRONMENT: ${name}; Xray client unavailable ==="
}

run_suite() {
  local name="$1"
  local command_path="$2"
  local work_dir="${SMOKE_ROOT_DIR}/${name}"
  local log_path="${work_dir}/suite.log"
  mkdir -p "${work_dir}"
  echo "=== suite: ${name} ==="
  SMOKE_SKIP_BUILD=1 \
  SMOKE_TIMEOUT="${SMOKE_TIMEOUT}" \
  SMOKE_WORK_DIR="${work_dir}" \
  SMOKE_RUST_XRAY_BIN="${RUST_XRAY_BIN}" \
  RUST_XRAY_BIN="${RUST_XRAY_BIN}" \
  SMOKE_XRAY_BIN="${XRAY_BIN}" \
  XRAY_BIN="${XRAY_BIN}" \
  bash "${command_path}" >"${log_path}" 2>&1 &
  OWNED_CHILD_PID=$!
  local rc=0
  wait "${OWNED_CHILD_PID}" || rc=$?
  OWNED_CHILD_PID=""
  if [[ "${SMOKE_VERBOSE}" == "1" ]]; then
    cat "${log_path}"
  fi
  SUITE_NAMES+=("${name}")
  if [[ "${rc}" -eq 0 ]]; then
    SUITE_RESULTS+=("PASS")
    SUITE_REASONS+=("")
    echo "=== PASS: ${name} ==="
  elif grep -Rqs "REALITY accepted stage DestConnect failed: failed to lookup address information" "${work_dir}"; then
    SUITE_RESULTS+=("SKIP_ENVIRONMENT")
    SUITE_REASONS+=("external REALITY target DNS resolution unavailable; log=${log_path}")
    echo "=== SKIP ENVIRONMENT: ${name}; external REALITY target DNS resolution unavailable ==="
  else
    SUITE_RESULTS+=("FAIL")
    SUITE_REASONS+=("log=${log_path}")
    echo "=== FAIL: ${name}; last log lines ===" >&2
    tail -n 40 "${log_path}" >&2 || true
  fi
}

write_summary() {
  local pass=0 fail=0 skip_env=0 skip_unsupported=0 index status
  echo
  printf '%-20s %5s %5s %9s %16s\n' "SUITE" "PASS" "FAIL" "SKIP_ENV" "SKIP_UNSUPPORTED"
  for ((index = 0; index < ${#SUITE_NAMES[@]}; index++)); do
    status="${SUITE_RESULTS[index]}"
    case "${status}" in
      PASS) pass=$((pass + 1)) ;;
      FAIL) fail=$((fail + 1)) ;;
      SKIP_ENVIRONMENT) skip_env=$((skip_env + 1)) ;;
      SKIP_UNSUPPORTED) skip_unsupported=$((skip_unsupported + 1)) ;;
    esac
    printf '%-20s %5s %5s %9s %16s\n' "${SUITE_NAMES[index]}" \
      "$([[ "${status}" == PASS ]] && echo 1 || echo 0)" \
      "$([[ "${status}" == FAIL ]] && echo 1 || echo 0)" \
      "$([[ "${status}" == SKIP_ENVIRONMENT ]] && echo 1 || echo 0)" \
      "$([[ "${status}" == SKIP_UNSUPPORTED ]] && echo 1 || echo 0)"
  done
  printf '%-20s %5s %5s %9s %16s\n' "TOTAL" "${pass}" "${fail}" "${skip_env}" "${skip_unsupported}"
  python3 - "${SUMMARY_JSON}" "$(git -C "${REPO_ROOT}" rev-parse HEAD)" "$(sha256 "${RUST_XRAY_BIN}")" "${XRAY_BIN}" "${SMOKE_STARTED_AT}" "${SUITE_NAMES[*]}" "${SUITE_RESULTS[*]}" "${SUITE_REASONS[*]}" <<'PY'
import json, sys
from datetime import datetime, timezone
path, head, binary_sha, xray_bin, started_at, names, results, reasons = sys.argv[1:]
items = [
    {"suite": name, "status": status, "reason": reason or None}
    for name, status, reason in zip(names.split(), results.split(), reasons.split())
]
with open(path, "w") as out:
    json.dump({
        "git_head": head,
        "binary_sha256": binary_sha,
        "xray_bin": xray_bin,
        "started_at": started_at,
        "finished_at": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
        "suites": items,
    }, out, indent=2)
PY
  echo "machine-readable report: ${SUMMARY_JSON}"
  if [[ "${fail}" -eq 0 ]]; then
    echo "FINAL STATUS: READY"
    return 0
  fi
  echo "FINAL STATUS: FAILED" >&2
  return 1
}

main() {
  case "${1:-all}" in
    all) SELECTED="reality udp vless-encryption xhttp" ;;
    reality|udp|vless-encryption|xhttp) SELECTED="$1" ;;
    *) echo "usage: $0 [all|reality|udp|vless-encryption|xhttp]" >&2; exit 2 ;;
  esac
  mkdir -p "${SMOKE_ROOT_DIR}"
  build_once
  if [[ "${SMOKE_ENVIRONMENT_READY}" != "1" ]]; then
    local suite
    for suite in ${SELECTED}; do
      case "${suite}" in
        vless-encryption)
          skip_suite_environment vless-encryption
          skip_suite_environment vless-encryption-0rtt
          ;;
        *) skip_suite_environment "${suite}" ;;
      esac
    done
    write_summary
    return
  fi
  local suite
  for suite in ${SELECTED}; do
    case "${suite}" in
      reality) run_suite reality "${REPO_ROOT}/scripts/live_reality_smoke/run-live-smoke.sh" ;;
      udp) run_suite udp "${REPO_ROOT}/scripts/live_udp_smoke/run-live-udp-smoke.sh" ;;
      vless-encryption)
        run_suite vless-encryption "${REPO_ROOT}/scripts/live_vless_encryption_smoke/run-live-vless-encryption-smoke.sh"
        run_suite vless-encryption-0rtt "${REPO_ROOT}/scripts/live_vless_encryption_smoke/run-live-vless-encryption-0rtt-smoke.sh"
        ;;
      xhttp) run_suite xhttp "${REPO_ROOT}/scripts/live_xhttp_smoke/run-live-xhttp-smoke.sh" ;;
    esac
  done
  write_summary
}

main "$@"
