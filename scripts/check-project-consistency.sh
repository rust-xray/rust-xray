#!/usr/bin/env bash
set -u

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "${ROOT}" || exit 1

declare -A STATUS
OVERALL=0

run_check() {
  local key="$1"
  shift
  if "$@"; then
    STATUS["${key}"]="PASS"
  else
    STATUS["${key}"]="FAIL"
    OVERALL=1
  fi
}

maybe_run_script() {
  local key="$1"
  local script="$2"
  if [[ -x "${script}" ]]; then
    run_check "${key}" bash "${script}"
  elif [[ -f "${script}" ]]; then
    run_check "${key}" bash "${script}"
  else
    STATUS["${key}"]="SKIP"
  fi
}

check_mux_source_of_truth() {
  [[ -d src/mux ]] || return 0
  grep -Eq '^[[:space:]]*pub[[:space:]]+mod[[:space:]]+mux;' src/lib.rs || return 1
  [[ -f src/vless/mux.rs ]] || return 0
  local non_comment
  non_comment="$(grep -Ev '^[[:space:]]*(//|$)' src/vless/mux.rs)"
  [[ "${non_comment}" == "pub use crate::mux::*;" ]]
}

check_normalized_config_exported() {
  [[ ! -f src/config/normalized.rs ]] || grep -Eq '^[[:space:]]*pub[[:space:]]+mod[[:space:]]+normalized;' src/config/mod.rs
}

check_transport_xhttp_module_exists() {
  if grep -Eq '^[[:space:]]*(pub[[:space:]]+)?mod[[:space:]]+xhttp;' src/transport/mod.rs; then
    [[ -f src/transport/xhttp.rs || -f src/transport/xhttp/mod.rs ]]
  else
    return 0
  fi
}

check_packet_up_status_consistent() {
  grep -q 'pub fn packet_up_download_side_ready() -> bool' src/xhttp/mode.rs || return 1
  grep -A4 'pub fn packet_up_download_side_ready() -> bool' src/xhttp/mode.rs | grep -q 'false' || return 1
  grep -q 'packet_up_download_side_not_implemented' src/xhttp/mode.rs || return 1
  grep -qi 'packet-up.*runtime unsupported\|runtime is .*unsupported\|PARTIAL_UNSUPPORTED' docs/xhttp-compat-notes.md || return 1
  grep -q 'mode_packet_up:' scripts/live_xhttp_smoke/run-live-xhttp-smoke.sh || return 1
  grep -q 'for unsupported_mode in packet_up stream_up auto_download packet_down' scripts/live_xhttp_smoke/run-live-xhttp-smoke.sh || return 1
  grep -q 'PASS|UNSUPPORTED' scripts/live_xhttp_smoke/run-live-xhttp-smoke.sh || return 1
}

check_docs_status_consistent() {
  [[ -f docs/config-architecture.md ]] || return 1
  grep -qi 'NormalizedConfig is built and tested for parity; runtime migration is staged' docs/config-architecture.md || return 1
  if grep -Rqi 'packet-up.*supported' docs README.md 2>/dev/null; then
    grep -Rqi 'packet-up.*unsupported\|packet-up.*skeleton\|packet-up.*PARTIAL_UNSUPPORTED' docs README.md 2>/dev/null || return 1
  fi
  if grep -Rqi 'xhttp unsupported' docs README.md 2>/dev/null; then
    return 1
  fi
  grep -Rqi 'XHTTP.*MVP\|xhttp.*MVP\|stream-one' docs README.md 2>/dev/null || return 1
  grep -q 'xhttpSettings' src/config/xray/raw.rs || return 1
}

run_check cargo_fmt cargo fmt --check
run_check cargo_check cargo check
run_check cargo_test cargo test
maybe_run_script reality_live_smoke scripts/live_reality_smoke/run-live-smoke.sh
maybe_run_script xhttp_live_smoke scripts/live_xhttp_smoke/run-live-xhttp-smoke.sh
maybe_run_script remna_api_smoke scripts/remna_compat/run-local-api-smoke.sh
run_check mux_source_of_truth check_mux_source_of_truth
run_check normalized_config_exported check_normalized_config_exported
run_check transport_xhttp_module_exists check_transport_xhttp_module_exists
run_check packet_up_status_consistent check_packet_up_status_consistent
run_check docs_status_consistent check_docs_status_consistent

if [[ "${OVERALL}" -eq 0 ]]; then
  STATUS["overall"]="PASS"
else
  STATUS["overall"]="FAIL"
fi

echo "[project consistency]"
for key in \
  cargo_fmt \
  cargo_check \
  cargo_test \
  reality_live_smoke \
  xhttp_live_smoke \
  remna_api_smoke \
  mux_source_of_truth \
  normalized_config_exported \
  transport_xhttp_module_exists \
  packet_up_status_consistent \
  docs_status_consistent \
  overall
do
  echo "${key}: ${STATUS[${key}]:-FAIL}"
done

exit "${OVERALL}"
