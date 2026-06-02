#!/usr/bin/env bash
set -euo pipefail

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
  [[ -d src/mux ]] || return 1
  grep -Eq '^[[:space:]]*pub[[:space:]]+mod[[:space:]]+mux;' src/lib.rs || return 1
  [[ -f src/vless/mux.rs ]] || return 1
  [[ "$(wc -l < src/vless/mux.rs)" -le 3 ]] || return 1
  local non_comment
  non_comment="$(grep -Ev '^[[:space:]]*(//|$)' src/vless/mux.rs)"
  [[ "${non_comment}" == "pub use crate::mux::*;" ]]
}

check_transport_boundary_used() {
  grep -R 'run_inbound_transport' -n src \
    | grep -v '^src/transport/mod.rs:' \
    | grep -q . || return 1
  grep -q 'AcceptedTransport::from_inbound_transport_config' src/reality/server.rs || return 1
  grep -q 'transport: &InboundTransportConfig' src/reality/server.rs || return 1
  grep -q 'run_raw_transport(stream, vless_handler)' src/transport/mod.rs || return 1
  grep -q 'run_xhttp_transport(stream, config, vless_handler)' src/transport/mod.rs || return 1
}

check_direct_vless_handoff_only_in_transport_raw() {
  if grep -Eq 'handle_reality_vless_tcp_inbound|handle_reality_vless_tcp_inbound_traced|handle_vless_tcp_inbound' \
    src/app.rs src/reality/*.rs; then
    return 1
  fi

  grep -q 'handle_reality_vless_tcp_inbound_traced' src/transport/raw.rs || return 1
}

check_xhttp_moved_to_transport() {
  [[ -d src/transport/xhttp ]] || return 1
  [[ ! -e src/xhttp ]] || return 1
}

check_no_crate_xhttp_imports() {
  ! grep -R 'crate::xhttp' -n src tests
}

check_xhttp_bridge_only_in_transport_xhttp() {
  grep -q 'serve_xhttp_stream_one' src/transport/xhttp/mod.rs || return 1
  ! grep -Eq 'serve_xhttp_stream_one|run_xhttp_transport' src/app.rs src/reality/*.rs
}

check_packet_up_status_consistent() {
  grep -q 'pub fn packet_up_download_side_ready() -> bool' src/transport/xhttp/mode.rs || return 1
  grep -A4 'pub fn packet_up_download_side_ready() -> bool' src/transport/xhttp/mode.rs | grep -q 'false' || return 1
  grep -q 'packet_up_download_side_not_implemented' src/transport/xhttp/mode.rs || return 1
  grep -qi 'packet-up.*skeleton\|packet-up.*runtime unsupported\|runtime is .*unsupported\|PARTIAL_UNSUPPORTED' docs/xhttp-compat-notes.md || return 1
  grep -q '501 Not Implemented' docs/xhttp-compat-notes.md || return 1
  grep -q 'No VLESS bridge' docs/xhttp-compat-notes.md || return 1
  ! grep -i 'packet-up.*supported' docs/xhttp-compat-notes.md | grep -vi 'unsupported'
}

bash -n scripts/check-project-consistency.sh
run_check cargo_fmt cargo fmt --check
run_check cargo_check cargo check
run_check cargo_test cargo test
run_check xhttp_moved_to_transport check_xhttp_moved_to_transport
run_check no_crate_xhttp_imports check_no_crate_xhttp_imports
run_check transport_boundary_used check_transport_boundary_used
run_check direct_vless_handoff_only_in_transport_raw check_direct_vless_handoff_only_in_transport_raw
run_check mux_source_of_truth check_mux_source_of_truth
run_check packet_up_status_consistent check_packet_up_status_consistent

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
  xhttp_moved_to_transport \
  no_crate_xhttp_imports \
  transport_boundary_used \
  direct_vless_handoff_only_in_transport_raw \
  mux_source_of_truth \
  packet_up_status_consistent \
  overall
do
  echo "${key}: ${STATUS[${key}]:-FAIL}"
done

exit "${OVERALL}"
