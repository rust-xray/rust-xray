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
  [[ -d src/mux ]] || return 0
  grep -Eq '^[[:space:]]*pub[[:space:]]+mod[[:space:]]+mux;' src/lib.rs || return 1
  [[ -f src/vless/mux.rs ]] || return 0
  local non_comment
  non_comment="$(grep -Ev '^[[:space:]]*(//|$)' src/vless/mux.rs)"
  [[ "${non_comment}" == "pub use crate::mux::*;" ]]
}

check_normalized_config_runtime_source() {
  grep -q 'normalize_config' src/app.rs || return 1
  grep -q 'NormalizedConfig' src/app.rs || return 1
  grep -q 'NormalizedInbound::VlessReality' src/app.rs || return 1
  if grep -q 'reality_inbound_runtimes(' src/app.rs; then
    return 1
  fi
}

check_legacy_reality_runtime_removed() {
  ! grep -Eq 'RealityInboundRuntime|reality_inbound_runtimes\(' src/app.rs
}

check_transport_boundary_used() {
  grep -q 'run_inbound_transport' src/reality/server.rs || return 1
  grep -q 'AcceptedTransport::from_inbound_transport_config' src/reality/server.rs || return 1
  grep -q 'transport: &InboundTransportConfig' src/reality/server.rs || return 1
  grep -q 'run_raw_transport(stream, vless_handler)' src/transport/mod.rs || return 1
  grep -q 'run_xhttp_transport(stream, config, vless_handler)' src/transport/mod.rs || return 1
  grep -q 'handle_accepted_reality_client_traced' src/app.rs || return 1
}

check_direct_vless_handoff_only_in_transport_raw() {
  if grep -Eq 'handle_reality_vless_tcp_inbound|handle_reality_vless_tcp_inbound_traced|handle_vless_tcp_inbound' \
    src/app.rs src/reality/*.rs; then
    return 1
  fi

  grep -q 'handle_reality_vless_tcp_inbound_traced' src/transport/raw.rs || return 1
}

check_xhttp_bridge_only_in_transport_xhttp() {
  grep -q 'serve_xhttp_stream_one' src/transport/xhttp.rs || return 1
  ! grep -Eq 'serve_xhttp_stream_one|run_xhttp_transport' src/app.rs src/reality/*.rs
}

check_packet_up_status_consistent() {
  grep -q 'pub fn packet_up_download_side_ready() -> bool' src/xhttp/mode.rs || return 1
  grep -A4 'pub fn packet_up_download_side_ready() -> bool' src/xhttp/mode.rs | grep -q 'false' || return 1
  grep -q 'packet_up_download_side_not_implemented' src/xhttp/mode.rs || return 1
  grep -qi 'packet-up.*runtime unsupported\|runtime is .*unsupported\|PARTIAL_UNSUPPORTED' docs/xhttp-compat-notes.md || return 1
  grep -q '501 Not Implemented' docs/xhttp-compat-notes.md || return 1
  grep -q 'No VLESS bridge' docs/xhttp-compat-notes.md || return 1
  grep -q 'mode_packet_up:' scripts/live_xhttp_smoke/run-live-xhttp-smoke.sh || return 1
  grep -q 'for unsupported_mode in packet_up stream_up auto_download packet_down' scripts/live_xhttp_smoke/run-live-xhttp-smoke.sh || return 1
  grep -q 'PASS|UNSUPPORTED' scripts/live_xhttp_smoke/run-live-xhttp-smoke.sh || return 1
}

run_check cargo_fmt cargo fmt --check
run_check cargo_check cargo check
run_check cargo_test cargo test
run_check normalized_config_runtime_source check_normalized_config_runtime_source
run_check legacy_reality_runtime_removed check_legacy_reality_runtime_removed
run_check transport_boundary_used check_transport_boundary_used
run_check direct_vless_handoff_only_in_transport_raw check_direct_vless_handoff_only_in_transport_raw
run_check xhttp_bridge_only_in_transport_xhttp check_xhttp_bridge_only_in_transport_xhttp
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
  normalized_config_runtime_source \
  legacy_reality_runtime_removed \
  transport_boundary_used \
  direct_vless_handoff_only_in_transport_raw \
  xhttp_bridge_only_in_transport_xhttp \
  mux_source_of_truth \
  packet_up_status_consistent \
  overall
do
  echo "${key}: ${STATUS[${key}]:-FAIL}"
done

exit "${OVERALL}"
