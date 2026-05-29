#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/../.." && pwd)"

# shellcheck source=scripts/remna_compat/remna-compat-lib.sh
source "${SCRIPT_DIR}/remna-compat-lib.sh"

REMNA_PUBLIC_KEY="${REMNA_PUBLIC_KEY:-oU1MbEgszawWQJa0S_DxLsNt9G2zyE4rF-CrqvJjTmg}"
REMNA_SERVER_PORT="${REMNA_SERVER_PORT:-25443}"
REMNA_API_PORT="${REMNA_API_PORT:-10185}"
REMNA_SOCKS_PORT="${REMNA_SOCKS_PORT:-11808}"
REMNA_HTTP_PORT="${REMNA_HTTP_PORT:-18080}"
REMNA_DYNAMIC_ID="${REMNA_DYNAMIC_ID:-22222222-2222-2222-2222-222222222222}"
REMNA_DYNAMIC_EMAIL="${REMNA_DYNAMIC_EMAIL:-remna-dynamic@example.test}"
REMNA_DYNAMIC_FLOW="${REMNA_DYNAMIC_FLOW:-xtls-rprx-vision}"
REMNA_INBOUND_TAG="${REMNA_INBOUND_TAG:-vless-reality-in}"
REMNA_SKIP_BUILD="${REMNA_SKIP_BUILD:-0}"
REMNA_SKIP_LIVE="${REMNA_SKIP_LIVE:-0}"

REMNA_WORK_DIR="${REMNA_WORK_DIR:-/tmp/rust-xray-remna-compat-$$}"
REMNA_REPORT_PATH="${REMNA_REPORT_PATH:-${REMNA_WORK_DIR}/remna-compat-report.json}"
REMNA_SERVER_CONFIG="${SCRIPT_DIR}/remna-generated-reality-vless-api.json"
REMNA_CLIENT_TEMPLATE="${SCRIPT_DIR}/xray-client-remna.template.json"
REMNA_API_ADDR="127.0.0.1:${REMNA_API_PORT}"
REMNA_CURL_URL="http://127.0.0.1:${REMNA_HTTP_PORT}/"

REMNA_SERVER_LOG="${REMNA_WORK_DIR}/server.log"
REMNA_CLIENT_LOG="${REMNA_WORK_DIR}/client.log"
REMNA_HTTP_LOG="${REMNA_WORK_DIR}/http.log"
REMNA_XRAY_BIN="${REMNA_WORK_DIR}/xray"
REMNA_CLIENT_CONFIG="${REMNA_WORK_DIR}/xray-client.json"
REMNA_GRPC_PAYLOAD="${REMNA_WORK_DIR}/alter-inbound.json"

REMNA_SERVER_PID=""
REMNA_CLIENT_PID=""
REMNA_HTTP_PID=""
REMNA_FAILED=0

git_rev() {
  if git -C "${REPO_ROOT}" rev-parse --short HEAD >/dev/null 2>&1; then
    git -C "${REPO_ROOT}" rev-parse --short HEAD
  else
    echo "unknown"
  fi
}

REMNA_REPORT_JSON="$(
  python3 - <<'PY'
import json
from datetime import datetime, timezone

print(
    json.dumps(
        {
            "generated_at": datetime.now(timezone.utc).isoformat(),
            "rust_xray_git_rev": None,
            "cli_run_passed": False,
            "api_reflection_passed": False,
            "getsysstats_passed": False,
            "add_user_passed": False,
            "curl_added_user_passed": False,
            "stats_query_passed": False,
            "stats_reset_passed": False,
            "remove_user_passed": False,
            "curl_removed_user_failed_as_expected": False,
        },
        indent=2,
        sort_keys=True,
    )
)
PY
)"
remna_set_report_field "rust_xray_git_rev" "$(git_rev)"

cleanup() {
  remna_stop_xray_client
  remna_stop_xray_server
  remna_stop_http_server
  remna_write_report || true
}
trap cleanup EXIT

mark_fail() {
  REMNA_FAILED=1
}

run_check() {
  local field="$1"
  shift
  if "$@"; then
    remna_set_report_field "${field}" "true"
    echo "PASS ${field}"
    return 0
  fi
  remna_set_report_field "${field}" "false"
  echo "FAIL ${field}" >&2
  mark_fail
  return 1
}

if [[ "${REMNA_SKIP_LIVE}" == "1" ]]; then
  echo "Skipping Remna compat smoke (REMNA_SKIP_LIVE=1)"
  remna_write_report
  exit 0
fi

mkdir -p "${REMNA_WORK_DIR}"

if ! remna_require_commands cargo curl python3 grpcurl; then
  mark_fail
  remna_write_report
  exit 1
fi

HAVE_XRAY_CLIENT=0
if command -v xray >/dev/null 2>&1; then
  HAVE_XRAY_CLIENT=1
else
  echo "warning: upstream xray client not found; curl checks will FAIL" >&2
fi

if [[ "${REMNA_SKIP_BUILD}" != "1" ]]; then
  echo "Building rust-xray (xray binary)..."
  cargo build --manifest-path "${REPO_ROOT}/Cargo.toml" --bin xray --quiet
fi

ln -sf "${REPO_ROOT}/target/debug/xray" "${REMNA_XRAY_BIN}"

remna_free_port "${REMNA_SERVER_PORT}"
remna_free_port "${REMNA_API_PORT}"
remna_free_port "${REMNA_SOCKS_PORT}"
remna_free_port "${REMNA_HTTP_PORT}"

remna_start_http_server

run_check cli_run_passed remna_start_xray_server
if ! remna_log_contains "REALITY listener started"; then
  echo "warning: server log missing REALITY listener started" >&2
  remna_set_report_field "cli_run_passed" "false"
  mark_fail
fi

run_check api_reflection_passed bash -c \
  "grpcurl -plaintext '${REMNA_API_ADDR}' list | grep -Fq 'xray.app.stats.command.StatsService' && \
   grpcurl -plaintext '${REMNA_API_ADDR}' list | grep -Fq 'xray.app.proxyman.command.HandlerService'"

run_check getsysstats_passed \
  grpcurl -plaintext -d '{}' "${REMNA_API_ADDR}" xray.app.stats.command.StatsService/GetSysStats \
    >/dev/null

python3 "${SCRIPT_DIR}/encode-handler-request.py" add-user \
  --tag "${REMNA_INBOUND_TAG}" \
  --email "${REMNA_DYNAMIC_EMAIL}" \
  --id "${REMNA_DYNAMIC_ID}" \
  --flow "${REMNA_DYNAMIC_FLOW}" >"${REMNA_GRPC_PAYLOAD}"

run_check add_user_passed \
  grpcurl -plaintext -d "$(cat "${REMNA_GRPC_PAYLOAD}")" "${REMNA_API_ADDR}" \
    xray.app.proxyman.command.HandlerService/AlterInbound >/dev/null

if [[ "${HAVE_XRAY_CLIENT}" -eq 1 ]]; then
  remna_write_client_config "${REMNA_CLIENT_CONFIG}" "${REMNA_DYNAMIC_ID}" "${REMNA_DYNAMIC_FLOW}"
  if remna_start_xray_client "${REMNA_CLIENT_CONFIG}"; then
    http_code="$(remna_curl_via_socks 30 "${REMNA_CURL_URL}" || echo "000")"
    if [[ "${http_code}" =~ ^[23][0-9][0-9]$ ]]; then
      run_check curl_added_user_passed true
    else
      echo "error: curl via added user returned HTTP ${http_code}" >&2
      remna_set_report_field "curl_added_user_passed" "false"
      echo "FAIL curl_added_user_passed" >&2
      mark_fail
    fi
  else
    run_check curl_added_user_passed false
  fi
else
  run_check curl_added_user_passed false
fi

USER_DOWNLINK="user>>>${REMNA_DYNAMIC_EMAIL}>>>traffic>>>downlink"
sleep 1
run_check stats_query_passed \
  remna_stats_has_traffic_counters "${REMNA_DYNAMIC_EMAIL}" "${REMNA_INBOUND_TAG}"

run_check stats_reset_passed remna_stats_reset_counter "${USER_DOWNLINK}"
remna_stop_xray_client

python3 "${SCRIPT_DIR}/encode-handler-request.py" remove-user \
  --tag "${REMNA_INBOUND_TAG}" \
  --email "${REMNA_DYNAMIC_EMAIL}" >"${REMNA_GRPC_PAYLOAD}"

run_check remove_user_passed \
  grpcurl -plaintext -d "$(cat "${REMNA_GRPC_PAYLOAD}")" "${REMNA_API_ADDR}" \
    xray.app.proxyman.command.HandlerService/AlterInbound >/dev/null

if [[ "${HAVE_XRAY_CLIENT}" -eq 1 ]]; then
  remna_start_xray_client "${REMNA_CLIENT_CONFIG}"
  if remna_curl_via_socks_expect_fail 20 "${REMNA_CURL_URL}"; then
    run_check curl_removed_user_failed_as_expected true
  else
    echo "error: curl still succeeded after RemoveUser" >&2
    run_check curl_removed_user_failed_as_expected false
  fi
else
  run_check curl_removed_user_failed_as_expected false
fi

remna_write_report

echo ""
echo "Remna compat report: ${REMNA_REPORT_PATH}"
cat "${REMNA_REPORT_PATH}"

if [[ "${REMNA_FAILED}" -ne 0 ]]; then
  echo "Remna compat smoke failed" >&2
  exit 1
fi

echo "Remna compat smoke passed"
