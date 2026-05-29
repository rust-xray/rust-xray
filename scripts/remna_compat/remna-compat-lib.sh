#!/usr/bin/env bash
# Shared helpers for Remna/Remnawave compatibility smoke (independent from live_reality_smoke).

remna_require_commands() {
  local name
  for name in "$@"; do
    if ! command -v "${name}" >/dev/null 2>&1; then
      echo "error: required command not found in PATH: ${name}" >&2
      return 1
    fi
  done
}

remna_wait_port() {
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

remna_wait_port_closed() {
  local host="$1"
  local port="$2"
  local label="$3"
  local timeout="${4:-40}"
  local elapsed=0

  while (( elapsed < timeout )); do
    if ! (echo >/dev/tcp/"${host}"/"${port}") >/dev/null 2>&1; then
      return 0
    fi
    sleep 0.25
    elapsed=$((elapsed + 1))
  done

  echo "error: timed out waiting for ${label} to close on ${host}:${port}" >&2
  return 1
}

remna_free_port() {
  local port="$1"
  if command -v fuser >/dev/null 2>&1; then
    fuser -k "${port}/tcp" >/dev/null 2>&1 || true
  fi
}

remna_stop_process() {
  local pid="${1:-}"
  if [[ -n "${pid}" ]] && kill -0 "${pid}" >/dev/null 2>&1; then
    kill "${pid}" >/dev/null 2>&1 || true
    local waited=0
    while kill -0 "${pid}" >/dev/null 2>&1 && (( waited < 40 )); do
      sleep 0.1
      waited=$((waited + 1))
    done
    if kill -0 "${pid}" >/dev/null 2>&1; then
      kill -9 "${pid}" >/dev/null 2>&1 || true
    fi
    wait "${pid}" 2>/dev/null || true
  fi
}

remna_log_contains() {
  local pattern="$1"
  grep -Fq "${pattern}" "${REMNA_SERVER_LOG}" 2>/dev/null
}

remna_write_client_config() {
  local output_path="$1"
  local user_id="$2"
  local flow="$3"
  sed \
    -e "s/__USER_ID__/${user_id}/g" \
    -e "s/__FLOW__/${flow}/g" \
    -e "s/__PUBLIC_KEY__/${REMNA_PUBLIC_KEY}/g" \
    "${REMNA_CLIENT_TEMPLATE}" >"${output_path}"
}

remna_start_http_server() {
  remna_stop_process "${REMNA_HTTP_PID:-}"
  python3 -m http.server "${REMNA_HTTP_PORT}" --bind 127.0.0.1 \
    >>"${REMNA_HTTP_LOG}" 2>&1 &
  REMNA_HTTP_PID=$!
  remna_wait_port 127.0.0.1 "${REMNA_HTTP_PORT}" "local HTTP test server"
}

remna_stop_http_server() {
  remna_stop_process "${REMNA_HTTP_PID:-}"
  REMNA_HTTP_PID=""
  remna_free_port "${REMNA_HTTP_PORT}"
}

remna_start_xray_server() {
  remna_stop_process "${REMNA_SERVER_PID:-}"
  remna_free_port "${REMNA_SERVER_PORT}"
  remna_free_port "${REMNA_API_PORT}"
  remna_wait_port_closed 127.0.0.1 "${REMNA_SERVER_PORT}" "rust-xray server" 20 || true
  : >>"${REMNA_SERVER_LOG}"
  (
    cd "${REMNA_WORK_DIR}"
    RUST_LOG="${REMNA_RUST_LOG:-info}" ./xray run -config "${REMNA_SERVER_CONFIG}" \
      >>"${REMNA_SERVER_LOG}" 2>&1
  ) &
  REMNA_SERVER_PID=$!
  sleep 0.2
  if ! kill -0 "${REMNA_SERVER_PID}" >/dev/null 2>&1; then
    echo "error: xray server exited during startup" >&2
    tail -30 "${REMNA_SERVER_LOG}" >&2 || true
    return 1
  fi
  remna_wait_port 127.0.0.1 "${REMNA_SERVER_PORT}" "VLESS REALITY inbound" 60 &&
    remna_wait_port 127.0.0.1 "${REMNA_API_PORT}" "gRPC API"
}

remna_stop_xray_server() {
  remna_stop_process "${REMNA_SERVER_PID:-}"
  REMNA_SERVER_PID=""
  remna_free_port "${REMNA_SERVER_PORT}"
  remna_free_port "${REMNA_API_PORT}"
}

remna_start_xray_client() {
  local client_config="$1"
  remna_stop_process "${REMNA_CLIENT_PID:-}"
  remna_free_port "${REMNA_SOCKS_PORT}"
  : >>"${REMNA_CLIENT_LOG}"
  xray run -config "${client_config}" >>"${REMNA_CLIENT_LOG}" 2>&1 &
  REMNA_CLIENT_PID=$!
  remna_wait_port 127.0.0.1 "${REMNA_SOCKS_PORT}" "xray client SOCKS"
}

remna_stop_xray_client() {
  remna_stop_process "${REMNA_CLIENT_PID:-}"
  REMNA_CLIENT_PID=""
  remna_free_port "${REMNA_SOCKS_PORT}"
}

remna_curl_via_socks() {
  curl --socks5-hostname "127.0.0.1:${REMNA_SOCKS_PORT}" -m "${1:-30}" -sS -o /dev/null -w "%{http_code}" "${2}"
}

remna_curl_via_socks_expect_fail() {
  local code
  if code="$(curl --socks5-hostname "127.0.0.1:${REMNA_SOCKS_PORT}" -m "${1:-20}" -sS -o /dev/null -w "%{http_code}" "${2}" 2>/dev/null)"; then
    [[ "${code}" == "000" ]] || [[ "${code}" -ge 400 ]]
  else
    return 0
  fi
}

remna_grpcurl() {
  grpcurl -plaintext "$@" "${REMNA_API_ADDR}"
}

remna_stats_has_traffic_counters() {
  local email="$1"
  local inbound_tag="$2"
  python3 - <<'PY' "${email}" "${inbound_tag}" "${REMNA_API_ADDR}"
import json
import subprocess
import sys

email, inbound_tag, api_addr = sys.argv[1:4]
pattern = f"user>>>{email}>>>"
raw = subprocess.check_output(
    [
        "grpcurl",
        "-plaintext",
        "-d",
        json.dumps({"pattern": pattern, "reset": False}),
        api_addr,
        "xray.app.stats.command.StatsService/QueryStats",
    ],
    text=True,
)
data = json.loads(raw)
stats = data.get("stat") or []
user_needles = (
    f"user>>>{email}>>>traffic>>>downlink",
    f"user>>>{email}>>>traffic>>>uplink",
)
for entry in stats:
    name = entry.get("name", "")
    raw_value = entry.get("value", 0)
    if raw_value in ("", None):
        raw_value = 0
    value = int(raw_value)
    if name in user_needles and value > 0:
        raise SystemExit(0)
raise SystemExit(1)
PY
}

remna_stats_reset_counter() {
  local counter_name="$1"
  python3 - <<'PY' "${counter_name}" "${REMNA_API_ADDR}"
import json
import subprocess
import sys

name, api_addr = sys.argv[1:3]

def get_stats(reset: bool) -> dict:
    raw = subprocess.check_output(
        [
            "grpcurl",
            "-plaintext",
            "-d",
            json.dumps({"name": name, "reset": reset}),
            api_addr,
            "xray.app.stats.command.StatsService/GetStats",
        ],
        text=True,
        stderr=subprocess.STDOUT,
    )
    return json.loads(raw)

try:
    get_stats(True)
except subprocess.CalledProcessError as err:
    if "not found" in (err.output or "").lower():
        raise SystemExit(1) from err
    raise

data = get_stats(False)
stat = data.get("stat") or {}
raw_value = stat.get("value", 0)
if raw_value in ("", None):
    raw_value = 0
value = int(raw_value)
raise SystemExit(0 if value == 0 else 1)
PY
}

remna_set_report_field() {
  local field="$1"
  local value="$2"
  REMNA_REPORT_JSON="$(
    python3 - <<'PY' "${field}" "${value}" "${REMNA_REPORT_JSON}"
import json
import sys

field, value, raw = sys.argv[1:4]
data = json.loads(raw)
if value in ("true", "false"):
    data[field] = value == "true"
else:
    data[field] = value
print(json.dumps(data, indent=2, sort_keys=True))
PY
  )"
}

remna_write_report() {
  python3 - <<'PY' "${REMNA_REPORT_PATH}" "${REMNA_REPORT_JSON}"
import json
import sys

path, raw = sys.argv[1:3]
data = json.loads(raw)
with open(path, "w", encoding="utf-8") as handle:
    json.dump(data, handle, indent=2, sort_keys=True)
    handle.write("\n")
PY
}
