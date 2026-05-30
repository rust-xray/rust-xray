#!/usr/bin/env bash
# Measure HTTP(S) latency via curl (optionally through a local proxy).
# Compare rust-xray vs Go Xray-core by running the same client/proxy setup twice.

set -euo pipefail

TARGET_URL="${TARGET_URL:-https://example.com/}"
PROXY_URL="${PROXY_URL:-}"
COUNT="${COUNT:-50}"
WARMUP="${WARMUP:-5}"
OUT_DIR="${OUT_DIR:-./target/latency-report-$(date -u +%Y%m%dT%H%M%SZ)}"

CURL_WRITE_OUT='time_connect=%{time_connect} time_appconnect=%{time_appconnect} time_starttransfer=%{time_starttransfer} time_total=%{time_total}\n'

usage() {
  cat <<'EOF'
Usage: scripts/latency/measure-latency.sh

Environment:
  TARGET_URL   URL to fetch (default: https://example.com/)
  PROXY_URL    Optional proxy for curl -x (e.g. socks5h://127.0.0.1:10808)
  COUNT        Measured requests after warmup (default: 50)
  WARMUP       Warmup requests discarded (default: 5)
  OUT_DIR      Output directory (default: ./target/latency-report-<timestamp>)

Example:
  PROXY_URL=socks5h://127.0.0.1:10808 COUNT=100 \
    scripts/latency/measure-latency.sh
EOF
}

if [[ "${1:-}" == "-h" || "${1:-}" == "--help" ]]; then
  usage
  exit 0
fi

if ! command -v curl >/dev/null 2>&1; then
  echo "error: curl not found in PATH" >&2
  exit 1
fi
if ! command -v awk >/dev/null 2>&1; then
  echo "error: awk not found in PATH" >&2
  exit 1
fi

mkdir -p "${OUT_DIR}"

REPORT="${OUT_DIR}/report.txt"
SAMPLES="${OUT_DIR}/samples.tsv"
RAW_LOG="${OUT_DIR}/curl-raw.log"

run_curl_once() {
  local -a curl_args=(
    -o /dev/null
    -sS
    -w "${CURL_WRITE_OUT}"
  )
  if [[ -n "${PROXY_URL}" ]]; then
    curl_args+=(-x "${PROXY_URL}")
  fi
  curl "${curl_args[@]}" "${TARGET_URL}"
}

{
  echo "latency measurement report"
  echo "generated_at_utc: $(date -u +%Y-%m-%dT%H:%M:%SZ)"
  echo "target_url: ${TARGET_URL}"
  echo "proxy_url: ${PROXY_URL:-<none>}"
  echo "warmup: ${WARMUP}"
  echo "count: ${COUNT}"
  echo
} >"${REPORT}"

echo "time_connect	time_appconnect	time_starttransfer	time_total" >"${SAMPLES}"
: >"${RAW_LOG}"

echo "Warmup (${WARMUP})..." >&2
for ((i = 1; i <= WARMUP; i++)); do
  if ! line="$(run_curl_once 2>>"${RAW_LOG}")"; then
    echo "error: warmup request ${i} failed (see ${RAW_LOG})" >&2
    exit 1
  fi
  printf '%s' "${line}" >>"${RAW_LOG}"
done

echo "Measuring (${COUNT})..." >&2
for ((i = 1; i <= COUNT; i++)); do
  if ! line="$(run_curl_once 2>>"${RAW_LOG}")"; then
    echo "error: measured request ${i} failed (see ${RAW_LOG})" >&2
    exit 1
  fi
  printf '%s' "${line}" >>"${RAW_LOG}"
  # Parse curl -w line into TSV (space-separated key=value pairs).
  awk -v raw="${line}" '
    BEGIN {
      split(raw, parts, " ")
      for (i = 1; i <= length(parts); i++) {
        split(parts[i], kv, "=")
        if (kv[1] == "time_connect") tc = kv[2]
        if (kv[1] == "time_appconnect") ta = kv[2]
        if (kv[1] == "time_starttransfer") ts = kv[2]
        if (kv[1] == "time_total") tt = kv[2]
      }
      print tc "\t" ta "\t" ts "\t" tt
    }
  ' >>"${SAMPLES}"
done

compute_stats() {
  local column="$1"
  awk -F '\t' -v col="${column}" '
    function percentile(sorted, p,    n, idx) {
      n = length(sorted)
      if (n == 0) return "nan"
      if (n == 1) return sorted[1]
      idx = int(p * (n - 1) + 0.5) + 1
      if (idx < 1) idx = 1
      if (idx > n) idx = n
      return sorted[idx]
    }
    NR == 1 { next }
    {
      v[NR - 1] = $col + 0
      sum += v[NR - 1]
      if (NR == 2 || $col + 0 < min) min = $col + 0
      if (NR == 2 || $col + 0 > max) max = $col + 0
    }
    END {
      n = NR - 1
      if (n == 0) {
        print "min=nan avg=nan p50=nan p95=nan max=nan n=0"
        exit
      }
      asort(v, sorted)
      avg = sum / n
      printf "min=%.6f avg=%.6f p50=%.6f p95=%.6f max=%.6f n=%d\n",
        min, avg, percentile(sorted, 0.50), percentile(sorted, 0.95), max, n
    }
  ' "${SAMPLES}"
}

{
  echo "[summary] (seconds)"
  echo "metric	min	avg	p50	p95	max	n"
  for metric_name in time_connect time_appconnect time_starttransfer time_total; do
    case "${metric_name}" in
      time_connect) col=1 ;;
      time_appconnect) col=2 ;;
      time_starttransfer) col=3 ;;
      time_total) col=4 ;;
    esac
    stats="$(compute_stats "${col}")"
    min=$(echo "${stats}" | sed -n 's/.*min=\([^ ]*\).*/\1/p')
    avg=$(echo "${stats}" | sed -n 's/.*avg=\([^ ]*\).*/\1/p')
    p50=$(echo "${stats}" | sed -n 's/.*p50=\([^ ]*\).*/\1/p')
    p95=$(echo "${stats}" | sed -n 's/.*p95=\([^ ]*\).*/\1/p')
    max=$(echo "${stats}" | sed -n 's/.*max=\([^ ]*\).*/\1/p')
    n=$(echo "${stats}" | sed -n 's/.*n=\([0-9]*\).*/\1/p')
    printf '%s\t%s\t%s\t%s\t%s\t%s\t%s\n' \
      "${metric_name}" "${min}" "${avg}" "${p50}" "${p95}" "${max}" "${n}"
  done
  echo
  echo "[per-request] (see ${SAMPLES})"
  echo "raw curl log: ${RAW_LOG}"
} | tee -a "${REPORT}" >&2

echo "Report written to ${REPORT}" >&2
