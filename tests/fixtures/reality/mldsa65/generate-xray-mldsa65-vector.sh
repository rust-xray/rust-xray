#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
XRAY_BIN="${XRAY_BIN:-${1:-xray}}"
OUTPUT_TXT="${SCRIPT_DIR}/sample-xray-mldsa65-output.txt"
VECTOR_JSON="${SCRIPT_DIR}/sample-mldsa65-vector.json"

if ! command -v "${XRAY_BIN}" >/dev/null 2>&1; then
  echo "error: xray binary not found: ${XRAY_BIN}" >&2
  echo "Set XRAY_BIN or pass the binary path as the first argument." >&2
  exit 1
fi

echo "Running: ${XRAY_BIN} mldsa65"
if ! "${XRAY_BIN}" mldsa65 >"${OUTPUT_TXT}" 2>&1; then
  echo "error: ${XRAY_BIN} mldsa65 failed; see ${OUTPUT_TXT}" >&2
  exit 1
fi

GENERATED_WITH="$("${XRAY_BIN}" version 2>/dev/null | head -n1 || echo "Xray-core")"

extract_field() {
  local label="$1"
  local line
  line="$(grep -E "^[[:space:]]*${label}:[[:space:]]*" "${OUTPUT_TXT}" | head -n1 || true)"
  if [[ -z "${line}" ]]; then
    return 1
  fi
  echo "${line#*:}" | sed 's/^[[:space:]]*//;s/[[:space:]]*$//'
}

SEED_B64=""
VERIFY_B64=""
PARSE_ERROR=0

if ! SEED_B64="$(extract_field Seed)"; then
  echo "warning: could not auto-parse Seed from ${OUTPUT_TXT}" >&2
  PARSE_ERROR=1
fi

if ! VERIFY_B64="$(extract_field Verify)"; then
  echo "warning: could not auto-parse Verify from ${OUTPUT_TXT}" >&2
  PARSE_ERROR=1
fi

if [[ "${PARSE_ERROR}" -ne 0 ]]; then
  cat >&2 <<EOF
Auto-parse failed. Fill ${VECTOR_JSON} manually from ${OUTPUT_TXT}:

  "fixture_status": "ready",
  "seed_b64url": "<Seed value from xray mldsa65>",
  "verify_b64url": "<Verify value from xray mldsa65>",

Upstream command: xray mldsa65
Expected decode lengths: seed 32 bytes, verify 1952 bytes (base64url, no padding).
EOF
  exit 1
fi

python3 - "${VECTOR_JSON}" "${GENERATED_WITH}" "${SEED_B64}" "${VERIFY_B64}" <<'PY'
import json
import sys

vector_path, generated_with, seed_b64, verify_b64 = sys.argv[1:5]
payload = {
    "source": "xray mldsa65",
    "generated_with": generated_with,
    "fixture_status": "ready",
    "seed_b64url": seed_b64,
    "verify_b64url": verify_b64,
    "expected": {
        "seed_len": 32,
        "verify_len": 1952,
    },
    "notes": [
        "seed is server-side mldsa65Seed",
        "verify is client-side mldsa65Verify",
        "no signing vector is included in this phase",
    ],
}
with open(vector_path, "w", encoding="utf-8") as fh:
    json.dump(payload, fh, indent=2)
    fh.write("\n")
PY

echo "Wrote ${VECTOR_JSON}"
echo "Raw output: ${OUTPUT_TXT}"
