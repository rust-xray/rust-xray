#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "${ROOT_DIR}"

fail=0
removed_feature="reality-mldsa65-""crypto"
quote='"'
removed_cfg_feature="cfg\\s*\\(\\s*feature\\s*=\\s*${quote}${removed_feature}${quote}\\s*\\)"
removed_cfg_not_feature="cfg\\s*\\(\\s*not\\s*\\(\\s*feature\\s*=\\s*${quote}${removed_feature}${quote}\\s*\\)\\s*\\)"
removed_compiled_marker="crypto_feature_""compiled"
req_left="requi"
req_right="res"
feat_left="fea"
feat_right="ture"
stale_requirement_marker="${req_left}${req_right}[[:space:]].*${feat_left}${feat_right}"

if rg -n "${removed_feature}" Cargo.toml src docs scripts; then
  echo "error: removed ML-DSA crypto feature marker found" >&2
  fail=1
fi

if rg -n "${removed_cfg_feature}" src docs scripts; then
  echo "error: removed ML-DSA crypto cfg(feature) found" >&2
  fail=1
fi

if rg -n "${removed_cfg_not_feature}" src docs scripts; then
  echo "error: removed ML-DSA crypto cfg(not(feature)) found" >&2
  fail=1
fi

if rg -n 'ml-dsa.*optional\s*=\s*true|optional\s*=\s*true.*ml-dsa' Cargo.toml; then
  echo "error: ml-dsa must remain a standard dependency, not optional" >&2
  fail=1
fi

if ! rg -n '^ml-dsa\s*=' Cargo.toml >/dev/null; then
  echo "error: ml-dsa dependency is missing from Cargo.toml" >&2
  fail=1
fi

if rg -n "${stale_requirement_marker}|${removed_compiled_marker}" Cargo.toml src docs scripts; then
  echo "error: stale ML-DSA feature-gate marker found" >&2
  fail=1
fi

exit "${fail}"
