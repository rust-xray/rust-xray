#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "${ROOT_DIR}"

fail=0

if rg -n 'reality-mldsa65-crypto' Cargo.toml src scripts/live_reality_smoke; then
  echo "error: removed reality-mldsa65-crypto feature marker found" >&2
  fail=1
fi

if rg -n 'cfg\s*\(\s*feature\s*=\s*"reality-mldsa65-crypto"\s*\)' src; then
  echo "error: removed cfg(feature = \"reality-mldsa65-crypto\") found" >&2
  fail=1
fi

if rg -n 'cfg\s*\(\s*not\s*\(\s*feature\s*=\s*"reality-mldsa65-crypto"\s*\)\s*\)' src; then
  echo "error: removed cfg(not(feature = \"reality-mldsa65-crypto\")) found" >&2
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

if rg -n 'requires feature|crypto_feature_compiled' Cargo.toml src scripts/live_reality_smoke; then
  echo "error: stale ML-DSA feature-gate marker found" >&2
  fail=1
fi

exit "${fail}"
