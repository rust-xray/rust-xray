#!/usr/bin/env bash
# Run on Linux x86_64 after copying dist/linux-x86_64-gnu/rust-xray.
set -euo pipefail

if [[ "$(uname -s)" != "Linux" ]]; then
  echo "ERROR: this script must run on Linux (got $(uname -s))" >&2
  exit 1
fi

if [[ "$(uname -m)" != "x86_64" ]]; then
  echo "ERROR: this script requires x86_64 (got $(uname -m))" >&2
  exit 1
fi

BIN="${1:-./rust-xray}"
if [[ ! -f "$BIN" ]]; then
  echo "ERROR: binary not found: $BIN" >&2
  exit 1
fi
chmod +x "$BIN"

echo "== host =="
uname -a
if command -v getconf >/dev/null 2>&1; then
  echo "GNU_LIBC_VERSION=$(getconf GNU_LIBC_VERSION 2>/dev/null || echo unknown)"
fi

echo "== file =="
FILE_OUT="$(file "$BIN")"
echo "$FILE_OUT"
case "$FILE_OUT" in
  *ELF*64-bit*x86-64* | *ELF*64-bit*80386* | *ELF*64-bit*x86_64*) ;;
  *)
    echo "ERROR: not Linux x86_64 ELF: $FILE_OUT" >&2
    exit 1
    ;;
esac

echo "== dynamic linker =="
if command -v readelf >/dev/null 2>&1; then
  readelf -l "$BIN" | awk '/interpreter/ {print}'
  echo "== NEEDED =="
  readelf -d "$BIN" | awk '/NEEDED/ {print}'
  MAX_GLIBC="$(readelf --dyn-syms "$BIN" 2>/dev/null \
    | awk '/@GLIBC_/ {print $NF}' \
    | sed -n 's/.*@GLIBC_\([0-9.]*\).*/\1/p' \
    | sort -V \
    | tail -1 || true)"
  if [[ -n "$MAX_GLIBC" ]]; then
    echo "max_glibc_symbol_version=${MAX_GLIBC}"
  fi
elif command -v llvm-readelf >/dev/null 2>&1; then
  llvm-readelf -l "$BIN" | awk '/interpreter/ {print}'
  echo "== NEEDED =="
  llvm-readelf -d "$BIN" | awk '/NEEDED/ {print}'
else
  echo "readelf not available; skipping detailed ELF audit"
fi

echo "== ldd =="
if command -v ldd >/dev/null 2>&1; then
  ldd "$BIN"
else
  echo "ldd not available"
fi

echo "== version =="
"$BIN" version

echo "PASS: Linux x86_64 GNU binary executes"
