#!/usr/bin/env bash
# Dockerless cross-build: macOS -> Linux x86_64 GNU/glibc rust-xray binary.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

GLIBC_VERSION="${RUST_XRAY_GLIBC_VERSION:-2.28}"
RUST_XRAY_PROFILE="${RUST_XRAY_PROFILE:-debug}"
RUST_XRAY_STRIP="${RUST_XRAY_STRIP:-1}"
RUST_TARGET="x86_64-unknown-linux-gnu"
ZIGBUILD_TARGET="${RUST_TARGET}.${GLIBC_VERSION}"
DIST_DIR="$ROOT/dist/linux-x86_64-gnu"
BIN_NAME="rust-xray"

require_cmd() {
  local name="$1"
  local install_hint="$2"
  if ! command -v "$name" >/dev/null 2>&1; then
    echo "ERROR: required command not found: $name" >&2
    echo "$install_hint" >&2
    exit 1
  fi
}

case "$RUST_XRAY_PROFILE" in
  debug | release) ;;
  *)
    echo "ERROR: unsupported RUST_XRAY_PROFILE=${RUST_XRAY_PROFILE} (expected debug or release)" >&2
    exit 1
    ;;
esac

echo "== Stage 8D-X: cross-build ${BIN_NAME} for ${RUST_TARGET} (glibc ${GLIBC_VERSION}, profile ${RUST_XRAY_PROFILE}) =="

require_cmd cargo "Install Rust: https://rustup.rs/"
require_cmd rustup "Install Rust: https://rustup.rs/"
require_cmd zig "Install Zig: brew install zig"
require_cmd cargo-zigbuild "Install cargo-zigbuild: cargo install --locked cargo-zigbuild"

if ! rustup target list --installed | grep -qx "$RUST_TARGET"; then
  echo "ERROR: rustup target not installed: $RUST_TARGET" >&2
  echo "Install with: rustup target add $RUST_TARGET" >&2
  exit 1
fi

HOST_OS="$(uname -s)"
HOST_ARCH="$(uname -m)"
UTC_TS="$(date -u +"%Y-%m-%dT%H:%M:%SZ")"

GIT_SHA="$(git rev-parse HEAD)"
if git diff --quiet && git diff --cached --quiet; then
  GIT_DIRTY="no"
else
  GIT_DIRTY="yes"
fi

RUSTC_VERSION="$(rustc --version)"
CARGO_VERSION="$(cargo --version)"
ZIG_VERSION="$(zig version)"
CARGO_ZIGBUILD_VERSION="$(cargo-zigbuild --version 2>&1 | head -1)"

mkdir -p "$DIST_DIR"

echo "== clean target cache for ${RUST_TARGET}* =="
rm -rf "$ROOT/target/${RUST_TARGET}"*
rm -rf "$ROOT/target/${RUST_TARGET}.${GLIBC_VERSION}"*

export RUSTFLAGS="${RUSTFLAGS:-} -C target-cpu=x86-64"
RUSTFLAGS="${RUSTFLAGS# }"

CARGO_PROFILE_DIR="$RUST_XRAY_PROFILE"
ZIGBUILD_ARGS=(--bin "$BIN_NAME" --target "$ZIGBUILD_TARGET")
if [[ "$RUST_XRAY_PROFILE" == "release" ]]; then
  ZIGBUILD_ARGS+=(--release --config profile.release.strip=false)
fi

echo "== cargo zigbuild (${RUST_XRAY_PROFILE}, bin ${BIN_NAME}) =="
echo "RUSTFLAGS=${RUSTFLAGS}"
cargo zigbuild "${ZIGBUILD_ARGS[@]}"

# cargo-zigbuild may place artifacts under either directory name.
BUILT_BIN=""
for candidate in \
  "$ROOT/target/${ZIGBUILD_TARGET}/${CARGO_PROFILE_DIR}/${BIN_NAME}" \
  "$ROOT/target/${RUST_TARGET}/${CARGO_PROFILE_DIR}/${BIN_NAME}"; do
  if [[ -x "$candidate" ]]; then
    BUILT_BIN="$candidate"
    break
  fi
done

if [[ -z "$BUILT_BIN" ]]; then
  echo "ERROR: built binary not found under target/${ZIGBUILD_TARGET} or target/${RUST_TARGET}" >&2
  exit 1
fi

UNSTRIPPED="$DIST_DIR/${BIN_NAME}.unstripped"
STRIPPED="$DIST_DIR/${BIN_NAME}"
cp "$BUILT_BIN" "$UNSTRIPPED"
chmod +x "$UNSTRIPPED"

UNSTRIPPED_SIZE="$(wc -c <"$UNSTRIPPED" | tr -d ' ')"

STRIP_METHOD=""
strip_linux_elf() {
  local input="$1"
  local output="$2"
  if [[ "$RUST_XRAY_STRIP" == "0" ]]; then
    cp "$input" "$output"
    STRIP_METHOD="disabled (RUST_XRAY_STRIP=0)"
    return 0
  fi
  if command -v llvm-strip >/dev/null 2>&1; then
    cp "$input" "$output"
    llvm-strip "$output"
    STRIP_METHOD="llvm-strip"
    return 0
  fi
  if command -v x86_64-linux-gnu-strip >/dev/null 2>&1; then
    cp "$input" "$output"
    x86_64-linux-gnu-strip "$output"
    STRIP_METHOD="x86_64-linux-gnu-strip"
    return 0
  fi
  cp "$input" "$output"
  STRIP_METHOD="unavailable (left unstripped)"
  echo "WARNING: ELF strip tool unavailable; artifact left unstripped" >&2
}

strip_linux_elf "$UNSTRIPPED" "$STRIPPED"
STRIPPED_SIZE="$(wc -c <"$STRIPPED" | tr -d ' ')"

echo "== ELF validation (file) =="
FILE_OUT="$(file "$STRIPPED")"
echo "$FILE_OUT"
if [[ "$FILE_OUT" != *ELF*64-bit* ]] && [[ "$FILE_OUT" != *ELF64* ]]; then
  echo "ERROR: artifact is not ELF 64-bit: $FILE_OUT" >&2
  exit 1
fi
if [[ "$FILE_OUT" != *x86-64* ]] && [[ "$FILE_OUT" != *x86_64* ]] && [[ "$FILE_OUT" != *80386* ]]; then
  echo "ERROR: artifact is not x86-64: $FILE_OUT" >&2
  exit 1
fi
if [[ "$FILE_OUT" == *Mach-O* ]] || [[ "$FILE_OUT" == *arm64* ]] || [[ "$FILE_OUT" == *aarch64* ]]; then
  echo "ERROR: artifact looks like macOS/arm64, not Linux x86_64 GNU: $FILE_OUT" >&2
  exit 1
fi
if [[ "$FILE_OUT" == *musl* ]]; then
  echo "ERROR: artifact appears musl-linked; expected GNU/glibc: $FILE_OUT" >&2
  exit 1
fi

READELF=""
for candidate in llvm-readelf readelf; do
  if command -v "$candidate" >/dev/null 2>&1; then
    READELF="$candidate"
    break
  fi
done

INTERP=""
NEEDED=""
MAX_GLIBC=""
GLIBC_AUDIT_STATUS="unavailable on host"

if [[ -n "$READELF" ]]; then
  INTERP="$("$READELF" -l "$UNSTRIPPED" 2>/dev/null | awk '/interpreter/ {print $NF; exit}' | tr -d '[]' || true)"
  NEEDED="$("$READELF" -d "$UNSTRIPPED" 2>/dev/null | awk '/NEEDED/ {print $NF}' | tr -d '[]' | sort -u | paste -sd, - || true)"

  GLIBC_VERSIONS="$("$READELF" --dyn-syms "$UNSTRIPPED" 2>/dev/null \
    | awk '/@GLIBC_/ {print $NF}' \
    | sed -n 's/.*@GLIBC_\([0-9.]*\).*/\1/p' \
    | sort -V \
    | uniq || true)"
  if [[ -n "$GLIBC_VERSIONS" ]]; then
    MAX_GLIBC="$(echo "$GLIBC_VERSIONS" | tail -1)"
    GLIBC_AUDIT_STATUS="observed max GLIBC_${MAX_GLIBC}"
    if [[ "$MAX_GLIBC" != "$GLIBC_VERSION" ]] \
      && [[ "$(printf '%s\n' "$GLIBC_VERSION" "$MAX_GLIBC" | sort -V | tail -1)" == "$MAX_GLIBC" ]]; then
      echo "ERROR: binary requires GLIBC_${MAX_GLIBC}, exceeds requested baseline ${GLIBC_VERSION}" >&2
      exit 1
    fi
  else
    GLIBC_AUDIT_STATUS="no GLIBC symbol versions found via ${READELF}"
  fi
else
  GLIBC_AUDIT_STATUS="readelf unavailable; verify on Linux with scripts/check-linux-x86_64-gnu-binary.sh"
fi

BUILD_INFO="$DIST_DIR/build-info.txt"
{
  echo "git_sha=${GIT_SHA}"
  echo "git_dirty=${GIT_DIRTY}"
  echo "rustc_version=${RUSTC_VERSION}"
  echo "cargo_version=${CARGO_VERSION}"
  echo "zig_version=${ZIG_VERSION}"
  echo "cargo_zigbuild_version=${CARGO_ZIGBUILD_VERSION}"
  echo "rust_target=${RUST_TARGET}"
  echo "zigbuild_target=${ZIGBUILD_TARGET}"
  echo "glibc_baseline=${GLIBC_VERSION}"
  echo "build_profile=${RUST_XRAY_PROFILE}"
  echo "build_timestamp_utc=${UTC_TS}"
  echo "source_host_os=${HOST_OS}"
  echo "source_host_arch=${HOST_ARCH}"
  echo "rustflags=${RUSTFLAGS}"
  echo "strip_method=${STRIP_METHOD}"
  echo "unstripped_bytes=${UNSTRIPPED_SIZE}"
  echo "stripped_bytes=${STRIPPED_SIZE}"
  echo "file_output=${FILE_OUT}"
  echo "dynamic_interpreter=${INTERP:-unknown}"
  echo "needed_libraries=${NEEDED:-unknown}"
  echo "glibc_symbol_audit=${GLIBC_AUDIT_STATUS}"
  if [[ -n "$MAX_GLIBC" ]]; then
    echo "maximum_required_glibc_symbol_version=${MAX_GLIBC}"
  fi
} >"$BUILD_INFO"

(
  cd "$DIST_DIR"
  shasum -a 256 "$BIN_NAME" "${BIN_NAME}.unstripped" >SHA256SUMS
)

cat "$BUILD_INFO"
echo
echo "Artifacts:"
echo "  $STRIPPED"
echo "  $UNSTRIPPED"
echo "  $BUILD_INFO"
echo "  $DIST_DIR/SHA256SUMS"
echo
echo "Remote validation (on Linux x86_64 host):"
echo "  scp dist/linux-x86_64-gnu/rust-xray user@host:/path/to/test/"
echo "  scripts/check-linux-x86_64-gnu-binary.sh /path/to/test/rust-xray"
echo
echo "Stage 8D RemnaNode E2E (on Linux host, after binary check):"
echo "  RUST_XRAY_BIN=/path/to/rust-xray SECRET_KEY=... bash scripts/remnanode_e2e/run-remnanode-e2e.sh"
