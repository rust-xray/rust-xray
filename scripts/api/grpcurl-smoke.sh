#!/usr/bin/env bash
# Optional developer helper: list and probe the local Xray-compatible gRPC API.
# Requires grpcurl in PATH; not used by automated tests.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/../.." && pwd)"
ADDR="${1:-127.0.0.1:61000}"

if ! command -v grpcurl >/dev/null 2>&1; then
  echo "grpcurl not found; install from https://github.com/fullstorydev/grpcurl" >&2
  exit 2
fi

echo "Listing services on ${ADDR} (plaintext)..."
grpcurl -plaintext "${ADDR}" list

echo
echo "GetSysStats on ${ADDR}..."
grpcurl -plaintext -d '{}' "${ADDR}" xray.app.stats.command.StatsService/GetSysStats
