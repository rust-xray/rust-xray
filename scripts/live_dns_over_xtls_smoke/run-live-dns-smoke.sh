#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/../.." && pwd)"

cat <<'EOF'
DNS over XTLS live smoke scaffold

Current implemented coverage is in cargo tests:
  cargo test dns --all-features

TODO for full end-to-end smoke:
  1. Start a local fake DNS-over-TCP upstream.
  2. Start a rust-xray topology with a real VLESS/REALITY outbound runtime.
  3. Expose a local TCP DNS inbound, for example 127.0.0.1:5353.
  4. Query with: dig @127.0.0.1 -p 5353 example.com A +tcp
  5. Assert selected_outbound_tag=proxy and fake DNS upstream hit.

This script is intentionally non-invasive until the project has a reusable
VLESS outbound runtime and dokodemo-door DNS TCP inbound.
EOF

cd "${REPO_ROOT}"
cargo test dns --all-features
