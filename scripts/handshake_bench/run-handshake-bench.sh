#!/usr/bin/env bash
# Informational handshake/transcript benchmark (not part of normal CI).
set -euo pipefail
cd "$(dirname "$0")/../.."
cargo test --lib transcript_digest_benchmark -- --ignored --nocapture
