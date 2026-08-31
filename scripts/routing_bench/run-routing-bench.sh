#!/usr/bin/env bash
# Informational routing decision benchmark (not part of normal CI).
set -euo pipefail
cd "$(dirname "$0")/../.."
cargo test --lib routing_decision_benchmark -- --ignored --nocapture
