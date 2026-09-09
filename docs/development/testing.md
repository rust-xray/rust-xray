# Testing and evidence

Use the smallest relevant check while iterating, then run the repository's
normal checks before handoff:

```bash
cargo test --lib <test_name>
cargo test --test <integration_test_name>
cargo fmt --check
cargo test
cargo clippy --all-targets --all-features
cargo doc --no-deps
```

Unit tests under `tests/unit/` are attached to their source modules. Top-level
`tests/` are integration tests. Fixtures live under `tests/fixtures/`; preserve
captured binary fixtures and their metadata unless the protocol change requires
an intentional update. `make fixture-test` and `make fixture-decode` inspect
existing fixture evidence; the write variant intentionally changes metadata.

Evidence labels matter. **UPSTREAM DERIVED** means bytes or behavior captured
from a pinned upstream implementation. **REFERENCE HARNESS DERIVED** means an
external reference harness produced the vector. **RUST SELF GENERATED** means
the Rust implementation generated its own expected bytes. The last is useful
for regression, but cannot by itself demonstrate Xray interoperability.

Live interoperability and smoke test complete processes, sockets, and selected
external tools; deterministic tests isolate parsing and state transitions. Both
are needed for a wire-sensitive change. Record which was run and any harness
limitation in the status matrix instead of promoting deterministic coverage to
a live claim. [live-smoke.md](live-smoke.md) covers the canonical runner.
