# AGENTS.md

## Scope

These instructions apply to the entire repository.

`rust-xray` is an experimental Rust implementation of selected Xray/VLESS
REALITY behavior. It is not production-ready and is not a drop-in replacement
for Xray-core. Treat `docs/compatibility-status.md` as the authoritative feature
matrix; do not describe partial or experimental behavior as fully supported.

## Start Here

Before changing code, read:

- `README.md` for the runtime flow, supported scenarios, and standard commands.
- `docs/compatibility-status.md` when a change affects a compatibility claim.
- The subsystem-specific document under `docs/` for REALITY, XHTTP, Mux, DNS,
  configuration, logging, or Remnawave compatibility.

Use `rg`/`rg --files` to locate implementations and tests. Keep changes focused
on the requested behavior and preserve unrelated work in the worktree.

## Architecture

- `src/app.rs` loads normalized configuration, constructs listeners and shared
  runtime state, and coordinates pre-auth, accepted, and fallback paths.
- `src/config/xray/raw.rs` contains serde-compatible Xray/Remnawave JSON shapes.
  Keep this layer data-only and preserve tolerant parsing where already used.
- `src/config/xray/{validate,transport,reality,xhttp,api,routing}.rs` contains
  validation and compatibility helpers.
- `src/config/normalized.rs` is the runtime source of truth for supported
  inbounds. Runtime code should not reconstruct behavior directly from raw JSON.
- `src/reality/` implements REALITY inspection, authentication, certificate
  handling, and the accepted TLS 1.3 path.
- `src/transport/` is the boundary between a decrypted REALITY application
  stream and VLESS. Raw TCP and XHTTP dispatch must remain behind
  `run_inbound_transport`; do not hand off directly from `app.rs` or
  `src/reality/` to VLESS.
- `src/vless/`, `src/mux/`, `src/dns/`, `src/outbound/`, `src/api/`, and
  `src/stats/` own their respective protocol/runtime concerns. `src/mux/` is the
  Mux implementation source of truth; `src/vless/mux.rs` is only a re-export.
- `proto/` and `build.rs` define the generated tonic/prost API. If a proto file
  is added, update the explicit proto list and rerun the relevant build/tests.

Unit tests live under `tests/unit/` but are attached to source modules through
`#[cfg(test)]` plus `#[path = "..."]`. Integration tests are top-level files in
`tests/`; fixtures belong in `tests/fixtures/`. Follow the existing layout when
adding coverage.

## Behavioral Invariants

- Ordinary or invalid non-REALITY traffic is relayed to the configured
  `dest`/`target` fallback.
- Once REALITY pre-auth is accepted, TLS/VLESS failures close the connection;
  they must not fall back to `dest`.
- Preserve the documented SNI, AEAD, short ID, client-version, and time-window
  validation order unless the task explicitly changes the protocol policy.
- Keep unsupported combinations fail-fast and explicit. In particular, do not
  silently enable features listed as partial or unsupported in the compatibility
  matrix.
- Preserve Xray-compatible aliases and config behavior unless a deliberate
  compatibility change is covered by tests and documentation.
- Never log private keys, auth keys, ECDHE shared secrets, traffic secrets,
  plaintext REALITY `session_id`, private signing keys, or fixture secrets.
  Logs may expose only the non-secret metadata already documented in README.
- Avoid blocking I/O in Tokio request/connection paths. Bound reads and buffers
  for untrusted network input and retain useful `io::ErrorKind` values.

## Making Changes

- Prefer the smallest module that owns the behavior; do not grow `src/app.rs`
  with protocol details that belong in a subsystem.
- Add or update tests with every behavior change. Cover successful behavior and
  the relevant malformed, rejected, fallback, or unsupported path.
- Keep protocol parsing byte-exact and avoid unchecked indexing or length
  arithmetic on peer-controlled input.
- Keep compatibility docs synchronized with runtime behavior. XHTTP status is
  checked mechanically against `README.md` and `docs/compatibility-status.md`.
- Do not rewrite captured binary fixtures or expected fixture metadata unless
  the protocol change requires it. Never commit `tests/fixtures/reality/local-*`.
- Run `cargo fmt` after Rust edits. Do not manually edit generated build output
  under `target/`.

## Verification

Use the narrowest useful test while iterating:

```bash
cargo test --lib <test_name>
cargo test --test <integration_test_name>
```

For a normal Rust change, finish with:

```bash
cargo fmt --check
cargo test
cargo clippy --all-targets
```

For changes to module boundaries, compatibility status, XHTTP, or Mux, also run:

```bash
bash scripts/check-project-consistency.sh
```

Live suites require local networking and external compatibility tooling and are
slower than the Rust test suite. Run the relevant suite for end-to-end protocol
or interoperability changes, and report clearly if it was not run:

```bash
make live-smoke
bash scripts/live_xhttp_smoke/run-live-xhttp-smoke.sh
bash scripts/remna_compat/run-local-api-smoke.sh
```

Useful fixture commands are `make fixture-test`, `make fixture-decode`, and
`make fixture-decode-write`; the last command intentionally rewrites expected
fixture metadata and should only be used when that update is intended.

## Handoff

Summarize changed behavior, list the verification commands actually run, and
call out remaining gaps or skipped live tests. Do not claim broader Xray
compatibility than the authoritative matrix demonstrates.
