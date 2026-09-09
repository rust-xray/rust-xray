# Developer guide

`rust-xray` is an experimental Rust implementation of selected Xray-core VLESS
and REALITY inbound behavior. It is neither production-ready nor a drop-in
replacement for Xray-core. The authoritative support matrix is
[compatibility-status.md](../compatibility-status.md); this directory explains
the design of behavior that the matrix says is implemented or deliberately
rejected.

Wire and externally observable semantics are compared with
[Xray-core @ `5ca6f4b7d4dc20a881d4330e498892697627ec0c`](https://github.com/XTLS/Xray-core/commit/5ca6f4b7d4dc20a881d4330e498892697627ec0c)
and, for REALITY server behavior,
[REALITY @ `8cdf7bf9c7f09cb9814bf08c3eb877f68b85fba8`](https://github.com/XTLS/REALITY/commit/8cdf7bf9c7f09cb9814bf08c3eb877f68b85fba8).
Those pins make a wire-sensitive discussion reviewable; update a pin only with
the corresponding regression evidence.

Start with [architecture.md](architecture.md), then follow an inbound through
[reality.md](reality.md), [vless.md](vless.md), and the selected transport
layer: [vless-encryption.md](vless-encryption.md), [vision.md](vision.md), or
[mux-xudp.md](mux-xudp.md). [routing.md](routing.md) covers dispatch after the
protocol layer. New behavior normally begins in `src/config/xray/` and
`src/config/normalized.rs`, crosses `src/app.rs` and `src/transport/`, and is
then owned by the subsystem that implements its wire format.

Useful commands are:

```bash
cargo build
cargo build --release
cargo test --lib
cargo clippy --all-targets --all-features
cargo doc --no-deps
make live-smoke
```

Read [testing.md](testing.md) before treating a test result as compatibility
evidence, and [live-smoke.md](live-smoke.md) before changing a smoke harness.
[performance.md](performance.md) records allocation and TFO constraints;
[api.md](api.md) covers the runtime service boundary; and
[upstream-parity.md](upstream-parity.md) gives the contribution workflow.

## Documentation inventory

| Document | Purpose | Current? | Overlap | Action |
| --- | --- | --- | --- | --- |
| `README.md` | Product scope, supported scenarios, quick commands | Yes | This index | Keep concise; link here |
| `compatibility-status.md` | Authoritative feature/evidence matrix | Yes | All guides | Keep as status authority |
| `config-architecture.md` | Raw/validated/normalized config layering | Mostly | Architecture guide | Retain as config-specific detail |
| `reality-accepted-path.md` | Deep accepted-handshake notes | Yes | REALITY guide | Retain as implementation detail |
| `mux-cool-compat-notes.md` | Focused Mux compatibility notes | Yes | Mux/XUDP guide | Retain as wire-note companion |
| `vless-encryption-0rtt.md` | 0-RTT vectors and limitations | Yes | Encryption guide | Retain as evidence companion |
| `remna-compat.md` | RemnaNode API compatibility | Yes | API guide | Retain as integration detail |
| `scripts/*/README.md` | Harness-local invocation notes | Yes | Live-smoke guide | Retain beside scripts |
| `dns-future.md`, ML-DSA plans/audits | Scoped gaps or historical plans | Mixed | None | Do not use as support claims |

The repository map is intentionally coarse: `src/reality` owns admission and
accepted TLS; `src/tls` parses record boundaries; `src/vless` owns request and
flow semantics; `src/mux` owns parent/child multiplexing; `src/udp` behavior is
implemented by the VLESS/Mux UDP modules; `src/routing`, `src/outbound`, and
`src/dns` choose and reach targets; `src/api` exposes gRPC services;
`scripts/live_smoke` is represented by `scripts/live_smoke/` plus the scoped
live runners; and `tests/unit` attaches unit tests to source modules.
