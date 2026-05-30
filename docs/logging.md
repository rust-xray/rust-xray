# Logging and performance

rust-xray uses async buffered logging (`tracing-appender` non-blocking writer to stderr) so the hot path does not block on syscall-heavy writes. Formatting and event construction still have a cost; per-record protocol logs are kept off the default INFO path.

## Recommended `RUST_LOG` levels

| Level | Use |
|-------|-----|
| `warn` | Latency measurements and production-like runs |
| `info` | Connection lifecycle (listener, accepted path complete, VLESS relay started/completed, mux session, fallback selected) |
| `debug` | Per-connection technical detail (auth, outbound connect, mux UDP DNS, TLS handshake steps) |
| `trace` | Per TLS record, Vision block, mux frame, hex/AAD previews |

Examples:

```bash
# Quiet runtime (latency)
RUST_LOG=warn ./target/debug/rust-xray run -config config.json

# Default server noise (lifecycle only)
RUST_LOG=info ./target/debug/rust-xray run -config config.json

# Protocol debugging
RUST_LOG=rust_xray=trace,tower=warn,hyper=warn,h2=warn,rustls=warn \
  ./target/debug/rust-xray run -config config.json
```

When `RUST_LOG` is unset, the binary uses its built-in default filter (`rust_xray=debug` for `run`, `warn` for `version`).

## Buffered logging environment variables

| Variable | Default | Meaning |
|----------|---------|---------|
| `RUST_XRAY_LOG_BUFFERED_LINES` | `65536` | Queue capacity (lines); invalid values fall back to default |
| `RUST_XRAY_LOG_BACKPRESSURE` | off (`lossy`) | `1` / `true` / `yes` / `on` → non-lossy mode (senders block when queue is full) |

Async buffered logging is always enabled for tracing output; there is no synchronous stderr `fmt` writer on the hot path.

## What you should not see at INFO

Under `RUST_LOG=info` with normal traffic, these should **not** appear repeatedly:

- `read client TLS application-stream record`
- `decrypting client application-data TLS record`
- `attempting client application-data TLS record decrypt`
- `parsed TLSInnerPlaintext after AEAD decrypt`
- `encrypted TLS application-stream record`
- `vision padding block written` / `vision unpadding block read`
- `mux frame parsed`

They remain available at `trace` (TLS/Vision/mux frames) or `debug` (mux UDP DNS, VLESS request parsed).

### Latency diagnostics (`RUST_LOG=debug`)

Connection-level timings (not per TLS record):

- `REALITY TLS 1.3 handshake completed` — `duration_ms`
- `REALITY accepted path completed` — `duration_ms`
- `VLESS auth completed` — `duration_ms`
- `vless relay completed` / `vless mux relay completed` — `duration_ms`
- `mux udp dns completed` — `latency_ms` per DNS substream
- `mux session completed` — `duration_ms`

## Optional debug env flags

| Variable | Effect |
|----------|--------|
| `RUST_XRAY_DEBUG_RELAY_PREFIX=1` | Hex prefixes on first relay writes / VLESS request (trace) |
| `RUST_XRAY_DEBUG_TLS13_PLAINTEXT=1` | Extra TLS 1.3 Finished decrypt diagnostics |
