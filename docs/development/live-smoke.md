# Live smoke

`make live-smoke` runs the canonical serial suite. It builds one release
`rust-xray` binary (unless `SMOKE_SKIP_BUILD=1`), prints the absolute binary
path and SHA-256, allocates dynamic listener ports, and invokes isolated
REALITY, UDP, VLESS Encryption 1RTT, VLESS Encryption 0RTT, and XHTTP suites.
Each suite writes below a private temporary root and the runner emits a summary
plus machine-readable JSON. Scoped commands are `make live-smoke-reality`,
`make live-smoke-udp`, and `make live-smoke-vless-encryption`; the script also
accepts `xhttp` directly.

The runner owns child process shutdown and executes suites serially, preventing
one suite from sharing a listener/process with another. `SMOKE_SERVER_PORT` and
`SMOKE_SOCKS_PORT` are optional fixed-port exceptions; otherwise the smoke
library chooses dynamic ports. `RUST_XRAY_BIN` and `XRAY_BIN` select exact
binaries. `SMOKE_KEEP_TMP=1` or `SMOKE_VERBOSE=1` retains artifacts on success;
failures retain their artifacts automatically. `SMOKE_TIMEOUT` controls suite
timeouts.

The summary distinguishes `PASS`, `FAIL`, `SKIP_ENVIRONMENT`, and
`SKIP_UNSUPPORTED`. A mandatory local case that fails must remain `FAIL`; it
must not be changed into an environment skip or hidden by retry logic. The
canonical runner currently recognizes one narrow environment classification:
external REALITY target DNS resolution failure. All other nonzero suite results
remain failures until evidence demonstrates an external-only cause.

The REALITY 10 MiB Vision regression downloads its payload from
`speed.cloudflare.com`. Its REALITY camouflage target may still be local for
that fixture. A CDN stall is therefore evidence about the external download,
not automatically about rust-xray; conversely, do not label every Vision
failure environmental. Preserve logs and inspect the local server/client phases
before classifying the result.

For diagnosis, use `RUST_LOG` with normal tracing filters. The source also
provides `RUST_XRAY_DEBUG_TLS13_PLAINTEXT`,
`RUST_XRAY_DEBUG_VLESS_PLAINTEXT`, and
`RUST_XRAY_DEBUG_TLS_RECORD_PREFIX`; these can expose bounded plaintext or
record previews and are for controlled debugging only. DNS timing/options use
the `RUST_XRAY_DNS_*` and `RUST_XRAY_MUX_DNS_*` names defined in
`src/dns/options.rs`.

Typical signals are: an accepted-path error after REALITY admission means close,
not fallback; a TLS truncation identifies a partial TLS record/handshake; the
VLESS message `connection closed before vless request` is a clean early close;
`vision direct relay started` marks the reader transition; a discarded stale
Mux event indicates generation filtering; XUDP logs should retain one GlobalID
across reattach; and an inflight DNS waiter failure after leader cancellation
means a subsequent query should become leader. These signals narrow the owning
state machine before changing code.
