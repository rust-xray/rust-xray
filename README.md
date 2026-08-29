# rust-xray

Experimental Rust implementation of selected Xray/VLESS REALITY behavior.

The project starts a TCP listener from an Xray-compatible `config.json`
`inbound`, reads the first TLS `ClientHello`, validates the REALITY candidate
(AEAD + policy), and either relays ordinary/invalid traffic to the fallback
address from `realitySettings.dest` / `realitySettings.target` or enters the
accepted path for a valid REALITY client.

**Non-REALITY clients are relayed to `dest`.**

**This is not a drop-in replacement for Xray-core.** Do not treat this project
as a production Xray replacement. It is **not production-ready**.

**Compatibility status (authoritative):** **[docs/compatibility-status.md](docs/compatibility-status.md)**

## Compatibility Status (summary)

See **[docs/compatibility-status.md](docs/compatibility-status.md)** for the full
matrix. Short version:

### Working

- REALITY TCP/raw inbound, pre-auth (SNI, AEAD, policy), and **accepted** TLS 1.3 path
- **REALITY fallback rate limits (Stage 6):** `limitFallbackUpload` / `limitFallbackDownload` on pre-auth fallback relay (juju/ratelimit-compatible; partial parity — see compatibility doc)
- **REALITY post-handshake record-length detection/cache (Stage 5B):** proactive `dest × serverName × ALPN` probes at startup; runtime cache lookup; post-client-Finished camouflage ApplicationData emission on accepted path
- **REALITY post-handshake CCS tolerance (Stage 5C):** proactive `dest × serverName × ALPN` extra-CCS tolerance probes; runtime cache lookup; accepted-path useless-record policy during `readClientFinished` and on the TLS application stream reader (default `Finite(32)`)
- REALITY pre-auth **X25519MLKEM768 ClientHello parsing**: hybrid `key_share` (`0x11EC`, 1216 bytes) parsed as opaque carrier; trailing 32-byte X25519 used for REALITY auth when no valid standalone `X25519` entry exists (upstream two-pass selection). **Does not** negotiate hybrid TLS on the accepted path.
- VLESS TCP inbound: UUID auth, custom string ID → UUIDv5, `flow=""` and `xtls-rprx-vision` (Vision DIRECT MVP)
- REALITY accepted-path cipher suites: AES128-GCM, AES256-GCM, ChaCha20-Poly1305
- VLESS fallback: default, SNI/name, HTTP path, ALPN (`http/1.1`, `h2`), PROXY v1/v2 (`xver=1|2`)
- Network aliases: `raw`, legacy `tcp`, and experimental `xhttp` / `splithttp`
- **Xray gRPC API (Stages 8A–8E4-B):** when `api` block is present — `ReflectionService` (optional), `StatsService`, `HandlerService`, `RoutingService`, `LoggerService`, `ObservatoryService`. Not full Xray API parity yet (see below).
- **Routing / balancers (Stage 8E2–8E4):** `RuntimeRouter` executes static + dynamic rules on VLESS TCP dispatch; `DomainStrategy` (`AsIs`, `IpOnDemand`, `IpIfNonMatch`); GeoSite/GeoIP; protocol sniff matcher; webhook rules; balancers (`random`, `roundRobin`, `leastPing`, `leastLoad` algorithms). Live Observatory health wired for `leastPing`/`leastLoad` and random/roundRobin fallback health filtering (Stage 8E4-C).
- **HandlerService (Stage 8E1):** dynamic inbound/outbound CRUD, user add/remove, list/get operations for supported VLESS+REALITY / freedom / blackhole types; merged logical inbound auth identity.
- **LoggerService (Stage 8E3):** `RestartLogger` runtime-backed; reopens configured error/access file sinks after external rotation. General logging config gaps remain (`dnsLog`, `maskAddress`, JSON `loglevel` mapping — see compatibility doc).

Accepted path **does not fallback** on failure — handshake/VLESS errors close the
connection.

### Xray gRPC API status (Stages 8A–8E3)

| Service | Status |
|---------|--------|
| API foundation (`api.listen`, reflection, shared runtime) | Implemented |
| `StatsService` | Implemented |
| `HandlerService` | Implemented |
| `RoutingService` | Implemented |
| `LoggerService` | Implemented |
| `ObservatoryService` | Implemented (standard Observatory + BurstObservatory HealthPing; live balancer health wired in Stage 8E4-C) |

This is **not** full Xray API compatibility closure. Remaining API work includes
legacy `v2ray.core.*` aliases, exact `api.tag` / `services` semantics, and
Remna unix-abstract E2E (Stages 8D–8E5).

### Experimental

- **REALITY + XHTTP accepted path (experimental MVP):** server-side HTTP/1.1 / HTTP/2 `stream-one`, `stream-up`, and `packet-up` over accepted REALITY TLS stream; official Xray 26.3.27 interop smoke PASS for default / `auto` / `stream-one` / `stream-up` / `packet-up` / `auto-download` (HTTP/2)
- **XHTTP `packet-up` (experimental supported):** GET download + POST upload ack; live smoke PASS (`mode_packet_up`); HTTP/1.1 chunked upload unit smoke PASS; official Xray H1 interop **not verified**
- **XHTTP `stream-up` (experimental supported):** GET download + POST upload on `/xhttp/{session}`; live smoke PASS (`mode_stream_up`) with official Xray 26.3.27 over HTTP/2
- **XHTTP unsupported / gated:** `packet-down`, XMUX — config may parse; runtime returns `501` / fail-fast
- **Vision over XHTTP:** unsupported (explicitly rejected at startup)
- **VLESS Mux (Happ baseline):** REALITY → TLS 1.3 → VLESS auth → `command=Mux` → mux session start (live smoke validated)
- **UDP DNS over VLESS Mux (port 53):** numeric `:53` targets (e.g. `1.1.1.1:53`) — query forwarded, response received, mux UDP response frame sent
- **Happ Proxy Utility baseline:** REALITY/VLESS/Vision/Mux path with numeric UDP DNS on port 53 works (experimental)
- **ML-DSA-65 baseline (experimental):** valid `mldsa65Seed` accepted, invalid seed rejected at startup, live smoke passes ([details](docs/reality-mldsa65-runtime-baseline.md))

### Partial

- Mux.Cool frame parser and single TCP substream (no parallel substreams)
- Mux UDP DNS for **domain** `:53` targets (resolver hook not wired)
- Remnawave / panel configs: load + REALITY inbound + API + routing execution for supported conditions; RemnaNode unix-abstract E2E pending Stage 8D

### Not yet implemented

- Full Mux.Cool runtime, generic UDP over Mux (non-`:53`), XUDP
- VLESS `command=Udp` (non-Mux)
- REALITY over gRPC / WebSocket transport runtime (rejected at startup when `security: reality`)
- **ML-KEM-768 cryptography** and **TLS 1.3 negotiated X25519MLKEM768** on the REALITY accepted path (hybrid ServerHello, 64-byte shared secret, dest group mirroring — Stage 3+; pre-auth hybrid **carrier parsing only** in Stage 2)
- Full outbound ecosystem beyond freedom/blackhole, DoH, Vision splice/zero-copy beyond DIRECT MVP
- Legacy `v2ray.core.*` API aliases and final API config closure (Stage 8E5)
- REALITY post-handshake **Stage 5C** extras: `GlobalMaxCSSMsgCount`, alert-driven CCS probe paths
- REALITY probe **exact uTLS ClientHello fingerprint** parity (`HelloGolang` / `HelloChrome_Auto`) — probes use rustls (**partial** parity; Stage 5B record-length + Stage 5C extra-CCS tolerance probing only)
- REALITY session resumption on accepted path
- DNS-over-TCP through VLESS outbound/routing (separate future task)
- Full Xray-core drop-in compatibility

**DNS note:** DNS-over-TCP via a future DNS/outbound module does **not** replace
Happ's current **UDP DNS over VLESS Mux** path by itself.

### Next milestone

**Stage 8E5 — API compatibility closure** (legacy `v2ray.core.*` aliases, exact `api.tag` / `services` semantics, Remna unix-abstract E2E).

See [compatibility-status.md](docs/compatibility-status.md) for remaining Mux/UDP gaps.

## Live smoke (Xray-core client matrix)

From repo root:

```bash
make live-smoke
# or: bash scripts/live_reality_smoke/run-live-smoke.sh
```

Validated scenarios include:

- `flow=""` and `flow="xtls-rprx-vision"` against Xray-core client
- Vision DIRECT relay, 100 sequential / 50 parallel requests, 100MB download
- `network: "raw"` and legacy `network: "tcp"`
- HTTP/1.1 and HTTP/2 curl modes, TLS 1.2 and 1.3 client modes
- VLESS custom string user ID end-to-end
- Fallback matrix (default, SNI/name, HTTP path, ALPN, PROXY v1/v2)
- Cipher suite smoke (AES128 / AES256 / ChaCha20)
- ML-DSA-65 baseline (4/4 checks when enabled in fixture)
- Happ baseline: REALITY/Vision/Mux + UDP DNS `1.1.1.1:53` (`PASS happ reality vision mux udp dns`, `PASS vless mux udp dns 1.1.1.1:53`)
- Transport rejection checks (`grpc`, `ws` + REALITY rejected at startup; `xhttp` / `splithttp` accepted for experimental XHTTP)

Details: **[scripts/live_reality_smoke/README.md](scripts/live_reality_smoke/README.md)**,
**[scripts/live_xhttp_smoke/README.md](scripts/live_xhttp_smoke/README.md)**,
**[docs/compatibility-status.md](docs/compatibility-status.md)**.

### Remaining gaps (see compatibility doc)

- Full Mux.Cool runtime; generic UDP over Mux; domain `:53` mux resolver; XUDP
- VLESS `command=Udp` (non-Mux); unsupported outbound proxy protocols
- XHTTP `packet-down` / XMUX; Vision over XHTTP; XUDP over XHTTP
- REALITY over gRPC / WebSocket runtime (rejected at startup)
- ML-KEM (ML-DSA-65 baseline is experimental — see docs)
- Vision splice / zero-copy beyond DIRECT MVP
- DNS-over-TCP through VLESS outbound/routing (separate future task)
- TLS 1.3 CCM cipher suites (0x1304, 0x1305)

Developer documentation: **[docs/reality-accepted-path.md](docs/reality-accepted-path.md)** (handshake internals; see compatibility doc for runtime status).

## TLS 1.3 cipher suite matrix (REALITY accepted path)

| Suite | IANA | Record crypto | Key schedule |
|-------|------|---------------|--------------|
| TLS_AES_128_GCM_SHA256 | 0x1301 | Supported | SHA-256 |
| TLS_AES_256_GCM_SHA384 | 0x1302 | Supported | SHA-384 |
| TLS_CHACHA20_POLY1305_SHA256 | 0x1303 | Supported | SHA-256 |
| TLS_AES_128_CCM_SHA256 | 0x1304 | Rejected (`Unsupported`) | — |
| TLS_AES_128_CCM_8_SHA256 | 0x1305 | Rejected (`Unsupported`) | — |

Live smoke forces each supported suite via local mock TLS 1.3 dest targets
(`scripts/live_reality_smoke/cipher-tls-servers.py`).

## Policy validation matrix

| Check | When | Pass | Fail |
|-------|------|------|------|
| SNI present | Before crypto | Continue | `Fallback` |
| SNI in `serverNames` | Before crypto | Continue | `Fallback` |
| `serverNames` non-empty | Before crypto | Continue | `Fallback` |
| X25519 (standalone or hybrid carrier) + HKDF | Crypto | Continue | `Fallback` |
| AEAD `session_id` open | Crypto | `Opened` | `Fallback` |
| `shortId` prefix match | After AEAD | Continue | `Fallback` |
| `minClientVer` | After AEAD | Continue | `Fallback` |
| `maxClientVer` | After AEAD | Continue | `Fallback` |
| Invalid version string (explicit config) | Config load | — | `Err(InvalidInput)` at startup |
| Invalid version string (runtime inspect) | After AEAD | — | `Err(InvalidInput)` |
| `maxTimeDiff` window | After AEAD | `Accepted` | `Fallback` |
| All checks pass | After AEAD | `Accepted` | — |

### REALITY server `minClientVer` (Xray-core compatibility)

rust-xray follows [Xray-core af7eb68](https://github.com/XTLS/Xray-core/commit/af7eb68028732a8ee3c0e5d6ab2b8a657bb2e770) server-side default behavior:

| Config value | Effective runtime `minClientVer` |
|--------------|----------------------------------|
| field omitted | `26.3.27` |
| `"minClientVer": ""` | `26.3.27` |
| explicit non-empty string (e.g. `"1.8.0"`, `"0.0.0"`) | used as-is |

`maxClientVer` has **no** server default: omitted or `""` means no upper bound; explicit values are preserved. Explicit non-empty `minClientVer` / `maxClientVer` strings are validated at config startup via `parse_reality_client_version`.

This matches Xray-core config normalization; it does **not** guarantee compatibility with every third-party REALITY client. Clients advertising a version below the effective minimum receive REALITY **fallback** (same as other pre-auth policy failures).

Constants and normalization: `DEFAULT_REALITY_MIN_CLIENT_VER` and `effective_reality_min_client_ver()` in `src/config/xray/reality.rs`. Regression: `tests/upstream_compat_vectors.rs`.

Secrets (`privateKey`, `auth_key`, ECDHE shared secrets, traffic secrets, plaintext
`session_id`, private signing keys) are **not logged** in production paths. Debug
logs may include `client_version`, `unix_time`, and shortId **prefix length** only.

## Requirements

- Rust stable
- Cargo
- An available TCP address for the configured `listen:port`

## Build, Tests, And Live Smoke

```bash
cargo fmt
cargo build
cargo test
cargo clippy --all-targets
make live-smoke
```

With `make` installed:

```bash
make test          # cargo test
make build         # cargo build
make live-smoke    # Xray-core compatibility/stress suite
make fixture-test  # REALITY fixture integration test
make fixture-decode       # decode tests/fixtures/reality/basic-xray
make fixture-decode-write # decode + write expected_* (--force)
make capture-clienthello  # TCP captor → /tmp/client_hello.bin
```

Fixture capture details: **[tests/fixtures/reality/README.md](tests/fixtures/reality/README.md)**.
Semi-automated setup (requires exported keys): `bash scripts/create_reality_fixture.sh`.

Manual REALITY accepted-path smoke test (local Xray client + `rust-xray` server):
**[scripts/live_reality_smoke/README.md](scripts/live_reality_smoke/README.md)** —
test-only keys, not for production. Automated runner: `make live-smoke`.

Release build:

```bash
cargo build --release
```

## Configuration

By default, the binary reads `./config.json`. You can pass a config path as the
first argument:

```bash
cargo run --bin rust-xray -- ./config.json
```

Minimal example:

```json
{
  "inbounds": [
    {
      "tag": "reality-in",
      "listen": "0.0.0.0",
      "port": 443,
      "protocol": "vless",
      "settings": {
        "clients": [
          {
            "id": "00000000-0000-0000-0000-000000000001"
          }
        ],
        "decryption": "none"
      },
      "streamSettings": {
        "network": "tcp",
        "security": "reality",
        "realitySettings": {
          "show": false,
          "dest": "www.example.com:443",
          "serverNames": ["www.example.com"],
          "privateKey": "REPLACE_WITH_BASE64URL_REALITY_PRIVATE_KEY",
          "shortIds": ["", "0123456789abcdef"],
          "maxTimeDiff": 60000,
          "maxClientVer": "24.9.30"
        }
      }
    }
  ],
  "outbounds": [
    {
      "protocol": "freedom"
    }
  ]
}
```

Omit `minClientVer` to use the Xray-core server default (`26.3.27`); an empty
string (`""`) is treated the same way. Set an explicit value (including
`"0.0.0"`) to override the default. This mirrors Xray-core config behavior and
does not imply compatibility with every third-party REALITY client.

## Running

```bash
cargo run --bin rust-xray -- ./config.json
make live-smoke
```

With logging (default: `error` on stdout when `RUST_LOG` is unset):

```bash
RUST_LOG=info cargo run --bin rust-xray -- ./config.json
RUST_LOG=rust_xray=debug cargo run --bin rust-xray -- ./config.json
```

See **[docs/logging.md](docs/logging.md)** for performance-oriented log levels (`warn` / `info` / `trace`) and buffered logging env vars.

For reproducible latency comparison with Go Xray-core, see **[docs/latency-measurement.md](docs/latency-measurement.md)** and `scripts/latency/measure-latency.sh`.

### Decision flow

1. Load config, bind on `listen:port`.
2. Read TLS `ClientHello` (supports TCP fragmentation and multi-record assembly).
3. SNI check → else **Fallback**.
4. X25519 + HKDF + AES-GCM open `session_id` → else **Fallback**.
5. Policy validation → else **Fallback**.
6. **Accepted** → TLS 1.3 handshake → VLESS → freedom relay (**no fallback**).
7. **Fallback** → TCP relay to `dest`/`target`.

## Troubleshooting

| Symptom / log | Possible cause |
|---------------|----------------|
| `REALITY fallback: SNI missing` | Client without SNI |
| `REALITY session_id auth failed` | Invalid REALITY ciphertext / key |
| `REALITY accepted client` | Pre-auth passed; accepted path started |
| `REALITY TLS 1.3 handshake complete` | Handshake finished in code |
| `REALITY VLESS handler started` | VLESS read/auth starting |
| `unknown vless client id` | VLESS auth failed |
| `unsupported vless command` | VLESS `command=Udp` (non-Mux) not implemented |
| `mux udp dns query forwarded` | Mux UDP DNS query relay started (Happ baseline, numeric `:53`; **debug** level) |
| `unsupported non-DNS UDP mux substream` | Generic UDP over Mux not implemented (non-`:53` ports) |
| `REALITY accepted path failed` | Handshake/VLESS error (no fallback) |

## Project Layout

```
src/
├── main.rs
├── config/
├── tls/
├── protocol/
├── reality/
│   ├── auth.rs, session.rs, decision.rs, sni.rs, version.rs
│   ├── certificate.rs     # REALITY cert HMAC patch
│   ├── handshake.rs, server.rs
│   └── tls13/             # handshake, stream, record crypto
├── vless/
├── outbound/freedom.rs
└── proxy/
docs/reality-accepted-path.md
```

## Limitations

- **Not an Xray-core replacement** and **not production-ready** (experiment branch).
- Accepted path errors do not fallback (see policy matrix above for pre-auth fallback cases).
- Vision DIRECT MVP only — no full splice/zero-copy beyond padding + DIRECT relay.
- VLESS Mux: experimental Happ baseline (Vision + Mux + numeric UDP DNS `:53`); full Mux.Cool / generic UDP / XUDP not implemented.
- VLESS `command=Udp` / XUDP; XHTTP `packet-down` / XMUX; Vision over XHTTP; REALITY over gRPC/WebSocket (rejected at startup); unsupported outbound proxy protocols beyond freedom/blackhole.
- ML-DSA-65 cert signing: experimental baseline when `mldsa65Seed` is set; **ML-KEM-768 crypto and hybrid TLS negotiation not implemented** (Stage 2: pre-auth hybrid `key_share` carrier parsing only)
- REALITY post-handshake probes use **rustls** ClientHello (not uTLS); fingerprint parity is **partial** for Stage 5B record-length and Stage 5C extra-CCS tolerance probing — see [reality-accepted-path.md](docs/reality-accepted-path.md#stage-5-post-handshake-record-mirroring)
- TLS 1.3 CCM cipher suites (0x1304, 0x1305) rejected on accepted path.

Full matrix: **[docs/compatibility-status.md](docs/compatibility-status.md)**.
