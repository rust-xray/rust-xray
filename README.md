# rust-xray

Экспериментальная реализация части Xray/VLESS REALITY на Rust.

Проект поднимает TCP-listener по `inbound` из Xray-совместимого `config.json`,
читает первый TLS `ClientHello`, проверяет REALITY-кандидата (AEAD + policy)
и либо проксирует обычный/невалидный трафик на fallback-адрес из
`realitySettings.dest` / `realitySettings.target`, либо попадает в accepted path
для валидного REALITY-клиента.

**Non-REALITY clients are relayed to `dest`.**

**This is not a drop-in replacement for Xray-core.** Do not treat this project
as a production Xray replacement. It is **not production-ready**.

**Compatibility status (authoritative):** **[docs/compatibility-status.md](docs/compatibility-status.md)**

## Compatibility Status (summary)

See **[docs/compatibility-status.md](docs/compatibility-status.md)** for the full
matrix. Short version:

### Working

- REALITY TCP/raw inbound, pre-auth (SNI, AEAD, policy), and **accepted** TLS 1.3 path
- VLESS TCP inbound: UUID auth, custom string ID → UUIDv5, `flow=""` and `xtls-rprx-vision` (Vision DIRECT MVP)
- REALITY accepted-path cipher suites: AES128-GCM, AES256-GCM, ChaCha20-Poly1305
- VLESS fallback: default, SNI/name, HTTP path, ALPN (`http/1.1`, `h2`), PROXY v1/v2 (`xver=1|2`)
- Network aliases: `raw` and legacy `tcp`
- Basic Remnawave/Xray gRPC API: `StatsService` (`QueryStats`, `GetStats`, `GetSysStats`) when `api` block is present

Accepted path **does not fallback** on failure — handshake/VLESS errors close the
connection.

### Experimental

- **VLESS Mux (Happ baseline):** REALITY → TLS 1.3 → VLESS auth → `command=Mux` → mux session start (live smoke validated)
- **UDP DNS over VLESS Mux (port 53):** numeric `:53` targets (e.g. `1.1.1.1:53`) — query forwarded, response received, mux UDP response frame sent
- **Happ Proxy Utility baseline:** REALITY/VLESS/Vision/Mux path with numeric UDP DNS on port 53 works (experimental)
- **ML-DSA-65 baseline (experimental):** valid `mldsa65Seed` accepted, invalid seed rejected at startup, live smoke passes ([details](docs/reality-mldsa65-runtime-baseline.md))

### Partial

- Mux.Cool frame parser and single TCP substream (no parallel substreams)
- Mux UDP DNS for **domain** `:53` targets (resolver hook not wired)
- Remnawave-style configs: load + REALITY inbound + API; routing/rules/balancers not executed

### Not yet implemented

- Full Mux.Cool runtime, generic UDP over Mux (non-`:53`), XUDP
- VLESS `command=Udp` (non-Mux)
- REALITY over XHTTP / gRPC / WebSocket transport runtime
- **ML-KEM** hybrid KEM (separate from ML-DSA-65; not implemented)
- Full routing, balancers, outbound ecosystem, DoH, Vision splice/zero-copy beyond DIRECT MVP
- DNS-over-TCP through VLESS outbound/routing (separate future task)
- Full Xray-core drop-in compatibility

**DNS note:** DNS-over-TCP via a future DNS/outbound module does **not** replace
Happ's current **UDP DNS over VLESS Mux** path by itself.

### Next milestone

Domain `:53` mux destinations, generic UDP over Mux, full Mux.Cool runtime — see
[compatibility-status.md](docs/compatibility-status.md).

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
- Negative transport configs (`xhttp`, `grpc`, `ws` + REALITY rejected at startup)

Details: **[scripts/live_reality_smoke/README.md](scripts/live_reality_smoke/README.md)**,
**[docs/compatibility-status.md](docs/compatibility-status.md)**.

### Remaining gaps (see compatibility doc)

- Full Mux.Cool runtime; generic UDP over Mux; domain `:53` mux resolver; XUDP
- VLESS `command=Udp` (non-Mux); full routing/outbounds
- REALITY over XHTTP / gRPC / WebSocket runtime
- ML-KEM (ML-DSA-65 baseline is experimental — see docs)
- Vision splice / zero-copy beyond DIRECT MVP
- DNS-over-TCP through VLESS outbound/routing (separate future task)
- Fallback rate limits (`limitFallbackUpload` / `limitFallbackDownload`)
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
| X25519 + HKDF | Crypto | Continue | `Fallback` |
| AEAD `session_id` open | Crypto | `Opened` | `Fallback` |
| `shortId` prefix match | After AEAD | Continue | `Fallback` |
| `minClientVer` | After AEAD | Continue | `Fallback` |
| `maxClientVer` | After AEAD | Continue | `Fallback` |
| Invalid version string | After AEAD | — | `Err(InvalidInput)` |
| `maxTimeDiff` window | After AEAD | `Accepted` | `Fallback` |
| All checks pass | After AEAD | `Accepted` | — |

Secrets (`privateKey`, `auth_key`, ECDHE shared secrets, traffic secrets, plaintext
`session_id`, private signing keys) are **not logged** in production paths. Debug
logs may include `client_version`, `unix_time`, and shortId **prefix length** only.

## Требования

- Rust stable
- Cargo
- Доступный TCP-адрес для `listen:port` из конфигурации

## Сборка, тесты и live smoke

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

Release-сборка:

```bash
cargo build --release
```

## Конфигурация

По умолчанию бинарник читает `./config.json`. Путь можно передать первым
аргументом:

```bash
cargo run --bin rust-xray -- ./config.json
```

Минимальный пример:

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
          "minClientVer": "1.8.0",
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

## Запуск

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

| Симптом / лог | Возможная причина |
|---------------|-------------------|
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

## Структура проекта

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

## Ограничения

- **Not an Xray-core replacement** and **not production-ready** (experiment branch).
- Accepted path errors do not fallback (see policy matrix above for pre-auth fallback cases).
- Vision DIRECT MVP only — no full splice/zero-copy beyond padding + DIRECT relay.
- VLESS Mux: experimental Happ baseline (Vision + Mux + numeric UDP DNS `:53`); full Mux.Cool / generic UDP / XUDP not implemented.
- VLESS `command=Udp` / XUDP; REALITY over XHTTP/gRPC/WebSocket; full routing/outbounds not implemented.
- ML-DSA-65 cert signing: experimental baseline when `mldsa65Seed` is set; **ML-KEM not implemented**.
- TLS 1.3 CCM cipher suites (0x1304, 0x1305) rejected on accepted path.

Full matrix: **[docs/compatibility-status.md](docs/compatibility-status.md)**.
