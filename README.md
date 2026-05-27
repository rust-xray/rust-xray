# rust-xray

Экспериментальная реализация части Xray/VLESS REALITY на Rust.

Проект поднимает TCP-listener по `inbound` из Xray-совместимого `config.json`,
читает первый TLS `ClientHello`, проверяет REALITY-кандидата (AEAD + policy)
и либо проксирует обычный/невалидный трафик на fallback-адрес из
`realitySettings.dest` / `realitySettings.target`, либо попадает в accepted path
для валидного REALITY-клиента.

**Non-REALITY clients are relayed to `dest`.**

**This is not a drop-in replacement for Xray-core.** Do not treat this project
as a production Xray replacement.

## Audit status (experiment branch)

Last checked: unit tests + build green against **Xray-core 26.3.27** live smoke
(`flow=""`, `flow="xtls-rprx-vision"`, 10MB download, bad shortId/SNI fallback).

| Area | Status |
|------|--------|
| REALITY pre-auth (AEAD, policy, SNI) | **Implemented + unit tested** |
| TLS 1.3 accepted handshake | **Implemented + unit tested** |
| Application stream adapter | **Implemented** (`AsyncRead` / `AsyncWrite`) |
| VLESS handoff on accepted path | **Wired + live smoke validated** |
| REALITY cert HMAC patching | **Implemented** (Ed25519 DER patch on accepted path) |
| Vision (`xtls-rprx-vision`) | **DIRECT MVP** — padding framing + `COMMAND_DIRECT` relay |
| Xray-core compatibility | **Validated** (26.3.27 REALITY client smoke) |

Accepted path **does not fallback** on failure — errors close the connection.

## Protocol coverage matrix

| Component | Coverage | Tests | Accepted-path gate |
|-----------|----------|-------|-------------------|
| TLS ClientHello (fragmented / multi-record) | Parse + read | Unit | N/A (pre-auth) |
| REALITY X25519 auth | HKDF → 32-byte auth key | Unit | Fallback if fail |
| AEAD `session_id` decrypt | AES-256-GCM | Unit | Fallback if fail |
| shortId / time / version / SNI | Policy matrix | Unit | Fallback if fail |
| Dest ServerHello observe | TLS 1.3 + X25519 | Unit | Error (no fallback) |
| ServerHello generation | rcgen camouflage random | Unit | Runs |
| Transcript hash | SHA-256 / SHA-384 | Unit | Runs |
| Handshake traffic secrets | HKDF labels | Unit | Runs |
| Encrypted EE/Cert/CV/Finished | AES-GCM records | Unit | Runs (ChaCha → `Unsupported`) |
| Certificate | Ed25519 ephemeral + REALITY patch | Unit + smoke | Runs |
| CertificateVerify | Ed25519 | Unit | Runs |
| Server Finished | HMAC verify_data | Unit | Runs |
| Client Finished verify | Decrypt + constant-time compare | Unit | Error if fail |
| Application secrets | master + traffic labels | Unit | Runs |
| App record encrypt/decrypt | AES-128/256-GCM | Unit | Runs |
| Application stream adapter | `RealityTls13ApplicationStream` | Unit | Runs |
| VLESS config users | JSON → `VlessClient` | Unit | Runs |
| VLESS UUID auth | PermissionDenied | Unit | Error |
| VLESS request parser | Header + initial payload | Unit | Runs |
| VLESS TCP command | Freedom connect + relay | Unit (mock) + smoke | Runs |
| VLESS flow validation | `""` vs `xtls-rprx-vision` | Unit | Error if mismatch |
| VLESS UDP / Mux | — | Unit | `Unsupported` |
| Vision framing | Padding + DIRECT relay | Unit + smoke | Runs for vision accounts |
| REALITY cert DER patch | HMAC-SHA512 | Unit | Runs on accepted path |
| mldsa65 / ML-KEM | — | — | Not implemented |
| Routing / balancers | — | — | Not implemented |

## What works today

### REALITY pre-auth (production-shaped for invalid clients)

- X25519 keyshare extraction, HKDF-SHA256 → 32-byte auth key
- AES-256-GCM `session_id` open (nonce = `random[20..32]`, zeroed AAD)
- Policy: `shortId` prefix, `maxTimeDiff`, `minClientVer` / `maxClientVer`, SNI whitelist
- Fallback TCP relay to `dest` for non-REALITY / failed auth

### Accepted path (Xray-interoperable MVP)

1. Connect `dest`, forward ClientHello, observe destination ServerHello
2. `complete_reality_tls13_handshake` — full server-side TLS 1.3 state machine
3. `RealityTls13ApplicationStream` — decrypt client / encrypt server ApplicationData
4. `handle_vless_tcp_inbound` — VLESS parse/auth → freedom TCP relay
5. Vision (`xtls-rprx-vision`) — padding framing + DIRECT copy relay after server signal

Live smoke validated against **Xray-core 26.3.27** (`scripts/live_reality_smoke/`).

## Experimental / incomplete

- ChaCha20-Poly1305 cipher suite → `Unsupported` at record crypto
- One TLS record per `AsyncWrite` on application stream (skeleton buffering)
- Vision splice/zero-copy beyond DIRECT MVP not implemented
- UDP / Mux / XUDP, xhttp, grpc transports not implemented

## Explicitly Unsupported

| Feature | Behavior |
|---------|----------|
| mldsa65 cert extension | `Unsupported` |
| ChaCha20-Poly1305 TLS 1.3 records | `Unsupported` |
| VLESS UDP / Mux / XUDP commands | `Unsupported` |
| xhttp / grpc stream transports | Not implemented |
| Routing / rules / balancers | Not implemented |
| Fallback rate limits | Not implemented |
| Vision splice (raw TLS bypass beyond DIRECT MVP) | Not implemented |

## Remaining blockers (before calling this “production-ready”)

1. **ChaCha20 destinations** — dest ServerHello may select suite that fails at record crypto.
2. **Post-quantum REALITY** — mldsa65 / ML-KEM extensions not implemented.
3. **UDP / Mux / XUDP** — VLESS command support missing.
4. **Alternate transports** — xhttp, grpc not implemented.
5. **Routing** — outbound selection, rules, balancers not implemented.

## Final TODO

- [ ] **mldsa65** — seed handling + cert extension location (upstream REALITY)
- [ ] **X25519MLKEM768** — post-quantum key exchange / REALITY extensions
- [ ] **Vision splice** — full zero-copy path beyond DIRECT MVP
- [ ] **UDP / Mux / XUDP** — VLESS command support
- [ ] **xhttp / grpc** — alternate stream transports
- [ ] **Routing** — outbound selection, rules, balancers
- [ ] **Real Xray fixture tests** — broader accepted-path e2e matrix
- [ ] **Fuzzing** — TLS record parser, ClientHello, VLESS header parsers

Developer documentation: **[docs/reality-accepted-path.md](docs/reality-accepted-path.md)**.

## Реализовано (summary)

### REALITY inbound

- REALITY ClientHello auth, AEAD, policy validation (see matrix above)
- Xray-compatible config parsing (`RealityInboundRuntime`, VLESS clients)
- TLS ClientHello parsing (TCP fragmentation, multi-record, coalesced trailing bytes)
- Fallback relay to `dest`/`target`

### TLS 1.3 (`src/reality/tls13/`)

- Transcript, key schedule, cipher suites, message builders
- `complete_reality_tls13_handshake`, `RealityTls13ApplicationStream`
- Ed25519 Certificate / CertificateVerify scaffold (`tls13/certificate.rs`)
- REALITY-specific cert patch in `src/reality/certificate.rs` (HMAC-SHA512 on accepted path)

### VLESS

- Config users, request parser, UUID auth, flow validation, TCP inbound + freedom outbound relay
- Vision DIRECT MVP (`src/vless/vision.rs`)

### Tests

420+ unit tests: config, TLS, REALITY auth/policy, TLS 1.3 primitives, VLESS, Vision,
freedom outbound, cert patch, stream adapter. REALITY fixture interop test (`basic-xray`).
Live smoke: Xray-core 26.3.27 (`scripts/live_reality_smoke/`).

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

## Сборка и тесты

```bash
cargo fmt
cargo build
cargo test
cargo clippy --all-targets
```

With `make` installed, the same workflow is available as Makefile targets:

```bash
make test          # cargo test
make build         # cargo build
make fixture-test  # REALITY fixture integration test
make fixture-decode       # decode tests/fixtures/reality/basic-xray
make fixture-decode-write # decode + write expected_* (--force)
make capture-clienthello  # TCP captor → /tmp/client_hello.bin
```

Fixture capture details: **[tests/fixtures/reality/README.md](tests/fixtures/reality/README.md)**.
Semi-automated setup (requires exported keys): `bash scripts/create_reality_fixture.sh`.

Manual REALITY accepted-path smoke test (local Xray client + `rust-xray` server):
**[scripts/live_reality_smoke/README.md](scripts/live_reality_smoke/README.md)** —
test-only keys, not for production.

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
RUST_LOG=info cargo run --bin rust-xray -- ./config.json
```

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
| `unsupported vless command` | UDP/Mux |
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
│   ├── certificate.rs     # REALITY cert patch API (stub)
│   ├── handshake.rs, server.rs
│   └── tls13/             # handshake, stream, record crypto
├── vless/
├── outbound/freedom.rs
└── proxy/
docs/reality-accepted-path.md
```

## Ограничения

- **Not an Xray-core replacement.**
- Accepted path errors do not fallback (see policy matrix above for pre-auth fallback cases).
- Vision DIRECT MVP only — no full splice/zero-copy beyond padding + DIRECT relay.
- UDP / Mux / XUDP, xhttp, grpc, mldsa65 / ML-KEM, routing not implemented.
- ChaCha20-Poly1305 record crypto unsupported when dest selects that suite.
