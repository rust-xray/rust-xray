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

Last checked: unit tests + build green; **clippy** may still report warnings
(see build status below).

| Area | Status |
|------|--------|
| REALITY pre-auth (AEAD, policy, SNI) | **Implemented + unit tested** |
| TLS 1.3 accepted handshake (code path) | **Implemented + unit tested** (no live Xray client e2e) |
| Application stream adapter | **Implemented** (`AsyncRead` / `AsyncWrite`) |
| VLESS handoff on accepted path | **Wired in code** (not interoperability-validated) |
| REALITY cert HMAC patching | **Unsupported** — unpatch rcgen cert is sent today |
| Vision (`xtls-rprx-vision`) | **Unsupported behavior** — flow metadata accepted only |
| Xray-core compatibility | **Not validated** |

Accepted path **does not fallback** on failure — errors close the connection.

## Protocol coverage matrix

| Component | Coverage | Tests | Accepted-path gate |
|-----------|----------|-------|-------------------|
| TLS ClientHello (1st record) | Parse + read | Unit | N/A (pre-auth) |
| REALITY X25519 auth | HKDF → 32-byte auth key | Unit | Fallback if fail |
| AEAD `session_id` decrypt | AES-256-GCM | Unit | Fallback if fail |
| shortId / time / version / SNI | Policy matrix | Unit | Fallback if fail |
| Dest ServerHello observe | TLS 1.3 + X25519 | Unit | Error (no fallback) |
| ServerHello generation | rcgen camouflage random | Unit | Runs |
| Transcript hash | SHA-256 / SHA-384 | Unit | Runs |
| Handshake traffic secrets | HKDF labels | Unit | Runs |
| Encrypted EE/Cert/CV/Finished | AES-GCM records | Unit | Runs (ChaCha → `Unsupported`) |
| Certificate | Ed25519 ephemeral (rcgen) | Unit | Runs **without** REALITY patch |
| CertificateVerify | Ed25519 | Unit | Runs |
| Server Finished | HMAC verify_data | Unit | Runs |
| Client Finished verify | Decrypt + constant-time compare | Unit | Error if fail |
| Application secrets | master + traffic labels | Unit | Runs |
| App record encrypt/decrypt | AES-128/256-GCM | Unit | Runs |
| Application stream adapter | `RealityTls13ApplicationStream` | Unit | Runs |
| VLESS config users | JSON → `VlessClient` | Unit | Runs |
| VLESS UUID auth | PermissionDenied | Unit | Error |
| VLESS request parser | Header + initial payload | Unit | Runs |
| VLESS TCP command | Freedom connect + relay | Unit (mock) | Runs |
| VLESS UDP / Mux | — | Unit | `Unsupported` |
| REALITY cert DER patch | API stub | Unit | **Not gated** (gap) |
| Vision framing | — | — | **Not gated** (gap) |
| mldsa65 / ML-KEM | — | — | Not implemented |
| Fragmented ClientHello | — | — | Rejected / not supported |
| Routing / balancers | — | — | Not implemented |

## What works today

### REALITY pre-auth (production-shaped for invalid clients)

- X25519 keyshare extraction, HKDF-SHA256 → 32-byte auth key
- AES-256-GCM `session_id` open (nonce = `random[20..32]`, zeroed AAD)
- Policy: `shortId` prefix, `maxTimeDiff`, `minClientVer` / `maxClientVer`, SNI whitelist
- Fallback TCP relay to `dest` for non-REALITY / failed auth

### Accepted path (experimental, not Xray-interoperable)

1. Connect `dest`, forward ClientHello, observe destination ServerHello
2. `complete_reality_tls13_handshake` — full server-side TLS 1.3 state machine
3. `RealityTls13ApplicationStream` — decrypt client / encrypt server ApplicationData
4. `handle_vless_tcp_inbound` — VLESS parse/auth → freedom TCP relay

Code + unit tests exist; **no confirmed end-to-end pass against Xray-core client**.

## Experimental / incomplete

- REALITY → TLS 1.3 → VLESS pipeline wired in `handle_accepted_reality_client`
- Ephemeral Ed25519 certificate (rcgen scaffold, **no upstream HMAC patch**)
- `xtls-rprx-vision` accepted as client metadata but **Vision not implemented**
- ChaCha20-Poly1305 cipher suite → `Unsupported` at record crypto
- One TLS record per `AsyncWrite` on application stream (skeleton buffering)

## Explicitly Unsupported

| Feature | Behavior |
|---------|----------|
| REALITY cert DER HMAC patch | `patch_reality_certificate_der` → `Unsupported`; **not called** on live path |
| mldsa65 cert extension | `Unsupported` in patch API |
| ChaCha20-Poly1305 TLS 1.3 records | `Unsupported` |
| VLESS UDP / Mux commands | `Unsupported` |
| Vision (`xtls-rprx-vision`) behavior | Not implemented (metadata-only today) |
| Routing / rules / balancers | Not implemented |
| Fragmented ClientHello | Not supported |
| Fallback rate limits | Not implemented |

## Remaining blockers (before calling this “done”)

1. **REALITY cert patching not gated** — accepted path sends unpatch rcgen cert instead of returning `Unsupported`.
2. **Vision not gated** — clients with `flow: xtls-rprx-vision` are accepted at VLESS auth layer without Vision framing.
3. **No Xray interoperability test** — full accepted path not validated against real Xray REALITY client.
4. **ChaCha20 destinations** — dest ServerHello may select suite that fails at record crypto.
5. **Clippy warnings** — non-fatal style/dead-code warnings remain in lib.

## Final TODO

- [ ] **mldsa65** — seed handling + cert extension location (upstream REALITY)
- [ ] **X25519MLKEM768** — post-quantum key exchange / REALITY extensions
- [ ] **Vision exact behavior** — `xtls-rprx-vision` framing on application stream; gate or implement
- [ ] **REALITY cert patch** — port signedCert offset, HMAC-SHA512, gate accepted path until verified
- [ ] **UDP / Mux** — VLESS command support
- [ ] **Routing** — outbound selection, rules, balancers
- [ ] **Fragmented ClientHello** — buffer across TLS records
- [ ] **Real Xray fixture tests** — accepted-path e2e against captured/live Xray client
- [ ] **Fuzzing** — TLS record parser, ClientHello, VLESS header parsers
- [ ] **Interoperability test** — rust-xray server vs Xray REALITY client (TCP + VLESS)

Developer documentation: **[docs/reality-accepted-path.md](docs/reality-accepted-path.md)**.

## Реализовано (summary)

### REALITY inbound

- REALITY ClientHello auth, AEAD, policy validation (see matrix above)
- Xray-compatible config parsing (`RealityInboundRuntime`, VLESS clients)
- TLS ClientHello first-record parsing
- Fallback relay to `dest`/`target`

### TLS 1.3 (`src/reality/tls13/`)

- Transcript, key schedule, cipher suites, message builders
- `complete_reality_tls13_handshake`, `RealityTls13ApplicationStream`
- Ed25519 Certificate / CertificateVerify scaffold (`tls13/certificate.rs`)
- REALITY-specific cert patch API isolated in `src/reality/certificate.rs` (stub)

### VLESS

- Config users, request parser, UUID auth, TCP inbound + freedom outbound relay

### Tests

289+ unit tests: config, TLS, REALITY auth/policy, TLS 1.3 primitives, VLESS,
freedom outbound, cert patch stub, stream adapter. REALITY fixture interop test (`basic-xray`).

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

Release-сборка:

```bash
cargo build --release
```

## Конфигурация

По умолчанию бинарник читает `./config.json`. Путь можно передать первым
аргументом:

```bash
cargo run -- ./config.json
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
RUST_LOG=info cargo run -- ./config.json
```

### Decision flow

1. Load config, bind on `listen:port`.
2. Read first TLS `ClientHello` record.
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
- First TLS record must contain a complete ClientHello.
- Accepted path errors do not fallback.
- Vision, cert patching, mldsa65, UDP/Mux, routing not production-ready.
