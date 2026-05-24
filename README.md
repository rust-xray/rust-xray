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

**Valid REALITY clients can now reach dest ServerHello observation** (connect to
`dest`, forward the client TLS record, parse and validate the destination TLS 1.3
ServerHello shape), **but the accepted path still returns `Unsupported`**. This
is expected until the REALITY TLS 1.3 server state machine is implemented.

VLESS parser/auth/outbound skeleton exists in the library, but **is not reachable
from a completed REALITY TLS stream** — there is no encrypted application stream
or VLESS handoff yet.

Developer documentation for the upstream accepted-path model and why a naive
ServerHello patch is insufficient:
**[docs/reality-accepted-path.md](docs/reality-accepted-path.md)**.

## Реализовано

### REALITY inbound

- **REALITY ClientHello auth** — X25519 keyshare extraction, HKDF-SHA256 auth key
  derivation.
- **AEAD `session_id` decrypt** — AES-256-GCM open, nonce = `random[20..32]`,
  AAD with zeroed `session_id`.
- **Policy validation**
  - `shortId` prefix match against `shortIds` (0..8 bytes; empty configured
    shortId = prefix length 0)
  - `maxTimeDiff` — `unix_time` from plaintext vs wall clock; `0` disables check
  - `minClientVer` / `maxClientVer` — optional; invalid version string →
    `InvalidInput` (not silent fallback)
  - `serverNames` / SNI — early check before crypto (exact match,
    case-insensitive)
- **Xray-compatible REALITY config parsing** — `RealityInboundRuntime`, typed
  VLESS inbound settings (`VlessClientObject`), listen/dest/keys/shortIds/policy
  fields.
- **TLS ClientHello parsing** — first TLS record.
- **Fallback relay** — TCP relay to `dest`/`target` for ordinary and invalid
  clients.
- **Accepted path + dest ServerHello observation**
  - `handle_accepted_reality_client` connects to `dest`, forwards
    `record.raw_record`, reads dest handshake bytes
  - TLS record parser (`src/tls/records.rs`) for multi-record observation
  - TLS 1.3 ServerHello parser (`src/tls/server_hello.rs`)
  - dest ServerHello validation: TLS 1.3 + X25519 `key_share`
    (`extract_observed_server_hello`, `patch_reality_server_hello`)
  - TLS 1.3 server state machine **skeleton only**
    (`src/reality/tls13/` — not wired to live path)

### VLESS (library skeleton, not on accepted path yet)

- **VLESS config users parsing** — `VlessInboundSettings`, `VlessClientObject`,
  `build_vless_clients()` at startup.
- **VLESS request parser** — `parse_vless_request()`, `read_vless_request()` with
  `initial_payload` preservation.
- **VLESS UUID auth** — `authenticate_vless_client()`, flow metadata check
  (`None`, `""`, `xtls-rprx-vision` allowed as metadata only).
- **Minimal freedom TCP outbound skeleton** — `connect_tcp_destination()`,
  `relay_tcp()`; `handle_vless_tcp_inbound()` pipeline (parse → auth → connect →
  relay) exists but is **not called** after REALITY accept.

### Tests

Unit tests for config, TLS records, ServerHello parser, AEAD, policy, SNI,
decision flow, dest handshake observation/validation, VLESS parser/auth, freedom
outbound helpers, TLS 1.3 skeleton, runtime config loading with VLESS clients.

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

`Accepted` contains `RealityAuthResult`, `RealityClientAuth`, `sni: Some(String)`.

Secrets (`privateKey`, `auth_key`, shared secret, plaintext `session_id`) are
not logged.

## Не реализовано

- **REALITY TLS 1.3 server handshake** — `src/reality/tls13/` is a placeholder
  skeleton only.
- **Real ServerHello generation / patching** — no client-facing ServerHello is
  generated; dest bytes are observed, not relayed as a fake handshake.
- **Certificate / CertificateVerify / Finished** — server handshake messages
  after ServerHello.
- **Client Finished validation** — `readClientFinished` equivalent.
- **Encrypted application stream** — post-handshake TLS record encrypt/decrypt
  wrapper.
- **VLESS handoff from completed REALITY TLS stream** — `handle_vless_tcp_inbound`
  is not reachable after REALITY accept.
- **Vision** — flow metadata accepted, `xtls-rprx-vision` behavior not
  implemented.
- **`mldsa65`** — post-quantum REALITY extensions (`mldsa65Seed`).
- **Fallback limits** — `limitFallbackUpload` / `limitFallbackDownload`.
- **UDP** — VLESS UDP command → `Unsupported`.
- **Mux** — VLESS Mux command → `Unsupported`.
- **Routing** — outbound selection, rules, balancers.
- Fragmented `ClientHello` across multiple TLS records.

## Осталось TODO

See **[docs/reality-accepted-path.md](docs/reality-accepted-path.md)** for the
full accepted-path design, upstream mapping, anti-patterns, and TODO matrix.
High level:

- **TLS 1.3 server handshake state machine** — prerequisite for accepted path
  (not a one-record ServerHello patch).
- **ServerHello generation, key schedule, transcript** — port/implement block A
  from the dev doc.
- **Certificate, CertificateVerify, Finished, client Finished** — complete
  server-side handshake.
- **Encrypted application stream** — decrypt/encrypt wrapper for post-handshake
  traffic.
- **VLESS handoff** — after handshake complete, call `handle_vless_tcp_inbound`
  on the decrypted stream.
- **VLESS response header** — exact client-facing semantics.
- **Vision**, **UDP/Mux/routing**, **`mldsa65`**, **fallback limits**,
  fragmented ClientHello (see above).

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

Поддерживаемые поля `realitySettings`:

| Поле | Поведение |
|------|-----------|
| `dest` / `target` | Fallback-адрес `host:port`; нельзя указывать оба одновременно |
| `privateKey` | base64url без padding, 32 байта после декодирования |
| `shortIds` | hex 0..16 символов; пустая строка = prefix длины 0 |
| `serverNames` | SNI whitelist (exact, case-insensitive) |
| `maxTimeDiff` | окно времени в ms; `0` = проверка отключена |
| `minClientVer` / `maxClientVer` | опциональные границы версии клиента (`"1.8.0"`) |
| `show` | читается и логируется |

## Запуск

```bash
RUST_LOG=info cargo run -- ./config.json
```

Подробная диагностика:

```bash
RUST_LOG=debug cargo run -- ./config.json
```

### Decision flow

1. Load config, bind on `listen:port`.
2. Read first TLS `ClientHello` record.
3. SNI check against `serverNames` → else **Fallback**.
4. X25519 + HKDF + AES-GCM open `session_id` → else **Fallback**.
5. Policy validation (`shortId`, client version, time) → else **Fallback**.
6. **Accepted** → `handle_accepted_reality_client`:
   connect `dest` → forward `raw_record` → observe/validate dest ServerHello →
   **`Unsupported`** (no fallback relay; no bytes sent to client).
7. **Fallback** → TCP relay to `dest`/`target` with bytes already read.

## Troubleshooting

| Симптом / лог | Возможная причина |
|---------------|-------------------|
| `REALITY fallback: SNI missing` | Client without SNI extension |
| `REALITY fallback: SNI not allowed` | Hostname not in `serverNames` |
| `REALITY session_id auth failed` | Invalid REALITY ciphertext / key |
| `shortId validation failed` | Decrypted shortId does not match configured prefix |
| `client version below min` / `above max` | REALITY client version out of range |
| `maxTimeDiff validation failed` | Client `unix_time` outside window |
| `REALITY accepted path started` then `Unsupported` | Client passed all checks; dest ServerHello observed; TLS 1.3 server SM not implemented yet — **expected** |
| `REALITY accepted path stopping because TLS server handshake is not implemented` | Observation succeeded; accepted path stops before client-facing handshake |
| `REALITY accepted path failed` | Connect/observation/validation error on accepted path (not fallback) |
| `fallback relay failed` | `dest`/`target` unreachable |

## Структура проекта

```
src/
├── main.rs              # listener, RuntimeConfig, fallback vs accepted routing
├── config/              # Xray JSON config, RealityInboundRuntime, VLESS settings
├── tls/
│   ├── record.rs        # ClientHello first-record read/parse
│   ├── records.rs       # TLS record parser (dest observation)
│   └── server_hello.rs  # TLS 1.3 ServerHello parser
├── protocol/            # TLS codec, ClientHello, extensions
├── reality/
│   ├── auth.rs          # X25519, HKDF auth key
│   ├── session.rs       # AEAD session_id decrypt, policy validation
│   ├── decision.rs      # inspect_reality_client_hello, RealityDecision
│   ├── sni.rs           # SNI extraction, serverNames check
│   ├── version.rs       # minClientVer / maxClientVer parse & compare
│   ├── short_id.rs
│   ├── handshake.rs     # fetch_dest_handshake, ServerHello observation/validation
│   ├── server.rs        # accepted-path entry (dest observation)
│   └── tls13/           # TLS 1.3 server SM skeleton (not wired)
├── vless/
│   ├── config.rs        # VlessClient, build_vless_clients
│   ├── protocol.rs      # VlessRequest parser
│   └── inbound.rs       # read_vless_request, auth, handle_vless_tcp_inbound
├── outbound/
│   └── freedom.rs       # connect_tcp_destination, relay_tcp
└── proxy/               # fallback relay
docs/
└── reality-accepted-path.md  # accepted-path design, upstream mapping, TODO matrix
```

## Ограничения

- First TLS record must contain a complete `ClientHello` without trailing data.
- Valid REALITY clients are **not** sent to fallback — intentional; accepted path
  still returns `Unsupported` until TLS 1.3 server state machine is implemented.
- Dest ServerHello observation validates shape (TLS 1.3 + X25519) but does **not**
  produce a client-facing handshake.
- VLESS parser/auth/freedom outbound are unit-tested but **not available** through
  a completed REALITY accepted connection.
- This is **not** a drop-in replacement for Xray-core.
