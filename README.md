# rust-xray

Экспериментальная реализация части Xray/VLESS REALITY на Rust.

Проект поднимает TCP-listener по `inbound` из Xray-совместимого `config.json`,
читает первый TLS `ClientHello`, проверяет REALITY-кандидата (AEAD + policy)
и либо проксирует обычный/невалидный трафик на fallback-адрес из
`realitySettings.dest` / `realitySettings.target`, либо попадает в accepted-path
stub для валидного REALITY-клиента.

**Non-REALITY clients are relayed to `dest`.**

**This is not a drop-in replacement for Xray-core.**

**Valid REALITY clients still reach the `Unsupported` accepted path until
ServerHello patching is implemented.** VLESS parser/auth/outbound skeleton exists
in the library, but **is not yet reachable from a real REALITY accepted
connection** — the accepted stream is not handed off until the REALITY server
handshake is completed.

## Реализовано

### REALITY inbound

- **Xray-compatible REALITY config parsing** — `RealityInboundRuntime`, typed
  VLESS inbound settings (`VlessClientObject`), listen/dest/keys/shortIds/policy
  fields.
- **REALITY ClientHello auth** — X25519 keyshare extraction, HKDF-SHA256 auth
  key derivation.
- **AEAD `session_id` decrypt** — AES-256-GCM open, nonce = `random[20..32]`,
  AAD с обнулённым `session_id`.
- **Policy validation**
  - `shortId` prefix match против `shortIds` (0..8 байт; пустой configured
    shortId = prefix длины 0)
  - `maxTimeDiff` — `unix_time` из plaintext vs wall clock; `0` отключает
    проверку
  - `minClientVer` / `maxClientVer` — опционально; invalid version string →
    `InvalidInput` (не silent fallback)
  - `serverNames` / SNI — ранняя проверка до crypto (exact match,
    case-insensitive)
- **TLS ClientHello parsing** — первый TLS record.
- **Fallback relay** — TCP relay на `dest`/`target` для обычных и невалидных
  клиентов.
- **Accepted-path wiring (stub)** — `RealityAccepted`, `handle_accepted_reality_client`
  принимает parsed VLESS clients, но возвращает `Unsupported`; ServerHello
  patching placeholder в `handshake.rs`.

### VLESS (library skeleton, not on accepted path yet)

- **VLESS config users parsing** — `VlessInboundSettings`, `VlessClientObject`,
  `build_vless_clients()` at startup.
- **VLESS request parser** — `parse_vless_request()`, `read_vless_request()`
  with `initial_payload` preservation.
- **VLESS UUID auth** — `authenticate_vless_client()`, flow metadata check
  (`None`, `""`, `xtls-rprx-vision` allowed as metadata only).
- **Minimal freedom TCP outbound skeleton** — `connect_tcp_destination()`,
  `relay_tcp()`; `handle_vless_tcp_inbound()` pipeline (parse → auth → connect →
  relay) exists but is **not called** from REALITY accepted path.

### Tests

Unit-тесты для config, TLS, AEAD, policy, SNI, decision flow, VLESS parser/auth,
freedom outbound helpers, runtime config loading with VLESS clients.

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

`Accepted` содержит `RealityAuthResult`, `RealityClientAuth`, `sni: Some(String)`.

Секреты (`privateKey`, `auth_key`, shared secret, plaintext `session_id`) в логи
не выводятся.

## Не реализовано

- **REALITY ServerHello patching** — `patch_reality_server_hello()` placeholder.
- **Actual accepted stream handoff** — после REALITY handshake stream не
  передаётся в VLESS handler.
- **VLESS response header exact semantics** — response header клиенту не
  отправляется; TODO в `handle_vless_tcp_inbound`.
- **Vision flow behavior** — flow metadata принимается, но Vision не
  реализован.
- **UDP** — VLESS UDP command → `Unsupported`.
- **Mux** — VLESS Mux command → `Unsupported`.
- **Routing** — outbound selection, rules, balancers.
- **`mldsa65`** — post-quantum REALITY extensions (`mldsa65Seed`).
- **Fallback limits** — `limitFallbackUpload` / `limitFallbackDownload`.
- Фрагментированный `ClientHello` across multiple TLS records.

## Осталось TODO

- **ServerHello patching** — REALITY crypto/session modification; prerequisite
  for accepted path.
- **Accepted path handoff** — connect to dest, forward ClientHello, read/patch
  ServerHello, reply to client, then call `handle_vless_tcp_inbound`.
- **VLESS response header** — exact client-facing semantics before/after relay.
- **Vision** — `xtls-rprx-vision` behavior after REALITY + VLESS are connected.
- **UDP / Mux / routing** — beyond minimal TCP freedom outbound.
- **`mldsa65`**, **fallback limits**, fragmented ClientHello (see above).

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

1. Загрузка конфигурации, bind на `listen:port`.
2. Чтение первого TLS `ClientHello` record.
3. SNI check против `serverNames` → иначе **Fallback**.
4. X25519 + HKDF + AES-GCM open `session_id` → иначе **Fallback**.
5. Policy validation (`shortId`, client version, time) → иначе **Fallback**.
6. **Accepted** → `handle_accepted_reality_client` → `Unsupported` (без fallback
   relay; VLESS clients loaded but not used until ServerHello patching).
7. **Fallback** → TCP relay на `dest`/`target` с уже прочитанными байтами.

## Troubleshooting

| Симптом / лог | Возможная причина |
|---------------|-------------------|
| `REALITY fallback: SNI missing` | Клиент без SNI extension |
| `REALITY fallback: SNI not allowed` | Hostname не в `serverNames` |
| `REALITY session_id auth failed` | Неверный REALITY ciphertext / ключ |
| `shortId validation failed` | Decrypted shortId не совпадает с configured prefix |
| `client version below min` / `above max` | Версия REALITY-клиента вне диапазона |
| `maxTimeDiff validation failed` | `unix_time` клиента вне окна |
| `REALITY accepted path reached but not implemented` | Клиент прошёл все проверки; accepted path — stub |
| `fallback relay failed` | `dest`/`target` недоступен |

## Структура проекта

```
src/
├── main.rs              # listener, RuntimeConfig, fallback vs accepted routing
├── config/              # Xray JSON config, RealityInboundRuntime, VLESS settings
├── tls/                 # TLS record read/parse
├── protocol/            # TLS codec, ClientHello, extensions
├── reality/
│   ├── auth.rs          # X25519, HKDF auth key
│   ├── session.rs       # AEAD session_id decrypt, policy validation
│   ├── decision.rs      # inspect_reality_client_hello, RealityDecision
│   ├── sni.rs           # SNI extraction, serverNames check
│   ├── version.rs       # minClientVer / maxClientVer parse & compare
│   ├── short_id.rs
│   ├── handshake.rs     # fetch_dest_handshake, patch placeholder
│   └── server.rs        # accepted-path entry (stub, VLESS clients wired)
├── vless/
│   ├── config.rs        # VlessClient, build_vless_clients
│   ├── protocol.rs      # VlessRequest parser
│   └── inbound.rs       # read_vless_request, auth, handle_vless_tcp_inbound
├── outbound/
│   └── freedom.rs       # connect_tcp_destination, relay_tcp
└── proxy/               # fallback relay
```

## Ограничения

- Первый TLS record должен содержать полный `ClientHello` без trailing data.
- Валидный REALITY-клиент **не** отправляется в fallback — это намеренно; accepted
  path всё равно возвращает `Unsupported` до ServerHello patching.
- VLESS parser/auth/freedom outbound протестированы unit-тестами, но **не
  доступны** через реальное REALITY accepted-соединение.
- Это **не** drop-in replacement для Xray-core.
