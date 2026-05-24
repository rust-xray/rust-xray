# rust-xray

Экспериментальная реализация части Xray/VLESS REALITY на Rust.

Проект поднимает TCP-listener по `inbound` из Xray-совместимого `config.json`,
читает первый TLS `ClientHello`, проверяет REALITY-кандидата (AEAD + policy)
и либо проксирует обычный/невалидный трафик на fallback-адрес из
`realitySettings.dest` / `realitySettings.target`, либо попадает в accepted-path
stub для валидного REALITY-клиента.

**Non-REALITY clients are relayed to `dest`.**

**This is not a drop-in replacement for Xray-core.** Accepted path (ServerHello
patching, VLESS/Vision handoff) ещё не реализован.

## Реализовано

- **AEAD `session_id` decrypt** — X25519 keyshare, HKDF-SHA256 auth key,
  AES-256-GCM open, nonce = `random[20..32]`, AAD с обнулённым `session_id`.
- **`shortId` validation** — prefix match против `shortIds` (0..8 байт; пустой
  configured shortId = prefix длины 0).
- **`maxTimeDiff` validation** — `unix_time` из plaintext vs wall clock;
  `maxTimeDiff == 0` отключает проверку.
- **`minClientVer` / `maxClientVer` validation** — опционально, если заданы в
  конфиге; invalid version string → `InvalidInput` (не silent fallback).
- **`serverNames` / SNI validation** — ранняя проверка до crypto (exact match,
  case-insensitive).

### Инфраструктура

- Xray-compatible config parsing (`RealityInboundRuntime`).
- TLS ClientHello parsing (первый TLS record).
- Fallback relay для обычных и невалидных клиентов.
- Accepted-path scaffold: `RealityAccepted`, `fetch_dest_handshake` /
  `patch_reality_server_hello` (placeholder).
- Unit-тесты для config, TLS, AEAD, policy, SNI и decision flow.

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

## Осталось TODO

- **Accepted path** — connect → forward ClientHello → read dest handshake →
  reply to client.
- **ServerHello patching** — REALITY crypto/session modification.
- **VLESS/Vision** — stream handoff после REALITY handshake.
- **`mldsa65`** — post-quantum REALITY extensions (`mldsa65Seed`).
- **Fallback limits** — `limitFallbackUpload` / `limitFallbackDownload`.
- Фрагментированный `ClientHello` across multiple TLS records.

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
6. **Accepted** → `handle_accepted_reality_client` → `Unsupported` (без fallback relay).
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
├── main.rs              # listener, client handler, fallback vs accepted routing
├── config/              # Xray JSON config, RealityInboundRuntime
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
│   └── server.rs        # accepted-path entry (stub)
└── proxy/               # fallback relay
```

## Ограничения

- Первый TLS record должен содержать полный `ClientHello` без trailing data.
- Валидный REALITY-клиент **не** отправляется в fallback — это намеренно.
