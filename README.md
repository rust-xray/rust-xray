# rust-xray

Экспериментальная реализация части Xray/VLESS REALITY на Rust.

Проект поднимает TCP-listener по `inbound` из Xray-совместимого `config.json`,
читает первый TLS `ClientHello`, проверяет REALITY-кандидата (AEAD + policy)
и либо проксирует обычный/невалидный трафик на fallback-адрес из
`realitySettings.dest` / `realitySettings.target`, либо попадает в accepted-path
stub для валидного REALITY-клиента.

**Non-REALITY clients are relayed to `dest`.**

**Valid REALITY clients currently reach the accepted-path stub and fail with
`Unsupported` until ServerHello patching and VLESS/Vision handoff are
implemented.**

**This is not a drop-in replacement for Xray-core yet.**

## Реализовано

- Xray-compatible config parsing для REALITY inbound (`inbounds`,
  `streamSettings.realitySettings`, `dest` / `target`, `privateKey`, `shortIds`,
  `serverNames`, `maxTimeDiff`, `minClientVer`, `maxClientVer`).
- TLS ClientHello parsing (первый TLS record, без фрагментации).
- X25519 keyshare extraction из `key_share` extension.
- HKDF REALITY auth key (salt = `random[0..20]`, info = `"REALITY"`, 32-byte key).
- AES-256-GCM decrypt REALITY `session_id` (nonce = `random[20..32]`, AAD =
  handshake message с обнулённым `session_id`).
- Policy validation после AEAD:
  - `shortId` — prefix match против `shortIds` (0..8 байт; пустой configured
    shortId совпадает с любым prefix длины 0);
  - `maxTimeDiff` — сравнение `unix_time` из plaintext с текущим временем
    (`maxTimeDiff == 0` отключает проверку);
  - `minClientVer` / `maxClientVer` — опционально, если заданы в конфиге;
  - SNI / `serverNames` — ранняя проверка до crypto (case-insensitive exact
    match).
- Fallback relay для обычных и невалидных клиентов (`tokio::io::copy_bidirectional`).
- Accepted-path scaffold: `RealityAccepted` с auth metadata, SNI и client auth;
  интерфейс `fetch_dest_handshake` / `patch_reality_server_hello` (patching —
  placeholder).
- Unit-тесты для config, TLS record, REALITY auth, AEAD, validation, SNI и
  decision flow.

## Не реализовано

- Full accepted path (connect → forward ClientHello → read dest handshake → patch
  → reply to client).
- ServerHello patching (REALITY crypto/session modification).
- VLESS/Vision stream handoff после успешного REALITY handshake.
- `mldsa65Seed` / post-quantum REALITY extensions.
- Fallback bandwidth limits (`limitFallbackUpload` / `limitFallbackDownload`).
- Фрагментированный `ClientHello` across multiple TLS records.
- Полная совместимость со всеми edge cases Xray-core.

## Требования

- Rust stable
- Cargo
- Доступный TCP-адрес для `listen:port` из конфигурации

## Сборка и тесты

```bash
cargo build
cargo test
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
          "maxClientVer": ""
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

Поддерживаемые и используемые поля `realitySettings`:

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
5. Policy validation (`shortId`, time, client version) → иначе **Fallback**.
6. **Accepted** → `handle_accepted_reality_client` → `Unsupported`, соединение
   закрывается (без fallback relay).
7. **Fallback** → TCP relay на `dest`/`target` с уже прочитанными байтами.

## Troubleshooting

| Симптом / лог | Возможная причина |
|---------------|-------------------|
| `REALITY session_id auth failed` / AEAD open failed | Неверный `privateKey`, `session_id`, AAD или nonce; клиент не REALITY; повреждённый ClientHello |
| `SNI missing` / `SNI not allowed` | Клиент без SNI или hostname не в `serverNames` |
| `shortId validation failed` | Decrypted shortId не совпадает ни с одним configured prefix |
| `maxTimeDiff validation failed` | `unix_time` клиента вне окна `maxTimeDiff` |
| `minClientVer validation failed` / `maxClientVer validation failed` | Версия REALITY-клиента вне заданного диапазона |
| `REALITY accepted path reached but not implemented` | Клиент прошёл все проверки, но ServerHello patching / VLESS ещё не реализованы — это ожидаемое поведение |
| `fallback relay failed` | `dest`/`target` недоступен или timeout connect |

Секреты (`privateKey`, `auth_key`, shared secret, полный decrypted session
payload) в логи не выводятся.

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
│   ├── client_version.rs
│   ├── short_id.rs
│   ├── handshake.rs     # fetch_dest_handshake, patch placeholder
│   └── server.rs        # accepted-path entry (stub)
└── proxy/               # fallback relay
```

## Ограничения

- Первый TLS record должен содержать полный `ClientHello` без trailing data.
- Проект не использует Xray как зависимость и не гарантирует идентичное
  поведение Xray-core до реализации accepted path.
- Валидный REALITY-клиент **не** отправляется в fallback — это намеренно, чтобы
  не маскировать ошибки accepted path.
