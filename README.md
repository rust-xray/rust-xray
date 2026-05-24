# rust-xray

Экспериментальная реализация части Xray/VLESS REALITY на Rust.

Проект поднимает TCP-listener по `inbound` из Xray-совместимого `config.json`,
читает первый TLS `ClientHello`, разбирает его как TLS/VLESS REALITY-кандидата,
проверяет базовые признаки REALITY и при необходимости проксирует соединение на
fallback-адрес из `realitySettings.dest` или `realitySettings.target`.

Важно: полноценный серверный REALITY-handshake пока не завершён. Успешный
REALITY-кандидат сейчас попадает в stub-обработчик, а открытие REALITY
`session_id` помечено как TODO. Проект подходит для разработки, изучения
формата и проверки отдельных частей протокола, но не является готовой заменой
Xray.

## Что уже есть

- Загрузка Xray-совместимого JSON-конфига.
- Поиск первого `inbound` со `streamSettings.security == "reality"`.
- Поддержка `realitySettings.dest` и алиаса `target`.
- Валидация `privateKey` и `shortIds`.
- Чтение TLS record с `ClientHello`.
- Парсер TLS `ClientHello` и основных расширений.
- Извлечение X25519 `key_share`.
- Вывод HKDF-ключа REALITY из клиентского X25519 ключа и серверного
  `privateKey`.
- Fallback relay через `tokio::io::copy_bidirectional`.
- Unit-тесты для конфигурации, TLS record, `shortId` и X25519-извлечения.

## Что ещё не реализовано

- AES-GCM открытие REALITY `session_id`.
- Проверка `shortId`, времени клиента и версий клиента после расшифровки
  `session_id`.
- Полный REALITY handshake с патчингом `ServerHello`.
- Полноценная обработка принятого VLESS/REALITY клиента.
- Поддержка фрагментированного `ClientHello`.

## Требования

- Rust stable.
- Cargo.
- Доступный TCP-адрес для `listen:port` из конфигурации.

## Сборка и тесты

```bash
cargo build
cargo test
```

Запуск в release-режиме:

```bash
cargo build --release
```

## Конфигурация

По умолчанию бинарник читает `./config.json`. Путь к конфигу можно передать
первым аргументом:

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
          "shortIds": ["", "0123456789abcdef"]
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

- `dest` или `target`: строка вида `host:port`, куда отправляется fallback.
- `privateKey`: base64url без padding, 32 байта после декодирования.
- `serverNames`: читается из конфига и логируется.
- `shortIds`: список hex-строк длиной до 16 символов; пустая строка допустима.
- `show`, `maxTimeDiff` и дополнительные поля Xray-конфига читаются, но часть
  из них пока не влияет на поведение.

Нельзя указывать одновременно `dest` и `target`.

## Запуск

```bash
RUST_LOG=info cargo run -- ./config.json
```

Для подробной диагностики:

```bash
RUST_LOG=debug cargo run -- ./config.json
```

После старта приложение:

1. Загружает конфигурацию.
2. Выбирает первый REALITY inbound.
3. Биндится на `listen:port`.
4. Для каждого TCP-клиента читает первый TLS `ClientHello`.
5. Пытается распознать REALITY-кандидата.
6. При ошибке разбора или неподходящем ClientHello открывает fallback-соединение
   к `dest`/`target` и передаёт туда уже прочитанные байты.

## Структура проекта

- `src/main.rs`: запуск listener, загрузка runtime-конфига, обработка клиентов.
- `src/config`: Xray-совместимые структуры и helpers для REALITY inbound.
- `src/tls`: чтение и проверка TLS record с `ClientHello`.
- `src/protocol`: codec и структуры TLS handshake/extensions.
- `src/reality`: REALITY-специфичная проверка ClientHello, X25519/HKDF,
  `shortId`, заготовка открытия `session_id`.
- `src/proxy`: fallback relay.
- `src/error`: ошибки протокольного парсинга.

## Ограничения

Проект сейчас намеренно строг к первому TLS record: `ClientHello` должен
полностью помещаться в один record и не иметь trailing data. Это упрощает
текущий парсер, но не покрывает все варианты реального TLS-трафика.

Также проект не использует Xray как зависимость и не гарантирует полную
совместимость с его поведением до завершения TODO в `src/reality/session.rs` и
обработчика принятого клиента в `src/main.rs`.
