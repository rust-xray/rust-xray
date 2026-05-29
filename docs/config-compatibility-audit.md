# Config compatibility audit (rust-xray vs Xray-core)

Audit date: 2026-05-29  
Branch: `experiment`  
Scope: **VLESS + REALITY + Vision** server inbound config as parsed by `src/config/xray.rs`.  
Upstream reference: [XTLS/Xray-core](https://github.com/XTLS/Xray-core) `main` — `infra/conf/transport_internet.go` (`REALITYConfig`, `StreamConfig`), `infra/conf/vless.go` (`VLessInboundConfig`), `transport/internet/reality/config.proto`.

**No runtime changes** were made for this audit. Behavior described here reflects the current code path.

**Update (explicit startup reject):** `validate_reality_inbound_config_policy` in `src/config/xray.rs` now rejects at startup (via `first_reality_inbound_runtime` / `validate_vless_reality_inbound_stream`):

- `realitySettings.limitFallbackUpload` / `limitFallbackDownload` → `Unsupported`
- Client-only inbound `realitySettings` keys in `extra` (`publicKey`, `fingerprint`, `mldsa65Verify`, …) → `InvalidInput`
- Unsupported `streamSettings` transport sub-objects in `extra` (`tlsSettings`, `wsSettings`, `grpcSettings`, …) → `Unsupported`
- `streamSettings.sockopt` remains allowed (Xray-compatible smoke fixtures)
- Server fields `show`, `dest`/`target`, `type`, `xver`, `serverNames`, `privateKey`, `shortIds`, version/time policy, `mldsa65Seed` remain accepted

## Methodology

1. Compare JSON field names and serde models in `src/config/xray.rs` / `src/vless/fallback.rs` with upstream config structs.
2. Trace which parsed values are copied into `RealityInboundRuntime` and consumed from `src/main.rs`, `src/reality/*`, `src/vless/*`.
3. Classify policy per field; call out **silent-ignore** risks (`#[serde(flatten)] extra` or parsed struct fields never read at runtime).
4. Map existing tests in `src/config/xray.rs` (`#[cfg(test)]`), `src/vless/*`, `tests/reality_mldsa65_baseline_regression.rs`, and smoke fixtures.

### Policy legend

| Policy | Meaning |
|--------|---------|
| **supported** | Parsed and used on the accepted REALITY/VLESS path (or intentional negative transport rejection). |
| **explicit unsupported** | Parse or `first_reality_inbound_runtime` / validators reject with a clear error. |
| **parsed but gated** | Stored on runtime struct or accepted at parse time, but only affects logging, selection, or non-handshake branches (document the gate). |
| **future work** | Known upstream field; not implemented; may parse without effect today. |
| **parsed ignored** | JSON deserializes successfully but is **not** applied at runtime (misconfiguration risk). |

### Out of scope (baseline already PASS — not re-audited here)

Raw/TCP network aliases, VLESS `flow=""` / `xtls-rprx-vision`, fallback matrix, TLS cipher matrix, ML-DSA-65 seed runtime, UDP/Mux/XUDP negatives, unsupported transport negatives — see existing tests and `docs/reality-mldsa65-runtime-baseline.md`.

---

## Executive summary

| Area | Upstream | rust-xray | Main gap / risk |
|------|----------|-----------|-----------------|
| VLESS inbound `settings` | `clients`/`users`, `decryption`, `fallbacks` | `clients`, `decryption`, `fallbacks` only | `users` alias → `settings.extra`; no runtime read. |
| `streamSettings.network` + `security` | Many transports + REALITY | TCP/raw supported; others rejected at validator | Aligned with explicit unsupported policy. |
| `realitySettings` server fields | dest/target, keys, policy, seed, limits | Core server fields supported | `type`, `xver`, `limitFallback*` parsed but **ignored** at runtime. |
| `realitySettings` client fields | outbound-only in upstream | Land in `realitySettings.extra` | **Silent misconfiguration** if copied onto server inbound. |
| Transport sub-settings | tls/raw/ws/grpc/xhttp/sockopt/finalmask | Stored in `streamSettings.extra` only | **Silent ignore** — no socket/TLS/finalmask behavior. |
| Top-level `api` / `stats` / `policy` | Remna blocks | Typed + `validate_xray_panel_config` | No gRPC stats server yet | **parsed + validated** | `tests/config_remna.rs` |
| Top-level `log` / `outbounds` | Panel metadata | `LogConfig` / `OutboundObject` | Not read at runtime | **parsed ignored** | Remna fixture, smoke fixtures |
| Top-level `routing` | Traffic rules | `RoutingConfig` | Non-empty `rules`/`balancers` rejected at load | **explicit unsupported** (non-empty) | `config_remna::routing_rules_are_rejected_when_non_empty` |

---

## 1. Inbound envelope

| Field | Upstream meaning | Parse status | Runtime status | Policy | Test coverage |
|-------|------------------|--------------|----------------|--------|---------------|
| `tag` | Inbound tag for routing/logs | `InboundObject.tag` | Copied to `RealityInboundRuntime.tag`; logged | **supported** | `builds_first_reality_inbound_runtime` |
| `listen` | Bind address | `InboundObject.listen` | `inbound_listen_addr` → `listen_addr` | **supported** | `parse_minimal_vless_reality_inbound`, `formats_ipv6_listen_correctly` |
| `port` | Listen port (number or string) | `InboundPortValue` | `inbound_listen_addr`; port ranges rejected | **supported** / **explicit unsupported** (range) | `accepts_port_as_string`, `rejects_port_range` |
| `protocol` | Must be `vless` for this project | `InboundObject.protocol` | Must be vless for REALITY selection | **supported** | `accepts_security_and_protocol_case_insensitively` |
| `settings` | Protocol settings blob | `Option<Value>` → `VlessInboundSettings` when vless | VLESS clients, decryption, fallbacks | **supported** | `inbound_vless_settings_*`, `preserves_client_flow_vision` |
| `streamSettings` | Transport + security | `StreamSettingsObject` | Network validator + REALITY settings | **supported** | transport tests in `xray.rs` `#[cfg(test)]` |
| `sniffing`, `allocate`, … | Xray sniffing / metadata | `InboundObject.extra` | Not read | **parsed ignored** | `parse_preserves_unknown_fields_in_extra` |
| Top-level `log`, `outbounds` | Full Xray instance | `LogConfig` / `Vec<OutboundObject>` | Not read by rust-xray server | **parsed ignored** | `parses_realistic_xray_vless_tcp_reality_server_config` |
| Top-level `routing` | Router rules | `RoutingConfig` | Rejected when `rules`/`balancers` non-empty | **explicit unsupported** (non-empty) | `tests/config_remna.rs` |
| Top-level `api`, `stats`, `policy` | Panel + stats API | Typed structs | gRPC server on `api.listen` when `run`; methods mostly `UNIMPLEMENTED` | **parsed + validated** / **runtime skeleton** | `tests/config_remna.rs`, `tests/api_grpc.rs` |

**Risk:** Non-empty `routing.rules` are rejected at load (no silent misrouting). `sniffing` and `outbounds` are still parsed-only at runtime.

---

## 2. VLESS `settings` (`VlessInboundSettings`)

| Field | Upstream meaning | Parse status | Runtime status | Policy | Test coverage |
|-------|------------------|--------------|----------------|--------|---------------|
| `clients[]` | Authorized users | `Vec<VlessClientObject>` | `build_vless_clients` → auth | **supported** | `inbound_vless_settings_parses_clients_and_decryption`, `validates_client_uuid_at_runtime` |
| `clients[].id` | UUID or custom string (Xray v5) | `String` | `parse_vless_user_id` | **supported** | `src/vless/config.rs` uuid tests |
| `clients[].email` | Optional email | `Option<String>` | Stored on `VlessClient` | **supported** | `build_vless_clients_copies_email_and_flow` |
| `clients[].flow` | Per-user flow (`xtls-rprx-vision`, …) | `Option<String>` | `validate_vless_client_flow` | **supported** (vision) / **explicit unsupported** (unknown) | `preserves_client_flow_vision`, `unknown_flow_returns_unsupported_at_runtime_validation`, `vision_flow_runtime_accepts_when_implemented` |
| `clients[].level` | User policy level | `VlessClientObject.level` | Preserved on client object; not applied at runtime | **parsed ignored** (runtime) | `tests/config_remna.rs` |
| `clients[]` custom keys | Legacy VMess fields | `clients[].extra` | Not read | **parsed ignored** | `parse_preserves_unknown_fields_in_extra` |
| `users[]` | Alias of `clients` in upstream | Not a field; → `settings.extra` | Not read | **parsed ignored** | — **risk: use `clients` on server configs** |
| `decryption` | VLESS encryption (`none` only here) | `Option<String>` | Default `"none"`; other values rejected | **supported** / **explicit unsupported** | `defaults_missing_vless_decryption_to_none`, `rejects_decryption_other_than_none` |
| `fallbacks[]` | Non-VLESS routing targets | `Vec<FallbackConfig>` | `resolve_fallback_selection` + `relay_fallback_with_xver` | **supported** | `src/vless/fallback.rs` matrix tests, `main.rs` fallback tests |
| `fallbacks[].name` | SNI match | `Option<String>` | Fallback matcher | **supported** | fallback tests |
| `fallbacks[].alpn` | ALPN match | `Option<String>` | Fallback matcher | **supported** | fallback tests |
| `fallbacks[].path` | HTTP path (`/…`) | `Option<String>` | Fallback matcher | **supported** | fallback tests |
| `fallbacks[].dest` | Port or `host:port` | `FallbackDest` | Relay target | **supported** | `inbound_vless_settings_parses_fallback_dest_number` |
| `fallbacks[].xver` | PROXY protocol v1/v2 on fallback | `u8` (default 0) | `relay_fallback_with_xver` | **supported** | `validate_fallback_xver_*`, `main.rs` `runtime_resolves_fallback_xver_values` |
| `fallbacks[].type` | Upstream legacy type hint | Not modeled → JSON parse still accepts key in array objects only if we add it — **currently unknown keys in fallback objects fail serde** | — | **explicit unsupported** at parse | — |
| `settings.flow` | Inbound-level flow (upstream) | → `settings.extra` | Not read | **parsed ignored** | — |
| `settings.testseed` | Vision test vectors | → `settings.extra` | Not read | **parsed ignored** | — |

**Note:** Unknown keys inside `fallbacks[]` entries cause deserialize failure (strict struct). Unknown keys at `settings` object level are captured by `extra` only if serde allows — `VlessInboundSettings` uses flatten for top-level unknown keys only.

---

## 3. `streamSettings`

| Field | Upstream meaning | Parse status | Runtime status | Policy | Test coverage |
|-------|------------------|--------------|----------------|--------|---------------|
| `network` | Transport (`tcp`, `raw`, `ws`, …) | `Option<String>` | `validate_reality_transport_network` when `security=reality` | **supported** (`tcp`/`raw`/missing) / **explicit unsupported** (others) | `validate_reality_transport_network_*`, `first_reality_inbound_runtime_rejects_*` |
| `security` | `reality`, `tls`, `none`, … | `Option<String>` | REALITY path requires `reality` + `realitySettings` | **supported** | `find_reality_inbounds_skips_non_reality_security` |
| `realitySettings` | See §4 | `RealitySettingsObject` | `RealityInboundRuntime` + handshake | **supported** (subset) | §4 |
| `sockopt` | Socket options (TFO, mark, …) | `streamSettings.extra` | Parsed only; not applied | **parsed ignored** (allowed) | `sockopt_in_stream_settings_extra_remains_valid`, realistic fixture |
| `tlsSettings` | TLS camouflage (non-REALITY) | `extra` | Startup reject | **explicit unsupported** | `rejects_stream_settings_tls_settings_on_reality_inbound` |
| `rawSettings` / `tcpSettings` | TCP transport options | `extra` | Startup reject | **explicit unsupported** | policy validator |
| `wsSettings` | WebSocket transport | `extra` | Startup reject (+ `network=ws`) | **explicit unsupported** | `rejects_stream_settings_ws_settings_on_reality_inbound` |
| `grpcSettings` | gRPC transport | `extra` | Startup reject | **explicit unsupported** | policy validator |
| `xhttpSettings` / `splithttpSettings` | SplitHTTP / XHTTP | `extra` | Startup reject | **explicit unsupported** | policy validator |
| `kcpSettings` / `httpupgradeSettings` / `hysteriaSettings` | Other transports | `extra` | Startup reject | **explicit unsupported** | policy validator |
| `finalmask` | Post-transport masking (Xray ≥ recent) | `extra` | Startup reject | **explicit unsupported** | policy validator |
| `address`, `port` | Stream-level dest override | `extra` | Startup reject | **explicit unsupported** | policy validator |

---

## 4. `realitySettings` — server-side fields

| Field | Upstream meaning | Parse status | Runtime status | Policy | Test coverage |
|-------|------------------|--------------|----------------|--------|---------------|
| `show` | Debug logging of REALITY handshakes | `bool` (default false) | Log line in `load_runtime_config` only | **parsed but gated** (logging) | `builds_first_reality_inbound_runtime_with_policy_fields` |
| `dest` | Camouflage target `host:port` (or legacy forms upstream) | `Option<Value>` string only | `reality_dest_addr` → dial target | **supported** (string) / **explicit unsupported** (numeric JSON) | `dest_without_port_defaults_to_443`, `rejects_both_dest_and_target` |
| `target` | Alias of `dest` in JSON configs | `Option<Value>` | Same as dest; **mutually exclusive** with `dest` in rust (upstream merges) | **supported** with stricter exclusivity | `parse_reality_settings_supports_target_alias` |
| `type` | dest interpretation (`tcp`, `unix`, …) | `Option<String>` on struct | Parsed; not applied to dial | **supported** (parse-only) | `reality_type_and_xver_remain_valid_at_startup` |
| `xver` | PROXY protocol version toward **dest** (upstream) | `u64` default 0 on struct | Parsed; fallback `xver` is separate | **supported** (parse-only) | `reality_type_and_xver_remain_valid_at_startup`, smoke fixture |
| `serverNames` | Allowed SNI list | `Vec<String>` | REALITY policy + cert generation | **supported** (no `*`) | `rejects_wildcard_server_names`, `rejects_empty_server_names_with_clear_error` |
| `privateKey` | Server X25519 private (base64url) | `Option<String>` | Required; validated; redacted in Debug | **supported** | `reality_private_key`, `reality_inbound_runtime_debug_does_not_expose_secrets` |
| `shortIds` | Client shortId prefixes (hex) | `Vec<String>` | `reality_short_ids` → policy | **supported** | `parse_short_ids_empty_and_hex`, shortId error tests |
| `minClientVer` / `maxClientVer` | Client version window | `Option<String>` | `validate_reality_client_auth` | **supported** | `builds_first_reality_inbound_runtime_with_policy_fields`, `src/reality/session.rs` policy tests |
| `maxTimeDiff` | Max \|now − auth time\| (ms); `0` disables | `u64` | Policy validation (`0` = off) | **supported** | session tests, runtime policy test |
| `mldsa65Seed` | ML-DSA-65 seed (32 bytes b64url) | `Option<String>` | `Mldsa65Seed` on runtime; cert patch mode | **supported** | `accepts_valid_mldsa65_seed_*`, `tests/reality_mldsa65_baseline_regression.rs` |

### 4a. `limitFallbackUpload` / `limitFallbackDownload` (separate classification)

Upstream (`REALITYConfig`, `config.proto`): rate-limit fallback traffic after N bytes (`afterBytes`, `bytesPerSec`, `burstBytesPerSec`).

| Field | Parse status | Runtime status | Policy | Test coverage |
|-------|--------------|----------------|--------|---------------|
| `limitFallbackUpload` | `Option<Value>` on `RealitySettingsObject` | Rejected at startup if present | **explicit unsupported** | `rejects_limit_fallback_upload_at_startup` |
| `limitFallbackDownload` | `Option<Value>` on `RealitySettingsObject` | Rejected at startup if present | **explicit unsupported** | `rejects_limit_fallback_download_at_startup` |

**Note:** Any non-null JSON value for these fields is rejected; rate limiting is not implemented.

---

## 5. `realitySettings` — client-only fields (must not be on server inbound)

Upstream documents these on **client outbound** `realitySettings` (see `REALITYConfig` fields `Fingerprint`, `server_name`, `public_key`, … in `config.proto`). Xray server inbound uses `privateKey` + `shortIds`; client uses `publicKey` + `shortId` + `serverName` + `fingerprint` + `spiderX` + `mldsa65Verify`.

rust-xray does **not** define typed fields for these on `RealitySettingsObject`; they deserialize into `realitySettings.extra` via `#[serde(flatten)]` and are **never** copied to `RealityInboundRuntime`.

| Field | Upstream role (client) | If present on server inbound | Policy | Test coverage |
|-------|------------------------|------------------------------|--------|---------------|
| `fingerprint` | uTLS fingerprint for outbound TLS | Startup reject if in `extra` | **explicit unsupported** | policy tests (extend as needed) |
| `serverName` | Client SNI choice | Startup reject if in `extra` | **explicit unsupported** | same |
| `password` | Legacy / unused in REALITY | Startup reject if in `extra` | **explicit unsupported** | same |
| `publicKey` | Client peer key | Startup reject if in `extra` | **explicit unsupported** | `rejects_client_only_public_key_on_inbound_reality_settings` |
| `shortId` | Client shortId (singular) | Startup reject if in `extra` | **explicit unsupported** | same |
| `mldsa65Verify` | Client ML-DSA verify key | Startup reject if in `extra` | **explicit unsupported** | `rejects_client_only_mldsa65_verify_on_inbound_reality_settings` |
| `spiderX` | Client crawl path | Startup reject if in `extra` | **explicit unsupported** | same |
| `spiderY` | Client crawl pattern (proto) | Startup reject if in `extra` | **explicit unsupported** | same |
| `masterKeyLog` | TLS key log file | Startup reject if in `extra` | **explicit unsupported** | same |

**Note:** Copy-pasting client outbound `realitySettings` onto server inbound now fails fast with a clear error.

---

## 6. `realitySettings.extra` / unknown keys

Any other JSON key (e.g. `customRealityField`, panel metadata) → `RealitySettingsObject.extra`.

| Policy | Runtime | Test coverage |
|--------|---------|---------------|
| **parsed ignored** | Not read | `preserves_unknown_fields` |

---

## 7. Compatibility deltas vs upstream (intentional or accidental)

| Topic | Upstream | rust-xray | Severity |
|-------|----------|-----------|----------|
| `dest` numeric JSON | Port → `localhost:port` | Rejected (`numeric realitySettings.dest is not supported`) | **explicit unsupported** — configs using numeric dest fail fast |
| `dest` + `target` together | `target` overwrites `dest` in Build | Both set → error | Stricter — may reject panels that set both |
| `realitySettings.type` / unix dest | Parses unix paths, `@abstract` sockets | Only string host:port normalization | **parsed ignored** / partial dest support |
| `realitySettings.xver` on dest dial | Applied to camouflage connection | Ignored | **parsed ignored** |
| `limitFallback*` | Rate limits fallback | Ignored | **parsed ignored** |
| Client fields on server inbound | Usually wrong config | Accepted into `extra` | **silent misconfiguration risk** |
| `users` vs `clients` | Aliased at build | Only `clients` typed | **parsed ignored** for `users` |
| Multiple REALITY inbounds | All started | First supported inbound; warn if >1 | **parsed but gated** | `skips_unsupported_ws_reality_inbound_and_selects_next_tcp` |

---

## 8. Test coverage index (by concern)

| Concern | Location |
|---------|----------|
| Minimal VLESS REALITY parse + runtime build | `src/config/xray.rs` `#[cfg(test)]` |
| Transport negatives (ws/grpc/xhttp/…) | `validate_reality_transport_network_*` |
| dest/target/shortIds/serverNames/privateKey | `reality_*` unit tests in `xray.rs` |
| mldsa65Seed validation | `xray.rs` + `tests/reality_mldsa65_baseline_regression.rs` |
| VLESS flow / vision | `xray.rs`, `src/vless/config.rs` |
| Fallback matrix | `src/vless/fallback.rs`, `src/main.rs` tests |
| REALITY policy (shortId, time, version) | `src/reality/session.rs`, `src/reality/decision.rs` |
| Realistic Xray JSON fixture | `scripts/live_reality_smoke/xray-compatible-server.fixture.json` + `parses_realistic_xray_vless_tcp_reality_server_config` |
| Explicit reject policy | `validate_reality_inbound_config_policy`, `rejects_*_at_startup`, `sockopt_in_stream_settings_extra_remains_valid`, `mldsa65_seed_config_still_valid_with_explicit_reject_policy` |

---

## 9. Recommended operator checklist (no code changes)

1. Server inbound must use `clients` (not `users`), `privateKey`, `shortIds`, string `dest` or exclusive `target`.
2. Do not place client outbound fields (`publicKey`, `shortId`, `fingerprint`, …) on server `realitySettings`.
3. Do not set `limitFallbackUpload` / `limitFallbackDownload` on server inbound — startup rejects them until implemented.
4. Do not rely on `sockopt`, `finalmask`, `sniffing`, or `routing` in server JSON for rust-xray behavior.
5. Use `fallbacks[].xver` (not `realitySettings.xver`) for PROXY protocol on fallback targets.
