# Configuration compatibility audit

This is a current, scoped audit of configuration consumed by rust-xray. It does
not claim that every Xray-core JSON shape is supported; authoritative runtime
status is in [compatibility-status.md](compatibility-status.md).

## VLESS + REALITY inbounds

| Configuration surface | Current behavior |
| --------------------- | ---------------- |
| `protocol: "vless"` | Supported for the implemented inbound runtime |
| `settings.clients` | UUID and custom string IDs; optional supported flow and level |
| `settings.decryption: "none"` | Required explicitly for unencrypted VLESS |
| `settings.decryption: "mlkem768x25519plus…"` | Supported inbound VLESS Encryption grammar |
| `settings.fallbacks` | Supported only with unencrypted VLESS; fallback selection and `xver` supported |
| `flow: ""` | Supported |
| `flow: "xtls-rprx-vision"` | Supported for TCP/direct and restricted as documented for UDP/Mux |
| `streamSettings.network: "raw"` / `"tcp"` | Supported REALITY transport aliases |
| XHTTP | Experimental supported modes only; see compatibility matrix |
| REALITY gRPC/WebSocket | Explicit startup rejection |
| `realitySettings` | Current server policy, min/max versions, short IDs, fallback limits, and `mldsa65Seed` are normalized and consumed |

Configuration that uses a VLESS Encryption key must follow the parser grammar;
the valid smoke fixtures under `scripts/live_vless_encryption_smoke/` are the
reference examples. Do not treat their fixture keys as production material.

## Routing, DNS, and API

Routing is runtime-backed: static and dynamic rules, DomainStrategy, GeoSite,
GeoIP, protocol sniffing, webhooks, and the supported balancers are compiled into
`RuntimeRouter`. The supported API surface includes StatsService, HandlerService,
RoutingService, LoggerService, ObservatoryService, optional reflection, and
direct TCP/filesystem-Unix/Linux-abstract-Unix listen modes.

Panel/Remna-shaped configuration is accepted for the implemented runtime surface;
see [remna-compat.md](remna-compat.md). Unsupported or deferred DNS behavior
(FakeDNS, DNS inbound/hijack, DoH/hostname servers) is called out in the main
matrix instead of silently presented as full DNS compatibility.

## Intentional validation limits

- Unsupported REALITY transport combinations fail at startup rather than silently
  selecting a different transport.
- VLESS Encryption and VLESS fallback configuration are mutually exclusive.
- Empty/missing VLESS `decryption` is rejected; use `"none"` when encryption is
  disabled.
- Unknown fields may be tolerated for Xray/panel parsing compatibility, but only
  documented normalized fields should be relied on at runtime.

## Verification

Configuration behavior is covered by the config, VLESS, routing, API, Remna, and
live-smoke fixtures. Run the relevant config tests after changing examples; no
production behavior was changed by this documentation audit.
