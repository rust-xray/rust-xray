# Config Architecture

This project keeps Xray/Remnawave compatibility parsing separate from runtime construction.

## Raw Xray JSON Structs

`src/config/xray/raw.rs` owns serde-compatible shapes for panel JSON:

- top-level `XrayConfig`, `LogConfig`, `ApiConfig`, `StatsConfig`, `PolicyConfig`, `RoutingConfig`;
- inbound/outbound structs such as `InboundObject`, `StreamSettingsObject`, `VlessInboundSettings`;
- REALITY and XHTTP settings structs, including tolerant unknown-field preservation via `extra`.

This layer should stay data-only: no runtime construction, logging, socket/API bind resolution, or REALITY grouping side effects.

## Validation Layer

`src/config/xray/validate.rs`, `transport.rs`, `reality.rs`, `xhttp.rs`, `api.rs`, and `routing.rs` validate raw config and provide compatibility helpers. This layer accepts the currently supported REALITY raw/tcp and XHTTP/splithttp transport shapes, rejects unsupported runtime combinations clearly, and preserves backward-compatible re-exports through `src/config/xray/mod.rs`.

## Normalization Layer

`src/config/normalized.rs` builds `NormalizedConfig` from raw `XrayConfig`.

NormalizedConfig is built and tested for parity; runtime migration is staged.

The normalized model currently covers:

- VLESS REALITY inbounds as `VlessRealityInbound`;
- raw/tcp and XHTTP runtime transport selection as `InboundTransportConfig`;
- API inbound metadata as `NormalizedApi` / `ApiInbound`;
- DNS and routing parse results, with routing marked as parsed but not fully enforced.

Parity tests compare normalized VLESS REALITY data against the legacy `RealityInboundRuntime` path via `vless_reality_matches_runtime`.

## Runtime Layer

The accepted REALITY runtime still uses legacy `RealityInboundRuntime` from `src/config/xray/reality.rs` through `src/app.rs` and `src/reality/server.rs`. Accepted application streams are dispatched through `src/transport`:

- `RawTcp` hands the stream to the existing VLESS handler;
- `XHttp` enters the HTTP/XHTTP bridge and then invokes VLESS behind the transport boundary.

## Migration TODO

- Move `app` runtime construction from `RealityInboundRuntime` to `NormalizedConfig`.
- Keep `RealityInboundRuntime` parity tests until the migration is complete.
- Expand normalized routing only when routing/balancer runtime support is implemented.
- Keep XHTTP packet-up in shadow/skeleton status until the download side is implemented.
