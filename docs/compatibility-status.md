# Compatibility Status

**Branch:** `experiment`  
**Upstream reference:** [XTLS/Xray-core](https://github.com/XTLS/Xray-core)  
**Rust port:** [rust-xray/rust-xray](https://github.com/rust-xray/rust-xray)

This document reflects **observed runtime behavior** on the current branch (live
smoke, Remna API smoke, and Happ Proxy Utility traces). It is not a marketing
checklist and does not claim production-ready or full Xray-core drop-in parity.

**Related docs**

- [Live REALITY smoke](../scripts/live_reality_smoke/README.md) — automated matrix
- [Remna / Remnawave smoke](./remna-compat.md) — gRPC API + panel-like configs
- [Config compatibility audit](./config-compatibility-audit.md) — field-level parse policy
- [REALITY ML-DSA-65 runtime baseline](./reality-mldsa65-runtime-baseline.md) — PQ cert signing smoke
- [REALITY accepted path (developer notes)](./reality-accepted-path.md) — handshake internals
- [XHTTP compatibility notes](./xhttp-compat-notes.md) — XHTTP server-side behavior
- [DNS future work](./dns-future.md) — dokodemo-door, hijack, FakeDNS (TODO)

---

## Working

| Area | Status | Notes |
|------|--------|-------|
| REALITY TCP/raw inbound | Working | `streamSettings.network`: `raw` or legacy `tcp` |
| REALITY pre-auth | Working | ClientHello parse, SNI allowlist, TLS 1.3 `supported_versions`, X25519 keyshare (standalone **or** `X25519MLKEM768` hybrid carrier for auth), `shortId` / `session_id` AEAD + policy. Regression: `tests/upstream_compat_vectors.rs`, `tests/unit/reality/key_share.rs`. |
| REALITY `minClientVer` default | Working | Xray-core af7eb68 semantics: omitted or `""` → effective `26.3.27`; explicit value (including `"0.0.0"`) overrides. Does **not** imply every third-party REALITY client is accepted — see [README policy matrix](../README.md#reality-server-minclientver-xray-core-compatibility). Regression: `tests/upstream_compat_vectors.rs`. |
| REALITY accepted path | Working | TLS 1.3 server handshake + application stream (live smoke) |
| REALITY post-handshake record detection (Stage 5B) | Working | Proactive `dest × serverName × ALPN` probes; typed cache; post-client-Finished camouflage emission |
| REALITY post-handshake CCS tolerance (Stage 5C) | Working | Proactive `dest × serverName × ALPN` CCS tolerance probes; typed cache; accepted-path `readClientFinished` uses default `Finite(32)`; detected tolerance applies after verified client Finished on the application stream (`Finite(1/16/32)` / `Unlimited`). |
| REALITY useless-record overflow TLS alert (Stage 7) | Working | On accepted TLS 1.3 path, consecutive useless-record overflow emits one encrypted fatal `unexpected_message` alert (best-effort) then returns `too many ignored records`. Covers `readClientFinished`, pre-VLESS parse, standard TCP relay, Vision TCP relay, and REALITY Mux (including Vision+Mux). **Partial:** general TLS alert parity outside this overflow case remains incomplete. |
| REALITY fallback rate limits (Stage 6) | Working | `limitFallbackUpload` / `limitFallbackDownload` on pre-auth fallback relay only; juju/ratelimit v1.0.2-compatible token bucket. **Partial parity:** no upstream `MirrorConn` ClientHello mirroring timing; no upstream `s2cSaved` download prebuffer — limiter starts at post-initial relay boundary. Accepted REALITY/VLESS traffic is never rate-limited. |
| TLS 1.3 accepted path | Working | AES128-GCM, AES256-GCM, CHACHA20-Poly1305 (CCM suites rejected) |
| VLESS TCP inbound | Working | UUID auth, explicit `decryption: "none"` required (empty/missing rejected at startup) |
| Custom string VLESS ID | Working | UUIDv5 mapping (Xray-compatible) |
| VLESS flow `""` | Working | Plain TCP relay via freedom outbound |
| VLESS flow `xtls-rprx-vision` | Working | Vision DIRECT MVP (padding + `COMMAND_DIRECT`) |
| Fallback default | Working | Live smoke |
| Fallback by SNI/name | Working | Live smoke |
| Fallback by HTTP path | Working | Plain HTTP preamble + TLS inspect fallback |
| Fallback by ALPN `http/1.1` / `h2` | Working | Live smoke |
| Fallback `xver=1` PROXY v1 | Working | Live smoke |
| Fallback `xver=2` PROXY v2 | Working | Live smoke + golden vector |
| Network alias `raw` / legacy `tcp` | Working | Same REALITY TCP runtime |
| StatsService API | Working | All seven RPCs when `api` block present; atomic counter reset; OnlineMap refcount; seven policy flags default false until `policy` enables them; online IP from TCP peer through all transports including XHTTP; dynamic users use level policy automatically; `GetSysStats` Go-runtime fields N/A in Rust (Stage 8B) |
| Xray gRPC API foundation (Stage 8A) | Working | Canonical protobuf/service registration, direct `api.listen` (TCP / filesystem Unix / Linux abstract `@name`), optional reflection, plaintext default (TLS/mTLS on direct listen = rust-xray extension), shared runtime state wiring (`StatsRegistry`, `InboundUserManagers`) |
| Commander API transport (Stage 8E5-A) | Working | `api.tag` required; `api.services` case-insensitive with unknown entries ignored; empty service list allowed; `api.listen != ""` binds direct listener without replacing same-tag outbound; `api.listen == ""` internal Commander outbound (bounded queue capacity 4, no network listener); Commander outbound hidden from `HandlerService.ListOutbounds`; duplicate recognized service entries fail startup (safe divergence — upstream allows duplicate config entries but tonic router rejects duplicate routes) |
| HandlerService (Stage 8E1) | Working | Full current `HandlerService` RPC surface runtime-backed via `RuntimeInboundManager` / `RuntimeOutboundManager`; dynamic VLESS+REALITY inbound, freedom/blackhole outbound; merged logical inbound auth identity; no config file rewrite |
| RoutingService (Stage 8E2–8E4) | Working | All seven RPCs runtime-backed via `RuntimeRouter`; static JSON + dynamic `AddRule`/`RemoveRule`; VLESS TCP dispatch uses same router; webhook rules fire after route selection; GeoSite/GeoIP; balancers (`random`, `roundRobin`, `leastPing`, `leastLoad` algorithms). `DomainStrategy`: `IpOnDemand` lazily resolves target DNS when an IP condition needs target IP; `IpIfNonMatch` runs first pass without forced DNS, resolves once if no rule matches, then second pass. Live Observatory health wired for `leastPing`/`leastLoad` and random/roundRobin fallback health filtering (Stage 8E4-C) |
| LoggerService (Stage 8E3) | Working | Canonical `RestartLogger` RPC; runtime-backed sink reopen from in-memory config; file rotation reopen proven via tonic E2E. Legacy `v2ray.core.app.log.command.LoggerService` alias (Stage 8E5-B) |
| Legacy `v2ray.core.*` gRPC service aliases (Stage 8E5-B) | Working | Runtime route aliases only (no legacy protobuf descriptors): `HandlerService`, `StatsService`, `RoutingService`, `LoggerService` each register canonical + legacy names when the corresponding `api.services` entry is enabled; `ObservatoryService` has **no** legacy alias (upstream parity). Reflection `list_services` includes legacy names; `file_containing_symbol` for legacy symbols intentionally returns not-found while canonical symbols resolve. Legacy route RPCs work via grpcurl/Xray CLI when reflection resolves the request through canonical descriptors (upstream parity: legacy `describe` fails; legacy grpcurl invoke also fails on upstream Xray 26.7.28 when reflection cannot resolve legacy symbols) |
| grpcurl API interoperability (Stage 8E5-C) | Working | Plaintext direct `api.listen`; reflection v1 + v1alpha; canonical `list`/`describe`/RPC matrix; legacy service names listed; legacy `describe` not-found parity; env-gated `tests/api_external_interop.rs` (`GRPCURL_BIN`) |
| Xray CLI API interoperability (Stage 8E5-C) | Working | Upstream `xray api` against plaintext TCP listener: stats (`statssys`, `stats`, `statsquery`, online commands), Handler CRUD/users (`lsi`, `lso`, `inbounduser`, `inboundusercount`, `adu`, `rmu`, `adi`, `rmi`, `ado`, `rmo`), routing (`bi`, `bo`, `adrules`, `rmrules`, `lrules`), `restartlogger`, `sib`; dynamic mutations affect live data plane; env-gated `tests/api_external_interop.rs` (`XRAY_UPSTREAM_BIN`) |
| ObservatoryService (Stage 8E4) | Working | Canonical `xray.core.app.observatory.command.ObservatoryService` with `GetOutboundStatus`; standard Observatory runtime probes selected outbounds via tagged outbound dispatch; BurstObservatory HealthPing ring-buffer statistics (`health_ping` populated, timestamps zero); background worker from JSON `observatory` / `burstObservatory` blocks independent of API service mount. When both blocks are configured, both runtimes start; active health provider for routing/API resolves standard Observatory first (upstream first-feature lookup). Live `leastPing`/`leastLoad`/random/roundRobin health filtering wired via shared `OutboundHealthProvider` (Stage 8E4-C) |
| Outbound routing / rules / balancers | Working | `RuntimeRouter` shared by VLESS data-plane + `RoutingService`; `DomainStrategy` `AsIs` / `IpOnDemand` / `IpIfNonMatch`; GeoSite/GeoIP matchers; webhook; balancer override/fallback. Health-dependent balancers (`leastPing`, `leastLoad`, `random`/`roundRobin` with `fallbackTag`) require configured Observatory (standard or burst) at router compile time, matching current Xray feature dependency semantics; `random`/`roundRobin` without `fallbackTag` do not require Observatory. **Default outbound:** first registered outbound; after default removal, next earliest registered outbound becomes default (rust-xray extends upstream, which clears default without reassignment). **Missing `outboundTag`:** upstream allows at config load; rust-xray matches — rule compiles, connect fails at runtime with structured `NotFound` diagnostics. **Zero outbounds:** startup allowed (API/dynamic configs); one-time `warn` when no outbounds registered at listener startup |
| DNS engine core (cache, dedup, UDP/TCP) | Working | `DnsEngine` in-process; numeric IP servers; no system resolver on engine path |
| Mux UDP DNS (Happ baseline) | Working | `DnsEngine` via `resolve_mux_udp_dns`; numeric `:53` (e.g. `1.1.1.1:53`) |

Accepted REALITY clients **do not** fall back on handshake/VLESS failure — the
connection closes (by design).

### gRPC API services (Stages 8A–8E5)

| Service | Status |
|---------|--------|
| `ReflectionService` | Working (optional; registers `grpc.reflection.v1` + `grpc.reflection.v1alpha`, matching grpc-go `reflection.Register`) |
| `StatsService` | Working (canonical + legacy `v2ray.core.app.stats.command.StatsService` alias) |
| `HandlerService` | Working (canonical + legacy `v2ray.core.app.proxyman.command.HandlerService` alias) |
| `RoutingService` | Working (canonical + legacy `v2ray.core.app.router.command.RoutingService` alias; server-streaming alias parity) |
| `LoggerService` | Working (canonical + legacy `v2ray.core.app.log.command.LoggerService` alias) |
| `ObservatoryService` | Working (canonical only; no legacy alias) |
| grpcurl interoperability | Working (Stage 8E5-C) |
| Xray CLI interoperability | Working (Stage 8E5-C) |

Remaining API work: Remna unix-abstract E2E (Stage 8D where applicable).

---

## Experimental

| Area | Status | Notes |
|------|--------|-------|
| VLESS `command=Mux` (Happ baseline) | **Experimental working** | REALITY → TLS 1.3 → VLESS auth → `command=Mux` → response header → mux session start; live smoke + Happ traces |
| UDP DNS over VLESS Mux (port 53) | **Experimental working** | `DnsEngine` cache/UDP transport; logs `mux udp dns engine query started` / `response sent` |
| Outbound domain resolve (`UseIP` / `UseIPv4` / `UseIPv6`) | **Experimental** | Freedom connect uses `DnsEngine.lookup_ip` when `routing.domainStrategy` or `dns.queryStrategy` requires it |
| Happ Proxy Utility baseline | **Experimental working** | REALITY/VLESS/Vision/Mux path reaches mux session; UDP DNS inside Mux works for numeric `:53` (live smoke validated) |
| ML-DSA-65 baseline | **Experimental** | Valid `mldsa65Seed` accepted; invalid seed rejected at startup; raw Vision smoke passes; no cargo feature gate (see [baseline doc](./reality-mldsa65-runtime-baseline.md)) |
| REALITY + XHTTP `stream-one` | **Experimental supported** | HTTP/1.1 / HTTP/2 POST over accepted REALITY TLS stream; official Xray 26.3.27 interop smoke PASS for default / `auto` / `stream-one` over HTTP/2; VLESS `flow=""` only |
| XHTTP `stream-up` over HTTP/2 | **Experimental supported** | GET download + POST upload on `/xhttp/{session}`; official Xray 26.3.27 live smoke **PASS** (`mode_stream_up`) |
| XHTTP `packet-up` over HTTP/2 | **Experimental supported** | Separate GET download + POST upload ack; official Xray 26.3.27 live smoke **PASS** (`mode_packet_up`, `mode_auto_download`) |
| XHTTP `packet-up` HTTP/1.1 chunked upload | **Experimental supported (unit smoke)** | `Transfer-Encoding: chunked` streaming upload on HTTP/1 adapter; `h1_chunked_upload_unit_smoke` **PASS**; **official Xray H1 origin interop not verified** (client uses HTTP/2 on REALITY) |
| XHTTP `packet-down` / XMUX | **Unsupported / gated** | Config may parse; runtime gated (`501` / fail-fast) |
| Vision over XHTTP | **Unsupported** | Explicitly rejected at startup (`flow="xtls-rprx-vision"` over XHTTP) |

**VLESS Mux wording (accurate):** Happ baseline path (Vision + Mux + numeric UDP DNS on
port 53) is smoke-validated. **Stage 4F:** parallel TCP mux substreams, generic Mux UDP,
native UDP, and XUDP are implemented on the forward inbound path. Domain `:53` mux DNS
fast-path (bypasses router) remains an intentional divergence — see forward matrix below.

---

## Forward VLESS Inbound Feature Matrix (Stage 4F)

Upstream baseline: `cd4ce973e9f6ef3a7acf9a7030927b4143f9ea47` (`XTLS/Xray-core` main).

| Feature | Upstream | rust-xray | Coverage | Status | Notes |
|---------|----------|-----------|----------|--------|-------|
| UUID auth | Wire UUID in request | Wire UUID for routing/logs | unit + live | PARITY | |
| ProcessUUID | Zeros bytes 6–7 for lookup | `vless_lookup_uuid()` | unit | PARITY | Wire UUID preserved for routing |
| TCP | Supported | Supported | unit + live | PARITY | |
| UDP (native) | Supported | Supported | unit + live | PARITY | |
| Mux TCP | Supported | Supported | unit + live | PARITY | |
| Parallel Mux | Supported | HashMap + split readers | unit | PARITY | Bounded downlink queue (32) |
| Generic Mux UDP | Supported | Persistent associations | unit + live | PARITY | |
| XUDP | Supported | Supported | unit + live | PARITY | |
| Vision TCP | Supported | Supported | unit + live | PARITY | |
| Vision native UDP | Rejected | Rejected | unit | PARITY | |
| Vision Mux/XUDP | Mux non-XUDP rejected early | `is_mux_and_not_xudp()` at VLESS layer | unit | PARITY | |
| testseed | Per-account, default `[900,500,900,256]` | Config + HandlerService proto field | unit | PARITY | |
| Addons Flow | Parsed | Parsed | unit | PARITY | |
| Addons Seed | Unused at runtime | Not consumed | audit | NOT APPLICABLE | Upstream inbound does not use |
| response header | `[version, 0]` | `[version, 0]` | unit | PARITY | |
| handshake timeout | Policy level 0 (default 4s) | `VlessInboundPolicy` on header read | unit | PARITY | Encryption uses separate 60s window |
| user level | Stored; policy hooks | Stored; level not wired to traffic policy yet | audit | SUPPORTED | Handshake uses level `"0"` pre-auth |
| dynamic AddUser | HandlerService | HandlerService | unit + API | PARITY | Includes testseed when set in proto |
| dynamic RemoveUser | HandlerService | HandlerService | unit + API | PARITY | Normalized lookup key |
| decryption none | Required explicit | Required explicit | unit | PARITY | |
| Encryption 1RTT | Supported | Supported | unit + live | PARITY | Stage 4C–4D |
| Encryption 0RTT | Supported | Supported | unit + live | PARITY | Stage 4E.1 |
| native/xorpub/random | Supported | Supported | unit + live | PARITY | |
| REALITY transport | Supported | Supported | live | PARITY | VLESS semantics shared post-TLS |
| raw TCP transport | Supported | Supported | live | PARITY | |
| XHTTP transport | Full upstream | MVP stream-one/up/packet-up | live | TRANSPORT GAP | VLESS parser shared once stream arrives |
| xtls-rprx-vision-udp443 | Outbound-oriented | N/A | audit | NOT APPLICABLE | Forward inbound |
| DNS fast path (Mux :53) | Router-integrated | Direct `DnsEngine` | unit | INTENTIONAL DIVERGENCE | Observable routing skip for numeric :53 |

**Forward inbound verdict (Stage 4F):** core matrix green; XHTTP transport remains MVP;
user `level` traffic policy not fully wired.

---

## Partial

| Area | Status | Notes |
|------|--------|-------|
| RemnaNode 3.3.2 E2E (Stage 8D) | Partial | StatsService parity implemented; unix-abstract API tunnel integration pending Stage 8D |
| Mux.Cool frame parser | Working | `New` / `Keep` / `End` / `KeepAlive`; TCP and UDP frame metadata parsed |
| Mux TCP substreams | Working | Parallel TCP children via split readers + bounded downlink channel (Stage 4F) |
| Mux UDP DNS (domain `:53`) | Partial | Domain `:53` mux targets still closed (numeric IP DNS works); numeric :53 uses DNS fast-path |
| Remnawave / panel configs | Partial | Config load + API + REALITY inbound + routing execution for supported conditions. GeoSite/GeoIP routing supported. `attributes` production extraction remains unavailable. Remote process metadata is generally unavailable for VLESS clients. Remna unix-abstract E2E remains pending |
| Routing rule metadata gaps | Partial | `attributes`: compiler/`TestRoute` supported; production extraction missing. `process`: compiler/`TestRoute` supported; remote VLESS has no process identity. `local_os`: canonical field 23 supported |
| DNS engine — DoH / hostname servers | Partial | `https://` parsed; queries return explicit unsupported |
| DNS engine — `protocol: "dns"` outbound | Partial | Config tolerated; placeholder only (see [dns-future.md](./dns-future.md)) |
| General logging config | Partial | `LoggerService.RestartLogger` works for supported sinks; `dnsLog` behavior, `maskAddress`, and JSON `loglevel` → filter mapping incomplete |
| VLESS Encryption foundation (Stage 4B) | Working | `mlkem768x25519plus` config grammar, validation, NFS key parsing, X25519/ML-KEM-768/Blake3/AEAD/nonce/xor/random/padding primitives implemented and unit-tested |
| VLESS Encryption 1-RTT handshake (Stage 4C) | Working | Inbound `VlessEncryptionServer` 1-RTT `mlkem768x25519plus` server handshake (NFS chain, PFS, UnitedKey, ticket issuance, prefix preservation) |
| VLESS Encryption traffic + inbound runtime (Stage 4D–4F) | Working | 1-RTT + 0-RTT forward inbound matrix green (TCP/Vision/Mux/XUDP/UDP/xorpub/random). **Not yet:** outbound encryption, reverse/Rvs |

---

## Not Yet Implemented

| Area | Status |
|------|--------|
| Full Mux.Cool runtime | Partial | Parallel TCP substreams (4F); session ID duplicate-New replaces prior child (documented) |
| Generic UDP over VLESS Mux (non-DNS / non-`:53`) | Working | Stage 4F — persistent generic Mux UDP associations |
| UDP over VLESS (non-Mux `command=Udp`) | Working | Stage 4F — native UDP framing + relay |
| XUDP | Working | Stage 4F — GlobalID, reattach, expiry |
| Full UDP mux relay (all destinations / parallel substreams) | Partial | Parallel TCP done; domain `:53` DNS fast-path divergence |
| DNS UDP relay inside Mux (domain names without resolver) | Not implemented |
| Live observatory-backed balancer health | Working (Stage 8E4-C) — `RuntimeRouter` receives active Observatory `OutboundHealthProvider`; `leastPing`/`leastLoad` and random/roundRobin fallback health filtering use live snapshots |
| BurstObservatory / HealthPing | Working (Stage 8E4-B) — tagged probes, ring buffer, All/Fail/Average/Deviation/Min/Max, connectivity check semantics, canonical `GetOutboundStatus` with `health_ping` |
| Full outbound ecosystem | Not implemented |
| FakeDNS | Not implemented |
| DNS inbound / dokodemo-door hijack | Not implemented |
| Full Xray DNS module compatibility | Not implemented |
| XHTTP `packet-down` / XMUX | Unsupported / gated (config parses; runtime fail-fast `501`) |
| XHTTP XUDP over XHTTP | Not implemented |
| REALITY over gRPC / WebSocket runtime | Not implemented (configs rejected at startup) |
| DoH through outbound | Not implemented |
| DNS-over-TCP through VLESS outbound / routing | Not implemented (see [dns-future.md](./dns-future.md)) |
| Vision splice / zero-copy beyond DIRECT MVP | Not implemented |
| REALITY probe uTLS ClientHello fingerprint parity (`HelloGolang` / `HelloChrome`) | Not implemented — probes use rustls default ClientHello (**partial** parity for Stage 5B record-length and Stage 5C extra-CCS tolerance probing) |
| REALITY post-handshake `GlobalMaxCSSMsgCount` / alert-driven CCS probe paths (Stage 5C extras) | Not implemented |
| REALITY session resumption on accepted path | Not implemented |
| ML-KEM / hybrid KEM on REALITY **accepted TLS handshake** | Not implemented | Stage 2 adds **pre-auth only**: parse `X25519MLKEM768` ClientHello `key_share` (1216 B) and extract trailing X25519 for REALITY auth. **Not yet:** ML-KEM-768 encaps/decaps, hybrid ServerHello, 64-byte TLS shared secret, dest `key_share` mirroring. See [design doc](./reality-mlkem-design.md). |
| VLESS Encryption runtime inbound (4C–4F) | Working | Forward inbound 1-RTT + 0-RTT. **Not yet:** outbound client encryption |
| Full Xray-core drop-in compatibility | Not implemented |
| Final API config compatibility closure | Working (Stage 8E5) | Commander semantics, legacy aliases, reflection parity, grpcurl + Xray CLI interoperability validated against upstream Xray 26.7.28 (`c1958db`). Safe divergences: duplicate recognized `api.services` entries fail startup; `GetSysStats` Go-runtime memory/goroutine fields zero/N/A; optional direct-listen TLS/mTLS is rust-xray extension; legacy reflection `describe`/grpcurl invoke limitation matches upstream |

**DNS clarification:** Built-in `DnsEngine` serves Mux UDP DNS and optional freedom
outbound resolve (`UseIP` / `UseIPv4` / `UseIPv6`). It does **not** replace full Xray DNS
(routing rules, FakeDNS, dokodemo-door, DNS outbound egress). Happ baseline still uses
**UDP DNS inside VLESS Mux** to numeric `:53` (e.g. `1.1.1.1:53`).

---

## Current Happ Status

Happ Proxy Utility (live traces + live smoke) typically reaches:

```text
REALITY TCP accept
  → TLS ClientHello / REALITY pre-auth
  → REALITY accepted path (TLS 1.3)
  → VLESS auth OK
  → command=Mux
  → VLESS response header sent
  → mux relay started / mux session started
  → Mux UDP frames (network=udp, destination=1.1.1.1:53, status=0x01 New, status=0x02 packet)
  → mux udp dns engine query started
  → dns query start / dns upstream response received
  → mux udp dns engine response sent
```

**Baseline status:** Happ-compatible REALITY/VLESS/Vision/Mux path with **numeric UDP
DNS on port 53** is **experimental working** (live smoke: `PASS happ reality vision
mux udp dns`, `PASS vless mux udp dns 1.1.1.1:53`).

**Remaining gaps (not forward-inbound blockers):**

- Domain `:53` mux destinations (resolver hook; numeric :53 DNS fast-path divergence)
- XHTTP transport MVP (gRPC/ws not supported at startup)
- User `level` traffic policy wiring beyond handshake timeout baseline

---

## Next Milestone

**Stage 8D — RemnaNode 3.3.2 E2E / unix-abstract tunnel**

Stage 8E5 (API compatibility closure) is complete:

1. ~~Commander `api.tag` / `listen` / `services` transport semantics~~ (Stage 8E5-A)
2. ~~Legacy `v2ray.core.*` service aliases + reflection quirks~~ (Stage 8E5-B)
3. ~~grpcurl + Xray CLI API interoperability~~ (Stage 8E5-C)
4. Remna unix-abstract E2E (Stage 8D)
5. Keep the fully-green `cargo test` baseline

---

## Smoke / regression anchors

| Suite | Command | Covers |
|-------|---------|--------|
| Live REALITY smoke | `make live-smoke` | Vision, fallback matrix, ciphers, ML-DSA-65, Happ mux UDP DNS baseline, unsupported UDP/XUDP probes with TCP regressions, transport rejection checks (`grpc` / `ws` + REALITY rejected; `xhttp` accepted for experimental XHTTP) |
| Live XHTTP smoke | `bash scripts/live_xhttp_smoke/run-live-xhttp-smoke.sh` | Official Xray 26.3.27 interop matrix + `h1_chunked_upload_unit_smoke` (see [XHTTP smoke README](../scripts/live_xhttp_smoke/README.md)) |
| Remna compat | `bash scripts/remna_compat/run-local-api-smoke.sh` | gRPC StatsService, panel fixture load |
| Config audit tests | `cargo test` | Parse policy, fallback selection unit tests |

### Confirmed XHTTP smoke matrix (`experiment`)

| Check | Result |
|-------|--------|
| `mode_default` | PASS |
| `mode_auto` | PASS |
| `mode_stream_one` | PASS |
| `mode_packet_up` (HTTP/2, official Xray 26.3.27) | PASS |
| `mode_stream_up` (HTTP/2, official Xray 26.3.27) | PASS |
| `mode_auto_download` | PASS |
| `mode_packet_down` | UNSUPPORTED (expected client config parse fail) |
| `h1_chunked_upload_unit_smoke` | PASS |
| Official Xray H1 chunked interop | **Not verified** |

Last full live smoke report on `experiment` (local): Vision sequential/parallel/download PASS,
fallback default/SNI/path/ALPN/xver PASS, ML-DSA-65 checks 4/4,
Happ mux UDP DNS baseline PASS (`mux udp dns engine query started`, `mux udp dns engine response sent`,
`dns query start`), `aes_gcm_decrypt_failed=0`.
