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
| REALITY pre-auth | Working | ClientHello parse, SNI allowlist, TLS 1.3 `supported_versions`, X25519 keyshare, `shortId` / `session_id` AEAD + policy |
| REALITY accepted path | Working | TLS 1.3 server handshake + application stream (live smoke) |
| TLS 1.3 accepted path | Working | AES128-GCM, AES256-GCM, CHACHA20-Poly1305 (CCM suites rejected) |
| VLESS TCP inbound | Working | UUID auth, `decryption: "none"` |
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
| StatsService API (basic) | Working | `QueryStats`, `GetStats`, `GetSysStats` when `api` block present |
| DNS engine core (cache, dedup, UDP/TCP) | Working | `DnsEngine` in-process; numeric IP servers; no system resolver on engine path |
| Mux UDP DNS (Happ baseline) | Working | `DnsEngine` via `resolve_mux_udp_dns`; numeric `:53` (e.g. `1.1.1.1:53`) |

Accepted REALITY clients **do not** fall back on handshake/VLESS failure — the
connection closes (by design).

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
| XHTTP `packet-up` over HTTP/2 | **Experimental supported** | Separate GET download + POST upload ack; official Xray 26.3.27 live smoke **PASS** (`mode_packet_up`, `mode_auto_download`) |
| XHTTP `packet-up` HTTP/1.1 chunked upload | **Experimental supported (unit smoke)** | `Transfer-Encoding: chunked` streaming upload on HTTP/1 adapter; `h1_chunked_upload_unit_smoke` **PASS**; **official Xray H1 origin interop not verified** (client uses HTTP/2 on REALITY) |
| XHTTP `stream-up` / `packet-down` / XMUX | **Unsupported / gated** | Config may parse; runtime gated (`501` / fail-fast) |
| Vision over XHTTP | **Unsupported** | Explicitly rejected at startup (`flow="xtls-rprx-vision"` over XHTTP) |

**VLESS Mux wording (accurate):** not full Xray-core Mux.Cool parity. The Happ
baseline path (Vision + Mux + numeric UDP DNS on port 53) is smoke-validated.
Domain `:53` targets, generic UDP, parallel substreams, and XUDP remain incomplete.

---

## Partial

| Area | Status | Notes |
|------|--------|-------|
| Mux.Cool frame parser | Partial | `New` / `Keep` / `End` / `KeepAlive`; TCP and UDP frame metadata parsed |
| Mux TCP substream | Partial | Single active TCP substream to freedom outbound (no parallel substreams) |
| Mux UDP DNS (domain `:53`) | Partial | Domain `:53` mux targets still closed (numeric IP DNS works) |
| Outbound routing / rules / balancers | Partial | `RoutingDnsRuntime` skeleton; freedom dial uses domain strategy only |
| Remnawave / panel configs | Partial | Config load + API + REALITY inbound; full routing execution not implemented |
| DNS engine — DoH / hostname servers | Partial | `https://` parsed; queries return explicit unsupported |
| DNS engine — `protocol: "dns"` outbound | Partial | Config tolerated; placeholder only (see [dns-future.md](./dns-future.md)) |

---

## Not Yet Implemented

| Area | Status |
|------|--------|
| Full Mux.Cool runtime | Not implemented |
| Generic UDP over VLESS Mux (non-DNS / non-`:53`) | Not implemented |
| UDP over VLESS (non-Mux `command=Udp`) | Not implemented |
| XUDP | Not implemented |
| Full UDP mux relay (all destinations / parallel substreams) | Not implemented |
| DNS UDP relay inside Mux (domain names without resolver) | Not implemented |
| Full routing / rules / balancers | Not implemented |
| Full outbound ecosystem | Not implemented |
| FakeDNS | Not implemented |
| DNS inbound / dokodemo-door hijack | Not implemented |
| Full Xray DNS module compatibility | Not implemented |
| XHTTP `stream-up` / `packet-down` / XMUX | Unsupported / gated (config parses; runtime fail-fast `501`) |
| XHTTP XUDP over XHTTP | Not implemented |
| REALITY over gRPC / WebSocket runtime | Not implemented (configs rejected at startup) |
| DoH through outbound | Not implemented |
| DNS-over-TCP through VLESS outbound / routing | Not implemented (see [dns-future.md](./dns-future.md)) |
| Vision splice / zero-copy beyond DIRECT MVP | Not implemented |
| ML-KEM / hybrid KEM on REALITY handshake | Not implemented (separate from ML-DSA-65; see [design doc](./reality-mlkem-design.md)) |
| Full Xray-core drop-in compatibility | Not implemented |

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

**Remaining gaps (not baseline blockers):**

- Domain `:53` mux destinations (resolver hook)
- Generic UDP over Mux (non-DNS ports)
- Full Mux.Cool runtime (parallel substreams, full frame lifecycle)
- XUDP

---

## Next Milestone

1. **Domain `:53` mux destinations** — resolver hook without claiming full DNS module.
2. **Generic UDP over Mux** — beyond port-53 DNS baseline.
3. **Full Mux.Cool runtime** — parallel substreams, complete frame lifecycle.
4. Keep REALITY/Vision/fallback/API/Happ-baseline smoke green (`aes_gcm_decrypt_failed=0`, ML-DSA-65 baseline).

---

## Smoke / regression anchors

| Suite | Command | Covers |
|-------|---------|--------|
| Live REALITY smoke | `make live-smoke` | Vision, fallback matrix, ciphers, ML-DSA-65, Happ mux UDP DNS baseline, transport negatives (`grpc` / `ws` + REALITY rejected; `xhttp` accepted for experimental XHTTP) |
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
| `mode_auto_download` | PASS |
| `mode_stream_up` | UNSUPPORTED |
| `mode_packet_down` | UNSUPPORTED (expected client config parse fail) |
| `h1_chunked_upload_unit_smoke` | PASS |
| Official Xray H1 chunked interop | **Not verified** |

Last full live smoke report on `experiment` (local): Vision sequential/parallel/download PASS,
fallback default/SNI/path/ALPN/xver PASS, ML-DSA-65 checks 4/4,
Happ mux UDP DNS baseline PASS (`mux udp dns engine query started`, `mux udp dns engine response sent`,
`dns query start`), `aes_gcm_decrypt_failed=0`.
