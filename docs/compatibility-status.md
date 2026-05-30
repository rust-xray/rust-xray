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
| ML-DSA-65 baseline | **Experimental** | Valid `mldsa65Seed` accepted; invalid seed rejected at startup; raw Vision smoke passes; no cargo feature gate (see [baseline doc](./reality-mldsa65-runtime-baseline.md)) |

Accepted REALITY clients **do not** fall back on handshake/VLESS failure — the
connection closes (by design).

---

## Partial

| Area | Status | Notes |
|------|--------|-------|
| VLESS `command=Mux` | Partial | Command accepted; VLESS response header sent; mux relay + session start |
| Mux.Cool frame parser | Partial | `New` / `Keep` / `End` / `KeepAlive`; TCP and UDP frame metadata |
| Mux TCP substream | Partial | Single active TCP substream to freedom outbound (no parallel substreams) |
| Mux UDP DNS (port 53) | Partial | Frames parsed; direct UDP relay attempted for **numeric** `:53` targets only; domain `:53` needs resolver (substream closed) |
| Remnawave / panel configs | Partial | Config load + API + REALITY inbound; routing/rules/balancers not executed |
| Happ Proxy Utility | **Blocked on Mux UDP** | Reaches mux session; UDP DNS inside Mux not fully relayed (see below) |

**VLESS Mux wording (accurate):** partial parser and session support exist. UDP
DNS over Mux is parsed and logged; full Happ-compatible UDP mux relay is **not**
complete.

---

## Not Yet Implemented

| Area | Status |
|------|--------|
| UDP over VLESS (non-Mux command) | Not implemented |
| Full UDP mux relay (all destinations / parallel substreams) | Not implemented |
| DNS UDP relay inside Mux (domain names, resolver integration) | Not implemented |
| XUDP | Not implemented |
| Full Mux.Cool runtime | Not implemented |
| Full routing / rules / balancers | Not implemented |
| Full outbound ecosystem | Not implemented |
| REALITY over XHTTP / gRPC / WebSocket runtime | Not implemented (configs rejected at startup) |
| DoH through outbound | Not implemented |
| Full DNS module compatibility | Not implemented |
| Vision splice / zero-copy beyond DIRECT MVP | Not implemented |
| ML-KEM / hybrid KEM on REALITY handshake | Not implemented (separate from ML-DSA-65; see [design doc](./reality-mlkem-design.md)) |
| Full Xray-core drop-in compatibility | Not implemented |

**DNS clarification:** DNS-over-TCP through a future DNS/outbound module is a
**separate** task. It does **not** by itself solve Happ's current path, which
uses **UDP DNS inside VLESS Mux** (`network=udp`, destination `:53`).

---

## Current Happ Status

Happ Proxy Utility (live traces) typically reaches:

```text
REALITY TCP accept
  → TLS ClientHello / REALITY pre-auth
  → REALITY accepted path (TLS 1.3)
  → VLESS auth OK
  → command=Mux
  → VLESS response header sent
  → mux relay started / mux session started
  → Mux UDP frames parsed (e.g. network=udp, destination=1.1.1.1:53, status=0x01 New, status=0x02 packet)
```

**Current blocker:** UDP mux substream is not fully relayed for Happ. rust-xray
parses Mux UDP frames but closes or short-circuits the substream when full UDP
DNS relay (especially domain `:53` via resolver) is unavailable. This is **not**
fixed by DNS-over-TCP outbound alone.

**Not the primary Happ blocker:** plain VLESS TCP, Vision DIRECT, or REALITY
fallback matrix (those paths are smoke-validated separately).

---

## Next Milestone

1. **Minimal VLESS Mux UDP DNS relay for port 53** — numeric and domain targets,
   single-substream Happ path, response frames back on the mux session.
2. Resolver hook for `Domain:53` mux destinations (without claiming full DNS module).
3. Keep REALITY/Vision/fallback/API smoke green (`aes_gcm_decrypt_failed=0`, ML-DSA-65 baseline).

---

## Smoke / regression anchors

| Suite | Command | Covers |
|-------|---------|--------|
| Live REALITY smoke | `make live-smoke` | Vision, fallback matrix, ciphers, ML-DSA-65, transport negatives |
| Remna compat | `bash scripts/remna_compat/run-local-api-smoke.sh` | gRPC StatsService, panel fixture load |
| Config audit tests | `cargo test` | Parse policy, fallback selection unit tests |

Last full live smoke report on `experiment` (local): Vision sequential/parallel/download PASS,
fallback default/SNI/path/ALPN/xver PASS, ML-DSA-65 checks 4/4, `aes_gcm_decrypt_failed=0`.
