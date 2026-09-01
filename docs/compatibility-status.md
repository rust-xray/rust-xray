# Compatibility status

**Branch:** `experiment`<br>
**rust-xray baseline:** `f054aa83bd0d09a6e3fddca624e8b2f9b71cc44b`<br>
**Xray-core reference:** [XTLS/Xray-core](https://github.com/XTLS/Xray-core)
`main` at `cd4ce973e9f6ef3a7acf9a7030927b4143f9ea47`

This is the authoritative, current feature-status document. It records observed
code and test/harness behavior, not an assertion of production readiness, full
parity, or drop-in compatibility.

## Scope

`Working` means the named rust-xray inbound/runtime behavior exists. `LIVE PASS`
means a repository harness exercises it with local networking and, where stated,
an upstream client. `DETERMINISTIC PASS` means unit or deterministic integration
coverage only. `REJECTED BY PROTOCOL` is an intentional validated rejection.

## VLESS inbound

| Feature | Status | Verification | Notes |
| ------- | ------ | ------------ | ----- |
| TCP | Working | LIVE PASS | Shared transport/routing dispatch |
| UUID authentication | Working | unit + live | Xray-compatible request UUID lookup |
| Custom string ID | Working | unit + live | UUIDv5 mapping |
| `flow=""` | Working | LIVE PASS | Standard TCP relay |
| `xtls-rprx-vision` TCP | Working | LIVE PASS | Padding/unpadding and `COMMAND_DIRECT` relay |
| Native `command=Udp` | Working | LIVE PASS | Persistent framed UDP relay; IP/domain destinations |
| Mux TCP | Working | LIVE PASS | Mux.Cool TCP children |
| Parallel Mux TCP | Working | DETERMINISTIC PASS | Split readers and bounded downlink queue |
| Generic Mux UDP | Working | LIVE PASS | Persistent per-SessionID associations, IP/domain destinations |
| XUDP | Working | LIVE PASS | GlobalID and reattach lifecycle |
| DNS fast path | Working | LIVE PASS + unit | Numeric Mux `:53` handled by `DnsEngine` |
| HandlerService dynamic users | Working | unit + API | Add/remove VLESS users without config rewrite |

Forward VLESS inbound is substantially implemented; final parity closure remains
pending. The current known exceptions are listed below rather than hidden behind
a broad parity claim.

## VLESS Encryption

| Feature | Status | Verification | Notes |
| ------- | ------ | ------------ | ----- |
| `mlkem768x25519plus` inbound | Working | unit + upstream vectors | Validated parser and NFS key chain |
| Modes: `native`, `xorpub`, `random` | Working | unit + LIVE PASS | Appearance modes do not replace authentication |
| 1RTT | Working | LIVE PASS | X25519 + ML-KEM-768 PFS, ticket issuance, CommonConn |
| 0RTT | Working | LIVE PASS TCP + deterministic matrix | Stored server session state and CommonConn reuse |
| Ticket/session cache | Working | unit | Bounded to 1024 sessions; expiry pruning |
| Replay protection | Working | unit | Per-ticket exact NFS replay key; fresh valid NFS may reuse ticket |
| TCP / Vision | Working | LIVE PASS | Vision direct is blocked so encryption is never bypassed |
| Mux TCP / generic Mux UDP / XUDP | Working | LIVE PASS 1RTT + deterministic 0RTT | Encryption-transparent transport dispatch |
| Native UDP | Working | LIVE PASS 1RTT + deterministic 0RTT | Vision native UDP remains rejected |
| VLESS outbound encryption | PROTOCOL GAP | audit | Not implemented |

## UDP, Mux, and XUDP

Native VLESS UDP maintains the framed association until uplink EOF and permits a
bounded downlink grace period for late packets. Generic Mux UDP uses persistent
associations and routes each opening destination through the runtime router.

XUDP tracks associations by GlobalID, permits cross-parent reattach, accepts a
destination-less `Keep` for an attached association, rebuilds a broken outbound,
and expires detached sessions. Its workers and generic Mux UDP report payload
bytes through the active stats session.

| Area | Status | Verification | Notes |
| ---- | ------ | ------------ | ----- |
| Mux frame parser (`New`/`Keep`/`End`/`KeepAlive`) | Working | unit | TCP and UDP metadata |
| TCP children | Working | LIVE PASS | Multiple children supported |
| Generic UDP | Working | LIVE PASS | Persistent SessionID associations |
| XUDP manager | Working | LIVE PASS | GlobalID, reattach, cleanup, rebuild |
| Numeric DNS `:53` fast path | Working | LIVE PASS | `DnsEngine`; deliberate route bypass |
| Domain DNS `:53` fast path | DEFERRED | unit/audit | Resolver hook not wired for this special path |
| Mux duplicate `New` SessionID | INTENTIONAL DIVERGENCE | unit | Replaces the existing child/association |

Vision rejects native UDP. Vision Mux permits the XUDP form but rejects ordinary
Mux at the VLESS flow validation layer, matching the implemented restrictions.

## Vision

`xtls-rprx-vision` supports the inbound padding/unpadding path, `COMMAND_DIRECT`,
and the classic REALITY direct relay. On encrypted VLESS traffic, direct is
explicitly blocked: VLESS Encryption always remains the traffic layer. Vision
native UDP is rejected. Vision Mux/XUDP behavior is governed by the restrictions
above. Full splice/zero-copy parity is a **PROTOCOL GAP**; DIRECT relay is not
described as splice parity.

## REALITY

| Feature | Status | Verification | Notes |
| ------- | ------ | ------------ | ----- |
| Pre-auth / fallback | Working | LIVE PASS | SNI, AEAD, short ID, version, time-window order |
| X25519 pre-auth | Working | unit + live | Standalone client share |
| X25519MLKEM768 pre-auth | Working | unit | Two-pass share selection for auth |
| Hybrid TLS 1.3 KEX | Working | unit | ML-KEM-768 encapsulation + X25519, 64-byte secret |
| Target KEX mirroring | Working | unit | Observed X25519 or hybrid target group must match client share |
| ML-DSA-65 | Working | LIVE PASS | Seed validation and certificate extension patch path |
| Position-6 camouflage | Working | unit | Encrypted application-data camouflage |
| Post-handshake record detection/cache | Working | unit + probe harness | `dest × serverName × ALPN` cache |
| CCS/useless-record tolerance | Working | unit + probe harness | Dynamic policy after verified Finished |
| `limitFallback*` | Working | unit | Pre-auth fallback only |
| Encrypted overflow alert | Working | unit | Fatal `unexpected_message`, best effort |
| Accepted-path no-fallback | Working | unit + live | TLS/VLESS/encryption failures close |

TLS 1.3 AES-GCM and ChaCha20-Poly1305 accepted-path suites are supported; the
two CCM suites are rejected. The post-handshake probes use rustls rather than
the exact upstream uTLS fingerprints, and complete probe timing parity remains
deferred. REALITY accepted-path session resumption is not implemented.

## Routing

| Feature | Status | Verification | Notes |
| ------- | ------ | ------------ | ----- |
| `RuntimeRouter` | Working | unit + API + data plane | Static and dynamic rules |
| Default outbound | Working | unit | First registered; reassigned after removal |
| Domain/IP rules and `DomainStrategy` | Working | unit + integration | `AsIs`, `IpOnDemand`, `IpIfNonMatch` |
| DNS integration | Working | unit | In-process DNS engine for supported paths |
| GeoSite / GeoIP | Working | unit + integration | Asset loading and matchers |
| Protocol sniff matcher / webhook | Working | unit | Runtime route context |
| Balancers | Working | unit + integration | random, roundRobin, leastPing, leastLoad |
| `RoutingService` | Working | API | `TestRoute`, rule mutation, `GetBalancerInfo` |

`attributes` matching and process metadata have compiler/TestRoute support but
not complete production extraction for remote VLESS clients. That is a scoped
**PROTOCOL GAP**. Reassigning the default outbound after removal is an
**INTENTIONAL DIVERGENCE** from the upstream behavior that clears it. Numeric
Mux DNS fast-path routing bypass is another intentional divergence.

## API and RemnaNode

| Surface | Status | Verification | Notes |
| ------- | ------ | ------------ | ----- |
| StatsService | Working | unit + API | Supported stats/runtime surface |
| HandlerService | Working | unit + API | Dynamic VLESS users and supported in/outbound CRUD |
| RoutingService | Working | unit + API | Runtime router mutations and tests |
| LoggerService | Working | unit + API | `RestartLogger` for supported sinks |
| ObservatoryService | Working | unit + API | Standard/Burst health and balancer health input |
| Reflection | Working | API | Optional v1 and v1alpha |
| Direct listen modes | Working | unit + API | TCP, filesystem Unix, Linux abstract Unix, Commander |
| RemnaNode 3.3.2 | Working, scoped | fixture + Linux E2E tests/harness | Implemented API/runtime surface only |

RemnaNode 3.3.2 integration has been verified for the currently implemented
API/runtime surface. The Linux Docker harness still requires a real Node secret
and environment, so it is not a universal live CI claim.

## Transports

| Transport | Status | Category |
| --------- | ------ | -------- |
| raw / legacy TCP with REALITY | Working | — |
| XHTTP `stream-one`, `stream-up`, `packet-up` | Experimental | TRANSPORT GAP |
| XHTTP `packet-down`, XMUX | Gated/unavailable | TRANSPORT GAP |
| Vision or XUDP over XHTTP | Unavailable | TRANSPORT GAP |
| REALITY over gRPC / WebSocket | Rejected at startup | TRANSPORT GAP |

An unavailable transport does not imply that the shared VLESS protocol behavior
is absent from the raw/REALITY transport.

## Live verification

| Harness | Coverage category | Current documented result |
| ------- | ----------------- | ------------------------- |
| `make live-smoke` | Canonical serial live runner | Builds one fresh release binary, then runs REALITY, UDP, VLESS Encryption (1RTT/0RTT), and XHTTP with per-suite cleanup and a unified summary |
| `scripts/live_udp_smoke/run-live-udp-smoke.sh` | LIVE PASS | Native UDP, generic Mux UDP, XUDP, routing; Vision-native-UDP rejection |
| `scripts/live_vless_encryption_smoke/run-live-vless-encryption-smoke.sh` | LIVE PASS | Encrypted 1RTT TCP, Vision, Mux, XUDP, UDP and modes |
| `scripts/live_vless_encryption_smoke/run-live-vless-encryption-0rtt-smoke.sh` | LIVE PASS | Native 0RTT TCP resume after 1RTT ticket issuance |

The scripts produce their own reports; this repository does not store a single
current aggregate report, so no new test counts are invented here. Upstream
client-harness limitations and deterministic-only rows are identified in
[VLESS Encryption 0RTT](vless-encryption-0rtt.md).

## Missing and deferred

- **PROTOCOL GAP:** Reverse / `RequestCommandRvs`, VLESS outbound (including
  outbound VLESS Encryption), broad outbound protocol ecosystem, FakeDNS, DNS
  inbound/dokodemo hijack, and full Xray DNS behavior.
- **PROTOCOL GAP:** full Vision splice/zero-copy parity; REALITY accepted-path
  resumption; exact uTLS probe fingerprint/timing parity; complete remote
  process/attribute metadata extraction.
- **TRANSPORT GAP:** the unavailable XHTTP/gRPC/WebSocket forms listed above.
- **DEFERRED:** domain-name Mux `:53` DNS fast path; DoH/hostname DNS servers;
  general logging configuration fields such as `dnsLog` and `maskAddress`.

## Current roadmap

1. VLESS-4F — Forward Inbound Final Parity Audit + Closure
2. Reverse / `RequestCommandRvs`
3. VLESS outbound foundation
4. Remaining transport and observability parity as prioritized
