# REALITY accepted path — developer notes

> **Runtime status:** For what works today in live smoke (accepted TLS 1.3 +
> VLESS + Vision, fallback, API), see
> **[compatibility-status.md](./compatibility-status.md)**. This file focuses on
> handshake architecture and upstream mapping for contributors.

This document explains how upstream Xray/XTLS implements the REALITY **accepted**
path, what rust-xray already has, and why a naive “patch ServerHello bytes”
approach is insufficient.

It is **not** an implementation spec. It is a guardrail for future work so we do
not ship a broken camouflage handshake.

**This project is not a drop-in Xray-core replacement and is not production-ready.**
Some sections below describe historical design constraints; trust
[compatibility-status.md](./compatibility-status.md) for current end-to-end behavior.

## Upstream REALITY accepted path (Xray / XTLS)

In upstream, REALITY inbound is **not** “validate ClientHello, then byte-relay
forever”. The accepted branch is a full TLS 1.3 server-side handshake layered on
top of camouflage timing/shape from a real destination.

Rough sequence:

1. **Dial `dest`** — open TCP to `realitySettings.dest` / `target`.
2. **MirrorConn** — while reading the client, simultaneously write mirrored bytes
   to the target (transparent relay phase for unauthenticated traffic).
3. **Read ClientHello** from the client connection.
4. **REALITY AEAD / session validation** — decrypt and validate `session_id`,
   policy fields (`shortId`, client version, time window, etc.). Server-side
   `minClientVer` follows Xray-core af7eb68: omitted or `""` → effective
   `26.3.27`; explicit values (including `"0.0.0"`) override. See
   [README](../README.md#reality-server-minclientver-xray-core-compatibility).
5. **If validation failed** → continue **transparent fallback relay** to `dest`
   (client sees the real site; no REALITY server semantics).
6. **If validation ok** → connection **switches** to the accepted REALITY server
   path (no longer a dumb relay).
7. **Observe target ServerHello / handshake** — read timing, record lengths, and
   shape from the real destination handshake (camouflage reference).
8. **Run TLS 1.3 server handshake state machine** — generate ServerHello,
   EncryptedExtensions, Certificate, CertificateVerify, Finished using REALITY
   key schedule and transcript state (not a single-record patch).
9. **Read client Finished** — `readClientFinished`; validate client handshake
   completion.
10. **Hand off `Conn`** — application-data read/write (decrypted stream) goes to
    the upper protocol layer (VLESS, Vision, etc.).

Key point: after step 6, the server must speak **valid TLS 1.3** to the client.
REALITY camouflage influences *what* is sent and *when*, but the bytes still must
 satisfy transcript hashing, key derivation, and record encryption rules.

## Upstream ↔ Rust mapping (TLS 1.3 server core)

When comparing with upstream Go/XTLS REALITY server handshake code:

| Upstream (Go / XTLS) | rust-xray | Status |
|----------------------|-----------|--------|
| `serverHandshakeStateTLS13` | `RealityTls13ServerState` (`src/reality/tls13/state.rs`) | **Working** — holds accepted client, observed dest ServerHello, suite, transcript, secrets |
| `hs.handshake()` | `complete_reality_tls13_handshake` (`state.rs`) | **Working** — production driver from `handle_accepted_reality_client` |
| Transcript hash updates | `TranscriptHash` (`src/reality/tls13/transcript.rs`) | **Working** |
| Key schedule / traffic secret derivation | `key_schedule.rs` free functions | **Working** — HKDF-Expand-Label, handshake/application secrets |
| Cipher suite selection | `cipher_suite.rs` | **Working** — AES-128-GCM, AES-256-GCM, ChaCha20-Poly1305 (CCM rejected) |
| ServerHello / EE / Certificate / Finished builders | `messages.rs`, `certificate.rs` | **Working** on accepted path |
| TLS record framing + encryption | `src/tls/records.rs`, `tls13/record_crypto.rs` | **Working** |
| Dest observation → state setup | `fetch_dest_handshake`, `prepare_reality_tls13_state` (`handshake.rs`) | **Working** |
| Application stream handoff | `RealityTls13ApplicationStream` → `run_inbound_transport` | **Working** |

## Deterministic Rust vectors (non-smoke)

Upstream compatibility edge cases that already have live smoke coverage are also locked in Rust:

- `tests/fixtures/fallback/proxy-v2-tcp4-127.0.0.1.bin` + `src/vless/fallback.rs` / `tests/upstream_compat_vectors.rs` (PROXY v2 `xver=2` bytes, path-over-ALPN precedence).
- `src/reality/decision.rs` `client_hello_policy_matrix_fallback_vs_inspect_error` (inspect → fallback vs `InvalidInput` for main relay).
- `tests/upstream_compat_vectors.rs` (unsupported transport startup, seed → `HmacPlusMldsa65` only).

Live matrix remains `scripts/live_reality_smoke/run-live-smoke.sh` unchanged.

## Current rust-xray architecture

### Implemented

| Area | Location | Status |
|------|----------|--------|
| REALITY ClientHello auth | `src/reality/auth.rs` | Done |
| AEAD `session_id` decrypt | `src/reality/session.rs` | Done |
| Policy validation (SNI, shortId, time, version) | `session.rs`, `decision.rs`, `sni.rs`, `version.rs` | Done (`minClientVer` default `26.3.27` at config parse) |
| Fallback relay to `dest` | `src/proxy/fallback.rs` | Done |
| Xray-compatible REALITY config | `src/config/xray.rs` | Done |
| TLS ClientHello record read | `src/tls/record.rs` | First record only |
| ClientHello parse | `src/protocol/` | Done |
| Dest ServerHello observation | `fetch_dest_handshake`, `extract_observed_server_hello` | Done |
| Minimal TLS 1.3 ServerHello parser | `src/tls/server_hello.rs` | Done |
| TLS record parser + builders | `src/tls/records.rs` | Done |
| TLS 1.3 transcript hash | `src/reality/tls13/transcript.rs` | Done |
| TLS 1.3 HKDF / key schedule | `src/reality/tls13/key_schedule.rs` | Done |
| TLS 1.3 cipher suite model | `src/reality/tls13/cipher_suite.rs` | Done |
| Handshake message builders | `src/reality/tls13/messages.rs`, `certificate.rs` | Done on accepted path |
| TLS 1.3 handshake driver | `complete_reality_tls13_handshake` | Done (live smoke) |
| Accepted entry | `handle_accepted_reality_client` in `server.rs` | Done |
| VLESS + transport handoff | `run_inbound_transport` after TLS app stream | Done |
| VLESS config users | `build_vless_clients`, `VlessClientObject` | Done |
| Freedom TCP outbound | `src/outbound/freedom.rs` | Wired from VLESS inbound |

### Partial / not yet implemented

- **MirrorConn-style concurrent mirror** during pre-auth ClientHello phase (upstream timing/shape sampling beyond dest ServerHello observation)
- **Vision splice / zero-copy** beyond DIRECT MVP
- **`mldsa65Seed`** — experimental runtime baseline when configured ([baseline doc](./reality-mldsa65-runtime-baseline.md))
- **X25519MLKEM768 on REALITY accepted TLS path** — Stage 2 implements **pre-auth carrier parsing only** (`src/reality/key_share.rs`): ClientHello group `0x11EC` with 1216-byte `key_exchange` (1184-byte opaque ML-KEM prefix + 32-byte X25519) may supply the REALITY auth X25519 public key when no valid standalone `X25519` entry exists. Upstream two-pass selection: standalone `X25519`/32 first, then hybrid trailing 32 bytes. **Not yet:** ML-KEM-768 crypto, hybrid ServerHello generation, 64-byte TLS shared secret, dest ServerHello group mirroring (`src/reality/tls13/key_share.rs` remains X25519-only).
- **Fallback limits** — `limitFallbackUpload` / `limitFallbackDownload`
- **TLS 1.3 CCM cipher suites** (0x1304, 0x1305) — rejected on accepted path

### Current decision flow (simplified)

```
TCP accept
  → read TLS ClientHello record
  → inspect_reality_client_hello
       ├─ Fallback → relay_fallback(client, dest, raw ClientHello bytes)
       └─ Accepted → handle_accepted_reality_client
            → connect dest, forward ClientHello record
            → fetch_dest_handshake
            → prepare_reality_tls13_state
            → complete_reality_tls13_handshake
            → run_inbound_transport (VLESS / XHTTP)
```

Valid REALITY clients **do not** fall back after accept. Handshake or VLESS errors
close the connection.

## Why “simple ServerHello patch” is wrong

A tempting but **incorrect** shortcut:

1. Forward ClientHello to `dest`.
2. Read ServerHello from `dest`.
3. Patch one field (e.g. replace `key_share`).
4. Relay remaining bytes both ways.

This fails because TLS 1.3 after ServerHello is a **state machine**, not opaque
bytes:

- **Transcript hash** — each handshake message updates the hash used for
  CertificateVerify and Finished.
- **Key schedule** — `early_secret` → handshake traffic secrets → application
  traffic secrets; derived from ECDHE shared secret and transcript.
- **Encrypted handshake** — EncryptedExtensions, Certificate, CertificateVerify,
  Finished are encrypted under handshake traffic keys with correct IV sequence.
- **Client Finished** — server must verify client Finished against the same
  transcript and keys.
- **Application data** — only after both Finished messages does application
  traffic use application traffic secrets (what VLESS expects to read/write).

Patching a single ServerHello extension or public key without maintaining the
full server-side TLS 1.3 state produces records the client cannot decrypt or
verify, or breaks camouflage timing/shape constraints REALITY relies on.

**Required approach:** implement (or port) a **TLS 1.3 server handshake core**
integrated with REALITY camouflage observation of the target, matching upstream
XTLS/REALITY behavior — not a one-record edit.

## Next implementation checklist

Remaining work (roughly by dependency):

1. **MirrorConn / camouflage timing** — upstream-style concurrent mirror during pre-auth.
2. **Dest handshake shape sampling** — record timing/length behavior beyond ServerHello observation.
3. **Vision splice / zero-copy** — beyond DIRECT MVP padding relay.
4. **ML-KEM / X25519MLKEM768 TLS negotiation** — Stage 2: pre-auth hybrid `key_share` carrier parsing only; accepted-path TLS 1.3 KEX remains X25519-only (Stage 3+).
5. **Fallback rate limits** — `limitFallbackUpload` / `limitFallbackDownload`.

## Required implementation blocks

### A. TLS 1.3 server handshake core — **implemented**

Production path: `prepare_reality_tls13_state` → `complete_reality_tls13_handshake`.

ServerHello generation, key schedule, transcript maintenance, encrypted EE/Cert/CertVerify/Finished, client Finished verification, application traffic secrets, and encrypted application stream are implemented and covered by live smoke.

Remaining gaps inside block A are upstream parity refinements (for example exact random/camouflage behavior — see TODOs in `state.rs`), not absence of a handshake driver.

### B. REALITY camouflage timing / shape — **partial**

REALITY tries to look like a handshake to the real `dest`:

- Connect to `dest` early (mirror phase)
- Observe target ServerHello and subsequent record **timing and lengths**
- Validate that target handshake **shape** is usable as camouflage reference
- Emit client-facing records that match expected timing/length behavior where
  required (not only static byte templates)

This is coupled with A — camouflage informs *when* and *what shape* records take,
but crypto still comes from the local TLS 1.3 state machine.

**Today:** dest ServerHello observation and validation are implemented; timing /
MirrorConn are not.

### C. VLESS handoff — **implemented**

After TLS handshake completes, `RealityTls13ApplicationStream` is passed to
`run_inbound_transport` (raw TCP or XHTTP). VLESS auth and freedom relay run on
the decrypted application stream.

### D. Fallback (unchanged semantics)

- Invalid / non-REALITY clients → transparent TCP relay to `dest` with initial
  bytes already read (current `relay_fallback` behavior)
- Must **not** regress: accepted validation failure after mirror phase should
  still behave like upstream transparent fallback where applicable

## TODO matrix

Use this as a checklist. Items are ordered roughly by dependency.

| ID | Block | Task | rust-xray today | Notes |
|----|-------|------|-----------------|-------|
| T1 | B | Dial `dest` from accepted handler | **Done** | `handle_accepted_reality_client` |
| T2 | B | MirrorConn-style concurrent client→dest write during ClientHello phase | Not implemented | Upstream mirror before accept decision |
| T3 | B | Parse / store **dest ServerHello record shape** (lengths, timing samples) | **Partial** | Records + validation; timing not sampled |
| T4 | A | TLS 1.3 **handshake state machine** (server role) | **Done** | `complete_reality_tls13_handshake` |
| T5 | A | ServerHello generation + key schedule | **Done** | Live smoke |
| T6 | A | Encrypted handshake records (EE, Cert, CertVerify, Finished) | **Done** | Live smoke |
| T7 | A | Ephemeral certificate + REALITY HMAC patch | **Done** | ML-DSA-65 baseline when configured |
| T8 | A | **Client Finished** read + validation | **Done** | Live smoke |
| T9 | A | Application data **encrypt/decrypt** stream wrapper | **Done** | `RealityTls13ApplicationStream` |
| T10 | C | Wire accepted stream → VLESS / transport | **Done** | `run_inbound_transport` |
| T11 | C | VLESS response header exact semantics | Mostly done | Vision DIRECT MVP |
| T12 | D | Ensure failed REALITY after mirror → transparent fallback | Partial | Policy fail before accept uses fallback |
| T13 | — | Vision splice / zero-copy | Not implemented | DIRECT MVP only |
| T14 | — | ML-KEM hybrid KEM | Not implemented | Out of scope |

## Anti-patterns (do not implement)

- **Single-record ServerHello patch** without transcript/key schedule.
- **Bidirectional byte relay** after REALITY accept — client expects TLS 1.3
  server messages, not raw dest bytes.
- **Calling VLESS on raw TCP** immediately after AEAD ClientHello validation —
  client has not completed TLS handshake; VLESS bytes are not yet application
  data.
- **Treating `fetch_dest_handshake` + state setup** as a complete handshake by
  itself — they are prerequisites; `complete_reality_tls13_handshake` must run.

## Related code map

```
src/reality/decision.rs   — inspect_reality_client_hello → Accepted | Fallback
src/reality/server.rs     — handle_accepted_reality_client (observation + full handshake)
src/reality/handshake.rs  — fetch_dest_handshake, extract_observed_server_hello, prepare_reality_tls13_state
src/reality/tls13/
  state.rs                — RealityTls13ServerState, complete_reality_tls13_handshake
  stream.rs               — RealityTls13ApplicationStream
  transcript.rs           — TranscriptHash (SHA-256/384)
  key_schedule.rs         — HKDF primitives, derive_traffic_key, derive_finished_key
  cipher_suite.rs         — Tls13CipherSuite lookup
  messages.rs             — handshake message builders
  certificate.rs          — ephemeral cert + CertificateVerify
  record_crypto.rs        — TLS 1.3 record encrypt/decrypt
src/tls/records.rs        — TLS record parse + build
src/tls/server_hello.rs   — dest ServerHello parser
src/proxy/fallback.rs     — transparent relay (fallback)
src/transport/            — run_inbound_transport (VLESS / XHTTP)
src/vless/                — VLESS auth + relay
src/outbound/freedom.rs   — TCP connect + relay (freedom outbound)
```

## References for implementers

When implementing, compare behavior against upstream Xray-core REALITY inbound
and XTLS server handshake code paths — specifically mirror connection handling,
accepted connection switch, TLS 1.3 server transcript/key schedule, and post-
handshake `Conn` handoff. This repo intentionally does **not** duplicate
upstream code here; read upstream when starting block A/B.

---

**Summary:** rust-xray **detects** valid REALITY ClientHello clients, **observes**
dest ServerHello shape, runs the **full TLS 1.3 server handshake**, and hands
the decrypted application stream to VLESS/transport. Remaining work is upstream
camouflage parity (MirrorConn timing), Vision splice, ML-KEM, and fallback rate
limits — not basic handshake completion.
