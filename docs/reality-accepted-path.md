# REALITY accepted path — developer notes

This document explains how upstream Xray/XTLS implements the REALITY **accepted**
path, what rust-xray already has, and why a naive “patch ServerHello bytes”
approach is insufficient.

It is **not** an implementation spec. It is a guardrail for future work so we do
not ship a broken camouflage handshake.

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
   policy fields (`shortId`, client version, time window, etc.).
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

When porting block A, use this correspondence as a guide (names from upstream
Go/XTLS REALITY server handshake code):

| Upstream (Go / XTLS) | rust-xray (planned) | Notes |
|----------------------|---------------------|-------|
| `serverHandshakeStateTLS13` | `RealityTls13ServerState` (`src/reality/tls13/state.rs`) | Holds client hello metadata, REALITY auth, observed dest ServerHello shape |
| `hs.handshake()` | Future `RealityTls13ServerState` handshake driver | Orchestrates ServerHello → EncryptedExtensions → Certificate → CertificateVerify → Finished → read client Finished |
| Transcript hash updates in `serverHandshakeStateTLS13` | `TranscriptHash` (`src/reality/tls13/transcript.rs`) | Running hash for CertificateVerify and Finished |
| Key schedule / traffic secret derivation | `Tls13KeySchedule` (`src/reality/tls13/key_schedule.rs`) | `early_secret` → handshake → application secrets |
| ServerHello / EE / Certificate / Finished builders | `Reality*Plan` structs (`src/reality/tls13/messages.rs`) | Message plans before record encryption |

The skeleton in `src/reality/tls13/` is **not wired** to `handle_accepted_reality_client`
yet. The live accepted path still stops after dest ServerHello observation in
`patch_reality_server_hello`.

## Current rust-xray architecture

### Already implemented

| Area | Location | Status |
|------|----------|--------|
| Xray-compatible REALITY config | `src/config/xray.rs` | Done |
| TLS ClientHello record read | `src/tls/` | First record only |
| ClientHello parse | `src/protocol/` | Done |
| REALITY X25519 + HKDF auth key | `src/reality/auth.rs` | Done |
| AEAD `session_id` decrypt | `src/reality/session.rs` | Done |
| Policy validation (SNI, shortId, time, version) | `src/reality/session.rs`, `decision.rs`, `sni.rs`, `version.rs` | Done |
| Fallback relay to `dest` | `src/proxy/fallback.rs` | Done |
| Accepted decision type | `RealityAccepted` in `decision.rs` | Done |
| Accepted entry + dest observation | `handle_accepted_reality_client` in `server.rs` | Connects dest, observes ServerHello, returns `Unsupported` |
| TLS 1.3 server state machine skeleton | `src/reality/tls13/` | Placeholder only; not connected to live path |
| VLESS config users | `build_vless_clients`, `VlessClientObject` | Done, loaded at startup |
| VLESS request parser / auth | `src/vless/protocol.rs`, `inbound.rs` | Unit-tested |
| Freedom TCP outbound skeleton | `src/outbound/freedom.rs` | Not wired to REALITY |

### Explicitly not connected yet

- **VLESS parser / freedom outbound** are **not** reachable from a real REALITY
  accepted TCP stream. `handle_accepted_reality_client` does not call
  `handle_vless_tcp_inbound`.
- **`patch_reality_server_hello`** in `src/reality/handshake.rs` is a placeholder
  only; it must not be treated as the accepted-path implementation.

### Current decision flow (simplified)

```
TCP accept
  → read TLS ClientHello record
  → inspect_reality_client_hello
       ├─ Fallback → relay_fallback(client, dest, raw ClientHello bytes)
       └─ Accepted → handle_accepted_reality_client → dest observation → Unsupported (TLS 1.3 SM TODO)
```

Valid REALITY clients are **not** sent to fallback (intentional). They hit the
stub and the connection ends with `Unsupported` until the real accepted path
exists.

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

## Required implementation blocks

### A. TLS 1.3 server handshake core

Minimum server-side responsibilities:

- ServerHello generation (version, random, session id, cipher suite, key share)
- Key schedule (shared secret → handshake secrets → application secrets)
- Transcript hash maintenance across all handshake messages
- EncryptedExtensions
- Certificate (often ephemeral / camouflage-oriented)
- CertificateVerify
- Finished (server)
- Read and validate **client Finished**

Without A, there is no decrypted application stream for VLESS.

### B. REALITY camouflage timing / shape

REALITY tries to look like a handshake to the real `dest`:

- Connect to `dest` early (mirror phase)
- Observe target ServerHello and subsequent record **timing and lengths**
- Validate that target handshake **shape** is usable as camouflage reference
- Emit client-facing records that match expected timing/length behavior where
  required (not only static byte templates)

This is coupled with A — camouflage informs *when* and *what shape* records take,
but crypto still comes from the local TLS 1.3 state machine.

### C. VLESS handoff

After TLS handshake completes on the accepted path:

- Application data read/write uses post-handshake keys
- Pass the **decrypted stream** (or equivalent `AsyncRead`/`AsyncWrite` wrapper)
  to `handle_vless_tcp_inbound` with configured `VlessClient` list
- Preserve any bytes already read after the handshake boundary as
  `initial_payload` if they belong to VLESS

Today: VLESS pipeline exists in isolation; REALITY accepted path does not reach
it.

### D. Fallback (unchanged semantics)

- Invalid / non-REALITY clients → transparent TCP relay to `dest` with initial
  bytes already read (current `relay_fallback` behavior)
- Must **not** regress: accepted validation failure after mirror phase should
  still behave like upstream transparent fallback where applicable

## TODO matrix

Use this as a checklist. Items are ordered roughly by dependency.

| ID | Block | Task | rust-xray today | Notes |
|----|-------|------|-----------------|-------|
| T1 | B | Dial `dest` from accepted handler | Not in accepted path | Fallback already dials dest |
| T2 | B | MirrorConn-style concurrent client→dest write during ClientHello phase | Not implemented | Upstream mirror before accept decision |
| T3 | B | Parse / store **dest ServerHello record shape** (lengths, timing samples) | Not implemented | Camouflage reference |
| T4 | A | TLS 1.3 **handshake state machine** (server role) | Not implemented | Core blocker |
| T5 | A | ServerHello generation + key schedule | Not implemented | Depends on T4 |
| T6 | A | EncryptedExtensions, Certificate, CertificateVerify, Finished | Not implemented | Depends on T4, T5 |
| T7 | A | **Fake / ephemeral certificate** generation for camouflage | Not implemented | May mirror dest cert profile |
| T8 | A | **Client Finished** read + validation | Not implemented | `readClientFinished` equivalent |
| T9 | A | Application data **encrypt/decrypt** stream wrapper | Not implemented | Post-handshake keys |
| T10 | C | Wire accepted `Conn` → `handle_vless_tcp_inbound` | Stub only | After T4–T9 |
| T11 | C | VLESS response header exact semantics | TODO in code | Before/along relay |
| T12 | D | Ensure failed REALITY after mirror → transparent fallback | Partial | Policy fail before accept uses fallback; post-mirror fail TBD |
| T13 | — | Vision (`xtls-rprx-vision`) behavior | Not implemented | After C stable |
| T14 | — | Remove / replace `patch_reality_server_hello` placeholder | Placeholder | Do not extend placeholder into “fake” patch |

## Anti-patterns (do not implement)

- **Single-record ServerHello patch** without transcript/key schedule.
- **Bidirectional byte relay** after REALITY accept — client expects TLS 1.3
  server messages, not raw dest bytes.
- **Calling VLESS on raw TCP** immediately after AEAD ClientHello validation —
  client has not completed TLS handshake; VLESS bytes are not yet application
  data.
- **Treating `fetch_dest_handshake` + `patch_reality_server_hello` placeholders**
  as the design — they exist only to mark the seam.

## Related code map

```
src/reality/decision.rs   — inspect_reality_client_hello → Accepted | Fallback
src/reality/server.rs     — handle_accepted_reality_client (dest observation)
src/reality/handshake.rs  — dest fetch + ServerHello validation seam
src/reality/tls13/        — TLS 1.3 server state machine skeleton (not wired)
src/proxy/fallback.rs     — transparent relay (fallback)
src/vless/inbound.rs      — VLESS pipeline (not connected to accepted path)
src/outbound/freedom.rs   — TCP connect + relay (freedom outbound)
```

## References for implementers

When implementing, compare behavior against upstream Xray-core REALITY inbound
and XTLS server handshake code paths — specifically mirror connection handling,
accepted connection switch, TLS 1.3 server transcript/key schedule, and post-
handshake `Conn` handoff. This repo intentionally does **not** duplicate
upstream code here; read upstream when starting block A/B.

---

**Summary:** rust-xray can already **detect** valid REALITY ClientHello clients.
Serving them requires a **full TLS 1.3 server handshake + REALITY camouflage
layer**, then VLESS on the decrypted stream. Anything less is a protocol break.
