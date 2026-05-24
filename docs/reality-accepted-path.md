# REALITY accepted path — developer notes

This document explains how upstream Xray/XTLS implements the REALITY **accepted**
path, what rust-xray already has, and why a naive “patch ServerHello bytes”
approach is insufficient.

It is **not** an implementation spec. It is a guardrail for future work so we do
not ship a broken camouflage handshake.

**Valid REALITY clients still stop at `Unsupported` after dest ServerHello
observation and TLS 1.3 state setup.** This is **expected**. The project is **not**
a drop-in Xray-core replacement.

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

| Upstream (Go / XTLS) | rust-xray | Status |
|----------------------|-----------|--------|
| `serverHandshakeStateTLS13` | `RealityTls13ServerState` (`src/reality/tls13/state.rs`) | **Container wired** — holds `RealityAccepted`, observed dest ServerHello, selected suite, `TranscriptHash` |
| `hs.handshake()` | Future `RealityTls13ServerState` handshake driver | **Not implemented** |
| Transcript hash updates | `TranscriptHash` (`src/reality/tls13/transcript.rs`) | **Scaffold** — buffer + on-demand SHA-256/384 digest |
| Key schedule / traffic secret derivation | `key_schedule.rs` | **Primitives** — HKDF-Expand-Label, `derive_traffic_key`, `derive_finished_key`; no live schedule state |
| Cipher suite selection | `cipher_suite.rs` | **Done** — lookup for AES-128-GCM-SHA256, AES-256-GCM-SHA384, ChaCha20-Poly1305-SHA256 |
| ServerHello / EE / Certificate / Finished builders | `messages.rs` | **Partial** — handshake framing, empty EE, Finished body; Certificate/CertificateVerify placeholders |
| TLS record framing | `src/tls/records.rs` | **Builders + parser** — no encryption layer yet |
| Dest observation → state setup | `prepare_reality_tls13_state` (`handshake.rs`) | **Wired** — called from `handle_accepted_reality_client`; then `Unsupported` |

## Current rust-xray architecture

### Implemented

| Area | Location | Status |
|------|----------|--------|
| REALITY ClientHello auth | `src/reality/auth.rs` | Done |
| AEAD `session_id` decrypt | `src/reality/session.rs` | Done |
| Policy validation (SNI, shortId, time, version) | `session.rs`, `decision.rs`, `sni.rs`, `version.rs` | Done |
| Fallback relay to `dest` | `src/proxy/fallback.rs` | Done |
| Xray-compatible REALITY config | `src/config/xray.rs` | Done |
| TLS ClientHello record read | `src/tls/record.rs` | First record only |
| ClientHello parse | `src/protocol/` | Done |
| Dest ServerHello observation | `fetch_dest_handshake`, `extract_observed_server_hello` | Done |
| Minimal TLS 1.3 ServerHello parser | `src/tls/server_hello.rs` | Done |
| TLS record parser + builders | `src/tls/records.rs` | Done |
| TLS 1.3 transcript hash scaffold | `src/reality/tls13/transcript.rs` | Done |
| TLS 1.3 HKDF / key schedule primitives | `src/reality/tls13/key_schedule.rs` | Done |
| TLS 1.3 cipher suite model | `src/reality/tls13/cipher_suite.rs` | Done |
| Handshake message builders (skeleton) | `src/reality/tls13/messages.rs` | Partial |
| TLS 1.3 state container | `RealityTls13ServerState` | Wired after observation |
| Accepted entry + state setup | `handle_accepted_reality_client` in `server.rs` | Returns `Unsupported` after state build |
| VLESS config users | `build_vless_clients`, `VlessClientObject` | Done, loaded at startup |
| VLESS request parser / auth | `src/vless/protocol.rs`, `inbound.rs` | Unit-tested |
| Freedom TCP outbound skeleton | `src/outbound/freedom.rs` | Not wired to REALITY |

### Not implemented

- **Full REALITY TLS 1.3 server handshake** — no handshake driver runs.
- **ServerHello generation** — no client-facing ServerHello.
- **Handshake encryption** — no encrypted handshake records to the client.
- **EncryptedExtensions encryption** — builder skeleton only.
- **Certificate generation / signing** — placeholder.
- **CertificateVerify** — placeholder.
- **Finished generation** — verify_data builder exists; not wired to keys / transcript.
- **Client Finished verification** — `readClientFinished` equivalent.
- **Encrypted application-data stream** — post-handshake record wrapper.
- **Real VLESS handoff after TLS handshake** — `handle_vless_tcp_inbound` unreachable.
- **Vision** — metadata only.
- **`mldsa65`** — not implemented.
- **Fallback limits** — `limitFallbackUpload` / `limitFallbackDownload`.

### Explicitly not connected yet

- **VLESS parser / freedom outbound** are **not** reachable from a real REALITY
  accepted TCP stream. `handle_accepted_reality_client` does not call
  `handle_vless_tcp_inbound`.
- **`patch_reality_server_hello`** is a thin wrapper over
  `prepare_reality_tls13_state` that still returns `Unsupported`; it must not be
  treated as the handshake implementation.

### Current decision flow (simplified)

```
TCP accept
  → read TLS ClientHello record
  → inspect_reality_client_hello
       ├─ Fallback → relay_fallback(client, dest, raw ClientHello bytes)
       └─ Accepted → handle_accepted_reality_client
            → connect dest, forward ClientHello record
            → fetch_dest_handshake
            → prepare_reality_tls13_state (RealityTls13ServerState)
            → Unsupported (no bytes to client; no fallback)
```

Valid REALITY clients are **not** sent to fallback (intentional). They reach
state setup, then the connection ends with `Unsupported` until the full server
handshake exists.

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

Ordered roughly by dependency:

1. **ServerHello generation** — client-facing ServerHello from REALITY state.
2. **ECDH shared secret** — derive shared key for the accepted TLS session.
3. **TLS 1.3 handshake traffic secrets** — early / handshake secret derivation.
4. **Encrypted handshake records** — EncryptedExtensions, Certificate,
   CertificateVerify, Finished under handshake keys.
5. **Certificate + CertificateVerify** — ephemeral / camouflage certificate
   chain and signature.
6. **Finished** — server Finished from transcript + finished key.
7. **Verify client Finished** — read and validate client handshake completion.
8. **Application traffic secrets** — post-handshake key schedule.
9. **Encrypted stream adapter** — decrypt/encrypt application TLS records.
10. **VLESS handoff** — pass decrypted stream to `handle_vless_tcp_inbound`.

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

**Today:** primitives and state container exist; block A handshake driver does
not run.

### B. REALITY camouflage timing / shape

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
| T1 | B | Dial `dest` from accepted handler | **Done** | `handle_accepted_reality_client` |
| T2 | B | MirrorConn-style concurrent client→dest write during ClientHello phase | Not implemented | Upstream mirror before accept decision |
| T3 | B | Parse / store **dest ServerHello record shape** (lengths, timing samples) | **Partial** | Records + validation; timing not sampled |
| T4 | A | TLS 1.3 **handshake state machine** (server role) | **Scaffold only** | State container + primitives; no driver |
| T5 | A | ServerHello generation + key schedule | Not implemented | Checklist items 1–3 |
| T6 | A | Encrypted handshake records (EE, Cert, CertVerify, Finished) | Not implemented | Checklist item 4 |
| T7 | A | **Fake / ephemeral certificate** generation for camouflage | Placeholder | Checklist item 5 |
| T8 | A | **Client Finished** read + validation | Not implemented | Checklist item 7 |
| T9 | A | Application data **encrypt/decrypt** stream wrapper | Not implemented | Checklist items 8–9 |
| T10 | C | Wire accepted `Conn` → `handle_vless_tcp_inbound` | Not connected | Checklist item 10 |
| T11 | C | VLESS response header exact semantics | TODO in code | Before/along relay |
| T12 | D | Ensure failed REALITY after mirror → transparent fallback | Partial | Policy fail before accept uses fallback; post-mirror fail TBD |
| T13 | — | Vision (`xtls-rprx-vision`) behavior | Not implemented | After C stable |
| T14 | — | Replace `patch_reality_server_hello` stub with real handshake driver | Stub wrapper | Do not extend into “fake” patch |

## Anti-patterns (do not implement)

- **Single-record ServerHello patch** without transcript/key schedule.
- **Bidirectional byte relay** after REALITY accept — client expects TLS 1.3
  server messages, not raw dest bytes.
- **Calling VLESS on raw TCP** immediately after AEAD ClientHello validation —
  client has not completed TLS handshake; VLESS bytes are not yet application
  data.
- **Treating `fetch_dest_handshake` + state setup** as a complete handshake —
  they mark the seam before the TLS 1.3 server driver.

## Related code map

```
src/reality/decision.rs   — inspect_reality_client_hello → Accepted | Fallback
src/reality/server.rs     — handle_accepted_reality_client (observation + state → Unsupported)
src/reality/handshake.rs  — fetch_dest_handshake, extract_observed_server_hello, prepare_reality_tls13_state
src/reality/tls13/
  transcript.rs           — TranscriptHash (SHA-256/384)
  key_schedule.rs         — HKDF primitives, derive_traffic_key, derive_finished_key
  cipher_suite.rs         — Tls13CipherSuite lookup
  messages.rs             — handshake message builders (skeleton)
  state.rs                — RealityTls13ServerState
src/tls/records.rs        — TLS record parse + build
src/tls/server_hello.rs   — dest ServerHello parser
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

**Summary:** rust-xray can **detect** valid REALITY ClientHello clients, **observe**
dest ServerHello shape, and **build** a TLS 1.3 state container with crypto
primitives in place. Serving them still requires the **full TLS 1.3 server
handshake + REALITY camouflage layer**, then VLESS on the decrypted stream.
Valid clients stopping at `Unsupported` after state setup is **expected**. Anything
less than a complete handshake is a protocol break.
