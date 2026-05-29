# REALITY ML-KEM / X25519MLKEM768 — foundation audit & design

**Status:** design / audit only — **no runtime implementation** in this document.  
**Branch reference:** `experiment` (2026-05-29).  
**Scope:** TLS 1.3 hybrid key exchange `X25519MLKEM768` on the REALITY accepted path.  
**Out of scope:** ML-DSA-65 certificate extension signing (`mldsa65Seed` / `mldsa65Verify`).

Upstream sources reviewed (shallow clone, `main`):

- [XTLS/Xray-core](https://github.com/XTLS/Xray-core) — REALITY transport wrapper, TLS curve config, VLESS encryption (separate PQ path).
- [XTLS/REALITY](https://github.com/XTLS/REALITY) — forked Go `crypto/tls` with hybrid handshake and REALITY server TLS 1.3 shortcut.

Related docs:

- [ML-DSA-65 research plan](./reality-mldsa65-mlkem-plan.md) — certificate signing only; **do not mix** with this ML-KEM plan.
- [REALITY accepted path](./reality-accepted-path.md) — current rust-xray TLS 1.3 scaffold.
- [Config compatibility audit](./config-compatibility-audit.md) — no `realitySettings` field for ML-KEM.

---

## Protocol distinction: ML-DSA vs ML-KEM

| | **ML-DSA-65** | **ML-KEM / X25519MLKEM768** |
|---|----------------|-----------------------------|
| **Purpose** | Post-quantum **signature** on REALITY ephemeral certificate extension | Post-quantum **KEM** in TLS 1.3 **key_share** / ECDHE |
| **Config (REALITY)** | Server: `mldsa65Seed`; client: `mldsa65Verify` | **No** REALITY JSON field — negotiation is automatic |
| **Wire** | Cert extension bytes (~3309 B signature) | TLS extension `key_share` (group `0x11EC`, concatenated payloads) |
| **Shared secret use** | HMAC message for signing only | TLS 1.3 `HandshakeSecret` input (64 B hybrid = ML-KEM ‖ X25519) |
| **rust-xray today** | Built-in `ml-dsa`, live cert patch when seed configured | **X25519 only** in auth, observation, and generated ServerHello |
| **Must not touch (first ML-KEM work)** | `src/reality/mldsa65.rs`, `certificate.rs` patch modes, `mldsa65Seed` config path | N/A |

**`derive_reality_auth_key` must stay on pure X25519.** Upstream REALITY client auth uses the **X25519** ECDH leg (`KeyShareKeys.Ecdhe` or `MlkemEcdhe` wrapper), not the 64-byte hybrid TLS shared secret. ML-KEM affects **TLS record keys**, not the 32-byte REALITY `AuthKey` HKDF.

There is **no upstream coupling** between `mldsa65Seed` and hybrid KEX: they are independent optional features checked separately in `Show` logging (`transport/internet/reality/reality.go`, `REALITY` server `handshake_server_tls13.go`).

---

## Upstream source map

### Named group & defaults

| Item | Upstream location | Notes |
|------|-------------------|--------|
| `X25519MLKEM768 = 4588` (`0x11EC`) | `XTLS/REALITY/common.go` | TLS 1.3 named group |
| Default curve preference order | `XTLS/REALITY/defaults.go` `defaultCurvePreferences()` | **`X25519MLKEM768` first**, then `X25519`, P-256, … |
| PQ / TLS-1.3-only group helpers | `XTLS/REALITY/common.go` `isPQKeyExchange`, `isTLS13OnlyKeyExchange` | Hybrid treated as PQ-preferring in server selection sort |

**Config-visible field:** REALITY `realitySettings` has **no** ML-KEM knob (see `config.proto` / `infra/conf/transport_internet.go` `REALITYConfig`). Hybrid enablement is **auto negotiation** via default `CurvePreferences` inside the REALITY TLS stack and the client’s uTLS fingerprint profile.

Regular Xray **TLS** (non-REALITY) may set `tlsSettings.curvePreferences` including `"x25519mlkem768"` (`transport/internet/tls/config.go` `ParseCurveName`). That path is **not** the REALITY inbound server handshake rust-xray implements.

**Separate product surface:** VLESS **encryption** `mlkem768x25519plus` (`proxy/vless/encryption/*.go`, `infra/conf/vless.go`) — ML-KEM for VLESS payload encryption, **not** REALITY TLS `key_share`. Do not conflate in implementation or tests.

### Where the group is selected

| Role | File | Behavior |
|------|------|----------|
| **TLS client** (incl. uTLS REALITY client) | `XTLS/REALITY/handshake_client.go` | `hello.supportedCurves[0]` drives primary group; if `X25519MLKEM768`, builds hybrid `key_share` |
| **TLS server** (generic TLS 1.3) | `XTLS/REALITY/handshake_server_tls13.go` `processClientHello` | Sorts client `supported_groups` vs server `config.CurvePreferences`; picks first mutual group; PQ groups preferred |
| **REALITY server shortcut** | `XTLS/REALITY/handshake_server_tls13.go` `serverHandshakeStateTLS13.handshake()` | Assumes client/server share **same group** as prepared `hs.hello.serverShare`; hybrid branch mirrors generic logic |

rust-xray does **not** run upstream `processClientHello`; it **observes** dest `ServerHello` and **builds** its own ServerHello with local code.

### `key_share` wire encoding (RFC 8446 + hybrid draft)

**TLS 1.3 `key_share` extension:**

- **ClientHello:** `KeyShareEntry` list: `NamedGroup (2)` + `key_exchange_length (2)` + `key_exchange (opaque)`.
- **ServerHello:** single entry: same shape (one group).

**`X25519MLKEM768` payloads** (`crypto/mlkem` + REALITY handshake):

| Direction | `group` | `key_exchange` length | Layout |
|-----------|---------|------------------------|--------|
| Client → Server | `0x11EC` | `EncapsulationKeySize768 + 32` | `mlkem_encap_key (1184 B) ‖ x25519_pubkey (32 B)` |
| Server → Client | `0x11EC` | `CiphertextSize768 + 32` | `mlkem_ciphertext (1088 B) ‖ x25519_pubkey (32 B)` |

**Hybrid shared secret** (both sides, draft-kwiatkowski-tls-ecdhe-mlkem / Go comments in `handshake_server_tls13.go`):

```text
shared_secret = ML-KEM-768.shared_secret (32 B) || X25519_ECDH.shared_secret (32 B)  // 64 bytes total
```

Server: encapsulate to client’s ML-KEM key, append X25519 server ephemeral.  
Client: decapsulate ciphertext, ECDH with X25519 server share.

**Pure X25519** (`group = 0x001D`): `key_exchange` is 32 bytes; shared secret is 32 bytes.

**Client dual key_share:** When hybrid is offered, REALITY/TLS client may also send a **second** `key_share` entry for `X25519` with the **same** 32-byte ephemeral (fallback / middlebox interop). This is why rust-xray’s current `find_x25519_public_key` can still work for **auth** even when hybrid is negotiated for TLS keys.

### REALITY accepted path vs ML-KEM

| Step | Upstream (Xray + REALITY) | rust-xray today |
|------|---------------------------|-----------------|
| ClientHello REALITY auth | `UClient` → `ecdhe.ECDH(publicKey)` → HKDF `REALITY` → seal `session_id` (`transport/internet/reality/reality.go`) | `derive_reality_auth_key` — **X25519 `key_share` only** (`src/reality/auth.rs`) |
| Dial dest / mirror | TCP to `dest` | Same |
| TLS 1.3 server handshake | REALITY fork: hybrid-aware `sharedKey` → standard key schedule | `RealityTls13ServerState` uses **32-byte** X25519 ECDH only (`src/reality/tls13/key_share.rs`, `key_schedule.rs`) |
| Cert verify | HMAC tail + optional ML-DSA-65 extension | ML-DSA patch path separate |
| Debug | Logs `X25519MLKEM768` vs ML-DSA independently | No ML-KEM logging |

**Dest observation:** `extract_observed_server_hello` rejects `key_share.group != 0x001D` (`src/reality/handshake.rs`). Real sites increasingly negotiate `0x11EC`; observation will fail until hybrid ServerHello parsing is added.

**Generated ServerHello:** `encode_key_share_extension_body` accepts **X25519 only** (`src/reality/tls13/key_share.rs`).

### Config / auto negotiation summary

| Mechanism | ML-KEM related? |
|-----------|-----------------|
| `realitySettings.*` | Only `mldsa65Seed` / client `mldsa65Verify` (ML-DSA) |
| `streamSettings.tlsSettings.curvePreferences` | Generic TLS outbound/inbound — **not** rust REALITY server path |
| uTLS fingerprint + REALITY `defaults.go` | **Primary** driver for REALITY clients |
| VLESS `encryption` / `decryption` `mlkem768x25519plus` | **Different subsystem** |

---

## rust-xray modules likely touched (future)

Ordered by dependency; **small blocks** suitable for separate PRs:

| Block | Module(s) | Goal |
|-------|-----------|------|
| **M0** | `src/protocol/enums.rs` | Add `NamedGroup::X25519MLKEM768 = 0x11EC` |
| **M1** | `src/tls/server_hello.rs`, `src/protocol/structs.rs` | Parse ServerHello / ClientHello hybrid `key_share` lengths |
| **M2** | `src/reality/tls13/key_share.rs` | Hybrid server share generation, `encode_key_share_extension_body` for `0x11EC` |
| **M3** | `src/reality/tls13/key_schedule.rs`, `state.rs` | Feed **64-byte** shared secret into TLS 1.3 HKDF (not auth HKDF) |
| **M4** | `src/reality/handshake.rs` | Dest observation accepts `0x11EC` + length checks |
| **M5** | `src/reality/tls13/messages.rs` | ServerHello builder emits hybrid extension body |
| **M6** | `tests/fixtures/reality/mlkem/`, integration tests | Golden bytes vs REALITY fork / captured dest |

### Forbidden modules for first implementation

Do **not** modify these in early ML-KEM PRs:

| Module | Reason |
|--------|--------|
| `src/reality/auth.rs` | **`derive_reality_auth_key` frozen** — stays X25519-only unless upstream contract changes |
| `src/reality/mldsa65.rs`, `mldsa65_crypto.rs` | ML-DSA-65 only |
| `src/reality/certificate.rs` | Cert extension / HMAC tail / ML-DSA patch |
| `src/config/xray.rs` | No upstream REALITY config field for ML-KEM |
| `src/main.rs` accepted flow control | No gate changes until handshake driver exists |
| `scripts/live_reality_smoke/*` | Smoke prerequisites documented below, not changed in foundation |
| `proxy/vless/encryption/*` (upstream only) | Unrelated VLESS encryption PQ |

**Dependency rule:** add `ml-kem` / `pqcrypto-mlkem` (or equivalent) only in TLS 1.3 KEX modules — **never** in ML-DSA signing crates path.

---

## Required offline vectors

Store under `tests/fixtures/reality/mlkem/` (directory **not** created in this audit):

| Vector | Contents | Source |
|--------|----------|--------|
| `x25519mlkem768-client-keyshare.bin` | ClientHello `key_share` extension body for group `0x11EC` | REALITY client handshake capture or `handshake_client.go` synthetic |
| `x25519mlkem768-server-keyshare.bin` | ServerHello `key_share` for `0x11EC` | Dest capture (e.g. microsoft.com:443) or REALITY server |
| `x25519-pure-keyshare.bin` | 32-byte X25519 entry | Regression guard |
| `hybrid-shared-secret-64.bin` | Expected ML-KEM ‖ X25519 secret | Go `crypto/mlkem` + ECDH test vector |
| `clienthello-dual-keyshare.bin` | Hybrid + X25519 entries | Prove auth X25519 leg stable |
| `README.md` | Field meanings, sizes 1184/1088/32 | Maintainer notes |

Constants to pin in README (Go `crypto/mlkem`, REALITY `tls.go`):

- `EncapsulationKeySize768` = **1184**
- `CiphertextSize768` = **1088**
- `SharedKeySize` = **32** per component; hybrid = **64**

---

## Required parser / builder tests (no runtime yet)

Unit/integration tests to add **before** enabling accepted path:

| Test | Asserts |
|------|---------|
| `parse_server_hello_key_share_x25519mlkem768_valid` | Group `0x11EC`, len = 1088+32 |
| `parse_server_hello_key_share_x25519mlkem768_bad_length` | Reject truncated / trailing garbage |
| `parse_client_key_share_x25519mlkem768_valid` | Len = 1184+32 |
| `extract_client_x25519_from_hybrid_client_hello` | X25519 slice offset 1184..1216 |
| `extract_client_x25519_still_finds_standalone_x25519_entry` | Dual key_share ClientHello |
| `encode_server_key_share_x25519mlkem768_matches_layout` | Ciphertext ‖ pubkey |
| `hybrid_shared_secret_concat_order` | ML-KEM first, X25519 second (match REALITY) |
| `derive_reality_auth_key_unchanged_with_hybrid_client_hello` | Auth still uses 32-byte X25519 ECDH |
| `named_group_x25519mlkem768_enum_roundtrip` | `0x11EC` |

Parser tests live in `src/tls/`, `src/protocol/`, `src/reality/tls13/` `#[cfg(test)]` — **not** in `auth.rs` behavior changes.

---

## Phased implementation plan

### Phase 0 — Foundation (this document)

- Upstream map, ML-DSA separation, module boundaries, vectors/tests checklist.
- **Exit:** reviewers agree auth vs TLS KEX split.

### Phase 1 — Parse & constants only

- M0 + M1 + fixture directory + parser tests.
- **Exit:** hybrid ClientHello/ServerHello bytes parse; **no** `RealityTls13ServerState` behavior change.

### Phase 2 — Cryptographic primitives offline

- Rust ML-KEM-768 encaps/decaps matching Go `crypto/mlkem` on fixture seeds.
- Hybrid 64-byte secret builder (test-only helper).
- **Exit:** `hybrid_shared_secret_concat_order` passes against Go reference output.

### Phase 3 — TLS 1.3 key schedule input

- M3: `derive_handshake_secrets` accepts 64-byte ECDHE input when suite/group hybrid.
- Still **no** live ServerHello to client if handshake driver incomplete.
- **Exit:** key schedule tests with fixed transcript + 64-byte secret.

### Phase 4 — Dest observation & encoding

- M4 + M5: observe dest hybrid ServerHello; encode hybrid server `key_share` in builders.
- **Exit:** `prepare_reality_tls13_state` works when dest uses `0x11EC`; generated extension bytes match fixtures.

### Phase 5 — Accepted path integration (explicit follow-up scope)

- Wire handshake driver only after Phases 1–4 green.
- **Still forbidden:** `derive_reality_auth_key`, ML-DSA, config parser, smoke script edits until dedicated task.

---

## Live smoke prerequisites (documentation only)

Before `scripts/live_reality_smoke` can assert ML-KEM:

1. **Dest observation** accepts `ServerHello.key_share.group == 0x11EC` (Phase 4).
2. **Client-facing ServerHello** emits valid hybrid `key_share` (Phase 4–5).
3. **TLS 1.3 key schedule** uses 64-byte secret (Phase 3–5).
4. **REALITY auth** still passes with dual `key_share` ClientHello (existing X25519 extract).
5. **ML-DSA-65** smoke remains independent — `mldsa65` fixtures unchanged.
6. New smoke assertions (future): log line or test hook “using X25519MLKEM768” equivalent to upstream `Show` — **do not** add in foundation PR.

Until then, smoke continues to validate **X25519-only** dest observation and cipher matrix against local TLS servers that emit `group=0x001D`.

---

## Risk register

| Risk | Mitigation |
|------|------------|
| Confuse ML-KEM with ML-DSA | Separate crates, modules, fixtures, PR titles |
| Change `derive_reality_auth_key` to 64-byte secret | Explicit forbidden list; test `derive_reality_auth_key_unchanged_*` |
| Break clients without hybrid | Keep X25519 `key_share` extraction; optional dual-entry ClientHello |
| Dest sites use `0x11EC` only | Phase 4 observation required before camouflage matches modern CDNs |
| Add `realitySettings.mlkem*` config | **Do not** — upstream has no field; avoid config creep |
| Pull VLESS encryption ML-KEM into REALITY | Document `mlkem768x25519plus` as separate upstream subsystem |

---

## Acceptance checklist (design doc)

- [x] Upstream source map with file paths
- [x] ML-DSA vs ML-KEM clearly separated
- [x] `key_share` encoding and group selection documented
- [x] No REALITY config field — auto negotiation noted
- [x] REALITY accepted path interaction vs rust-xray gaps
- [x] No `mldsa65*` coupling
- [x] Concrete future blocks (M0–M6)
- [x] Forbidden modules list includes `auth.rs` / `derive_reality_auth_key`
- [x] Offline vectors + parser test list
- [x] Phased plan + smoke prerequisites
- [x] **No** `src/` runtime changes in this task
