# REALITY ML-DSA-65 live integration plan (scaffold only)

This document records where live signing inputs exist in rust-xray today, what is
already implemented offline, and the constraints for a future live integration
block. **Nothing here authorizes runtime changes.**

## Current foundation status

| Item | Location | Status |
|------|----------|--------|
| Config parse `mldsa65Seed` | `src/config/xray.rs` | Done — stored on `RealityInboundRuntime` |
| Seed decode / validation | `src/reality/mldsa65.rs` | Done |
| Offline message builder | `build_reality_mldsa65_message` | Done |
| Offline signer / DER patch | `sign_reality_mldsa65_message`, `sign_reality_cert_extension`, `patch_reality_cert_der_with_mldsa65_signature` | Done under `reality-mldsa65-crypto` |
| Certificate patch mode API | `RealityCertificatePatchMode::HmacPlusMldsa65` | Done — offline only, requires seed |
| Runtime capability enum | `RealityMldsa65RuntimeMode` | Done — live remains closed |
| Live patch context scaffold | `RealityMldsa65LivePatchContext` | Done — not wired to handshake |
| Legacy HMAC cert patch | `patch_reality_certificate_der` | Unchanged — live path uses this |

## Why live runtime stays disabled

1. Startup gate rejects any config with parsed `mldsa65Seed`
   (`ConfiguredButLiveRuntimeUnsupported`), even when `reality-mldsa65-crypto` is
   compiled.
2. Offline crypto proves seed/sign/verify compatibility; it does **not** prove
   transcript wiring, ServerHello byte selection, or certificate DER timing in the
   accepted TLS 1.3 path.
3. `HmacPlusMldsa65` is not called from `handle_accepted_reality_client` or
   `complete_reality_tls13_handshake`.

## Data required for live ML-DSA certificate extension signing

Upstream REALITY signs:

`ML-DSA-65( HMAC-SHA512(auth_key, ed25519_public_key || raw ClientHello || raw ServerHello) )`

and embeds the 3309-byte signature at certificate DER offset `126`.

Required inputs:

| Input | Purpose |
|-------|---------|
| Raw ClientHello handshake message bytes | ML-DSA message |
| Raw generated ServerHello handshake message bytes | ML-DSA message |
| Ephemeral certificate DER before patch | HMAC tail + extension write target |
| Ed25519 public key (`[u8; 32]`) | HMAC + ML-DSA message |
| REALITY `auth_key` (`[u8; 32]`) | HMAC + ML-DSA message |
| `mldsa65Seed` | ML-DSA signing key derivation |

## Where inputs exist in rust-xray today

### ClientHello bytes

- `TlsClientHelloRecord::handshake_message` — parsed TLS ClientHello handshake
  message (`src/tls/record.rs`, passed through `src/main.rs` inspect path).
- `handle_accepted_reality_client` receives `record.handshake_message` and passes
  it to `complete_reality_tls13_handshake` (`src/reality/server.rs`).
- `RealityTls13ServerState::update_transcript_client_server_hello` consumes raw
  ClientHello bytes (`src/reality/tls13/state.rs`).

### ServerHello bytes

- Generated ServerHello stored in `RealityTls13ServerState::server_hello_message`
  after `prepare_server_hello` (`src/reality/tls13/state.rs`).
- Observed dest ServerHello raw bytes in
  `RealityObservedServerHello::raw_handshake_message` (`src/reality/handshake.rs`).
  **ML-DSA must use the generated server-facing ServerHello, not the dest copy.**

### Certificate DER / Ed25519 public key

- `generate_reality_ephemeral_ed25519_certificate` in
  `build_encrypted_server_handshake_records` (`src/reality/tls13/state.rs`).
- Mutable `cert_der` exists immediately before legacy HMAC patch at lines calling
  `patch_reality_certificate_der`.

### auth_key

- Derived once during inspect via `derive_reality_auth_key`
  (`src/reality/auth.rs`).
- Stored on `RealityAccepted.auth.auth_key` and copied into
  `RealityTls13ServerState.accepted`.

### mldsa65Seed

- Parsed into `RealityInboundRuntime.mldsa65_seed` (`src/config/xray.rs`).
- **Not passed** into `handle_accepted_reality_client` or TLS state today.
- Startup gate blocks configs where seed is present.

### Current HMAC-only patch site (live)

```text
RealityTls13ServerState::build_encrypted_server_handshake_records
  -> generate_reality_ephemeral_ed25519_certificate
  -> patch_reality_certificate_der(cert_der, public_key_raw, accepted.auth.auth_key)
```

This is the only live certificate mutation today. Future ML-DSA integration must
extend this seam without changing HMAC-only behavior when seed is absent.

## Future live patching order (not implemented)

When live integration is explicitly scoped:

1. Confirm runtime gate allows configured seed (new `Enabled` mode — **not added yet**).
2. Build `RealityMldsa65LivePatchContext` from transcript-local bytes + runtime seed reference.
3. `validate_reality_mldsa65_live_patch_context` — shape check only.
4. Apply legacy HMAC tail via `patch_reality_certificate_der` (unchanged semantics).
5. `sign_reality_cert_extension` — offline primitive, feature-gated.
6. `patch_reality_cert_der_with_mldsa65_signature` — write extension at offset 126.
7. Continue Certificate / CertificateVerify / Finished generation unchanged.

Alternative: route through `patch_reality_certificate_der_with_mode` once live path
has all inputs; still must preserve HMAC-only mode for configs without seed.

## Hard constraints (do not break)

- **No silent fallback** — configured seed must not degrade to HMAC-only at runtime.
- **No seed disclosure** — seed never in Debug, logs, errors, or test output.
- **Do not change** until separate integration block:
  - `handle_accepted_reality_client`
  - `complete_reality_tls13_handshake`
  - `derive_reality_auth_key`
  - `patch_reality_certificate_der` (legacy HMAC-only API)
- **Do not change** Vision/REALITY accepted flow for configs without `mldsa65Seed`.
- **Do not enable** `reality-mldsa65-crypto` by default.
- **Do not modify** live smoke scripts.

## Risks to avoid

| Risk | Mitigation |
|------|------------|
| Using dest ServerHello instead of generated ServerHello | Document + validate byte source in integration tests |
| Patching DER after encryption | Patch only plaintext cert DER before `build_tls13_certificate_message` |
| Runtime starts with seed but HMAC-only cert | Keep startup gate closed until live path is wired |
| Seed in error strings on validation failure | Context validation errors mention field names only |
| Breaking transcript hash | ML-DSA patch must not alter handshake messages already hashed |

## Related docs

- [REALITY ML-DSA foundation / offline plan](./reality-mldsa65-mlkem-plan.md)
- [REALITY accepted path notes](./reality-accepted-path.md)
