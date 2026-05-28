# REALITY ML-DSA-65 live integration plan

This document records where live signing inputs exist in rust-xray today, what is
already implemented offline, and the constraints for controlled live integration.

## Current foundation status

| Item | Location | Status |
|------|----------|--------|
| Config parse `mldsa65Seed` | `src/config/xray.rs` | Done — stored on `RealityInboundRuntime` |
| Seed decode / validation | `src/reality/mldsa65.rs` | Done |
| Offline message builder | `build_reality_mldsa65_message` | Done |
| Offline signer / DER patch | `sign_reality_mldsa65_message`, `sign_reality_cert_extension`, `patch_reality_cert_der_with_mldsa65_signature` | Done under `reality-mldsa65-crypto` |
| Certificate patch mode API | `RealityCertificatePatchMode::HmacPlusMldsa65` | Done — used by live path only when seed is configured |
| Runtime capability enum | `RealityMldsa65RuntimeMode` | Done — seed requires `reality-mldsa65-crypto` |
| Live patch context scaffold | `RealityMldsa65LivePatchContext` | Done — offline shape helper remains non-runtime |
| Legacy HMAC cert patch | `patch_reality_certificate_der` | Unchanged — no-seed live path still selects HMAC-only |

## Current live runtime gate

1. Startup gate rejects parsed `mldsa65Seed` without `reality-mldsa65-crypto`
   as `ErrorKind::Unsupported`.
2. Startup gate allows parsed `mldsa65Seed` with `reality-mldsa65-crypto`.
3. No-seed configs still select HMAC-only patching.
4. Seed configs select `HmacPlusMldsa65`; signing or DER patch failure aborts
   the accepted path, with no HMAC-only fallback.

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

- `TlsClientHelloRecord::raw_record` — original ClientHello TLS record bytes
  (`src/tls/record.rs`, passed through `src/main.rs` inspect path).
- `handle_accepted_reality_client` receives `record.raw_record` and passes
  it to `complete_reality_tls13_handshake` (`src/reality/server.rs`).
- `RealityTls13ServerState::update_transcript_client_server_hello` consumes raw
  parsed ClientHello handshake bytes for TLS transcript logic
  (`src/reality/tls13/state.rs`).

### ServerHello bytes

- Destination ServerHello bytes are retained in
  `RealityDestHandshake::raw_server_bytes` (`src/reality/handshake.rs`).
- `handle_accepted_reality_client` clones `raw_server_bytes` before
  `prepare_reality_tls13_state` consumes the handshake and passes the slice to
  `complete_reality_tls13_handshake`.
- Generated ServerHello remains stored in
  `RealityTls13ServerState::server_hello_message` for TLS transcript and record
  generation (`src/reality/tls13/state.rs`).

### Certificate DER / Ed25519 public key

- `generate_reality_ephemeral_ed25519_certificate` in
  `build_encrypted_server_handshake_records` (`src/reality/tls13/state.rs`).
- Mutable `cert_der` exists immediately before
  `patch_reality_certificate_der_with_mode`.

### auth_key

- Derived once during inspect via `derive_reality_auth_key`
  (`src/reality/auth.rs`).
- Stored on `RealityAccepted.auth.auth_key` and copied into
  `RealityTls13ServerState.accepted`.

### mldsa65Seed

- Parsed into `RealityInboundRuntime.mldsa65_seed` (`src/config/xray.rs`).
- Borrowed from `src/main.rs` into `handle_accepted_reality_client`, then into
  `complete_reality_tls13_handshake`.
- Startup gate blocks configs where seed is present unless
  `reality-mldsa65-crypto` is compiled.

### Current HMAC-only patch site (live)

```text
RealityTls13ServerState::build_encrypted_server_handshake_records
  -> generate_reality_ephemeral_ed25519_certificate
  -> patch_reality_certificate_der_with_mode(HmacOnly or HmacPlusMldsa65)
```

This is the only live certificate mutation today. HMAC-only behavior remains the
selected mode when seed is absent.

## Live patching order

1. Confirm runtime gate allows configured seed only under `reality-mldsa65-crypto`.
2. Build `RealityMldsa65LivePatchContext` from transcript-local bytes + runtime seed reference.
3. `validate_reality_mldsa65_live_patch_context` — shape check only.
4. Select `HmacOnly` for no seed, or `HmacPlusMldsa65` for configured seed.
5. Apply legacy HMAC tail through `patch_reality_certificate_der_with_mode`.
6. For `HmacPlusMldsa65`, `sign_reality_cert_extension` is feature-gated and
   `patch_reality_cert_der_with_mldsa65_signature` writes extension offset 126.
7. Continue Certificate / CertificateVerify / Finished generation unchanged.

## Hard constraints (do not break)

- **No silent fallback** — configured seed must not degrade to HMAC-only at runtime.
- **No seed disclosure** — seed never in Debug, logs, errors, or test output.
- **Do not change** `derive_reality_auth_key`.
- Keep `patch_reality_certificate_der` legacy HMAC-only API unchanged.
- **Do not change** Vision/REALITY accepted flow for configs without `mldsa65Seed`.
- **Do not enable** `reality-mldsa65-crypto` by default.
- **Do not modify** live smoke scripts.

## Risks to avoid

| Risk | Mitigation |
|------|------------|
| Using dest ServerHello instead of generated ServerHello | Document + validate byte source in integration tests |
| Patching DER after encryption | Patch only plaintext cert DER before `build_tls13_certificate_message` |
| Runtime starts with seed but HMAC-only cert | Seed path selects `HmacPlusMldsa65` and propagates patch errors |
| Seed in error strings on validation failure | Context validation errors mention field names only |
| Breaking transcript hash | ML-DSA patch must not alter handshake messages already hashed |

## Related docs

- [REALITY ML-DSA foundation / offline plan](./reality-mldsa65-mlkem-plan.md)
- [REALITY accepted path notes](./reality-accepted-path.md)
