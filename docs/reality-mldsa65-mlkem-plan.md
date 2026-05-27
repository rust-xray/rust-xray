# REALITY ML-DSA-65 / ML-KEM research plan

This document captures upstream-compatible notes for post-quantum REALITY
extensions. It is a **research foundation** only. Nothing here authorizes
runtime behavior changes on the current accepted REALITY path.

## Upstream-compatible notes

### Server `mldsa65Seed`

- REALITY server config field: `realitySettings.mldsa65Seed`
- Wire format: **base64url, no padding**
- Decoded length: **exactly 32 bytes**
- Upstream derives the signing key pair with `mldsa65.NewKeyFromSeed(seed)` later
  in the handshake path; rust-xray currently parses and stores the seed only.

### Client `mldsa65Verify`

- REALITY client config field: `realitySettings.mldsa65Verify` (client outbound)
- Wire format: **base64url, no padding**
- Decoded length: **exactly 1952 bytes** (ML-DSA-65 public verify key)

### Certificate extension signature

Upstream REALITY signs a certificate extension over:

1. HMAC state accumulated during REALITY auth / handshake preparation
2. Raw **ClientHello** bytes
3. Raw **ServerHello** bytes

The resulting ML-DSA-65 signature is embedded in the certificate extension value
(length **3309 bytes** in upstream layout).

### X25519MLKEM768 is separate

- TLS 1.3 **X25519MLKEM768** hybrid key exchange is a distinct feature from
  ML-DSA-65 certificate extension signing.
- Do **not** mix ML-KEM auth/key-share handling with ML-DSA-65 cert signature
  support when designing or implementing either path.

## rust-xray foundation (this PR)

| Item | Location | Status |
|------|----------|--------|
| Config parse for `mldsa65Seed` | `src/config/xray.rs` | **Done** — stored on `RealityInboundRuntime` |
| Seed decode / validation | `src/reality/mldsa65.rs` | **Done** — length, base64, `privateKey` collision guard |
| Constants + redacted seed type | `src/reality/mldsa65.rs` | **Done** — no sign/verify yet |

Secrets (`mldsa65Seed`, `privateKey`) must never appear in logs or `Debug` output.

## Non-goals (hard constraints for follow-up work)

The following must **not** change until explicitly scoped and tested:

- **No runtime accepted-path changes** — `handle_accepted_reality_client` behavior
  stays as-is.
- **No `complete_reality_tls13_handshake` changes** — TLS 1.3 completion path
  unchanged.
- **No live certificate DER mutation** — existing Ed25519 tail patch path only.
- **No ML-KEM auth derivation changes** — `derive_reality_auth_key` untouched.
- **No Vision / fallback / transport / smoke script changes.**

Future ML-DSA-65 work should add isolated unit/integration tests before wiring
any handshake or certificate mutation.

## Related reading

- [REALITY accepted path notes](./reality-accepted-path.md)
- Upstream Xray REALITY server handshake (Go): `mldsa65Seed`, cert extension
  signing over HMAC + ClientHello + ServerHello
