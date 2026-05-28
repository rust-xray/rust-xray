# REALITY ML-DSA-65 live handshake data audit

## Current status

- `realitySettings.mldsa65Seed` parsing and validation is present in `src/config/xray.rs` via `reality_mldsa65_seed`; bytes are stored as `Mldsa65Seed` on `RealityInboundRuntime`.
- Runtime admission remains closed without `reality-mldsa65-crypto`; with that feature, `validate_reality_runtime_feature_gates` allows configured `mldsa65Seed`.
- Offline certificate patch primitives are present in `src/reality/mldsa65.rs` and `src/reality/certificate.rs`. `HmacPlusMldsa65` is feature-backed or returns `Unsupported`.
- Live runtime ML-DSA-65 patch selection is wired for configured seeds under `reality-mldsa65-crypto`; accepted REALITY/Vision without `mldsa65Seed` still uses HMAC-only certificate patching.

## Required data for ML-DSA-65 live certificate extension signing

- Ed25519 public key: 32 bytes from the generated ephemeral certificate.
- `auth_key`: 32-byte REALITY auth key.
- Original ClientHello: raw TLS ClientHello handshake message bytes.
- Original ServerHello: raw TLS ServerHello handshake message bytes.
- Certificate DER with ML-DSA-65 extension placeholder.
- `mldsa65Seed`: server-side `RealityInboundRuntime` seed.
- Fixed DER offset: `MLDSA65_REALITY_CERT_EXTENSION_DER_OFFSET == 126`.
- Signature length: `MLDSA65_SIGNATURE_LEN == 3309`.

## Current data availability in Rust codebase

| Item | Location | Type | Ownership | Future API/lifetime work | Copy/fragmentation/coalescing risk |
| --- | --- | --- | --- | --- | --- |
| Original ClientHello bytes | `src/tls/record.rs`, `TlsClientHelloRecord.raw_record`; passed from `src/reality/server.rs` into `complete_reality_tls13_handshake` | `Vec<u8>` / `&[u8]` | `TlsClientHelloRecord` owns the original TLS record bytes; TLS13 completion receives a slice | Already passed to the certificate patch mode selector | Parser preserves `raw_record`; it may be a TLS record wrapper rather than parsed handshake-only bytes |
| Original ServerHello bytes | `src/reality/handshake.rs`, `RealityDestHandshake.raw_server_bytes`; cloned in `src/reality/server.rs` before `prepare_reality_tls13_state` consumes the handshake | `Vec<u8>` / `&[u8]` | Destination handshake owns the upstream bytes; server accepted path owns a clone while TLS13 completion runs | Already passed to the certificate patch mode selector | Contains the bytes fetched from upstream through ServerHello; callers must preserve exact transcript intent |
| Certificate DER before patch | `src/reality/tls13/state.rs`, `build_encrypted_server_handshake_records`, local `cert_der` cloned from `RealityEphemeralCertificate.der` before `patch_reality_certificate_der_with_mode` | `Vec<u8>` | Local mutable DER is owned inside the function | Mode selection is now passed into this local patch call | No network fragmentation risk; DER is generated locally. ML-DSA mode requires the fixed extension patch range |
| Ed25519 public key | `src/reality/tls13/certificate.rs`, `RealityEphemeralCertificate.public_key_raw`; used in `src/reality/tls13/state.rs` | `[u8; 32]` | `RealityEphemeralCertificate` owns it; `patch_reality_certificate_der` receives `&[u8; 32]` | Already available at the current certificate patch site | No copy risk relevant to wire fragmentation; Debug redacts private key but public key is still treated as signing input |
| REALITY `auth_key` | `src/reality/auth.rs`, `RealityAuthResult.auth_key`; created by `derive_reality_auth_key`; carried by `RealityAccepted.auth` | `[u8; 32]` | `RealityAccepted` owns `RealityAuthResult`; TLS13 state owns `RealityAccepted` | Already available at the current certificate patch site as `self.accepted.auth.auth_key` | Secret is redacted in Debug and zeroized on drop; no wire fragmentation risk |
| `mldsa65Seed` from runtime config | `src/config/xray.rs`, `RealityInboundRuntime.mldsa65_seed`; passed from `src/main.rs` into `handle_accepted_reality_client` | `Option<Mldsa65Seed>` / `Option<&Mldsa65Seed>` | Runtime config owns seed; accepted path borrows it for the handshake | Already available at certificate patch mode selection | No wire risk. Must not be logged or included in errors |
| Legacy HMAC-only certificate patch call | `src/reality/tls13/state.rs`, `build_encrypted_server_handshake_records` calls `patch_reality_certificate_der_with_mode` with `RealityCertificatePatchMode::HmacOnly` when no seed is configured | mode enum plus `RealityCertificatePatchInput` | Mutates local certificate DER | HMAC-only remains the no-seed mode | No fallback from configured ML-DSA to HMAC-only is allowed |
| ServerHello build/send | `src/reality/tls13/state.rs`, `prepare_server_hello` stores `server_hello_message`; `complete_reality_tls13_handshake` wraps it with `build_handshake_record` and writes to stream | `Vec<u8>` / TLS record `Vec<u8>` | `RealityTls13ServerState` owns handshake message; write path owns record buffer | Future ML-DSA signing needs the handshake message bytes, not the TLS record wrapper | No coalescing risk for generated ServerHello message; record framing is built after message creation |
| HmacOnly vs HmacPlusMldsa65 choice | `src/reality/certificate.rs`, `select_reality_certificate_patch_mode`; called from `src/reality/tls13/state.rs` before certificate patching | enum plus borrowed inputs | Mode borrows seed and original hello slices for the patch call only | No additional lifetime work for the current live selection | Silent fallback is forbidden when `mldsa65Seed` is configured |

## Current forbidden functions

- `handle_accepted_reality_client` in `src/reality/server.rs` should only change for explicit ML-DSA live integration wiring.
- `complete_reality_tls13_handshake` in `src/reality/tls13/state.rs` should only change for explicit ML-DSA live integration wiring.
- `derive_reality_auth_key` in `src/reality/auth.rs` must not change.
- Live smoke scripts under `scripts/` must not change.

## Future integration seam

- Runtime config may contain `mldsa65Seed`; without `reality-mldsa65-crypto` it is still rejected, with the feature it selects `HmacPlusMldsa65`.
- Live integration passes original ClientHello record bytes and upstream ServerHello bytes into TLS13 completion at the point where certificate DER, Ed25519 public key, `auth_key`, and seed are available.
- Live integration calls `HmacPlusMldsa65` only after complete data is available; the patch call still rejects certificate DER without the fixed patch range.
- If `mldsa65Seed` is configured, ML-DSA signing or patch failure aborts the accepted path explicitly.
- No fallback from ML-DSA to HMAC-only is allowed when ML-DSA was configured.

## Non-regression rules

- No behavior change for configs without `mldsa65Seed`.
- No seed disclosure in Debug, logs, error strings, panic messages, traces, or test output.
- `reality-mldsa65-crypto` remains non-default.
- Live smoke scripts stay unchanged.
- No ML-DSA to HMAC-only fallback.
