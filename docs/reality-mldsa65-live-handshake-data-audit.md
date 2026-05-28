# REALITY ML-DSA-65 live handshake data audit

## Current status

- `realitySettings.mldsa65Seed` parsing and validation is present in `src/config/xray.rs` via `reality_mldsa65_seed`; bytes are stored as `Mldsa65Seed` on `RealityInboundRuntime`.
- Runtime admission remains closed in `src/main.rs` via `validate_reality_runtime_feature_gates`; configured `mldsa65Seed` returns `ErrorKind::Unsupported`.
- Offline certificate patch primitives are present in `src/reality/mldsa65.rs` and `src/reality/certificate.rs`. `HmacPlusMldsa65` is either feature-backed in tests or returns `Unsupported`.
- Live runtime ML-DSA-65 signing is not enabled. The accepted REALITY/Vision path still uses HMAC-only certificate patching.

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
| Original ClientHello bytes | `src/tls/record.rs`, `TlsClientHelloRecord.handshake_message`; passed from `src/reality/server.rs` into `complete_reality_tls13_handshake` | `Vec<u8>` / `&[u8]` | `TlsClientHelloRecord` owns the contiguous handshake message; TLS13 completion receives a slice | Future ML-DSA live signing would need this slice at certificate patch time inside TLS13 state | Parser supports split ClientHello records and coalesced trailing bytes; `raw_record` is record bytes for dest, `handshake_message` is contiguous handshake bytes |
| Original ServerHello bytes | `src/reality/handshake.rs`, `RealityObservedServerHello.raw_handshake_message` from `extract_observed_server_hello` | `Vec<u8>` | `RealityObservedServerHello` owns cloned first destination ServerHello handshake payload | Future live signing can read it through `RealityTls13ServerState.observed_server_hello` | `fetch_dest_handshake` stores complete TLS records until ServerHello; only the first ServerHello handshake payload is cloned |
| Certificate DER before patch | `src/reality/tls13/state.rs`, `build_encrypted_server_handshake_records`, local `cert_der` cloned from `RealityEphemeralCertificate.der` before `patch_reality_certificate_der` | `Vec<u8>` | Local mutable DER is owned inside the function | Future ML-DSA integration would need mode selection before this local patch call | No network fragmentation risk; DER is generated locally. Current DER only validates Ed25519 tail layout before HMAC-only patch |
| Ed25519 public key | `src/reality/tls13/certificate.rs`, `RealityEphemeralCertificate.public_key_raw`; used in `src/reality/tls13/state.rs` | `[u8; 32]` | `RealityEphemeralCertificate` owns it; `patch_reality_certificate_der` receives `&[u8; 32]` | Already available at the current certificate patch site | No copy risk relevant to wire fragmentation; Debug redacts private key but public key is still treated as signing input |
| REALITY `auth_key` | `src/reality/auth.rs`, `RealityAuthResult.auth_key`; created by `derive_reality_auth_key`; carried by `RealityAccepted.auth` | `[u8; 32]` | `RealityAccepted` owns `RealityAuthResult`; TLS13 state owns `RealityAccepted` | Already available at the current certificate patch site as `self.accepted.auth.auth_key` | Secret is redacted in Debug and zeroized on drop; no wire fragmentation risk |
| `mldsa65Seed` from runtime config | `src/config/xray.rs`, `RealityInboundRuntime.mldsa65_seed` | `Option<Mldsa65Seed>` | Runtime config owns seed | Not passed into accepted path today because runtime gate rejects configured seeds before serving | No wire risk. Must not be logged or included in errors |
| Legacy HMAC-only certificate patch call | `src/reality/tls13/state.rs`, `build_encrypted_server_handshake_records` calls `patch_reality_certificate_der` | `fn(&mut [u8], &[u8; 32], &[u8; 32])` | Mutates local certificate DER | Future selection point is immediately before/at this call, after DER/public key/auth key exist | No fallback from configured ML-DSA to HMAC-only is allowed in future integration |
| ServerHello build/send | `src/reality/tls13/state.rs`, `prepare_server_hello` stores `server_hello_message`; `complete_reality_tls13_handshake` wraps it with `build_handshake_record` and writes to stream | `Vec<u8>` / TLS record `Vec<u8>` | `RealityTls13ServerState` owns handshake message; write path owns record buffer | Future ML-DSA signing needs the handshake message bytes, not the TLS record wrapper | No coalescing risk for generated ServerHello message; record framing is built after message creation |
| Future HmacOnly vs HmacPlusMldsa65 choice | `src/reality/certificate.rs`, `RealityCertificatePatchMode`; live HMAC-only call is still direct in `src/reality/tls13/state.rs` | enum plus patch input | Offline mode owns only borrowed inputs | Future live integration can route the state patch site through mode selection only after all required inputs are present | Silent fallback is forbidden when `mldsa65Seed` is configured |

## Current forbidden functions

- `handle_accepted_reality_client` in `src/reality/server.rs` must not change in this stage.
- `complete_reality_tls13_handshake` in `src/reality/tls13/state.rs` must not change in this stage.
- `derive_reality_auth_key` in `src/reality/auth.rs` must not change.
- Live smoke scripts under `scripts/` must not change.

## Future integration seam

- Runtime config may contain `mldsa65Seed`, but runtime mode continues to reject it until an explicit live integration block.
- Future integration must collect the original ClientHello and generated ServerHello handshake messages at the point where certificate DER, Ed25519 public key, `auth_key`, and seed are all available.
- Future integration must call `HmacPlusMldsa65` only after complete data is available and the certificate DER has the fixed patch range.
- If `mldsa65Seed` is configured, ML-DSA signing failure must abort the accepted path explicitly.
- No fallback from ML-DSA to HMAC-only is allowed when ML-DSA was configured.

## Non-regression rules

- No behavior change for configs without `mldsa65Seed`.
- No seed disclosure in Debug, logs, error strings, panic messages, traces, or test output.
- `reality-mldsa65-crypto` remains non-default.
- Live smoke scripts stay unchanged.
- No ML-DSA to HMAC-only fallback.
