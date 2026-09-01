# rust-xray

`rust-xray` is an experimental Rust implementation of selected Xray-core VLESS
and REALITY behavior. It is not production-ready, is not a drop-in replacement
for Xray-core, and does not claim full Xray-core parity.

The code, tests, and smoke harnesses are the source of truth. The detailed,
authoritative status matrix is [docs/compatibility-status.md](docs/compatibility-status.md).

## Current status

The forward VLESS inbound is substantially implemented: TCP, `xtls-rprx-vision`,
native UDP, Mux TCP (including parallel children), generic Mux UDP, XUDP, dynamic
users, and inbound VLESS Encryption all run through the shared transport and
routing boundary. Final parity closure remains pending.

Supported core behavior includes:

- REALITY raw/TCP pre-auth and accepted TLS 1.3 paths, with X25519 and
  X25519MLKEM768 hybrid key exchange, target-group mirroring, ML-DSA-65,
  position-6 camouflage, post-handshake record detection, CCS tolerance,
  fallback limits, and accepted-path no-fallback semantics.
- VLESS UUID authentication, custom string IDs mapped as UUIDv5, empty flow and
  `xtls-rprx-vision`, native UDP, Mux.Cool, XUDP, DNS fast path, and routing.
- Inbound VLESS Encryption `mlkem768x25519plus`: `native`, `xorpub`, and
  `random` modes; 1RTT and 0RTT; CommonConn traffic; TCP, Vision, Mux, generic
  Mux UDP, XUDP, and native UDP. VLESS outbound encryption is not implemented.
- `RuntimeRouter`, domain/IP rules, `DomainStrategy`, GeoIP/GeoSite, protocol
  sniffing, webhooks, and random/roundRobin/leastPing/leastLoad balancers.
- Xray-compatible gRPC APIs: Stats, Handler, Routing, Logger, Observatory, and
  optional reflection. HandlerService can manage supported VLESS users at runtime.
- RemnaNode 3.3.2 integration verified for the currently implemented API/runtime
  surface; this is not a claim of future RemnaNode compatibility.

## API status

Direct API listeners support TCP, filesystem Unix sockets, and Linux abstract
Unix sockets. An empty `api.listen` selects the internal Commander path.
Plaintext gRPC is the Xray-core-compatible default; optional TLS/mTLS direct
listening is a rust-xray extension. See [docs/remna-compat.md](docs/remna-compat.md).

## Verification

`make live-smoke` is the canonical serial live regression runner. It builds one
fresh release binary, prints its absolute path and SHA-256, then runs REALITY,
UDP, VLESS Encryption (1RTT and 0RTT), and XHTTP in isolated work directories.
It requires `cargo`, `python3`, `curl`, and an Xray-core client binary (`xray`
by default; override with `XRAY_BIN`). Use scoped runners while debugging:

```bash
make live-smoke
make live-smoke-reality
make live-smoke-udp
make live-smoke-vless-encryption
```

`SMOKE_SKIP_BUILD=1` reuses an explicitly available release binary;
`SMOKE_VERBOSE=1` or `SMOKE_KEEP_TMP=1` preserves logs and generated fixtures;
`RUST_XRAY_BIN` and `XRAY_BIN` select exact binaries. The final table separates
`PASS`, `FAIL`, `SKIP ENVIRONMENT`, and `SKIP UNSUPPORTED`; only mandatory
failures produce a nonzero exit code.

The detailed matrix labels evidence as `LIVE PASS`, `DETERMINISTIC PASS`,
`UPSTREAM CLIENT HARNESS LIMITATION`, or `REJECTED BY PROTOCOL`; deterministic
coverage is never presented as a live smoke result.

## Known gaps

Protocol gaps include Reverse / `RequestCommandRvs`, VLESS outbound, the full
outbound ecosystem, FakeDNS/dokodemo DNS behavior, and full Xray-core parity.
The Vision direct relay is functional but does not provide full splice/zero-copy
parity. REALITY accepted-path session resumption and TLS 1.3 CCM suites remain
unimplemented.

Transport gaps are separate: REALITY over gRPC/WebSocket is rejected; XHTTP is
experimental (`stream-one`, `stream-up`, and `packet-up`), while `packet-down`,
XMUX, Vision-over-XHTTP, and XUDP-over-XHTTP remain unavailable.

## Build and test

```bash
cargo fmt
cargo build --release
cargo test
cargo clippy --all-targets
```

For the repository consistency check:

```bash
bash scripts/check-project-consistency.sh
```

## Configuration

Plain VLESS inbounds must explicitly set `"decryption": "none"`; an omitted or
empty value is rejected at startup. This reduced REALITY example uses placeholders
only:

```json
{
  "inbounds": [{
    "tag": "reality-in",
    "listen": "0.0.0.0",
    "port": 443,
    "protocol": "vless",
    "settings": {
      "clients": [{ "id": "00000000-0000-0000-0000-000000000001" }],
      "decryption": "none"
    },
    "streamSettings": {
      "network": "raw",
      "security": "reality",
      "realitySettings": {
        "dest": "www.example.com:443",
        "serverNames": ["www.example.com"],
        "privateKey": "REPLACE_WITH_BASE64URL_REALITY_PRIVATE_KEY",
        "shortIds": ["", "0123456789abcdef"]
      }
    }
  }],
  "outbounds": [{ "protocol": "freedom" }]
}
```

For `mlkem768x25519plus` grammar and valid test-only examples, use
[tests/fixtures/vless/encryption/README.md](tests/fixtures/vless/encryption/README.md)
and the encryption smoke fixtures; do not copy fixture keys into deployments.

`minClientVer` omitted or set to `""` uses the Xray-core-compatible server
default `26.3.27`; an explicit non-empty value overrides it.

## Security notes

VLESS Encryption derives its traffic layer from NFS and PFS material, issues a
ticket after successful 1RTT, and uses bounded server-side session/replay storage
for 0RTT. Replay detection is exact-NFS-wire based; a still-valid ticket may be
reused with fresh valid NFS material. Unknown or expired resumption attempts fail
the encrypted handshake and do not fall back. Secrets used by the crypto paths
are zeroized and are not logged.

VLESS Encryption provides authentication and confidentiality through its protocol
design. `xorpub` and `random` are traffic-appearance modes, not substitutes for
authentication. Vision `COMMAND_DIRECT` cannot bypass the VLESS Encryption layer.
After REALITY pre-auth acceptance, TLS, encryption, and VLESS failures close the
connection rather than falling back to `dest`.

## Roadmap

1. VLESS-4F — Forward Inbound Final Parity Audit + Closure
2. Reverse / `RequestCommandRvs`
3. VLESS outbound foundation
4. Remaining transport and observability parity as prioritized
