# REALITY X25519MLKEM768 design and current status

This is the current design note for the REALITY accepted TLS 1.3 hybrid KEX.
For the authoritative status, see [compatibility-status.md](compatibility-status.md).

## Separation of mechanisms

ML-DSA-65 certificate signing and ML-KEM-768 key exchange are independent:

| Mechanism | Purpose | Current rust-xray status |
| --------- | ------- | ------------------------ |
| ML-DSA-65 | REALITY certificate extension signing | Implemented when `mldsa65Seed` is configured |
| X25519MLKEM768 | TLS 1.3 `key_share` and handshake secret | Implemented on the accepted path |
| `mlkem768x25519plus` | VLESS Encryption traffic/handshake | Separate inbound subsystem |

REALITY pre-auth derives its auth key from the X25519 component. It does not use
the 64-byte hybrid TLS secret.

## Wire semantics

| Direction | Group | Key exchange |
| --------- | ----- | ------------ |
| Client → server | `0x11EC` | ML-KEM-768 encapsulation key (1184 bytes) followed by X25519 public key (32 bytes) |
| Server → client | `0x11EC` | ML-KEM-768 ciphertext (1088 bytes) followed by X25519 public key (32 bytes) |

The accepted TLS 1.3 shared secret is:

```text
ML-KEM shared secret (32 bytes) || X25519 ECDH shared secret (32 bytes)
```

The server observes the selected target ServerHello group. For X25519 it requires
a matching 32-byte client X25519 share. For X25519MLKEM768 it requires a valid
1216-byte client hybrid share, encapsulates to its ML-KEM component, generates an
ephemeral X25519 share, and feeds the combined 64-byte secret to the TLS key
schedule. There is no cross-group fallback on the accepted path.

## Verification boundary

Unit coverage verifies hybrid wire length, malformed-share rejection, target group
mirroring, ML-KEM client/server interoperability, ServerHello encoding, and the
64-byte secret path. The public live REALITY smoke focuses on the broadly
available upstream-client matrix; it must not be read as an exhaustive hybrid-KEX
interop result.

## Remaining work

Remaining REALITY work is unrelated to implementing hybrid KEX itself: exact
upstream uTLS probe fingerprints/timing, MirrorConn timing parity, accepted-path
resumption, TLS CCM suites, and full splice/zero-copy Vision parity.
