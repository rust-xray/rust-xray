# VLESS Encryption (`mlkem768x25519plus`)

This inbound implementation follows the wire behavior of
[Xray-core @ `5ca6f4b7d4dc20a881d4330e498892697627ec0c`](https://github.com/XTLS/Xray-core/commit/5ca6f4b7d4dc20a881d4330e498892697627ec0c).
It supports `native`, `xorpub`, and `random` traffic-appearance modes; those
modes do not authenticate traffic by themselves. The actual availability is in
[compatibility-status.md](../compatibility-status.md).

NFS is the configured static key-chain material. A 1RTT handshake combines an
ephemeral X25519 exchange with ML-KEM-768 to produce PFS material, derives the
united key, and establishes CommonConn traffic keys. It then issues a ticket
when the configured lifetime permits. A 0RTT handshake finds the ticket's
stored PFS state and atomically consumes the `(ticket, NFS)` replay key before
accepting early traffic. Unknown, expired, or replayed resume attempts fail the
encrypted handshake and do not fall back to VLESS or REALITY.

```
Client -> Server, handshake: NFS-authenticated hello + X25519/ML-KEM material
Server -> Client, handshake: PFS response + ticket when enabled
Client -> Server, post-handshake: CommonConn framed AEAD records
Server -> Client, post-handshake: CommonConn framed AEAD records
```

The AEAD sequence is wire-sensitive: Xray increments the 96-bit nonce
**before** Seal and Open. Both peers therefore use the incremented nonce for
their first traffic record. Changing this to post-increment shifts every record
and is incompatible. `MaxNonce` triggers context rotation after processing the
record at the maximum stored counter; sequence and rotation state remain with
the direction's `TrafficAead`, never with callers or pooled buffers.

CommonConn frames have bounded traffic plaintext and protocol padding. Keep
handshake and traffic buffering local to a connection/session. Static private
keys, ephemeral X25519 private keys, ML-KEM shared secrets, NFS/PFS keys,
united keys, ticket secret material, and replay keys are secret; crypto wrappers
zeroize owned secret bytes on drop where implemented. Never put them in a
general reusable buffer pool: another connection could observe retained memory.

The 0RTT store bounds both the session map and ticket ordering/index at 1024
entries, prunes expiry, and retains replay keys only with their session. Bounding
only one of those structures permits attacker-controlled memory growth through
the other. The dedicated fixture README and upstream/reference vectors describe
exact test inputs; a Rust-self-generated value alone is not interoperability
proof.
