# VLESS Encryption 0RTT

This document describes the implemented **inbound** `mlkem768x25519plus` 0RTT
behavior against Xray-core `main` at
`cd4ce973e9f6ef3a7acf9a7030927b4143f9ea47`. It does not document or claim
VLESS outbound encryption.

## Handshake and traffic semantics

A successful 1RTT inbound handshake derives NFS/PFS/UnitedKey material, creates
the CommonConn encrypted traffic layer, and issues a 16-byte session ticket when
the configured ticket lifetime is non-zero. The server stores the associated PFS
state in its bounded session cache.

A 0RTT client presents that ticket through the current NFS-protected hello and
uses the cached state to derive CommonConn keys immediately. The server sends a
16-byte random prewrite value before its first encrypted traffic record; this is
especially relevant to `random` mode, whose CTR state consumes the configured
prewrite offset before normal traffic.

| Item | Current behavior |
| ---- | ---------------- |
| 1RTT | Issues a ticket and stores resumable server state when lifetime permits |
| 0RTT | Resumes with stored PFS state; does not issue a replacement ticket |
| Ticket reuse | A ticket may be reused while valid with fresh valid NFS material |
| Replay key | Exact NFS shared secret from the current hello, scoped to its ticket |
| Replay | Same ticket + same NFS key is rejected |
| Expiry | Resume allowed only while `now < expires_at`; expired entries are pruned |
| Unknown/expired ticket | Writes invalid-ticket noise then fails the encrypted handshake |
| Replay failure | Fails the encrypted handshake without fallback |
| Disabled lifetime | 0RTT rejected as `ResumeNotAllowed` |
| Cache bound | At most 1024 stored sessions; overflow clears the bounded store |
| Cleanup | Expiry and minute-bucket pruning remove sessions and replay keys |

Unknown, expired, malformed, AEAD-failed, or replayed encrypted handshakes never
fall back to the REALITY destination. After REALITY acceptance, they close.

## Wire outline

The initial 0RTT hello is:

| Field | Wire role |
| ----- | --------- |
| 16-byte IV | Seeds the NFS exchange |
| NFS relay material | Same chain used by 1RTT |
| NFS-AEAD length | Plaintext sentinel selects 0RTT |
| NFS-AEAD ticket | Encrypts the 16-byte cached session key |
| Optional coalesced encrypted traffic | May follow the hello immediately |

The 16-byte plaintext ticket includes an encoded lifetime prefix and random
session bytes; the complete ticket is the cache key. The lifetime prefix is not
a standalone authorization check: the server cache expiry is authoritative.

## Forward inbound matrix

| Feature | Status | Verification | Notes |
| ------- | ------ | ------------ | ----- |
| TCP | Working | LIVE PASS | Native 0RTT TCP smoke resumes after 1RTT |
| Vision TCP | Working | DETERMINISTIC PASS | Direct remains blocked under encryption |
| Native UDP | Working | DETERMINISTIC PASS | Vision native UDP is REJECTED BY PROTOCOL |
| Mux TCP | Working | DETERMINISTIC PASS | CommonConn transport reuse |
| Generic Mux UDP | Working | DETERMINISTIC PASS | Persistent associations |
| XUDP | Working | DETERMINISTIC PASS | GlobalID lifecycle |
| DNS fast path | Working | UPSTREAM CLIENT HARNESS LIMITATION | No corresponding upstream 0RTT client harness row |
| `native` / `xorpub` / `random` | Working | unit + 1RTT LIVE PASS | Traffic appearance modes |

The 1RTT encryption harness exercises live TCP, Vision, Mux, generic UDP, XUDP,
native UDP, and the modes. The separate 0RTT live harness proves native TCP
resumption; other 0RTT transport rows are deterministic coverage, not live
claims.

## Security notes

NFS supplies the non-forward-secret component and the one-time PFS exchange
supplies the forward-secret component used by the traffic layer. The bounded
session/replay store prevents unbounded retention. `xorpub` and `random` affect
traffic appearance only; they are not authentication mechanisms. Secret-bearing
types are zeroized and secret values are not logged.
