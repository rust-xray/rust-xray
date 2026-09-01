# VLESS Encryption 0-RTT Wire Format (Xray-core cd4ce973)

Upstream reference: `proxy/vless/encryption/client.go`, `server.go` @ `cd4ce973e9f6ef3a7acf9a7030927b4143f9ea47`.

## Client → Server (0-RTT hello)

| Offset | Length | Field | Notes |
|--------|--------|-------|-------|
| 0 | 16 | IV | Random; seeds NFS CTR/AEAD |
| 16 | `RelaysLength` | NFS relay material | Same chain as 1-RTT (X25519/ML-KEM hybrid) |
| 16+Relays | 18 | Encrypted length | NFS AEAD; plaintext `EncodeLength(32)` → sentinel **32** |
| +18 | 32 | Encrypted ticket | NFS AEAD; plaintext 16-byte ticket |
| (coalesced) | var | First upload record(s) | Optional; client may append encrypted traffic immediately |

**Total fixed prefix:** `16 + RelaysLength + 18 + 32` bytes before optional application records.

## Ticket format (16 bytes plaintext)

| Bytes | Content |
|-------|---------|
| 0–1 | `EncodeLength(lifetime_seconds)` — big-endian u16 |
| 2–15 | Random session id |

- Full 16 bytes are the server cache key (`Sessions[ticket]`).
- Lifetime prefix is **not** used for lookup; expiry uses server minute buckets + client-side `Expire`.
- Ticket is NFS-AEAD encrypted on the wire (32 bytes ciphertext); client presents **decrypted** ticket bytes inside NFS AEAD during 0-RTT.

## Server → Client (after 0-RTT accept)

| Field | Notes |
|-------|-------|
| 16-byte server random (`PreWrite`) | Prepended to first server upload record; download AEAD context |
| Encrypted upload records | AEAD context = server random |
| Client download AEAD context | 32-byte **encrypted ticket ciphertext** from hello |

## Replay key

`ReplayKey = NFS shared secret (32 bytes)` from **this** connection's IV+relay exchange.

`ServerSession.NfsKeys.LoadOrStore(nfsKey)` — identical full hello replay rejected; fresh IV (new nfsKey) allowed within ticket lifetime.

## Failure behavior

| Condition | Server action |
|-----------|---------------|
| Unknown / expired ticket | Write random noise 1279–2279 bytes (invalid TLS header), return error |
| Replay (duplicate nfsKey) | Close with replay error (no noise) |
| `ticket_lifetime = 0` | 0-RTT disallowed (`ResumeNotAllowed`) |
| AEAD / malformed | Crypto error, no fallback |

## Session rotation

Ticket is **reusable** within lifetime; no replacement ticket on 0-RTT success (upstream cd4ce973).

## Expiry comparison (rust-xray)

Resume is allowed while **`expires_at > now`** (strict). At **`now >= expires_at`**, the session entry is pruned and subsequent lookups return **`UnknownSession`** (wire-equivalent to unknown ticket after prune). Per-entry `ExpiredSession` is returned only if a stale entry is observed before minute-bucket / instant prune removes it.

## Session cache bounds

- `MAX_STORED_SESSIONS = 1024`; overflow clears the entire map (rust-xray policy; upstream bounded strategy not byte-matched).
- Replay keys (`HashSet` per session) are dropped when the session is removed (expiry, bucket prune, or overflow clear).

## Forward inbound matrix (VLESS-4E.1 baseline)

| Feature | Plain | Vision | Encryption 1-RTT | Encryption 0-RTT |
|---------|-------|--------|------------------|------------------|
| TCP | LIVE PASS | LIVE PASS | LIVE PASS | LIVE PASS (deterministic + live smoke) |
| Native UDP | LIVE PASS | REJECTED BY PROTOCOL | LIVE PASS | DETERMINISTIC PASS |
| Mux TCP | Experimental | Experimental | LIVE PASS | DETERMINISTIC PASS |
| Generic Mux UDP | LIVE PASS | N/A | LIVE PASS | DETERMINISTIC PASS |
| XUDP | Experimental | N/A | LIVE PASS | DETERMINISTIC PASS |
| DNS fast path | Experimental | N/A | LIVE PASS | UNSUPPORTED BY UPSTREAM CLIENT HARNESS |

Vision **DIRECT** remains blocked under VLESS Encryption (`VisionDirectCapability::BlockedByVlessEncryption`) for both 1-RTT and 0-RTT.

