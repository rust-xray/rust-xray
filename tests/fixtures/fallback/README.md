# Fallback upstream compatibility fixtures

Deterministic byte vectors for Rust unit/integration tests. Live smoke scripts under
`scripts/live_reality_smoke/` exercise the same behaviors end-to-end; these fixtures avoid
duplicating shell logic.

| File | Meaning |
|------|---------|
| `proxy-v2-tcp4-127.0.0.1.bin` | HAProxy PROXY protocol v2, TCP/IPv4, src `127.0.0.1:12345`, dst `127.0.0.1:24443` (`xver=2`) |

Golden layout (28 bytes): 12-byte signature, `0x21` (v2+PROXY), `0x11` (AF_INET+STREAM),
`0x000C` address block length, 4+4 byte addresses, 2+2 byte ports (big-endian).
