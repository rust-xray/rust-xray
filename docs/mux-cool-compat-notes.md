# VLESS Mux.Cool compatibility notes

This records the current Mux.Cool inbound implementation in `src/mux/`, checked
against Xray-core wire semantics. It is a scoped inbound status document, not a
claim of complete Mux.Cool or Xray-core parity.

| Wire item | rust-xray behavior |
| --------- | ------------------ |
| Frame metadata | Reads bounded metadata and optional data payload |
| Session ID | 16-bit `mux_id`; retained in child/association responses |
| Statuses | `New`, `Keep`, `End`, and `KeepAlive` |
| Network metadata | TCP and UDP, with IPv4, domain, and IPv6 destinations |
| TCP | Concurrent children with split readers and a bounded downlink queue |
| Generic UDP | Persistent per-SessionID association; routed outbound and stats |
| XUDP | GlobalID-managed association with reattach, expiry, and rebuild |
| DNS `:53` | Numeric destinations use the in-process DNS fast path |

A TCP `New` creates a child relay. Multiple TCP children can be active at once.
A duplicate TCP `New` SessionID replaces its existing child; this is an explicit
intentional divergence documented in the compatibility matrix.

A generic UDP `New` creates a persistent association. Subsequent `Keep` frames
can supply a destination override or reuse the existing association. Replies are
encoded as UDP `Keep + Data` frames. `End` or session shutdown cleans up workers
without stopping unrelated children.

XUDP associations are keyed by GlobalID rather than only the parent Mux ID. A
detached association can reattach to a new parent, destination-less `Keep` is
valid for the attached association, broken outbounds are rebuilt, and detached
associations expire.

Numeric Mux DNS `:53` is a special in-process `DnsEngine` route and intentionally
bypasses the normal router. The special domain-name `:53` resolver hook is
deferred; generic UDP domain destinations are independently supported through
their routed UDP association.

## Vision and VLESS Encryption

Vision native UDP is rejected. Vision ordinary Mux is rejected at flow validation;
the implemented XUDP form is permitted. VLESS Encryption is transparent to the
Mux dispatcher: 1RTT is live-covered and 0RTT transport combinations have
deterministic coverage. Vision `COMMAND_DIRECT` is blocked under VLESS Encryption,
so encrypted traffic cannot bypass CommonConn.

## Evidence

- `tests/unit/mux/` covers parsing, TCP children, packet UDP, and XUDP lifecycle.
- `scripts/live_udp_smoke/run-live-udp-smoke.sh` covers native UDP, generic Mux
  UDP, XUDP, persistence, and routing with local services.
- `scripts/live_vless_encryption_smoke/` covers encrypted 1RTT Mux/XUDP and
  deterministic 0RTT transport cases.
