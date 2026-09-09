# Mux, generic UDP, and XUDP

Mux.Cool has a parent VLESS stream and per-`mux_id` children. Frames carry
`New`, `Keep`/data, `End`, and `KeepAlive`; the parent serializes responses while
TCP child reader tasks publish downlink events through a bounded channel.
`mux_id` is only meaningful within that parent. A duplicate TCP `New` replaces
the existing child as documented in the compatibility matrix.

Each TCP child owns an outbound writer and an abortable reader task. Replacing
or removing it aborts the reader, but an event may already be queued. The child
generation token accompanies every event so an event from generation N cannot
be applied to a replacement at generation N+1 with the same `mux_id`. Parent
shutdown aborts remaining tasks.

Generic Mux UDP creates a persistent routed association on `New`; `Keep`/data
uses it, `End` removes it, and replies retain the session association. Duplicate
`New` follows the documented replacement behavior. The opening destination is
routed; response association and idle lifecycle are kept with that session.

XUDP uses `GlobalID` as a cross-parent association identity and `mux_id` as the
current parent-local attachment. `New` creates or reattaches; `Keep` can carry
a destination or be destination-less while attached; `End` detaches/removes as
the state dictates. Detached sessions remain available for reattach until
expiry, and a sweeper removes expired state. A broken routed outbound is rebuilt
for the association rather than confusing it with a new `GlobalID`.

Numeric Mux DNS `:53` has a deliberate in-process `DnsEngine` fast path;
domain-name special handling is deferred. Read [routing.md](routing.md) for
ordinary routing and [compatibility-status.md](../compatibility-status.md) for
intentional divergences and remaining restrictions.
