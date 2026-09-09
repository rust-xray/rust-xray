# VLESS inbound

The VLESS request starts with the version and UUID, followed by optional flow
metadata, command, destination address/port, and any bytes coalesced after the
request header. `src/vless/inbound.rs` reads it incrementally with a bounded
header size; `src/vless/protocol.rs` owns byte layout. UUID authentication uses
the selected logical inbound's user manager; custom string IDs are mapped to
the Xray-compatible UUIDv5 form. Dynamic users change that manager through the
Handler API without rewriting the config file.

The authenticated flow determines the relay. Empty flow supports TCP, native
UDP, and Mux. `xtls-rprx-vision` enables Vision's framing constraints; it
rejects native UDP and ordinary Mux where the matrix says so. The command and
destination are routed through `RuntimeRouter` when configured, otherwise the
normal outbound path is used. Initial payload must be forwarded exactly once
after the response header; readers must handle headers and first payload split
across arbitrary transport reads or coalesced in one read.

Request EOF has three distinct meanings. Zero bytes followed by clean EOF is a
clean early close, useful when a peer closes before a request. A partial header
followed by EOF is a truncation error. Once a complete request is parsed,
normal relay and its command-specific close rules apply. Do not turn truncation
into a successful empty request.

Native UDP keeps a framed association until uplink EOF and permits a bounded
downlink grace period. Mux owns independent TCP children and persistent UDP
associations; [mux-xudp.md](mux-xudp.md) describes those lifecycles. Stats are
attached after user lookup and record the protocol path's payload accounting.
VLESS Encryption, if configured, wraps the VLESS stream before this parsing
layer; [vless-encryption.md](vless-encryption.md) describes why Vision cannot
escape that layer. The pinned upstream comparison policy is in
[upstream-parity.md](upstream-parity.md).
