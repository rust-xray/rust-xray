# Vision

Vision is the `xtls-rprx-vision` VLESS flow. It pads outbound chunks, incrementally
unpads inbound chunks, and filters TLS-shaped traffic before it switches relay
behavior. Its parser owns fragmented command/header bytes until a complete
frame exists; pending output uses ownership-preserving `Bytes` progression, and
padding is written into the final allocation where practical. These are durable
allocation rules, not a promise of splice or zero-copy parity.

```
TLS/Vision framed
  -> COMMAND_DIRECT observed by reader
  -> pending framed writer output drains
  -> reader and writer independently enable raw mode
  -> direct relay
```

`COMMAND_DIRECT` is a lifecycle transition, not permission to discard queued
data. The reader retains any read-ahead bytes and hands them to raw mode before
reading the socket again. The writer drains its padded/framed output before raw
writes begin. Flush and shutdown do the same draining; FIN and RST retain their
underlying socket meanings rather than becoming Vision framing commands.

For classic REALITY traffic, the application stream provides the controlled raw
DIRECT capability. Encrypted VLESS Vision must not bypass VLESS Encryption or
CommonConn: its direct capability is blocked so encryption remains the traffic
layer. Vision's available command combinations are scoped by the
[compatibility matrix](../compatibility-status.md), while accepted TLS sequence
ownership is described in [reality.md](reality.md).
