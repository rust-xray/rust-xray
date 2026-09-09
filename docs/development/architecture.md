# Architecture and inbound data path

The normalized configuration is the runtime contract. `src/config/xray/raw.rs`
only represents tolerant Xray/Remnawave JSON; validation helpers reject
unsupported combinations; `src/config/normalized.rs` turns supported inputs
into listener/runtime definitions. `src/app.rs` groups inbounds, constructs
shared DNS, routing, outbound, stats, dynamic-user, and encryption state, then
starts listeners.

```
listener
  -> transport preamble (raw TCP or TLS ClientHello)
  -> REALITY inspection / accepted TLS 1.3 application stream / plain raw
  -> VLESS request and authentication
  -> optional VLESS Encryption CommonConn
  -> Vision framing | Mux children | native UDP | TCP relay
  -> RuntimeRouter and OutboundRegistry
  -> selected outbound
```

`src/transport::run_inbound_transport` is the boundary after a REALITY accepted
stream. Raw TCP and XHTTP both dispatch through it; code in `app.rs` and
`reality/` must not hand a decrypted stream directly to VLESS. Before REALITY
acceptance, ordinary or invalid candidate traffic remains on the configured
fallback path. After acceptance, errors close rather than returning to fallback.

The API boundary is `src/api`: generated protobuf types are isolated in
`proto/` and `build.rs`, while service implementations use runtime managers.
Dynamic VLESS users belong to `src/runtime/inbound_users.rs` and user managers;
they are shared by listeners instead of reconstructing config on every request.
Stats state is selected after authentication so accounting follows the logical
inbound/user.

Split relays transfer ownership, rather than clone cryptographic state. A
REALITY application stream moves its read decryptor into one half and its write
encryptor into the other; Vision uses corresponding reader/writer adapters.
Mux TCP creates child tasks whose queued events return to the parent. Any new
split or task should state who owns shutdown, pending buffers, and terminal
errors. See [upstream-parity.md](upstream-parity.md) for the pinned reference.
