# VLESS Mux.Cool Compatibility Notes

Scope: this documents the subset implemented by `src/vless/mux.rs`, cross-checked against Xray-core `common/mux` writer/reader semantics.

Reference points:
- Xray-core Go package docs: <https://pkg.go.dev/github.com/xtls/xray-core/common/mux>
- Mux.Cool protocol notes: <https://xtls.github.io/en/development/protocols/muxcool.html>

| Field | Xray-core / Mux.Cool semantics | rust-xray expectation |
| --- | --- | --- |
| Frame length | 2-byte big-endian metadata length, followed by metadata. If `OptionData` is set, a 2-byte big-endian data length and payload follow. | `read_mux_frame` reads metadata first, then optional data. |
| Session id | 16-bit unsigned mux/session id. | `mux_id: u16`. |
| Status | `New = 0x01`, `Keep = 0x02`, `End = 0x03`, `KeepAlive = 0x04`. | `MuxStatus`. |
| Option | `OptionData = 0x01` means a data payload follows. Other bits are not used by this implementation. | `MuxOption { has_data }`. |
| Network | In address metadata: `TCP = 0x01`, `UDP = 0x02`. | `MuxNetwork`. |
| Address metadata | `network`, `port`, `address type`, address bytes. Address types match VLESS-style IPv4/domain/IPv6. | `MuxDestination`. |
| TCP open/data/close | Client sends `New + TCP + destination` with optional initial data; later `Keep + Data`; close is `End`. Server responds with `Keep + Data` and `End`. | One active TCP substream is supported today. |
| UDP packet flow | UDP packet frames carry destination metadata and data. Server response is also a UDP `Keep + Data` frame with destination metadata. | Used for Mux UDP DNS. |
| UDP close/end | Xray-core response writer writes `Keep + Data`; `Close()` writes a separate `End`. | rust-xray does not send `End` after a successful UDP response by default; `RUST_XRAY_MUX_UDP_SEND_CLOSE_AFTER_RESPONSE=1` restores the diagnostic old behavior. |
| mux_id reuse | A mux id is scoped to one substream/datagram lifecycle and must be preserved in all response frames for that lifecycle. | DNS response and end preserve request `mux_id`. |

Mux.Cool UDP semantics:
- Frame length format: `u16be(metadata_len) || metadata || optional u16be(data_len) || data`.
- mux_id/session id: `u16`, preserved across UDP response and `End`.
- Status values: `New=0x01`, `Keep=0x02`, `End=0x03`, `KeepAlive=0x04`.
- Option values: `OptionData=0x01`; set when the frame carries the optional data section.
- network=udp value: `0x02` in address metadata.
- UDP request frame shape: `New` or `Keep` with UDP destination metadata and packet payload.
- UDP response frame shape: `Keep + OptionData` with UDP destination metadata and packet payload.
- Response address metadata: present; rust-xray echoes the peer destination metadata used by the request.
- Close/end requirement: successful UDP responses are data frames only by default; `End` is reserved for explicit close/error/timeout paths or diagnostic compatibility mode.
- mux_id reuse rules: clients may send more UDP packets on the same mux id; rust-xray keeps the id usable after a successful response.
- Timeout/cleanup behavior: timeout closes only the UDP mux id with `End`; it must not close the whole mux session or block unrelated mux frames.

Compatibility constraints:
- Do not use system resolver for Mux UDP DNS.
- Do not close the whole mux session after a UDP DNS packet.
- Keep response payload and close ordering observable in logs.
