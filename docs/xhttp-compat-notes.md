# XHTTP Compatibility Notes

Scope: server-side VLESS inbound transport MVP, cross-checked against Xray-core `transport/internet/splithttp` / XHTTP naming.

## Upstream Shape

- XHTTP is a separate HTTP-layer transport. Xray also keeps the legacy `splithttp` name; configs may use `network: "xhttp"` or `network: "splithttp"` / `splitHTTP`.
- The transport has multiple modes: `auto`, `stream-one`, `packet-up`, `packet-down`, and older split upload/download behavior. `auto` lets upstream choose based on settings and HTTP version; this MVP treats it as `stream-one`.
- `stream-one` uses one POST request. Client upload bytes are carried in the request body; server download bytes are carried in the response body.
- Packet modes use a session id plus sequence values to correlate independent upload/download HTTP requests. Upstream material names include `sessionId`, `seqStr`, `sessionPlacement`, `mode`, `path`, `host`, `xmux`, `xPaddingBytes`, `packet-up`, and `packet-down`.
- Session ids may be placed in request metadata such as path/query/header depending on upstream settings. This MVP does not implement those multi-request session modes.
- `path` is the HTTP request target that identifies the transport endpoint. `host` maps to Host header validation when configured.
- Advanced options include XHTTP/XMUX concurrency and reuse controls, padding ranges (`xPaddingBytes`), browser dialer behavior, and separate upload/download settings.

## MVP Mapping

- Accepted config networks: `xhttp`, `splithttp`, and case-insensitive `splitHTTP`.
- Implemented effective mode: `stream-one`.
- Accepted alias mode: `auto`, mapped conservatively to `stream-one`.
- HTTP method: POST only.
- Request body maps to the byte stream read by the existing VLESS inbound parser.
- Response body maps to bytes written by the existing VLESS inbound handler.
- HTTP/1.1 is implemented. HTTP/2 is not implemented in this patch.
- REALITY/TLS handshake is unchanged. XHTTP parsing starts only after the accepted REALITY TLS 1.3 application stream is ready.
- VLESS `flow=""` is supported. `flow="xtls-rprx-vision"` over XHTTP is explicitly rejected for this MVP.

## Unsupported

- `packet-up`, `packet-down`, and multi-request split upload/download sessions.
- XMUX behavior beyond tolerant config parsing.
- `sessionId`, `seqStr`, and `sessionPlacement` runtime handling.
- Chunked request body decoding in the first HTTP/1.1 adapter.
- XUDP over XHTTP.
- HTTP/2 and CDN bypass tuning.
- Vision over XHTTP.
