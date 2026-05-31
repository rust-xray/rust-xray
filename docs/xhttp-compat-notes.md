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
- HTTP method: POST only for `stream-one`.
- Request body maps to the byte stream read by the existing VLESS inbound parser.
- Response body maps to bytes written by the existing VLESS inbound handler.
- HTTP/1.1 and HTTP/2 `stream-one` are implemented. Official Xray 26.3.27 was observed using HTTP/2 for REALITY + XHTTP in the live smoke.
- REALITY/TLS handshake is unchanged. XHTTP parsing starts only after the accepted REALITY TLS 1.3 application stream is ready.
- VLESS `flow=""` is supported. `flow="xtls-rprx-vision"` over XHTTP is explicitly rejected for this MVP.

## Observed `packet-up` Request Model (Xray 26.3.27 live smoke)

Captured via `./scripts/live_xhttp_smoke/run-live-xhttp-smoke.sh` with official Xray client outbound `mode: "packet-up"`. Diagnostics log request metadata only; session UUID values in paths are redacted to `{session}` and payload bytes are never logged.

### First observed request shape

| Field | Observed value |
|-------|----------------|
| HTTP version | HTTP/2 |
| Method | `GET` |
| Path pattern | `/xhttp/{session}` (UUID suffix after configured base path) |
| Query keys | none |
| Header names | browser-like set: `accept`, `accept-encoding`, `accept-language`, `cache-control`, `dnt`, `pragma`, `priority`, `referer`, `sec-ch-ua*`, `sec-fetch-*`, `user-agent` |
| `content-length` | absent |
| `transfer-encoding` | absent |
| Body chunk sizes | empty (no request body on observed GET) |

### Session / sequence candidates

| Candidate | Location in observed smoke | Notes |
|-----------|---------------------------|-------|
| Session id | `path_segment:1` | UUID appended after `/xhttp/` base path |
| Seq id | not observed | No `seq`, `seqStr`, or related query/header keys seen on captured GET requests |

### Separate download request?

- Official client opened **two independent REALITY/TCP connections** in one curl attempt (`conn_id=1` and `conn_id=2`), each carrying one HTTP/2 GET to a different `/xhttp/{session}` path.
- No follow-up HTTP/2 stream was observed on the same connection after the first GET (`request_index` stayed `0` per connection).
- Interpretation: download side likely uses standalone GET request(s) per session, not `stream-one` duplex POST. Upload POST (with VLESS payload body) was **not captured** in this smoke because the server currently returns `501 Not Implemented` before interop proceeds.

### Server behavior today

- Config parses tolerant for `packet-up`.
- Runtime rejects with `501 Not Implemented` and logs `xhttp mode unsupported mode=packet-up reason=packet_up_not_implemented`.
- Diagnostics event: `xhttp packet-up request shape` with method/path/query/header names/body chunk sizes/session+seq location hints.

## Unsupported (not yet implemented)

- `packet-up` runtime relay/session correlation.
- `packet-down` and multi-request split upload/download sessions beyond diagnostics.
- XMUX behavior beyond tolerant config parsing and explicit runtime reject.
- `seqStr` / `sessionPlacement` runtime handling.
- Chunked request body decoding in the first HTTP/1.1 adapter.
- XUDP over XHTTP.
- CDN bypass tuning beyond the basic HTTP/2 stream-one interop path.
- Vision over XHTTP.

## What the next `packet-up` PR needs

1. **Session routing** — accept `/xhttp/{uuid}` path suffix (in addition to exact `/xhttp` match used by `stream-one`).
2. **Method split** — handle `GET` download channel separately from upload POST; observed client uses GET first over HTTP/2.
3. **Multi-connection state** — correlate sessions across independent REALITY connections using the path UUID (and later query/header placements if observed).
4. **Sequence handling** — implement once upload POST is captured; `seqStr` was not present on observed GET requests.
5. **Body framing** — read upload POST `content-length` / chunked body chunk sizes into VLESS bridge; validate against official client upload request once 501 gate is replaced with staged accept/logging.
6. **Download response** — produce HTTP/2 response body stream for GET download channel after VLESS relay is wired.
7. **Fail-fast policy** — keep explicit `501` for unimplemented sub-features until each step is verified against live smoke diagnostics.

## Diagnostics tooling

- Module: `src/xhttp_diagnostics.rs`
- Live smoke report section: `[packet-up diagnostics]` / per-mode `packet_up_observed_request_shapes`
- Re-run capture: `XHTTP_RUST_LOG=rust_xray::xhttp_diagnostics=warn ./scripts/live_xhttp_smoke/run-live-xhttp-smoke.sh`
