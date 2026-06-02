# XHTTP Compatibility Notes

Scope: server-side VLESS inbound transport MVP, cross-checked against Xray-core `transport/internet/splithttp` / XHTTP naming.

## Upstream Shape

- XHTTP is a separate HTTP-layer transport. Xray also keeps the legacy `splithttp` name; configs may use `network: "xhttp"` or `network: "splithttp"` / `splitHTTP`.
- The transport has multiple modes: `auto`, `stream-one`, `stream-up`, `packet-up`, `packet-down`, and older split upload/download behavior. `auto` lets upstream choose based on settings and HTTP version; this MVP treats absent/`auto` without download settings as `stream-one`.
- `stream-one` uses one POST request. Client upload bytes are carried in the request body; server download bytes are carried in the response body.
- `stream-up` and `packet-up` use a session id to correlate independent upload/download HTTP requests on `/xhttp/{session}`.
- `packet-up` upload posts additionally use a sequence suffix: `/xhttp/{session}/{seq}`.
- Session ids are read from path suffix in this MVP (`/xhttp/{session}` / `/xhttp/{session}/{seq}`).
- `path` is the HTTP request target that identifies the transport endpoint. `host` maps to Host header validation when configured.

## MVP Mapping

- Accepted config networks: `xhttp`, `splithttp`, and case-insensitive `splitHTTP`.
- **Supported effective modes:** `stream-one`, `packet-up` (when `packet_up_download_side_ready()`), `stream-up` (when `stream_up_download_side_ready()`).
- **Accepted alias:** `auto` → `stream-one` (conservative default without download settings).
- **Unsupported / gated:** `packet-down`, XMUX → `501` / fail-fast.
- REALITY/TLS handshake is unchanged. XHTTP parsing starts after the accepted REALITY TLS 1.3 application stream is ready.
- VLESS `flow=""` is supported. `flow="xtls-rprx-vision"` over XHTTP is explicitly rejected at startup.

## Confirmed live smoke matrix (`experiment`)

From `./scripts/live_xhttp_smoke/run-live-xhttp-smoke.sh` with official Xray **26.3.27**:

| Check | Result |
|-------|--------|
| `mode_default` | PASS |
| `mode_auto` | PASS |
| `mode_stream_one` | PASS |
| `mode_packet_up` (HTTP/2) | PASS |
| `mode_stream_up` (HTTP/2) | PASS |
| `mode_auto_download` | PASS |
| `mode_packet_down` | UNSUPPORTED (expected client config parse fail) |
| `h1_chunked_upload_unit_smoke` | PASS |

**Official Xray HTTP/1.1 origin interop for packet-up chunked upload: not verified**
(Xray client observed on REALITY uses HTTP/2).

## Stream-up runtime (current branch)

When `stream_up_download_side_ready()` is true:

| Leg | Method | Path | Body | Response |
|-----|--------|------|------|----------|
| Download | `GET` | `/xhttp/{session}` | empty | long-lived response (`text/event-stream`; chunked on HTTP/1.1) |
| Upload | `POST` | `/xhttp/{session}` | long-lived VLESS stream | `200` when upload stream ends |

- Separate session manager from `packet-up`; shared bridge/input/download channel patterns only.
- Duplicate download GET or upload POST on the same session → `409 Conflict`.
- Download recv idle timeout; disconnect of either leg cleans the session.
- Early downstream bytes before GET attach are buffered until download binds.
- Official client uses **HTTP/2** on REALITY for end-to-end interop (`mode_stream_up: PASS`).

## Packet-up runtime (current branch)

When `packet_up_download_side_ready()` is true:

| Leg | Method | Path | Body | Response |
|-----|--------|------|------|----------|
| Download | `GET` | `/xhttp/{session}` | empty | long-lived response (`text/event-stream`; chunked on HTTP/1.1) |
| Upload | `POST` | `/xhttp/{session}/{seq}` | VLESS chunks | ack-only `200` (not duplex on upload) |

- Limits: `scMaxEachPostBytes`, `scMaxBufferedPosts`, bounded input backpressure.
- Duplicate download GET on the same session → `409 Conflict`.
- HTTP/1.1 upload accepts `Content-Length` and `Transfer-Encoding: chunked` (streaming, no full-body buffer).
- Official client uses **HTTP/2** on REALITY for end-to-end interop (`mode_packet_up: PASS`).

## Download-side diagnostics

Live smoke still runs recon modes with `downloadSettings` where applicable and logs
**`xhttp download reconnaissance`** (metadata only). For unsupported modes such as
`packet-down`, server returns **`501 Not Implemented`** immediately and emits
reconnaissance before reject.

## Unsupported (not yet implemented)

- `packet-down`, XMUX (runtime `501` / fail-fast)
- XUDP over XHTTP
- Vision over XHTTP (rejected at startup)
- `seqStr` / alternate `sessionPlacement` (query/header) — only path suffix implemented
- Chunked request body on **stream-one** HTTP/1.1 path (still `501`)

## Future work (non-goals for current baseline)

1. Official Xray **HTTP/1.1 origin** interop verification for packet-up chunked upload.
2. `packet-down` mode semantics beyond fail-fast recon.
3. XMUX concurrency controls beyond tolerant parse + runtime reject.
4. Query/header `sessionPlacement` variants if observed in the wild.

## Diagnostics tooling

- Module: `src/transport/xhttp/diagnostics.rs`
- Live smoke report: `[xhttp download reconnaissance]`, `[packet-up diagnostics]`
