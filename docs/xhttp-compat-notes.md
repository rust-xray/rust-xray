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
- Implemented effective modes: `stream-one`, `packet-up` (download GET + upload POST when `packet_up_download_side_ready()`).
- Accepted alias mode: `auto`, mapped conservatively to `stream-one`.
- `stream-up`, `packet-down`, and XMUX remain unsupported (`501` / fail-fast).
- HTTP method: POST only for `stream-one`.
- Request body maps to the byte stream read by the existing VLESS inbound parser.
- Response body maps to bytes written by the existing VLESS inbound handler.
- HTTP/1.1 and HTTP/2 `stream-one` are implemented. Official Xray 26.3.27 was observed using HTTP/2 for REALITY + XHTTP in the live smoke.
- REALITY/TLS handshake is unchanged. XHTTP parsing starts only after the accepted REALITY TLS 1.3 application stream is ready.
- VLESS `flow=""` is supported. `flow="xtls-rprx-vision"` over XHTTP is explicitly rejected for this MVP.

## Download-side reconnaissance (this branch)

Live smoke runs official Xray client modes intended to open a **separate download leg** and captures server-side metadata only (no payload bytes):

| Smoke mode key | Client `xhttpSettings.mode` | `downloadSettings` |
|----------------|----------------------------|--------------------|
| `packet-up` | `packet-up` | `{"path":"/xhttp"}` |
| `stream-up` | `stream-up` | `{"path":"/xhttp"}` |
| `auto-download` | `auto` | `{"path":"/xhttp"}` |
| `packet-down` | `packet-down` | (none) |

Server diagnostics event: **`xhttp download reconnaissance`** (`src/transport/xhttp/diagnostics.rs`), fields:

- `method`, `path` (session UUID redacted as `{session}`), `query_keys`, `header_names`
- `session_id_source` (e.g. `path_segment:1`)
- `upload_download_relation` (e.g. `packet-up:download_get`, `stream-up:download_get`)
- `version`, `body_direction` (`server_to_client` on download GET), `requires_h2`
- `body_chunk_sizes` / `content_length` only (never payload)

Smoke report section **`[xhttp download reconnaissance]`** aggregates the last observed download GET across recon modes.

### Download GET runtime policy

When `xhttp_download_side_ready()` is true (packet-up end-to-end path):

- `GET /xhttp/{session}` binds a bounded download receiver and streams VLESS downstream bytes on the response body.
- Response headers include `Content-Type: text/event-stream`, `Cache-Control: no-store`, `X-Accel-Buffering: no`, and CORS allow headers.
- HTTP/1.1 uses chunked transfer encoding on the download response.
- Duplicate download GET on the same session returns `409 Conflict`.
- Session idle timeout + explicit close still apply; disconnect ends the download stream cleanly.

When download side is not ready (recon-only modes such as `stream-up` / `packet-down` before implementation):

- Return **`501 Not Implemented` immediately** (no long-poll, no session bind).
- Log: `xhttp download side not implemented` (`reason=download_side_not_implemented`).
- Emit `xhttp download reconnaissance` **before** reject.
- Session manager is **not** touched on this path (no corrupt / half-open session).

### Observed download-side semantics (baseline)

| Field | Expected / observed baseline |
|-------|------------------------------|
| Download method | `GET` |
| Download path | `/xhttp/{session}` (no seq suffix on download GET) |
| Upload relation | Separate HTTP request(s); upload POST ack-only |
| Body direction | Download bytes on **GET response body** (`server_to_client`) |
| HTTP version | Official client uses **HTTP/2** on REALITY (`requires_h2: yes`) |
| Session id | `path_segment:1` after configured base path |

Re-run `./scripts/live_xhttp_smoke/run-live-xhttp-smoke.sh` after changes; use `[xhttp download reconnaissance]` to confirm exact shape before implementing download streaming.

### Proposed implementation plan (next PR, no XMUX)

1. **Gate:** flip `xhttp_download_side_ready()` after recon report shows stable shape.
2. **Download GET handler:** `GET /xhttp/{session}` → register bounded download receiver per session (reuse `bind_download_session` / `broadcast_download`).
3. **Response streaming:** stream VLESS downstream bytes on GET response body; bounded mpsc + backpressure; no full-buffer.
4. **Upload path unchanged:** `POST /xhttp/{session}/{seq}` ack-only; bridge reads upload side via existing bounded input.
5. **Session lifecycle:** idle timeout + explicit close; download GET ends cleanly when session closes (no hang).
6. **Modes:** enable for `packet-up` first; extend to `stream-up` / `auto`+`downloadSettings` once shapes match.
7. **Explicit non-goals:** XMUX, `packet-down` mode semantics, query/header `sessionPlacement` until observed.
8. **Verification:** live smoke `mode_packet_up: PASS`; `[xhttp download reconnaissance]` unchanged shape; curl 200 via SOCKS+HTTP.

## Observed `packet-up` downstream policy (Xray 26.3.27 live smoke)

Official client behavior (diagnostics only; session UUID redacted as `{session}`):

| Leg | Method | Path | Body | Where client reads downstream |
|-----|--------|------|------|-------------------------------|
| Download | `GET` | `/xhttp/{session}` | empty | **response body** on the download GET (long-lived HTTP/2 stream) |
| Upload | `POST` | `/xhttp/{session}/{seq}` | VLESS upload chunks | ack only (`200` empty body observed upstream); **not** duplex on upload |

- Separate download side **observed**: standalone GET per session on independent REALITY/H2 connections (often before upload POST).
- Downstream bytes are **not** returned on the upload POST response in observed behavior.

### Runtime policy (this branch)

- Config `mode: packet-up` parses and resolves to effective `packet-up`.
- Runtime is **PARTIAL_UNSUPPORTED** until download-side interop is complete:
  - HTTP/2 `GET` / `POST` packet-up requests return **`501 Not Implemented` immediately** (no long-poll hang).
  - Log: `xhttp packet-up requires download side; not implemented` (`reason=packet_up_download_side_not_implemented`).
  - **No VLESS bridge** is started for packet-up while gated.
- Upload-side modules (`src/transport/xhttp/packet_up*.rs`, bounded input, seq reorder) remain in-tree for the follow-up PR; gated by `packet_up_download_side_ready()` in `src/transport/xhttp/mode.rs`.

### Future PR: packet-up download side (TODO)

1. Flip `packet_up_download_side_ready()` after interop validation.
2. Wire `GET /xhttp/{session}` → bounded download channel ← VLESS downstream (`broadcast_download`).
3. Keep upload `POST /xhttp/{session}/{seq}` ack-only; do **not** duplex downstream on upload response.
4. Close policy: idle timeout + explicit session close; download GET ends when session closes (no infinite hang).
5. Re-run live smoke; target `mode_packet_up: PASS` only when curl checks succeed end-to-end.

## Observed `packet-up` Request Model (Xray 26.3.27 live smoke)

Captured via `./scripts/live_xhttp_smoke/run-live-xhttp-smoke.sh` with official Xray client outbound `mode: "packet-up"`. Diagnostics log request metadata only; session UUID values in paths are redacted to `{session}` and payload bytes are never logged.

### Packet-up observed

| Field | Value |
|-------|-------|
| method | `GET` (download channel observed first); upload uses `POST` per upstream path suffix |
| path | `/xhttp/{session}` for download; `/xhttp/{session}/{seq}` for upload (upstream + path parser) |
| query keys | none on observed GET |
| header names | browser-like set on GET: `accept`, `accept-encoding`, `accept-language`, `cache-control`, `dnt`, `pragma`, `priority`, `referer`, `sec-ch-ua*`, `sec-fetch-*`, `user-agent` |
| session id source | `path_segment:1` — UUID after configured base path |
| seq id source | `path_segment:2` on upload POST (not present on observed GET) |
| body model | GET: empty; upload POST: `content-length` body streamed in chunks (not captured in smoke while server returned 501) |
| separate download side observed | yes — standalone GET per session on independent REALITY connections |
| implemented in this PR | **no** — explicit `501` fail-fast; upload plumbing in-tree but gated until download-side PR |

### First observed request shape (download GET)

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

### Server behavior (this PR)

- Config parses tolerant for `packet-up`.
- Runtime effective mode `packet-up` is **PARTIAL_UNSUPPORTED**:
  - HTTP/2 `GET /xhttp/{session}` and `POST /xhttp/{session}/{seq}` return **`501 Not Implemented` immediately**.
  - Log: `xhttp packet-up requires download side; not implemented`.
  - No VLESS bridge; live smoke classifies `mode_packet_up: UNSUPPORTED` (not FAIL/hang).
- HTTP/1 `packet-up` uses the same explicit `501` path via mode unsupported handling.
- `packet-down`, `stream-up`, and XMUX remain explicit runtime `501`.
- Diagnostics event `xhttp packet-up request shape` is still emitted before reject (shape capture).

## Unsupported (not yet implemented)

- `packet-down` and multi-request split upload/download beyond packet-up MVP.
- XMUX behavior beyond tolerant config parsing and explicit runtime reject.
- `seqStr` / alternate `sessionPlacement` (query/header) — only path suffix observed so far.
- HTTP/1 packet-up adapter.
- Chunked request body decoding in the HTTP/1.1 adapter (stream-one path).
- XUDP over XHTTP.
- CDN bypass tuning beyond the basic HTTP/2 interop path.
- Vision over XHTTP.

## What a future PR still needs

1. **Packet-up download side** — enable `packet_up_download_side_ready()`, bounded GET response streaming, end-to-end live smoke PASS.
2. **Live interop verification** — re-run live smoke with official Xray 26.3.27 client; capture upload POST shape once end-to-end relay works.
3. **sessionPlacement variants** — query/header session id if observed in the wild.
4. **HTTP/1 packet-up** — only if clients use it (observed client uses HTTP/2).
5. **Download refinement** — long-poll semantics, padding, XMUX download reuse.
6. **Packet-down** — separate mode; do not conflate with packet-up upload path.

## Diagnostics tooling

- Module: `src/transport/xhttp/diagnostics.rs`
- Live smoke report sections:
  - `[packet-up diagnostics]` / `packet_up_observed_request_shapes`
  - `[xhttp download reconnaissance]` / download GET metadata
- Re-run capture: `XHTTP_RUST_LOG=rust_xray::xhttp::diagnostics=warn ./scripts/live_xhttp_smoke/run-live-xhttp-smoke.sh`
