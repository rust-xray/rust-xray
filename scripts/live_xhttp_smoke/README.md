# Live XHTTP Smoke

Interop smoke for official Xray client -> `rust-xray` server:

- VLESS
- `network: "xhttp"`
- `security: "reality"`
- `flow: ""`
- XHTTP path `/xhttp`

Run from the repository root:

```bash
./scripts/live_xhttp_smoke/run-live-xhttp-smoke.sh
```

## What it does

1. Builds `rust-xray` (`cargo build --bin rust-xray`).
2. Starts `rust-xray` as the XHTTP/REALITY server on localhost.
3. Starts the official `xray` client with local SOCKS and HTTP inbounds.
4. Runs `curl` through both local inbounds to an HTTPS target.
5. Runs HTTP/1.1 packet-up chunked upload **unit smoke** (`cargo test --lib` subset).
6. Runs HTTP/1.1 packet-up chunked upload **live TCP smoke** (`cargo test --test xhttp_h1_chunked_live_probe`).
7. Writes `report.txt` with per-mode results and aggregate counters.
8. Keeps `server-<mode>.log` and `client-<mode>.log`.
9. Stops server/client processes after each mode and on exit.

## Requirements

- `cargo`
- official `xray` in `PATH`
- `curl`
- `python3`

## Mode matrix

| Mode | Expected |
|------|----------|
| absent/default | PASS |
| `auto` | PASS |
| `stream-one` | PASS |
| `packet-up` | PASS over HTTP/2 (official Xray client; must not hang) |
| `stream-up` | UNSUPPORTED (must not hang) |
| `auto-download` | PASS |
| `packet-down` | UNSUPPORTED (client config parse fail expected) |
| `h1_chunked_upload_unit_smoke` | PASS (lib duplex tests) |
| `h1_chunked_upload_live_or_origin_smoke` | PASS (live TCP probe; **not** official Xray REALITY/H1 origin) |

At least `default`, `auto`, `stream-one`, and `packet-up` must PASS for acceptance.

## HTTP/1.1 packet-up chunked upload

Official Xray 26.3.27 uses **HTTP/2** for REALITY + XHTTP packet-up in live interop
(`mode_packet_up: PASS`). Direct official-client HTTP/1.1 origin is **not verified**.

This runner validates chunked upload via:

| Gate | What it covers |
|------|----------------|
| `h1_chunked_upload_unit_smoke` | Lib unit tests over duplex (`serve_xhttp_stream_one`) |
| `h1_chunked_upload_live_or_origin_smoke` | Integration tests over real `TcpStream` to `serve_xhttp_stream_one` (same HTTP/1 adapter as post-REALITY app data without H2 preface) |

Report field: `official_xray_h1_origin_interop: NOT_VERIFIED`.

## Environment variables

| Variable | Default | Purpose |
|----------|---------|---------|
| `XHTTP_SERVER_PORT` | `24443` | rust-xray REALITY/XHTTP listen port |
| `XHTTP_SOCKS_PORT` | `10808` | official Xray local SOCKS port |
| `XHTTP_HTTP_PORT` | `10809` | official Xray local HTTP proxy port |
| `XHTTP_TARGET_URL` | `https://example.com/` | curl HTTPS target |
| `XHTTP_WORK_DIR` | `/tmp/rust-xray-live-xhttp-smoke-$$` | logs/report directory |
| `XHTTP_REPORT_PATH` | `${XHTTP_WORK_DIR}/report.txt` | report output path |
| `XHTTP_SKIP_BUILD` | `0` | set to `1` to reuse `target/debug/rust-xray` |
| `XHTTP_MODE_TIMEOUT` | `90` | per-mode watchdog threshold (seconds) |
| `TEST_PUBLIC_KEY` | committed fixture key | REALITY client public key |

## Config files

- `rust-xray-server-xhttp.json` — server template
- `xray-client-xhttp.json` — official client template

Both are copied into `XHTTP_WORK_DIR` with mode-specific ports and `xhttpSettings.mode`.
Packet-up modes inject `extra.scMaxEachPostBytes` / `scMaxBufferedPosts` for Xray client compatibility.

## Report format

```
[xhttp summary]
mode_default: PASS/FAIL
mode_auto: PASS/FAIL
mode_stream_one: PASS/FAIL
mode_packet_up: PASS/UNSUPPORTED/FAIL
mode_stream_up: PASS/UNSUPPORTED/FAIL
mode_auto_download: PASS/UNSUPPORTED/FAIL
mode_packet_down: UNSUPPORTED/FAIL
h1_chunked_upload_unit_smoke: PASS/FAIL
h1_chunked_upload_live_or_origin_smoke: PASS/FAIL
official_xray_h1_origin_interop: NOT_VERIFIED
curl_checks_passed:
curl_checks_failed:
http_version_observed:
xhttp_request_received:
xhttp_bridge_started:
xhttp_bridge_completed:
xhttp_unsupported_mode:
```

Failure classifications include:

- `config_parse_failure`
- `server_start_failure`
- `client_start_failure`
- `reality_failure`
- `http_path_mismatch`
- `unsupported_mode`
- `vless_auth_failure`
- `bridge_failure`
- `curl_failure`
- `timeout`

## Outputs

- `${XHTTP_WORK_DIR}/report.txt`
- `${XHTTP_WORK_DIR}/server-<mode>.log`
- `${XHTTP_WORK_DIR}/client-<mode>.log`
- `${XHTTP_WORK_DIR}/h1-chunked-unit-smoke.log`
- `${XHTTP_WORK_DIR}/h1-chunked-live-smoke.log`

Unsupported XHTTP modes should fail fast during rust-xray runtime instead of hanging the smoke run.

### `packet-up` / download-side diagnostics

The smoke runs recon modes (`packet-up`, `stream-up`, `auto-download`, `packet-down`) with
`downloadSettings` where applicable. Server logs **`xhttp download reconnaissance`** (metadata
only; no payload bytes). Report fields under **`[xhttp download reconnaissance]`**:

- `download_request_observed`, `download_method`, `download_path`
- `download_query_keys`, `download_header_names`, `session_id_source`
- `http_version`, `requires_h2`

Use with `docs/xhttp-compat-notes.md` when extending download-side behavior.
