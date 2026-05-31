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
5. Writes `report.txt` with per-mode results and aggregate counters.
6. Keeps `server-<mode>.log` and `client-<mode>.log`.
7. Stops server/client processes after each mode and on exit.

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
| `packet-up` | PASS or UNSUPPORTED (must not hang) |
| `stream-up` | PASS or UNSUPPORTED (must not hang) |
| `packet-down` | UNSUPPORTED or FAIL (must not hang) |

At least `default`, `auto`, and `stream-one` must PASS for acceptance.

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

## Report format

```
[xhttp summary]
mode_default: PASS/FAIL
mode_auto: PASS/FAIL
mode_stream_one: PASS/FAIL
mode_packet_up: PASS/UNSUPPORTED/FAIL
mode_stream_up: PASS/UNSUPPORTED/FAIL
mode_packet_down: UNSUPPORTED/FAIL
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

Unsupported XHTTP modes should fail fast during rust-xray runtime instead of hanging the smoke run.

### `packet-up` diagnostics mode

The smoke always runs `packet-up` and captures server-side request-shape logs for implementation planning (no payload bytes logged). Report fields:

- `packet_up_observed_request_shapes` — lines containing `xhttp packet-up request shape`
- summary section `[packet-up diagnostics]`

Use these logs with `docs/xhttp-compat-notes.md` when preparing the next packet-up implementation PR.
