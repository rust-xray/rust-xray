# Latency measurement (rust-xray vs Go Xray-core)

Reproducible HTTP timing via `curl` and a small harness script. No runtime code changes — only client-side measurement.

## Prerequisites

- `curl` with proxy support (`-x socks5h://...` or `http://...`)
- Matching client config for **rust-xray** and **Go Xray-core** (same inbound/outbound path, same local SOCKS/HTTP port)

## 1. Run servers with quiet logging

Latency runs should avoid hot-path log overhead:

```bash
# rust-xray
RUST_LOG=warn ./target/debug/rust-xray run -config /path/to/server.json

# Go Xray-core (example)
RUST_LOG=warn xray run -config /path/to/server.json
```

Start the **client** (or local mixed inbound) so the proxy listens on a known port, e.g. `127.0.0.1:10808`.

## 2. Measure through the proxy

```bash
chmod +x scripts/latency/measure-latency.sh

PROXY_URL=socks5h://127.0.0.1:10808 \
TARGET_URL=https://example.com/ \
COUNT=50 \
WARMUP=5 \
scripts/latency/measure-latency.sh
```

Output directory defaults to `./target/latency-report-<UTC-timestamp>/`:

| File | Contents |
|------|----------|
| `report.txt` | Config + min/avg/p50/p95/max per metric |
| `samples.tsv` | One row per measured request |
| `curl-raw.log` | Raw curl stderr/stdout log |

Custom output dir:

```bash
OUT_DIR=./target/latency-rust-xray-1 \
  PROXY_URL=socks5h://127.0.0.1:10808 \
  scripts/latency/measure-latency.sh
```

## 3. Measure without proxy (baseline)

Direct curl to the target (no tunnel):

```bash
unset PROXY_URL
TARGET_URL=https://example.com/ \
  scripts/latency/measure-latency.sh
```

## 4. Compare rust-xray vs Go Xray-core

Use the **same** `TARGET_URL`, `COUNT`, `WARMUP`, and client topology. Only swap the server binary/config:

1. Run rust-xray server + client → `OUT_DIR=./target/latency-rust-xray PROXY_URL=... scripts/latency/measure-latency.sh`
2. Run Go Xray server + client (same ports) → `OUT_DIR=./target/latency-go-xray PROXY_URL=... scripts/latency/measure-latency.sh`
3. Open each `report.txt` and compare **p50** and **p95** for `time_total` (end-to-end) and optionally `time_connect` / `time_appconnect` (TLS/TCP via proxy).

### Metrics (curl `-w`)

| Field | Meaning |
|-------|---------|
| `time_connect` | TCP connect to proxy or origin |
| `time_appconnect` | TLS handshake to proxy or origin |
| `time_starttransfer` | Time until first byte of response |
| `time_total` | Full request |

## Environment reference

| Variable | Default | Description |
|----------|---------|-------------|
| `TARGET_URL` | `https://example.com/` | URL fetched by curl |
| `PROXY_URL` | _(empty)_ | Passed to `curl -x` when set |
| `COUNT` | `50` | Measured requests (after warmup) |
| `WARMUP` | `5` | Discarded warmup requests |
| `OUT_DIR` | `./target/latency-report-<timestamp>` | Report directory |

## Tips

- Increase `COUNT` (e.g. `100`) for stabler p95 on noisy links.
- Keep server and client idle except the harness during the run.
- Repeat each side 2–3 times; compare medians of p50/p95 across runs.
