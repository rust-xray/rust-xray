# Live REALITY smoke test

**Compatibility status:** [docs/compatibility-status.md](../../docs/compatibility-status.md)

**Manual local testing only.** This is a smoke configuration for exercising the
REALITY accepted path with a real Xray client against `rust-xray`. **Not for
production.**

## Test key material

These configs use the same **disposable test-only** REALITY key pair as the
committed fixture [`tests/fixtures/reality/basic-xray/`](../../tests/fixtures/reality/basic-xray/README.md).

| Role | Value |
|------|-------|
| REALITY `privateKey` (server) | `MKVGVTTvyEyI7hpl7vP7WKtRXLhH0JieCMHgFdn6A3s` |
| REALITY `publicKey` (client) | `oU1MbEgszawWQJa0S_DxLsNt9G2zyE4rF-CrqvJjTmg` |
| `shortId` | `0123456789abcdef` |
| SNI / `serverName` | `www.microsoft.com` |
| VLESS UUID | `11111111-1111-1111-1111-111111111111` |

The private key is intentionally public for deterministic CI/fixture testing.
**Never reuse this key outside local smoke tests.**

## Files

| File | Purpose |
|------|---------|
| `rust-xray-server.fixture.json` | REALITY + plain VLESS inbound (empty flow) on `127.0.0.1:24443` |
| `xray-compatible-server.fixture.json` | Xray-style server config with log/routing/outbounds/sniffing/sockopt |
| `xray-compatible-server-vision.fixture.json` | Xray-compatible config with `xtls-rprx-vision` |
| `rust-xray-server.vision.fixture.json` | rust-xray server config with `xtls-rprx-vision` |
| `xray-client.template.json` | Xray client template with `__TEST_PUBLIC_KEY__` placeholder |
| `xray-client-smoke.fixture.json` | Pre-filled plain VLESS client config for the committed test key pair |
| `xray-client-smoke.vision.fixture.json` | Vision client config (`flow: "xtls-rprx-vision"`) |
| `rust-xray-server.raw.fixture.json` | Vision server with `streamSettings.network: "raw"` |
| `run-smoke.sh` | Helper: checks tools, writes client config, prints 3-terminal commands |
| `run-live-smoke.sh` | Automated compatibility/stress suite + local report |
| `mux-udp-dns-probe.py` | SOCKS5 UDP DNS probe for Happ mux baseline (`1.1.1.1:53`) |
| `rust-xray-server.fallbacks.fixture.json` | REALITY server with VLESS `fallbacks[]` for smoke |
| `fallback-tcp-servers.py` / `fallback-probe.py` | Local fallback target listeners and TLS trigger helper |
| `smoke-lib.sh` | Shared helpers for `run-live-smoke.sh` |

Quick start (manual):

```bash
TEST_PUBLIC_KEY='oU1MbEgszawWQJa0S_DxLsNt9G2zyE4rF-CrqvJjTmg' \
  bash scripts/live_reality_smoke/run-smoke.sh
```

Automated live smoke (from repo root, requires [Xray-core](https://github.com/XTLS/Xray-core)):

```bash
bash scripts/live_reality_smoke/run-live-smoke.sh
```

The automated runner executes regression checks, Vision stress coverage (100 sequential
+ 50 parallel requests, 100MB download), negative/flow-mismatch cases, network alias
(`raw` vs legacy `tcp`), HTTP (`--http1.1` / `--http2`) and TLS (`--tls-max 1.2` /
default 1.3) modes, VLESS `fallbacks[]` routing (default, SNI/name, HTTP path, ALPN,
PROXY v1/v2), cipher forcing, ML-DSA-65 baseline checks, Happ mux UDP DNS baseline (REALITY/Vision/Mux + `1.1.1.1:53`, server log at
`rust_xray=debug` for `mux udp response frame sent`), then writes a local report
under `/tmp/rust-xray-live-smoke-*/report.txt` with accepted-path counters, Vision
DIRECT command counts, Happ mux baseline log grep counts, AES-GCM decrypt failures,
and curl status summary.

Pass/fail expectations vs upstream: [docs/compatibility-status.md](../../docs/compatibility-status.md).

**XHTTP transport smoke** (separate runner, does not replace this REALITY suite):

```bash
bash scripts/live_xhttp_smoke/run-live-xhttp-smoke.sh
```

See **[scripts/live_xhttp_smoke/README.md](../live_xhttp_smoke/README.md)** and
**[docs/xhttp-compat-notes.md](../../docs/xhttp-compat-notes.md)**.

### Confirmed XHTTP smoke matrix

| Check | Expected |
|-------|----------|
| `mode_default` | PASS |
| `mode_auto` | PASS |
| `mode_stream_one` | PASS |
| `mode_packet_up` (HTTP/2, official Xray 26.3.27) | PASS |
| `mode_auto_download` | PASS |
| `mode_stream_up` | UNSUPPORTED |
| `mode_packet_down` | UNSUPPORTED (expected client config parse fail) |
| `h1_chunked_upload_unit_smoke` | PASS |

Hard gates: all PASS rows above. HTTP/1.1 chunked upload is covered by
`h1_chunked_upload_unit_smoke` (lib tests). **Official Xray H1 origin interop is
not verified** (client uses HTTP/2 on REALITY + XHTTP packet-up).

Optional environment variables for `run-live-smoke.sh`:

| Variable | Default | Purpose |
|----------|---------|---------|
| `TEST_PUBLIC_KEY` | committed fixture public key | REALITY client `publicKey` |
| `SMOKE_SKIP_BUILD` | `0` | Skip `cargo build --bin rust-xray` |
| `SMOKE_SKIP_LIVE` | `0` | Skip the live suite entirely |
| `SMOKE_WORK_DIR` | `/tmp/rust-xray-live-smoke-$$` | Logs + generated client configs |
| `SMOKE_REPORT_PATH` | `${SMOKE_WORK_DIR}/report.txt` | Report output path |
| `SMOKE_DOWNLOAD_10MB_URL` | Cloudflare 10MiB endpoint | 10MB regression download |
| `SMOKE_DOWNLOAD_100MB_URL` | OVH `100Mb.dat` mirror | 100MB stress download |

Manual quick start (legacy):

When using `xray-client.template.json`, replace `__TEST_PUBLIC_KEY__` with the
public key that matches `realitySettings.privateKey` in
`rust-xray-server.fixture.json` (from `xray x25519` or the table above).

**REALITY fields must match between client and server:**

- `publicKey` (client) must correspond to `privateKey` in `rust-xray-server.fixture.json`.
- `shortId` (client) must appear in server `shortIds`.
- `serverName` (client) must appear in server `serverNames`.

Example:

```bash
export TEST_PUBLIC_KEY='oU1MbEgszawWQJa0S_DxLsNt9G2zyE4rF-CrqvJjTmg'
sed "s/__TEST_PUBLIC_KEY__/${TEST_PUBLIC_KEY}/g" \
  scripts/live_reality_smoke/xray-client.template.json \
  > /tmp/xray-client-smoke.json
xray run -config /tmp/xray-client-smoke.json
```

## Run (two terminals)

From the repository root:

**Terminal 1 — rust-xray server:**

```bash
RUST_LOG=info cargo run --bin rust-xray -- scripts/live_reality_smoke/rust-xray-server.fixture.json
```

**Terminal 2 — Xray client** (requires [Xray-core](https://github.com/XTLS/Xray-core)):

```bash
xray run -config scripts/live_reality_smoke/xray-client-smoke.fixture.json
```

**Terminal 3 — trigger traffic:**

```bash
curl -x socks5h://127.0.0.1:10808 https://example.com/ -m 10 -v
```

## Expectations

Validated against **Xray-core 26.3.27**:

- REALITY pre-auth accepts the Xray client (`Accepted` path).
- Default smoke fixtures use **plain VLESS** (`flow: ""`) over REALITY application traffic.
- Vision smoke: `rust-xray-server.vision.fixture.json` + `xray-client-smoke.vision.fixture.json` (`flow: "xtls-rprx-vision"`).
- Vision MVP uses padding framing + DIRECT copy relay (no raw splice).
- Automated `run-live-smoke.sh` covers 10MB/100MB downloads, 100 sequential + 50 parallel
  Vision requests, wrong UUID, flow mismatch negatives, `network: raw` alias, HTTP/TLS
  modes, openssl fallback, and bad shortId/SNI fallback.
- Failures after REALITY accept close the connection (no fallback) — check server logs.

## Notes

- Smoke configs only; do not deploy to production.
- `dest` points at `www.microsoft.com:443` for REALITY camouflage / fallback relay.
- For private captures or alternate keys, use `tests/fixtures/reality/local-*` workflows
  instead of editing these committed smoke files.
