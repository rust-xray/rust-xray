# Live REALITY smoke test

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
| `rust-xray-server.fixture.json` | REALITY + VLESS inbound for `rust-xray` on `127.0.0.1:24443` |
| `xray-client.template.json` | Xray client template with `__TEST_PUBLIC_KEY__` placeholder |
| `xray-client-smoke.fixture.json` | Pre-filled client config for the committed test key pair |
| `run-smoke.sh` | Helper: checks tools, writes client config, prints 3-terminal commands |

Quick start:

```bash
TEST_PUBLIC_KEY='oU1MbEgszawWQJa0S_DxLsNt9G2zyE4rF-CrqvJjTmg' \
  bash scripts/live_reality_smoke/run-smoke.sh
```

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

- REALITY pre-auth should accept the Xray client (`Accepted` path).
- Full end-to-end success depends on experimental TLS 1.3 / VLESS / Vision support
  in `rust-xray` (not Xray-core compatible today).
- Failures after REALITY accept may still be useful smoke signal — check server logs.

## Notes

- Smoke configs only; do not deploy to production.
- `dest` points at `www.microsoft.com:443` for REALITY camouflage / fallback relay.
- For private captures or alternate keys, use `tests/fixtures/reality/local-*` workflows
  instead of editing these committed smoke files.
