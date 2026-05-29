# Remna / Remnawave compatibility smoke

End-to-end smoke that checks whether `rust-xray` can replace the upstream **Xray**
binary for Remna/Remnawave-style deployments (CLI, panel-like config, gRPC API,
dynamic VLESS users, stats).

This suite is **independent** from `scripts/live_reality_smoke/` (REALITY/Vision
matrix). It does not require a Remna panel or external services beyond what the
fixture already references (`www.microsoft.com:443` as REALITY `dest`).

## Quick start

```bash
# From repo root (requires: cargo, curl, python3, grpcurl, upstream xray client)
bash scripts/remna_compat/run-remna-compat-smoke.sh
```

Optional environment:

| Variable | Default | Purpose |
|----------|---------|---------|
| `REMNA_PUBLIC_KEY` | committed fixture key | Client REALITY `publicKey` |
| `REMNA_SKIP_BUILD` | `0` | Skip `cargo build --bin xray` |
| `REMNA_SKIP_LIVE` | `1` | Skip smoke entirely |
| `REMNA_WORK_DIR` | `/tmp/rust-xray-remna-compat-$$` | Temp logs and report |

## What it verifies

1. **CLI** — `./xray run -config` starts with the Remna-like fixture.
2. **API** — gRPC listens on `127.0.0.1:10185` (`HandlerService`, `StatsService`, `ReflectionService`).
3. **Reflection** — `grpcurl list` shows Stats/Handler services.
4. **Stats** — `GetSysStats`, `QueryStats`, `GetStats` with `reset=true`.
5. **Dynamic users** — `AlterInbound` `AddUser` / `RemoveUser` for VLESS.
6. **Traffic** — `curl` via upstream **xray** SOCKS client through the added user to a local HTTP server.
7. **Report** — JSON at `${REMNA_WORK_DIR}/remna-compat-report.json` with per-step PASS/FAIL fields.

## Fixtures

| Path | Role |
|------|------|
| `scripts/remna_compat/remna-generated-reality-vless-api.json` | Canonical smoke server config |
| `tests/fixtures/remna/remna-generated-reality-vless-api.json` | Same JSON for Rust config tests |
| `tests/fixtures/remna/reality_vless_api_config.json` | Earlier Remna panel sample (unit tests) |
| `scripts/remna_compat/xray-client-remna.template.json` | Upstream xray client template |

Ports are chosen to avoid `live_reality_smoke` defaults (`24443`, `10085`, `10808`).

## gRPC helpers

`scripts/remna_compat/encode-handler-request.py` builds `AlterInbound` JSON for
`grpcurl` (stdlib-only protobuf wire encoding). Example:

```bash
python3 scripts/remna_compat/encode-handler-request.py add-user \
  --email remna-dynamic@example.test \
  --id 22222222-2222-2222-2222-222222222222 \
  --flow xtls-rprx-vision
```

## Report fields

- `cli_run_passed`
- `api_reflection_passed`
- `getsysstats_passed`
- `add_user_passed`
- `curl_added_user_passed`
- `stats_query_passed`
- `stats_reset_passed`
- `remove_user_passed`
- `curl_removed_user_failed_as_expected`

## CI / local notes

- Install [grpcurl](https://github.com/fullstorydev/grpcurl) and the upstream
  [Xray](https://github.com/XTLS/Xray-core) client (`xray` in `PATH`) for full
  curl coverage.
- Without `xray` client, API steps still run; curl-related report fields are
  marked failed.
- Logs: `${REMNA_WORK_DIR}/server.log`, `client.log`, `http.log` (no private
  keys beyond what is already in the committed fixture).
