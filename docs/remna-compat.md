# Remna / Remnawave compatibility smoke

End-to-end smoke that checks whether `rust-xray` can replace the upstream **Xray**
binary for Remna/Remnawave-style deployments (CLI, panel-like config, gRPC API,
dynamic VLESS users, stats).

This suite is **independent** from `scripts/live_reality_smoke/` (REALITY/Vision
matrix). It does not require a Remna panel or external services beyond what the
fixture already references (`www.microsoft.com:443` as REALITY `dest`).

## How Remnawave starts the core

`remnawave/node:2.7.0` supervisord does **not** use `run -config file.json`.
The upstream command line is:

```text
/usr/local/bin/rw-core -config http+unix://%(ENV_INTERNAL_SOCKET_PATH)s/internal/get-config?token=%(ENV_INTERNAL_REST_TOKEN)s -format json
```

`rust-xray` must accept the same direct invocation (no `run` subcommand), load
JSON from the internal Unix socket, then start inbounds and the Xray-compatible
gRPC API.

Entrypoint also runs:

```bash
rw-core version | head -n 1
```

Version output must be **one line** and must not panic on `BrokenPipe` when
`head` closes stdout after the first line.

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

1. **CLI** — direct `-config` / `run -config`, `-format json`, `version`.
2. **Config** — `http+unix://` loader for Remnawave internal socket.
3. **API** — gRPC on address from `api.listen` or Xray-style dokodemo-door inbound.
4. **Reflection** — `grpcurl list` when `ReflectionService` is enabled.
5. **Stats** — `GetSysStats`, `QueryStats`, `GetStats` with `reset=true`.
6. **Dynamic users** — `AlterInbound` `AddUser` / `RemoveUser` for VLESS.
7. **Report** — JSON at `${REMNA_WORK_DIR}/remna-compat-report.json`.

## Fixtures

| Path | Role |
|------|------|
| `scripts/remna_compat/remna-generated-reality-vless-api.json` | Canonical smoke server config |
| `tests/fixtures/remna/remna-generated-reality-vless-api.json` | Same JSON for Rust config tests |
| `tests/fixtures/remna/reality_vless_api_config.json` | Panel sample (`127.0.0.1:10085`) |
| `tests/fixtures/remna/reality_vless_api_61000_config.json` | Remna node API port (`127.0.0.1:61000`) |

Port **61000** is used in fixtures/docs/diagnostics only — runtime never hardcodes it.

## Alpine / musl (`remnawave/node`)

`remnawave/node:2.7.0` is Alpine-based (musl). A **glibc-linked** binary may
exist on disk but fail at runtime with `no such file or directory` when
executed inside the container.

```bash
# Manjaro / Arch example
sudo pacman -S --needed base-devel musl protobuf pkgconf
rustup target add x86_64-unknown-linux-musl
CARGO_TARGET_X86_64_UNKNOWN_LINUX_MUSL_LINKER=musl-gcc \
  CC_x86_64_unknown_linux_musl=musl-gcc \
  cargo build --release --target x86_64-unknown-linux-musl
```

Mount the musl binary as both `xray` and `rw-core` (read-only):

```yaml
volumes:
  - ./rust-xray:/usr/local/bin/xray:ro
  - ./rust-xray:/usr/local/bin/rw-core:ro
```

## Internal API (`api.listen` / dokodemo-door)

Remna often omits top-level `api.listen` and uses:

- `api.tag` (e.g. `"api"` or `"REMNAWAVE_API"`)
- `api.services`: `HandlerService`, `StatsService`, …
- dokodemo-door inbound on `127.0.0.1:<port>` (commonly **61000**, `XTLS_API_PORT`)
- routing rule: `inboundTag` → `outboundTag` = `api.tag`

`rust-xray` resolves the gRPC bind address from that topology. Default transport
is **plaintext gRPC** (Xray-compatible).

Startup logs (no tokens/private keys):

- `Xray config loaded`
- `Xray API starting`
- `Xray API config listen: …`
- `Xray API listening on … plaintext`
- `Xray API enabled services: …`
- `REALITY inbound starting`

Quick check:

```bash
bash scripts/remna_compat/check-api.sh 127.0.0.1:61000
```

## Troubleshooting

### Broken pipe in `version`

**Meaning:** entrypoint runs `rw-core version | head -n 1`; closing the pipe
after one line must not panic (`failed printing to stdout: Broken pipe`).

**Fix:** use current `rust-xray`; version is a single line and ignores `BrokenPipe`.

### Startup logs in `xray.out.log`

After a musl `rw-core` drop-in, supervisor logs should include (tokens redacted):

- `rust-xray starting` with `command_line=rw-core -config http+unix://...?<redacted> -format json`
- `config_source_kind=http+unix` and `config loaded OK`
- `api_tag`, `api_services`, `API listener resolved` / `detected Xray API listener address`
- `skipping normal inbound startup for API dokodemo-door inbound` when topology uses dokodemo on port 61000
- `Xray API bind OK` and `Xray API listening on 127.0.0.1:61000 plaintext`
- `REALITY runtime loaded OK` and `REALITY inbound bind OK`

On failure, look for `config loaded FAIL`, `Xray API bind FAIL`, or `REALITY runtime loaded FAIL`.

`ObservatoryService` in `api.services` is accepted but not mounted (warn only); `StatsService` must be present for Remna health checks.

### `ECONNREFUSED 127.0.0.1:61000`

**Meaning:** Remna expects StatsService on `XTLS_API_PORT` (often 61000), but
nothing listens there — config may not have loaded from `http+unix://`, or API
inbound was not detected, or the core exited during startup.

**Commands:**

```bash
docker exec -it remnanode sh -lc 'cat /etc/supervisord.conf'
docker exec -it remnanode sh -lc 'supervisorctl status'
docker exec -it remnanode sh -lc 'xerrors'
docker exec -it remnanode sh -lc 'xlogs'
docker exec -it remnanode sh -lc 'ss -lntp | grep 61000 || true'
docker exec -it remnanode sh -lc 'ps aux | grep -E "rw-core|xray" | grep -v grep'
docker exec -it remnanode sh -lc 'tail -200 /var/log/supervisor/xray.out.log'
bash scripts/remna_compat/check-api.sh 127.0.0.1:61000
```

Look for `Xray config loaded` and `Xray API listening on 127.0.0.1:61000 plaintext`.

### `wrong version number` (TLS / wrong protocol)

**Meaning:** something listens on the port, but it is not plaintext gRPC
(TLS client vs plaintext API, or wrong protocol on `XTLS_API_PORT`).

**Commands:**

```bash
grpcurl -plaintext 127.0.0.1:61000 list
grpcurl 127.0.0.1:61000 list
docker exec -it remnanode sh -lc 'env | sort | grep -Ei "xray|core|grpc|ssl|tls|api|secure"'
```

If `grpcurl` without `-plaintext` fails with `wrong version number` but
`-plaintext` works, the Remna client is using TLS against the internal API.

### Other API errors

| Symptom | Likely cause |
|---------|----------------|
| `UNIMPLEMENTED` on GetSysStats | `StatsService` missing from `api.services` |
| `grpcurl list` fails, GetSysStats OK | `ReflectionService` disabled (non-fatal) |

`RUST_XRAY_API_TLS=true` is not implemented; leave unset for plaintext.
