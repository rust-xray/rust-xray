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

## Version works but `xray.out.log` / `xray.err.log` are empty

The entrypoint runs `rw-core version` **separately** from the long-running core.
Seeing `XRay Core: v0.1.0` only proves the binary executes for `version`; it does
**not** prove supervisord started:

```text
rw-core -config http+unix://... -format json
```

If both supervisor log files stay **0 bytes** after node startup:

1. Supervisord may not have started the core program (wrong command, immediate exit before logging, or logs redirected elsewhere).
2. The core may exit before any output (check `supervisord.log` and process list).
3. Previously, `tracing` with no `RUST_LOG` hid `info!` logs — current builds always emit `[rust-xray]` lines on **stderr** before config load.

Diagnostic commands inside the container:

```bash
docker exec -it remnanode sh -lc 'cat /var/log/supervisor/supervisord.log'
docker exec -it remnanode sh -lc 'ps aux | grep -E "rw-core|xray|supervisord|node" | grep -v grep'
docker exec -it remnanode sh -lc 'grep -R "rw-core\|xray" -n /etc /app /opt 2>/dev/null | head -100'
docker exec -it remnanode sh -lc 'tail -300 /var/log/supervisor/xray.out.log'
docker exec -it remnanode sh -lc 'tail -300 /var/log/supervisor/xray.err.log'
docker exec -it remnanode sh -lc 'grep -i ":EE48" /proc/net/tcp /proc/net/tcp6 2>/dev/null || true'
```

Port `61000` is `0xEE48` in `/proc/net/tcp` (127.0.0.1 appears as `0100007F`).

Expected stderr after a successful core start inside Remnawave (tokens redacted):

```text
[rust-xray] main_entry start
[rust-xray] argv: rw-core -config http+unix://...?<redacted> -format json
[rust-xray] mode: run
[rust-xray] config_source_kind: http+unix
[rust-xray] config load success
[rust-xray] API listen resolved: 127.0.0.1:61000 source=routing inbound_tag=REMNAWAVE_API_INBOUND api_tag=REMNAWAVE_API
[rust-xray] Xray API transport selected: mTLS reason=remnawave-http-unix-auto
[rust-xray] Xray API listening on 127.0.0.1:61000 mTLS
```

## Local API smoke (no container)

```bash
bash scripts/remna_compat/run-local-api-smoke.sh
```

Uses `tests/fixtures/remna/remnawave_node_minimal_61000.json` (Xray-style API routing on port 61000).
File-based smoke keeps **plaintext** API (vanilla Xray default). Remnawave `http+unix` mode auto-selects **mTLS**.

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
| `tests/fixtures/remna/remnawave_node_minimal_61000.json` | Routing + dokodemo-door API topology (local smoke, plaintext) |

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

`rust-xray` resolves the gRPC bind address from that topology.

### Vanilla Xray API is plaintext

Upstream **Xray-core** (`app/commander/commander.go`) creates the API server with
`grpc.NewServer()` and **does not enable TLS** on the API listener. Official docs:

```bash
grpcurl -plaintext localhost:10085 list
```

Outside Remnawave, `rust-xray` defaults to **plaintext** (`reason=xray-default-plaintext`).

### Remnawave Node uses mTLS gRPC to Xray API

`remnawave/node` (`src/app.module.ts`) connects `@remnawave/xtls-sdk` with:

```typescript
const certs = getClientCerts();
ChannelCredentials.createSsl(
  Buffer.from(certs.caCertPem),
  Buffer.from(certs.clientKeyPem),
  Buffer.from(certs.clientCertPem),
  { rejectUnauthorized: true },
);
// options: grpc.ssl_target_name_override = 'internal.remnawave.local'
```

Therefore a drop-in `rw-core` inside `remnawave/node` must support **Remnawave mTLS API mode**, not only vanilla plaintext Xray API.

Remnawave generates mTLS CA/server/client certs in Node memory (`initializeMTLSCerts`) and injects server cert/key + verify CA into the API inbound via `generateApiConfig()` → `streamSettings.tlsSettings.certificates`. `rust-xray` reads those PEM blocks from the loaded config when auto mTLS is selected.

Startup logs (no tokens/private keys):

- `Xray config loaded`
- `Xray API starting`
- `Xray API transport selected: mTLS reason=remnawave-http-unix-auto`
- `Xray API listening on … mTLS`
- `REALITY inbound starting`

Quick check:

```bash
bash scripts/remna_compat/check-api.sh 127.0.0.1:61000
```

Diagnostics:

```bash
bash scripts/remna_compat/inspect-remna-mtls.sh
bash scripts/remna_compat/inspect-remna-api-mode.sh
```

### API transport environment

| Variable | Values | Purpose |
|----------|--------|---------|
| `RUST_XRAY_API_TRANSPORT` | `plaintext` \| `tls` \| `mtls` | Explicit transport override |
| `RUST_XRAY_API_TLS_CA` | PEM file path | Client CA for mTLS (or server trust anchor for manual setup) |
| `RUST_XRAY_API_TLS_CERT` | PEM file path | Server certificate |
| `RUST_XRAY_API_TLS_KEY` | PEM file path | Server private key |

Selection order:

1. `RUST_XRAY_API_TRANSPORT=plaintext|tls|mtls` → `reason=env-override`
2. Else Remnawave auto: `http+unix` + `/internal/get-config` + API listen `127.0.0.1:*` → `mtls` (`reason=remnawave-http-unix-auto`)
3. Else → plaintext (`reason=xray-default-plaintext`)

Cert sources for TLS/mTLS (in order):

1. `RUST_XRAY_API_TLS_*` file paths
2. API inbound `streamSettings.tlsSettings.certificates` from loaded config (Remnawave get-config)

**Do not** rely on auto-generated unrelated self-signed CA: Remnawave client trusts only its in-process CA from `getClientCerts().caCertPem`.

Legacy `RUST_XRAY_API_TLS=true|false` maps to `tls` / `plaintext` override.

For manual mTLS checks with grpcurl:

```bash
export RUST_XRAY_API_TLS_CA=/path/ca.pem
export RUST_XRAY_API_CLIENT_CERT=/path/client.pem
export RUST_XRAY_API_CLIENT_KEY=/path/client-key.pem
bash scripts/remna_compat/check-api.sh 127.0.0.1:61000
```

`check-api.sh` prints: `PLAINTEXT_OK`, `TLS_OK`, `MTLS_OK`, `TLS_CLIENTHELLO_TO_PLAINTEXT`, `CERT_REQUIRED`, `CERT_VERIFY_FAILED`.

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
- `Xray API bind OK` and `Xray API listening on 127.0.0.1:61000 mTLS` (Remnawave `http+unix` mode)
- `REALITY runtime loaded OK` and `REALITY inbound bind OK`

On failure, look for `config loaded FAIL`, `Xray API bind FAIL`, `failed to configure API transport`, or `REALITY runtime loaded FAIL`.

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

### `API received TLS ClientHello on plaintext gRPC listener`

**Meaning:** Remnawave/XTLS-SDK is using a **TLS/mTLS gRPC client** against
`127.0.0.1:61000`, while rust-xray is still on **plaintext** (wrong transport mode or startup before get-config TLS material is available).

**Fix:** ensure Remnawave `http+unix` auto mTLS is active and config includes API inbound `streamSettings.tlsSettings`. Expected log:

```text
Xray API transport selected: mTLS reason=remnawave-http-unix-auto
Xray API listening on 127.0.0.1:61000 mTLS
```

Force plaintext only for vanilla Xray debugging:

```bash
export RUST_XRAY_API_TRANSPORT=plaintext
```

### REALITY accepted then VLESS flow mismatch

If logs show REALITY accepted through application stream (`application stream ready`,
`handing off to VLESS inbound`), then VLESS fails with:

```text
account flow does not match request flow xtls-rprx-vision
```

REALITY/TLS handshake already works. Next checks:

1. **`clients[].flow` and `settings.flow` parsing** — startup should log
   `flow_distribution=flow="xtls-rprx-vision" count=N` on each supported inbound
   (no UUID/email). Remnawave may omit per-client `flow` and rely on inbound-level
   `settings.flow` or `network=raw` + `security=reality` inference.
2. **User lookup by UUID** — flow mismatch with `account_flow=""` often means flow
   was not applied at config load or the wrong inbound's user table was selected.
3. **Multiple REALITY listeners** — different listen addresses (e.g. `0.0.0.0:443`
   and `0.0.0.0:8444`) each get their own listener; same-address compatible inbounds
   merge users. Look for `REALITY listener started addr=... tag=...`.
4. **HandlerService AddUser** — dynamic users must include `flow` in
   `xray.proxy.vless.Account`; AddUser upserts flow for an existing UUID/email.

Enhanced mismatch logs include:

```text
VLESS flow mismatch request_flow=xtls-rprx-vision account_flow="" inbound_tag=Third mice user_lookup_result=matched user_id_hint=11111111 flow_distribution=flow="" count=1, flow="xtls-rprx-vision" count=20
```

Diagnostic grep inside remnanode:

```bash
docker exec -it remnanode sh -lc 'grep -E "flow_distribution|flow mismatch|REALITY listener started|supported VLESS REALITY inbound" /var/log/supervisor/xray.out.log | tail -200'
```

Fixtures:

- `tests/fixtures/remna/remnawave_vless_reality_vision_users.json` (same-port merge)
- `tests/fixtures/remna/remnawave_two_reality_inbounds_flow.json` (443 + 8444)

API transport (mTLS vs plaintext) and VLESS flow mismatch are independent blockers.

### Repeated supervisor restarts

If `xray.out.log` shows the same startup banner every ~30–60s, Remna may be
restarting the core when internal status checks fail. New logs include:

- `rust-xray received shutdown signal`
- `critical task exited: api server ...`
- `run_server returning`

Use these to tell whether Remna sent SIGTERM vs the API task crashed.

### Local API verification

```bash
bash scripts/remna_compat/check-api.sh 127.0.0.1:61000

# Optional Node client (requires npm packages):
node scripts/remna_compat/node-getsysstats-smoke.mjs 127.0.0.1:61000
```

### Other API errors

| Symptom | Likely cause |
|---------|----------------|
| `UNIMPLEMENTED` on GetSysStats | `StatsService` missing from `api.services` |
| `grpcurl list` fails, GetSysStats OK | `ReflectionService` disabled (non-fatal) |
| mTLS startup error about tlsSettings | get-config missing Remnawave API inbound TLS block |
| `CERT_REQUIRED` from check-api.sh | API is mTLS; client must present cert |
