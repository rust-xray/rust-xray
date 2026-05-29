# Remna / Remnawave compatibility smoke

Automated drop-in check: build `rust-xray`, run it as `xray`, exercise gRPC API and
dynamic VLESS users. See [docs/remna-compat.md](../../docs/remna-compat.md) for details.

```bash
bash scripts/remna_compat/run-remna-compat-smoke.sh
```

Requirements: `cargo`, `curl`, `python3`, `grpcurl`, upstream `xray` client binary.
