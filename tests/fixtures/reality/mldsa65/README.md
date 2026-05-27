# REALITY ML-DSA-65 upstream vectors

Golden vectors for **server-side `mldsa65Seed`** and **client-side `mldsa65Verify`**
compatibility checks. Generated from upstream Xray-core; consumed by
`tests/reality_mldsa65_vectors.rs`.

## Scope of this phase

- **Included:** seed/verify base64url decode validation against upstream `xray mldsa65` output.
- **Not included:** certificate extension signing vectors, runtime handshake wiring, or
  ML-DSA crypto implementation.

This directory does **not** affect the live REALITY accepted path.

## Files

| File | Description |
|------|-------------|
| `README.md` | This document |
| `generate-xray-mldsa65-vector.sh` | Helper to run `xray mldsa65` and refresh fixture artifacts |
| `sample-xray-mldsa65-output.txt` | Raw stdout from `xray mldsa65` (optional, created by script) |
| `sample-mldsa65-vector.json` | Parsed seed/verify vector for Rust integration tests |

## Generate vectors with upstream Xray

From the repository root:

```bash
tests/fixtures/reality/mldsa65/generate-xray-mldsa65-vector.sh
```

Or with an explicit binary path:

```bash
XRAY_BIN=/path/to/xray tests/fixtures/reality/mldsa65/generate-xray-mldsa65-vector.sh
tests/fixtures/reality/mldsa65/generate-xray-mldsa65-vector.sh /path/to/xray
```

The script:

1. Runs `xray mldsa65`
2. Saves raw output to `sample-xray-mldsa65-output.txt`
3. Attempts to extract `Seed:` and `Verify:` lines into `sample-mldsa65-vector.json`
4. If auto-parse fails, prints manual fill instructions (does not fail silently)

## JSON fixture format

`sample-mldsa65-vector.json`:

- `seed_b64url` — server REALITY config field `mldsa65Seed` (32 bytes after decode)
- `verify_b64url` — client REALITY config field `mldsa65Verify` (1952 bytes after decode)
- `fixture_status` — `"ready"` when populated from real `xray mldsa65` output; `"placeholder"`
  when values must be filled manually (integration test skips with a message)

## Run tests

```bash
cargo test --test reality_mldsa65_vectors -- --nocapture
```

When `fixture_status` is `"placeholder"`, vector decode tests skip but remain green.
