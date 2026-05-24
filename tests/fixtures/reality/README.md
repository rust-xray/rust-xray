# REALITY client fixtures

Place captured traffic from a real **Xray REALITY client** here for integration
tests (`tests/reality_fixture.rs`).

## Committed test fixture

[`basic-xray/`](basic-xray/) is a **committed** interop fixture with disposable
test-only REALITY keys and a captured Xray REALITY `ClientHello`. It runs
automatically in `cargo test` via `inspect_reality_client_hello_from_xray_fixture`.

See [`basic-xray/README.md`](basic-xray/README.md) for key-handling notes.

For **local or private captures**, use directory names like `local-*` (for example
`local-my-capture/`). Those paths are gitignored and must not be committed.

Each fixture case lives in its own subdirectory:

```
tests/fixtures/reality/
  README.md
  xray-client-fixture.template.json
  basic-xray/              # committed test fixture
  local-*/                 # gitignored local captures
  <case-name>/
    client_hello.bin
    server_private_key.txt
    expected_sni.txt
    expected_short_id.hex
    expected_client_version.txt
    expected_unix_time.txt
```

## File format

| File | Description |
|------|-------------|
| `client_hello.bin` | Raw bytes of the **first TLS record** from the client (TLS record header + body). Must be a single complete ClientHello record as sent on the wire. |
| `server_private_key.txt` | REALITY `privateKey` in Xray config format: base64url, no padding, 32 bytes after decode. |
| `expected_sni.txt` | SNI hostname the client used (single line, trimmed). Must appear in `serverNames` when running the test. |
| `expected_short_id.hex` | Hex-encoded shortId prefix (0..16 hex chars, lowercase, no spaces). Empty file means empty configured shortId. |
| `expected_client_version.txt` | REALITY client version from decrypted `session_id`, e.g. `1.8.0.0` (four components from `decode_reality_fixture`). Shorter forms like `1.8.0` also parse in tests. |
| `expected_unix_time.txt` | Unix timestamp (seconds) from decrypted `session_id`, decimal integer, one line. |

---

## Capture a real Xray REALITY ClientHello

This workflow uses a small TCP **captor** that listens for one connection, saves
the first bytes the client sends, and closes. The captor is **not** a TLS server
and does not speak REALITY or TLS — it only records the raw ClientHello record.

After the ClientHello is saved, the Xray client connection **will fail** (TLS
handshake error, reset, or timeout). That is expected and does not invalidate
the capture.

### 1. Generate a REALITY key pair

Use Xray’s built-in tool:

```bash
xray x25519
```

Example output (yours will differ):

```
Private key: <PRIVATE_KEY>
Public key: <PUBLIC_KEY>
```

Export shell variables for the rest of this guide:

```bash
export PRIVATE_KEY='<paste private key>'
export PUBLIC_KEY='<paste public key>'
export SHORT_ID='0123456789abcdef'   # 0..16 hex chars; empty string is valid
export SNI='www.example.com'         # must match realitySettings.serverName
export DEST='www.example.com:443'    # typical REALITY dest (not used by captor)
```

**Do not commit real private keys** if this repository is public or shared.
Use throwaway keys for local captures only.

### 2. Start the ClientHello captor

From the repository root:

```bash
python3 scripts/capture_reality_clienthello.py \
  --listen 127.0.0.1:24443 \
  --out /tmp/client_hello.bin
```

Leave this running until the client connects once.

### 3. Xray client config from template

Use the checked-in template
[`xray-client-fixture.template.json`](xray-client-fixture.template.json).
It contains SOCKS inbound on `127.0.0.1:10808`, VLESS outbound to the captor on
`127.0.0.1:24443`, and REALITY settings with placeholders:

- `__USER_ID__` — any valid VLESS UUID (not validated by the captor)
- `__SNI__` — REALITY `serverName`
- `__PUBLIC_KEY__` — from `xray x25519` (client side only; **no `privateKey`** in this file)
- `__SHORT_ID__` — REALITY `shortId` hex prefix

Copy the template, then replace placeholders manually or from shell variables:

```bash
cp tests/fixtures/reality/xray-client-fixture.template.json /tmp/xray-client-fixture.json

export SNI='www.example.com'
export PUBLIC_KEY='<paste public key>'
export SHORT_ID='0123456789abcdef'
export USER_ID='00000000-0000-0000-0000-000000000001'
```

**sed** (direct `__PLACEHOLDER__` replacement):

```bash
sed \
  -e "s/__SNI__/${SNI}/g" \
  -e "s/__PUBLIC_KEY__/${PUBLIC_KEY}/g" \
  -e "s/__SHORT_ID__/${SHORT_ID}/g" \
  -e "s/__USER_ID__/${USER_ID}/g" \
  tests/fixtures/reality/xray-client-fixture.template.json \
  > /tmp/xray-client-fixture.json
```

**envsubst** (convert `__VAR__` → `${VAR}`, then expand exported variables):

```bash
sed 's/__\([A-Z_]*\)__/${\1}/g' \
  tests/fixtures/reality/xray-client-fixture.template.json \
  | envsubst \
  > /tmp/xray-client-fixture.json
```

Or edit `/tmp/xray-client-fixture.json` by hand. Do not put `PRIVATE_KEY` in the
client config — it belongs only in `server_private_key.txt` for decode/tests.

Start the client:

```bash
xray run -c /tmp/xray-client-fixture.json
```

### 4. Trigger a connection through the client

In another terminal:

```bash
curl -x socks5h://127.0.0.1:10808 https://example.com/ -m 5 -v
```

The captor should write `/tmp/client_hello.bin` and exit. The curl request will
fail because nothing completes the TLS handshake — that is normal.

### 5. Create the fixture directory

```bash
mkdir -p tests/fixtures/reality/basic-xray
```

### 6. Copy capture artifacts

```bash
cp /tmp/client_hello.bin tests/fixtures/reality/basic-xray/
printf '%s\n' "$PRIVATE_KEY" > tests/fixtures/reality/basic-xray/server_private_key.txt
```

Do not copy `PUBLIC_KEY` into the fixture; tests only need the server private key
that matches the client’s configured `publicKey`.

### 7. Decode and write expected metadata

From the repository root:

```bash
cargo run --bin decode_reality_fixture -- \
  tests/fixtures/reality/basic-xray \
  --write-expected
```

This runs REALITY AEAD open on `client_hello.bin` and writes:

- `expected_sni.txt`
- `expected_short_id.hex`
- `expected_client_version.txt`
- `expected_unix_time.txt`

To overwrite existing expected files:

```bash
cargo run --bin decode_reality_fixture -- \
  tests/fixtures/reality/basic-xray \
  --write-expected \
  --force
```

Without `--write-expected`, the binary only prints decoded fields to stdout.

### 8. Run the fixture test

When a case directory contains all six required files, it is picked up automatically:

```bash
cargo test --test reality_fixture -- --nocapture
```

The committed `basic-xray/` case runs in normal `cargo test` as well.

The test sets `max_time_diff_ms: 0` and does not pass `now_unix_ms`, so fixture
**time drift does not matter** as long as `expected_unix_time.txt` matches the
decrypted value from the capture.

---

## Running fixture tests (summary)

All complete fixture cases under this directory run in `cargo test`:

```bash
cargo test --test reality_fixture
```

Or use Makefile targets from the repository root:

```bash
make capture-clienthello   # start TCP captor → /tmp/client_hello.bin
make fixture-decode        # decode tests/fixtures/reality/basic-xray
make fixture-decode-write  # decode + write expected_* (--force)
make fixture-test          # run integration test (--nocapture)
```

Add another committed case by creating a new subdirectory (not `local-*`) with all
required files. Keep private captures under `local-*` only.

---

## Troubleshooting

| Symptom | Likely cause |
|---------|----------------|
| `AuthFailed` from `decode_reality_fixture` or test `Fallback` | Wrong `server_private_key.txt` / client `publicKey` pair, or `client_hello.bin` captured from a different key or a non-REALITY ClientHello. |
| SNI mismatch in test assertions | Client `realitySettings.serverName` differs from `expected_sni.txt`. Regenerate with `--write-expected` after fixing the client config. |
| shortId mismatch | Client `shortId` differs from `expected_short_id.hex`. |
| `InvalidData`: first byte != `0x16` | File is not a TLS record (ContentType Handshake). You may have captured HTTP, garbage, or a partial read. Re-run the captor and ensure the client targets the captor port. |
| `missing SNI` when writing expected files | REALITY requires SNI; client did not send Server Name extension. Fix client / SNI config. |
| `fixture expected file already exists` | Run with `--write-expected --force`, or remove stale expected files. |
| Time-related failures (if you change test config) | Default fixture test disables time skew checks via `max_time_diff_ms: 0`. If you enable `maxTimeDiff` / `now_unix_ms` in tests, refresh `expected_unix_time.txt` or relax the window. |

Other constraints:

- Fragmented ClientHello across multiple TLS records is not supported; capture must be **one complete record**.
- The captor saves the **first** TCP payload only; ensure no extra bytes (e.g. PROXY protocol) precede the TLS record unless your stack sends them too.

---

## Notes

- The captor is **not** a TLS server; it never completes a handshake.
- Connection failure after a successful capture is **expected**.
- **`basic-xray/`** commits disposable test keys on purpose for CI/interop tests.
- **Local/private captures** belong in `local-*` directories (gitignored). Do not
  commit production or personal REALITY private keys.
- The test calls `inspect_reality_client_hello` and expects `RealityDecision::Accepted`.
