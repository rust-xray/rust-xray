# REALITY client fixtures

Place captured traffic from a real **Xray REALITY client** here for integration
tests (`tests/reality_fixture.rs`).

Each fixture case lives in its own subdirectory:

```
tests/fixtures/reality/
  README.md
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
| `expected_short_id.hex` | Hex-encoded shortId prefix (0..16 hex chars). Empty file means empty configured shortId. |
| `expected_client_version.txt` | REALITY client version string from decrypted session_id, e.g. `1.8.0` or `24.9.30`. |
| `expected_unix_time.txt` | Unix timestamp (seconds) from decrypted session_id, decimal integer, one line. |

## Running fixture tests

Fixtures are optional. By default the integration test is ignored:

```bash
cargo test --test reality_fixture -- --ignored
```

Add a case directory with all required files, then run the command above.

## Notes

- Do not commit secrets you do not intend to share; use throwaway keys for local captures.
- Fragmented ClientHello across multiple TLS records is not supported yet; capture must be one record.
- The test calls `inspect_reality_client_hello` and expects `RealityDecision::Accepted`.
