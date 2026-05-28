use std::fs;
use std::path::Path;

use rust_xray::reality::mldsa65_crypto::{
    mldsa65_signature_from_bytes_for_test, sign_reality_mldsa65_message_for_test,
    verify_reality_mldsa65_signature_for_test,
};
use rust_xray::reality::{
    build_reality_mldsa65_message, decode_mldsa65_seed, decode_mldsa65_verify_key,
};
use serde::Deserialize;

const VECTOR_PATH: &str = concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/tests/fixtures/reality/mldsa65/sample-mldsa65-vector.json"
);
const TEST_REALITY_PRIVATE_KEY: &str = "some-different-private-key";

#[derive(Debug, Deserialize)]
struct SigningVector {
    auth_key_hex: String,
    ed25519_public_key_hex: String,
    client_hello_original_hex: String,
    server_hello_original_hex: String,
    message_kind: String,
}

#[derive(Debug, Deserialize)]
struct Mldsa65VectorFixture {
    #[serde(default = "default_fixture_status")]
    fixture_status: String,
    seed_b64url: String,
    verify_b64url: String,
    signing_vector: SigningVector,
}

fn default_fixture_status() -> String {
    "placeholder".to_string()
}

fn load_vector_fixture(path: &Path) -> std::io::Result<Mldsa65VectorFixture> {
    let contents = fs::read_to_string(path)?;
    serde_json::from_str(&contents).map_err(|err| {
        std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            format!("invalid {}: {err}", path.display()),
        )
    })
}

fn is_placeholder_fixture(fixture: &Mldsa65VectorFixture) -> bool {
    fixture.fixture_status.eq_ignore_ascii_case("placeholder")
        || fixture.seed_b64url.contains("PLACEHOLDER")
        || fixture.verify_b64url.contains("PLACEHOLDER")
}

fn decode_hex(value: &str) -> std::io::Result<Vec<u8>> {
    if value.len() % 2 != 0 {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "hex string must have even length",
        ));
    }

    value
        .as_bytes()
        .chunks_exact(2)
        .map(|pair| {
            let s = std::str::from_utf8(pair).map_err(|err| {
                std::io::Error::new(
                    std::io::ErrorKind::InvalidInput,
                    format!("invalid hex utf8: {err}"),
                )
            })?;
            u8::from_str_radix(s, 16).map_err(|err| {
                std::io::Error::new(
                    std::io::ErrorKind::InvalidInput,
                    format!("invalid hex byte {s}: {err}"),
                )
            })
        })
        .collect()
}

fn decode_hex_array<const N: usize>(value: &str, name: &str) -> std::io::Result<[u8; N]> {
    let bytes = decode_hex(value)?;
    bytes.try_into().map_err(|bytes: Vec<u8>| {
        std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            format!(
                "invalid {name} length: expected {N} bytes, got {}",
                bytes.len()
            ),
        )
    })
}

fn hex_prefix(bytes: &[u8]) -> String {
    bytes
        .iter()
        .take(8)
        .map(|byte| format!("{byte:02x}"))
        .collect::<String>()
}

#[test]
fn rustcrypto_mldsa65_sign_verify_reality_message_vector() -> Result<(), Box<dyn std::error::Error>>
{
    let fixture = load_vector_fixture(Path::new(VECTOR_PATH))?;

    if is_placeholder_fixture(&fixture) {
        eprintln!("skipping real upstream mldsa65 sign/verify vector: placeholder fixture");
        return Ok(());
    }

    assert_eq!(
        fixture.signing_vector.message_kind,
        "reality_mldsa65_hmac_sum"
    );

    let seed = decode_mldsa65_seed(Some(&fixture.seed_b64url), TEST_REALITY_PRIVATE_KEY)?
        .ok_or("expected non-empty mldsa65 seed in real fixture")?;
    let verify_key = decode_mldsa65_verify_key(&fixture.verify_b64url)?;
    let auth_key = decode_hex_array::<32>(&fixture.signing_vector.auth_key_hex, "auth_key_hex")?;
    let ed25519_public_key = decode_hex_array::<32>(
        &fixture.signing_vector.ed25519_public_key_hex,
        "ed25519_public_key_hex",
    )?;
    let client_hello_original = decode_hex(&fixture.signing_vector.client_hello_original_hex)?;
    let server_hello_original = decode_hex(&fixture.signing_vector.server_hello_original_hex)?;
    let message = build_reality_mldsa65_message(
        &auth_key,
        &ed25519_public_key,
        &client_hello_original,
        &server_hello_original,
    );

    let signature = sign_reality_mldsa65_message_for_test(&seed, &message)?;
    verify_reality_mldsa65_signature_for_test(&verify_key, &message, &signature)?;

    let mut modified_message = message;
    modified_message[0] ^= 0x80;
    assert!(
        verify_reality_mldsa65_signature_for_test(&verify_key, &modified_message, &signature)
            .is_err(),
        "modified REALITY ML-DSA-65 message must not verify"
    );

    let mut modified_signature = signature.as_bytes().to_vec();
    modified_signature[0] ^= 0x80;
    let modified_signature = mldsa65_signature_from_bytes_for_test(modified_signature)?;
    assert!(
        verify_reality_mldsa65_signature_for_test(&verify_key, &message, &modified_signature)
            .is_err(),
        "modified REALITY ML-DSA-65 signature must not verify"
    );

    let debug = format!("{signature:?}");
    assert!(debug.contains("redacted"));
    assert!(!debug.contains(&hex_prefix(signature.as_bytes())));

    Ok(())
}
