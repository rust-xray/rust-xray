//! Integration tests for upstream Xray ML-DSA-65 seed/verify fixture vectors.
//!
//! Fixture layout: see `tests/fixtures/reality/mldsa65/README.md`.

use std::fs;
use std::path::{Path, PathBuf};

use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use rust_xray::reality::{
    decode_mldsa65_seed, decode_mldsa65_verify_key, sign_reality_cert_extension_stub,
    Mldsa65Seed, MLDSA65_SEED_LEN, MLDSA65_VERIFY_KEY_LEN,
};
use serde::Deserialize;

const FIXTURE_ROOT: &str = concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/tests/fixtures/reality/mldsa65"
);
const VECTOR_JSON: &str = "sample-mldsa65-vector.json";
const TEST_REALITY_PRIVATE_KEY: &str = "CMZoLYnNxeaUoLn7LwK4RzBIdpzBXI5TOIlZ3tEfOn4";

#[derive(Debug, Deserialize)]
struct ExpectedLengths {
    seed_len: usize,
    verify_len: usize,
}

#[derive(Debug, Deserialize)]
struct Mldsa65VectorFixture {
    source: String,
    generated_with: String,
    #[serde(default = "default_fixture_status")]
    fixture_status: String,
    seed_b64url: String,
    verify_b64url: String,
    expected: ExpectedLengths,
}

fn default_fixture_status() -> String {
    "placeholder".to_string()
}

fn fixture_root() -> PathBuf {
    PathBuf::from(FIXTURE_ROOT)
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

fn b64url_no_pad(bytes: &[u8]) -> String {
    URL_SAFE_NO_PAD.encode(bytes)
}

#[test]
fn mldsa65_fixture_directory_and_readme_exist() {
    let root = fixture_root();
    assert!(root.is_dir(), "missing fixture root: {}", root.display());
    assert!(
        root.join("README.md").is_file(),
        "missing fixture README: {}",
        root.join("README.md").display()
    );
    assert!(
        root.join(VECTOR_JSON).is_file(),
        "missing vector JSON: {}",
        root.join(VECTOR_JSON).display()
    );
}

#[test]
fn sample_mldsa65_vector_decodes_when_ready() -> Result<(), Box<dyn std::error::Error>> {
    let vector_path = fixture_root().join(VECTOR_JSON);
    let fixture = load_vector_fixture(&vector_path)?;

    if is_placeholder_fixture(&fixture) {
        eprintln!(
            "skip: {} has placeholder mldsa65 vectors; run tests/fixtures/reality/mldsa65/generate-xray-mldsa65-vector.sh",
            vector_path.display()
        );
        return Ok(());
    }

    assert_eq!(fixture.source, "xray mldsa65");
    assert_eq!(fixture.expected.seed_len, MLDSA65_SEED_LEN);
    assert_eq!(fixture.expected.verify_len, MLDSA65_VERIFY_KEY_LEN);
    assert!(
        !fixture.generated_with.is_empty(),
        "generated_with must identify upstream Xray version"
    );

    let seed = decode_mldsa65_seed(Some(&fixture.seed_b64url), TEST_REALITY_PRIVATE_KEY)?
        .ok_or("expected non-empty mldsa65 seed in ready fixture")?;
    let verify = decode_mldsa65_verify_key(&fixture.verify_b64url)?;

    assert_eq!(seed.as_bytes().len(), MLDSA65_SEED_LEN);
    assert_eq!(verify.as_bytes().len(), MLDSA65_VERIFY_KEY_LEN);

    let seed_debug = format!("{seed:?}");
    assert!(seed_debug.contains("redacted"));
    assert!(!seed_debug.contains(&fixture.seed_b64url));

    let verify_debug = format!("{verify:?}");
    assert!(verify_debug.contains("redacted"));
    assert!(!verify_debug.contains(&fixture.verify_b64url));

    Ok(())
}

#[test]
fn decode_mldsa65_verify_key_validation_matrix() {
    let err = decode_mldsa65_verify_key("not-valid-base64!!!").unwrap_err();
    assert_eq!(err.kind(), std::io::ErrorKind::InvalidInput);
    assert!(err.to_string().contains("invalid mldsa65Verify base64"));

    let verify_1951 = b64url_no_pad(&vec![0x01; MLDSA65_VERIFY_KEY_LEN - 1]);
    let err = decode_mldsa65_verify_key(&verify_1951).unwrap_err();
    assert_eq!(err.kind(), std::io::ErrorKind::InvalidInput);
    assert!(err.to_string().contains("expected 1952 bytes, got 1951"));

    let verify_1953 = b64url_no_pad(&vec![0x01; MLDSA65_VERIFY_KEY_LEN + 1]);
    let err = decode_mldsa65_verify_key(&verify_1953).unwrap_err();
    assert_eq!(err.kind(), std::io::ErrorKind::InvalidInput);
    assert!(err.to_string().contains("expected 1952 bytes, got 1953"));

    let verify_1952 = b64url_no_pad(&vec![0x01; MLDSA65_VERIFY_KEY_LEN]);
    let verify = decode_mldsa65_verify_key(&verify_1952).expect("1952-byte verify key");
    assert_eq!(verify.as_bytes().len(), MLDSA65_VERIFY_KEY_LEN);
}

#[test]
fn sign_reality_cert_extension_stub_is_unsupported_and_non_mutating() {
    let cert_before = vec![0x55; 256];
    let cert_after = cert_before.clone();
    let public_key = [0x11; 32];
    let auth_key = [0x22; 32];
    let client_hello = [0x01, 0x02, 0x03];
    let server_hello = [0x04, 0x05, 0x06];
    let mldsa65_seed = Mldsa65Seed::from_bytes([0x33; 32]);

    let err = sign_reality_cert_extension_stub(
        &cert_after,
        &mldsa65_seed,
        &public_key,
        &auth_key,
        &client_hello,
        &server_hello,
    )
    .unwrap_err();

    assert_eq!(err.kind(), std::io::ErrorKind::Unsupported);
    assert_eq!(cert_after, cert_before);
}
