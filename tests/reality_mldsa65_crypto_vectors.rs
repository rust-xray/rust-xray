#![cfg(feature = "reality-mldsa65-crypto")]

use std::fs;
use std::path::Path;

use rust_xray::reality::mldsa65_crypto::derive_mldsa65_key_from_seed_for_test;
use rust_xray::reality::{decode_mldsa65_seed, decode_mldsa65_verify_key};
use serde::Deserialize;

const VECTOR_PATH: &str = concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/tests/fixtures/reality/mldsa65/sample-mldsa65-vector.json"
);
const TEST_REALITY_PRIVATE_KEY: &str = "some-different-private-key";

#[derive(Debug, Deserialize)]
struct Mldsa65VectorFixture {
    #[serde(default = "default_fixture_status")]
    fixture_status: String,
    seed_b64url: String,
    verify_b64url: String,
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

#[test]
fn rustcrypto_mldsa65_seed_derivation_matches_upstream_verify_key(
) -> Result<(), Box<dyn std::error::Error>> {
    let fixture = load_vector_fixture(Path::new(VECTOR_PATH))?;

    if is_placeholder_fixture(&fixture) {
        eprintln!("skipping real upstream mldsa65 crypto vector: placeholder fixture");
        return Ok(());
    }

    let seed = decode_mldsa65_seed(Some(&fixture.seed_b64url), TEST_REALITY_PRIVATE_KEY)?
        .ok_or("expected non-empty mldsa65 seed in real fixture")?;
    let verify = decode_mldsa65_verify_key(&fixture.verify_b64url)?;
    let derived = derive_mldsa65_key_from_seed_for_test(&seed)?;

    assert_eq!(
        derived.verify_key_bytes,
        verify.as_bytes(),
        "Rust ML-DSA-65 verify key encoding does not match upstream Xray-core/CIRCL mldsa65Verify"
    );

    Ok(())
}
