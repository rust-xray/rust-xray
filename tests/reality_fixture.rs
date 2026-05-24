//! Integration tests for real Xray REALITY client captures.
//!
//! Fixture layout: see `tests/fixtures/reality/README.md`.

use std::fs;
use std::path::{Path, PathBuf};

use rust_xray::codec::{Codec, Reader};
use rust_xray::protocol::structs::ClientHelloPayload;
use rust_xray::reality::{
    inspect_reality_client_hello, parse_reality_client_version, parse_short_id_hex,
    RealityDecision, RealityInspectConfig,
};
use rust_xray::tls::parse_client_hello_record_bytes;

const FIXTURE_ROOT: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/fixtures/reality");

const REQUIRED_FILES: &[&str] = &[
    "client_hello.bin",
    "server_private_key.txt",
    "expected_sni.txt",
    "expected_short_id.hex",
    "expected_client_version.txt",
    "expected_unix_time.txt",
];

fn fixture_root() -> PathBuf {
    PathBuf::from(FIXTURE_ROOT)
}

fn read_trimmed(path: &Path) -> std::io::Result<String> {
    let contents = fs::read_to_string(path)?;
    Ok(contents.trim().to_string())
}

fn discover_fixture_cases() -> Vec<PathBuf> {
    let root = fixture_root();
    let entries = match fs::read_dir(&root) {
        Ok(entries) => entries,
        Err(_) => return Vec::new(),
    };

    let mut cases = Vec::new();
    for entry in entries.flatten() {
        let path = entry.path();
        if !path.is_dir() {
            continue;
        }

        if REQUIRED_FILES.iter().all(|name| path.join(name).is_file()) {
            cases.push(path);
        }
    }

    cases.sort();
    cases
}

fn load_fixture_case(case_dir: &Path) -> std::io::Result<FixtureCase> {
    let client_hello = fs::read(case_dir.join("client_hello.bin"))?;
    let private_key = read_trimmed(&case_dir.join("server_private_key.txt"))?;
    let expected_sni = read_trimmed(&case_dir.join("expected_sni.txt"))?;
    let expected_short_id_hex = read_trimmed(&case_dir.join("expected_short_id.hex"))?;
    let expected_client_version = read_trimmed(&case_dir.join("expected_client_version.txt"))?;
    let expected_unix_time = read_trimmed(&case_dir.join("expected_unix_time.txt"))?
        .parse::<u32>()
        .map_err(|e| {
            std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                format!(
                    "expected_unix_time.txt in {} must be a decimal u32: {e}",
                    case_dir.display()
                ),
            )
        })?;

    Ok(FixtureCase {
        name: case_dir
            .file_name()
            .and_then(|s| s.to_str())
            .unwrap_or("unknown")
            .to_string(),
        client_hello,
        private_key,
        expected_sni,
        expected_short_id_hex,
        expected_client_version,
        expected_unix_time,
    })
}

struct FixtureCase {
    name: String,
    client_hello: Vec<u8>,
    private_key: String,
    expected_sni: String,
    expected_short_id_hex: String,
    expected_client_version: String,
    expected_unix_time: u32,
}

fn run_fixture_case(case: &FixtureCase) -> std::io::Result<()> {
    let record = parse_client_hello_record_bytes(&case.client_hello)?;

    let mut rd = Reader::init(&record.handshake_payload);
    let hello = ClientHelloPayload::read(&mut rd).map_err(|e| {
        std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            format!("ClientHello parse failed for fixture {}: {e:?}", case.name),
        )
    })?;

    let short_id = parse_short_id_hex(&case.expected_short_id_hex)?;
    let expected_version = parse_reality_client_version(&case.expected_client_version)?;
    let server_names = vec![case.expected_sni.clone()];
    let short_ids = vec![short_id];

    let inspect_cfg = RealityInspectConfig {
        private_key: &case.private_key,
        server_names: &server_names,
        short_ids: &short_ids,
        max_time_diff_ms: 0,
        min_client_ver: None,
        max_client_ver: None,
        now_unix_ms: None,
    };

    let result = inspect_reality_client_hello(&hello, &record.handshake_message, inspect_cfg)?;

    match result {
        RealityDecision::Accepted(accepted) => {
            assert_eq!(
                accepted.sni.as_deref(),
                Some(case.expected_sni.as_str()),
                "fixture {}",
                case.name
            );
            assert_eq!(
                accepted.client.client_version, expected_version,
                "fixture {}",
                case.name
            );
            assert_eq!(
                accepted.client.unix_time, case.expected_unix_time,
                "fixture {}",
                case.name
            );
            Ok(())
        }
        RealityDecision::Fallback => Err(std::io::Error::new(
            std::io::ErrorKind::Other,
            format!(
                "fixture {}: inspect_reality_client_hello returned Fallback",
                case.name
            ),
        )),
    }
}

#[test]
fn reality_fixture_readme_and_directory_exist() {
    let root = fixture_root();
    assert!(root.is_dir(), "missing fixture root: {}", root.display());
    assert!(
        root.join("README.md").is_file(),
        "missing fixture README: {}",
        root.join("README.md").display()
    );
}

#[test]
fn discover_fixture_cases_returns_empty_when_no_cases_present() {
    let cases = discover_fixture_cases();
    assert!(
        cases.is_empty(),
        "expected no complete fixture cases in a fresh checkout, found: {:?}",
        cases
    );
}

#[test]
#[ignore = "requires real Xray REALITY client fixtures; see tests/fixtures/reality/README.md"]
fn inspect_reality_client_hello_from_xray_fixture() {
    let cases = discover_fixture_cases();
    if cases.is_empty() {
        eprintln!(
            "no complete fixture cases under {}; add a subdirectory with required files (see README.md)",
            fixture_root().display()
        );
        return;
    }

    for case_dir in cases {
        let case = load_fixture_case(&case_dir)
            .unwrap_or_else(|e| panic!("failed to load fixture {}: {e}", case_dir.display()));
        run_fixture_case(&case)
            .unwrap_or_else(|e| panic!("fixture case {} failed: {e}", case.name));
    }
}
