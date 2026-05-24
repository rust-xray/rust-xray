//! Integration tests for real Xray REALITY client captures.
//!
//! Fixture layout: see `tests/fixtures/reality/README.md`.

use std::fs;
use std::path::{Path, PathBuf};

use rust_xray::codec::{Codec, Reader};
use rust_xray::protocol::structs::ClientHelloPayload;
use rust_xray::reality::{
    format_reality_short_id_hex, inspect_reality_client_hello, parse_reality_client_version,
    parse_short_id_hex, RealityDecision, RealityInspectConfig,
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

fn discover_fixture_cases(root: &Path) -> std::io::Result<Vec<PathBuf>> {
    let entries = fs::read_dir(root)?;

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
    Ok(cases)
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
        case_dir: case_dir.to_path_buf(),
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
    case_dir: PathBuf,
    name: String,
    client_hello: Vec<u8>,
    private_key: String,
    expected_sni: String,
    expected_short_id_hex: String,
    expected_client_version: String,
    expected_unix_time: u32,
}

fn run_fixture_case(case: &FixtureCase) -> Result<(), String> {
    let label = format!("{} ({})", case.name, case.case_dir.display());

    let record = parse_client_hello_record_bytes(&case.client_hello).map_err(|err| {
        format!("{label}: failed to parse client_hello.bin as TLS ClientHello record: {err}")
    })?;

    let mut rd = Reader::init(&record.handshake_payload);
    let hello = ClientHelloPayload::read(&mut rd)
        .map_err(|err| format!("{label}: failed to decode ClientHello payload: {err:?}"))?;

    let configured_short_id = parse_short_id_hex(&case.expected_short_id_hex).map_err(|err| {
        format!(
            "{label}: expected_short_id.hex is invalid: {err} (value={:?})",
            case.expected_short_id_hex
        )
    })?;
    let expected_version =
        parse_reality_client_version(&case.expected_client_version).map_err(|err| {
            format!(
                "{label}: expected_client_version.txt is invalid: {err} (value={:?})",
                case.expected_client_version
            )
        })?;

    let server_names = vec![case.expected_sni.clone()];
    let short_ids = vec![configured_short_id];

    let inspect_cfg = RealityInspectConfig {
        private_key: &case.private_key,
        server_names: &server_names,
        short_ids: &short_ids,
        max_time_diff_ms: 0,
        min_client_ver: None,
        max_client_ver: None,
        now_unix_ms: None,
    };

    let result = inspect_reality_client_hello(&hello, &record.handshake_message, inspect_cfg)
        .map_err(|err| format!("{label}: REALITY inspect failed: {err}"))?;

    let accepted = match result {
        RealityDecision::Accepted(accepted) => accepted,
        RealityDecision::Fallback => {
            return Err(format!(
                "{label}: REALITY inspect returned Fallback (auth/key mismatch, shortId, SNI, or policy failure)"
            ));
        }
    };

    let sni = accepted
        .sni
        .as_deref()
        .ok_or_else(|| format!("{label}: decrypted ClientHello missing SNI"))?;
    if sni != case.expected_sni {
        return Err(format!(
            "{label}: SNI mismatch: expected {:?}, got {:?}",
            case.expected_sni, sni
        ));
    }

    let short_id_hex = format_reality_short_id_hex(&accepted.client.short_id);
    if short_id_hex != case.expected_short_id_hex {
        return Err(format!(
            "{label}: short_id mismatch: expected {:?}, got {:?}",
            case.expected_short_id_hex, short_id_hex
        ));
    }

    if accepted.client.client_version != expected_version {
        return Err(format!(
            "{label}: client_version mismatch: expected {:?}, got {:?}",
            expected_version, accepted.client.client_version
        ));
    }

    if accepted.client.unix_time != case.expected_unix_time {
        return Err(format!(
            "{label}: unix_time mismatch: expected {}, got {}",
            case.expected_unix_time, accepted.client.unix_time
        ));
    }

    Ok(())
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
    let temp = tempfile::tempdir().expect("create tempdir");
    let cases = discover_fixture_cases(temp.path()).expect("discover cases");
    assert!(cases.is_empty());
}

#[test]
fn inspect_reality_client_hello_from_xray_fixture() {
    let cases = discover_fixture_cases(&fixture_root()).expect("discover cases");
    if cases.is_empty() {
        panic!("no fixture cases found; see tests/fixtures/reality/README.md");
    }

    for case_dir in cases {
        eprintln!("running fixture case: {}", case_dir.display());

        let case = load_fixture_case(&case_dir).unwrap_or_else(|err| {
            panic!(
                "failed to load fixture {}: {err}",
                case_dir.file_name().unwrap_or_default().to_string_lossy()
            );
        });

        run_fixture_case(&case).unwrap_or_else(|err| panic!("{err}"));
    }
}
