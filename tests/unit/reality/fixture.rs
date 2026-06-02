
use super::*;
use std::fs;

fn sample_metadata() -> RealityFixtureExpectedMetadata {
    RealityFixtureExpectedMetadata {
        sni: "www.example.com".to_string(),
        client_version: "1.8.0.0".to_string(),
        unix_time: 1_700_000_000,
        short_id_hex: "0123456789abcdef".to_string(),
    }
}

#[test]
fn format_reality_client_version_formats_four_components() {
    assert_eq!(format_reality_client_version([1, 8, 0, 0]), "1.8.0.0");
}

#[test]
fn format_reality_short_id_hex_formats_lowercase_prefix() {
    let short_id = [0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef];
    assert_eq!(format_reality_short_id_hex(&short_id), "0123456789abcdef");
}

#[test]
fn format_reality_short_id_hex_strips_trailing_zero_bytes() {
    let short_id = [0x01, 0x02, 0, 0, 0, 0, 0, 0];
    assert_eq!(format_reality_short_id_hex(&short_id), "0102");
}

#[test]
fn format_reality_short_id_hex_empty_prefix_is_empty_string() {
    assert_eq!(format_reality_short_id_hex(&[0u8; 8]), "");
}

#[test]
fn reality_fixture_expected_metadata_requires_sni() {
    let result = RealityFixtureSessionResult::Opened {
        sni: None,
        client_version: "1.8.0.0".to_string(),
        unix_time: 1,
        short_id_hex: "01".to_string(),
    };

    let err = reality_fixture_expected_metadata(&result).unwrap_err();
    assert_eq!(err.kind(), ErrorKind::InvalidData);
    assert!(err.to_string().contains("missing SNI"));
}

#[test]
fn write_reality_fixture_expected_files_refuses_overwrite_without_force() {
    let dir = tempfile::tempdir().expect("tempdir");
    fs::write(dir.path().join(EXPECTED_SNI_FILE), "old\n").expect("seed file");

    let err =
        write_reality_fixture_expected_files(dir.path(), &sample_metadata(), false).unwrap_err();

    assert_eq!(err.kind(), ErrorKind::InvalidInput);
    assert!(err.to_string().contains("--force"));
    assert_eq!(
        fs::read_to_string(dir.path().join(EXPECTED_SNI_FILE)).expect("read"),
        "old\n"
    );
}

#[test]
fn write_reality_fixture_expected_files_overwrites_with_force() {
    let dir = tempfile::tempdir().expect("tempdir");
    fs::write(dir.path().join(EXPECTED_SNI_FILE), "old\n").expect("seed file");

    write_reality_fixture_expected_files(dir.path(), &sample_metadata(), true)
        .expect("write expected files");

    assert_eq!(
        fs::read_to_string(dir.path().join(EXPECTED_SNI_FILE)).expect("read sni"),
        "www.example.com\n"
    );
    assert_eq!(
        fs::read_to_string(dir.path().join(EXPECTED_SHORT_ID_FILE)).expect("read short id"),
        "0123456789abcdef\n"
    );
    assert_eq!(
        fs::read_to_string(dir.path().join(EXPECTED_CLIENT_VERSION_FILE)).expect("read version"),
        "1.8.0.0\n"
    );
    assert_eq!(
        fs::read_to_string(dir.path().join(EXPECTED_UNIX_TIME_FILE)).expect("read unix time"),
        "1700000000\n"
    );
}
