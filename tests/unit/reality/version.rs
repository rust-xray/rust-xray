
use super::*;

#[test]
fn parse_reality_client_version_parses_single_component() {
    assert_eq!(parse_reality_client_version("1").unwrap(), [1, 0, 0, 0]);
}

#[test]
fn parse_reality_client_version_parses_three_components() {
    assert_eq!(parse_reality_client_version("1.8.0").unwrap(), [1, 8, 0, 0]);
}

#[test]
fn parse_reality_client_version_parses_four_components() {
    assert_eq!(
        parse_reality_client_version("1.8.1.2").unwrap(),
        [1, 8, 1, 2]
    );
}

#[test]
fn parse_reality_client_version_parses_date_style_version() {
    assert_eq!(
        parse_reality_client_version("24.9.30").unwrap(),
        [24, 9, 30, 0]
    );
}

#[test]
fn parse_reality_client_version_trims_whitespace() {
    assert_eq!(
        parse_reality_client_version("  1.8.0  ").unwrap(),
        [1, 8, 0, 0]
    );
}

#[test]
fn parse_reality_client_version_rejects_empty_string() {
    let err = parse_reality_client_version("").unwrap_err();
    assert_eq!(err.kind(), std::io::ErrorKind::InvalidInput);
}

#[test]
fn parse_reality_client_version_rejects_whitespace_only() {
    let err = parse_reality_client_version("   ").unwrap_err();
    assert_eq!(err.kind(), std::io::ErrorKind::InvalidInput);
}

#[test]
fn parse_reality_client_version_rejects_too_many_components() {
    let err = parse_reality_client_version("1.2.3.4.5").unwrap_err();
    assert_eq!(err.kind(), std::io::ErrorKind::InvalidInput);
}

#[test]
fn parse_reality_client_version_rejects_component_above_255() {
    let err = parse_reality_client_version("1.300.0").unwrap_err();
    assert_eq!(err.kind(), std::io::ErrorKind::InvalidInput);
}

#[test]
fn parse_reality_client_version_rejects_empty_component() {
    let err = parse_reality_client_version("1..0").unwrap_err();
    assert_eq!(err.kind(), std::io::ErrorKind::InvalidInput);
}

#[test]
fn version_ge_passes_when_actual_is_greater() {
    assert!(version_ge([1, 8, 1, 0], [1, 8, 0, 9]));
}

#[test]
fn version_ge_passes_when_equal() {
    assert!(version_ge([1, 8, 0, 0], [1, 8, 0, 0]));
}

#[test]
fn version_ge_fails_when_actual_is_less() {
    assert!(!version_ge([1, 8, 0, 9], [1, 8, 1, 0]));
}

#[test]
fn version_le_passes_when_actual_is_less() {
    assert!(version_le([1, 8, 0, 9], [1, 8, 1, 0]));
}

#[test]
fn version_le_passes_when_equal() {
    assert!(version_le([1, 8, 0, 0], [1, 8, 0, 0]));
}

#[test]
fn version_le_fails_when_actual_is_greater() {
    assert!(!version_le([1, 8, 1, 0], [1, 8, 0, 9]));
}
