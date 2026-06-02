use super::*;

#[test]
fn parse_buffered_lines_valid() {
    assert_eq!(parse_buffered_lines(Some("131072")), 131_072);
}

#[test]
fn parse_buffered_lines_invalid_falls_back() {
    assert_eq!(parse_buffered_lines(Some("bad")), DEFAULT_BUFFERED_LINES);
}

#[test]
fn parse_buffered_lines_none_uses_default() {
    assert_eq!(parse_buffered_lines(None), DEFAULT_BUFFERED_LINES);
}

#[test]
fn parse_backpressure_true_values() {
    for v in ["1", "true", "yes", "on", "TRUE", "On"] {
        assert!(parse_backpressure(Some(v)), "expected true for {v:?}");
    }
}

#[test]
fn default_env_filter_is_error() {
    use crate::cli::{Command, RunOptions};

    assert_eq!(default_env_filter(&Command::Version), "error");
    assert_eq!(
        default_env_filter(&Command::Run(RunOptions {
            config: "config.json".into(),
            format: None,
        })),
        "error"
    );
}

#[test]
fn parse_backpressure_false_values() {
    for v in [
        None,
        Some(""),
        Some("0"),
        Some("false"),
        Some("no"),
        Some("off"),
    ] {
        assert!(!parse_backpressure(v), "expected false for {v:?}");
    }
}
