
use super::*;

#[test]
fn redact_argv_hides_token_in_http_unix_uri() {
    let args = vec![
        "rw-core".to_string(),
        "-config".to_string(),
        "http+unix:///run/a.sock/internal/get-config?token=secret".to_string(),
        "-format".to_string(),
        "json".to_string(),
    ];
    let redacted = redact_argv(&args);
    assert!(!redacted.contains("secret"));
    assert!(redacted.contains("?<redacted>"));
}
