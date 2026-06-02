
use super::*;
use serde_json::json;

fn fallback(
    name: Option<&str>,
    alpn: Option<&str>,
    path: Option<&str>,
    dest: &str,
    xver: u8,
) -> FallbackConfig {
    FallbackConfig {
        name: name.map(str::to_string),
        alpn: alpn.map(str::to_string),
        path: path.map(str::to_string),
        dest: FallbackDest {
            addr: dest.to_string(),
        },
        xver,
    }
}

#[test]
fn parse_fallback_dest_number_uses_localhost() {
    let dest = parse_fallback_dest(&json!(8080)).expect("parse numeric dest");
    assert_eq!(dest.addr, "127.0.0.1:8080");
}

#[test]
fn parse_fallback_dest_host_port() {
    let dest = parse_fallback_dest(&json!("backend.example.com:9443")).expect("parse host");
    assert_eq!(dest.addr, "backend.example.com:9443");
}

#[test]
fn parse_fallback_dest_rejects_unix_socket() {
    let err = parse_fallback_dest(&json!("/run/fallback.sock")).unwrap_err();
    assert_eq!(err.kind(), std::io::ErrorKind::Unsupported);
}

#[test]
fn select_default_fallback() {
    let fallbacks = vec![
        fallback(None, None, None, "127.0.0.1:8080", 0),
        fallback(Some("other.test"), None, None, "127.0.0.1:8081", 0),
    ];
    let ctx = FallbackContext::default();
    let selected = select_vless_fallback(&fallbacks, &ctx).expect("selected");
    assert_eq!(selected.dest.addr, "127.0.0.1:8080");
}

#[test]
fn select_by_name() {
    let fallbacks = vec![
        fallback(None, None, None, "127.0.0.1:8080", 0),
        fallback(Some("named.test"), None, None, "127.0.0.1:8081", 0),
    ];
    let ctx = FallbackContext {
        sni: Some("named.test".to_string()),
        ..FallbackContext::default()
    };
    let selected = select_vless_fallback(&fallbacks, &ctx).expect("selected");
    assert_eq!(selected.dest.addr, "127.0.0.1:8081");
}

#[test]
fn select_by_alpn() {
    let fallbacks = vec![
        fallback(None, None, None, "127.0.0.1:8080", 0),
        fallback(None, Some("h2"), None, "127.0.0.1:8082", 0),
    ];
    let ctx = FallbackContext {
        alpn: Some("h2".to_string()),
        ..FallbackContext::default()
    };
    let selected = select_vless_fallback(&fallbacks, &ctx).expect("selected");
    assert_eq!(selected.dest.addr, "127.0.0.1:8082");
}

#[test]
fn select_by_alpn_http11() {
    let fallbacks = vec![
        fallback(None, None, None, "127.0.0.1:8080", 0),
        fallback(None, Some("http/1.1"), None, "127.0.0.1:8085", 0),
    ];
    let ctx = FallbackContext {
        alpn: Some("http/1.1".to_string()),
        ..FallbackContext::default()
    };
    let selected = select_vless_fallback(&fallbacks, &ctx).expect("selected");
    assert_eq!(selected.dest.addr, "127.0.0.1:8085");
}

#[test]
fn select_duplicate_alpn_last_one_wins() {
    let fallbacks = vec![
        fallback(None, Some("h2"), None, "127.0.0.1:8082", 0),
        fallback(None, Some("h2"), None, "127.0.0.1:8092", 0),
    ];
    let ctx = FallbackContext {
        alpn: Some("h2".to_string()),
        ..FallbackContext::default()
    };
    let selected = select_vless_fallback(&fallbacks, &ctx).expect("selected");
    assert_eq!(selected.dest.addr, "127.0.0.1:8092");
}

#[test]
fn select_duplicate_path_last_one_wins() {
    let fallbacks = vec![
        fallback(None, None, Some("/smoke-path"), "127.0.0.1:8083", 0),
        fallback(None, None, Some("/smoke-path"), "127.0.0.1:8093", 0),
    ];
    let request = b"GET /smoke-path/extra HTTP/1.1\r\nHost: x\r\n\r\n";
    let ctx = build_fallback_context(None, request);
    let selected = select_vless_fallback(&fallbacks, &ctx).expect("selected");
    assert_eq!(selected.dest.addr, "127.0.0.1:8093");
}

#[test]
fn select_by_path_with_inheritance_when_path_missing() {
    let fallbacks = vec![
        fallback(None, None, None, "127.0.0.1:8080", 0),
        fallback(None, None, Some("/secret"), "127.0.0.1:8083", 0),
        fallback(Some("named.test"), None, None, "127.0.0.1:8084", 0),
    ];
    let ctx = FallbackContext {
        sni: Some("named.test".to_string()),
        http_path: Some("/other".to_string()),
        ..FallbackContext::default()
    };
    let selected = select_vless_fallback(&fallbacks, &ctx).expect("selected");
    assert_eq!(selected.dest.addr, "127.0.0.1:8084");
}

#[test]
fn select_by_path_when_http_request_matches() {
    let fallbacks = vec![
        fallback(None, None, None, "127.0.0.1:8080", 0),
        fallback(None, None, Some("/secret"), "127.0.0.1:8083", 0),
    ];
    let request = b"GET /secret/resource HTTP/1.1\r\nHost: x\r\n\r\n";
    let ctx = build_fallback_context(None, request);
    let selected = select_vless_fallback(&fallbacks, &ctx).expect("selected");
    assert_eq!(selected.dest.addr, "127.0.0.1:8083");
}

#[test]
fn select_by_alpn_matches_any_offered_protocol() {
    let fallbacks = vec![
        fallback(None, None, None, "127.0.0.1:8080", 0),
        fallback(None, Some("h2"), None, "127.0.0.1:8082", 0),
    ];
    let ctx = FallbackContext {
        alpn: Some("http/1.1".to_string()),
        alpn_offers: vec!["http/1.1".to_string(), "h2".to_string()],
        ..FallbackContext::default()
    };
    let selected = select_vless_fallback(&fallbacks, &ctx).expect("selected");
    assert_eq!(selected.dest.addr, "127.0.0.1:8082");
}

#[test]
fn resolve_fallback_selection_uses_default_entry() {
    let fallbacks = vec![
        fallback(None, None, None, "127.0.0.1:8080", 0),
        fallback(Some("named.test"), None, None, "127.0.0.1:8081", 0),
    ];
    let selection =
        resolve_fallback_selection(&fallbacks, "example.com:443", &FallbackContext::default())
            .expect("selection");
    assert_eq!(selection.dest, "127.0.0.1:8080");
    assert_eq!(selection.kind, FallbackMatchKind::Default);
    assert!(selection.used_configured_fallback);
}

#[test]
fn resolve_fallback_selection_never_uses_reality_dest_when_fallbacks_configured() {
    let fallbacks = vec![fallback(None, None, None, "127.0.0.1:19501", 0)];
    let selection = resolve_fallback_selection(
        &fallbacks,
        "www.microsoft.com:443",
        &FallbackContext::default(),
    )
    .expect("selection");
    assert_eq!(selection.dest, "127.0.0.1:19501");
    assert_ne!(selection.dest, "www.microsoft.com:443");
    assert!(selection.used_configured_fallback);
}

#[test]
fn resolve_fallback_selection_without_fallbacks_uses_reality_dest() {
    let selection =
        resolve_fallback_selection(&[], "www.microsoft.com:443", &FallbackContext::default())
            .expect("selection");
    assert_eq!(selection.dest, "www.microsoft.com:443");
    assert!(!selection.used_configured_fallback);
}

#[test]
fn matching_alpn_offer_prefers_offered_protocol() {
    let fallbacks = vec![fallback(None, Some("h2"), None, "127.0.0.1:8082", 0)];
    let ctx = FallbackContext {
        alpn: Some("http/1.1".to_string()),
        alpn_offers: vec!["http/1.1".to_string(), "h2".to_string()],
        ..FallbackContext::default()
    };
    let selected = select_vless_fallback(&fallbacks, &ctx).expect("selected");
    assert_eq!(selected.dest.addr, "127.0.0.1:8082");
    assert_eq!(matching_alpn_offer(selected, &ctx).as_deref(), Some("h2"));
}

#[test]
fn xver_1_builds_valid_proxy_v1_header() {
    let header = build_proxy_protocol_v1(
        "127.0.0.1:12345".parse().unwrap(),
        "127.0.0.1:24443".parse().unwrap(),
    )
    .expect("proxy header");
    assert_eq!(
        std::str::from_utf8(&header).unwrap(),
        "PROXY TCP4 127.0.0.1 127.0.0.1 12345 24443\r\n"
    );
}

#[test]
fn xver_2_builds_valid_proxy_v2_header() {
    assert!(validate_fallback_xver(2).is_ok());

    let header = build_proxy_protocol_v2(
        "127.0.0.1:12345".parse().unwrap(),
        "127.0.0.1:24443".parse().unwrap(),
    )
    .expect("proxy v2 header");
    assert_eq!(header.len(), 28);
    assert_eq!(&header[..12], PROXY_V2_SIGNATURE);
    assert_eq!(header[12], 0x21);
    assert_eq!(header[13], 0x11);
    assert_eq!(&header[14..16], &[0x00, 0x0C]);
    assert_eq!(
        header,
        [
            0x0D, 0x0A, 0x0D, 0x0A, 0x00, 0x0D, 0x0A, 0x51, 0x55, 0x49, 0x54, 0x0A, 0x21, 0x11,
            0x00, 0x0C, 0x7F, 0x00, 0x00, 0x01, 0x7F, 0x00, 0x00, 0x01, 0x30, 0x39, 0x5F, 0x7B,
        ]
    );
}

#[test]
fn xver_2_builds_valid_proxy_v2_header_ipv6() {
    let header = build_proxy_protocol_v2(
        "[::1]:12345".parse().unwrap(),
        "[::1]:24443".parse().unwrap(),
    )
    .expect("proxy v2 ipv6 header");
    assert_eq!(header.len(), 52);
    assert_eq!(&header[..12], PROXY_V2_SIGNATURE);
    assert_eq!(header[12], 0x21);
    assert_eq!(header[13], 0x21);
    assert_eq!(&header[14..16], &[0x00, 0x24]);
}

#[test]
fn xver_2_builds_unknown_family_for_mismatched_ip_versions() {
    let header = build_proxy_protocol_v2(
        "127.0.0.1:12345".parse().unwrap(),
        "[::1]:24443".parse().unwrap(),
    )
    .expect("proxy v2 unknown header");
    assert_eq!(header.len(), 16);
    assert_eq!(&header[..12], PROXY_V2_SIGNATURE);
    assert_eq!(&header[12..], &[0x20, 0x00, 0x00, 0x00]);
}

#[test]
fn validate_fallback_xver_rejects_values_above_two() {
    let err = validate_fallback_xver(3).unwrap_err();
    assert_eq!(err.kind(), std::io::ErrorKind::InvalidInput);
    assert!(err.to_string().contains("unsupported fallback xver: 3"));
}

#[test]
fn select_by_name_alpn_and_path_prefers_most_specific_match() {
    let fallbacks = vec![
        fallback(None, None, None, "127.0.0.1:8080", 0),
        fallback(Some("named.test"), None, None, "127.0.0.1:8081", 0),
        fallback(None, Some("h2"), None, "127.0.0.1:8082", 0),
        fallback(None, None, Some("/secret"), "127.0.0.1:8083", 0),
        fallback(
            Some("named.test"),
            Some("h2"),
            Some("/secret"),
            "127.0.0.1:8084",
            0,
        ),
    ];
    let ctx = FallbackContext {
        sni: Some("named.test".to_string()),
        alpn: Some("h2".to_string()),
        alpn_offers: vec!["h2".to_string()],
        http_path: Some("/secret/extra".to_string()),
    };
    let selected = select_vless_fallback(&fallbacks, &ctx).expect("selected");
    assert_eq!(selected.dest.addr, "127.0.0.1:8084");
}

#[test]
fn validate_fallback_configs_rejects_path_without_leading_slash() {
    let fallbacks = vec![fallback(None, None, Some("secret"), "127.0.0.1:8080", 0)];
    let err = validate_fallback_configs(&fallbacks).unwrap_err();
    assert_eq!(err.kind(), std::io::ErrorKind::InvalidInput);
    assert!(err.to_string().contains("path must start with '/'"));
}

#[test]
fn proxy_v2_builder_matches_golden_fixture_bytes() {
    const FIXTURE: &[u8] = include_bytes!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/tests/fixtures/fallback/proxy-v2-tcp4-127.0.0.1.bin"
    ));

    let header = build_proxy_protocol_v2(
        "127.0.0.1:12345".parse().unwrap(),
        "127.0.0.1:24443".parse().unwrap(),
    )
    .expect("proxy v2 header");

    assert_eq!(header, FIXTURE);
    assert_eq!(header[16], 0x7F);
    assert_eq!(header[20], 0x7F);
    assert_eq!(&header[24..26], &12345u16.to_be_bytes());
    assert_eq!(&header[26..28], &24443u16.to_be_bytes());
}

#[test]
fn proxy_v2_tcp6_exact_byte_layout() {
    let header = build_proxy_protocol_v2(
        "[2001:db8::1]:12345".parse().unwrap(),
        "[2001:db8::2]:24443".parse().unwrap(),
    )
    .expect("proxy v2 ipv6");

    assert_eq!(header.len(), 52);
    assert_eq!(&header[..12], PROXY_V2_SIGNATURE);
    assert_eq!(header[12], 0x21);
    assert_eq!(header[13], 0x21);
    assert_eq!(&header[14..16], &[0x00, 0x24]);
    assert_eq!(
        &header[16..32],
        [0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1]
    );
    assert_eq!(
        &header[32..48],
        [0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2]
    );
    assert_eq!(&header[48..50], &12345u16.to_be_bytes());
    assert_eq!(&header[50..52], &24443u16.to_be_bytes());
}

#[test]
fn http_path_match_prefers_path_fallback_over_alpn_only() {
    let fallbacks = vec![
        fallback(None, Some("h2"), None, "127.0.0.1:8082", 0),
        fallback(None, None, Some("/smoke-path"), "127.0.0.1:8083", 0),
    ];
    let request = b"GET /smoke-path/extra HTTP/1.1\r\nHost: x\r\n\r\n";
    let mut ctx = build_fallback_context(None, request);
    ctx.alpn = Some("h2".to_string());
    ctx.alpn_offers = vec!["h2".to_string()];

    let selected = select_vless_fallback_with_kind(&fallbacks, &ctx).expect("selected");
    assert_eq!(selected.config.dest.addr, "127.0.0.1:8083");
    assert_eq!(selected.kind, FallbackMatchKind::Path);
}

#[test]
fn alpn_only_wins_over_name_only_when_both_match_without_http_path() {
    let fallbacks = vec![
        fallback(Some("named.test"), None, None, "127.0.0.1:8081", 0),
        fallback(None, Some("h2"), None, "127.0.0.1:8082", 0),
    ];
    let ctx = FallbackContext {
        sni: Some("named.test".to_string()),
        alpn: Some("h2".to_string()),
        alpn_offers: vec!["h2".to_string()],
        ..FallbackContext::default()
    };

    let selected = select_vless_fallback_with_kind(&fallbacks, &ctx).expect("selected");
    assert_eq!(selected.config.dest.addr, "127.0.0.1:8082");
    assert_eq!(selected.kind, FallbackMatchKind::Alpn);
}
