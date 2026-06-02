use super::*;

#[test]
fn exact_path_matches() {
    assert!(path_matches("/xhttp", "/xhttp"));
}

#[test]
fn trailing_slash_path_matches_configured_without_slash() {
    assert!(path_matches("/xhttp", "/xhttp/"));
    assert!(path_matches("/xhttp/", "/xhttp"));
}

#[test]
fn query_path_matches_without_query_in_compare() {
    assert!(path_matches(
        "/xhttp",
        request_path_component("/xhttp?sid=abc")
    ));
    assert_eq!(
        query_keys("/xhttp?sessionId=abc&seqStr=1&flag"),
        vec![
            "sessionId".to_string(),
            "seqStr".to_string(),
            "flag".to_string()
        ]
    );
}

#[test]
fn wrong_path_rejected() {
    assert!(!path_matches("/xhttp", "/wrong"));
}

#[test]
fn host_absent_accepts_any() {
    assert!(host_matches(
        None,
        Some("anything.example"),
        TransportSecurity::Reality
    ));
    assert!(host_matches(None, None, TransportSecurity::Reality));
}

#[test]
fn host_exact_match_case_insensitive() {
    assert!(host_matches(
        Some("Example.COM"),
        Some("example.com"),
        TransportSecurity::Reality
    ));
}

#[test]
fn host_with_default_port_accepted_for_reality() {
    assert!(host_matches(
        Some("example.com"),
        Some("example.com:443"),
        TransportSecurity::Reality
    ));
    assert!(host_matches(
        Some("example.com"),
        Some("example.com:443"),
        TransportSecurity::Tls
    ));
}

#[test]
fn host_with_non_default_port_rejected_for_bare_configured_host() {
    assert!(!host_matches(
        Some("example.com"),
        Some("example.com:8080"),
        TransportSecurity::Reality
    ));
}

#[test]
fn wrong_host_rejected() {
    assert!(!host_matches(
        Some("example.com"),
        Some("other.example"),
        TransportSecurity::Reality
    ));
}

#[test]
fn post_accepted_for_stream_one() {
    assert!(method_matches_stream_one("POST"));
    assert!(method_matches_stream_one("post"));
}

#[test]
fn get_rejected_for_stream_one() {
    assert!(!method_matches_stream_one("GET"));
}

#[test]
fn parse_packet_up_path_extracts_session_and_seq() {
    let parsed = parse_packet_up_path("/xhttp", "/xhttp/0897e374-2f32-4d61-aee9-b9c8523aa358")
        .expect("session");
    assert_eq!(parsed.session_id, "0897e374-2f32-4d61-aee9-b9c8523aa358");
    assert_eq!(parsed.seq, None);

    let parsed = parse_packet_up_path("/xhttp", "/xhttp/0897e374-2f32-4d61-aee9-b9c8523aa358/0")
        .expect("upload");
    assert_eq!(parsed.session_id, "0897e374-2f32-4d61-aee9-b9c8523aa358");
    assert_eq!(parsed.seq, Some(0));
}

#[test]
fn validate_packet_up_upload_requires_seq_suffix() {
    let settings = XHttpMatchSettings {
        path: "/xhttp",
        host: None,
    };
    let request = XHttpRequestDescriptor {
        method: "POST",
        request_target: "/xhttp/session-a/0",
        host: Some("example.com"),
    };
    assert!(validate_packet_up_request(&settings, &request, TransportSecurity::Reality).is_ok());
    let without_seq = XHttpRequestDescriptor {
        method: "POST",
        request_target: "/xhttp/session-a",
        host: Some("example.com"),
    };
    assert!(
        validate_packet_up_request(&settings, &without_seq, TransportSecurity::Reality).is_ok()
    );
}

#[test]
fn validate_request_accepts_official_client_shape() {
    let settings = XHttpMatchSettings {
        path: "/xhttp",
        host: Some("example.com"),
    };
    let request = XHttpRequestDescriptor {
        method: "POST",
        request_target: "/xhttp?sessionId=abc&seq=1",
        host: Some("example.com:443"),
    };
    assert!(
        validate_xhttp_stream_one_request(&settings, &request, TransportSecurity::Reality).is_ok()
    );
}
