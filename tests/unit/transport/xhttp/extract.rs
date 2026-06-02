use super::*;
use http::Request;

fn request(method: &str, target: &str) -> Request<()> {
    Request::builder()
        .method(method)
        .uri(format!("https://example.com{target}"))
        .body(())
        .unwrap()
}

fn settings() -> XHttpSettings {
    XHttpSettings {
        path: "/xhttp".to_string(),
        ..XHttpSettings::default()
    }
}

#[test]
fn session_id_extracted_from_observed_path_segment() {
    let req = request("GET", "/xhttp/0897e374-2f32-4d61-aee9-b9c8523aa358");
    let session_id = extract_xhttp_session_id(&req, &settings()).expect("session id");
    assert_eq!(session_id, "0897e374-2f32-4d61-aee9-b9c8523aa358");
}

#[test]
fn invalid_session_id_rejected() {
    let req = request("GET", "/xhttp/../escape");
    let err = extract_xhttp_session_id(&req, &settings()).unwrap_err();
    assert!(matches!(err, XHttpError::InvalidSessionId(_)));

    let req = request("GET", "/xhttp/bad%2fid");
    let err = extract_xhttp_session_id(&req, &settings()).unwrap_err();
    assert!(matches!(err, XHttpError::InvalidSessionId(_)));
}

#[test]
fn missing_session_id_is_clear_error() {
    let req = request("GET", "/xhttp");
    let err = extract_xhttp_session_id(&req, &settings()).unwrap_err();
    assert_eq!(err, XHttpError::MissingSessionId);
}

#[test]
fn seq_extracted_from_upload_path_suffix() {
    let req = request("POST", "/xhttp/0897e374-2f32-4d61-aee9-b9c8523aa358/7");
    assert_eq!(
        extract_xhttp_packet_seq_for_settings(&req, &settings()).expect("seq"),
        Some(7)
    );
}

#[test]
fn download_get_has_no_seq() {
    let req = request("GET", "/xhttp/0897e374-2f32-4d61-aee9-b9c8523aa358");
    assert_eq!(
        extract_xhttp_packet_seq_for_settings(&req, &settings()).expect("seq"),
        None
    );
}

#[test]
fn malformed_seq_segment_is_rejected() {
    let req = request("POST", "/xhttp/session-a/not-a-number");
    let err = extract_xhttp_packet_seq_for_settings(&req, &settings()).unwrap_err();
    assert!(matches!(err, XHttpError::MalformedPacketRequest(_)));
}

#[test]
fn extract_xhttp_packet_seq_without_settings() {
    let req = request("POST", "/xhttp/0897e374-2f32-4d61-aee9-b9c8523aa358/3");
    assert_eq!(extract_xhttp_packet_seq(&req), Some(3));
}

#[test]
fn unsupported_query_session_source_is_not_used() {
    let req = request("GET", "/xhttp?sessionId=ignored");
    let err = extract_xhttp_session_id(&req, &settings()).unwrap_err();
    assert_eq!(err, XHttpError::MissingSessionId);
}
