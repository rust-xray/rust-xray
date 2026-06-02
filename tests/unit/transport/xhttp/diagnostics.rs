use super::*;

#[test]
fn query_and_header_names_are_logged_without_values() {
    let shape = build_request_shape(
        "/xhttp",
        "POST",
        "/xhttp?sessionId=secret&seqStr=7",
        vec![
            "host".to_string(),
            "content-type".to_string(),
            "x-custom".to_string(),
        ],
        "HTTP/1.1",
        Some(128),
        None,
        vec![64, 64],
    );
    assert_eq!(shape.query_keys, vec!["sessionId", "seqStr"]);
    assert_eq!(shape.header_names, vec!["host", "content-type", "x-custom"]);
    assert_eq!(
        shape.session_id_location,
        Some("query_key:sessionId".to_string())
    );
    assert_eq!(shape.seq_id_location, Some("query_key:seqStr".to_string()));
}

#[test]
fn session_id_in_path_suffix_is_detected_by_segment_index() {
    let shape = build_request_shape(
        "/xhttp",
        "GET",
        "/xhttp/0897e374-2f32-4d61-aee9-b9c8523aa358",
        vec!["host".to_string()],
        "HTTP/2",
        None,
        None,
        vec![],
    );
    assert_eq!(
        shape.session_id_location,
        Some("path_segment:1".to_string())
    );
    assert_eq!(shape.path, "/xhttp/{session}");
    assert!(!shape.path.contains("0897e374"));
}

#[test]
fn shape_fields_do_not_embed_payload_content() {
    let secret = "top-secret-vless-payload-data";
    let shape = build_request_shape(
        "/xhttp",
        "POST",
        "/xhttp",
        vec!["host".to_string()],
        "HTTP/1.1",
        Some(secret.len() as u64),
        None,
        vec![secret.len()],
    );
    let debug = format!("{shape:?}");
    assert!(!debug.contains(secret));
    assert_eq!(shape.body_chunk_sizes, vec![secret.len()]);
}

#[test]
fn diagnostics_redact_payload_bytes() {
    let payload = b"super-secret-vless-payload-data";
    let shape = build_request_shape(
        "/xhttp",
        "POST",
        "/xhttp",
        vec!["host".to_string()],
        "HTTP/1.1",
        Some(payload.len() as u64),
        None,
        vec![payload.len()],
    );
    assert!(shape_redacts_payload(&shape, payload));
}

#[test]
fn download_get_is_classified_with_session_path_suffix() {
    let shape = build_request_shape(
        "/xhttp",
        "GET",
        "/xhttp/0897e374-2f32-4d61-aee9-b9c8523aa358",
        vec!["host".to_string()],
        "HTTP/2",
        None,
        None,
        vec![],
    );
    let leg = classify_request_leg(
        "GET",
        "/xhttp/0897e374-2f32-4d61-aee9-b9c8523aa358",
        "/xhttp",
        EffectiveXHttpMode::PacketUp,
        shape.session_id_location.as_deref(),
    );
    assert_eq!(leg, XHttpRequestLeg::Download);
    let recon = build_download_recon(&shape, leg, EffectiveXHttpMode::PacketUp).unwrap();
    assert_eq!(recon.method, "GET");
    assert_eq!(recon.path, "/xhttp/{session}");
    assert_eq!(recon.body_direction, "server_to_client");
    assert_eq!(recon.requires_h2, "yes");
    assert_eq!(recon.upload_download_relation, "packet-up:download_get");
}

#[test]
fn upload_post_is_not_download_recon_candidate() {
    let shape = build_request_shape(
        "/xhttp",
        "POST",
        "/xhttp/0897e374-2f32-4d61-aee9-b9c8523aa358/0",
        vec!["host".to_string()],
        "HTTP/2",
        Some(128),
        None,
        vec![64, 64],
    );
    let leg = classify_request_leg(
        "POST",
        "/xhttp/0897e374-2f32-4d61-aee9-b9c8523aa358/0",
        "/xhttp",
        EffectiveXHttpMode::PacketUp,
        shape.session_id_location.as_deref(),
    );
    assert_eq!(leg, XHttpRequestLeg::Upload);
    assert!(build_download_recon(&shape, leg, EffectiveXHttpMode::PacketUp).is_none());
}
