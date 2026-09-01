use super::*;
use std::collections::BTreeMap;

fn client_object(id: &str, email: Option<&str>, flow: Option<&str>) -> VlessClientObject {
    VlessClientObject {
        id: id.to_string(),
        email: email.map(str::to_string),
        flow: flow.map(str::to_string),
        level: None,
        testseed: None,
        extra: BTreeMap::new(),
    }
}

#[test]
fn build_vless_clients_parses_valid_uuid() {
    let clients = build_vless_clients(&[client_object(
        "00000000-0000-0000-0000-000000000001",
        None,
        None,
    )])
    .unwrap();

    assert_eq!(clients.len(), 1);
    assert_eq!(
        clients[0].id,
        uuid::Uuid::parse_str("00000000-0000-0000-0000-000000000001").unwrap()
    );
}

#[test]
fn parse_vless_user_id_accepts_canonical_uuid_unchanged() {
    let id = parse_vless_user_id("00000000-0000-0000-0000-000000000001").unwrap();
    assert_eq!(
        id,
        uuid::Uuid::parse_str("00000000-0000-0000-0000-000000000001").unwrap()
    );
}

#[test]
fn parse_vless_user_id_accepts_dashless_uuid_unchanged() {
    let id = parse_vless_user_id("00000000000000000000000000000001").unwrap();
    assert_eq!(
        id,
        uuid::Uuid::parse_str("00000000-0000-0000-0000-000000000001").unwrap()
    );
}

#[test]
fn parse_vless_user_id_maps_custom_string_like_xray() {
    let id = parse_vless_user_id("example").unwrap();
    assert_eq!(
        id,
        uuid::Uuid::parse_str("feb54431-301b-52bb-a6dd-e1e93e81bb9e").unwrap()
    );

    let id = parse_vless_user_id("not-a-uuid").unwrap();
    assert_eq!(
        id,
        uuid::Uuid::parse_str("9b70e619-d7b3-55b1-b743-756ebd573b4e").unwrap()
    );
}

#[test]
fn parse_vless_user_id_maps_utf8_custom_string_like_xray() {
    let id = parse_vless_user_id("我爱🍉老师1314").unwrap();
    assert_eq!(
        id,
        uuid::Uuid::parse_str("5783a3e7-e373-51cd-8642-c83782b807c5").unwrap()
    );
    assert_eq!("我爱🍉老师1314".len(), 20);
}

#[test]
fn parse_vless_user_id_rejects_empty_and_too_long_custom_strings() {
    for input in ["", &"a".repeat(31)] {
        let err = parse_vless_user_id(input).unwrap_err();
        assert_eq!(
            err.kind(),
            std::io::ErrorKind::InvalidInput,
            "input len={}",
            input.len()
        );
    }
}

#[test]
fn parse_vless_user_id_rejects_invalid_uuid_length_strings() {
    let err = parse_vless_user_id("00000000-0000-0000-0000-00000000000g").unwrap_err();
    assert_eq!(err.kind(), std::io::ErrorKind::InvalidInput);
}

#[test]
fn build_vless_clients_maps_custom_string_id() {
    let clients = build_vless_clients(&[client_object("example", None, None)]).unwrap();
    assert_eq!(
        clients[0].id,
        uuid::Uuid::parse_str("feb54431-301b-52bb-a6dd-e1e93e81bb9e").unwrap()
    );
}

#[test]
fn build_vless_clients_copies_email_and_flow() {
    let clients = build_vless_clients(&[client_object(
        "00000000-0000-0000-0000-000000000001",
        Some("user@example.com"),
        Some("xtls-rprx-vision"),
    )])
    .unwrap();

    assert_eq!(clients[0].email.as_deref(), Some("user@example.com"));
    assert_eq!(clients[0].flow.as_deref(), Some("xtls-rprx-vision"));
}

#[test]
fn build_vless_clients_empty_input_returns_empty_vec() {
    let clients = build_vless_clients(&[]).unwrap();
    assert!(clients.is_empty());
}

#[test]
fn validate_vless_client_flow_accepts_missing_and_empty() {
    assert!(validate_vless_client_flow(None).is_ok());
    assert!(validate_vless_client_flow(Some("")).is_ok());
}

#[test]
fn validate_vless_client_flow_rejects_unknown_flow() {
    let err = validate_vless_client_flow(Some("unknown-flow")).unwrap_err();
    assert_eq!(err.kind(), std::io::ErrorKind::Unsupported);
    assert_eq!(err.to_string(), "unsupported VLESS flow: unknown-flow");
}

#[test]
fn build_vless_clients_normalizes_empty_flow_to_none() {
    let clients = build_vless_clients(&[client_object(
        "00000000-0000-0000-0000-000000000001",
        None,
        Some(""),
    )])
    .unwrap();
    assert!(clients[0].flow.is_none());
}

#[test]
fn merge_vless_client_objects_prefers_non_empty_flow() {
    let id = "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee";
    let merged = merge_vless_client_objects([
        client_object(id, None, None),
        client_object(id, None, Some("xtls-rprx-vision")),
    ])
    .expect("merge");
    assert_eq!(merged.len(), 1);
    assert_eq!(merged[0].flow.as_deref(), Some("xtls-rprx-vision"));
}

#[test]
fn validate_vless_client_flow_accepts_vision_when_implemented() {
    assert!(vision_relay_supported());
    assert!(validate_vless_client_flow(Some("xtls-rprx-vision")).is_ok());
}

#[test]
fn resolve_inbound_default_flow_from_raw_reality() {
    assert_eq!(
        resolve_inbound_default_vless_flow(None, Some("reality"), Some("raw")).as_deref(),
        Some("xtls-rprx-vision")
    );
    assert_eq!(
        resolve_inbound_default_vless_flow(None, Some("reality"), Some("tcp")).as_deref(),
        Some("xtls-rprx-vision")
    );
    assert_eq!(
        resolve_inbound_default_vless_flow(None, Some("reality"), Some("ws")).as_deref(),
        None
    );
}

#[test]
fn resolve_inbound_default_flow_from_settings_flow() {
    assert_eq!(
        resolve_inbound_default_vless_flow(Some("xtls-rprx-vision"), None, None).as_deref(),
        Some("xtls-rprx-vision")
    );
    assert_eq!(
        resolve_inbound_default_vless_flow(Some(""), None, None).as_deref(),
        None
    );
}

#[test]
fn apply_inbound_flow_preserves_explicit_empty_client_flow() {
    let mut clients = vec![client_object(
        "00000000-0000-0000-0000-000000000001",
        None,
        Some(""),
    )];
    apply_inbound_vless_client_flows(&mut clients, None, Some("reality"), Some("raw")).unwrap();
    assert_eq!(clients[0].flow.as_deref(), Some(""));
}

#[test]
fn apply_inbound_flow_fills_missing_client_flow() {
    let mut clients = vec![client_object(
        "00000000-0000-0000-0000-000000000001",
        None,
        None,
    )];
    apply_inbound_vless_client_flows(&mut clients, None, Some("reality"), Some("raw")).unwrap();
    assert_eq!(clients[0].flow.as_deref(), Some("xtls-rprx-vision"));
}
