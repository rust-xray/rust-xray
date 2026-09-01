use super::*;
use crate::mux::{encode_mux_new_tcp, encode_mux_new_udp_xudp};
use crate::vless::config::VlessClient;
use crate::vless::protocol::{VlessCommand, VlessDestination};
use std::net::{IpAddr, Ipv4Addr};

const USER_ID: uuid::Uuid =
    uuid::Uuid::from_bytes([0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1]);

const UNKNOWN_ID: uuid::Uuid =
    uuid::Uuid::from_bytes([0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2]);

fn vless_client(email: Option<&str>, flow: Option<&str>) -> VlessClient {
    VlessClient {
        id: USER_ID,
        email: email.map(str::to_string),
        flow: flow.map(str::to_string),
        level: None,
        testseed: crate::vless::UPSTREAM_DEFAULT_TESTSEED,
    }
}

fn test_users(clients: Vec<VlessClient>) -> VlessUserManager {
    VlessUserManager::new("test-in", clients)
}

fn vless_request(user_id: uuid::Uuid) -> VlessRequest {
    VlessRequest {
        version: 0,
        user_id,
        command: VlessCommand::Tcp,
        destination: VlessDestination::Ip(IpAddr::V4(Ipv4Addr::LOCALHOST), 443),
        additional_info: Vec::new(),
    }
}

#[test]
fn authenticate_vless_client_known_uuid() {
    let users = test_users(vec![vless_client(
        Some("user@example.com"),
        Some("xtls-rprx-vision"),
    )]);
    let request = vless_request(USER_ID);

    let auth = authenticate_vless_client(&request, &users).unwrap();

    assert_eq!(auth.id, USER_ID);
    assert_eq!(auth.email.as_deref(), Some("user@example.com"));
    assert_eq!(auth.flow.as_deref(), Some("xtls-rprx-vision"));
}

#[test]
fn authenticate_vless_client_unknown_uuid_is_permission_denied() {
    let users = test_users(vec![vless_client(None, None)]);
    let request = vless_request(UNKNOWN_ID);

    let err = authenticate_vless_client(&request, &users).unwrap_err();
    assert_eq!(err.kind(), std::io::ErrorKind::PermissionDenied);
}

#[test]
fn authenticate_vless_client_flow_none_ok() {
    let users = test_users(vec![vless_client(Some("user@example.com"), None)]);
    let request = vless_request(USER_ID);

    authenticate_vless_client(&request, &users).unwrap();
}

#[test]
fn authenticate_vless_client_flow_empty_ok() {
    let users = test_users(vec![vless_client(Some("user@example.com"), Some(""))]);
    let request = vless_request(USER_ID);

    authenticate_vless_client(&request, &users).unwrap();
}

#[test]
fn authenticate_vless_client_flow_vision_ok() {
    let users = test_users(vec![vless_client(None, Some("xtls-rprx-vision"))]);
    let request = vless_request(USER_ID);

    authenticate_vless_client(&request, &users).unwrap();
}

#[test]
fn authenticate_vless_client_unsupported_flow_is_unsupported() {
    let users = test_users(vec![vless_client(None, Some("xtls-rprx-direct"))]);
    let request = vless_request(USER_ID);

    let err = authenticate_vless_client(&request, &users).unwrap_err();
    assert_eq!(err.kind(), std::io::ErrorKind::Unsupported);
    assert_eq!(err.to_string(), "unsupported VLESS flow: xtls-rprx-direct");
}

#[test]
fn is_supported_vless_flow_accepts_none_empty_and_vision() {
    assert!(is_supported_vless_flow(None));
    assert!(is_supported_vless_flow(Some("")));
    assert!(is_supported_vless_flow(Some("xtls-rprx-vision")));
    assert!(!is_supported_vless_flow(Some("xtls-rprx-direct")));
}

#[test]
fn validate_flow_rejects_empty_account_with_vision_request() {
    let err = validate_vless_flow_for_command(
        Some(FLOW_XTLS_RPRX_VISION),
        Some(""),
        VlessCommand::Tcp,
        &[],
    )
    .unwrap_err();
    assert_eq!(err.kind(), ErrorKind::PermissionDenied);
}

#[test]
fn validate_flow_rejects_vision_account_with_empty_request() {
    let err =
        validate_vless_flow_for_command(None, Some(FLOW_XTLS_RPRX_VISION), VlessCommand::Tcp, &[])
            .unwrap_err();
    assert_eq!(err.kind(), ErrorKind::PermissionDenied);
    assert!(err.to_string().contains("empty"));
}

#[test]
fn validate_flow_rejects_vision_udp() {
    let err = validate_vless_flow_for_command(
        Some(FLOW_XTLS_RPRX_VISION),
        Some(FLOW_XTLS_RPRX_VISION),
        VlessCommand::Udp,
        &[],
    )
    .unwrap_err();
    assert_eq!(err.kind(), ErrorKind::Unsupported);
    assert!(err.to_string().contains("UDP"));
}

#[test]
fn validate_flow_rejects_unknown_flow() {
    let err = validate_vless_flow_for_command(
        Some("xtls-rprx-direct"),
        Some("xtls-rprx-direct"),
        VlessCommand::Tcp,
        &[],
    )
    .unwrap_err();
    assert_eq!(err.kind(), ErrorKind::Unsupported);
}

#[test]
fn validate_flow_rejects_vision_account_with_empty_mux_tcp() {
    let tcp_open = encode_mux_new_tcp(
        1,
        &VlessDestination::Ip(IpAddr::V4(Ipv4Addr::LOCALHOST), 443),
        b"",
    );
    let err = validate_vless_flow_for_command(
        None,
        Some(FLOW_XTLS_RPRX_VISION),
        VlessCommand::Mux,
        &tcp_open,
    )
    .unwrap_err();
    assert_eq!(err.kind(), ErrorKind::PermissionDenied);
}

#[test]
fn validate_flow_allows_vision_account_with_xudp_mux() {
    let destination = VlessDestination::Ip(IpAddr::V4(Ipv4Addr::LOCALHOST), 53);
    let global_id = [1u8; 8];
    let xudp_open = encode_mux_new_udp_xudp(0, &destination, &global_id, b"ping");
    validate_vless_flow_for_command(
        None,
        Some(FLOW_XTLS_RPRX_VISION),
        VlessCommand::Mux,
        &xudp_open,
    )
    .expect("vision mux xudp allowed");
}

#[test]
fn validate_flow_empty_regression_unchanged() {
    validate_vless_flow_for_command(None, None, VlessCommand::Tcp, &[]).unwrap();
    validate_vless_flow_for_command(Some(""), Some(""), VlessCommand::Tcp, &[]).unwrap();
}

#[tokio::test]
async fn mux_route_environment_keeps_authenticated_connection_stats() {
    let registry = Arc::new(crate::stats::StatsRegistry::new());
    let session = crate::stats::StatsSession::new(
        registry,
        crate::stats::StatsPolicy {
            user_uplink: true,
            user_downlink: true,
            user_online: false,
            inbound_uplink: true,
            inbound_downlink: true,
            outbound_uplink: true,
            outbound_downlink: true,
        },
        None,
        "test-in".to_string(),
        "direct".to_string(),
        Some("user@example.com".to_string()),
        None,
        None,
    );
    let stats = StatsConnection::open(session);
    let outbound = crate::runtime::RuntimeOutboundManager::new();
    outbound
        .register_startup_outbound(&crate::config::xray::raw::OutboundObject {
            tag: Some("direct".to_string()),
            protocol: Some("freedom".to_string()),
            extra: Default::default(),
        })
        .expect("freedom outbound");
    let router = RuntimeRouter::new(None, outbound, crate::dns::DnsEngine::shared(), false, None)
        .expect("router");
    let auth = VlessAuthenticatedClient {
        id: USER_ID,
        email: Some("user@example.com".to_string()),
        flow: None,
        level: None,
        testseed: crate::vless::UPSTREAM_DEFAULT_TESTSEED,
        inbound_tag: "test-in".to_string(),
    };

    let env = mux_route_env(
        Some(&router),
        &auth,
        false,
        Some(&stats),
        &RouteSocketMeta::default(),
        false,
    )
    .expect("mux route env");

    assert!(env.stats.is_some());
}

#[test]
fn flow_matching_selects_user_by_uuid_not_first() {
    use crate::vless::vision::encode_vision_flow_addons_protobuf;

    const USER_A: uuid::Uuid =
        uuid::Uuid::from_bytes([0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x0a]);
    const USER_B: uuid::Uuid =
        uuid::Uuid::from_bytes([0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x0b]);

    let users = test_users(vec![
        VlessClient {
            id: USER_A,
            email: None,
            flow: None,
            level: None,
            testseed: crate::vless::UPSTREAM_DEFAULT_TESTSEED,
        },
        VlessClient {
            id: USER_B,
            email: None,
            flow: Some("xtls-rprx-vision".to_string()),
            level: None,
            testseed: crate::vless::UPSTREAM_DEFAULT_TESTSEED,
        },
    ]);

    let vision_addons = encode_vision_flow_addons_protobuf();
    let mut request_b = vless_request(USER_B);
    request_b.additional_info = vision_addons.clone();

    let auth_b = authenticate_vless_client(&request_b, &users).expect("user B auth");
    validate_vless_flow_for_command(
        parse_vless_request_flow(&request_b.additional_info).as_deref(),
        auth_b.flow.as_deref(),
        request_b.command,
        &[],
    )
    .expect("user B vision flow");

    let mut request_a = vless_request(USER_A);
    request_a.additional_info = vision_addons;
    let auth_a = authenticate_vless_client(&request_a, &users).expect("user A auth");
    let err = validate_vless_flow_for_command(
        parse_vless_request_flow(&request_a.additional_info).as_deref(),
        auth_a.flow.as_deref(),
        request_a.command,
        &[],
    )
    .unwrap_err();
    assert_eq!(err.kind(), ErrorKind::PermissionDenied);
    assert!(err.to_string().contains(FLOW_XTLS_RPRX_VISION));

    let unknown = authenticate_vless_client(&vless_request(UNKNOWN_ID), &users).unwrap_err();
    assert_eq!(unknown.kind(), ErrorKind::PermissionDenied);
}
