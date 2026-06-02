
use super::*;
use crate::vless::vision::encode_vision_flow_addons_protobuf;
use std::net::Ipv4Addr;

const USER_ID: [u8; 16] = [
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01,
];

const LIVE_SMOKE_USER_ID: [u8; 16] = [0x11; 16];

fn build_request(
    version: u8,
    additional_info: &[u8],
    command: u8,
    port: u16,
    address: &[u8],
) -> Vec<u8> {
    build_vless_request_wire(version, &USER_ID, additional_info, command, port, address)
}

#[test]
fn vless_command_debug_includes_variant_name() {
    assert!(format!("{:?}", VlessCommand::Tcp).contains("Tcp"));
    assert!(format!("{:?}", VlessCommand::Unknown(99)).contains("Unknown"));
}

#[test]
fn vless_destination_debug_formats_ip_and_domain() {
    let ip = VlessDestination::Ip(IpAddr::V4(Ipv4Addr::LOCALHOST), 443);
    let domain = VlessDestination::Domain("example.com".to_string(), 443);

    assert!(format!("{ip:?}").contains("127.0.0.1"));
    assert!(format!("{domain:?}").contains("example.com"));
}

#[test]
fn parse_vless_request_tcp_ipv4() {
    let input = build_request(0, &[], 0x01, 443, &[0x01, 127, 0, 0, 1]);
    let (request, consumed) = parse_vless_request(&input).unwrap();

    assert_eq!(consumed, input.len());
    assert_eq!(request.version, 0);
    assert_eq!(request.user_id, uuid::Uuid::from_bytes(USER_ID));
    assert_eq!(request.command, VlessCommand::Tcp);
    assert_eq!(
        request.destination,
        VlessDestination::Ip(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 443)
    );
    assert!(request.additional_info.is_empty());
}

#[test]
fn parse_vless_request_tcp_ipv6() {
    let ipv6 = [
        0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x01,
    ];
    let mut address = vec![0x03];
    address.extend_from_slice(&ipv6);

    let input = build_request(0, &[], 0x01, 8443, &address);
    let (request, consumed) = parse_vless_request(&input).unwrap();

    assert_eq!(consumed, input.len());
    assert_eq!(request.command, VlessCommand::Tcp);
    assert_eq!(
        request.destination,
        VlessDestination::Ip(IpAddr::V6(Ipv6Addr::from(ipv6)), 8443)
    );
}

#[test]
fn parse_vless_request_tcp_domain() {
    let domain = b"example.com";
    let mut address = vec![0x02, domain.len() as u8];
    address.extend_from_slice(domain);

    let input = build_request(0, &[], 0x01, 443, &address);
    let (request, consumed) = parse_vless_request(&input).unwrap();

    assert_eq!(consumed, input.len());
    assert_eq!(request.command, VlessCommand::Tcp);
    assert_eq!(
        request.destination,
        VlessDestination::Domain("example.com".to_string(), 443)
    );
}

#[test]
fn parse_vless_request_preserves_additional_info() {
    let additional_info = encode_vision_flow_addons_protobuf();
    assert_eq!(additional_info.len(), 18);
    let input = build_request(0, &additional_info, 0x01, 443, &[0x01, 10, 0, 0, 1]);
    let (request, _) = parse_vless_request(&input).unwrap();

    assert_eq!(request.additional_info, additional_info);
}

#[test]
fn parse_vless_request_rejects_non_zero_version() {
    let input = build_request(1, &[], 0x01, 443, &[0x01, 10, 0, 0, 1]);
    let err = parse_vless_request(&input).unwrap_err();
    assert_eq!(err.kind(), ErrorKind::InvalidData);
}

#[test]
fn parse_vless_request_live_smoke_shape_example_com() {
    let tls_client_hello = [
        0x16, 0x03, 0x01, 0x00, 0x10, 0x01, 0x00, 0x00, 0x0c, 0x03, 0x03, 0x00, 0x00, 0x00, 0x00,
        0x00,
    ];
    let mut packet = build_vless_request_wire(
        0,
        &LIVE_SMOKE_USER_ID,
        &[],
        0x01,
        443,
        &build_vless_domain_address("example.com"),
    );
    packet.extend_from_slice(&tls_client_hello);

    let (request, consumed) = parse_vless_request(&packet).unwrap();
    let initial_payload = &packet[consumed..];

    assert_eq!(request.version, 0);
    assert_eq!(request.user_id, uuid::Uuid::from_bytes(LIVE_SMOKE_USER_ID));
    assert_eq!(request.command, VlessCommand::Tcp);
    assert_eq!(
        request.destination,
        VlessDestination::Domain("example.com".to_string(), 443)
    );
    assert!(request.additional_info.is_empty());
    assert!(initial_payload.starts_with(&[0x16, 0x03]));
    assert_ne!(
        initial_payload[..16.min(initial_payload.len())],
        LIVE_SMOKE_USER_ID
    );
}

#[test]
fn parse_vless_request_live_smoke_shape_with_vision_addons() {
    let addons = encode_vision_flow_addons_protobuf();
    let tls_client_hello = [0x16, 0x03, 0x01, 0x00, 0x10, 0x01, 0x02, 0x03];
    let mut packet = build_vless_request_wire(
        0,
        &LIVE_SMOKE_USER_ID,
        &addons,
        0x01,
        443,
        &build_vless_domain_address("example.com"),
    );
    packet.extend_from_slice(&tls_client_hello);

    let (request, consumed) = parse_vless_request(&packet).unwrap();
    let initial_payload = &packet[consumed..];

    assert_eq!(request.additional_info.len(), 18);
    assert_eq!(request.command, VlessCommand::Tcp);
    assert!(initial_payload.starts_with(&[0x16, 0x03]));
    assert_ne!(
        initial_payload[..16.min(initial_payload.len())],
        LIVE_SMOKE_USER_ID
    );
}

#[test]
fn parse_vless_request_does_not_include_uuid_in_initial_payload() {
    let tls_client_hello = [0x16, 0x03, 0x03, 0x00, 0x05];
    let mut packet = build_vless_request_wire(
        0,
        &LIVE_SMOKE_USER_ID,
        &[],
        0x01,
        443,
        &build_vless_domain_address("example.com"),
    );
    packet.extend_from_slice(&tls_client_hello);

    let (request, consumed) = parse_vless_request(&packet).unwrap();
    let initial_payload = &packet[consumed..];

    assert_eq!(request.user_id, uuid::Uuid::from_bytes(LIVE_SMOKE_USER_ID));
    assert_eq!(initial_payload, tls_client_hello);
}

#[test]
fn parse_vless_request_mux_command_has_no_address_on_wire() {
    let mut input = Vec::new();
    input.push(0);
    input.extend_from_slice(&USER_ID);
    input.push(0);
    input.push(0x03);
    input.extend_from_slice(b"mux-session-bytes");

    let (request, consumed) = parse_vless_request(&input).unwrap();

    assert_eq!(consumed, 19);
    assert_eq!(request.command, VlessCommand::Mux);
    assert_eq!(
        request.destination,
        VlessDestination::Domain("v1.mux.cool".to_string(), 0)
    );
}

#[test]
fn parse_vless_request_unknown_command() {
    let input = build_request(0, &[], 0x99, 443, &[0x01, 10, 0, 0, 1]);
    let (request, _) = parse_vless_request(&input).unwrap();

    assert_eq!(request.command, VlessCommand::Unknown(0x99));
}

#[test]
fn parse_vless_request_unknown_address_type_is_invalid_data() {
    let input = build_request(0, &[], 0x01, 443, &[0x04, 0, 0, 0, 0]);
    let err = parse_vless_request(&input).unwrap_err();

    assert_eq!(err.kind(), ErrorKind::InvalidData);
}

#[test]
fn parse_vless_request_truncated_uuid_is_unexpected_eof() {
    let mut input = build_request(0, &[], 0x01, 443, &[0x01, 10, 0, 0, 1]);
    input.truncate(10);

    let err = parse_vless_request(&input).unwrap_err();
    assert_eq!(err.kind(), ErrorKind::UnexpectedEof);
}

#[test]
fn parse_vless_request_truncated_domain_is_unexpected_eof() {
    let input = build_request(0, &[], 0x01, 443, &[0x02, 11, b'e', b'x']);
    let err = parse_vless_request(&input).unwrap_err();

    assert_eq!(err.kind(), ErrorKind::UnexpectedEof);
}

#[test]
fn parse_vless_request_invalid_utf8_domain_is_invalid_data() {
    let input = build_request(0, &[], 0x01, 443, &[0x02, 1, 0xff]);
    let err = parse_vless_request(&input).unwrap_err();

    assert_eq!(err.kind(), ErrorKind::InvalidData);
}

fn encode_vless_response_for_request(request: &VlessRequest, addons: Option<&[u8]>) -> Vec<u8> {
    encode_vless_response_header(request.version, addons)
}

#[test]
fn encode_vless_response_header_version_zero_has_empty_addons() {
    assert_eq!(encode_vless_response_header(0, None), vec![0, 0]);
    assert_eq!(encode_vless_response_header(0, Some(&[])), vec![0, 0]);
}

#[test]
fn encode_vless_response_header_version_one_has_empty_addons() {
    assert_eq!(encode_vless_response_header(1, None), vec![1, 0]);
    assert_eq!(encode_vless_response_header(1, Some(&[])), vec![1, 0]);
}

#[test]
fn encode_vless_response_header_non_empty_addons() {
    let addons = b"vision-meta";
    let mut expected = vec![0, addons.len() as u8];
    expected.extend_from_slice(addons);
    assert_eq!(encode_vless_response_header(0, Some(addons)), expected);

    let (version, decoded_addons) =
        decode_vless_response_header(&encode_vless_response_header(0, Some(addons))).unwrap();
    assert_eq!(version, 0);
    assert_eq!(decoded_addons, addons);
}

#[test]
fn encode_vless_response_header_matches_request_version() {
    let input = build_request(0, &[], 0x01, 443, &[0x01, 127, 0, 0, 1]);
    let (request, _) = parse_vless_request(&input).unwrap();

    let header = encode_vless_response_for_request(&request, None);
    let (decoded_version, decoded_addons) = decode_vless_response_header(&header).unwrap();

    assert_eq!(decoded_version, request.version);
    assert_eq!(decoded_version, 0);
    assert!(decoded_addons.is_empty());
}

#[test]
fn decode_vless_response_header_rejects_truncated_addons() {
    let err = decode_vless_response_header(&[0, 3, 0x01]).unwrap_err();
    assert_eq!(err.kind(), ErrorKind::UnexpectedEof);
    assert!(err.to_string().contains("truncated"));
}
