
use super::*;

fn build_server_hello_handshake_message(
    random: [u8; 32],
    session_id_echo: &[u8],
    cipher_suite: u16,
    extensions: &[(u16, &[u8])],
) -> Vec<u8> {
    assert!(session_id_echo.len() <= u8::MAX as usize);

    let mut body = Vec::new();
    body.extend_from_slice(&[0x03, 0x03]);
    body.extend_from_slice(&random);
    body.push(session_id_echo.len() as u8);
    body.extend_from_slice(session_id_echo);
    body.extend_from_slice(&cipher_suite.to_be_bytes());
    body.push(0x00);

    let mut extension_bytes = Vec::new();
    for (extension_type, data) in extensions {
        extension_bytes.extend_from_slice(&extension_type.to_be_bytes());
        extension_bytes.extend_from_slice(&(data.len() as u16).to_be_bytes());
        extension_bytes.extend_from_slice(data);
    }
    body.extend_from_slice(&(extension_bytes.len() as u16).to_be_bytes());
    body.extend_from_slice(&extension_bytes);

    let mut message = Vec::with_capacity(HANDSHAKE_HEADER_LEN + body.len());
    message.push(TLS_HANDSHAKE_SERVER_HELLO);
    message.extend_from_slice(&(body.len() as u32).to_be_bytes()[1..]);
    message.extend_from_slice(&body);
    message
}

#[test]
fn parse_minimal_valid_tls13_server_hello_with_supported_versions_and_key_share() {
    let random = [0x11; 32];
    let supported_versions = [0x03, 0x04];
    let key_share = {
        let mut data = Vec::new();
        data.extend_from_slice(&0x001du16.to_be_bytes()); // x25519
        data.extend_from_slice(&32u16.to_be_bytes());
        data.extend_from_slice(&[0x22; 32]);
        data
    };

    let input = build_server_hello_handshake_message(
        random,
        &[],
        0x1301,
        &[
            (EXTENSION_SUPPORTED_VERSIONS, &supported_versions),
            (EXTENSION_KEY_SHARE, &key_share),
        ],
    );

    let server_hello = parse_tls_server_hello_handshake(&input).expect("valid ServerHello");

    assert_eq!(server_hello.legacy_version, [0x03, 0x03]);
    assert_eq!(server_hello.random, random);
    assert!(server_hello.session_id_echo.is_empty());
    assert_eq!(server_hello.cipher_suite, 0x1301);
    assert_eq!(server_hello.compression_method, 0x00);
    assert_eq!(server_hello.extensions.len(), 2);
    assert_eq!(
        server_hello.get_extension(EXTENSION_SUPPORTED_VERSIONS),
        Some(supported_versions.as_slice())
    );
    assert_eq!(
        server_hello.get_extension(EXTENSION_KEY_SHARE),
        Some(key_share.as_slice())
    );
}

#[test]
fn parse_rejects_wrong_handshake_type() {
    let mut input = build_server_hello_handshake_message([0; 32], &[], 0x1301, &[]);
    input[0] = 0x01;

    let err = parse_tls_server_hello_handshake(&input).unwrap_err();
    assert_eq!(err.kind(), ErrorKind::InvalidData);
    assert!(err.to_string().contains("ServerHello handshake"));
}

#[test]
fn parse_rejects_truncated_body() {
    let input = build_server_hello_handshake_message([0; 32], &[], 0x1301, &[]);
    let truncated = &input[..input.len() - 2];

    let err = parse_tls_server_hello_handshake(truncated).unwrap_err();
    assert_eq!(err.kind(), ErrorKind::UnexpectedEof);
}

#[test]
fn parse_rejects_trailing_bytes() {
    let mut input = build_server_hello_handshake_message([0; 32], &[], 0x1301, &[]);
    input.push(0xff);

    let err = parse_tls_server_hello_handshake(&input).unwrap_err();
    assert_eq!(err.kind(), ErrorKind::InvalidData);
    assert!(err.to_string().contains("trailing data"));
}

#[test]
fn parse_server_hello_key_share_valid_x25519() {
    let mut data = Vec::new();
    data.extend_from_slice(&NAMED_GROUP_X25519.to_be_bytes());
    data.extend_from_slice(&32u16.to_be_bytes());
    data.extend_from_slice(&[0x44; 32]);

    let key_share = parse_server_hello_key_share(&data).expect("valid key_share");
    assert_eq!(key_share.group, NAMED_GROUP_X25519);
    assert_eq!(key_share.key_exchange, vec![0x44; 32]);
}

#[test]
fn extension_lookup_works() {
    let custom_ext_data = [0xaa, 0xbb, 0xcc];
    let input = build_server_hello_handshake_message(
        [0x33; 32],
        &[0x01, 0x02],
        0x1302,
        &[(0x1234, &custom_ext_data)],
    );

    let server_hello = parse_tls_server_hello_handshake(&input).expect("valid ServerHello");

    assert_eq!(server_hello.session_id_echo, vec![0x01, 0x02]);
    assert_eq!(
        server_hello.get_extension(0x1234),
        Some(custom_ext_data.as_slice())
    );
    assert_eq!(
        server_hello.get_extension(EXTENSION_SUPPORTED_VERSIONS),
        None
    );
}
