
use super::*;
use crate::reality::tls13::key_share::{
    encode_key_share_extension_body, Tls13ServerKeyShare, NAMED_GROUP_X25519, X25519_KEY_LEN,
};
use crate::reality::tls13::TLS_AES_128_GCM_SHA256;
use crate::tls::parse_tls_server_hello_handshake;

fn sample_server_hello_params(session_id_echo: Vec<u8>) -> Tls13ServerHelloParams {
    let key_share = Tls13ServerKeyShare {
        group: NAMED_GROUP_X25519,
        public_key: [0x55; X25519_KEY_LEN],
        shared_secret: [0x66; X25519_KEY_LEN],
    };

    Tls13ServerHelloParams {
        random: [0x11; 32],
        session_id_echo,
        cipher_suite: TLS_AES_128_GCM_SHA256,
        key_share_extension_body: encode_key_share_extension_body(&key_share)
            .expect("valid key_share extension body"),
    }
}

#[test]
fn build_tls13_server_hello_encodes_handshake_message() {
    let params = sample_server_hello_params(vec![0x22; 8]);
    let message = build_tls13_server_hello(&params).expect("valid ServerHello");

    assert_eq!(message[0], HANDSHAKE_TYPE_SERVER_HELLO);
    let declared_len = u32::from_be_bytes([0, message[1], message[2], message[3]]) as usize;
    assert_eq!(declared_len, message.len() - 4);
}

#[test]
fn build_tls13_server_hello_preserves_body_fields_and_extensions() {
    let params = sample_server_hello_params(vec![0x22; 8]);
    let message = build_tls13_server_hello(&params).expect("valid ServerHello");
    let body = &message[4..];
    let parsed = parse_tls_server_hello_handshake(&message).expect("parsable ServerHello");

    assert_eq!(&body[..2], &TLS_VERSION_1_2_LEGACY);
    assert_eq!(parsed.legacy_version, TLS_VERSION_1_2_LEGACY);
    assert_eq!(parsed.random, params.random);
    assert_eq!(parsed.session_id_echo, params.session_id_echo);
    assert_eq!(parsed.cipher_suite, params.cipher_suite);
    assert_eq!(parsed.compression_method, 0);
    assert_eq!(
        parsed.get_extension(EXT_SUPPORTED_VERSIONS),
        Some(TLS_VERSION_1_3.as_slice())
    );
    assert_eq!(
        parsed.get_extension(EXT_KEY_SHARE),
        Some(params.key_share_extension_body.as_slice())
    );
}

#[test]
fn build_tls13_server_hello_rejects_session_id_echo_longer_than_32() {
    let params = sample_server_hello_params(vec![0x33; 33]);
    let err = build_tls13_server_hello(&params).unwrap_err();

    assert_eq!(err.kind(), ErrorKind::InvalidInput);
    assert!(err.to_string().contains("session_id_echo too long"));
}

#[test]
fn build_key_update_message_encodes_request_update_byte() {
    let message = build_key_update_message(KEY_UPDATE_NOT_REQUESTED).unwrap();
    assert_eq!(message, vec![0x18, 0x00, 0x00, 0x01, 0x00]);

    let requested = build_key_update_message(KEY_UPDATE_REQUESTED).unwrap();
    assert_eq!(requested, vec![0x18, 0x00, 0x00, 0x01, 0x01]);
}

#[test]
fn parse_key_update_handshake_roundtrips() {
    let message = build_key_update_message(KEY_UPDATE_REQUESTED).unwrap();
    assert_eq!(
        parse_key_update_handshake(&message).expect("valid key update"),
        KEY_UPDATE_REQUESTED
    );
}

#[test]
fn build_handshake_message_encodes_length_correctly() {
    let body = [0x01, 0x02, 0x03];
    let message = build_handshake_message(HANDSHAKE_TYPE_SERVER_HELLO, &body).unwrap();

    assert_eq!(message, vec![0x02, 0x00, 0x00, 0x03, 0x01, 0x02, 0x03]);
}

#[test]
fn build_handshake_message_rejects_body_too_long() {
    let body = vec![0u8; MAX_HANDSHAKE_BODY_LEN + 1];
    let err = build_handshake_message(HANDSHAKE_TYPE_FINISHED, &body).unwrap_err();

    assert_eq!(err.kind(), ErrorKind::InvalidInput);
    assert!(err.to_string().contains("handshake body too long"));
}

#[test]
fn build_encrypted_extensions_empty_is_exact_bytes() {
    let message = build_encrypted_extensions_empty().unwrap();
    assert_eq!(message, vec![0x08, 0x00, 0x00, 0x02, 0x00, 0x00]);
}

#[test]
fn build_finished_wraps_verify_data() {
    let verify_data = [0xaa, 0xbb, 0xcc, 0xdd];
    let message = build_finished(&verify_data).unwrap();

    assert_eq!(
        message,
        vec![0x14, 0x00, 0x00, 0x04, 0xaa, 0xbb, 0xcc, 0xdd]
    );
}

#[test]
fn build_certificate_placeholder_returns_unsupported() {
    let err = build_certificate_placeholder().unwrap_err();
    assert_eq!(err.kind(), ErrorKind::Unsupported);
}

#[test]
fn build_certificate_verify_placeholder_returns_unsupported() {
    let err = build_certificate_verify_placeholder().unwrap_err();
    assert_eq!(err.kind(), ErrorKind::Unsupported);
}
