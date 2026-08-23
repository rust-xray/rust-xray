//! Deterministic upstream compatibility vectors (no live smoke duplication).
//!
//! Live matrix coverage remains in `scripts/live_reality_smoke/run-live-smoke.sh`.
//! These tests lock parser/selection/policy contracts in Rust only.

use rust_xray::config::{
    effective_reality_min_client_ver, first_reality_inbound_runtime,
    validate_reality_transport_network, XrayConfig, DEFAULT_REALITY_MIN_CLIENT_VER,
};
use rust_xray::reality::{select_reality_certificate_patch_mode, RealityCertificatePatchMode};

const TEST_REALITY_PRIVATE_KEY: &str = "CMZoLYnNxeaUoLn7LwK4RzBIdpzBXI5TOIlZ3tEfOn4";
const TEST_MLDSA65_SEED: &str = "AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8";

fn vless_reality_config_json(network: &str, mldsa65_seed: Option<&str>) -> String {
    let seed_field = mldsa65_seed
        .map(|seed| format!(r#","mldsa65Seed": "{seed}""#))
        .unwrap_or_default();

    format!(
        r#"{{
            "inbounds": [{{
                "port": 443,
                "protocol": "vless",
                "settings": {{
                    "clients": [{{"id": "00000000-0000-0000-0000-000000000001"}}],
                    "decryption": "none"
                }},
                "streamSettings": {{
                    "network": "{network}",
                    "security": "reality",
                    "realitySettings": {{
                        "dest": "example.com:443",
                        "serverNames": ["example.com"],
                        "privateKey": "{TEST_REALITY_PRIVATE_KEY}",
                        "shortIds": [""]
                        {seed_field}
                    }}
                }}
            }}]
        }}"#
    )
}

#[test]
fn reality_min_client_ver_default_matches_xray_core_af7eb68() {
    assert_eq!(DEFAULT_REALITY_MIN_CLIENT_VER, "26.3.27");
    assert_eq!(effective_reality_min_client_ver(None), "26.3.27");
    assert_eq!(
        effective_reality_min_client_ver(Some(String::new())),
        "26.3.27"
    );
    assert_eq!(
        effective_reality_min_client_ver(Some("1.8.0".to_string())),
        "1.8.0"
    );
    assert_eq!(
        effective_reality_min_client_ver(Some("0.0.0".to_string())),
        "0.0.0"
    );
}

#[test]
fn reality_runtime_without_min_client_ver_applies_xray_default() {
    let config: XrayConfig =
        serde_json::from_str(&vless_reality_config_json("tcp", None)).expect("parse");
    let runtime = first_reality_inbound_runtime(&config).expect("runtime");
    assert_eq!(
        runtime.min_client_ver.as_deref(),
        Some(DEFAULT_REALITY_MIN_CLIENT_VER)
    );
}

#[test]
fn unsupported_reality_transport_network_remains_explicit_error() {
    let err = validate_reality_transport_network(Some("ws")).unwrap_err();
    assert_eq!(err.kind(), std::io::ErrorKind::InvalidInput);
    assert!(err.to_string().contains("WebSocket"));
}

#[test]
fn unsupported_reality_transport_rejected_at_startup() {
    let config: rust_xray::config::XrayConfig =
        serde_json::from_str(&vless_reality_config_json("ws", None)).expect("parse");
    let err = first_reality_inbound_runtime(&config).unwrap_err();
    assert_eq!(err.kind(), std::io::ErrorKind::InvalidInput);
    assert!(err.to_string().contains("WebSocket"));
}

#[test]
fn configured_seed_must_select_hmac_plus_mldsa65_not_hmac_only() {
    let config: rust_xray::config::XrayConfig =
        serde_json::from_str(&vless_reality_config_json("tcp", Some(TEST_MLDSA65_SEED)))
            .expect("parse");
    let runtime = first_reality_inbound_runtime(&config).expect("runtime");
    assert!(runtime.mldsa65_seed.is_some());

    let mode = select_reality_certificate_patch_mode(
        runtime.mldsa65_seed.as_ref(),
        &[0x01, 0x02, 0x03],
        &[0x04, 0x05, 0x06],
    )
    .expect("patch mode");
    assert!(matches!(
        mode,
        RealityCertificatePatchMode::HmacPlusMldsa65 { .. }
    ));
}

#[test]
fn no_seed_config_stays_hmac_only_patch_mode() {
    let config: rust_xray::config::XrayConfig =
        serde_json::from_str(&vless_reality_config_json("tcp", None)).expect("parse");
    let runtime = first_reality_inbound_runtime(&config).expect("runtime");
    assert!(runtime.mldsa65_seed.is_none());

    let mode = select_reality_certificate_patch_mode(None, &[0x01], &[0x02]).expect("patch mode");
    assert!(matches!(mode, RealityCertificatePatchMode::HmacOnly));
}

#[test]
fn reality_x25519mlkem768_pre_auth_upstream_layout_vector() {
    use rust_xray::protocol::enums::NamedGroup;
    use rust_xray::protocol::structs::KeyShareEntry;
    use rust_xray::reality::{
        build_x25519mlkem768_client_key_share, find_reality_auth_x25519_public_key,
        MLKEM768_ENCAPSULATION_KEY_LEN, NAMED_GROUP_X25519MLKEM768,
        X25519_MLKEM768_CLIENT_KEY_SHARE_LEN, X25519_PUBLIC_KEY_LEN,
    };

    const IANA_GROUP: u16 = 4588;

    assert_eq!(IANA_GROUP, 0x11ec);
    assert_eq!(u16::from(NamedGroup::X25519MLKEM768), IANA_GROUP);
    assert_eq!(NamedGroup::from(0x11ec_u16), NamedGroup::X25519MLKEM768);
    assert_eq!(NamedGroup::from(4588_u16), NamedGroup::X25519MLKEM768);
    assert_eq!(IANA_GROUP.to_be_bytes(), [0x11, 0xec]);

    assert_eq!(NAMED_GROUP_X25519MLKEM768, IANA_GROUP);
    assert_eq!(X25519_PUBLIC_KEY_LEN, 32);
    assert_eq!(MLKEM768_ENCAPSULATION_KEY_LEN, 1184);
    assert_eq!(X25519_MLKEM768_CLIENT_KEY_SHARE_LEN, 1216);
    assert_eq!(
        X25519_MLKEM768_CLIENT_KEY_SHARE_LEN,
        MLKEM768_ENCAPSULATION_KEY_LEN + X25519_PUBLIC_KEY_LEN
    );

    let trailing_x25519: [u8; 32] = core::array::from_fn(|i| 0xD0 + i as u8);
    let hybrid_payload = build_x25519mlkem768_client_key_share(trailing_x25519);
    assert_eq!(hybrid_payload.len(), X25519_MLKEM768_CLIENT_KEY_SHARE_LEN);
    assert_eq!(
        &hybrid_payload[..MLKEM768_ENCAPSULATION_KEY_LEN],
        &vec![0u8; MLKEM768_ENCAPSULATION_KEY_LEN][..]
    );
    assert_eq!(
        &hybrid_payload[MLKEM768_ENCAPSULATION_KEY_LEN..],
        trailing_x25519.as_slice()
    );

    let entry = KeyShareEntry::new(NamedGroup::X25519MLKEM768, hybrid_payload.clone());
    assert_eq!(u16::from(entry.group()), IANA_GROUP);

    let extracted = find_reality_auth_x25519_public_key(std::slice::from_ref(&entry))
        .expect("valid hybrid REALITY auth carrier");
    assert_eq!(extracted.len(), X25519_PUBLIC_KEY_LEN);
    assert_eq!(extracted, trailing_x25519);
    assert_eq!(
        &hybrid_payload[MLKEM768_ENCAPSULATION_KEY_LEN..],
        extracted.as_slice()
    );

    // Upstream REALITY pre-auth: standalone X25519 pass runs before hybrid pass.
    let standalone: [u8; 32] = [0x5A; 32];
    let hybrid_tail: [u8; 32] = [0xA5; 32];
    assert_ne!(standalone, hybrid_tail);
    let shares = vec![
        KeyShareEntry::new(
            NamedGroup::X25519MLKEM768,
            build_x25519mlkem768_client_key_share(hybrid_tail),
        ),
        KeyShareEntry::new(NamedGroup::X25519, standalone.to_vec()),
    ];
    assert_eq!(
        find_reality_auth_x25519_public_key(&shares),
        Some(standalone)
    );
}

#[test]
fn proxy_v2_fixture_matches_vless_builder() {
    use rust_xray::vless::build_proxy_protocol_v2;

    const FIXTURE: &[u8] = include_bytes!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/tests/fixtures/fallback/proxy-v2-tcp4-127.0.0.1.bin"
    ));

    let header = build_proxy_protocol_v2(
        "127.0.0.1:12345".parse().expect("src"),
        "127.0.0.1:24443".parse().expect("dst"),
    )
    .expect("header");

    assert_eq!(header.as_slice(), FIXTURE);
}

#[test]
fn reality_target_server_hello_key_share_observation_vector() {
    use rust_xray::protocol::enums::NamedGroup;
    use rust_xray::reality::handshake::{extract_observed_server_hello, RealityDestHandshake};
    use rust_xray::reality::key_share::{
        NAMED_GROUP_X25519, NAMED_GROUP_X25519MLKEM768, X25519_MLKEM768_SERVER_KEY_SHARE_LEN,
        X25519_PUBLIC_KEY_LEN,
    };
    use rust_xray::tls::{
        parse_server_hello_key_share, TlsRecord, TlsRecordContentType, EXTENSION_KEY_SHARE,
        EXTENSION_SUPPORTED_VERSIONS,
    };

    const TLS13_VERSION: [u8; 2] = [0x03, 0x04];

    fn key_share_extension_body(group: u16, key_exchange: &[u8]) -> Vec<u8> {
        let mut body = Vec::with_capacity(4 + key_exchange.len());
        body.extend_from_slice(&group.to_be_bytes());
        body.extend_from_slice(&(key_exchange.len() as u16).to_be_bytes());
        body.extend_from_slice(key_exchange);
        body
    }

    fn server_hello_message(key_share_body: &[u8]) -> Vec<u8> {
        let cipher_suite = 0x1301u16;
        let mut extension_bytes = Vec::new();
        for (extension_type, data) in [
            (EXTENSION_SUPPORTED_VERSIONS, TLS13_VERSION.as_slice()),
            (EXTENSION_KEY_SHARE, key_share_body),
        ] {
            extension_bytes.extend_from_slice(&extension_type.to_be_bytes());
            extension_bytes.extend_from_slice(&(data.len() as u16).to_be_bytes());
            extension_bytes.extend_from_slice(data);
        }

        let mut body = Vec::new();
        body.extend_from_slice(&[0x03, 0x03]);
        body.extend_from_slice(&[0x11; 32]);
        body.push(0);
        body.extend_from_slice(&cipher_suite.to_be_bytes());
        body.push(0);
        body.extend_from_slice(&(extension_bytes.len() as u16).to_be_bytes());
        body.extend_from_slice(&extension_bytes);

        let mut message = Vec::with_capacity(4 + body.len());
        message.push(0x02);
        message.extend_from_slice(&(body.len() as u32).to_be_bytes()[1..]);
        message.extend_from_slice(&body);
        message
    }

    fn dest_handshake(message: &[u8]) -> RealityDestHandshake {
        let mut raw = Vec::with_capacity(5 + message.len());
        raw.push(0x16);
        raw.extend_from_slice(&[0x03, 0x03]);
        raw.extend_from_slice(&(message.len() as u16).to_be_bytes());
        raw.extend_from_slice(message);
        RealityDestHandshake::try_from_records(
            raw.clone(),
            vec![TlsRecord {
                content_type: TlsRecordContentType::Handshake,
                legacy_version: [0x03, 0x03],
                payload: message.to_vec(),
                raw,
            }],
        )
        .expect("valid single-record dest handshake")
    }

    let x25519_body = key_share_extension_body(NAMED_GROUP_X25519, &[0xB1; X25519_PUBLIC_KEY_LEN]);
    assert_eq!(&x25519_body[..2], &[0x00, 0x1d]);
    assert_eq!(&x25519_body[2..4], &[0x00, 0x20]);
    assert_eq!(x25519_body.len(), 4 + X25519_PUBLIC_KEY_LEN);

    let x25519_observed =
        extract_observed_server_hello(&dest_handshake(&server_hello_message(&x25519_body)))
            .expect("target X25519 observation");
    assert_eq!(x25519_observed.selected_key_share_group, NamedGroup::X25519);

    let hybrid_body = key_share_extension_body(
        NAMED_GROUP_X25519MLKEM768,
        &vec![0xA5; X25519_MLKEM768_SERVER_KEY_SHARE_LEN],
    );
    assert_eq!(&hybrid_body[..2], &[0x11, 0xec]);
    assert_eq!(&hybrid_body[2..4], &[0x04, 0x60]);
    assert_eq!(hybrid_body.len(), 4 + X25519_MLKEM768_SERVER_KEY_SHARE_LEN);

    let hybrid_observed =
        extract_observed_server_hello(&dest_handshake(&server_hello_message(&hybrid_body)))
            .expect("target hybrid observation");
    assert_eq!(
        hybrid_observed.selected_key_share_group,
        NamedGroup::X25519MLKEM768
    );

    let parsed = parse_server_hello_key_share(
        hybrid_observed
            .server_hello
            .get_extension(EXTENSION_KEY_SHARE)
            .expect("key_share"),
    )
    .expect("parse hybrid key_share");
    assert_eq!(parsed.group, NAMED_GROUP_X25519MLKEM768);
    assert_eq!(
        parsed.key_exchange.len(),
        X25519_MLKEM768_SERVER_KEY_SHARE_LEN
    );
}
