use prost::Message;

use crate::runtime::{
    encode_inbound_handler_config, encode_outbound_handler_config, OutboundProtocol,
    VLESS_INBOUND_CONFIG_TYPE,
};
use crate::vless::encryption::VlessDecryption;
use crate::vless::user_manager::ManagedUser;

#[test]
fn encode_vless_inbound_uses_canonical_typed_message_types() {
    let inbound = crate::config::VlessRealityInbound {
        tag: Some("test-in".to_string()),
        listen_addr: "127.0.0.1:8443".to_string(),
        users: vec![],
        transport: crate::config::InboundTransportConfig::RawTcp,
        reality: crate::config::RealityServerConfig {
            dest_addr: "www.example.com:443".to_string(),
            private_key: "MKVGVTTvyEyI7hpl7vP7WKtRXLhH0JieCMHgFdn6A3s".to_string(),
            server_names: vec!["www.example.com".to_string()],
            short_ids: vec![vec![0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef]],
            max_time_diff: 0,
            min_client_ver: None,
            max_client_ver: None,
            show: false,
            mldsa65_seed: None,
            decryption: VlessDecryption::None,
            dest_xver: 0,
            dest_transport: crate::reality::RealityDestTransport::Tcp,
            limit_fallback_upload: Default::default(),
            limit_fallback_download: Default::default(),
        },
        fallbacks: vec![],
        sniffing_enabled: false,
    };
    let config = encode_inbound_handler_config(&inbound, &[]).expect("encode inbound");
    assert_eq!(config.tag, "test-in");
    assert_eq!(
        config
            .proxy_settings
            .as_ref()
            .map(|msg| msg.r#type.as_str()),
        Some(VLESS_INBOUND_CONFIG_TYPE)
    );
}

#[test]
fn encode_freedom_outbound_round_trip_tag() {
    let config = encode_outbound_handler_config("dynamic-direct", OutboundProtocol::Freedom);
    assert_eq!(config.tag, "dynamic-direct");
    assert!(config.proxy_settings.is_some());
}

#[test]
fn managed_user_proto_preserves_email_and_flow() {
    let user = ManagedUser {
        id: uuid::Uuid::parse_str("11111111-1111-1111-1111-111111111111").unwrap(),
        email: "user@example.test".to_string(),
        flow: Some("xtls-rprx-vision".to_string()),
        level: Some(1),
        testseed: crate::vless::UPSTREAM_DEFAULT_TESTSEED,
        expiry_secs: None,
    };
    let inbound = crate::config::VlessRealityInbound {
        tag: Some("in".to_string()),
        listen_addr: "127.0.0.1:8443".to_string(),
        users: vec![],
        transport: crate::config::InboundTransportConfig::RawTcp,
        reality: crate::config::RealityServerConfig {
            dest_addr: "www.example.com:443".to_string(),
            private_key: "MKVGVTTvyEyI7hpl7vP7WKtRXLhH0JieCMHgFdn6A3s".to_string(),
            server_names: vec!["www.example.com".to_string()],
            short_ids: vec![vec![0x01]],
            max_time_diff: 0,
            min_client_ver: None,
            max_client_ver: None,
            show: false,
            mldsa65_seed: None,
            decryption: VlessDecryption::None,
            dest_xver: 0,
            dest_transport: crate::reality::RealityDestTransport::Tcp,
            limit_fallback_upload: Default::default(),
            limit_fallback_download: Default::default(),
        },
        fallbacks: vec![],
        sniffing_enabled: false,
    };
    let config =
        encode_inbound_handler_config(&inbound, std::slice::from_ref(&user)).expect("encode");
    let proxy = config.proxy_settings.expect("proxy");
    let vless = crate::api::proto::proxy::vless::inbound::Config::decode(proxy.value.as_slice())
        .expect("decode vless inbound");
    assert_eq!(vless.users.len(), 1);
    assert_eq!(vless.users[0].email, "user@example.test");
}
