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
