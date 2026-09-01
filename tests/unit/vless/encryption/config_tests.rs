use std::time::Duration;

use base64::Engine;

use crate::vless::encryption::{
    parse_inbound_decryption, parse_outbound_encryption,
    validate_inbound_decryption_with_fallbacks, ClientHandshakeMode, TicketLifetimeRange,
    VlessDecryption, XorMode,
};
use crate::vless::FallbackConfig;

fn b64(data: &[u8]) -> String {
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(data)
}

fn sample_x25519_key_token() -> String {
    b64(&[0xAB; 32])
}

fn sample_mlkem_seed_token() -> String {
    b64(&(0u8..64).collect::<Vec<_>>())
}

#[test]
fn none_is_valid() {
    let parsed = parse_inbound_decryption("none").expect("none");
    assert!(matches!(parsed, VlessDecryption::None));
}

#[test]
fn empty_decryption_is_rejected() {
    let err = parse_inbound_decryption("").unwrap_err();
    assert!(err.to_string().contains("decryption"));
}

#[test]
fn missing_decryption_rejected_by_validator() {
    let err = validate_inbound_decryption_with_fallbacks(None, false).unwrap_err();
    assert!(err.to_string().contains("decryption"));
}

#[test]
fn unknown_scheme_is_invalid() {
    let err = parse_inbound_decryption("auto").unwrap_err();
    assert!(err.to_string().contains("unsupported") || err.to_string().contains("malformed"));
}

#[test]
fn native_inbound_config_parses() {
    let raw = format!(
        "mlkem768x25519plus.native.600s.{}",
        sample_x25519_key_token()
    );
    let parsed = parse_inbound_decryption(&raw).expect("native inbound");
    match parsed {
        VlessDecryption::Mlkem768X25519Plus { config, .. } => {
            assert_eq!(config.xor_mode, XorMode::Native);
            assert_eq!(
                config.ticket_lifetime,
                TicketLifetimeRange {
                    min_secs: 600,
                    max_secs: 0,
                }
            );
            assert_eq!(config.nfs_keys.len(), 1);
        }
        _ => panic!("expected encrypted config"),
    }
}

#[test]
fn xorpub_and_random_modes_parse() {
    for mode in ["xorpub", "random"] {
        let raw = format!(
            "mlkem768x25519plus.{mode}.600-900s.{}",
            sample_mlkem_seed_token()
        );
        parse_inbound_decryption(&raw).expect(mode);
    }
}

#[test]
fn outbound_zero_rtt_and_one_rtt_parse() {
    let key = sample_x25519_key_token();
    let zero = format!("mlkem768x25519plus.native.0rtt.{key}");
    let one = format!("mlkem768x25519plus.native.1rtt.{key}");
    match parse_outbound_encryption(&zero).expect("0rtt") {
        crate::vless::encryption::VlessEncryption::Mlkem768X25519Plus(config) => {
            assert_eq!(config.handshake_mode, ClientHandshakeMode::ZeroRtt);
        }
        _ => panic!("expected outbound config"),
    }
    match parse_outbound_encryption(&one).expect("1rtt") {
        crate::vless::encryption::VlessEncryption::Mlkem768X25519Plus(config) => {
            assert_eq!(config.handshake_mode, ClientHandshakeMode::OneRtt);
        }
        _ => panic!("expected outbound config"),
    }
}

#[test]
fn invalid_mode_rejected() {
    let raw = format!(
        "mlkem768x25519plus.invalid-mode.600s.{}",
        sample_x25519_key_token()
    );
    assert!(parse_inbound_decryption(&raw).is_err());
}

#[test]
fn invalid_key_length_rejected() {
    let raw = format!("mlkem768x25519plus.native.600s.{}", b64(&[1u8; 17]));
    assert!(parse_inbound_decryption(&raw).is_err());
}

#[test]
fn invalid_base64_rejected() {
    let raw = "mlkem768x25519plus.native.600s.not!!!base64";
    assert!(parse_inbound_decryption(&raw).is_err());
}

#[test]
fn none_with_fallbacks_is_valid() {
    let fallbacks = vec![FallbackConfig {
        name: None,
        alpn: None,
        path: None,
        dest: crate::vless::FallbackDest {
            addr: "127.0.0.1:8443".to_string(),
        },
        xver: 0,
    }];
    let parsed = validate_inbound_decryption_with_fallbacks(Some("none"), !fallbacks.is_empty())
        .expect("ok");
    assert!(parsed.is_none());
}

#[test]
fn encryption_with_fallbacks_is_invalid() {
    let raw = format!(
        "mlkem768x25519plus.native.600s.{}",
        sample_x25519_key_token()
    );
    let err = validate_inbound_decryption_with_fallbacks(Some(&raw), true).unwrap_err();
    assert!(err.to_string().contains("fallbacks"));
}

#[test]
fn encryption_without_fallbacks_is_valid() {
    let raw = format!(
        "mlkem768x25519plus.native.600s.{}",
        sample_x25519_key_token()
    );
    validate_inbound_decryption_with_fallbacks(Some(&raw), false).expect("valid");
}

#[test]
fn padding_profile_parses() {
    let raw = format!(
        "mlkem768x25519plus.native.600s.100-111-1111.50-0-3333.{}",
        sample_x25519_key_token()
    );
    let parsed = parse_inbound_decryption(&raw).expect("padding");
    match parsed {
        VlessDecryption::Mlkem768X25519Plus { config, .. } => {
            assert_eq!(config.padding.length_ranges.len(), 1);
            assert_eq!(config.padding.gap_ranges.len(), 1);
        }
        _ => panic!("expected encrypted config"),
    }
}

#[test]
fn ticket_lifetime_range_sampling() {
    let range = TicketLifetimeRange {
        min_secs: 600,
        max_secs: 900,
    };
    assert_eq!(range.sample_secs(0), Duration::from_secs(600));
    assert_eq!(range.sample_secs(100), Duration::from_secs(900));
}
