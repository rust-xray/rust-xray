use std::fmt::Write as _;

use tracing::info;

use crate::reality::stages;

pub const MAX_RELAY_PREFIX_BYTES: usize = 16;

pub fn debug_relay_prefix_enabled() -> bool {
    std::env::var("RUST_XRAY_DEBUG_RELAY_PREFIX")
        .as_deref()
        .ok()
        .is_some_and(|value| value == "1")
}

pub fn relay_prefix_hex(bytes: &[u8]) -> String {
    let preview_len = bytes.len().min(MAX_RELAY_PREFIX_BYTES);
    let mut out = String::with_capacity(preview_len * 2);
    for byte in &bytes[..preview_len] {
        let _ = write!(out, "{byte:02x}");
    }
    out
}

pub fn log_vless_response_header_prefix(header: &[u8], version: u8, header_len: usize) {
    if !debug_relay_prefix_enabled() {
        return;
    }

    info!(
        stage = stages::VLESS_RESPONSE_HEADER_SENT,
        version,
        header_len,
        header_hex = relay_prefix_hex(header),
        debug_relay_prefix_enabled = true,
        write_direction = "client_stream",
        "sent VLESS response header"
    );
}

pub fn log_outbound_stream_first_write(payload: &[u8]) {
    if !debug_relay_prefix_enabled() || payload.is_empty() {
        return;
    }

    info!(
        stage = stages::VLESS_OUTBOUND_STREAM_FIRST_WRITE,
        prefix_hex = relay_prefix_hex(payload),
        len = payload.len(),
        debug_relay_prefix_enabled = true,
        write_direction = "outbound_stream",
        "first write to outbound stream"
    );
}

pub fn log_outbound_to_client_first_write(payload: &[u8], written_len: usize) {
    if !debug_relay_prefix_enabled() || written_len == 0 {
        return;
    }

    info!(
        stage = stages::VLESS_OUTBOUND_TO_CLIENT_FIRST_WRITE,
        prefix_hex = relay_prefix_hex(&payload[..written_len.min(payload.len())]),
        len = written_len,
        debug_relay_prefix_enabled = true,
        write_direction = "client_stream",
        "first outbound-to-client relay write"
    );
}

pub fn log_vless_request_diagnostics(
    version: u8,
    additional_info_len: usize,
    raw_initial_payload: &[u8],
    forward_initial_payload: &[u8],
) {
    if debug_relay_prefix_enabled() {
        info!(
            stage = stages::VLESS_RAW_PLAINTEXT,
            raw_plaintext_len = raw_initial_payload.len(),
            raw_plaintext_prefix_hex = relay_prefix_hex(raw_initial_payload),
            debug_relay_prefix_enabled = true,
            "VLESS raw decrypted initial plaintext before outbound forwarding prep"
        );
        info!(
            stage = stages::VLESS_REQUEST_PARSED,
            version,
            additional_info_len,
            initial_payload_len = forward_initial_payload.len(),
            initial_payload_prefix_hex = relay_prefix_hex(forward_initial_payload),
            debug_relay_prefix_enabled = true,
            "parsed VLESS request header"
        );
        return;
    }

    info!(
        stage = stages::VLESS_REQUEST_PARSED,
        version,
        additional_info_len,
        initial_payload_len = forward_initial_payload.len(),
        "parsed VLESS request header"
    );
}

#[cfg(test)]
pub(crate) fn forward_initial_payload_prefix_hex_for_log(payload: &[u8]) -> Option<String> {
    debug_relay_prefix_enabled().then(|| relay_prefix_hex(payload))
}

#[cfg(test)]
pub(crate) fn initial_payload_prefix_hex_for_log(payload: &[u8]) -> Option<String> {
    forward_initial_payload_prefix_hex_for_log(payload)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex;

    static ENV_LOCK: Mutex<()> = Mutex::new(());

    fn with_relay_prefix_env<F>(value: Option<&str>, f: F)
    where
        F: FnOnce(),
    {
        let key = "RUST_XRAY_DEBUG_RELAY_PREFIX";
        let _guard = ENV_LOCK
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let previous = std::env::var(key).ok();
        match value {
            Some(value) => std::env::set_var(key, value),
            None => std::env::remove_var(key),
        }
        f();
        match previous {
            Some(value) => std::env::set_var(key, value),
            None => std::env::remove_var(key),
        }
    }

    #[test]
    fn relay_prefix_hex_empty() {
        assert_eq!(relay_prefix_hex(&[]), "");
    }

    #[test]
    fn relay_prefix_hex_truncates_to_16_bytes() {
        let bytes: Vec<u8> = (0..32).collect();
        assert_eq!(relay_prefix_hex(&bytes).len(), MAX_RELAY_PREFIX_BYTES * 2);
        assert_eq!(relay_prefix_hex(&bytes), "000102030405060708090a0b0c0d0e0f");
    }

    #[test]
    fn hex_prefix_helper_caps_at_16_bytes() {
        let bytes: Vec<u8> = (0x11..0x11 + 32).collect();
        let prefix = relay_prefix_hex(&bytes);
        assert_eq!(prefix.len(), MAX_RELAY_PREFIX_BYTES * 2);
    }

    #[test]
    fn initial_payload_prefix_for_log_absent_without_env() {
        with_relay_prefix_env(None, || {
            assert!(initial_payload_prefix_hex_for_log(&[0x11; 16]).is_none());
        });
    }

    #[test]
    fn initial_payload_prefix_for_log_present_with_env() {
        with_relay_prefix_env(Some("1"), || {
            let payload = [0x16, 0x03, 0x01, 0x00];
            assert_eq!(
                initial_payload_prefix_hex_for_log(&payload).as_deref(),
                Some("16030100")
            );

            let long_payload: Vec<u8> = (0..32).collect();
            let prefix = initial_payload_prefix_hex_for_log(&long_payload).expect("prefix");
            assert_eq!(prefix.len(), MAX_RELAY_PREFIX_BYTES * 2);
        });
    }

    #[test]
    fn debug_relay_prefix_enabled_requires_exact_one() {
        with_relay_prefix_env(Some("1"), || {
            assert!(debug_relay_prefix_enabled());
            std::env::set_var("RUST_XRAY_DEBUG_RELAY_PREFIX", "true");
            assert!(!debug_relay_prefix_enabled());
        });
    }

    #[test]
    fn forward_initial_payload_prefix_matches_tls_client_hello_without_vision() {
        use crate::vless::protocol::{
            build_vless_domain_address, build_vless_request_wire, parse_vless_request,
        };

        let user_id = [0x11; 16];
        let tls_client_hello = [0x16, 0x03, 0x01, 0x06, 0x1e, 0x01, 0x00];
        let mut packet = build_vless_request_wire(
            0,
            &user_id,
            &[],
            0x01,
            443,
            &build_vless_domain_address("example.com"),
        );
        packet.extend_from_slice(&tls_client_hello);

        let (request, consumed) = parse_vless_request(&packet).unwrap();
        let forward_initial_payload = &packet[consumed..];

        assert_eq!(request.version, 0);
        assert!(forward_initial_payload.starts_with(&[0x16, 0x03]));

        with_relay_prefix_env(Some("1"), || {
            assert!(debug_relay_prefix_enabled());
            assert_eq!(
                relay_prefix_hex(forward_initial_payload),
                forward_initial_payload_prefix_hex_for_log(forward_initial_payload)
                    .expect("debug relay prefix enabled")
            );
        });
    }

    #[test]
    fn forward_initial_payload_prefix_matches_tls_after_vision_unpad_not_uuid() {
        use crate::vless::protocol::{
            build_vless_domain_address, build_vless_request_wire, parse_vless_request,
        };
        use crate::vless::vision::{wrap_vision_uplink_block, TrafficState};

        let user_id = [0x11; 16];
        let tls_client_hello = [0x16, 0x03, 0x01, 0x06, 0x1e, 0x01, 0x00];
        let raw_initial_payload = wrap_vision_uplink_block(&user_id, &tls_client_hello);

        let mut packet = build_vless_request_wire(
            0,
            &user_id,
            &[],
            0x01,
            443,
            &build_vless_domain_address("example.com"),
        );
        packet.extend_from_slice(&raw_initial_payload);

        let (_request, consumed) = parse_vless_request(&packet).unwrap();
        let parsed_raw_initial_payload = &packet[consumed..];
        assert!(parsed_raw_initial_payload.starts_with(&user_id));

        let mut state = TrafficState::new(user_id);
        let forward_initial_payload = state
            .unpad_uplink_chunk(parsed_raw_initial_payload)
            .unwrap();
        assert!(forward_initial_payload.starts_with(&[0x16, 0x03]));
        assert_ne!(
            &forward_initial_payload[..16.min(forward_initial_payload.len())],
            user_id
        );

        with_relay_prefix_env(Some("1"), || {
            assert_eq!(
                relay_prefix_hex(parsed_raw_initial_payload),
                "11111111111111111111111111111111"
            );
            assert_eq!(
                forward_initial_payload_prefix_hex_for_log(&forward_initial_payload).as_deref(),
                Some(relay_prefix_hex(&forward_initial_payload).as_str())
            );
        });
    }
}
