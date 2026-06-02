use std::fmt::Write as _;

use tracing::{debug, trace};

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

    trace!(
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

    trace!(
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

    trace!(
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
        trace!(
            stage = stages::VLESS_RAW_PLAINTEXT,
            raw_plaintext_len = raw_initial_payload.len(),
            raw_plaintext_prefix_hex = relay_prefix_hex(raw_initial_payload),
            debug_relay_prefix_enabled = true,
            "VLESS raw decrypted initial plaintext before outbound forwarding prep"
        );
        trace!(
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

    debug!(
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
#[path = "../../tests/unit/vless/relay_debug.rs"]
mod tests;
