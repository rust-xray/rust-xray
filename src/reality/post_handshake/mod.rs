//! REALITY post-handshake record-length detection infrastructure.

pub mod alpn;
pub mod cache;
pub mod emission;
pub mod parser;
pub mod probe;
mod tls_client;
mod validation;

pub use alpn::RealityAlpnProfile;
pub use cache::{PostHandshakeProbeCache, PostHandshakeProbeKey, PostHandshakeProbeState};
pub use emission::{
    emit_post_handshake_camouflage_records, post_handshake_probe_key,
    resolve_post_handshake_wire_lengths, POST_HANDSHAKE_CACHE_WAIT_TIMEOUT,
};
pub use parser::{
    parse_post_handshake_application_record_lengths, post_handshake_parse_error,
    PostHandshakeParseError,
};
pub use validation::{is_valid_post_handshake_wire_length, sanitize_post_handshake_wire_lengths};

#[cfg(test)]
#[path = "../../../tests/unit/reality/post_handshake/parser.rs"]
mod parser_tests;
