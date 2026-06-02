//! Stage names and helpers for REALITY accepted-path tracing and errors.

use std::io::Error;

/// Accepted-path failure classification for error messages.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RealityAcceptedStage {
    DestConnect,
    DestServerHello,
    Tls13State,
    ServerHello,
    Transcript,
    HandshakeSecrets,
    ServerHandshakeRecords,
    ClientFinishedRead,
    ClientFinishedVerify,
    ApplicationSecrets,
    ApplicationStream,
    Vless,
}

impl RealityAcceptedStage {
    pub fn name(self) -> &'static str {
        match self {
            Self::DestConnect => "DestConnect",
            Self::DestServerHello => "DestServerHello",
            Self::Tls13State => "Tls13State",
            Self::ServerHello => "ServerHello",
            Self::Transcript => "Transcript",
            Self::HandshakeSecrets => "HandshakeSecrets",
            Self::ServerHandshakeRecords => "ServerHandshakeRecords",
            Self::ClientFinishedRead => "ClientFinishedRead",
            Self::ClientFinishedVerify => "ClientFinishedVerify",
            Self::ApplicationSecrets => "ApplicationSecrets",
            Self::ApplicationStream => "ApplicationStream",
            Self::Vless => "Vless",
        }
    }
}

pub const ACCEPTED_START: &str = "reality.accepted.start";
pub const DEST_CONNECT_START: &str = "reality.dest.connect.start";
pub const DEST_CONNECT_OK: &str = "reality.dest.connect.ok";
pub const DEST_SERVER_HELLO_OBSERVED: &str = "reality.dest.server_hello.observed";
pub const TLS13_STATE_CREATED: &str = "reality.tls13.state.created";
pub const TLS13_SERVER_HELLO_GENERATED: &str = "reality.tls13.server_hello.generated";
pub const TLS13_TRANSCRIPT_CLIENT_SERVER_HELLO_UPDATED: &str =
    "reality.tls13.transcript.client_server_hello.updated";
pub const TLS13_HANDSHAKE_SECRETS_DERIVED: &str = "reality.tls13.handshake_secrets.derived";
pub const TLS13_SERVER_ENCRYPTED_HANDSHAKE_BUILT: &str =
    "reality.tls13.server_encrypted_handshake.built";
pub const TLS13_SERVER_ENCRYPTED_HANDSHAKE_SENT: &str =
    "reality.tls13.server_encrypted_handshake.sent";
pub const TLS13_CLIENT_FINISHED_READ: &str = "reality.tls13.client_finished.read";
pub const TLS13_CLIENT_FINISHED_VERIFIED: &str = "reality.tls13.client_finished.verified";
pub const TLS13_APPLICATION_SECRETS_DERIVED: &str = "reality.tls13.application_secrets.derived";
pub const TLS13_APPLICATION_STREAM_READY: &str = "reality.tls13.application_stream.ready";
pub const TLS13_APPLICATION_STREAM_DECRYPT: &str = "reality.tls13.application_stream.decrypt";
pub const TLS13_APPLICATION_STREAM_RECORD: &str = "reality.tls13.application_stream.record";
pub const TLS13_APPLICATION_STREAM_ENCRYPT: &str = "reality.tls13.application_stream.encrypt";
pub const TLS13_APPLICATION_STREAM_FLUSH: &str = "reality.tls13.application_stream.flush";
pub const TLS13_APPLICATION_STREAM_SPLIT: &str = "reality.tls13.application_stream.split";
pub const TLS13_APPLICATION_STREAM_KEY_UPDATE: &str = "reality.tls13.application_stream.key_update";
pub const TLS13_APPLICATION_STREAM_ALERT: &str = "reality.tls13.application_stream.alert";
pub const TLS13_APPLICATION_STREAM_SHUTDOWN: &str = "reality.tls13.application_stream.shutdown";
pub const VLESS_START: &str = "reality.vless.start";
pub const VLESS_RAW_PLAINTEXT: &str = "reality.vless.raw_plaintext";
pub const VLESS_REQUEST_PARSED: &str = "reality.vless.request.parsed";
pub const VLESS_AUTH_OK: &str = "reality.vless.auth.ok";
pub const VLESS_OUTBOUND_CONNECTED: &str = "reality.vless.outbound.connected";
pub const VLESS_RESPONSE_HEADER_SENT: &str = "reality.vless.response_header.sent";
pub const VLESS_INITIAL_PAYLOAD_FORWARDED: &str = "reality.vless.initial_payload.forwarded";
pub const VLESS_OUTBOUND_STREAM_FIRST_WRITE: &str = "reality.vless.outbound_stream.first_write";
pub const VLESS_OUTBOUND_TO_CLIENT_FIRST_WRITE: &str =
    "reality.vless.outbound_to_client.first_write";
pub const VLESS_RELAY_STARTED: &str = "reality.vless.relay.started";
pub const VLESS_RELAY_DONE: &str = "reality.vless.relay.done";

pub fn stage_error(stage: RealityAcceptedStage, source: impl Into<Error>) -> Error {
    let source = source.into();
    Error::new(
        source.kind(),
        format!("REALITY accepted stage {} failed: {source}", stage.name()),
    )
}

#[cfg(test)]
#[path = "../../tests/unit/reality/stages.rs"]
mod tests;
