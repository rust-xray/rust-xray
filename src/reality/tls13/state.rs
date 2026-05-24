use std::fmt;
use std::io::{Error, ErrorKind};

use crate::reality::handshake::RealityObservedServerHello;
use crate::reality::RealityAccepted;

use super::cipher_suite::{tls13_cipher_suite, Tls13CipherSuite};
use super::transcript::TranscriptHash;

const HANDSHAKE_NOT_IMPLEMENTED_MSG: &str =
    "REALITY TLS 1.3 server state machine is not implemented yet";

/// REALITY accepted-path TLS 1.3 server handshake state container.
///
/// Upstream equivalent: Go `serverHandshakeStateTLS13` in XTLS/REALITY.
pub struct RealityTls13ServerState {
    pub accepted: RealityAccepted,
    pub observed_server_hello: RealityObservedServerHello,
    pub suite: Tls13CipherSuite,
    pub transcript: TranscriptHash,
}

struct ObservedServerHelloDebug<'a>(&'a RealityObservedServerHello);

impl fmt::Debug for ObservedServerHelloDebug<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("RealityObservedServerHello")
            .field(
                "cipher_suite",
                &format!("0x{:04x}", self.0.server_hello.cipher_suite),
            )
            .field(
                "raw_handshake_message_len",
                &self.0.raw_handshake_message.len(),
            )
            .finish()
    }
}

impl fmt::Debug for RealityTls13ServerState {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("RealityTls13ServerState")
            .field("sni", &self.accepted.sni)
            .field("client_version", &self.accepted.client.client_version)
            .field("suite", &self.suite.name)
            .field("transcript", &self.transcript)
            .field(
                "observed_server_hello",
                &ObservedServerHelloDebug(&self.observed_server_hello),
            )
            .finish()
    }
}

impl RealityTls13ServerState {
    pub fn new(
        accepted: RealityAccepted,
        observed_server_hello: RealityObservedServerHello,
    ) -> std::io::Result<Self> {
        let suite = tls13_cipher_suite(observed_server_hello.server_hello.cipher_suite)
            .ok_or_else(|| {
                Error::new(
                    ErrorKind::Unsupported,
                    format!(
                        "unsupported destination ServerHello cipher suite: 0x{:04x}",
                        observed_server_hello.server_hello.cipher_suite
                    ),
                )
            })?;
        let transcript = TranscriptHash::new(suite.hash);

        Ok(Self {
            accepted,
            observed_server_hello,
            suite,
            transcript,
        })
    }

    pub fn handshake_not_implemented(&self) -> Error {
        Error::new(ErrorKind::Unsupported, HANDSHAKE_NOT_IMPLEMENTED_MSG)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::reality::auth::RealityAuthResult;
    use crate::reality::handshake::{
        extract_observed_server_hello, RealityDestHandshake, RealityObservedServerHello,
    };
    use crate::reality::session::RealityClientAuth;
    use crate::reality::tls13::cipher_suite::TLS_AES_128_GCM_SHA256;
    use crate::reality::tls13::transcript::Tls13HashAlgorithm;
    use crate::tls::{
        TlsRecord, TlsRecordContentType, EXTENSION_KEY_SHARE, EXTENSION_SUPPORTED_VERSIONS,
        NAMED_GROUP_X25519,
    };

    const TLS_RECORD_LEGACY_VERSION: [u8; 2] = [0x03, 0x03];
    const TLS13_VERSION: [u8; 2] = [0x03, 0x04];
    const X25519_KEY_EXCHANGE_LEN: usize = 32;

    fn build_server_hello_handshake_message(
        cipher_suite: u16,
        extensions: &[(u16, &[u8])],
    ) -> Vec<u8> {
        let random = [0x11; 32];
        let mut body = Vec::new();
        body.extend_from_slice(&TLS_RECORD_LEGACY_VERSION);
        body.extend_from_slice(&random);
        body.push(0);
        body.extend_from_slice(&cipher_suite.to_be_bytes());
        body.push(0);

        let mut extension_bytes = Vec::new();
        for (extension_type, data) in extensions {
            extension_bytes.extend_from_slice(&extension_type.to_be_bytes());
            extension_bytes.extend_from_slice(&(data.len() as u16).to_be_bytes());
            extension_bytes.extend_from_slice(data);
        }
        body.extend_from_slice(&(extension_bytes.len() as u16).to_be_bytes());
        body.extend_from_slice(&extension_bytes);

        let mut message = Vec::with_capacity(4 + body.len());
        message.push(0x02);
        message.extend_from_slice(&(body.len() as u32).to_be_bytes()[1..]);
        message.extend_from_slice(&body);
        message
    }

    fn x25519_key_share_bytes(key_exchange: &[u8]) -> Vec<u8> {
        let mut data = Vec::new();
        data.extend_from_slice(&NAMED_GROUP_X25519.to_be_bytes());
        data.extend_from_slice(&(key_exchange.len() as u16).to_be_bytes());
        data.extend_from_slice(key_exchange);
        data
    }

    fn valid_observed_server_hello(cipher_suite: u16) -> RealityObservedServerHello {
        let message = build_server_hello_handshake_message(
            cipher_suite,
            &[
                (EXTENSION_SUPPORTED_VERSIONS, &TLS13_VERSION),
                (
                    EXTENSION_KEY_SHARE,
                    &x25519_key_share_bytes(&[0x22; X25519_KEY_EXCHANGE_LEN]),
                ),
            ],
        );
        let mut raw = Vec::with_capacity(5 + message.len());
        raw.push(0x16);
        raw.extend_from_slice(&TLS_RECORD_LEGACY_VERSION);
        raw.extend_from_slice(&(message.len() as u16).to_be_bytes());
        raw.extend_from_slice(&message);

        let dest_handshake = RealityDestHandshake {
            raw_server_bytes: raw.clone(),
            records: vec![TlsRecord {
                content_type: TlsRecordContentType::Handshake,
                legacy_version: TLS_RECORD_LEGACY_VERSION,
                payload: message.clone(),
                raw,
            }],
        };

        extract_observed_server_hello(&dest_handshake).expect("valid observed ServerHello")
    }

    fn sample_accepted() -> RealityAccepted {
        RealityAccepted {
            auth: RealityAuthResult {
                auth_key: [0xde; 32],
                client_public_key: [0xad; 32],
            },
            client: RealityClientAuth {
                client_version: [1, 8, 0, 0],
                unix_time: 1_700_000_000,
                short_id: [0xAB, 0xCD, 0, 0, 0, 0, 0, 0],
            },
            sni: Some("example.com".to_string()),
        }
    }

    #[test]
    fn new_works_with_observed_server_hello_cipher_suite_0x1301() {
        let observed = valid_observed_server_hello(TLS_AES_128_GCM_SHA256);
        let state = RealityTls13ServerState::new(sample_accepted(), observed).expect("valid state");

        assert_eq!(state.suite.id, TLS_AES_128_GCM_SHA256);
        assert_eq!(state.suite.name, "TLS_AES_128_GCM_SHA256");
        assert_eq!(state.transcript.algorithm(), Tls13HashAlgorithm::Sha256);
        assert_eq!(state.accepted.sni, Some("example.com".to_string()));
    }

    #[test]
    fn new_rejects_unknown_cipher_suite() {
        let observed = valid_observed_server_hello(0x1304);
        let err = RealityTls13ServerState::new(sample_accepted(), observed).unwrap_err();

        assert_eq!(err.kind(), ErrorKind::Unsupported);
        assert!(err.to_string().contains("0x1304"));
    }

    #[test]
    fn debug_does_not_include_auth_key_or_raw_handshake_bytes() {
        let observed = valid_observed_server_hello(TLS_AES_128_GCM_SHA256);
        let state = RealityTls13ServerState::new(sample_accepted(), observed.clone()).unwrap();
        let debug = format!("{state:?}");

        assert!(!debug.contains("auth_key"));
        assert!(!debug.contains("0xde"));
        assert!(!debug.contains(&format!("{:?}", observed.raw_handshake_message)));
        assert!(debug.contains("TLS_AES_128_GCM_SHA256"));
        assert!(debug.contains("example.com"));
        assert!(debug.contains("[1, 8, 0, 0]"));
        assert!(debug.contains("raw_handshake_message_len"));
    }

    #[test]
    fn handshake_not_implemented_returns_unsupported() {
        let observed = valid_observed_server_hello(TLS_AES_128_GCM_SHA256);
        let state = RealityTls13ServerState::new(sample_accepted(), observed).unwrap();
        let err = state.handshake_not_implemented();

        assert_eq!(err.kind(), ErrorKind::Unsupported);
        assert_eq!(err.to_string(), HANDSHAKE_NOT_IMPLEMENTED_MSG);
    }
}
