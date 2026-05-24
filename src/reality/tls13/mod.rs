//! TLS 1.3 server handshake skeleton for the REALITY accepted path.
//!
//! Cryptography and message generation are intentionally **not** implemented here
//! yet. This module defines the structure for porting upstream XTLS/REALITY in
//! smaller steps.

mod cipher_suite;
mod key_schedule;
mod messages;
mod state;
mod transcript;

pub use cipher_suite::{
    tls13_cipher_suite, Tls13AeadAlgorithm, Tls13CipherSuite, TLS_AES_128_GCM_SHA256,
    TLS_AES_256_GCM_SHA384, TLS_CHACHA20_POLY1305_SHA256,
};

pub use key_schedule::{
    derive_finished_key, derive_secret_sha256, derive_secret_sha384, derive_traffic_key, hash_len,
    hkdf_expand_label_sha256, hkdf_expand_label_sha384, hkdf_extract_sha256, hkdf_extract_sha384,
    Tls13KeySchedule, Tls13TrafficKeys,
};
pub use messages::{
    build_certificate_placeholder, build_certificate_verify_placeholder,
    build_encrypted_extensions_empty, build_finished, build_handshake_message,
    RealityCertificatePlan, RealityEncryptedExtensionsPlan, RealityFinishedPlan,
    RealityServerHelloPlan, HANDSHAKE_TYPE_CERTIFICATE, HANDSHAKE_TYPE_CERTIFICATE_VERIFY,
    HANDSHAKE_TYPE_ENCRYPTED_EXTENSIONS, HANDSHAKE_TYPE_FINISHED, HANDSHAKE_TYPE_SERVER_HELLO,
};
pub use state::RealityTls13ServerState;
pub use transcript::{Tls13HashAlgorithm, TranscriptHash};
