//! TLS 1.3 server handshake skeleton for the REALITY accepted path.
//!
//! Cryptography and message generation are intentionally **not** implemented here
//! yet. This module defines the structure for porting upstream XTLS/REALITY in
//! smaller steps.

mod certificate;
mod cipher_suite;
mod key_schedule;
pub mod key_share;
mod messages;
mod record_crypto;
mod state;
mod stream;
mod transcript;

pub use certificate::{
    build_tls13_certificate_message, build_tls13_certificate_verify_ed25519,
    generate_reality_ephemeral_ed25519_certificate, tls13_certificate_verify_message_to_sign,
    RealityEphemeralCertificate, SIGNATURE_SCHEME_ED25519,
};
pub use cipher_suite::{
    tls13_cipher_suite, Tls13AeadAlgorithm, Tls13CipherSuite, TLS_AES_128_GCM_SHA256,
    TLS_AES_256_GCM_SHA384, TLS_CHACHA20_POLY1305_SHA256,
};

pub use key_schedule::{
    compute_finished_verify_data, derive_application_traffic_secrets, derive_finished_key,
    derive_handshake_traffic_secrets, derive_master_secret, derive_secret_sha256,
    derive_secret_sha384, derive_traffic_key, empty_hash, hash_len, hkdf_expand_label_sha256,
    hkdf_expand_label_sha384, hkdf_extract_sha256, hkdf_extract_sha384, verify_finished_data,
    Tls13ApplicationSecrets, Tls13HandshakeSecrets, Tls13KeySchedule, Tls13TrafficKeys,
};
pub use key_share::{
    encode_key_share_extension_body, extract_client_x25519_key_share,
    generate_x25519_server_key_share, Tls13ServerKeyShare, NAMED_GROUP_X25519, X25519_KEY_LEN,
};
pub use messages::{
    build_certificate_placeholder, build_certificate_verify_placeholder,
    build_encrypted_extensions_empty, build_finished, build_handshake_message,
    build_tls13_server_hello, RealityCertificatePlan, RealityEncryptedExtensionsPlan,
    RealityFinishedPlan, RealityServerHelloPlan, Tls13ServerHelloParams, EXT_KEY_SHARE,
    EXT_SUPPORTED_VERSIONS, HANDSHAKE_TYPE_CERTIFICATE, HANDSHAKE_TYPE_CERTIFICATE_VERIFY,
    HANDSHAKE_TYPE_ENCRYPTED_EXTENSIONS, HANDSHAKE_TYPE_FINISHED, HANDSHAKE_TYPE_SERVER_HELLO,
    TLS_VERSION_1_2_LEGACY, TLS_VERSION_1_3,
};
pub use record_crypto::{tls13_record_nonce, Tls13RecordDecryptor, Tls13RecordEncryptor};
pub use state::{complete_reality_tls13_handshake, RealityTls13ServerState};
pub use stream::{
    ApplicationStreamDirectRelay, RealityTls13ApplicationStream, RealityTls13ClientReader,
    RealityTls13ClientWriter, RealityTls13RelayClient, RealityTls13RelaySplit,
};
pub use transcript::{Tls13HashAlgorithm, TranscriptHash};
