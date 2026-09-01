mod aead;
#[cfg(test)]
mod client_session;
mod config;
mod handshake;
mod header;
mod hybrid;
mod io;
mod kdf;
mod keys;
mod mlkem;
mod nfs;
mod nonce;
mod padding;
mod resume_noise;
mod runtime;
mod server;
mod session_cache;
mod stream;
mod x25519;
mod xor;

pub use aead::{TrafficAead, TrafficAeadKind};
pub use config::{
    parse_inbound_decryption, parse_outbound_encryption,
    validate_inbound_decryption_with_fallbacks, ClientHandshakeMode, Mlkem768X25519PlusConfig,
    TicketLifetimeRange, VlessDecryption, VlessEncryption, XorMode,
};
pub use handshake::{
    prefer_aes_hardware, HandshakeError, ServerHandshakeResult, TrafficDirectionKeys, XorConnState,
    DEFAULT_HANDSHAKE_TIMEOUT,
};
pub use header::{decode_traffic_header, encode_traffic_header, TrafficHeaderError};
pub use hybrid::{
    compose_pfs_key, compose_united_key, decode_length, encode_length, PfsKey, UnitedKey,
    PFS_KEY_LEN, UNITED_KEY_LEN,
};
pub use io::{HandshakeStream, PrefixStream};
pub use kdf::{derive_blake3_key, derive_ctr_key};
pub use keys::{nfs_public_key_hash, NfsStaticKey, SecretBytes};
#[cfg(test)]
pub(crate) use mlkem::encapsulate_mlkem768_with_seed;
pub use mlkem::{decapsulate_mlkem768, encapsulate_mlkem768};
pub use nfs::NfsServerChain;
pub use nonce::{increase_nonce, is_max_nonce, NonceCounter, MAX_NONCE};
pub use padding::{create_padding_lengths, parse_padding_profile, PaddingProfile, SeededRng};
#[cfg(test)]
pub(crate) use resume_noise::{generate_invalid_ticket_noise, invalid_ticket_noise_length};
pub use runtime::{
    build_encryption_server, build_encryption_server_from_decryption, handshake_and_wrap,
    handshake_and_wrap_with_rng, map_handshake_error, SharedVlessEncryptionServer,
};
pub use server::{HandshakeRng, OsHandshakeRng, VlessEncryptionServer};
#[cfg(test)]
pub(crate) use session_cache::{
    MockCacheTime, SessionCache, SessionLookupError, INVALID_TICKET_NOISE_MAX,
    INVALID_TICKET_NOISE_MIN, MAX_STORED_SESSIONS,
};
#[cfg(test)]
pub(crate) use stream::{reset_test_seal_count, EncryptedReader, EncryptedWriter};
pub use stream::{
    VlessEncryptedReader, VlessEncryptedRelaySplit, VlessEncryptedStream, VlessEncryptedWriter,
    MAX_TRAFFIC_PLAINTEXT_PER_RECORD,
};
pub use x25519::{x25519_ecdh, x25519_public_key, X25519PublicKey, X25519SecretKey};
pub use xor::{ctr_xor, CtrStream};

#[cfg(test)]
#[path = "../../../tests/unit/vless/encryption/mod.rs"]
#[allow(dead_code)]
mod tests;
