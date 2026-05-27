mod client_hello;
pub mod prefixed;
pub mod record;
pub mod records;
pub mod server_hello;

pub use prefixed::PrefixedStream;
pub use record::{parse_client_hello_record_bytes, read_client_hello_record, TlsClientHelloRecord};
pub use records::{
    build_application_data_record, build_change_cipher_spec_record, build_handshake_record,
    build_tls_record, parse_complete_tls_records_prefix, parse_tls_records, TlsRecord,
    TlsRecordContentType, TLS_LEGACY_VERSION_1_2, TLS_RECORD_ALERT, TLS_RECORD_APPLICATION_DATA,
    TLS_RECORD_CHANGE_CIPHER_SPEC, TLS_RECORD_HANDSHAKE,
};
pub use server_hello::{
    parse_server_hello_key_share, parse_tls_server_hello_handshake, ServerHelloKeyShare,
    TlsExtension, TlsServerHello, EXTENSION_KEY_SHARE, EXTENSION_SUPPORTED_VERSIONS,
    NAMED_GROUP_X25519,
};
