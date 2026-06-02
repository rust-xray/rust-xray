
use super::*;
use crate::pki_types::DnsName;
use crate::protocol::enums::ProtocolVersion;
use crate::protocol::structs::{ClientExtension, ClientHelloPayload, Random, SessionId};

fn hello_with_sni(hostname: &str) -> ClientHelloPayload {
    let dns = DnsName::try_from(hostname).expect("valid dns name");
    ClientHelloPayload {
        client_version: ProtocolVersion::TLSv1_2,
        random: Random([0u8; 32]),
        session_id: SessionId::empty(),
        cipher_suites: Vec::new(),
        compression_methods: Vec::new(),
        extensions: vec![ClientExtension::make_sni(&dns)],
    }
}

#[test]
fn extract_sni_hostname_returns_first_dns_hostname_lowercased() {
    let hello = hello_with_sni("Example.COM");
    assert_eq!(extract_sni_hostname(&hello).as_deref(), Some("example.com"));
}

#[test]
fn extract_sni_hostname_returns_none_without_sni_extension() {
    let hello = ClientHelloPayload {
        client_version: ProtocolVersion::TLSv1_2,
        random: Random([0u8; 32]),
        session_id: SessionId::empty(),
        cipher_suites: Vec::new(),
        compression_methods: Vec::new(),
        extensions: Vec::new(),
    };

    assert!(extract_sni_hostname(&hello).is_none());
}

#[test]
fn server_name_allowed_exact_match() {
    let allowed = vec!["www.example.com".to_string()];
    assert!(server_name_allowed("www.example.com", &allowed));
}

#[test]
fn server_name_allowed_case_insensitive_match() {
    let allowed = vec!["www.example.com".to_string()];
    assert!(server_name_allowed("WWW.EXAMPLE.COM", &allowed));
}

#[test]
fn server_name_allowed_matches_when_allowed_entry_is_uppercase() {
    let allowed = vec!["WWW.EXAMPLE.COM".to_string()];
    assert!(server_name_allowed("www.example.com", &allowed));
}

#[test]
fn server_name_allowed_rejects_unknown_hostname() {
    let allowed = vec!["www.example.com".to_string()];
    assert!(!server_name_allowed("other.example.com", &allowed));
}

#[test]
fn server_name_allowed_rejects_empty_allowed_list() {
    assert!(!server_name_allowed("www.example.com", &[]));
}
