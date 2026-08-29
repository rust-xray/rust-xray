use super::*;
use std::sync::{Mutex, MutexGuard};

static ENV_LOCK: Mutex<()> = Mutex::new(());

struct EnvGuard {
    _lock: MutexGuard<'static, ()>,
    vars: Vec<(&'static str, Option<String>)>,
}

impl EnvGuard {
    fn new(pairs: &[(&'static str, Option<&str>)]) -> Self {
        let lock = ENV_LOCK.lock().expect("env lock");
        let mut saved = Vec::new();
        for (key, value) in pairs {
            saved.push((*key, std::env::var(key).ok()));
            match value {
                Some(v) => std::env::set_var(key, v),
                None => std::env::remove_var(key),
            }
        }
        Self {
            _lock: lock,
            vars: saved,
        }
    }
}

impl Drop for EnvGuard {
    fn drop(&mut self) {
        for (key, value) in &self.vars {
            match value {
                Some(v) => std::env::set_var(key, v),
                None => std::env::remove_var(key),
            }
        }
    }
}

#[test]
fn parse_api_listen_requires_host_and_port() {
    assert!(parse_api_grpc_listen_addr("127.0.0.1:10085").is_ok());
    assert!(parse_api_grpc_listen_addr("0.0.0.0:10085").is_ok());
    let err = parse_api_grpc_listen_addr("127.0.0.1").unwrap_err();
    assert_eq!(err.kind(), std::io::ErrorKind::InvalidInput);
    assert!(err.to_string().contains("host:port"));
}

#[test]
fn transport_defaults_plaintext_for_file_config() {
    let _guard = EnvGuard::new(&[
        ("RUST_XRAY_API_TRANSPORT", None),
        ("RUST_XRAY_API_TLS", None),
        ("RUST_XRAY_API_TLS_CA", None),
        ("RUST_XRAY_API_TLS_CERT", None),
        ("RUST_XRAY_API_TLS_KEY", None),
    ]);
    let sel = resolve_api_transport_mode(ApiTransportContext {
        config_source: "/etc/xray/config.json",
        api_listen: Some("127.0.0.1:61000"),
        xray: None,
    })
    .expect("plaintext");
    assert_eq!(sel.mode, ApiTransportMode::Plaintext);
    assert_eq!(sel.reason, "xray-default-plaintext");
}

#[test]
fn transport_env_plaintext_override() {
    let _guard = EnvGuard::new(&[
        ("RUST_XRAY_API_TRANSPORT", Some("plaintext")),
        ("RUST_XRAY_API_TLS", None),
        ("RUST_XRAY_API_TLS_CA", None),
        ("RUST_XRAY_API_TLS_CERT", None),
        ("RUST_XRAY_API_TLS_KEY", None),
    ]);
    let sel = resolve_api_transport_mode(ApiTransportContext {
        config_source: "http+unix:///run/remna.sock/internal/get-config?token=x",
        api_listen: Some("127.0.0.1:61000"),
        xray: None,
    })
    .expect("plaintext override");
    assert_eq!(sel.mode, ApiTransportMode::Plaintext);
    assert_eq!(sel.reason, "env-override");
}

#[test]
fn transport_remnawave_auto_selects_mtls() {
    let _guard = EnvGuard::new(&[
        ("RUST_XRAY_API_TRANSPORT", None),
        ("RUST_XRAY_API_TLS", None),
        ("RUST_XRAY_API_TLS_CA", None),
        ("RUST_XRAY_API_TLS_CERT", None),
        ("RUST_XRAY_API_TLS_KEY", None),
    ]);
    let err = resolve_api_transport_mode(ApiTransportContext {
        config_source: "http+unix:///run/remna.sock/internal/get-config?token=x",
        api_listen: Some("127.0.0.1:61000"),
        xray: None,
    })
    .unwrap_err();
    assert_eq!(err.kind(), std::io::ErrorKind::InvalidInput);
    assert!(err.to_string().contains("Remnawave mTLS"));
}

#[test]
fn transport_env_tls_requires_cert_and_key() {
    let _guard = EnvGuard::new(&[
        ("RUST_XRAY_API_TRANSPORT", Some("tls")),
        ("RUST_XRAY_API_TLS", None),
        ("RUST_XRAY_API_TLS_CA", None),
        ("RUST_XRAY_API_TLS_CERT", None),
        ("RUST_XRAY_API_TLS_KEY", None),
    ]);
    let err = resolve_api_transport_mode(ApiTransportContext {
        config_source: "/etc/xray/config.json",
        api_listen: None,
        xray: None,
    })
    .unwrap_err();
    assert_eq!(err.kind(), std::io::ErrorKind::InvalidInput);
}

#[test]
fn transport_env_tls_with_files() {
    let dir = tempfile::tempdir().expect("tempdir");
    let cert_path = dir.path().join("api.crt");
    let key_path = dir.path().join("api.key");
    write_test_tls_pem(&cert_path, &key_path);
    let _guard = EnvGuard::new(&[
        ("RUST_XRAY_API_TRANSPORT", Some("tls")),
        ("RUST_XRAY_API_TLS", None),
        ("RUST_XRAY_API_TLS_CA", None),
        ("RUST_XRAY_API_TLS_CERT", Some(cert_path.to_str().unwrap())),
        ("RUST_XRAY_API_TLS_KEY", Some(key_path.to_str().unwrap())),
    ]);
    let sel = resolve_api_transport_mode(ApiTransportContext {
        config_source: "/etc/xray/config.json",
        api_listen: None,
        xray: None,
    })
    .expect("tls files");
    assert!(matches!(sel.mode, ApiTransportMode::Tls { .. }));
    assert_eq!(sel.reason, "env-override");
}

#[test]
fn transport_invalid_cert_key_errors() {
    let dir = tempfile::tempdir().expect("tempdir");
    let cert_path = dir.path().join("bad.crt");
    let key_path = dir.path().join("bad.key");
    std::fs::write(&cert_path, b"not a cert").expect("write cert");
    std::fs::write(&key_path, b"not a key").expect("write key");
    let _guard = EnvGuard::new(&[
        ("RUST_XRAY_API_TRANSPORT", Some("tls")),
        ("RUST_XRAY_API_TLS", None),
        ("RUST_XRAY_API_TLS_CA", None),
        ("RUST_XRAY_API_TLS_CERT", Some(cert_path.to_str().unwrap())),
        ("RUST_XRAY_API_TLS_KEY", Some(key_path.to_str().unwrap())),
    ]);
    let err = resolve_api_transport_mode(ApiTransportContext {
        config_source: "/etc/xray/config.json",
        api_listen: None,
        xray: None,
    })
    .unwrap_err();
    assert_eq!(err.kind(), std::io::ErrorKind::InvalidInput);
}

#[test]
fn parse_enabled_services_skips_observatory_when_runtime_missing() {
    let enabled =
        parse_enabled_services(&["ObservatoryService".to_string(), "StatsService".to_string()])
            .expect("parse services");
    assert_eq!(enabled, vec![ApiService::Observatory, ApiService::Stats]);
}

fn write_test_tls_pem(cert_path: &std::path::Path, key_path: &std::path::Path) {
    use rcgen::{CertificateParams, KeyPair};
    let key_pair = KeyPair::generate().expect("generate key");
    let params = CertificateParams::new(vec!["localhost".to_string()]).expect("cert params");
    let cert = params.self_signed(&key_pair).expect("self signed cert");
    std::fs::write(cert_path, cert.pem()).expect("write cert");
    std::fs::write(key_path, key_pair.serialize_pem()).expect("write key");
}
