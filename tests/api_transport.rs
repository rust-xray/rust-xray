use std::net::{IpAddr, Ipv4Addr};
use std::sync::Arc;
use std::time::Duration;

use rcgen::{
    BasicConstraints, CertificateParams, DnType, ExtendedKeyUsagePurpose, IsCa, KeyPair, SanType,
};
use rust_xray::api::proto::app::stats::command::stats_service_client::StatsServiceClient;
use rust_xray::api::proto::app::stats::command::SysStatsRequest;
use rust_xray::api::server::{
    resolve_api_transport_mode, serve_grpc_on, ApiService, ApiTransportContext, ApiTransportMode,
};
use rust_xray::config::{extract_api_inbound_tls_material, XrayConfig};
use rust_xray::runtime::InboundUserManagers;
use rust_xray::stats::StatsRegistry;
use tempfile::tempdir;
use tokio::net::TcpListener;
use tonic::transport::{Certificate, ClientTlsConfig, Endpoint, Identity};

struct RemnaTestCerts {
    ca_pem: Vec<u8>,
    server_cert_pem: Vec<u8>,
    server_key_pem: Vec<u8>,
    client_cert_pem: Vec<u8>,
    client_key_pem: Vec<u8>,
}

fn generate_remnawave_test_certs() -> RemnaTestCerts {
    let ca_key = KeyPair::generate().expect("ca key");
    let mut ca_params = CertificateParams::default();
    ca_params
        .distinguished_name
        .push(DnType::CommonName, "Remnawave Internal CA");
    ca_params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    let ca_cert = ca_params.self_signed(&ca_key).expect("ca cert");

    let server_key = KeyPair::generate().expect("server key");
    let mut server_params = CertificateParams::new(vec![
        "internal.remnawave.local".to_string(),
        "localhost".to_string(),
    ])
    .expect("server params");
    server_params
        .subject_alt_names
        .push(SanType::IpAddress(IpAddr::V4(Ipv4Addr::LOCALHOST)));
    let server_cert = server_params
        .signed_by(&server_key, &ca_cert, &ca_key)
        .expect("server cert");

    let client_key = KeyPair::generate().expect("client key");
    let mut client_params = CertificateParams::new(vec!["internal.remnawave.local".to_string()])
        .expect("client params");
    client_params.extended_key_usages = vec![ExtendedKeyUsagePurpose::ClientAuth];
    let client_cert = client_params
        .signed_by(&client_key, &ca_cert, &ca_key)
        .expect("client cert");

    RemnaTestCerts {
        ca_pem: ca_cert.pem().into_bytes(),
        server_cert_pem: server_cert.pem().into_bytes(),
        server_key_pem: server_key.serialize_pem().into_bytes(),
        client_cert_pem: client_cert.pem().into_bytes(),
        client_key_pem: client_key.serialize_pem().into_bytes(),
    }
}

fn pem_lines(pem: &[u8]) -> Vec<String> {
    String::from_utf8_lossy(pem)
        .lines()
        .map(str::to_string)
        .collect()
}

fn remnawave_mtls_config_json(certs: &RemnaTestCerts) -> String {
    serde_json::json!({
        "api": {
            "tag": "REMNAWAVE_API",
            "services": ["StatsService"]
        },
        "routing": {
            "rules": [{
                "inboundTag": ["REMNAWAVE_API_INBOUND"],
                "outboundTag": "REMNAWAVE_API"
            }]
        },
        "inbounds": [{
            "tag": "REMNAWAVE_API_INBOUND",
            "listen": "127.0.0.1",
            "port": 61000,
            "protocol": "dokodemo-door",
            "settings": { "address": "127.0.0.1" },
            "streamSettings": {
                "security": "tls",
                "tlsSettings": {
                    "serverName": "internal.remnawave.local",
                    "certificates": [
                        {
                            "certificate": pem_lines(&certs.server_cert_pem),
                            "key": pem_lines(&certs.server_key_pem)
                        },
                        {
                            "usage": "verify",
                            "certificate": pem_lines(&certs.ca_pem)
                        }
                    ]
                }
            }
        }]
    })
    .to_string()
}

async fn start_stats_server(transport: ApiTransportMode) -> std::net::SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
    let addr = listener.local_addr().expect("addr");
    let registry = Arc::new(StatsRegistry::new());
    tokio::spawn(async move {
        let inbound_users = Arc::new(InboundUserManagers::new());
        let _ = serve_grpc_on(
            listener,
            vec![ApiService::Stats],
            registry,
            inbound_users,
            transport,
        )
        .await;
    });
    tokio::time::sleep(Duration::from_millis(50)).await;
    addr
}

#[tokio::test]
async fn get_sys_stats_over_tls_with_internal_remnawave_local() {
    let certs = generate_remnawave_test_certs();
    let transport = ApiTransportMode::Tls {
        cert_pem: certs.server_cert_pem.clone(),
        key_pem: certs.server_key_pem.clone(),
    };
    let addr = start_stats_server(transport).await;

    let tls = ClientTlsConfig::new()
        .domain_name("internal.remnawave.local")
        .ca_certificate(Certificate::from_pem(certs.ca_pem.clone()));
    let channel = Endpoint::from_shared(format!("https://{addr}"))
        .expect("endpoint")
        .tls_config(tls)
        .expect("client tls")
        .connect()
        .await
        .expect("connect");

    StatsServiceClient::new(channel)
        .get_sys_stats(SysStatsRequest {})
        .await
        .expect("GetSysStats over TLS")
        .into_inner();
}

#[tokio::test]
async fn get_sys_stats_over_mtls_with_client_cert() {
    let certs = generate_remnawave_test_certs();
    let transport = ApiTransportMode::Mtls {
        ca_pem: certs.ca_pem.clone(),
        cert_pem: certs.server_cert_pem.clone(),
        key_pem: certs.server_key_pem.clone(),
    };
    let addr = start_stats_server(transport).await;

    let identity = Identity::from_pem(certs.client_cert_pem.clone(), certs.client_key_pem.clone());
    let tls = ClientTlsConfig::new()
        .domain_name("internal.remnawave.local")
        .ca_certificate(Certificate::from_pem(certs.ca_pem.clone()))
        .identity(identity);
    let channel = Endpoint::from_shared(format!("https://{addr}"))
        .expect("endpoint")
        .tls_config(tls)
        .expect("client tls")
        .connect()
        .await
        .expect("connect");

    StatsServiceClient::new(channel)
        .get_sys_stats(SysStatsRequest {})
        .await
        .expect("GetSysStats over mTLS")
        .into_inner();
}

#[tokio::test]
async fn mtls_rejects_client_without_cert() {
    let certs = generate_remnawave_test_certs();
    let transport = ApiTransportMode::Mtls {
        ca_pem: certs.ca_pem.clone(),
        cert_pem: certs.server_cert_pem.clone(),
        key_pem: certs.server_key_pem.clone(),
    };
    let addr = start_stats_server(transport).await;

    let tls = ClientTlsConfig::new()
        .domain_name("internal.remnawave.local")
        .ca_certificate(Certificate::from_pem(certs.ca_pem));
    let channel = Endpoint::from_shared(format!("https://{addr}"))
        .expect("endpoint")
        .tls_config(tls)
        .expect("client tls")
        .connect()
        .await
        .expect("connect");

    let err = StatsServiceClient::new(channel)
        .get_sys_stats(SysStatsRequest {})
        .await
        .expect_err("mTLS without client cert should fail");
    assert!(!err.message().is_empty());
}

#[test]
fn remnawave_auto_mtls_loads_tls_material_from_config() {
    let certs = generate_remnawave_test_certs();
    let config: XrayConfig =
        serde_json::from_str(&remnawave_mtls_config_json(&certs)).expect("parse config");
    let material = extract_api_inbound_tls_material(&config)
        .expect("extract")
        .expect("tls material");
    assert_eq!(
        material.server_name.as_deref(),
        Some("internal.remnawave.local")
    );

    let selection = resolve_api_transport_mode(ApiTransportContext {
        config_source: "http+unix:///run/remna/internal/get-config?token=x",
        api_listen: Some("127.0.0.1:61000"),
        xray: Some(&config),
    })
    .expect("resolve mtls from config");
    assert_eq!(selection.reason, "remnawave-http-unix-auto");
    assert!(matches!(selection.mode, ApiTransportMode::Mtls { .. }));
}

#[test]
fn file_config_defaults_to_plaintext_transport() {
    let selection = resolve_api_transport_mode(ApiTransportContext {
        config_source: "/etc/xray/config.json",
        api_listen: Some("127.0.0.1:10085"),
        xray: None,
    })
    .expect("plaintext default");
    assert_eq!(selection.reason, "xray-default-plaintext");
    assert_eq!(selection.mode, ApiTransportMode::Plaintext);
}

#[test]
fn tls_env_invalid_pem_errors() {
    let dir = tempdir().expect("tempdir");
    let cert_path = dir.path().join("bad.crt");
    let key_path = dir.path().join("bad.key");
    std::fs::write(&cert_path, b"not a cert").expect("write cert");
    std::fs::write(&key_path, b"not a key").expect("write key");

    std::env::set_var("RUST_XRAY_API_TRANSPORT", "tls");
    std::env::set_var("RUST_XRAY_API_TLS_CERT", cert_path.to_str().unwrap());
    std::env::set_var("RUST_XRAY_API_TLS_KEY", key_path.to_str().unwrap());

    let err = resolve_api_transport_mode(ApiTransportContext {
        config_source: "/etc/xray/config.json",
        api_listen: None,
        xray: None,
    })
    .unwrap_err();

    std::env::remove_var("RUST_XRAY_API_TRANSPORT");
    std::env::remove_var("RUST_XRAY_API_TLS_CERT");
    std::env::remove_var("RUST_XRAY_API_TLS_KEY");

    assert_eq!(err.kind(), std::io::ErrorKind::InvalidInput);
}
