use std::sync::Arc;
use std::time::Duration;

use rcgen::{BasicConstraints, CertificateParams, DnType, IsCa, KeyPair};
use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use rustls::server::ServerConnection;
use rustls::{RootCertStore, ServerConfig};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::time::sleep;

use crate::reality::dest_dial::{RealityDestDialConfig, RealityDestTransport};
use crate::reality::post_handshake::alpn::RealityAlpnProfile;
use crate::reality::post_handshake::cache::PostHandshakeProbeKey;
use crate::reality::post_handshake::ccs_probe_exec::execute_ccs_tolerance_probe_with_roots;
use crate::reality::post_handshake::probe_io::{
    build_fatal_unexpected_message_alert_record, is_tls13_compatibility_ccs_record,
};
use crate::reality::post_handshake::tls_client::ensure_rustls_crypto_provider;
use crate::reality::post_handshake::tolerance::UselessRecordTolerance;

const MOCK_SNI: &str = "ccs-probe.test.local";

struct MockProbeCa {
    roots: RootCertStore,
    ca_cert: rcgen::Certificate,
    ca_key: KeyPair,
}

impl MockProbeCa {
    fn new() -> Self {
        ensure_rustls_crypto_provider();
        let ca_key = KeyPair::generate().expect("mock CA key");
        let mut ca_params = CertificateParams::default();
        ca_params
            .distinguished_name
            .push(DnType::CommonName, "CCS Probe Test CA");
        ca_params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        let ca_cert = ca_params.self_signed(&ca_key).expect("mock CA cert");

        let mut roots = RootCertStore::empty();
        roots
            .add(CertificateDer::from(ca_cert.der().to_vec()))
            .expect("add mock root");
        Self {
            roots,
            ca_cert,
            ca_key,
        }
    }

    fn server_config(&self, alpn: Option<Vec<Vec<u8>>>) -> Arc<ServerConfig> {
        ensure_rustls_crypto_provider();
        let server_key = KeyPair::generate().expect("mock server key");
        let server_params =
            CertificateParams::new(vec![MOCK_SNI.to_string()]).expect("server params");
        let server_cert = server_params
            .signed_by(&server_key, &self.ca_cert, &self.ca_key)
            .expect("signed server cert");
        let cert_chain = vec![CertificateDer::from(server_cert.der().to_vec())];
        let key = PrivateKeyDer::Pkcs8(server_key.serialize_der().into());

        let mut config = ServerConfig::builder()
            .with_no_client_auth()
            .with_single_cert(cert_chain, key)
            .expect("server config");
        if let Some(protocols) = alpn {
            config.alpn_protocols = protocols;
        }
        config.send_tls13_tickets = 0;
        Arc::new(config)
    }
}

fn probe_key(server_name: &str, alpn: RealityAlpnProfile, dest: &str) -> PostHandshakeProbeKey {
    PostHandshakeProbeKey {
        dest_addr: dest.to_string(),
        server_name: server_name.to_string(),
        alpn_profile: alpn,
    }
}

fn probe_dial(addr: std::net::SocketAddr) -> RealityDestDialConfig {
    RealityDestDialConfig {
        dest_addr: addr.to_string(),
        transport: RealityDestTransport::Tcp,
        xver: 0,
    }
}

async fn spawn_mock_ccs_target(
    server_config: Arc<ServerConfig>,
    max_tolerated_extra_ccs: Option<usize>,
) -> (std::net::SocketAddr, tokio::task::JoinHandle<()>) {
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind mock");
    let addr = listener.local_addr().expect("addr");
    let join = tokio::spawn(async move {
        if let Ok((stream, _)) = listener.accept().await {
            run_mock_ccs_tolerance_target(stream, server_config, max_tolerated_extra_ccs).await;
        }
    });
    (addr, join)
}

async fn run_mock_ccs_tolerance_target(
    mut stream: TcpStream,
    server_config: Arc<ServerConfig>,
    max_tolerated_extra_ccs: Option<usize>,
) {
    let mut server = ServerConnection::new(server_config).expect("server");
    let mut inbound = vec![0u8; 8192];
    let mut outbound = Vec::new();
    let mut wrote_server_data = false;
    let mut raw_mode = false;
    let mut raw_buf = Vec::new();
    let mut extra_ccs = 0usize;

    loop {
        if !raw_mode {
            while server.wants_write() {
                outbound.clear();
                server.write_tls(&mut outbound).expect("write tls");
                if outbound.is_empty() {
                    break;
                }
                wrote_server_data = true;
                stream.write_all(&outbound).await.expect("write socket");
            }

            if !server.is_handshaking() {
                raw_mode = true;
            } else if server.wants_read() {
                if wrote_server_data {
                    raw_mode = true;
                } else {
                    let read_len = stream.read(&mut inbound).await.expect("read socket");
                    if read_len == 0 {
                        return;
                    }
                    let mut cursor = &inbound[..read_len];
                    while !cursor.is_empty() {
                        server.read_tls(&mut cursor).expect("read tls");
                    }
                    server.process_new_packets().expect("process");
                    continue;
                }
            } else {
                sleep(Duration::from_millis(5)).await;
                continue;
            }
        }

        let read_len = stream.read(&mut inbound).await.expect("read socket");
        if read_len == 0 {
            return;
        }
        raw_buf.extend_from_slice(&inbound[..read_len]);

        while raw_buf.len() >= 5 {
            let record_len = u16::from_be_bytes([raw_buf[3], raw_buf[4]]) as usize;
            let total = 5 + record_len;
            if raw_buf.len() < total {
                break;
            }

            let record = raw_buf[..total].to_vec();
            raw_buf.drain(..total);

            if is_tls13_compatibility_ccs_record(&record) {
                extra_ccs += 1;
                if let Some(max) = max_tolerated_extra_ccs {
                    if extra_ccs > max {
                        let alert = build_fatal_unexpected_message_alert_record();
                        stream.write_all(&alert).await.ok();
                        return;
                    }
                }
            }
        }
    }
}

async fn run_ccs_probe_on_spawned(
    ca: &MockProbeCa,
    max_tolerated: Option<usize>,
    alpn: RealityAlpnProfile,
) -> UselessRecordTolerance {
    let (addr, _join) = spawn_mock_ccs_target(
        ca.server_config(alpn.probe_next_protocols().map(|values| {
            values
                .into_iter()
                .map(|value| value.as_bytes().to_vec())
                .collect()
        })),
        max_tolerated,
    )
    .await;
    let key = probe_key(MOCK_SNI, alpn, &addr.to_string());
    execute_ccs_tolerance_probe_with_roots(&probe_dial(addr), &key, ca.roots.clone()).await
}

#[tokio::test]
async fn detects_tolerance_one() {
    let ca = MockProbeCa::new();
    let tolerance = run_ccs_probe_on_spawned(&ca, Some(1), RealityAlpnProfile::None).await;
    assert_eq!(tolerance, UselessRecordTolerance::Finite(1));
}

#[tokio::test]
async fn detects_tolerance_sixteen() {
    let ca = MockProbeCa::new();
    let tolerance = run_ccs_probe_on_spawned(&ca, Some(16), RealityAlpnProfile::None).await;
    assert_eq!(tolerance, UselessRecordTolerance::Finite(16));
}

#[tokio::test]
async fn detects_tolerance_thirty_two() {
    let ca = MockProbeCa::new();
    let tolerance = run_ccs_probe_on_spawned(&ca, Some(32), RealityAlpnProfile::None).await;
    assert_eq!(tolerance, UselessRecordTolerance::Finite(32));
}

#[tokio::test]
async fn detects_unlimited() {
    let ca = MockProbeCa::new();
    let tolerance = run_ccs_probe_on_spawned(&ca, None, RealityAlpnProfile::None).await;
    assert_eq!(tolerance, UselessRecordTolerance::Unlimited);
}

#[tokio::test]
async fn connect_failure_defaults_to_thirty_two() {
    let ca = MockProbeCa::new();
    let key = probe_key(MOCK_SNI, RealityAlpnProfile::None, "127.0.0.1:1");
    let tolerance = execute_ccs_tolerance_probe_with_roots(
        &probe_dial("127.0.0.1:1".parse().expect("addr")),
        &key,
        ca.roots.clone(),
    )
    .await;
    assert_eq!(tolerance, UselessRecordTolerance::Finite(32));
}

#[tokio::test]
async fn tls_handshake_failure_defaults_to_thirty_two() {
    let ca = MockProbeCa::new();
    let (addr, _join) = spawn_mock_ccs_target(ca.server_config(None), Some(0)).await;
    let key = probe_key("wrong.name", RealityAlpnProfile::None, &addr.to_string());
    let tolerance =
        execute_ccs_tolerance_probe_with_roots(&probe_dial(addr), &key, ca.roots.clone()).await;
    assert_eq!(tolerance, UselessRecordTolerance::Finite(32));
}

#[tokio::test]
async fn alpn_profile_none_http11_h2_each_probeable() {
    let ca = MockProbeCa::new();
    for alpn in RealityAlpnProfile::PROBE_PROFILES {
        let tolerance = run_ccs_probe_on_spawned(&ca, Some(1), alpn).await;
        assert_eq!(
            tolerance,
            UselessRecordTolerance::Finite(1),
            "alpn profile {alpn:?}"
        );
    }
}
