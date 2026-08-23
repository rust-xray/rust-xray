use std::io::Write;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use rcgen::{BasicConstraints, CertificateParams, DnType, IsCa, KeyPair};
use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use rustls::server::ServerConnection;
use rustls::{RootCertStore, ServerConfig};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::oneshot;
use tokio::time::sleep;

use crate::reality::dest_dial::{RealityDestDialConfig, RealityDestTransport};
use crate::reality::post_handshake::alpn::RealityAlpnProfile;
use crate::reality::post_handshake::cache::{PostHandshakeProbeCache, PostHandshakeProbeKey};
use crate::reality::post_handshake::probe::{
    execute_post_handshake_probe_with_roots, probe_lengths_from_capture,
    POST_HANDSHAKE_PROBE_CAPTURE_TIMEOUT,
};
use crate::reality::post_handshake::tls_client::ensure_rustls_crypto_provider;

const MOCK_SNI: &str = "probe.test.local";

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
            .push(DnType::CommonName, "Post Handshake Probe Test CA");
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

async fn spawn_mock_target<F>(handler: F) -> (SocketAddr, tokio::task::JoinHandle<()>)
where
    F: FnOnce(TcpStream) -> tokio::task::JoinHandle<(Option<String>, Option<Vec<u8>>)>
        + Send
        + 'static,
{
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind mock");
    let addr = listener.local_addr().expect("addr");
    let join = tokio::spawn(async move {
        if let Ok((stream, _)) = listener.accept().await {
            let _ = handler(stream).await;
        }
    });
    (addr, join)
}

fn probe_key(server_name: &str, alpn: RealityAlpnProfile) -> PostHandshakeProbeKey {
    PostHandshakeProbeKey {
        dest_addr: String::new(),
        server_name: server_name.to_string(),
        alpn_profile: alpn,
    }
}

fn probe_dial(addr: SocketAddr) -> RealityDestDialConfig {
    RealityDestDialConfig {
        dest_addr: addr.to_string(),
        transport: RealityDestTransport::Tcp,
        xver: 0,
    }
}

async fn drive_rustls_server(
    mut stream: TcpStream,
    server_config: Arc<ServerConfig>,
    post_plaintext: Vec<Vec<u8>>,
    hang_after_handshake: bool,
) -> (Option<String>, Option<Vec<u8>>) {
    let mut server = ServerConnection::new(server_config).expect("server connection");
    let mut inbound = vec![0u8; 4096];
    let mut outbound = Vec::new();

    loop {
        while server.wants_write() {
            outbound.clear();
            let _ = server.write_tls(&mut outbound).expect("write tls");
            if outbound.is_empty() {
                break;
            }
            stream.write_all(&outbound).await.expect("write socket");
        }

        if !server.is_handshaking() {
            break;
        }

        if server.wants_read() {
            let read_len = stream.read(&mut inbound).await.expect("read socket");
            if read_len == 0 {
                break;
            }
            let mut cursor = &inbound[..read_len];
            while !cursor.is_empty() {
                server.read_tls(&mut cursor).expect("read tls");
            }
            server.process_new_packets().expect("process packets");
        }
    }

    let sni = server.server_name().map(str::to_string);
    let alpn = server.alpn_protocol().map(|value| value.to_vec());

    if hang_after_handshake {
        sleep(POST_HANDSHAKE_PROBE_CAPTURE_TIMEOUT + Duration::from_millis(200)).await;
        return (sni, alpn);
    }

    for chunk in post_plaintext {
        server.writer().write_all(&chunk).expect("write app");
        while server.wants_write() {
            outbound.clear();
            let _ = server.write_tls(&mut outbound).expect("flush tls");
            if outbound.is_empty() {
                break;
            }
            stream.write_all(&outbound).await.expect("write socket");
        }
    }

    (sni, alpn)
}

async fn run_probe(
    ca: &MockProbeCa,
    addr: SocketAddr,
    server_name: &str,
    alpn: RealityAlpnProfile,
) -> Vec<usize> {
    let mut key = probe_key(server_name, alpn);
    key.dest_addr = addr.to_string();
    execute_post_handshake_probe_with_roots(&probe_dial(addr), &key, ca.roots.clone())
        .await
        .expect("probe ok")
}

#[tokio::test]
async fn successful_handshake_without_post_records_yields_empty_ready() {
    let ca = Arc::new(MockProbeCa::new());
    let server_config = ca.server_config(None);
    let (addr, _server) = spawn_mock_target(move |stream| {
        tokio::spawn(
            async move { drive_rustls_server(stream, server_config, Vec::new(), false).await },
        )
    })
    .await;

    let lengths = run_probe(&ca, addr, MOCK_SNI, RealityAlpnProfile::None).await;
    assert!(lengths.is_empty());
}

#[tokio::test]
async fn successful_handshake_with_one_post_record() {
    let ca = Arc::new(MockProbeCa::new());
    let server_config = ca.server_config(None);
    let (addr, _server) = spawn_mock_target(move |stream| {
        tokio::spawn(async move {
            drive_rustls_server(stream, server_config, vec![vec![0xAA; 64]], false).await
        })
    })
    .await;

    let lengths = run_probe(&ca, addr, MOCK_SNI, RealityAlpnProfile::None).await;
    assert_eq!(lengths.len(), 1);
    assert!(lengths[0] >= 5);
}

#[tokio::test]
async fn successful_handshake_with_multiple_post_records() {
    let ca = Arc::new(MockProbeCa::new());
    let server_config = ca.server_config(None);
    let (addr, _server) = spawn_mock_target(move |stream| {
        tokio::spawn(async move {
            drive_rustls_server(
                stream,
                server_config,
                vec![vec![0x01; 32], vec![0x02; 128], vec![0x03; 16]],
                false,
            )
            .await
        })
    })
    .await;

    let lengths = run_probe(&ca, addr, MOCK_SNI, RealityAlpnProfile::None).await;
    assert!(!lengths.is_empty());
}

#[tokio::test]
async fn connect_failure_completes_empty() {
    let ca = MockProbeCa::new();
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
    let addr = listener.local_addr().expect("addr");
    drop(listener);

    let key = PostHandshakeProbeKey {
        dest_addr: addr.to_string(),
        server_name: MOCK_SNI.to_string(),
        alpn_profile: RealityAlpnProfile::None,
    };
    let err = execute_post_handshake_probe_with_roots(&probe_dial(addr), &key, ca.roots.clone())
        .await
        .expect_err("connect should fail");
    assert_eq!(err.kind(), std::io::ErrorKind::ConnectionRefused);
}

#[tokio::test]
async fn tls_handshake_failure_returns_error() {
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
    let addr = listener.local_addr().expect("addr");
    tokio::spawn(async move {
        if let Ok((mut stream, _)) = listener.accept().await {
            let _ = stream.write_all(b"not-a-tls-handshake").await;
        }
    });

    let ca = MockProbeCa::new();
    let key = PostHandshakeProbeKey {
        dest_addr: addr.to_string(),
        server_name: MOCK_SNI.to_string(),
        alpn_profile: RealityAlpnProfile::None,
    };
    let err = execute_post_handshake_probe_with_roots(&probe_dial(addr), &key, ca.roots.clone())
        .await
        .expect_err("garbage server should fail");
    assert!(matches!(
        err.kind(),
        std::io::ErrorKind::InvalidData | std::io::ErrorKind::UnexpectedEof
    ));
}

#[tokio::test]
async fn capture_timeout_yields_empty_or_prefix_only() {
    let ca = Arc::new(MockProbeCa::new());
    let server_config = ca.server_config(None);
    let (addr, _server) = spawn_mock_target(move |stream| {
        tokio::spawn(
            async move { drive_rustls_server(stream, server_config, Vec::new(), true).await },
        )
    })
    .await;

    let lengths = run_probe(&ca, addr, MOCK_SNI, RealityAlpnProfile::None).await;
    assert!(lengths.is_empty());
}

#[tokio::test]
async fn sni_is_propagated_to_server() {
    let ca = Arc::new(MockProbeCa::new());
    let server_config = ca.server_config(None);
    let (tx, rx) = oneshot::channel();
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
    let addr = listener.local_addr().expect("addr");
    tokio::spawn(async move {
        if let Ok((stream, _)) = listener.accept().await {
            let (sni, _) = drive_rustls_server(stream, server_config, Vec::new(), false).await;
            let _ = tx.send(sni);
        }
    });

    let _ = run_probe(&ca, addr, MOCK_SNI, RealityAlpnProfile::None).await;
    assert_eq!(rx.await.expect("sni signal"), Some(MOCK_SNI.to_string()));
}

#[tokio::test]
async fn alpn_none_profile_offers_no_alpn() {
    let ca = Arc::new(MockProbeCa::new());
    let server_config = ca.server_config(Some(vec![b"http/1.1".to_vec()]));
    let (tx, rx) = oneshot::channel();
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
    let addr = listener.local_addr().expect("addr");
    tokio::spawn(async move {
        if let Ok((stream, _)) = listener.accept().await {
            let (_, alpn) = drive_rustls_server(stream, server_config, Vec::new(), false).await;
            let _ = tx.send(alpn);
        }
    });

    let _ = run_probe(&ca, addr, MOCK_SNI, RealityAlpnProfile::None).await;
    assert!(rx.await.expect("alpn signal").is_none());
}

#[tokio::test]
async fn alpn_http11_profile_negotiates_http11() {
    let ca = Arc::new(MockProbeCa::new());
    let server_config = ca.server_config(Some(vec![b"http/1.1".to_vec()]));
    let (tx, rx) = oneshot::channel();
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
    let addr = listener.local_addr().expect("addr");
    tokio::spawn(async move {
        if let Ok((stream, _)) = listener.accept().await {
            let (_, alpn) = drive_rustls_server(stream, server_config, Vec::new(), false).await;
            let _ = tx.send(alpn);
        }
    });

    let _ = run_probe(&ca, addr, MOCK_SNI, RealityAlpnProfile::Http11).await;
    assert_eq!(rx.await.expect("alpn signal"), Some(b"http/1.1".to_vec()));
}

#[tokio::test]
async fn alpn_h2_profile_prefers_h2() {
    let ca = Arc::new(MockProbeCa::new());
    let server_config = ca.server_config(Some(vec![b"h2".to_vec(), b"http/1.1".to_vec()]));
    let (tx, rx) = oneshot::channel();
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
    let addr = listener.local_addr().expect("addr");
    tokio::spawn(async move {
        if let Ok((stream, _)) = listener.accept().await {
            let (_, alpn) = drive_rustls_server(stream, server_config, Vec::new(), false).await;
            let _ = tx.send(alpn);
        }
    });

    let _ = run_probe(&ca, addr, MOCK_SNI, RealityAlpnProfile::H2).await;
    assert_eq!(rx.await.expect("alpn signal"), Some(b"h2".to_vec()));
}

#[tokio::test]
async fn cache_does_not_leak_detecting_after_probe_failure() {
    let cache = PostHandshakeProbeCache::new();
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
    let addr = listener.local_addr().expect("addr");
    drop(listener);

    let key = PostHandshakeProbeKey {
        dest_addr: addr.to_string(),
        server_name: MOCK_SNI.to_string(),
        alpn_profile: RealityAlpnProfile::Http11,
    };
    assert!(cache.try_begin_detection(key.clone()));

    let cache_clone = cache.clone();
    let dial = probe_dial(addr);
    let key_clone = key.clone();
    let ca = MockProbeCa::new();
    tokio::spawn(async move {
        let mut guard = ProbeGuard::new(cache_clone, key_clone);
        let result =
            execute_post_handshake_probe_with_roots(&dial, &guard.key, ca.roots.clone()).await;
        match result {
            Ok(lengths) => guard.complete_with(lengths),
            Err(_) => guard.complete_empty(),
        }
    });

    tokio::time::timeout(Duration::from_secs(3), async {
        loop {
            if cache.get(&key).is_some_and(|state| state.is_ready()) {
                break;
            }
            sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .expect("probe should complete cache entry");

    assert!(cache.get(&key).unwrap().is_ready());
}

struct ProbeGuard {
    cache: PostHandshakeProbeCache,
    key: PostHandshakeProbeKey,
    completed: bool,
}

impl ProbeGuard {
    fn new(cache: PostHandshakeProbeCache, key: PostHandshakeProbeKey) -> Self {
        Self {
            cache,
            key,
            completed: false,
        }
    }

    fn complete_with(&mut self, lengths: Vec<usize>) {
        self.cache.complete_detection(&self.key, lengths);
        self.completed = true;
    }

    fn complete_empty(&mut self) {
        self.cache.complete_detection_empty(&self.key);
        self.completed = true;
    }
}

impl Drop for ProbeGuard {
    fn drop(&mut self) {
        if !self.completed {
            self.cache.complete_detection_empty(&self.key);
        }
    }
}

#[test]
fn probe_lengths_from_capture_uses_prefix_on_trailing_partial() {
    let payload = 8usize;
    let mut record = vec![0x17, 0x03, 0x03];
    record.extend_from_slice(&(payload as u16).to_be_bytes());
    record.extend(vec![0xAA; payload]);
    let mut bytes = record.clone();
    bytes.extend_from_slice(&[0x17, 0x03, 0x03, 0x00, 0x10, 0x01]);

    let lengths = probe_lengths_from_capture(&bytes);
    assert_eq!(lengths, vec![record.len()]);
}
