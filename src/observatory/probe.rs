use std::sync::Arc;
use std::time::{Duration, Instant};

use http::{Method, Uri};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::time::timeout;

use std::io::{Read, Write};

use crate::outbound::runtime::OutboundConnectRuntime;
use crate::routing::{connect_routed_outbound, RoutedOutbound};
use crate::runtime::RuntimeOutboundManager;
use crate::vless::protocol::VlessDestination;

pub const PROBE_HTTP_TIMEOUT: Duration = Duration::from_secs(5);
pub const DEAD_PROBE_DELAY_MS: i64 = 99_999_999;

#[derive(Debug, Clone)]
pub struct HttpProbeOptions {
    pub method: Method,
    pub timeout: Duration,
}

impl HttpProbeOptions {
    pub fn parse_method(raw: &str, default: &str) -> Result<Self, String> {
        let method_raw = if raw.trim().is_empty() {
            default
        } else {
            raw.trim()
        };
        let method = Method::from_bytes(method_raw.as_bytes())
            .map_err(|_| format!("invalid HTTP method: {method_raw}"))?;
        Ok(Self {
            method,
            timeout: PROBE_HTTP_TIMEOUT,
        })
    }

    pub fn with_timeout(mut self, timeout: Duration) -> Self {
        self.timeout = timeout;
        self
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProbeResult {
    pub alive: bool,
    pub delay_ms: i64,
    pub last_error_reason: String,
}

impl ProbeResult {
    pub fn alive(delay_ms: i64) -> Self {
        Self {
            alive: true,
            delay_ms,
            last_error_reason: String::new(),
        }
    }

    pub fn dead(outbound_tag: &str, reason: impl Into<String>) -> Self {
        let reason = reason.into();
        Self {
            alive: false,
            delay_ms: DEAD_PROBE_DELAY_MS,
            last_error_reason: format!(
                "the outbound {outbound_tag} is dead: GET request failed:{reason}with outbound handler report underlying connection failed"
            ),
        }
    }
}

pub async fn measure_delay_tagged(
    outbound_tag: &str,
    destination: &str,
    options: &HttpProbeOptions,
    outbound_manager: Arc<RuntimeOutboundManager>,
    connect_runtime: Arc<OutboundConnectRuntime>,
) -> Result<Duration, String> {
    timeout(
        options.timeout,
        measure_delay_tagged_unbounded(
            outbound_tag,
            destination,
            options,
            outbound_manager,
            connect_runtime,
        ),
    )
    .await
    .map_err(|_| "probe timed out".to_string())?
}

pub async fn measure_delay_direct(
    destination: &str,
    options: &HttpProbeOptions,
) -> Result<Duration, String> {
    timeout(
        options.timeout,
        measure_delay_direct_unbounded(destination, options),
    )
    .await
    .map_err(|_| "probe timed out".to_string())?
}

async fn measure_delay_tagged_unbounded(
    outbound_tag: &str,
    destination: &str,
    options: &HttpProbeOptions,
    outbound_manager: Arc<RuntimeOutboundManager>,
    connect_runtime: Arc<OutboundConnectRuntime>,
) -> Result<Duration, String> {
    let uri = parse_destination_uri(destination)?;
    let host = uri
        .host()
        .ok_or_else(|| "probe URL missing host".to_string())?;
    let port = default_port(&uri);
    let path = uri.path_and_query().map(|pq| pq.as_str()).unwrap_or("/");
    let vless_destination = vless_destination_from_host(host, port);

    let routed = connect_routed_outbound(
        outbound_tag,
        &vless_destination,
        outbound_manager.as_ref(),
        Arc::clone(&connect_runtime),
    )
    .await
    .map_err(|err| format!("cannot dial remote address: {err}"))?;

    match routed {
        RoutedOutbound::Blackhole => Err("blackhole outbound cannot relay probe".to_string()),
        RoutedOutbound::Tcp(stream) => {
            if uri.scheme_str() == Some("https") {
                https_request(stream, host, path, options).await
            } else {
                http_request(stream, path, options).await
            }
        }
    }
}

async fn measure_delay_direct_unbounded(
    destination: &str,
    options: &HttpProbeOptions,
) -> Result<Duration, String> {
    let uri = parse_destination_uri(destination)?;
    let host = uri
        .host()
        .ok_or_else(|| "probe URL missing host".to_string())?;
    let port = default_port(&uri);
    let path = uri.path_and_query().map(|pq| pq.as_str()).unwrap_or("/");
    let vless_destination = vless_destination_from_host(host, port);
    let connect_runtime = OutboundConnectRuntime::shared();
    let stream = crate::outbound::freedom::connect_tcp_destination_with_runtime(
        &vless_destination,
        connect_runtime,
    )
    .await
    .map_err(|err| format!("direct connectivity probe failed: {err}"))?;
    if uri.scheme_str() == Some("https") {
        https_request(stream, host, path, options).await
    } else {
        http_request(stream, path, options).await
    }
}

pub async fn probe_outbound(
    outbound_tag: &str,
    probe_url: &str,
    outbound_manager: Arc<RuntimeOutboundManager>,
    connect_runtime: Arc<OutboundConnectRuntime>,
) -> ProbeResult {
    let options = HttpProbeOptions {
        method: Method::GET,
        timeout: PROBE_HTTP_TIMEOUT,
    };
    let started = Instant::now();
    match measure_delay_tagged(
        outbound_tag,
        probe_url,
        &options,
        outbound_manager,
        connect_runtime,
    )
    .await
    {
        Ok(_) => ProbeResult::alive(started.elapsed().as_millis() as i64),
        Err(reason) => ProbeResult::dead(outbound_tag, reason),
    }
}

fn parse_destination_uri(destination: &str) -> Result<Uri, String> {
    destination
        .parse::<Uri>()
        .map_err(|err| format!("invalid probe URL: {err}"))
}

fn default_port(uri: &Uri) -> u16 {
    uri.port_u16().unwrap_or_else(|| {
        if uri.scheme_str() == Some("https") {
            443
        } else {
            80
        }
    })
}

fn vless_destination_from_host(host: &str, port: u16) -> VlessDestination {
    if let Ok(ip) = host.parse() {
        VlessDestination::Ip(ip, port)
    } else {
        VlessDestination::Domain(host.to_string(), port)
    }
}

async fn http_request(
    mut stream: TcpStream,
    path: &str,
    options: &HttpProbeOptions,
) -> Result<Duration, String> {
    let started = Instant::now();
    let request = format!(
        "{} {path} HTTP/1.1\r\nHost: probe\r\nUser-Agent: rust-xray-observatory\r\nConnection: close\r\n\r\n",
        options.method
    );
    stream
        .write_all(request.as_bytes())
        .await
        .map_err(|err| err.to_string())?;
    read_http_response(&mut stream, options).await?;
    Ok(started.elapsed())
}

async fn https_request(
    stream: TcpStream,
    host: &str,
    path: &str,
    options: &HttpProbeOptions,
) -> Result<Duration, String> {
    use rustls::pki_types::ServerName;
    use rustls::{ClientConfig, RootCertStore};

    let started = Instant::now();
    let mut root_store = RootCertStore::empty();
    root_store.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
    let config = ClientConfig::builder()
        .with_root_certificates(root_store)
        .with_no_client_auth();
    let server_name = ServerName::try_from(host.to_string()).map_err(|err| err.to_string())?;
    let mut connection = rustls::ClientConnection::new(Arc::new(config), server_name)
        .map_err(|err| err.to_string())?;

    let mut stream = stream;
    let request = format!(
        "{} {path} HTTP/1.1\r\nHost: {host}\r\nUser-Agent: rust-xray-observatory\r\nConnection: close\r\n\r\n",
        options.method
    );

    drive_tls_handshake(&mut connection, &mut stream).await?;
    connection
        .writer()
        .write_all(request.as_bytes())
        .map_err(|err| err.to_string())?;
    connection.writer().flush().map_err(|err| err.to_string())?;
    drive_tls_io(&mut connection, &mut stream).await?;

    let mut response = Vec::new();
    loop {
        let mut chunk = [0_u8; 1024];
        match connection.reader().read(&mut chunk) {
            Ok(0) => break,
            Ok(n) => response.extend_from_slice(&chunk[..n]),
            Err(err) if err.kind() == std::io::ErrorKind::WouldBlock => {
                drive_tls_io(&mut connection, &mut stream).await?;
            }
            Err(err) => return Err(err.to_string()),
        }
        if response.len() > 8192 {
            break;
        }
    }
    validate_status_line(&response)?;
    if options.method == Method::GET {
        // GET probes drain the body in upstream MeasureDelay.
    }
    Ok(started.elapsed())
}

async fn read_http_response(
    stream: &mut TcpStream,
    options: &HttpProbeOptions,
) -> Result<(), String> {
    let mut buf = [0_u8; 1024];
    let n = stream.read(&mut buf).await.map_err(|err| err.to_string())?;
    if n == 0 {
        return Err("empty HTTP response".to_string());
    }
    validate_status_line(&buf[..n])?;
    if options.method == Method::GET {
        // Upstream drains body for GET; best-effort discard for parity.
        let mut drain = [0_u8; 1024];
        while stream.read(&mut drain).await.unwrap_or(0) > 0 {}
    }
    Ok(())
}

fn validate_status_line(response: &[u8]) -> Result<(), String> {
    let status_line = std::str::from_utf8(response)
        .map_err(|err| err.to_string())?
        .lines()
        .next()
        .unwrap_or_default()
        .to_string();
    if !status_line.starts_with("HTTP/") {
        return Err(format!("invalid HTTP response: {status_line}"));
    }
    Ok(())
}

async fn drive_tls_handshake(
    connection: &mut rustls::ClientConnection,
    stream: &mut TcpStream,
) -> Result<(), String> {
    while connection.is_handshaking() {
        drive_tls_io(connection, stream).await?;
    }
    Ok(())
}

async fn drive_tls_io(
    connection: &mut rustls::ClientConnection,
    stream: &mut TcpStream,
) -> Result<(), String> {
    while connection.wants_write() {
        let mut tls_out = Vec::new();
        connection
            .write_tls(&mut tls_out)
            .map_err(|err| err.to_string())?;
        if !tls_out.is_empty() {
            stream
                .write_all(&tls_out)
                .await
                .map_err(|err| err.to_string())?;
        }
    }

    let mut tls_in = [0_u8; 4096];
    let n = stream
        .read(&mut tls_in)
        .await
        .map_err(|err| err.to_string())?;
    if n > 0 {
        let mut cursor = &tls_in[..n];
        connection
            .read_tls(&mut cursor)
            .map_err(|err| err.to_string())?;
    }
    connection
        .process_new_packets()
        .map_err(|err| err.to_string())?;
    Ok(())
}
