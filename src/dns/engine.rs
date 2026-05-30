use std::collections::HashMap;
use std::net::{IpAddr, SocketAddr};
use std::sync::{Arc, OnceLock};

use std::time::{Duration, Instant};
use tokio::sync::Mutex;

use tokio::sync::Notify;
use tracing::{debug, trace, warn};

use crate::dns::cache::{CachedDnsResponse, DnsCache};
use crate::dns::config::{self};
use crate::dns::config::{DnsConfig, QueryStrategy};
use crate::dns::error::{DnsError, DnsQueryResponse};
use crate::dns::packet::{
    build_dns_query, extract_ipv4_addresses, extract_ipv6_addresses, inflight_key_from_packet,
    is_negative_dns_response, parse_dns_question_key, parse_response_min_ttl, DnsInflightKey,
    DnsQuestionKey,
};
use crate::dns::question::parse_dns_question_for_log;
use crate::dns::transport::DnsTransportStack;
use crate::dns::udp_transport::socket_addr_for_server;

const DEFAULT_CACHE_TTL: Duration = Duration::from_secs(30);
const NEGATIVE_CACHE_TTL: Duration = Duration::from_secs(30);

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DnsQuerySource {
    MuxUdp,
    BuiltinDns,
    Routing,
    OutboundResolution,
}

impl DnsQuerySource {
    fn as_str(self) -> &'static str {
        match self {
            Self::MuxUdp => "mux_udp",
            Self::BuiltinDns => "builtin_dns",
            Self::Routing => "routing",
            Self::OutboundResolution => "outbound_resolution",
        }
    }
}

#[derive(Debug, Clone)]
pub struct DnsQueryRequest {
    pub raw_query: Vec<u8>,
    pub destination: Option<SocketAddr>,
    pub inbound_tag: Option<String>,
    pub source: DnsQuerySource,
}

#[derive(Debug, Clone)]
pub struct DnsEngineOptions {
    pub default_timeout: Duration,
    pub max_retries: usize,
    pub cache_enabled: bool,
    pub cache_max_entries: usize,
    pub cache_min_ttl: Duration,
    pub cache_max_ttl: Duration,
}

impl Default for DnsEngineOptions {
    fn default() -> Self {
        Self {
            default_timeout: Duration::from_secs(5),
            max_retries: 1,
            cache_enabled: true,
            cache_max_entries: 4096,
            cache_min_ttl: Duration::from_secs(30),
            cache_max_ttl: Duration::from_secs(3600),
        }
    }
}

#[derive(Default)]
struct DnsMetrics {
    queries_total: u64,
    cache_hits_total: u64,
    cache_misses_total: u64,
    upstream_timeouts_total: u64,
    inflight_dedup_hits_total: u64,
}

struct InflightQuery {
    notify: Arc<Notify>,
    result: Mutex<Option<Result<CachedDnsResponse, DnsError>>>,
}

pub struct DnsEngine {
    config: DnsConfig,
    options: DnsEngineOptions,
    cache: DnsCache,
    transports: DnsTransportStack,
    inflight: Mutex<HashMap<DnsInflightKey, Arc<InflightQuery>>>,
    metrics: std::sync::Mutex<DnsMetrics>,
}

impl DnsEngine {
    pub fn new(config: DnsConfig, options: DnsEngineOptions) -> Self {
        Self {
            cache: DnsCache::new(options.cache_max_entries),
            config,
            options,
            transports: DnsTransportStack::default(),
            inflight: Mutex::new(HashMap::new()),
            metrics: std::sync::Mutex::new(DnsMetrics::default()),
        }
    }

    pub fn default_mux_config() -> DnsConfig {
        DnsConfig {
            servers: vec![config::parse_dns_server("1.1.1.1").expect("1.1.1.1 parses")],
            query_strategy: QueryStrategy::UseIP,
            disable_cache: false,
            extra: Default::default(),
        }
    }

    pub fn from_xray_config(dns: Option<&DnsConfig>) -> Self {
        let mut config = dns.cloned().unwrap_or_else(Self::default_mux_config);
        if config.servers.is_empty() {
            config.servers = Self::default_mux_config().servers;
        }
        Self::new(config, DnsEngineOptions::default())
    }

    pub fn with_mux_defaults() -> Self {
        Self::from_xray_config(None)
    }

    /// Initialize the process-wide engine from top-level `dns` config (first call wins).
    pub fn init_shared(dns: Option<&DnsConfig>) {
        static SHARED: OnceLock<Arc<DnsEngine>> = OnceLock::new();
        let _ = SHARED.get_or_init(|| Arc::new(Self::from_xray_config(dns)));
    }

    pub fn shared() -> Arc<Self> {
        static SHARED: OnceLock<Arc<DnsEngine>> = OnceLock::new();
        Arc::clone(SHARED.get_or_init(|| Arc::new(Self::with_mux_defaults())))
    }

    pub async fn query_raw(&self, request: DnsQueryRequest) -> Result<DnsQueryResponse, DnsError> {
        let started = Instant::now();
        let inflight_key = inflight_key_from_packet(&request.raw_query)?;
        let question = parse_dns_question_for_log(&request.raw_query);
        let response_server = self.response_socket_addr(&request)?;
        debug!(
            qname = question.as_ref().map(|q| q.qname.as_str()),
            qtype = question.as_ref().map(|q| q.qtype),
            %response_server,
            source = request.source.as_str(),
            inbound_tag = request.inbound_tag.as_deref(),
            cache_enabled = self.options.cache_enabled && !self.config.disable_cache,
            "dns query start"
        );
        self.record_query();

        if self.options.cache_enabled && !self.config.disable_cache {
            if let Some((hit, server_id)) = self.cache_lookup(&request.raw_query, &request) {
                self.record_cache_hit();
                debug!(
                    qname = %hit_key_qname(&inflight_key),
                    qtype = inflight_key.qtype,
                    server_id = %server_id,
                    source = request.source.as_str(),
                    "dns cache hit"
                );
                return Ok(self.to_query_response(hit, response_server, true, started.elapsed()));
            }
            self.record_cache_miss();
        }

        let leader = {
            let mut guard = self.inflight.lock().await;
            if let Some(existing) = guard.get(&inflight_key).cloned() {
                self.record_inflight_dedup_hit();
                debug!(
                    qname = %inflight_key.qname,
                    qtype = inflight_key.qtype,
                    source = request.source.as_str(),
                    "dns in-flight dedup hit"
                );
                drop(guard);
                return self
                    .wait_inflight(existing, response_server, started)
                    .await
                    .map(|cached| {
                        self.to_query_response(cached, response_server, false, started.elapsed())
                    });
            }
            let entry = Arc::new(InflightQuery {
                notify: Arc::new(Notify::new()),
                result: Mutex::new(None),
            });
            guard.insert(inflight_key.clone(), entry.clone());
            entry
        };

        let upstream = self
            .execute_upstream(&request, &request.raw_query)
            .await
            .map(|(raw, server_id)| {
                let cache_key =
                    parse_dns_question_key(&request.raw_query, server_id).expect("question key");
                self.store_in_cache(cache_key, raw)
            });
        {
            let mut guard = leader.result.lock().await;
            *guard = Some(match &upstream {
                Ok(cached) => Ok(cached.clone()),
                Err(err) => Err(err.clone()),
            });
        }
        leader.notify.notify_waiters();
        self.inflight.lock().await.remove(&inflight_key);

        let cached = upstream?;
        debug!(
            qname = %inflight_key.qname,
            qtype = inflight_key.qtype,
            %response_server,
            source = request.source.as_str(),
            cached = self.options.cache_enabled && !self.config.disable_cache,
            latency_ms = started.elapsed().as_millis(),
            "dns query completed"
        );
        Ok(self.to_query_response(cached, response_server, false, started.elapsed()))
    }

    /// Built-in lookup: `queryStrategy` controls which RR types are queried.
    /// Raw `query_raw` leaves the query packet unchanged (AsIs semantics).
    pub async fn lookup_ip(
        &self,
        domain: &str,
        strategy: QueryStrategy,
    ) -> Result<Vec<IpAddr>, DnsError> {
        match strategy {
            QueryStrategy::UseIPv4 => self.lookup_ips_for_qtype(domain, 1).await,
            QueryStrategy::UseIPv6 => self.lookup_ips_for_qtype(domain, 28).await,
            QueryStrategy::UseIP => {
                let mut ips = self
                    .lookup_ips_for_qtype(domain, 1)
                    .await
                    .unwrap_or_default();
                ips.extend(
                    self.lookup_ips_for_qtype(domain, 28)
                        .await
                        .unwrap_or_default(),
                );
                if ips.is_empty() {
                    return Err(DnsError::ServerFailed);
                }
                Ok(ips)
            }
            QueryStrategy::UseSystem => {
                debug!(
                    domain,
                    "dns queryStrategy UseSystem mapped conservatively to A (IPv4) only"
                );
                self.lookup_ips_for_qtype(domain, 1).await
            }
        }
    }

    async fn lookup_ips_for_qtype(
        &self,
        domain: &str,
        qtype: u16,
    ) -> Result<Vec<IpAddr>, DnsError> {
        let raw_query = build_dns_query(domain, qtype)?;
        let response = self
            .query_raw(DnsQueryRequest {
                raw_query,
                destination: None,
                inbound_tag: None,
                source: DnsQuerySource::BuiltinDns,
            })
            .await?;
        let ips = if qtype == 28 {
            extract_ipv6_addresses(&response.raw_response)
        } else {
            extract_ipv4_addresses(&response.raw_response)
        };
        if ips.is_empty() {
            return Err(DnsError::ServerFailed);
        }
        Ok(ips)
    }

    pub async fn resolve_mux_udp_dns(
        &self,
        mux_id: u16,
        destination: SocketAddr,
        payload: &[u8],
    ) -> Result<DnsQueryResponse, DnsError> {
        trace!(mux_id, %destination, payload_len = payload.len(), "mux udp dns engine resolve");
        self.query_raw(DnsQueryRequest {
            raw_query: payload.to_vec(),
            destination: Some(destination),
            inbound_tag: None,
            source: DnsQuerySource::MuxUdp,
        })
        .await
    }

    fn to_query_response(
        &self,
        cached: CachedDnsResponse,
        server: SocketAddr,
        cached_flag: bool,
        latency: Duration,
    ) -> DnsQueryResponse {
        DnsQueryResponse {
            raw_response: cached.raw_response,
            server,
            cached: cached_flag,
            latency,
        }
    }

    async fn wait_inflight(
        &self,
        entry: Arc<InflightQuery>,
        _server: SocketAddr,
        _started: Instant,
    ) -> Result<CachedDnsResponse, DnsError> {
        loop {
            if let Some(result) = entry.result.lock().await.clone() {
                return result;
            }
            entry.notify.notified().await;
            if let Some(result) = entry.result.lock().await.clone() {
                return result;
            }
        }
    }

    async fn execute_upstream(
        &self,
        request: &DnsQueryRequest,
        query: &[u8],
    ) -> Result<(Vec<u8>, String), DnsError> {
        if let Some(destination) = request.destination {
            let mut attempt = 0usize;
            loop {
                let result = {
                    let mut udp = self.transports.udp.lock().await;
                    udp.query_at(destination, query, self.options.default_timeout)
                        .await
                };
                match result {
                    Ok(response) => {
                        return Ok((response, format!("mux:{destination}")));
                    }
                    Err(DnsError::Timeout) => {
                        self.record_timeout();
                        if attempt >= self.options.max_retries {
                            return Err(DnsError::Timeout);
                        }
                    }
                    Err(err) => return Err(err),
                }
                attempt += 1;
            }
        }

        let mut last_err: Option<DnsError> = None;
        for server in &self.config.servers {
            if !DnsTransportStack::is_supported(&server.transport) {
                trace!(
                    transport = server.transport.label(),
                    dns_server = %server.original,
                    "dns upstream skipping unsupported transport"
                );
                last_err = Some(DnsError::UnsupportedTransport(format!(
                    "DNS transport {} is parsed but not implemented yet",
                    server.transport.label()
                )));
                continue;
            }

            let mut attempt = 0usize;
            loop {
                match self
                    .transports
                    .query(query, server, self.options.default_timeout)
                    .await
                {
                    Ok(response) => return Ok((response, server.original.clone())),
                    Err(err @ DnsError::MalformedQuery) => return Err(err),
                    Err(err @ DnsError::Timeout) => {
                        self.record_timeout();
                        last_err = Some(err);
                        if attempt >= self.options.max_retries {
                            break;
                        }
                    }
                    Err(err @ (DnsError::Upstream | DnsError::ServerFailed)) => {
                        warn!(
                            transport = server.transport.label(),
                            dns_server = %server.original,
                            error = %err,
                            "dns upstream server failed; trying next server"
                        );
                        last_err = Some(err);
                        break;
                    }
                    Err(err @ DnsError::UnsupportedTransport(_)) => {
                        trace!(
                            transport = server.transport.label(),
                            dns_server = %server.original,
                            error = %err,
                            "dns upstream skipping unsupported transport"
                        );
                        last_err = Some(err);
                        break;
                    }
                    Err(err @ DnsError::Io(_, _)) => {
                        warn!(
                            transport = server.transport.label(),
                            dns_server = %server.original,
                            error = %err,
                            "dns upstream I/O error; trying next server"
                        );
                        last_err = Some(err);
                        break;
                    }
                }
                attempt += 1;
            }
        }

        Err(last_err.unwrap_or_else(|| {
            DnsError::UnsupportedTransport(
                "dns.servers must contain at least one supported UDP or TCP server".to_string(),
            )
        }))
    }

    fn cache_lookup(
        &self,
        packet: &[u8],
        request: &DnsQueryRequest,
    ) -> Option<(CachedDnsResponse, String)> {
        for server_id in self.cache_server_ids(request) {
            let key = parse_dns_question_key(packet, server_id.clone()).ok()?;
            if let Some(hit) = self.cache.get(&key) {
                return Some((hit, server_id));
            }
        }
        None
    }

    fn cache_server_ids(&self, request: &DnsQueryRequest) -> Vec<String> {
        if let Some(destination) = request.destination {
            return vec![format!("mux:{destination}")];
        }
        self.config
            .servers
            .iter()
            .map(|server| server.original.clone())
            .collect()
    }

    fn response_socket_addr(&self, request: &DnsQueryRequest) -> Result<SocketAddr, DnsError> {
        if let Some(destination) = request.destination {
            return Ok(destination);
        }
        for server in &self.config.servers {
            if DnsTransportStack::is_supported(&server.transport) {
                return socket_addr_for_server(&server.host, server.port);
            }
        }
        socket_addr_for_server("1.1.1.1", 53)
    }

    fn store_in_cache(&self, key: DnsQuestionKey, raw: Vec<u8>) -> CachedDnsResponse {
        if !self.options.cache_enabled || self.config.disable_cache {
            return CachedDnsResponse {
                raw_response: raw,
                expires_at: Instant::now() + DEFAULT_CACHE_TTL,
                original_ttl: DEFAULT_CACHE_TTL,
            };
        }
        let ttl = self.ttl_for_response(&raw);
        self.cache.insert(key, raw, ttl)
    }

    fn ttl_for_response(&self, raw: &[u8]) -> Duration {
        if is_negative_dns_response(raw) {
            return NEGATIVE_CACHE_TTL;
        }
        let ttl_secs = parse_response_min_ttl(raw).unwrap_or(DEFAULT_CACHE_TTL.as_secs() as u32);
        let ttl = Duration::from_secs(u64::from(ttl_secs));
        ttl.clamp(self.options.cache_min_ttl, self.options.cache_max_ttl)
    }

    fn record_query(&self) {
        self.metrics.lock().expect("dns metrics lock").queries_total += 1;
    }

    fn record_cache_hit(&self) {
        self.metrics
            .lock()
            .expect("dns metrics lock")
            .cache_hits_total += 1;
    }

    fn record_cache_miss(&self) {
        self.metrics
            .lock()
            .expect("dns metrics lock")
            .cache_misses_total += 1;
    }

    fn record_timeout(&self) {
        self.metrics
            .lock()
            .expect("dns metrics lock")
            .upstream_timeouts_total += 1;
    }

    fn record_inflight_dedup_hit(&self) {
        self.metrics
            .lock()
            .expect("dns metrics lock")
            .inflight_dedup_hits_total += 1;
    }
}

fn hit_key_qname(key: &DnsInflightKey) -> &str {
    &key.qname
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr};
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::Arc;

    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::{TcpListener, UdpSocket};

    fn example_query() -> Vec<u8> {
        let mut packet = vec![
            0x12, 0x34, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        ];
        packet.extend_from_slice(&[
            7, b'e', b'x', b'a', b'm', b'p', b'l', b'e', 3, b'c', b'o', b'm', 0, 0, 1, 0, 1,
        ]);
        packet
    }

    fn example_query_aaaa() -> Vec<u8> {
        let mut packet = example_query();
        let len = packet.len();
        packet[len - 2] = 0;
        packet[len - 1] = 28;
        packet
    }

    fn example_response() -> Vec<u8> {
        vec![
            0x12, 0x34, 0x81, 0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        ]
    }

    fn response_with_a(ip: [u8; 4]) -> Vec<u8> {
        let mut packet = example_query();
        packet[2] = 0x81;
        packet[3] = 0x80;
        packet[6] = 0x00;
        packet[7] = 0x01;
        packet.extend_from_slice(&[
            0xc0, 0x0c, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00, 0x3c, 0x00, 0x04,
        ]);
        packet.extend_from_slice(&ip);
        packet
    }

    fn response_with_aaaa(ip: [u8; 16]) -> Vec<u8> {
        let mut packet = example_query_aaaa();
        packet[2] = 0x81;
        packet[3] = 0x80;
        packet[6] = 0x00;
        packet[7] = 0x01;
        packet.extend_from_slice(&[
            0xc0, 0x0c, 0x00, 0x1c, 0x00, 0x01, 0x00, 0x00, 0x00, 0x3c, 0x00, 0x10,
        ]);
        packet.extend_from_slice(&ip);
        packet
    }

    #[tokio::test]
    async fn cache_hit_by_qname_qtype() {
        let engine = DnsEngine::new(
            DnsConfig {
                servers: vec![config::parse_dns_server("127.0.0.1").unwrap()],
                query_strategy: QueryStrategy::UseIP,
                disable_cache: false,
                extra: Default::default(),
            },
            DnsEngineOptions::default(),
        );
        let destination = SocketAddr::from((Ipv4Addr::LOCALHOST, 53));
        let key = parse_dns_question_key(&example_query(), format!("mux:{destination}")).unwrap();
        engine
            .cache
            .insert(key, example_response(), Duration::from_secs(60));

        let response = engine
            .query_raw(DnsQueryRequest {
                raw_query: example_query(),
                destination: Some(destination),
                inbound_tag: None,
                source: DnsQuerySource::MuxUdp,
            })
            .await
            .unwrap();
        assert!(response.cached);
        assert_eq!(response.raw_response, example_response());
    }

    #[tokio::test]
    async fn cache_isolated_per_qtype() {
        let engine = DnsEngine::new(
            DnsConfig {
                servers: vec![config::parse_dns_server("127.0.0.1").unwrap()],
                query_strategy: QueryStrategy::UseIP,
                disable_cache: false,
                extra: Default::default(),
            },
            DnsEngineOptions::default(),
        );
        let a_query = build_dns_query("example.com", 1).unwrap();
        let aaaa_query = build_dns_query("example.com", 28).unwrap();
        let a_key = parse_dns_question_key(&a_query, "127.0.0.1").unwrap();
        let aaaa_key = parse_dns_question_key(&aaaa_query, "127.0.0.1").unwrap();
        engine.cache.insert(
            a_key,
            response_with_a([1, 1, 1, 1]),
            Duration::from_secs(60),
        );
        engine.cache.insert(
            aaaa_key,
            response_with_aaaa([0x20, 0x01, 0x48, 0x60, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1]),
            Duration::from_secs(60),
        );

        let a_response = engine
            .lookup_ip("example.com", QueryStrategy::UseIPv4)
            .await
            .unwrap();
        assert_eq!(a_response, vec![IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1))]);

        let aaaa_response = engine
            .lookup_ip("example.com", QueryStrategy::UseIPv6)
            .await
            .unwrap();
        assert_eq!(
            aaaa_response,
            vec![IpAddr::V6(Ipv6Addr::new(0x2001, 0x4860, 0, 0, 0, 0, 0, 1))]
        );
    }

    #[tokio::test]
    async fn lookup_ip_use_ip_queries_both_types() {
        let engine = DnsEngine::new(
            DnsConfig {
                servers: vec![config::parse_dns_server("127.0.0.1").unwrap()],
                query_strategy: QueryStrategy::UseIP,
                disable_cache: false,
                extra: Default::default(),
            },
            DnsEngineOptions::default(),
        );
        let a_query = build_dns_query("example.com", 1).unwrap();
        let aaaa_query = build_dns_query("example.com", 28).unwrap();
        let a_key = parse_dns_question_key(&a_query, "127.0.0.1").unwrap();
        let aaaa_key = parse_dns_question_key(&aaaa_query, "127.0.0.1").unwrap();
        engine.cache.insert(
            a_key,
            response_with_a([1, 0, 0, 1]),
            Duration::from_secs(60),
        );
        engine.cache.insert(
            aaaa_key,
            response_with_aaaa([0x20, 0x01, 0x48, 0x60, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2]),
            Duration::from_secs(60),
        );

        let ips = engine
            .lookup_ip("example.com", QueryStrategy::UseIP)
            .await
            .unwrap();
        assert_eq!(ips.len(), 2);
        assert!(ips.contains(&IpAddr::V4(Ipv4Addr::new(1, 0, 0, 1))));
        assert!(ips.contains(&IpAddr::V6(Ipv6Addr::new(0x2001, 0x4860, 0, 0, 0, 0, 0, 2))));
    }

    #[tokio::test]
    async fn disable_cache_bypasses_cache() {
        let engine = DnsEngine::new(
            DnsConfig {
                servers: vec![config::parse_dns_server("127.0.0.1").unwrap()],
                query_strategy: QueryStrategy::UseIP,
                disable_cache: true,
                extra: Default::default(),
            },
            DnsEngineOptions {
                default_timeout: Duration::from_millis(200),
                max_retries: 0,
                ..DnsEngineOptions::default()
            },
        );
        let key = parse_dns_question_key(&example_query(), "127.0.0.1").unwrap();
        engine
            .cache
            .insert(key, example_response(), Duration::from_secs(60));

        let err = engine
            .query_raw(DnsQueryRequest {
                raw_query: example_query(),
                destination: Some(SocketAddr::from((Ipv4Addr::LOCALHOST, 9))),
                inbound_tag: None,
                source: DnsQuerySource::MuxUdp,
            })
            .await
            .unwrap_err();
        assert_eq!(err, DnsError::Timeout);
    }

    #[tokio::test]
    async fn fake_udp_server_returns_response() {
        let upstream_count = Arc::new(AtomicUsize::new(0));
        let upstream_task = Arc::clone(&upstream_count);
        let udp = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let port = udp.local_addr().unwrap().port();
        let expected_query = example_query();
        let expected_response = example_response();
        let query_task = expected_query.clone();
        let response_task = expected_response.clone();

        tokio::spawn(async move {
            let mut buf = [0u8; 512];
            let (read, peer) = udp.recv_from(&mut buf).await.unwrap();
            upstream_task.fetch_add(1, Ordering::SeqCst);
            assert_eq!(&buf[..read], query_task.as_slice());
            udp.send_to(&response_task, peer).await.unwrap();
        });

        let engine = DnsEngine::new(
            DnsConfig {
                servers: vec![config::parse_dns_server("127.0.0.1").unwrap()],
                query_strategy: QueryStrategy::UseIP,
                disable_cache: false,
                extra: Default::default(),
            },
            DnsEngineOptions {
                default_timeout: Duration::from_secs(2),
                max_retries: 0,
                ..DnsEngineOptions::default()
            },
        );

        let response = engine
            .resolve_mux_udp_dns(
                3,
                SocketAddr::from((Ipv4Addr::LOCALHOST, port)),
                &expected_query,
            )
            .await
            .unwrap();
        assert_eq!(response.raw_response, expected_response);
        assert_eq!(upstream_count.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn tcp_dns_server_returns_response() {
        use crate::dns::tcp_codec::encode_dns_tcp_frame;

        let expected_query = example_query();
        let expected_response = example_response();
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let query_task = expected_query.clone();
        let response_task = expected_response.clone();
        let want_response = expected_response.clone();
        tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            let mut buf = vec![0u8; 512];
            let read = stream.read(&mut buf).await.unwrap();
            assert_eq!(&buf[..read], encode_dns_tcp_frame(&query_task).unwrap());
            stream
                .write_all(&encode_dns_tcp_frame(&response_task).unwrap())
                .await
                .unwrap();
        });

        let engine = DnsEngine::new(
            DnsConfig {
                servers: vec![config::parse_dns_server(&format!(
                    "tcp://127.0.0.1:{}",
                    addr.port()
                ))
                .unwrap()],
                query_strategy: QueryStrategy::UseIP,
                disable_cache: false,
                extra: Default::default(),
            },
            DnsEngineOptions {
                default_timeout: Duration::from_secs(2),
                max_retries: 0,
                ..DnsEngineOptions::default()
            },
        );

        let response = engine
            .query_raw(DnsQueryRequest {
                raw_query: example_query(),
                destination: None,
                inbound_tag: None,
                source: DnsQuerySource::BuiltinDns,
            })
            .await
            .unwrap();
        assert_eq!(response.raw_response, want_response);
    }

    #[tokio::test]
    async fn server_failover_after_timeout() {
        let good = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let good_port = good.local_addr().unwrap().port();
        let expected_query = example_query();
        let want_response = example_response();
        let response_for_task = want_response.clone();
        tokio::spawn(async move {
            let mut buf = [0u8; 512];
            let (read, peer) = good.recv_from(&mut buf).await.unwrap();
            assert_eq!(&buf[..read], expected_query.as_slice());
            good.send_to(&response_for_task, peer).await.unwrap();
        });

        let engine = DnsEngine::new(
            DnsConfig {
                servers: vec![
                    config::parse_dns_server("127.0.0.1:9").unwrap(),
                    config::parse_dns_server(&format!("127.0.0.1:{good_port}")).unwrap(),
                ],
                query_strategy: QueryStrategy::UseIP,
                disable_cache: false,
                extra: Default::default(),
            },
            DnsEngineOptions {
                default_timeout: Duration::from_millis(150),
                max_retries: 0,
                ..DnsEngineOptions::default()
            },
        );

        let response = engine
            .query_raw(DnsQueryRequest {
                raw_query: example_query(),
                destination: None,
                inbound_tag: None,
                source: DnsQuerySource::BuiltinDns,
            })
            .await
            .unwrap();
        assert_eq!(response.raw_response, want_response);
    }

    #[tokio::test]
    async fn doh_server_returns_explicit_unsupported() {
        let engine = DnsEngine::new(
            DnsConfig {
                servers: vec![config::parse_dns_server("https://dns.google/dns-query").unwrap()],
                query_strategy: QueryStrategy::UseIP,
                disable_cache: false,
                extra: Default::default(),
            },
            DnsEngineOptions::default(),
        );
        let err = engine
            .query_raw(DnsQueryRequest {
                raw_query: example_query(),
                destination: None,
                inbound_tag: None,
                source: DnsQuerySource::BuiltinDns,
            })
            .await
            .unwrap_err();
        assert!(matches!(
            err,
            DnsError::UnsupportedTransport(message) if message.contains("not implemented")
        ));
    }

    #[tokio::test]
    async fn concurrent_identical_queries_deduplicate_upstream() {
        let upstream_count = Arc::new(AtomicUsize::new(0));
        let upstream_task = Arc::clone(&upstream_count);
        let udp = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let port = udp.local_addr().unwrap().port();
        let expected_query = example_query();
        let expected_response = example_response();
        let query_task = expected_query.clone();
        let response_task = expected_response.clone();

        tokio::spawn(async move {
            let mut buf = [0u8; 512];
            loop {
                let (read, peer) = match udp.recv_from(&mut buf).await {
                    Ok(value) => value,
                    Err(_) => break,
                };
                upstream_task.fetch_add(1, Ordering::SeqCst);
                assert_eq!(&buf[..read], query_task.as_slice());
                udp.send_to(&response_task, peer).await.unwrap();
            }
        });

        let engine = Arc::new(DnsEngine::new(
            DnsConfig {
                servers: vec![config::parse_dns_server("127.0.0.1").unwrap()],
                query_strategy: QueryStrategy::UseIP,
                disable_cache: true,
                extra: Default::default(),
            },
            DnsEngineOptions {
                default_timeout: Duration::from_secs(2),
                max_retries: 0,
                cache_enabled: false,
                ..DnsEngineOptions::default()
            },
        ));

        let destination = SocketAddr::from((Ipv4Addr::LOCALHOST, port));
        let mut handles = Vec::new();
        for _ in 0..4 {
            let engine = Arc::clone(&engine);
            let query = expected_query.clone();
            handles.push(tokio::spawn(async move {
                engine.resolve_mux_udp_dns(1, destination, &query).await
            }));
        }
        for handle in handles {
            assert_eq!(
                handle.await.unwrap().unwrap().raw_response,
                expected_response
            );
        }
        assert_eq!(upstream_count.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn timeout_returns_dns_error_timeout() {
        let engine = DnsEngine::new(
            DnsConfig {
                servers: vec![config::parse_dns_server("127.0.0.1").unwrap()],
                query_strategy: QueryStrategy::UseIP,
                disable_cache: false,
                extra: Default::default(),
            },
            DnsEngineOptions {
                default_timeout: Duration::from_millis(100),
                max_retries: 0,
                ..DnsEngineOptions::default()
            },
        );
        let err = engine
            .resolve_mux_udp_dns(
                1,
                SocketAddr::from((Ipv4Addr::new(127, 0, 0, 1), 9)),
                &example_query(),
            )
            .await
            .unwrap_err();
        assert_eq!(err, DnsError::Timeout);
    }

    #[tokio::test]
    async fn malformed_query_rejected() {
        let engine = DnsEngine::with_mux_defaults();
        let err = engine
            .resolve_mux_udp_dns(
                1,
                SocketAddr::from((Ipv4Addr::new(1, 1, 1, 1), 53)),
                &[0x00, 0x01],
            )
            .await
            .unwrap_err();
        assert_eq!(err, DnsError::MalformedQuery);
    }
}
