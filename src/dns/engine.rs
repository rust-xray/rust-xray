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
use crate::dns::mux_upstream::{build_mux_udp_candidates, execute_mux_udp_upstream};
use crate::dns::options::DnsEngineOptions;
use crate::dns::packet::{
    build_dns_query, extract_ipv4_addresses, extract_ipv6_addresses, inflight_key_from_packet,
    is_negative_dns_response, parse_dns_question_key, parse_response_min_ttl,
    rewrite_dns_response_id_for_query, DnsInflightKey, DnsQuestionKey,
};
use crate::dns::question::parse_dns_question_for_log;
use crate::dns::transport::DnsTransportStack;
use crate::dns::udp_transport::socket_addr_for_server;

const DEFAULT_CACHE_TTL: Duration = Duration::from_secs(30);
const NEGATIVE_CACHE_TTL: Duration = Duration::from_secs(30);

static SHARED_DNS_ENGINE: OnceLock<Arc<DnsEngine>> = OnceLock::new();

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

#[derive(Debug, Clone, Copy)]
pub struct DnsQueryTrace {
    pub conn_id: u64,
    pub mux_id: Option<u16>,
    pub conn_started: Instant,
    pub dns_started: Instant,
}

impl DnsQueryTrace {
    fn elapsed_ms_since_conn_start(self) -> u128 {
        self.conn_started.elapsed().as_millis()
    }

    fn elapsed_ms_since_dns_start(self) -> u128 {
        self.dns_started.elapsed().as_millis()
    }
}

#[derive(Debug, Clone)]
pub struct DnsQueryRequest {
    pub raw_query: Vec<u8>,
    pub destination: Option<SocketAddr>,
    pub inbound_tag: Option<String>,
    pub source: DnsQuerySource,
    pub trace: Option<DnsQueryTrace>,
}

#[derive(Debug, Clone, Copy)]
struct UpstreamPolicy {
    timeout: Duration,
    max_retries: usize,
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
    pub fn init_shared(dns: Option<&DnsConfig>) -> Arc<DnsEngine> {
        let owned = dns.cloned();
        Arc::clone(SHARED_DNS_ENGINE.get_or_init(|| {
            crate::dns::options::log_mux_dns_startup_options();
            Arc::new(Self::from_xray_config(owned.as_ref()))
        }))
    }

    pub fn shared() -> Arc<DnsEngine> {
        Arc::clone(SHARED_DNS_ENGINE.get_or_init(|| Arc::new(Self::with_mux_defaults())))
    }

    pub fn dns_servers_count(&self) -> usize {
        self.config.servers.len()
    }

    pub fn dns_server_labels(&self) -> Vec<String> {
        self.config
            .servers
            .iter()
            .map(|server| server.original.clone())
            .collect()
    }

    pub fn disable_cache(&self) -> bool {
        self.config.disable_cache
    }

    pub fn query_strategy(&self) -> QueryStrategy {
        self.config.query_strategy
    }

    #[cfg(test)]
    pub(crate) fn config_snapshot(&self) -> &DnsConfig {
        &self.config
    }

    pub async fn query_raw(&self, request: DnsQueryRequest) -> Result<DnsQueryResponse, DnsError> {
        let started = Instant::now();
        let inflight_key = inflight_key_from_packet(&request.raw_query)?;
        let question = parse_dns_question_for_log(&request.raw_query);
        let response_server = self.response_socket_addr(&request)?;
        let policy = self.upstream_policy(&request);
        if request.source == DnsQuerySource::MuxUdp {
            debug!(
                conn_id = request.trace.map(|trace| trace.conn_id),
                mux_id = request.trace.and_then(|trace| trace.mux_id),
                qname = question.as_ref().map(|q| q.qname.as_str()),
                qtype = question.as_ref().map(|q| q.qtype),
                source = request.source.as_str(),
                timeout_ms = policy.timeout.as_millis(),
                total_timeout_ms = self.options.mux_udp_dns_total_timeout.as_millis(),
                mode = self.options.mux_dns_upstream_mode.as_str(),
                destination = ?request.destination,
                elapsed_ms_since_conn_start = request.trace.map(|trace| trace.elapsed_ms_since_conn_start()),
                elapsed_ms_since_mux_dns_start = request.trace.map(|trace| trace.elapsed_ms_since_dns_start()),
                "dns query start"
            );
        } else {
            debug!(
                qname = question.as_ref().map(|q| q.qname.as_str()),
                qtype = question.as_ref().map(|q| q.qtype),
                %response_server,
                source = request.source.as_str(),
                timeout_ms = policy.timeout.as_millis(),
                max_retries = policy.max_retries,
                destination = ?request.destination,
                inbound_tag = request.inbound_tag.as_deref(),
                cache_enabled = self.options.cache_enabled && !self.config.disable_cache,
                "dns query start"
            );
        }
        self.record_query();

        if self.options.cache_enabled && !self.config.disable_cache {
            let cache_lookup_started = Instant::now();
            if let Some((hit, server_id)) = self.cache_lookup(&request.raw_query, &request) {
                self.record_cache_hit();
                let rewritten = self.rewrite_cached_for_query(hit, &request.raw_query)?;
                debug!(
                        qname = %inflight_key.qname,
                        qtype = inflight_key.qtype,
                        source = request.source.as_str(),
                    server_id = %server_id,
                    cache_hit = true,
                    elapsed_us = cache_lookup_started.elapsed().as_micros(),
                    conn_id = request.trace.map(|trace| trace.conn_id),
                    mux_id = request.trace.and_then(|trace| trace.mux_id),
                    elapsed_ms_since_conn_start = request.trace.map(|trace| trace.elapsed_ms_since_conn_start()),
                    elapsed_ms_since_mux_dns_start = request.trace.map(|trace| trace.elapsed_ms_since_dns_start()),
                    "dns cache lookup done"
                );
                return Ok(self.to_query_response(
                    rewritten,
                    response_server,
                    true,
                    started.elapsed(),
                ));
            }
            self.record_cache_miss();
            debug!(
                qname = %inflight_key.qname,
                qtype = inflight_key.qtype,
                source = request.source.as_str(),
                cache_hit = false,
                elapsed_us = cache_lookup_started.elapsed().as_micros(),
                conn_id = request.trace.map(|trace| trace.conn_id),
                mux_id = request.trace.and_then(|trace| trace.mux_id),
                elapsed_ms_since_conn_start = request.trace.map(|trace| trace.elapsed_ms_since_conn_start()),
                elapsed_ms_since_mux_dns_start = request.trace.map(|trace| trace.elapsed_ms_since_dns_start()),
                "dns cache lookup done"
            );
        }

        let leader = {
            let mut guard = self.inflight.lock().await;
            if let Some(existing) = guard.get(&inflight_key).cloned() {
                self.record_inflight_dedup_hit();
                let inflight_wait_started = Instant::now();
                debug!(
                    qname = %inflight_key.qname,
                    qtype = inflight_key.qtype,
                    source = request.source.as_str(),
                    conn_id = request.trace.map(|trace| trace.conn_id),
                    mux_id = request.trace.and_then(|trace| trace.mux_id),
                    elapsed_ms_since_conn_start = request.trace.map(|trace| trace.elapsed_ms_since_conn_start()),
                    elapsed_ms_since_mux_dns_start = request.trace.map(|trace| trace.elapsed_ms_since_dns_start()),
                    "dns inflight dedup wait start"
                );
                drop(guard);
                return self
                    .wait_inflight(
                        existing,
                        &request.raw_query,
                        response_server,
                        inflight_wait_started,
                        request.source,
                    )
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
                trace: None,
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
        self.resolve_mux_udp_dns_with_trace(mux_id, destination, payload, None)
            .await
    }

    pub async fn resolve_mux_udp_dns_with_trace(
        &self,
        mux_id: u16,
        destination: SocketAddr,
        payload: &[u8],
        trace: Option<DnsQueryTrace>,
    ) -> Result<DnsQueryResponse, DnsError> {
        trace!(mux_id, %destination, payload_len = payload.len(), "mux udp dns engine resolve");
        self.query_raw(DnsQueryRequest {
            raw_query: payload.to_vec(),
            destination: Some(destination),
            inbound_tag: None,
            source: DnsQuerySource::MuxUdp,
            trace,
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
        current_query: &[u8],
        _server: SocketAddr,
        wait_started: Instant,
        source: DnsQuerySource,
    ) -> Result<CachedDnsResponse, DnsError> {
        loop {
            if let Some(result) = entry.result.lock().await.clone() {
                let outcome =
                    result.and_then(|cached| self.rewrite_cached_for_query(cached, current_query));
                debug!(
                    source = source.as_str(),
                    elapsed_us = wait_started.elapsed().as_micros(),
                    ok = outcome.is_ok(),
                    "dns inflight dedup wait done"
                );
                return outcome;
            }
            entry.notify.notified().await;
            if let Some(result) = entry.result.lock().await.clone() {
                let outcome =
                    result.and_then(|cached| self.rewrite_cached_for_query(cached, current_query));
                debug!(
                    source = source.as_str(),
                    elapsed_us = wait_started.elapsed().as_micros(),
                    ok = outcome.is_ok(),
                    "dns inflight dedup wait done"
                );
                return outcome;
            }
        }
    }

    fn rewrite_cached_for_query(
        &self,
        cached: CachedDnsResponse,
        current_query: &[u8],
    ) -> Result<CachedDnsResponse, DnsError> {
        Ok(CachedDnsResponse {
            raw_response: rewrite_dns_response_id_for_query(&cached.raw_response, current_query)?,
            expires_at: cached.expires_at,
            original_ttl: cached.original_ttl,
        })
    }

    fn upstream_policy(&self, request: &DnsQueryRequest) -> UpstreamPolicy {
        if request.source == DnsQuerySource::MuxUdp || request.destination.is_some() {
            UpstreamPolicy {
                timeout: self.options.mux_udp_dns_timeout,
                max_retries: self.options.mux_udp_dns_max_retries,
            }
        } else {
            UpstreamPolicy {
                timeout: self.options.default_timeout,
                max_retries: self.options.max_retries,
            }
        }
    }

    async fn execute_upstream(
        &self,
        request: &DnsQueryRequest,
        query: &[u8],
    ) -> Result<(Vec<u8>, String), DnsError> {
        let policy = self.upstream_policy(request);
        if request.source == DnsQuerySource::MuxUdp {
            if let Some(destination) = request.destination {
                let candidates = build_mux_udp_candidates(
                    destination,
                    &self.config,
                    self.options.mux_dns_upstream_mode,
                );
                debug!(
                    conn_id = request.trace.map(|trace| trace.conn_id),
                    mux_id = request.trace.and_then(|trace| trace.mux_id),
                    mode = self.options.mux_dns_upstream_mode.as_str(),
                    candidates = ?candidates.iter().map(|candidate| candidate.addr.to_string()).collect::<Vec<_>>(),
                    timeout_ms = policy.timeout.as_millis(),
                    total_timeout_ms = self.options.mux_udp_dns_total_timeout.as_millis(),
                    elapsed_ms_since_conn_start = request.trace.map(|trace| trace.elapsed_ms_since_conn_start()),
                    elapsed_ms_since_mux_dns_start = request.trace.map(|trace| trace.elapsed_ms_since_dns_start()),
                    "dns upstream candidates built"
                );
                return execute_mux_udp_upstream(
                    &self.transports.udp,
                    query,
                    &candidates,
                    self.options.mux_dns_upstream_mode,
                    policy.timeout,
                    self.options.mux_udp_dns_total_timeout,
                )
                .await
                .map_err(|err| {
                    if matches!(err, DnsError::Timeout) {
                        self.record_timeout();
                    }
                    err
                });
            }
        } else if let Some(destination) = request.destination {
            let mut attempt = 0usize;
            loop {
                let result = self
                    .transports
                    .udp
                    .query_at(destination, query, policy.timeout)
                    .await;
                match result {
                    Ok(response) => {
                        return Ok((response, format!("mux:{destination}")));
                    }
                    Err(DnsError::Timeout) => {
                        self.record_timeout();
                        if attempt >= policy.max_retries {
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
                match self.transports.query(query, server, policy.timeout).await {
                    Ok(response) => return Ok((response, server.original.clone())),
                    Err(err @ DnsError::MalformedQuery) => return Err(err),
                    Err(err @ DnsError::Timeout) => {
                        self.record_timeout();
                        last_err = Some(err);
                        if attempt >= policy.max_retries {
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
        if request.source == DnsQuerySource::MuxUdp {
            if let Some(destination) = request.destination {
                return build_mux_udp_candidates(
                    destination,
                    &self.config,
                    self.options.mux_dns_upstream_mode,
                )
                .into_iter()
                .map(|candidate| candidate.server_id)
                .collect();
            }
        } else if let Some(destination) = request.destination {
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

#[cfg(test)]
#[path = "../../tests/unit/dns/engine.rs"]
mod tests;
