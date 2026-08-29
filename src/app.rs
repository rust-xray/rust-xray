use std::collections::{BTreeMap, HashMap};
use std::pin::Pin;
use std::sync::{Arc, RwLock};
use std::task::{Context, Poll};
use std::time::Instant;

use crate::api;
use crate::cli::{self, Command, RunOptions};
use tokio::io::{AsyncRead, AsyncReadExt, ReadBuf};
use tokio::net::TcpStream;
use tracing::{debug, error, info, trace, warn};

use crate::codec::{Codec, Reader};
use crate::config::{
    api_dokodemo_inbound_tag, config_source_kind, format_redacted_run_command,
    load_xray_config_from_source, normalize_config, redact_config_source, resolve_api_listen,
    InboundTransportConfig, NormalizedConfig, NormalizedInbound, VlessRealityInbound, XrayConfig,
};
use crate::dns::DnsEngine;
use crate::mux::MuxSessionTrace;
use crate::outbound::{log_dns_outbounds, OutboundConnectRuntime};
use crate::protocol::structs::ClientHelloPayload;
use crate::proxy::{relay_fallback_with_options, FallbackRelayOptions};
use crate::reality::{
    handle_accepted_reality_client_traced, inspect_reality_client_hello,
    start_reality_post_handshake_probes, RealityDecision, RealityInspectConfig,
};
use crate::routing::RuntimeRouter;
use crate::runtime::{
    encode_inbound_handler_config, HandlerRuntime, LogicalInboundAuthError, LogicalInboundAuthSet,
    VlessInboundAuthContext,
};
use crate::stats::{StatsRegistry, StatsState};
use crate::tls::{read_client_hello_record, PrefixedStream, TlsClientHelloRecord};
use crate::vless::{
    build_fallback_context, fallback_match_kind_label, looks_like_http_request,
    resolve_fallback_selection, VlessClient, VlessUserManager,
};

const TLS_CONTENT_TYPE_HANDSHAKE: u8 = 0x16;
const NON_TLS_PREAMBLE_READ_LIMIT: usize = 4096;
const PREAMBLE_HEX_PREVIEW_MAX: usize = 32;
#[derive(Clone)]
pub struct InboundListenerConfig {
    pub inbound: VlessRealityInbound,
    pub merged_inbound_tags: Vec<String>,
    pub auth: VlessInboundAuthContext,
    pub plain_vless: bool,
    pub router: Option<Arc<RuntimeRouter>>,
}

impl std::fmt::Debug for InboundListenerConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("InboundListenerConfig")
            .field("inbound", &self.inbound)
            .field("merged_inbound_tags", &self.merged_inbound_tags)
            .field(
                "logical_inbound_count",
                &self.auth.auth_set().manager_count(),
            )
            .field("plain_vless", &self.plain_vless)
            .field("router", &self.router.is_some())
            .finish()
    }
}

impl InboundListenerConfig {
    fn tag(&self) -> Option<&str> {
        self.inbound.tag.as_deref()
    }

    fn inbound_tag_label(&self) -> &str {
        self.tag().unwrap_or("reality-in")
    }

    pub fn auth_context(&self) -> &VlessInboundAuthContext {
        &self.auth
    }
}

pub(crate) fn build_inbound_auth_context(
    merged_tags: &[String],
    logical_users: &BTreeMap<String, Vec<VlessClient>>,
    inbound: &VlessRealityInbound,
    xray: &XrayConfig,
    stats_registry: &Arc<StatsRegistry>,
    stats_enabled: bool,
) -> Result<VlessInboundAuthContext, LogicalInboundAuthError> {
    let auth_set = Arc::new(LogicalInboundAuthSet::new());
    let mut stats_by_tag = HashMap::new();

    let users_by_tag = if logical_users.is_empty() {
        let primary = merged_tags
            .first()
            .cloned()
            .unwrap_or_else(|| "reality-in".to_string());
        BTreeMap::from([(primary, inbound.users.clone())])
    } else {
        logical_users.clone()
    };

    for tag in merged_tags {
        let users = users_by_tag.get(tag).cloned().unwrap_or_default();
        let manager = Arc::new(VlessUserManager::new_with_sniffing(
            tag.clone(),
            users,
            inbound.sniffing_enabled,
        ));
        auth_set.register(manager)?;
        if stats_enabled {
            stats_by_tag.insert(
                tag.clone(),
                Arc::new(StatsState::from_xray_config_with_registry(
                    xray,
                    Arc::clone(stats_registry),
                    tag.clone(),
                )),
            );
        }
    }

    Ok(VlessInboundAuthContext::new(
        auth_set,
        Arc::new(RwLock::new(stats_by_tag)),
    ))
}

pub(crate) fn plain_vless_merge_key(listen_addr: &str) -> String {
    format!("plain:{listen_addr}")
}

struct ServerRuntimeConfig {
    inbounds: Vec<InboundListenerConfig>,
}

enum InboundPreamble {
    Tls {
        stream: TcpStream,
        record: TlsClientHelloRecord,
    },
    RawFallback {
        stream: TcpStream,
        initial_bytes: Vec<u8>,
    },
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct PreambleReadStats {
    bytes_read: usize,
    preview: Vec<u8>,
}

impl PreambleReadStats {
    fn new() -> Self {
        Self {
            bytes_read: 0,
            preview: Vec::new(),
        }
    }

    fn record(&mut self, data: &[u8]) {
        self.bytes_read += data.len();
        for &byte in data {
            if self.preview.len() >= PREAMBLE_HEX_PREVIEW_MAX {
                break;
            }
            self.preview.push(byte);
        }
    }

    fn hex_preview(&self) -> String {
        self.preview
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect::<Vec<_>>()
            .join("")
    }
}

struct CountingTcpStream {
    inner: TcpStream,
    stats: PreambleReadStats,
}

impl CountingTcpStream {
    fn new(inner: TcpStream) -> Self {
        Self {
            inner,
            stats: PreambleReadStats::new(),
        }
    }

    fn into_inner(self) -> (TcpStream, PreambleReadStats) {
        (self.inner, self.stats)
    }
}

impl AsyncRead for CountingTcpStream {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        let filled_before = buf.filled().len();
        let result = Pin::new(&mut self.as_mut().get_mut().inner).poll_read(cx, buf);
        if let Poll::Ready(Ok(())) = &result {
            let newly_read = &buf.filled()[filled_before..];
            self.as_mut().get_mut().stats.record(newly_read);
        }
        result
    }
}

fn preamble_len(preamble: &InboundPreamble) -> usize {
    match preamble {
        InboundPreamble::Tls { record, .. } => record.initial_client_bytes().len(),
        InboundPreamble::RawFallback { initial_bytes, .. } => initial_bytes.len(),
    }
}

fn preamble_read_error_kind(err: &std::io::Error) -> &'static str {
    if err.kind() == std::io::ErrorKind::ConnectionReset {
        return "connection reset";
    }
    if is_early_eof(err) {
        if err.to_string().to_ascii_lowercase().contains("early eof") {
            return "early eof";
        }
        return "UnexpectedEof";
    }
    "other"
}

fn log_preamble_bytes_preview(peer: Option<std::net::SocketAddr>, stats: &PreambleReadStats) {
    if stats.bytes_read == 0 {
        return;
    }
    trace!(
        ?peer,
        bytes_read = stats.bytes_read,
        hex_preview = %stats.hex_preview(),
        "inbound preamble bytes preview"
    );
}

async fn relay_vless_fallback_with_log(
    client: TcpStream,
    config: &InboundListenerConfig,
    initial_client_bytes: &[u8],
    hello: Option<&ClientHelloPayload>,
    reason: &str,
) -> std::io::Result<()> {
    let stats = config
        .auth
        .auth_set()
        .tags()
        .first()
        .and_then(|tag| config.auth.stats_for(tag))
        .as_ref()
        .and_then(|state| state.session(None, None, None));
    let ctx = build_fallback_context(hello, initial_client_bytes);
    let selection = resolve_fallback_selection(
        &config.inbound.fallbacks,
        &config.inbound.reality.dest_addr,
        &ctx,
    )?;
    let dest_addr = selection.dest;
    let xver = selection.xver;

    debug!(
        reason,
        requested_sni = ?ctx.sni,
        detected_alpn = ?ctx.alpn,
        alpn_offers = ?ctx.alpn_offers,
        detected_http_path = ?ctx.http_path,
        selected_dest = %dest_addr,
        selected_reason = fallback_match_kind_label(selection.kind),
        matched_alpn = ?selection.matched_alpn,
        xver,
        bytes_to_forward = initial_client_bytes.len(),
        "VLESS fallback dispatch decision"
    );

    info!(
        reason,
        fallback_count = config.inbound.fallbacks.len(),
        selected_reason = fallback_match_kind_label(selection.kind),
        used_configured_fallback = selection.used_configured_fallback,
        %dest_addr,
        xver,
        sni = ?ctx.sni,
        alpn = ?ctx.alpn,
        alpn_offers = ?ctx.alpn_offers,
        matched_alpn = ?selection.matched_alpn,
        http_path = ?ctx.http_path,
        initial_bytes = initial_client_bytes.len(),
        "VLESS fallback target selected"
    );

    relay_fallback_with_options(
        client,
        &dest_addr,
        initial_client_bytes,
        FallbackRelayOptions::with_reality_limits(
            xver,
            config.inbound.reality.limit_fallback_upload,
            config.inbound.reality.limit_fallback_download,
        ),
        stats.as_ref(),
    )
    .await
    .map_err(|e| {
        error!(reason, %dest_addr, xver, error = %e, "fallback relay failed");
        std::io::Error::new(e.kind(), format!("fallback relay failed ({reason}): {e}"))
    })
}

async fn read_inbound_preamble(
    stream: TcpStream,
) -> (Result<InboundPreamble, std::io::Error>, PreambleReadStats) {
    let mut counting = CountingTcpStream::new(stream);

    let mut first = [0u8; 1];
    if let Err(err) = counting.read_exact(&mut first).await {
        let stats = counting.into_inner().1;
        return (Err(err), stats);
    }

    if first[0] == TLS_CONTENT_TYPE_HANDSHAKE {
        let mut prefixed = PrefixedStream::new(counting, first.to_vec());
        match read_client_hello_record(&mut prefixed).await {
            Ok(record) => {
                let counting = prefixed.into_inner();
                let (stream, stats) = counting.into_inner();
                (Ok(InboundPreamble::Tls { stream, record }), stats)
            }
            Err(err) => {
                let counting = prefixed.into_inner();
                let (_, stats) = counting.into_inner();
                (Err(err), stats)
            }
        }
    } else {
        let mut initial_bytes = first.to_vec();
        let mut chunk = [0u8; NON_TLS_PREAMBLE_READ_LIMIT - 1];
        match counting.read(&mut chunk).await {
            Ok(read) => {
                initial_bytes.extend_from_slice(&chunk[..read]);
                let (stream, stats) = counting.into_inner();
                if looks_like_http_request(&initial_bytes) {
                    (
                        Ok(InboundPreamble::RawFallback {
                            stream,
                            initial_bytes,
                        }),
                        stats,
                    )
                } else {
                    (
                        Err(std::io::Error::new(
                            std::io::ErrorKind::InvalidData,
                            "inbound preamble is neither TLS ClientHello nor HTTP/1.x request",
                        )),
                        stats,
                    )
                }
            }
            Err(err) => {
                let (_, stats) = counting.into_inner();
                (Err(err), stats)
            }
        }
    }
}

fn is_early_eof(err: &std::io::Error) -> bool {
    if err.kind() == std::io::ErrorKind::UnexpectedEof {
        return true;
    }
    err.to_string().to_ascii_lowercase().contains("early eof")
}

pub async fn handle_inbound_client(
    stream: TcpStream,
    config: Arc<InboundListenerConfig>,
    conn_id: u64,
    conn_started: Instant,
) -> std::io::Result<()> {
    if config.plain_vless {
        return handle_plain_vless_client(stream, config, conn_id, conn_started).await;
    }

    let peer = stream.peer_addr().ok();
    let inbound_tag = config.inbound_tag_label();
    let inbound_protocol = "vless";

    debug!(
        conn_id,
        ?peer,
        inbound_tag,
        inbound_protocol,
        transport = "tcp",
        elapsed_ms_since_conn_start = conn_started.elapsed().as_millis(),
        "reading inbound preamble"
    );

    let (preamble_result, stats) = read_inbound_preamble(stream).await;

    match preamble_result {
        Ok(preamble) => {
            debug!(
                conn_id,
                ?peer,
                inbound_tag,
                preamble_len = preamble_len(&preamble),
                elapsed_ms_since_conn_start = conn_started.elapsed().as_millis(),
                "inbound preamble read ok"
            );
            match preamble {
                InboundPreamble::RawFallback {
                    stream,
                    initial_bytes,
                } => {
                    debug!(
                        ?peer,
                        initial_bytes = initial_bytes.len(),
                        "non-TLS inbound routed to VLESS fallback"
                    );
                    return relay_vless_fallback_with_log(
                        stream,
                        &config,
                        &initial_bytes,
                        None,
                        "non-TLS inbound fallback",
                    )
                    .await;
                }
                InboundPreamble::Tls { stream, record } => {
                    handle_tls_client(stream, config, record, peer, conn_id, conn_started).await
                }
            }
        }
        Err(err) => {
            if is_early_eof(&err) {
                debug!(
                    ?peer,
                    inbound_tag,
                    bytes_read = stats.bytes_read,
                    error_kind = preamble_read_error_kind(&err),
                    "client closed before inbound preamble"
                );
                log_preamble_bytes_preview(peer, &stats);
                Ok(())
            } else {
                error!(
                    ?peer,
                    inbound_tag,
                    bytes_read = stats.bytes_read,
                    error_kind = preamble_read_error_kind(&err),
                    error = %err,
                    "failed to read inbound preamble"
                );
                log_preamble_bytes_preview(peer, &stats);
                Err(err)
            }
        }
    }
}

async fn handle_tls_client(
    stream: TcpStream,
    config: Arc<InboundListenerConfig>,
    record: TlsClientHelloRecord,
    peer: Option<std::net::SocketAddr>,
    conn_id: u64,
    conn_started: Instant,
) -> std::io::Result<()> {
    let socket_meta = crate::routing::RouteSocketMeta::from_tcp_stream(&stream);
    debug!(
        conn_id,
        ?peer,
        raw_record_len = record.raw_record.len(),
        handshake_payload_len = record.handshake_payload.len(),
        elapsed_ms_since_conn_start = conn_started.elapsed().as_millis(),
        "ClientHello record read ok"
    );

    let mut rd = Reader::init(&record.handshake_payload);

    let ch = match ClientHelloPayload::read(&mut rd) {
        Ok(ch) => ch,
        Err(err) => {
            warn!(?peer, error = ?err, "ClientHello parse failed");
            return relay_vless_fallback_with_log(
                stream,
                &config,
                record.initial_client_bytes(),
                None,
                "ClientHello parse error",
            )
            .await;
        }
    };

    let inspect_cfg = RealityInspectConfig {
        private_key: &config.inbound.reality.private_key,
        server_names: &config.inbound.reality.server_names,
        short_ids: &config.inbound.reality.short_ids,
        max_time_diff_ms: config.inbound.reality.max_time_diff,
        min_client_ver: config.inbound.reality.min_client_ver.as_deref(),
        max_client_ver: config.inbound.reality.max_client_ver.as_deref(),
        now_unix_ms: None,
    };

    match inspect_reality_client_hello(&ch, &record.handshake_message, inspect_cfg) {
        Ok(RealityDecision::Accepted(accepted)) => {
            // Accepted REALITY clients must not be sent to fallback relay.
            let mldsa65_seed = config
                .inbound
                .reality
                .mldsa65_seed
                .map(crate::reality::Mldsa65Seed::from_bytes);
            if let Err(err) = handle_accepted_reality_client_traced(
                stream,
                record,
                ch,
                accepted,
                &config.inbound.reality.dest_addr,
                config.auth.clone(),
                mldsa65_seed.as_ref(),
                &config.inbound.transport,
                Some(MuxSessionTrace {
                    conn_id,
                    conn_started,
                }),
                socket_meta,
                config.router.clone(),
            )
            .await
            {
                warn!(?peer, error = %err, "REALITY accepted path failed");
                return Err(err);
            }
            Ok(())
        }
        Ok(RealityDecision::Fallback) => {
            let ctx = build_fallback_context(Some(&ch), record.initial_client_bytes());
            debug!(
                ?peer,
                requested_sni = ?ctx.sni,
                detected_alpn = ?ctx.alpn,
                alpn_offers = ?ctx.alpn_offers,
                detected_http_path = ?ctx.http_path,
                client_hello_bytes = record.initial_client_bytes().len(),
                "REALITY inspect returned fallback"
            );
            relay_vless_fallback_with_log(
                stream,
                &config,
                record.initial_client_bytes(),
                Some(&ch),
                "REALITY fallback",
            )
            .await
        }
        Err(err) => {
            warn!(?peer, error = %err, "REALITY inspect failed");
            relay_vless_fallback_with_log(
                stream,
                &config,
                record.initial_client_bytes(),
                Some(&ch),
                "REALITY inspect error",
            )
            .await
        }
    }
}

async fn handle_plain_vless_client(
    stream: TcpStream,
    config: Arc<InboundListenerConfig>,
    _conn_id: u64,
    _conn_started: Instant,
) -> std::io::Result<()> {
    let socket_meta = crate::routing::RouteSocketMeta::from_tcp_stream(&stream);
    crate::vless::handle_vless_tcp_inbound_with_auth_context(
        stream,
        &config.auth,
        &socket_meta,
        config.router.as_ref(),
    )
    .await
}

pub fn validate_reality_runtime_feature_gates(
    config: &InboundListenerConfig,
) -> std::io::Result<()> {
    let _mldsa65_enabled = config.inbound.reality.mldsa65_seed.is_some();
    Ok(())
}

#[cfg(test)]
fn runtime_config_from_xray(xray: &XrayConfig) -> std::io::Result<InboundListenerConfig> {
    load_runtime_config(xray, Arc::new(StatsRegistry::new()))?
        .inbounds
        .into_iter()
        .next()
        .ok_or_else(|| {
            std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "no supported VLESS TCP REALITY inbound found",
            )
        })
}

fn transport_log_label(transport: &InboundTransportConfig) -> &'static str {
    match transport {
        InboundTransportConfig::RawTcp => "raw",
        InboundTransportConfig::XHttp(_) => "xhttp",
    }
}

pub fn normalized_reality_merge_key(inbound: &VlessRealityInbound) -> String {
    let transport_key = match &inbound.transport {
        InboundTransportConfig::RawTcp => "raw".to_string(),
        InboundTransportConfig::XHttp(xhttp) => {
            format!(
                "xhttp:path={}:host={}:mode={}",
                xhttp.path,
                xhttp.host.as_deref().unwrap_or(""),
                xhttp.mode
            )
        }
    };
    format!(
        "listen={}|private_key={}|dest={}|decryption={}|max_time_diff={}|min={}|max={}|show={}|mldsa={:?}|transport={}|sniffing={}|upload_limit={:?}|download_limit={:?}",
        inbound.listen_addr,
        inbound.reality.private_key,
        inbound.reality.dest_addr,
        inbound.reality.decryption,
        inbound.reality.max_time_diff,
        inbound.reality.min_client_ver.as_deref().unwrap_or(""),
        inbound.reality.max_client_ver.as_deref().unwrap_or(""),
        inbound.reality.show,
        inbound.reality.mldsa65_seed,
        transport_key,
        inbound.sniffing_enabled,
        inbound.reality.limit_fallback_upload,
        inbound.reality.limit_fallback_download,
    )
}

fn push_unique_string(values: &mut Vec<String>, value: String) {
    if !values.iter().any(|existing| existing == &value) {
        values.push(value);
    }
}

fn push_unique_bytes(values: &mut Vec<Vec<u8>>, value: Vec<u8>) {
    if !values.iter().any(|existing| existing == &value) {
        values.push(value);
    }
}

fn merge_vless_users(
    users: impl IntoIterator<Item = VlessClient>,
) -> std::io::Result<Vec<VlessClient>> {
    let mut merged: HashMap<uuid::Uuid, VlessClient> = HashMap::new();
    for user in users {
        match merged.remove(&user.id) {
            None => {
                merged.insert(user.id, user);
            }
            Some(mut existing) => {
                match (existing.flow.as_deref(), user.flow.as_deref()) {
                    (None, Some(flow)) | (Some(""), Some(flow)) => {
                        existing.flow = Some(flow.to_string());
                    }
                    (Some(left), Some(right))
                        if !left.is_empty() && !right.is_empty() && left != right =>
                    {
                        return Err(std::io::Error::new(
                            std::io::ErrorKind::InvalidInput,
                            format!(
                                "conflicting VLESS client flow for id {}: {left:?} vs {right:?}",
                                user.id
                            ),
                        ));
                    }
                    _ => {}
                }
                if existing.email.is_none() {
                    existing.email = user.email;
                }
                if existing.level.is_none() {
                    existing.level = user.level;
                }
                merged.insert(existing.id, existing);
            }
        }
    }
    let mut users: Vec<_> = merged.into_values().collect();
    users.sort_by(|left, right| left.id.cmp(&right.id));
    Ok(users)
}

fn reject_duplicate_uuid_across_logical_inbounds(
    logical_users: &BTreeMap<String, Vec<VlessClient>>,
    tag: &str,
    users: &[VlessClient],
) -> std::io::Result<()> {
    for user in users {
        for (existing_tag, existing_users) in logical_users {
            if existing_tag == tag {
                continue;
            }
            if existing_users.iter().any(|existing| existing.id == user.id) {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidInput,
                    format!(
                        "duplicate vless user id {} on merged listener: already registered under inbound {existing_tag}, cannot add under {tag}",
                        user.id
                    ),
                ));
            }
        }
    }
    Ok(())
}

fn merged_normalized_reality_inbounds(
    normalized: &NormalizedConfig,
) -> std::io::Result<
    Vec<(
        VlessRealityInbound,
        Vec<String>,
        BTreeMap<String, Vec<VlessClient>>,
    )>,
> {
    let mut groups: Vec<(
        String,
        VlessRealityInbound,
        Vec<String>,
        BTreeMap<String, Vec<VlessClient>>,
    )> = Vec::new();
    for inbound in normalized
        .inbounds
        .iter()
        .filter_map(|inbound| match inbound {
            NormalizedInbound::VlessReality(inbound) => Some(inbound),
            _ => None,
        })
    {
        let key = normalized_reality_merge_key(inbound);
        let tag = inbound
            .tag
            .clone()
            .filter(|value| !value.is_empty())
            .unwrap_or_else(|| "reality-in".to_string());
        if let Some((_, existing, tags, logical_users)) = groups
            .iter_mut()
            .find(|(group_key, _, _, _)| group_key == &key)
        {
            push_unique_string(tags, tag.clone());
            reject_duplicate_uuid_across_logical_inbounds(logical_users, &tag, &inbound.users)?;
            logical_users.insert(tag, inbound.users.clone());
            for server_name in &inbound.reality.server_names {
                push_unique_string(&mut existing.reality.server_names, server_name.clone());
            }
            for short_id in &inbound.reality.short_ids {
                push_unique_bytes(&mut existing.reality.short_ids, short_id.clone());
            }
            existing.users = merge_vless_users(
                existing
                    .users
                    .clone()
                    .into_iter()
                    .chain(inbound.users.clone().into_iter()),
            )?;
        } else {
            let tags = vec![tag.clone()];
            let mut logical_users = BTreeMap::new();
            logical_users.insert(tag, inbound.users.clone());
            groups.push((key, inbound.clone(), tags, logical_users));
        }
    }

    Ok(groups
        .into_iter()
        .map(|(_, inbound, tags, logical_users)| (inbound, tags, logical_users))
        .collect())
}

fn load_runtime_config(
    xray: &XrayConfig,
    stats_registry: Arc<StatsRegistry>,
) -> std::io::Result<ServerRuntimeConfig> {
    let normalized = normalize_config(xray)?;
    runtime_config_from_normalized(&normalized, xray, stats_registry)
}

fn runtime_config_from_normalized(
    normalized: &NormalizedConfig,
    xray: &XrayConfig,
    stats_registry: Arc<StatsRegistry>,
) -> std::io::Result<ServerRuntimeConfig> {
    let runtimes = merged_normalized_reality_inbounds(normalized)?;
    if runtimes.is_empty() {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "no supported VLESS TCP REALITY inbound found",
        ));
    }
    let stats_enabled = StatsState::from_xray_config(xray, None).enabled();
    let mut inbounds = Vec::with_capacity(runtimes.len());

    for (inbound, merged_inbound_tags, logical_users) in runtimes {
        let inbound_tag = inbound
            .tag
            .clone()
            .filter(|tag| !tag.is_empty())
            .unwrap_or_else(|| "reality-in".to_string());
        let auth = build_inbound_auth_context(
            &merged_inbound_tags,
            &logical_users,
            &inbound,
            xray,
            &stats_registry,
            stats_enabled,
        )
        .map_err(|err| std::io::Error::new(std::io::ErrorKind::InvalidInput, err.to_string()))?;
        let listener_config = InboundListenerConfig {
            inbound,
            merged_inbound_tags,
            auth,
            plain_vless: false,
            router: None,
        };
        validate_reality_runtime_feature_gates(&listener_config)?;

        info!(tag = ?listener_config.inbound.tag, "using VLESS REALITY inbound");

        if listener_config.inbound.reality.show {
            info!("REALITY show mode enabled in config");
        }

        let total_users = listener_config.auth.auth_set().manager_count();
        info!(
            listen = %listener_config.inbound.listen_addr,
            dest = %listener_config.inbound.reality.dest_addr,
            server_names = ?listener_config.inbound.reality.server_names,
            short_id_count = listener_config.inbound.reality.short_ids.len(),
            transport = transport_log_label(&listener_config.inbound.transport),
            max_time_diff = listener_config.inbound.reality.max_time_diff,
            logical_inbound_count = total_users,
            merged_inbound_tags = ?listener_config.merged_inbound_tags,
            vless_fallback_count = listener_config.inbound.fallbacks.len(),
            "loaded REALITY inbound settings"
        );

        for (index, fallback) in listener_config.inbound.fallbacks.iter().enumerate() {
            info!(
                index,
                name = fallback.name.as_deref().unwrap_or(""),
                alpn = fallback.alpn.as_deref().unwrap_or(""),
                path = fallback.path.as_deref().unwrap_or(""),
                dest = %fallback.dest.addr,
                xver = fallback.xver,
                "VLESS fallback entry"
            );
        }

        inbounds.push(listener_config);
    }

    Ok(ServerRuntimeConfig { inbounds })
}

fn stage_error(stage: &str, err: std::io::Error) -> std::io::Error {
    crate::startup_log::eprintln_stage(stage, &err);
    std::io::Error::new(err.kind(), format!("{stage}: {err}"))
}

pub async fn main_entry() -> std::io::Result<()> {
    let raw_args: Vec<String> = std::env::args().collect();

    let command = match cli::parse_args(raw_args.iter().map(|s| s.as_str())) {
        Ok(command) => command,
        Err(err) => {
            if !matches!(raw_args.get(1).map(String::as_str), Some("version")) {
                crate::startup_log::eprintln_bootstrap("main_entry start");
                crate::startup_log::eprintln_bootstrap(format!(
                    "argv: {}",
                    crate::startup_log::redact_argv(&raw_args)
                ));
            }
            crate::startup_log::eprintln_fatal_message(err.to_string());
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                err.to_string(),
            ));
        }
    };

    if let Command::Run(ref opts) = command {
        crate::startup_log::log_server_bootstrap(&raw_args, opts);
    }

    let _logging_guard = crate::logging::init_logging(&command)?;
    dispatch(command).await
}

async fn dispatch(command: Command) -> std::io::Result<()> {
    match command {
        Command::Version => {
            cli::print_version();
            Ok(())
        }
        Command::Api(api) => api::execute(api).await.map_err(|err| {
            stage_error("api command failed", std::io::Error::other(err.to_string()))
        }),
        Command::Run(opts) => run_server(opts).await,
    }
}

async fn start_xray_api_server(
    config_source: &str,
    xray: &XrayConfig,
    handler_runtime: Arc<HandlerRuntime>,
    stats_registry: Arc<StatsRegistry>,
) -> std::io::Result<Option<tokio::task::JoinHandle<std::io::Result<()>>>> {
    let Some(api) = xray.api.as_ref() else {
        info!("Xray API disabled (no api block in config)");
        return Ok(None);
    };

    info!(api_tag = %api.tag, api_services = ?api.services, "Xray API starting");

    let resolved = resolve_api_listen(xray)
        .map_err(|err| stage_error("failed to resolve API listener", err))?;
    let Some((listen, listen_source, dokodemo_tag)) = resolved else {
        let err = std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            format!(
                "API services configured for tag {:?} but no api.listen and no routed dokodemo-door API inbound was found",
                api.tag
            ),
        );
        return Err(stage_error("failed to resolve API listener", err));
    };

    crate::startup_log::eprintln_api_listen_resolved(
        &listen,
        listen_source.as_log_label(),
        dokodemo_tag.as_deref(),
        api.tag.as_str(),
    );
    info!(
        api_listen = %listen,
        api_listen_source = listen_source.as_log_label(),
        dokodemo_inbound_tag = ?dokodemo_tag,
        "detected Xray API listener address"
    );

    if let Some(tag) = dokodemo_tag.as_deref() {
        info!(
            inbound_tag = %tag,
            api_listen = %listen,
            "skipping normal inbound startup for API dokodemo-door inbound (API gRPC owns this listen/port)"
        );
        crate::startup_log::eprintln_bootstrap(format!(
            "skipped inbound tag {tag} (API gRPC owns {listen})"
        ));
    }

    let selection = api::server::resolve_api_transport_mode(api::server::ApiTransportContext {
        config_source,
        api_listen: Some(&listen),
        xray: Some(xray),
    })
    .map_err(|err| stage_error("failed to configure API transport", err))?;
    api::server::log_api_transport_selected(&selection);
    let transport = selection.mode;
    info!(api_transport = transport.as_log_label(), "Xray API mode");

    let enabled = api::server::parse_enabled_services(&api.services)
        .map_err(|err| stage_error("failed to parse API services", err))?;

    let (listener, bound_addr) = api::server::bind_api_listener(&listen)
        .await
        .map_err(|err| stage_error("failed to bind Xray API", err))?;
    info!(bind_addr = %bound_addr, "Xray API bind OK");

    api::server::log_api_listener_ready(&listen, bound_addr, &api.services, &enabled, &transport);
    crate::startup_log::eprintln_api_listening(&listen, transport.as_log_label());

    let api_task = tokio::spawn(async move {
        api::server::serve_grpc_on(
            listener,
            enabled,
            stats_registry,
            handler_runtime,
            transport,
        )
        .await
    });

    Ok(Some(api_task))
}

async fn run_server(opts: RunOptions) -> std::io::Result<()> {
    let program = std::env::args()
        .next()
        .unwrap_or_else(|| "rw-core".to_string());
    let config_source = opts.config.clone();
    let source_kind = config_source_kind(&config_source);

    info!(
        command_line = %format_redacted_run_command(&program, &config_source, opts.format.as_deref()),
        config_source_kind = source_kind,
        "rust-xray starting"
    );
    if let Some(format) = opts.format.as_deref() {
        info!(format = %format, "Xray config format");
    }

    info!(
        source = %redact_config_source(&config_source),
        config_source_kind = source_kind,
        "loading Xray config"
    );
    let xray = load_xray_config_from_source(&config_source)
        .await
        .map_err(|err| stage_error("failed to load config source", err))?;
    crate::startup_log::eprintln_bootstrap("config load success");
    if let Some(controller) = crate::logging::RuntimeLoggerController::global() {
        controller.apply_runtime_config(xray.log.as_ref());
        controller.restart().map_err(|err| {
            stage_error(
                "failed to start configured logger outputs",
                std::io::Error::other(err.to_string()),
            )
        })?;
    }
    info!(
        source = %redact_config_source(&config_source),
        config_source_kind = source_kind,
        inbound_count = xray.inbounds.len(),
        outbound_count = xray.outbounds.len(),
        has_api = xray.api.is_some(),
        "config loaded OK"
    );
    let dns_engine = DnsEngine::init_shared(xray.dns.as_ref());
    OutboundConnectRuntime::init_shared(&xray);
    log_dns_outbounds(&xray.outbounds);
    info!(
        dns_servers = dns_engine.dns_servers_count(),
        disable_cache = dns_engine.disable_cache(),
        query_strategy = ?dns_engine.query_strategy(),
        has_top_level_dns = xray.dns.is_some(),
        domain_strategy = ?OutboundConnectRuntime::shared().domain_strategy,
        "dns engine initialized"
    );
    debug!(
        default_timeout_ms = crate::dns::DnsEngineOptions::from_env().default_timeout.as_millis(),
        mux_udp_dns_timeout_ms = crate::dns::DnsEngineOptions::from_env().mux_udp_dns_timeout.as_millis(),
        mux_udp_dns_total_timeout_ms = crate::dns::DnsEngineOptions::from_env().mux_udp_dns_total_timeout.as_millis(),
        max_retries = crate::dns::DnsEngineOptions::from_env().max_retries,
        mux_udp_dns_max_retries = crate::dns::DnsEngineOptions::from_env().mux_udp_dns_max_retries,
        mux_dns_upstream_mode = crate::dns::DnsEngineOptions::from_env().mux_dns_upstream_mode.as_str(),
        cache_enabled = crate::dns::DnsEngineOptions::from_env().cache_enabled,
        disable_cache = dns_engine.disable_cache(),
        servers = ?dns_engine.dns_server_labels(),
        "dns engine options"
    );

    if let Some(api) = xray.api.as_ref() {
        info!(api_tag = %api.tag, api_services = ?api.services, "api block present");
        if let Ok(Some((listen, source, tag))) = resolve_api_listen(&xray) {
            crate::startup_log::eprintln_api_listen_resolved(
                &listen,
                source.as_log_label(),
                tag.as_deref(),
                api.tag.as_str(),
            );
            info!(
                api_listen = %listen,
                api_listen_source = source.as_log_label(),
                dokodemo_inbound_tag = ?tag,
                "API listener resolved from config"
            );
        }
    }

    let stats_state = StatsState::from_xray_config(&xray, api_dokodemo_inbound_tag(&xray));
    let stats_registry = Arc::clone(&stats_state.registry);
    let xray = Arc::new(xray);
    let handler_runtime = Arc::new(
        HandlerRuntime::new(
            Arc::clone(&xray),
            Arc::clone(&stats_registry),
            api_dokodemo_inbound_tag(&xray),
            false,
        )
        .map_err(|err| {
            stage_error(
                "failed to initialize routing runtime",
                std::io::Error::new(std::io::ErrorKind::InvalidInput, err.to_string()),
            )
        })?,
    );
    handler_runtime.start_observatory();

    let api_task = start_xray_api_server(
        &config_source,
        &xray,
        Arc::clone(&handler_runtime),
        Arc::clone(&stats_registry),
    )
    .await?;

    info!("loading REALITY runtime");
    let mut server_config = load_runtime_config(&xray, stats_registry)
        .map_err(|err| stage_error("failed to load REALITY runtime", err))?;
    for inbound in &mut server_config.inbounds {
        inbound.router = Some(Arc::clone(&handler_runtime.router));
    }
    if server_config.inbounds.is_empty() {
        return Err(stage_error(
            "failed to load REALITY runtime",
            std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "no supported VLESS TCP REALITY inbound found",
            ),
        ));
    }
    crate::startup_log::eprintln_bootstrap(format!(
        "REALITY runtime loaded OK listener_count={}",
        server_config.inbounds.len()
    ));
    for inbound in &server_config.inbounds {
        info!(
            listen = %inbound.inbound.listen_addr,
            tag = ?inbound.inbound.tag,
            transport = transport_log_label(&inbound.inbound.transport),
            "REALITY runtime loaded OK"
        );
    }

    let probe_inbounds: Vec<VlessRealityInbound> = server_config
        .inbounds
        .iter()
        .map(|inbound| inbound.inbound.clone())
        .collect();
    start_reality_post_handshake_probes(&probe_inbounds);

    for outbound in &xray.outbounds {
        handler_runtime
            .outbound
            .register_startup_outbound(outbound)
            .map_err(|err| {
                stage_error(
                    "failed to register startup outbound",
                    std::io::Error::new(std::io::ErrorKind::InvalidInput, err.to_string()),
                )
            })?;
    }

    for inbound in &server_config.inbounds {
        let inbound_tag = inbound
            .inbound
            .tag
            .clone()
            .unwrap_or_else(|| "reality-in".to_string());
        let users = inbound
            .auth
            .auth_set()
            .get_manager(&inbound_tag)
            .map(|manager| {
                manager
                    .list_managed_users()
                    .into_iter()
                    .filter(|user| !user.email.is_empty())
                    .collect::<Vec<_>>()
            })
            .unwrap_or_default();
        let handler_config =
            encode_inbound_handler_config(&inbound.inbound, &users).map_err(|err| {
                stage_error(
                    "failed to encode startup inbound handler config",
                    std::io::Error::new(std::io::ErrorKind::InvalidInput, err.to_string()),
                )
            })?;

        info!(
            addr = %inbound.inbound.listen_addr,
            inbound_tag = %inbound_tag,
            transport = transport_log_label(&inbound.inbound.transport),
            "REALITY inbound starting"
        );
        if let InboundTransportConfig::XHttp(xhttp) = &inbound.inbound.transport {
            info!(
                inbound_tag = %inbound_tag,
                listen = %inbound.inbound.listen_addr,
                path = %xhttp.path,
                mode = %xhttp.mode,
                "xhttp inbound starting"
            );
        }

        for tag in &inbound.merged_inbound_tags {
            if let Some(manager) = inbound.auth.auth_set().get_manager(tag) {
                handler_runtime
                    .inbound
                    .user_managers()
                    .register(Arc::clone(&manager));
            }
        }

        handler_runtime
            .inbound
            .register_startup_inbound(
                Arc::new(InboundListenerConfig {
                    inbound: inbound.inbound.clone(),
                    merged_inbound_tags: inbound.merged_inbound_tags.clone(),
                    auth: inbound.auth.clone(),
                    plain_vless: inbound.plain_vless,
                    router: inbound.router.clone(),
                }),
                handler_config,
            )
            .await
            .map_err(|err| {
                stage_error(
                    "failed to register startup inbound",
                    std::io::Error::new(std::io::ErrorKind::Other, err.to_string()),
                )
            })?;

        crate::startup_log::eprintln_bootstrap(format!(
            "REALITY listener started addr={} tag={inbound_tag}",
            inbound.inbound.listen_addr
        ));
        info!(
            addr = %inbound.inbound.listen_addr,
            inbound_tag = %inbound_tag,
            transport = transport_log_label(&inbound.inbound.transport),
            "REALITY listener started"
        );
    }

    if let Some(mut api_task) = api_task {
        tokio::select! {
            api_result = &mut api_task => {
                match api_result {
                    Ok(Ok(())) => {
                        crate::startup_log::eprintln_bootstrap(
                            "critical task exited: api server returned",
                        );
                        error!("Xray API server task exited unexpectedly");
                    }
                    Ok(Err(err)) => {
                        crate::startup_log::eprintln_bootstrap(format!(
                            "critical task exited: api server error: {err}"
                        ));
                        error!(error = %err, "Xray API server task failed");
                        return Err(err);
                    }
                    Err(join_err) => {
                        crate::startup_log::eprintln_bootstrap(format!(
                            "critical task exited: api server join error: {join_err}"
                        ));
                        error!(error = %join_err, "Xray API server task join failed");
                        return Err(std::io::Error::other(join_err));
                    }
                }
            }
            _ = wait_shutdown_signal() => {
                info!("rust-xray shutting down after signal");
                crate::startup_log::eprintln_bootstrap("rust-xray shutting down after signal");
                api_task.abort();
            }
        }
    } else {
        wait_shutdown_signal().await;
        info!("rust-xray shutting down after signal");
        crate::startup_log::eprintln_bootstrap("rust-xray shutting down after signal");
    }

    crate::startup_log::eprintln_bootstrap("run_server returning");
    info!("rust-xray run_server exiting");
    Ok(())
}

async fn wait_shutdown_signal() {
    #[cfg(unix)]
    {
        use tokio::signal::unix::{signal, SignalKind};
        let mut sigterm = signal(SignalKind::terminate()).expect("install SIGTERM handler");
        let mut sigint = signal(SignalKind::interrupt()).expect("install SIGINT handler");
        tokio::select! {
            _ = tokio::signal::ctrl_c() => {}
            _ = sigterm.recv() => {}
            _ = sigint.recv() => {}
        }
    }
    #[cfg(not(unix))]
    {
        let _ = tokio::signal::ctrl_c().await;
    }
    info!("rust-xray received shutdown signal");
    crate::startup_log::eprintln_bootstrap("rust-xray received shutdown signal");
}

#[cfg(test)]
#[path = "../tests/unit/app.rs"]
mod tests;
