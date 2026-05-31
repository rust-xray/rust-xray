use std::collections::{BTreeMap, HashMap};
use std::path::Path;

use crate::dns::DnsConfig;
use crate::vless::{validate_fallback_configs, FallbackConfig};
use serde::Deserialize;
use serde_json::Value;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::UnixStream;
use tracing::{info, warn};

const REALITY_DEFAULT_DEST_PORT: u16 = 443;
const HTTP_UNIX_SCHEME: &str = "http+unix://";

#[derive(Debug, Clone, Deserialize, Default)]
pub struct LogConfig {
    pub loglevel: Option<String>,

    #[serde(flatten)]
    pub extra: BTreeMap<String, Value>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct ApiConfig {
    pub tag: String,
    #[serde(default)]
    pub listen: Option<String>,
    #[serde(default)]
    pub services: Vec<String>,
}

/// Empty object `{}` enables Xray stats counters (parsed for Remna compatibility).
#[derive(Debug, Clone, Deserialize, Default)]
pub struct StatsConfig {}

#[derive(Debug, Clone, Deserialize, Default, PartialEq, Eq)]
pub struct PolicyLevel {
    #[serde(rename = "statsUserUplink", default)]
    pub stats_user_uplink: bool,
    #[serde(rename = "statsUserDownlink", default)]
    pub stats_user_downlink: bool,
    #[serde(rename = "statsUserOnline", default)]
    pub stats_user_online: bool,

    #[serde(flatten)]
    pub extra: BTreeMap<String, Value>,
}

#[derive(Debug, Clone, Deserialize, Default, PartialEq, Eq)]
pub struct SystemPolicy {
    #[serde(rename = "statsInboundUplink", default)]
    pub stats_inbound_uplink: bool,
    #[serde(rename = "statsInboundDownlink", default)]
    pub stats_inbound_downlink: bool,
    #[serde(rename = "statsOutboundUplink", default)]
    pub stats_outbound_uplink: bool,
    #[serde(rename = "statsOutboundDownlink", default)]
    pub stats_outbound_downlink: bool,

    #[serde(flatten)]
    pub extra: BTreeMap<String, Value>,
}

#[derive(Debug, Clone, Deserialize, Default, PartialEq, Eq)]
pub struct PolicyConfig {
    #[serde(default)]
    pub levels: BTreeMap<String, PolicyLevel>,
    pub system: Option<SystemPolicy>,

    #[serde(flatten)]
    pub extra: BTreeMap<String, Value>,
}

#[derive(Debug, Clone, Deserialize, Default)]
pub struct RoutingRuleObject {
    #[serde(rename = "type", default)]
    pub rule_type: Option<String>,
    #[serde(rename = "inboundTag", default)]
    pub inbound_tag: Option<Value>,
    #[serde(rename = "outboundTag", default)]
    pub outbound_tag: Option<String>,
    #[serde(rename = "balancerTag", default)]
    pub balancer_tag: Option<String>,

    #[serde(flatten)]
    pub extra: BTreeMap<String, Value>,
}

#[derive(Debug, Clone, Deserialize, Default)]
pub struct RoutingConfig {
    #[serde(default)]
    pub rules: Vec<RoutingRuleObject>,
    #[serde(rename = "domainStrategy", default)]
    pub domain_strategy: Option<String>,
    #[serde(default)]
    pub balancers: Vec<Value>,

    #[serde(flatten)]
    pub extra: BTreeMap<String, Value>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct OutboundObject {
    pub tag: Option<String>,
    pub protocol: Option<String>,

    #[serde(flatten)]
    pub extra: BTreeMap<String, Value>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct XrayConfig {
    pub log: Option<LogConfig>,
    pub api: Option<ApiConfig>,
    pub dns: Option<DnsConfig>,
    pub stats: Option<StatsConfig>,
    pub policy: Option<PolicyConfig>,
    pub routing: Option<RoutingConfig>,

    #[serde(default)]
    pub outbounds: Vec<OutboundObject>,

    #[serde(default)]
    pub inbounds: Vec<InboundObject>,

    #[serde(flatten)]
    pub extra: BTreeMap<String, Value>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(untagged)]
pub enum InboundPortValue {
    Number(u16),
    String(String),
}

#[derive(Debug, Clone, Deserialize)]
pub struct InboundObject {
    pub tag: Option<String>,
    pub listen: Option<String>,
    pub port: Option<InboundPortValue>,
    pub protocol: Option<String>,
    pub settings: Option<Value>,
    #[serde(rename = "streamSettings")]
    pub stream_settings: Option<StreamSettingsObject>,

    #[serde(flatten)]
    pub extra: BTreeMap<String, Value>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct VlessInboundSettings {
    #[serde(default)]
    pub clients: Vec<VlessClientObject>,

    /// Inbound-level default flow (Remnawave panel / Xray upstream).
    pub flow: Option<String>,

    pub decryption: Option<String>,

    #[serde(default)]
    pub fallbacks: Vec<FallbackConfig>,

    #[serde(flatten)]
    pub extra: BTreeMap<String, Value>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct VlessClientObject {
    pub id: String,
    pub email: Option<String>,
    pub flow: Option<String>,
    pub level: Option<u32>,

    #[serde(flatten)]
    pub extra: BTreeMap<String, Value>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct StreamSettingsObject {
    pub network: Option<String>,
    pub security: Option<String>,
    #[serde(rename = "realitySettings")]
    pub reality_settings: Option<RealitySettingsObject>,
    #[serde(rename = "xhttpSettings")]
    pub xhttp_settings: Option<XHttpSettings>,
    #[serde(rename = "splithttpSettings")]
    pub splithttp_settings: Option<XHttpSettings>,

    #[serde(flatten)]
    pub extra: BTreeMap<String, Value>,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum TransportNetwork {
    RawTcp,
    XHttp,
}

impl TransportNetwork {
    pub fn parse(network: Option<&str>) -> std::io::Result<Self> {
        let normalized = network
            .map(str::trim)
            .filter(|value| !value.is_empty())
            .map(str::to_ascii_lowercase);

        match normalized.as_deref() {
            None | Some("tcp") | Some("raw") => Ok(Self::RawTcp),
            Some("xhttp") | Some("splithttp") => Ok(Self::XHttp),
            Some("grpc") => Err(std::io::Error::new(
                std::io::ErrorKind::Unsupported,
                "REALITY over gRPC runtime is not implemented yet",
            )),
            Some("ws") | Some("websocket") => Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "REALITY over WebSocket transport (network=ws) is not supported",
            )),
            Some("mkcp") | Some("kcp") => Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "REALITY over mKCP transport (network=mkcp/kcp) is not supported",
            )),
            Some("httpupgrade") => Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "REALITY over HTTPUpgrade transport (network=httpupgrade) is not supported",
            )),
            Some("hysteria") => Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "REALITY over Hysteria transport (network=hysteria) is not supported",
            )),
            Some(value) => Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                format!("unsupported REALITY transport network: {value}"),
            )),
        }
    }

    pub fn as_log_label(&self) -> &'static str {
        match self {
            Self::RawTcp => "raw",
            Self::XHttp => "xhttp",
        }
    }
}

#[derive(Debug, Clone, Deserialize, Default, PartialEq, Eq)]
pub struct XmuxRangeSettings {
    pub from: Option<i32>,
    pub to: Option<i32>,

    #[serde(flatten)]
    pub extra: BTreeMap<String, Value>,
}

#[derive(Debug, Clone, Deserialize, Default, PartialEq, Eq)]
pub struct XmuxSettings {
    #[serde(rename = "maxConcurrency")]
    pub max_concurrency: Option<XmuxRangeSettings>,
    #[serde(rename = "maxConnections")]
    pub max_connections: Option<XmuxRangeSettings>,
    #[serde(rename = "cMaxReuseTimes")]
    pub c_max_reuse_times: Option<XmuxRangeSettings>,
    #[serde(rename = "hMaxRequestTimes")]
    pub h_max_request_times: Option<XmuxRangeSettings>,
    #[serde(rename = "hMaxReusableSecs")]
    pub h_max_reusable_secs: Option<XmuxRangeSettings>,
    #[serde(rename = "hKeepAlivePeriod")]
    pub h_keep_alive_period: Option<i64>,

    #[serde(flatten)]
    pub extra: BTreeMap<String, Value>,
}

#[derive(Debug, Clone, Deserialize, Default, PartialEq, Eq)]
pub struct XHttpSettings {
    #[serde(default)]
    pub path: String,
    pub host: Option<String>,
    pub mode: Option<String>,
    #[serde(rename = "noGRPCHeader")]
    pub no_grpc_header: Option<bool>,
    #[serde(rename = "xPaddingBytes")]
    pub x_padding_bytes: Option<XmuxRangeSettings>,
    pub xmux: Option<XmuxSettings>,
    #[serde(rename = "downloadSettings")]
    pub download_settings: Option<Value>,
    #[serde(rename = "uploadSettings")]
    pub upload_settings: Option<Value>,

    #[serde(flatten)]
    pub extra: BTreeMap<String, Value>,
}

impl XHttpSettings {
    pub fn effective_mode(&self) -> &str {
        self.mode
            .as_deref()
            .map(str::trim)
            .filter(|value| !value.is_empty())
            .unwrap_or("auto")
    }

    pub fn effective_path(&self) -> &str {
        if self.path.trim().is_empty() {
            "/"
        } else {
            self.path.trim()
        }
    }
}

#[derive(Debug, Clone, Deserialize)]
pub struct RealitySettingsObject {
    #[serde(default)]
    pub show: bool,

    pub dest: Option<Value>,
    pub target: Option<Value>,

    #[serde(rename = "type")]
    pub transport_type: Option<String>,

    #[serde(default)]
    pub xver: u64,

    #[serde(rename = "serverNames", default)]
    pub server_names: Vec<String>,

    #[serde(rename = "privateKey")]
    pub private_key: Option<String>,

    #[serde(rename = "minClientVer")]
    pub min_client_ver: Option<String>,

    #[serde(rename = "maxClientVer")]
    pub max_client_ver: Option<String>,

    #[serde(rename = "maxTimeDiff", default)]
    pub max_time_diff: u64,

    #[serde(rename = "shortIds", default)]
    pub short_ids: Vec<String>,

    #[serde(rename = "mldsa65Seed")]
    pub mldsa65_seed: Option<String>,

    #[serde(rename = "limitFallbackUpload")]
    pub limit_fallback_upload: Option<Value>,

    #[serde(rename = "limitFallbackDownload")]
    pub limit_fallback_download: Option<Value>,

    #[serde(flatten)]
    pub extra: BTreeMap<String, Value>,
}

#[derive(Clone)]
pub struct RealityInboundRuntime {
    pub tag: Option<String>,
    /// All inbound tags merged into this runtime (includes `tag` when set).
    pub merged_inbound_tags: Vec<String>,
    pub protocol: Option<String>,
    pub listen_addr: String,
    pub dest_addr: String,
    pub private_key: String,
    pub server_names: Vec<String>,
    pub short_ids: Vec<Vec<u8>>,
    pub max_time_diff: u64,
    pub min_client_ver: Option<String>,
    pub max_client_ver: Option<String>,
    pub show: bool,
    pub mldsa65_seed: Option<crate::reality::Mldsa65Seed>,
    pub vless_clients: Vec<VlessClientObject>,
    pub vless_decryption: String,
    pub vless_fallbacks: Vec<FallbackConfig>,
    pub transport: TransportNetwork,
    pub xhttp_settings: Option<XHttpSettings>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RealityMldsa65RuntimeMode {
    Disabled,
    Enabled,
}

pub fn reality_mldsa65_runtime_mode(reality: &RealityInboundRuntime) -> RealityMldsa65RuntimeMode {
    if reality.mldsa65_seed.is_none() {
        RealityMldsa65RuntimeMode::Disabled
    } else {
        RealityMldsa65RuntimeMode::Enabled
    }
}

impl RealityInboundRuntime {
    pub fn mldsa65_runtime_mode(&self) -> RealityMldsa65RuntimeMode {
        reality_mldsa65_runtime_mode(self)
    }
}

impl std::fmt::Debug for RealityInboundRuntime {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RealityInboundRuntime")
            .field("tag", &self.tag)
            .field("merged_inbound_tags", &self.merged_inbound_tags)
            .field("protocol", &self.protocol)
            .field("listen_addr", &self.listen_addr)
            .field("dest_addr", &self.dest_addr)
            .field("private_key", &"<redacted>")
            .field("server_names", &self.server_names)
            .field("short_ids", &self.short_ids)
            .field("max_time_diff", &self.max_time_diff)
            .field("min_client_ver", &self.min_client_ver)
            .field("max_client_ver", &self.max_client_ver)
            .field("show", &self.show)
            .field(
                "mldsa65_seed",
                &self.mldsa65_seed.as_ref().map(|_| "<redacted>"),
            )
            .field("vless_clients", &self.vless_clients)
            .field("vless_decryption", &self.vless_decryption)
            .field("vless_fallbacks", &self.vless_fallbacks)
            .field("transport", &self.transport)
            .field("xhttp_settings", &self.xhttp_settings)
            .finish()
    }
}

fn eq_ignore_ascii_case(left: &str, right: &str) -> bool {
    left.eq_ignore_ascii_case(right)
}

fn is_vless_protocol(protocol: Option<&str>) -> bool {
    protocol.is_some_and(|value| eq_ignore_ascii_case(value, "vless"))
}

fn is_reality_security(security: Option<&str>) -> bool {
    security.is_some_and(|value| eq_ignore_ascii_case(value, "reality"))
}

fn is_vless_reality_inbound(inbound: &InboundObject) -> bool {
    inbound.stream_settings.as_ref().is_some_and(|stream| {
        is_vless_protocol(inbound.protocol.as_deref())
            && is_reality_security(stream.security.as_deref())
            && stream.reality_settings.is_some()
    })
}

/// Validate REALITY inbound `streamSettings.network`.
///
/// `tcp` is the legacy alias for raw TCP transport; `raw` is the explicit form.
pub fn validate_reality_transport_network(network: Option<&str>) -> std::io::Result<()> {
    TransportNetwork::parse(network).map(|_| ())
}

/// Validate `streamSettings.network` when `streamSettings.security` is REALITY.
pub fn validate_reality_stream_settings(stream: &StreamSettingsObject) -> std::io::Result<()> {
    if !is_reality_security(stream.security.as_deref()) {
        return Ok(());
    }

    validate_reality_transport_network(stream.network.as_deref())
}

/// Client-outbound REALITY fields that panels may leak into inbound server `realitySettings`.
const REALITY_CLIENT_ONLY_INBOUND_FIELDS: &[&str] = &[
    "fingerprint",
    "serverName",
    "password",
    "publicKey",
    "shortId",
    "mldsa65Verify",
    "spiderX",
    "spiderY",
    "masterKeyLog",
];

/// `streamSettings` sub-objects that are not implemented for REALITY inbound (misconfiguration risk).
///
/// `sockopt` is intentionally allowed so Xray-compatible smoke fixtures keep validating.
const REALITY_UNSUPPORTED_STREAM_SUBOBJECTS: &[&str] = &[
    "tlsSettings",
    "rawSettings",
    "tcpSettings",
    "wsSettings",
    "grpcSettings",
    "kcpSettings",
    "httpupgradeSettings",
    "hysteriaSettings",
    "finalmask",
    "address",
    "port",
];

/// Validate parsed-but-unsupported REALITY inbound fields at startup.
pub fn validate_reality_inbound_config_policy(
    stream: &StreamSettingsObject,
    settings: &RealitySettingsObject,
) -> std::io::Result<()> {
    if settings.limit_fallback_upload.is_some() {
        return Err(std::io::Error::new(
            std::io::ErrorKind::Unsupported,
            "realitySettings.limitFallbackUpload is not supported",
        ));
    }

    if settings.limit_fallback_download.is_some() {
        return Err(std::io::Error::new(
            std::io::ErrorKind::Unsupported,
            "realitySettings.limitFallbackDownload is not supported",
        ));
    }

    for field in REALITY_CLIENT_ONLY_INBOUND_FIELDS {
        if settings.extra.contains_key(*field) {
            warn!(
                field,
                "ignoring client-only realitySettings field on inbound REALITY server config"
            );
        }
    }

    for field in REALITY_UNSUPPORTED_STREAM_SUBOBJECTS {
        if stream.extra.contains_key(*field) {
            return Err(std::io::Error::new(
                std::io::ErrorKind::Unsupported,
                format!("streamSettings.{field} is not supported on REALITY inbound"),
            ));
        }
    }

    match TransportNetwork::parse(stream.network.as_deref())? {
        TransportNetwork::RawTcp => {
            if stream.xhttp_settings.is_some() || stream.splithttp_settings.is_some() {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::Unsupported,
                    "streamSettings.xhttpSettings is only supported when network=xhttp/splithttp",
                ));
            }
        }
        TransportNetwork::XHttp => {
            let settings = stream
                .xhttp_settings
                .as_ref()
                .or(stream.splithttp_settings.as_ref());
            if let Some(settings) = settings {
                let mode = settings.effective_mode();
                if !matches!(
                    mode,
                    "auto" | "stream-one" | "packet-up" | "packet-down" | "stream-up"
                ) {
                    return Err(std::io::Error::new(
                        std::io::ErrorKind::Unsupported,
                        format!("unsupported XHTTP mode: {mode}"),
                    ));
                }
            }
        }
    }

    Ok(())
}

fn validate_vless_reality_inbound_stream(inbound: &InboundObject) -> std::io::Result<()> {
    let stream = inbound.stream_settings.as_ref().ok_or_else(|| {
        std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "VLESS REALITY inbound is missing streamSettings",
        )
    })?;

    validate_reality_stream_settings(stream)?;

    if let Some(settings) = stream.reality_settings.as_ref() {
        validate_reality_inbound_config_policy(stream, settings)?;
    }

    Ok(())
}

pub fn find_vless_reality_inbounds(config: &XrayConfig) -> Vec<&InboundObject> {
    config
        .inbounds
        .iter()
        .filter(|inbound| is_vless_reality_inbound(inbound))
        .collect()
}

pub fn parse_inbound_port(port: Option<&InboundPortValue>) -> std::io::Result<u16> {
    let port = port.ok_or_else(|| {
        std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "inbound.port is required for REALITY inbound",
        )
    })?;

    match port {
        InboundPortValue::Number(value) => Ok(*value),
        InboundPortValue::String(value) => {
            if value.contains('-') {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::Unsupported,
                    format!("port ranges are not supported for REALITY inbound: {value}"),
                ));
            }
            value.parse::<u16>().map_err(|_| {
                std::io::Error::new(
                    std::io::ErrorKind::InvalidInput,
                    format!("invalid inbound port string: {value:?}"),
                )
            })
        }
    }
}

pub fn format_listen_host(listen: Option<&str>) -> std::io::Result<String> {
    let listen = listen
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .unwrap_or("0.0.0.0");

    if listen == "::" {
        return Ok("[::]".to_string());
    }
    if listen == "::1" || listen == "[::1]" {
        return Ok("[::1]".to_string());
    }
    if listen.starts_with('[') {
        if !listen.contains(']') {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                format!("invalid IPv6 listen address: {listen:?}"),
            ));
        }
        return Ok(listen.to_string());
    }
    if listen.contains(':') {
        return Ok(format!("[{listen}]"));
    }

    Ok(listen.to_string())
}

fn validate_vless_decryption(decryption: Option<&str>) -> std::io::Result<String> {
    match decryption.map(str::trim).filter(|value| !value.is_empty()) {
        None => Ok("none".to_string()),
        Some(value) if eq_ignore_ascii_case(value, "none") => Ok("none".to_string()),
        Some(value) => Err(std::io::Error::new(
            std::io::ErrorKind::Unsupported,
            format!("unsupported VLESS decryption: {value}; only 'none' is supported"),
        )),
    }
}

/// Known Xray API `services` entries (Remna panels typically enable Handler + Stats).
pub const KNOWN_API_SERVICES: &[&str] = &[
    "ReflectionService",
    "HandlerService",
    "LoggerService",
    "StatsService",
    "ObservatoryService",
    "RoutingService",
];

fn find_api_inbound<'a>(config: &'a XrayConfig, api_tag: &str) -> Option<&'a InboundObject> {
    find_api_inbound_with_source(config, api_tag)
        .ok()
        .map(|(inbound, _)| inbound)
}

fn validate_api_inbound_protocol(inbound: &InboundObject, api_tag: &str) -> std::io::Result<()> {
    if let Some(protocol) = inbound.protocol.as_deref() {
        if !eq_ignore_ascii_case(protocol, "dokodemo-door") {
            return Err(std::io::Error::new(
                std::io::ErrorKind::Unsupported,
                format!(
                    "api inbound {:?} uses unsupported protocol {protocol}; expected dokodemo-door",
                    api_tag
                ),
            ));
        }
    }

    Ok(())
}

fn api_rule_inbound_tags(rule: &RoutingRuleObject) -> Vec<&str> {
    match rule.inbound_tag.as_ref() {
        Some(Value::String(tag)) => vec![tag.as_str()],
        Some(Value::Array(tags)) => tags.iter().filter_map(Value::as_str).collect(),
        _ => Vec::new(),
    }
}

/// Parse Remnawave `http+unix://` config source into `(socket_path, request_path)`.
pub fn parse_http_unix_config_uri(source: &str) -> std::io::Result<(String, String)> {
    let (socket_path, request_path) = parse_http_unix_source(source)?;
    Ok((socket_path.to_string(), request_path.to_string()))
}

pub fn validate_xray_panel_config(config: &XrayConfig) -> std::io::Result<()> {
    if let Some(api) = config.api.as_ref() {
        if api.tag.trim().is_empty() {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "api.tag must not be empty",
            ));
        }
        if !api.services.is_empty() {
            let Some((listen, _, _)) = resolve_api_listen(config)? else {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidInput,
                    format!(
                        "API services configured for tag {:?} but no api.listen and no routed dokodemo-door API inbound was found",
                        api.tag
                    ),
                ));
            };
            crate::api::server::parse_api_grpc_listen_addr(&listen)?;
        } else if let Some((listen, _, _)) = resolve_api_listen(config)? {
            crate::api::server::parse_api_grpc_listen_addr(&listen)?;
        }
        for service in &api.services {
            let known = KNOWN_API_SERVICES
                .iter()
                .any(|candidate| eq_ignore_ascii_case(service, candidate));
            if !known {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::Unsupported,
                    format!("api.services entry is not supported: {service}"),
                ));
            }
        }
    }

    if let Some(routing) = config.routing.as_ref() {
        if !routing.rules.is_empty() {
            warn!(
                rule_count = routing.rules.len(),
                "routing.rules are parsed for API listen compatibility but are not enforced for proxy traffic"
            );
        }
        if !routing.balancers.is_empty() {
            return Err(std::io::Error::new(
                std::io::ErrorKind::Unsupported,
                "routing.balancers are not supported at runtime",
            ));
        }
    }

    Ok(())
}

pub fn load_xray_config_from_file(path: impl AsRef<Path>) -> std::io::Result<XrayConfig> {
    let path = path.as_ref();
    let contents = std::fs::read_to_string(path).map_err(|e| {
        std::io::Error::new(
            e.kind(),
            format!("failed to read config file {}: {e}", path.display()),
        )
    })?;

    let config: XrayConfig = serde_json::from_str(&contents).map_err(|e| {
        std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            format!("failed to parse config file {}: {e}", path.display()),
        )
    })?;
    validate_xray_panel_config(&config)?;
    Ok(config)
}

pub fn redact_config_source(source: &str) -> String {
    if let Some((before_query, _)) = source.split_once('?') {
        return format!("{before_query}?<redacted>");
    }
    source.to_string()
}

/// Config source kind for startup diagnostics.
pub fn config_source_kind(source: &str) -> &'static str {
    if source.starts_with(HTTP_UNIX_SCHEME) {
        "http+unix"
    } else {
        "file"
    }
}

const REMNAWAVE_INTERNAL_CONFIG_PATH: &str = "/internal/get-config";

/// True when config is loaded from Remnawave's internal `http+unix` socket API.
pub fn is_remnawave_http_unix_config_source(source: &str) -> bool {
    if config_source_kind(source) != "http+unix" {
        return false;
    }
    match parse_http_unix_config_uri(source) {
        Ok((_, path)) => path.starts_with(REMNAWAVE_INTERNAL_CONFIG_PATH),
        Err(_) => source.contains(REMNAWAVE_INTERNAL_CONFIG_PATH),
    }
}

/// Redacted Xray-style command line for logs (`rw-core -config ... -format json`).
pub fn format_redacted_run_command(
    program: &str,
    config_source: &str,
    format: Option<&str>,
) -> String {
    let mut parts = vec![
        program.to_string(),
        "-config".to_string(),
        redact_config_source(config_source),
    ];
    if let Some(format) = format {
        parts.push("-format".to_string());
        parts.push(format.to_string());
    }
    parts.join(" ")
}

/// How the API listen address was resolved (for startup logs).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ApiListenSource {
    ApiListenField,
    InboundTagMatchesApiTag,
    RoutingRule,
}

impl ApiListenSource {
    pub fn as_log_label(self) -> &'static str {
        match self {
            Self::ApiListenField => "api.listen",
            Self::InboundTagMatchesApiTag => "inbound.tag==api.tag",
            Self::RoutingRule => "routing.outboundTag==api.tag",
        }
    }
}

/// PEM material for Remnawave-style mTLS on the API dokodemo-door inbound.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ApiTlsMaterial {
    pub cert_pem: Vec<u8>,
    pub key_pem: Vec<u8>,
    pub ca_pem: Vec<u8>,
    pub server_name: Option<String>,
}

fn pem_bytes_from_json_value(value: &Value) -> Option<Vec<u8>> {
    match value {
        Value::String(text) => {
            let pem = text.replace("\\n", "\n");
            if pem.trim().is_empty() {
                None
            } else {
                Some(pem.into_bytes())
            }
        }
        Value::Array(lines) => {
            let joined = lines
                .iter()
                .filter_map(Value::as_str)
                .collect::<Vec<_>>()
                .join("\n");
            if joined.trim().is_empty() {
                None
            } else {
                Some(joined.into_bytes())
            }
        }
        _ => None,
    }
}

fn parse_tls_settings_certificates(
    tls_settings: &Value,
) -> std::io::Result<Option<ApiTlsMaterial>> {
    let Some(entries) = tls_settings.get("certificates").and_then(Value::as_array) else {
        return Ok(None);
    };

    let mut cert_pem = None;
    let mut key_pem = None;
    let mut ca_pem = None;

    for entry in entries {
        let Some(obj) = entry.as_object() else {
            continue;
        };
        let usage = obj
            .get("usage")
            .and_then(Value::as_str)
            .map(str::trim)
            .filter(|value| !value.is_empty());
        let certificate = obj.get("certificate").and_then(pem_bytes_from_json_value);
        if usage.is_some_and(|value| eq_ignore_ascii_case(value, "verify")) {
            if let Some(ca) = certificate {
                ca_pem = Some(ca);
            }
            continue;
        }
        if let Some(cert) = certificate {
            cert_pem = Some(cert);
        }
        if let Some(key) = obj.get("key").and_then(pem_bytes_from_json_value) {
            key_pem = Some(key);
        }
    }

    let (cert_pem, key_pem, ca_pem) = match (cert_pem, key_pem, ca_pem) {
        (Some(cert_pem), Some(key_pem), Some(ca_pem)) => (cert_pem, key_pem, ca_pem),
        _ => return Ok(None),
    };

    let server_name = tls_settings
        .get("serverName")
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(str::to_string);

    Ok(Some(ApiTlsMaterial {
        cert_pem,
        key_pem,
        ca_pem,
        server_name,
    }))
}

/// Parse Remnawave/Xray API inbound `streamSettings.tlsSettings` PEM material.
pub fn extract_tls_material_from_inbound(
    inbound: &InboundObject,
) -> std::io::Result<Option<ApiTlsMaterial>> {
    let Some(stream) = inbound.stream_settings.as_ref() else {
        return Ok(None);
    };
    if !stream
        .security
        .as_deref()
        .is_some_and(|value| eq_ignore_ascii_case(value, "tls"))
    {
        return Ok(None);
    }
    let Some(tls_settings) = stream.extra.get("tlsSettings") else {
        return Ok(None);
    };
    parse_tls_settings_certificates(tls_settings)
}

/// Extract API TLS material from the routed dokodemo-door inbound (if present).
pub fn extract_api_inbound_tls_material(
    config: &XrayConfig,
) -> std::io::Result<Option<ApiTlsMaterial>> {
    let Some(api) = config.api.as_ref() else {
        return Ok(None);
    };
    let Some(inbound) = find_api_inbound(config, api.tag.as_str()) else {
        return Ok(None);
    };
    extract_tls_material_from_inbound(inbound)
}

/// True when the resolved API listen address is localhost-only (`127.0.0.1:*`).
pub fn is_localhost_api_listen(listen: &str) -> bool {
    listen.trim().starts_with("127.0.0.1:")
}

/// Resolved API listen address and optional dokodemo-door inbound tag (when not using `api.listen`).
pub fn resolve_api_listen(
    config: &XrayConfig,
) -> std::io::Result<Option<(String, ApiListenSource, Option<String>)>> {
    let Some(api) = config.api.as_ref() else {
        return Ok(None);
    };

    if let Some(listen) = api
        .listen
        .as_deref()
        .map(str::trim)
        .filter(|s| !s.is_empty())
    {
        return Ok(Some((
            listen.to_string(),
            ApiListenSource::ApiListenField,
            None,
        )));
    }

    let (inbound, source) = find_api_inbound_with_source(config, api.tag.as_str())?;
    validate_api_inbound_protocol(inbound, api.tag.as_str())?;
    let listen = inbound_listen_addr(inbound)?;
    Ok(Some((listen, source, inbound.tag.clone())))
}

/// Tag of the dokodemo-door inbound used for API (if any).
pub fn api_dokodemo_inbound_tag(config: &XrayConfig) -> Option<String> {
    let api = config.api.as_ref()?;
    if api.listen.as_deref().is_some_and(|s| !s.trim().is_empty()) {
        return None;
    }
    find_api_inbound(config, api.tag.as_str()).and_then(|inbound| inbound.tag.clone())
}

pub fn api_listen_addr(config: &XrayConfig) -> std::io::Result<Option<String>> {
    Ok(resolve_api_listen(config)?.map(|(listen, _, _)| listen))
}

fn find_api_inbound_with_source<'a>(
    config: &'a XrayConfig,
    api_tag: &str,
) -> std::io::Result<(&'a InboundObject, ApiListenSource)> {
    if let Some(inbound) = config
        .inbounds
        .iter()
        .find(|inbound| inbound.tag.as_deref() == Some(api_tag))
    {
        return Ok((inbound, ApiListenSource::InboundTagMatchesApiTag));
    }

    let routing = config.routing.as_ref().ok_or_else(|| {
        std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            format!(
                "API services configured for tag {:?} but no api.listen and no routed dokodemo-door API inbound was found",
                api_tag
            ),
        )
    })?;

    let mut matched_inbounds = Vec::new();
    for rule in &routing.rules {
        if rule.outbound_tag.as_deref() != Some(api_tag) {
            continue;
        }
        for tag in api_rule_inbound_tags(rule) {
            if let Some(inbound) = config
                .inbounds
                .iter()
                .find(|inbound| inbound.tag.as_deref() == Some(tag))
            {
                matched_inbounds.push(inbound);
            }
        }
    }

    matched_inbounds.sort_by_key(|inbound| inbound.tag.as_deref().unwrap_or(""));
    matched_inbounds.dedup_by_key(|inbound| inbound.tag.as_deref().unwrap_or(""));

    match matched_inbounds.len() {
        0 => Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            format!(
                "API services configured for tag {:?} but no api.listen and no routed dokodemo-door API inbound was found",
                api_tag
            ),
        )),
        1 => Ok((
            matched_inbounds[0],
            ApiListenSource::RoutingRule,
        )),
        _ => {
            let tags: Vec<_> = matched_inbounds
                .iter()
                .filter_map(|inbound| inbound.tag.as_deref())
                .collect();
            Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                format!(
                    "ambiguous API inbound routing for tag {:?}: multiple inbounds matched ({tags:?})",
                    api_tag
                ),
            ))
        }
    }
}

pub async fn load_xray_config_from_source(source: &str) -> std::io::Result<XrayConfig> {
    let contents = if source.starts_with(HTTP_UNIX_SCHEME) {
        fetch_http_unix_config(source).await?
    } else {
        std::fs::read_to_string(source).map_err(|e| {
            std::io::Error::new(
                e.kind(),
                format!(
                    "failed to read config file {}: {e}",
                    redact_config_source(source)
                ),
            )
        })?
    };

    let config: XrayConfig = serde_json::from_str(&contents).map_err(|e| {
        std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            format!(
                "failed to parse config from {}: {e}",
                redact_config_source(source)
            ),
        )
    })?;
    validate_xray_panel_config(&config)?;
    Ok(config)
}

async fn fetch_http_unix_config(source: &str) -> std::io::Result<String> {
    let (socket_path, request_target) = parse_http_unix_source(source)?;
    crate::startup_log::eprintln_bootstrap(format!(
        "http+unix config fetch: socket={} path={}",
        socket_path,
        redact_config_source(request_target)
    ));
    let mut stream = UnixStream::connect(socket_path).await.map_err(|e| {
        std::io::Error::new(
            e.kind(),
            format!(
                "failed to connect config unix socket {}: {e}",
                redact_config_source(source)
            ),
        )
    })?;
    let request = format!(
        "GET {request_target} HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\nAccept: application/json\r\n\r\n"
    );
    stream.write_all(request.as_bytes()).await?;

    let mut response = Vec::new();
    stream.read_to_end(&mut response).await?;
    decode_http_config_response(source, &response)
}

fn parse_http_unix_source(source: &str) -> std::io::Result<(&str, &str)> {
    let rest = source.strip_prefix(HTTP_UNIX_SCHEME).ok_or_else(|| {
        std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "config source is not http+unix",
        )
    })?;
    let sock_end = rest
        .find(".sock")
        .map(|idx| idx + ".sock".len())
        .ok_or_else(|| {
            std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                format!(
                    "invalid http+unix config source {}: missing .sock path",
                    redact_config_source(source)
                ),
            )
        })?;
    let socket_path = &rest[..sock_end];
    let request_target = &rest[sock_end..];
    let request_target = if request_target.is_empty() {
        "/"
    } else {
        request_target
    };
    if !request_target.starts_with('/') {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            format!(
                "invalid http+unix config source {}: request path must start with /",
                redact_config_source(source)
            ),
        ));
    }
    Ok((socket_path, request_target))
}

fn decode_http_config_response(source: &str, response: &[u8]) -> std::io::Result<String> {
    let header_end = response
        .windows(4)
        .position(|window| window == b"\r\n\r\n")
        .ok_or_else(|| {
            std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                format!(
                    "invalid config response from {}: missing HTTP headers",
                    redact_config_source(source)
                ),
            )
        })?;
    let headers = std::str::from_utf8(&response[..header_end]).map_err(|e| {
        std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            format!(
                "invalid config response headers from {}: {e}",
                redact_config_source(source)
            ),
        )
    })?;
    let mut lines = headers.lines();
    let status_line = lines.next().unwrap_or_default();
    if !status_line.contains(" 200 ") {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            format!(
                "config endpoint {} returned {status_line}",
                redact_config_source(source)
            ),
        ));
    }
    let chunked = lines.any(|line| {
        line.split_once(':')
            .map(|(name, value)| {
                name.eq_ignore_ascii_case("transfer-encoding")
                    && value.to_ascii_lowercase().contains("chunked")
            })
            .unwrap_or(false)
    });
    let body = &response[header_end + 4..];
    let body = if chunked {
        decode_chunked_body(source, body)?
    } else {
        body.to_vec()
    };
    let body = trim_http_body_by_content_length(headers, &body);
    String::from_utf8(body).map_err(|e| {
        std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            format!(
                "config endpoint {} returned non-UTF-8 body: {e}",
                redact_config_source(source)
            ),
        )
    })
}

fn trim_http_body_by_content_length(headers: &str, body: &[u8]) -> Vec<u8> {
    let content_length = headers.lines().skip(1).find_map(|line| {
        let (name, value) = line.split_once(':')?;
        name.trim()
            .eq_ignore_ascii_case("content-length")
            .then(|| value.trim().parse::<usize>().ok())?
    });
    if let Some(len) = content_length {
        body.get(..len.min(body.len())).unwrap_or(body).to_vec()
    } else {
        body.to_vec()
    }
}

fn decode_chunked_body(source: &str, mut body: &[u8]) -> std::io::Result<Vec<u8>> {
    let mut decoded = Vec::new();
    loop {
        let line_end = body
            .windows(2)
            .position(|window| window == b"\r\n")
            .ok_or_else(|| {
                std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    format!(
                        "invalid chunked config response from {}",
                        redact_config_source(source)
                    ),
                )
            })?;
        let size_line = std::str::from_utf8(&body[..line_end]).map_err(|e| {
            std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                format!("invalid chunk size: {e}"),
            )
        })?;
        let size_hex = size_line.split(';').next().unwrap_or("").trim();
        let size = usize::from_str_radix(size_hex, 16).map_err(|e| {
            std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                format!("invalid chunk size: {e}"),
            )
        })?;
        body = &body[line_end + 2..];
        if size == 0 {
            return Ok(decoded);
        }
        if body.len() < size + 2 || &body[size..size + 2] != b"\r\n" {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                format!(
                    "truncated chunked config response from {}",
                    redact_config_source(source)
                ),
            ));
        }
        decoded.extend_from_slice(&body[..size]);
        body = &body[size + 2..];
    }
}

pub fn find_reality_inbounds(config: &XrayConfig) -> Vec<&InboundObject> {
    find_vless_reality_inbounds(config)
        .into_iter()
        .filter(|inbound| validate_vless_reality_inbound_stream(inbound).is_ok())
        .collect()
}

pub fn is_supported_reality_tcp_inbound(inbound: &InboundObject) -> bool {
    is_vless_reality_inbound(inbound) && validate_vless_reality_inbound_stream(inbound).is_ok()
}

pub fn get_inbound_reality_settings(inbound: &InboundObject) -> Option<&RealitySettingsObject> {
    inbound
        .stream_settings
        .as_ref()
        .and_then(|stream| stream.reality_settings.as_ref())
}

pub fn inbound_vless_settings(
    inbound: &InboundObject,
) -> std::io::Result<Option<VlessInboundSettings>> {
    if !is_vless_protocol(inbound.protocol.as_deref()) {
        return Ok(None);
    }

    let settings = inbound.settings.as_ref().ok_or_else(|| {
        std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "vless inbound settings are required",
        )
    })?;

    let settings: VlessInboundSettings = serde_json::from_value(settings.clone()).map_err(|e| {
        std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            format!("failed to parse vless inbound settings: {e}"),
        )
    })?;

    validate_vless_decryption(settings.decryption.as_deref())?;
    validate_fallback_configs(&settings.fallbacks)?;

    Ok(Some(settings))
}

pub fn inbound_listen_addr(inbound: &InboundObject) -> std::io::Result<String> {
    let host = format_listen_host(inbound.listen.as_deref())?;
    let port = parse_inbound_port(inbound.port.as_ref())?;
    Ok(format!("{host}:{port}"))
}

fn normalize_dest_addr(addr: &str) -> std::io::Result<String> {
    let addr = addr.trim();
    if addr.is_empty() {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "dest/target must not be empty",
        ));
    }

    if addr.starts_with('[') {
        let closing = addr.find(']').ok_or_else(|| {
            std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                format!("invalid IPv6 dest/target address: {addr:?}"),
            )
        })?;
        let host = &addr[..=closing];
        let remainder = &addr[closing + 1..];
        if remainder.is_empty() {
            return Ok(format!("{host}:{REALITY_DEFAULT_DEST_PORT}"));
        }
        if remainder.starts_with(':')
            && remainder[1..].parse::<u16>().is_ok()
            && remainder[1..].parse::<u16>().unwrap() > 0
        {
            return Ok(addr.to_string());
        }
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            format!("invalid IPv6 dest/target address: {addr:?}"),
        ));
    }

    if let Some((host, port)) = addr.rsplit_once(':') {
        if !host.is_empty() && port.parse::<u16>().is_ok() {
            return Ok(addr.to_string());
        }
    }

    Ok(format!("{addr}:{REALITY_DEFAULT_DEST_PORT}"))
}

fn parse_dest_target_value(value: &Value, field: &str) -> std::io::Result<String> {
    match value {
        Value::String(addr) => normalize_dest_addr(addr),
        Value::Number(_) => Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            format!("numeric realitySettings.{field} is not supported"),
        )),
        _ => Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            format!("realitySettings.{field} must be a JSON string"),
        )),
    }
}

pub fn reality_dest_addr(settings: &RealitySettingsObject) -> std::io::Result<String> {
    match (&settings.dest, &settings.target) {
        (Some(_), Some(_)) => Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "realitySettings.dest and realitySettings.target are mutually exclusive",
        )),
        (Some(dest), None) => parse_dest_target_value(dest, "dest"),
        (None, Some(target)) => parse_dest_target_value(target, "target"),
        (None, None) => Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "realitySettings.dest or realitySettings.target is required",
        )),
    }
}

pub fn reality_private_key(settings: &RealitySettingsObject) -> std::io::Result<&str> {
    match settings.private_key.as_deref() {
        Some(key) if !key.is_empty() => Ok(key),
        _ => Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "realitySettings.privateKey is required",
        )),
    }
}

pub fn reality_server_names(settings: &RealitySettingsObject) -> std::io::Result<Vec<String>> {
    if settings.server_names.is_empty() {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "realitySettings.serverNames must contain at least one server name",
        ));
    }

    for server_name in &settings.server_names {
        if server_name == "*" {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "wildcard realitySettings.serverNames are not supported",
            ));
        }
    }

    Ok(settings.server_names.clone())
}

pub fn reality_short_ids(settings: &RealitySettingsObject) -> std::io::Result<Vec<Vec<u8>>> {
    settings
        .short_ids
        .iter()
        .map(|short_id| crate::reality::parse_short_id_hex(short_id))
        .collect()
}

pub fn reality_mldsa65_seed(
    settings: &RealitySettingsObject,
    private_key: &str,
) -> std::io::Result<Option<crate::reality::Mldsa65Seed>> {
    crate::reality::decode_mldsa65_seed(settings.mldsa65_seed.as_deref(), private_key)
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
struct RealityMergeKey {
    listen_addr: String,
    private_key: String,
    dest_addr: String,
    vless_decryption: String,
    max_time_diff: u64,
    min_client_ver: Option<String>,
    max_client_ver: Option<String>,
    show: bool,
    mldsa65_present: bool,
    transport: TransportNetwork,
    xhttp_path: Option<String>,
    xhttp_host: Option<String>,
    xhttp_mode: Option<String>,
}

struct ParsedRealityInbound {
    tag: Option<String>,
    protocol: Option<String>,
    merge_key: RealityMergeKey,
    server_names: Vec<String>,
    short_ids: Vec<Vec<u8>>,
    mldsa65_seed: Option<crate::reality::Mldsa65Seed>,
    clients: Vec<VlessClientObject>,
    fallbacks: Vec<FallbackConfig>,
    xhttp_settings: Option<XHttpSettings>,
}

fn parse_reality_inbound_for_merge(
    inbound: &InboundObject,
) -> std::io::Result<ParsedRealityInbound> {
    let stream = inbound.stream_settings.as_ref().ok_or_else(|| {
        std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "VLESS REALITY inbound is missing streamSettings",
        )
    })?;
    let settings = get_inbound_reality_settings(inbound).ok_or_else(|| {
        std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "reality inbound is missing realitySettings",
        )
    })?;
    validate_reality_inbound_config_policy(stream, settings)?;
    let transport = TransportNetwork::parse(stream.network.as_deref())?;
    let xhttp_settings = match transport {
        TransportNetwork::RawTcp => None,
        TransportNetwork::XHttp => Some(
            stream
                .xhttp_settings
                .clone()
                .or_else(|| stream.splithttp_settings.clone())
                .unwrap_or_default(),
        ),
    };

    let private_key = reality_private_key(settings)?.to_owned();
    crate::reality::validate_reality_private_key_b64(&private_key)?;
    let mldsa65_seed = reality_mldsa65_seed(settings, &private_key)?;

    let vless_settings = inbound_vless_settings(inbound)?;
    let (clients, vless_decryption, fallbacks) = match vless_settings {
        Some(settings) => {
            let mut clients = settings.clients;
            crate::vless::apply_inbound_vless_client_flows(
                &mut clients,
                settings.flow.as_deref(),
                stream.security.as_deref(),
                stream.network.as_deref(),
            )?;
            (
                clients,
                settings
                    .decryption
                    .as_deref()
                    .filter(|value| !value.is_empty())
                    .map(str::to_string)
                    .unwrap_or_else(|| "none".to_string()),
                settings.fallbacks,
            )
        }
        None => (Vec::new(), "none".to_string(), Vec::new()),
    };

    Ok(ParsedRealityInbound {
        tag: inbound.tag.clone(),
        protocol: inbound.protocol.clone(),
        merge_key: RealityMergeKey {
            listen_addr: inbound_listen_addr(inbound)?,
            private_key,
            dest_addr: reality_dest_addr(settings)?,
            vless_decryption: vless_decryption.clone(),
            max_time_diff: settings.max_time_diff,
            min_client_ver: settings.min_client_ver.clone(),
            max_client_ver: settings.max_client_ver.clone(),
            show: settings.show,
            mldsa65_present: mldsa65_seed.is_some(),
            transport,
            xhttp_path: xhttp_settings
                .as_ref()
                .map(|settings| settings.effective_path().to_string()),
            xhttp_host: xhttp_settings.as_ref().and_then(|settings| {
                settings
                    .host
                    .as_deref()
                    .map(str::trim)
                    .filter(|value| !value.is_empty())
                    .map(str::to_ascii_lowercase)
            }),
            xhttp_mode: xhttp_settings
                .as_ref()
                .map(|settings| settings.effective_mode().to_ascii_lowercase()),
        },
        server_names: reality_server_names(settings)?,
        short_ids: reality_short_ids(settings)?,
        mldsa65_seed,
        clients,
        fallbacks,
        xhttp_settings,
    })
}

fn merge_server_names(values: impl IntoIterator<Item = String>) -> Vec<String> {
    let mut merged = Vec::new();
    for name in values {
        if !merged.iter().any(|existing| existing == &name) {
            merged.push(name);
        }
    }
    merged
}

fn merge_short_ids(values: impl IntoIterator<Item = Vec<u8>>) -> Vec<Vec<u8>> {
    let mut merged = Vec::new();
    for short_id in values {
        if !merged.iter().any(|existing| existing == &short_id) {
            merged.push(short_id);
        }
    }
    merged
}

fn log_supported_reality_inbound(parsed: &ParsedRealityInbound) {
    info!(
        inbound_tag = ?parsed.tag,
        listen = %parsed.merge_key.listen_addr,
        server_name_count = parsed.server_names.len(),
        user_count = parsed.clients.len(),
        flow_distribution = %crate::vless::format_vless_flow_distribution(
            &crate::vless::vless_flow_distribution(&parsed.clients)
        ),
        "supported VLESS REALITY inbound"
    );
}

fn build_reality_inbound_runtime_from_group(
    group: &[ParsedRealityInbound],
) -> std::io::Result<RealityInboundRuntime> {
    let primary = &group[0];
    let mut merged_tags: Vec<String> = group
        .iter()
        .filter_map(|inbound| inbound.tag.clone())
        .collect();
    if merged_tags.is_empty() {
        merged_tags.push("reality-in".to_string());
    }
    if group.len() > 1 {
        info!(
            merged_inbound_count = group.len(),
            merged_tags = ?merged_tags,
            listen = %primary.merge_key.listen_addr,
            "merging compatible VLESS REALITY inbounds on shared listen address"
        );
    }

    let merged_clients = crate::vless::merge_vless_client_objects(
        group.iter().flat_map(|inbound| inbound.clients.clone()),
    )?;
    crate::vless::validate_vless_client_flows(&merged_clients)?;
    if primary.merge_key.transport == TransportNetwork::XHttp
        && merged_clients.iter().any(|client| {
            client
                .flow
                .as_deref()
                .is_some_and(|flow| flow.trim() == "xtls-rprx-vision")
        })
    {
        return Err(std::io::Error::new(
            std::io::ErrorKind::Unsupported,
            "flow=xtls-rprx-vision over XHTTP is not supported in the stream-one MVP",
        ));
    }
    crate::vless::build_vless_clients(&merged_clients).map(|_| ())?;

    let merged_server_names = merge_server_names(
        group
            .iter()
            .flat_map(|inbound| inbound.server_names.clone()),
    );
    let merged_short_ids =
        merge_short_ids(group.iter().flat_map(|inbound| inbound.short_ids.clone()));

    info!(
        inbound_tag = ?primary.tag,
        merged_tags = ?merged_tags,
        listen = %primary.merge_key.listen_addr,
        user_count = merged_clients.len(),
        flow_distribution = %crate::vless::format_vless_flow_distribution(
            &crate::vless::vless_flow_distribution(&merged_clients)
        ),
        "selected VLESS REALITY inbound runtime"
    );

    Ok(RealityInboundRuntime {
        tag: primary.tag.clone(),
        merged_inbound_tags: merged_tags,
        protocol: primary.protocol.clone(),
        listen_addr: primary.merge_key.listen_addr.clone(),
        dest_addr: primary.merge_key.dest_addr.clone(),
        private_key: primary.merge_key.private_key.clone(),
        server_names: merged_server_names,
        short_ids: merged_short_ids,
        max_time_diff: primary.merge_key.max_time_diff,
        min_client_ver: primary.merge_key.min_client_ver.clone(),
        max_client_ver: primary.merge_key.max_client_ver.clone(),
        show: primary.merge_key.show,
        mldsa65_seed: primary.mldsa65_seed.clone(),
        vless_clients: merged_clients,
        vless_decryption: primary.merge_key.vless_decryption.clone(),
        vless_fallbacks: primary.fallbacks.clone(),
        transport: primary.merge_key.transport.clone(),
        xhttp_settings: primary.xhttp_settings.clone(),
    })
}

/// All supported VLESS REALITY runtime listeners (one per compatible merge group).
pub fn reality_inbound_runtimes(
    config: &XrayConfig,
) -> std::io::Result<Vec<RealityInboundRuntime>> {
    let inbounds = find_reality_inbounds(config);
    if inbounds.is_empty() {
        let vless_reality_inbounds = find_vless_reality_inbounds(config);
        if let Some(inbound) = vless_reality_inbounds.first() {
            if let Err(err) = validate_vless_reality_inbound_stream(inbound) {
                return Err(err);
            }
        }
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "no supported VLESS TCP REALITY inbound found",
        ));
    }

    let mut parsed_inbounds = Vec::with_capacity(inbounds.len());
    for inbound in inbounds {
        parsed_inbounds.push(parse_reality_inbound_for_merge(inbound)?);
    }

    for parsed in &parsed_inbounds {
        log_supported_reality_inbound(parsed);
    }

    let mut groups: HashMap<RealityMergeKey, Vec<ParsedRealityInbound>> = HashMap::new();
    for parsed in parsed_inbounds {
        groups
            .entry(parsed.merge_key.clone())
            .or_default()
            .push(parsed);
    }

    let mut runtimes = Vec::with_capacity(groups.len());
    for group in groups.into_values() {
        runtimes.push(build_reality_inbound_runtime_from_group(&group)?);
    }
    runtimes.sort_by(|left, right| left.listen_addr.cmp(&right.listen_addr));
    Ok(runtimes)
}

pub fn first_reality_inbound_runtime(
    config: &XrayConfig,
) -> std::io::Result<RealityInboundRuntime> {
    reality_inbound_runtimes(config)?
        .into_iter()
        .next()
        .ok_or_else(|| {
            std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "no supported VLESS TCP REALITY inbound found",
            )
        })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeMap;

    const TEST_REALITY_PRIVATE_KEY: &str = "CMZoLYnNxeaUoLn7LwK4RzBIdpzBXI5TOIlZ3tEfOn4";
    const TEST_MLDSA65_SEED: &str = "AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8";
    const TEST_MLDSA65_SEED_31_BYTES: &str = "AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHg";
    const TEST_MLDSA65_SEED_33_BYTES: &str = "AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8g";

    const MINIMAL_VLESS_REALITY: &str = r#"{
        "inbounds": [{
            "listen": "0.0.0.0",
            "port": 443,
            "protocol": "vless",
            "settings": {
                "clients": [{"id": "00000000-0000-0000-0000-000000000001"}],
                "decryption": "none"
            },
            "streamSettings": {
                "network": "tcp",
                "security": "reality",
                "realitySettings": {
                    "show": false,
                    "dest": "www.example.com:443",
                    "serverNames": ["www.example.com"],
                    "privateKey": "CMZoLYnNxeaUoLn7LwK4RzBIdpzBXI5TOIlZ3tEfOn4",
                    "shortIds": ["", "0123456789abcdef"]
                },
                "sockopt": {"tcpFastOpen": true}
            },
            "sniffing": {"enabled": true}
        }],
        "outbounds": [{"protocol": "freedom"}],
        "unknownTopLevel": {"enabled": true}
    }"#;

    #[test]
    fn parse_config_without_inbounds_defaults_to_empty() {
        let json = r#"{"outbounds": [{"protocol": "freedom"}]}"#;

        let config: XrayConfig = serde_json::from_str(json).expect("parse config");

        assert!(config.inbounds.is_empty());
        assert!(find_reality_inbounds(&config).is_empty());

        let err = first_reality_inbound_runtime(&config).unwrap_err();
        assert_eq!(err.kind(), std::io::ErrorKind::InvalidInput);
        assert_eq!(
            err.to_string(),
            "no supported VLESS TCP REALITY inbound found"
        );
    }

    #[test]
    fn top_level_dns_tcp_server_parse() {
        let json = r#"{"dns":{"servers":["tcp://1.1.1.1:53"],"queryStrategy":"UseIPv4"}}"#;
        let config: XrayConfig = serde_json::from_str(json).expect("parse config");
        let dns = config.dns.expect("dns block");
        assert_eq!(dns.servers.len(), 1);
        assert_eq!(dns.servers[0].host, "1.1.1.1");
        assert_eq!(dns.servers[0].port, 53);
        assert_eq!(
            dns.servers[0].transport,
            crate::dns::DnsServerTransport::Tcp
        );
        assert_eq!(dns.query_strategy, crate::dns::QueryStrategy::UseIPv4);
    }

    #[test]
    fn top_level_dns_udp_and_doh_parse_without_runtime_support() {
        let json = r#"{"dns":{"servers":["1.1.1.1","https://dns.google/dns-query"]}}"#;
        let config: XrayConfig = serde_json::from_str(json).expect("parse config");
        let dns = config.dns.expect("dns block");
        assert_eq!(
            dns.servers[0].transport,
            crate::dns::DnsServerTransport::Udp
        );
        assert_eq!(dns.servers[0].port, 53);
        assert_eq!(
            dns.servers[1].transport,
            crate::dns::DnsServerTransport::Doh
        );
        assert_eq!(dns.servers[1].path.as_deref(), Some("/dns-query"));
    }

    #[test]
    fn parse_minimal_vless_reality_inbound() {
        let config: XrayConfig = serde_json::from_str(MINIMAL_VLESS_REALITY).expect("parse config");
        let inbounds = find_reality_inbounds(&config);

        assert_eq!(inbounds.len(), 1);
        assert_eq!(inbounds[0].protocol.as_deref(), Some("vless"));
        assert_eq!(inbound_listen_addr(inbounds[0]).unwrap(), "0.0.0.0:443");

        let settings = get_inbound_reality_settings(inbounds[0]).unwrap();
        assert_eq!(reality_dest_addr(settings).unwrap(), "www.example.com:443");
        assert_eq!(
            reality_private_key(settings).unwrap(),
            "CMZoLYnNxeaUoLn7LwK4RzBIdpzBXI5TOIlZ3tEfOn4"
        );
        assert_eq!(settings.server_names, vec!["www.example.com".to_string()]);
    }

    #[test]
    fn builds_first_reality_inbound_runtime() {
        let json = r#"{
            "inbounds": [{
                "tag": "reality-in",
                "listen": "127.0.0.1",
                "port": 443,
                "protocol": "vless",
                "settings": {
                    "clients": [{"id": "00000000-0000-0000-0000-000000000001"}],
                    "decryption": "none"
                },
                "streamSettings": {
                    "network": "tcp",
                    "security": "reality",
                    "realitySettings": {
                        "show": false,
                        "dest": "www.example.com:443",
                        "serverNames": ["www.example.com"],
                        "privateKey": "CMZoLYnNxeaUoLn7LwK4RzBIdpzBXI5TOIlZ3tEfOn4",
                        "maxTimeDiff": 10000,
                        "shortIds": ["", "0123456789abcdef"]
                    }
                }
            }]
        }"#;

        let config: XrayConfig = serde_json::from_str(json).unwrap();
        let runtime = first_reality_inbound_runtime(&config).unwrap();

        assert_eq!(runtime.tag.as_deref(), Some("reality-in"));
        assert_eq!(runtime.protocol.as_deref(), Some("vless"));
        assert_eq!(runtime.listen_addr, "127.0.0.1:443");
        assert_eq!(runtime.dest_addr, "www.example.com:443");
        assert_eq!(runtime.server_names, vec!["www.example.com".to_string()]);
        assert_eq!(
            runtime.short_ids,
            vec![
                Vec::<u8>::new(),
                vec![0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef]
            ]
        );
        assert_eq!(runtime.max_time_diff, 10000);
        assert!(!runtime.show);
        assert_eq!(runtime.private_key, TEST_REALITY_PRIVATE_KEY);
        assert_eq!(runtime.vless_clients.len(), 1);
        assert_eq!(
            runtime.vless_clients[0].id,
            "00000000-0000-0000-0000-000000000001"
        );
        assert_eq!(runtime.vless_decryption, "none");
    }

    #[test]
    fn inbound_vless_settings_parses_fallback_dest_number() {
        let json = r#"{
            "protocol": "vless",
            "settings": {
                "clients": [{"id": "00000000-0000-0000-0000-000000000001"}],
                "decryption": "none",
                "fallbacks": [{"dest": 8080}]
            }
        }"#;

        let inbound: InboundObject = serde_json::from_str(json).unwrap();
        let settings = inbound_vless_settings(&inbound).unwrap().unwrap();

        assert_eq!(settings.fallbacks.len(), 1);
        assert_eq!(settings.fallbacks[0].dest.addr, "127.0.0.1:8080");
    }

    #[test]
    fn inbound_vless_settings_parses_clients_and_decryption() {
        let json = r#"{
            "protocol": "vless",
            "settings": {
                "clients": [{
                    "id": "00000000-0000-0000-0000-000000000001",
                    "email": "user@example.com",
                    "flow": "xtls-rprx-vision",
                    "level": 0
                }],
                "decryption": "none",
                "fallbacks": []
            }
        }"#;

        let inbound: InboundObject = serde_json::from_str(json).unwrap();
        let settings = inbound_vless_settings(&inbound).unwrap().unwrap();

        assert_eq!(settings.clients.len(), 1);
        assert_eq!(
            settings.clients[0].id,
            "00000000-0000-0000-0000-000000000001"
        );
        assert_eq!(
            settings.clients[0].email.as_deref(),
            Some("user@example.com")
        );
        assert_eq!(
            settings.clients[0].flow.as_deref(),
            Some("xtls-rprx-vision")
        );
        assert_eq!(settings.decryption.as_deref(), Some("none"));
        assert!(settings.fallbacks.is_empty());
        assert_eq!(settings.clients[0].level, Some(0));
    }

    #[test]
    fn inbound_vless_settings_returns_none_for_non_vless_protocol() {
        let json = r#"{
            "protocol": "trojan",
            "settings": {"clients": []}
        }"#;

        let inbound: InboundObject = serde_json::from_str(json).unwrap();

        assert!(inbound_vless_settings(&inbound).unwrap().is_none());
    }

    #[test]
    fn inbound_vless_settings_requires_settings_for_vless() {
        let inbound = InboundObject {
            tag: None,
            listen: None,
            port: None,
            protocol: Some("vless".to_string()),
            settings: None,
            stream_settings: None,
            extra: BTreeMap::new(),
        };

        let err = inbound_vless_settings(&inbound).unwrap_err();
        assert_eq!(err.kind(), std::io::ErrorKind::InvalidInput);
    }

    #[test]
    fn builds_first_reality_inbound_runtime_with_policy_fields() {
        let json = r#"{
            "inbounds": [{
                "tag": "reality-in",
                "listen": "127.0.0.1",
                "port": 443,
                "protocol": "vless",
                "settings": {
                    "clients": [{"id": "00000000-0000-0000-0000-000000000001"}],
                    "decryption": "none"
                },
                "streamSettings": {
                    "security": "reality",
                    "realitySettings": {
                        "show": true,
                        "dest": "www.example.com:443",
                        "serverNames": ["Example.COM"],
                        "privateKey": "CMZoLYnNxeaUoLn7LwK4RzBIdpzBXI5TOIlZ3tEfOn4",
                        "minClientVer": "1.8.0",
                        "maxClientVer": "24.9.30",
                        "maxTimeDiff": 5000,
                        "shortIds": [""]
                    }
                }
            }]
        }"#;

        let config: XrayConfig = serde_json::from_str(json).unwrap();
        let runtime = first_reality_inbound_runtime(&config).unwrap();

        assert_eq!(runtime.tag.as_deref(), Some("reality-in"));
        assert_eq!(runtime.protocol.as_deref(), Some("vless"));
        assert_eq!(runtime.server_names, vec!["Example.COM".to_string()]);
        assert_eq!(runtime.min_client_ver.as_deref(), Some("1.8.0"));
        assert_eq!(runtime.max_client_ver.as_deref(), Some("24.9.30"));
        assert_eq!(runtime.max_time_diff, 5000);
        assert!(runtime.show);
    }

    #[test]
    fn parse_reality_settings_supports_target_alias() {
        let json = r#"{
            "inbounds": [{
                "port": 8443,
                "streamSettings": {
                    "security": "reality",
                    "realitySettings": {
                        "target": "example.com:443",
                        "privateKey": "abc",
                        "shortIds": [""]
                    }
                }
            }]
        }"#;

        let config: XrayConfig = serde_json::from_str(json).unwrap();
        let settings = get_inbound_reality_settings(&config.inbounds[0]).unwrap();
        assert_eq!(reality_dest_addr(settings).unwrap(), "example.com:443");
    }

    #[test]
    fn parse_reality_settings_rejects_dest_and_target_together() {
        let json = r#"{
            "inbounds": [{
                "port": 8443,
                "streamSettings": {
                    "security": "reality",
                    "realitySettings": {
                        "dest": "a.example.com:443",
                        "target": "b.example.com:443",
                        "privateKey": "abc",
                        "shortIds": [""]
                    }
                }
            }]
        }"#;

        let config: XrayConfig = serde_json::from_str(json).unwrap();
        let settings = get_inbound_reality_settings(&config.inbounds[0]).unwrap();
        let err = reality_dest_addr(settings).unwrap_err();
        assert_eq!(err.kind(), std::io::ErrorKind::InvalidInput);
    }

    #[test]
    fn find_reality_inbounds_skips_non_reality_security() {
        let json = r#"{
            "inbounds": [{
                "port": 443,
                "streamSettings": {
                    "security": "tls",
                    "realitySettings": {
                        "dest": "example.com:443",
                        "privateKey": "abc",
                        "shortIds": [""]
                    }
                }
            }]
        }"#;

        let config: XrayConfig = serde_json::from_str(json).unwrap();
        assert!(find_reality_inbounds(&config).is_empty());
    }

    #[test]
    fn parse_preserves_unknown_fields_in_extra() {
        let config: XrayConfig = serde_json::from_str(MINIMAL_VLESS_REALITY).unwrap();

        assert!(config.extra.contains_key("unknownTopLevel"));
        assert!(config.inbounds[0].extra.contains_key("sniffing"));

        let stream = config.inbounds[0].stream_settings.as_ref().unwrap();
        assert!(stream.extra.contains_key("sockopt"));
        assert_eq!(
            stream.extra["sockopt"]["tcpFastOpen"],
            serde_json::json!(true)
        );
    }

    #[test]
    fn parse_short_ids_empty_and_hex() {
        let json = r#"{
            "inbounds": [{
                "port": 443,
                "streamSettings": {
                    "security": "reality",
                    "realitySettings": {
                        "dest": "example.com:443",
                        "privateKey": "abc",
                        "shortIds": ["", "0123456789abcdef"]
                    }
                }
            }]
        }"#;

        let config: XrayConfig = serde_json::from_str(json).unwrap();
        let settings = get_inbound_reality_settings(&config.inbounds[0]).unwrap();
        let short_ids = reality_short_ids(settings).unwrap();

        assert_eq!(short_ids.len(), 2);
        assert!(short_ids[0].is_empty());
        assert_eq!(
            short_ids[1],
            vec![0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef]
        );
    }

    const REALISTIC_XRAY_SERVER: &str =
        include_str!("../../scripts/live_reality_smoke/xray-compatible-server.fixture.json");

    #[test]
    fn parses_realistic_xray_vless_tcp_reality_server_config() {
        let config: XrayConfig =
            serde_json::from_str(REALISTIC_XRAY_SERVER).expect("parse realistic config");
        let runtime = first_reality_inbound_runtime(&config).expect("runtime");

        assert_eq!(runtime.listen_addr, "127.0.0.1:24443");
        assert_eq!(runtime.dest_addr, "www.microsoft.com:443");
        assert_eq!(runtime.vless_decryption, "none");
        assert!(config.log.is_some());
        assert!(config.routing.is_some());
        assert_eq!(config.outbounds.len(), 2);
        assert!(config.inbounds[0].extra.contains_key("sniffing"));
        assert!(config.inbounds[0]
            .stream_settings
            .as_ref()
            .unwrap()
            .extra
            .contains_key("sockopt"));
    }

    #[test]
    fn accepts_port_as_string() {
        let inbound: InboundObject =
            serde_json::from_str(r#"{"listen":"127.0.0.1","port":"443","protocol":"vless"}"#)
                .unwrap();
        assert_eq!(inbound_listen_addr(&inbound).unwrap(), "127.0.0.1:443");
    }

    #[test]
    fn rejects_port_range() {
        let inbound: InboundObject =
            serde_json::from_str(r#"{"listen":"127.0.0.1","port":"10000-20000"}"#).unwrap();
        let err = inbound_listen_addr(&inbound).unwrap_err();
        assert_eq!(err.kind(), std::io::ErrorKind::Unsupported);
        assert_eq!(
            err.to_string(),
            "port ranges are not supported for REALITY inbound: 10000-20000"
        );
    }

    #[test]
    fn formats_ipv6_listen_correctly() {
        assert_eq!(format_listen_host(Some("::")).unwrap(), "[::]");
        assert_eq!(format_listen_host(Some("::1")).unwrap(), "[::1]");
        assert_eq!(format_listen_host(Some("[::1]")).unwrap(), "[::1]");
        assert_eq!(
            inbound_listen_addr(&InboundObject {
                tag: None,
                listen: Some("::1".to_string()),
                port: Some(InboundPortValue::Number(24443)),
                protocol: None,
                settings: None,
                stream_settings: None,
                extra: BTreeMap::new(),
            })
            .unwrap(),
            "[::1]:24443"
        );
    }

    #[test]
    fn accepts_security_and_protocol_case_insensitively() {
        let json = r#"{
            "inbounds": [{
                "port": 443,
                "protocol": "VLESS",
                "settings": {"clients": [], "decryption": "none"},
                "streamSettings": {
                    "security": "REALITY",
                    "realitySettings": {
                        "dest": "example.com:443",
                        "serverNames": ["example.com"],
                        "privateKey": "CMZoLYnNxeaUoLn7LwK4RzBIdpzBXI5TOIlZ3tEfOn4",
                        "shortIds": [""]
                    }
                }
            }]
        }"#;
        let config: XrayConfig = serde_json::from_str(json).unwrap();
        assert_eq!(find_reality_inbounds(&config).len(), 1);
    }

    #[test]
    fn accepts_network_raw_as_tcp_compatible() {
        let json = r#"{
            "inbounds": [{
                "port": 443,
                "protocol": "vless",
                "settings": {"clients": [], "decryption": "none"},
                "streamSettings": {
                    "network": "raw",
                    "security": "reality",
                    "realitySettings": {
                        "dest": "example.com:443",
                        "serverNames": ["example.com"],
                        "privateKey": "CMZoLYnNxeaUoLn7LwK4RzBIdpzBXI5TOIlZ3tEfOn4",
                        "shortIds": [""]
                    }
                }
            }]
        }"#;
        let config: XrayConfig = serde_json::from_str(json).unwrap();
        assert_eq!(find_reality_inbounds(&config).len(), 1);
        assert!(validate_reality_transport_network(Some("raw")).is_ok());
        assert!(validate_reality_transport_network(Some("tcp")).is_ok());
        assert!(validate_reality_transport_network(None).is_ok());
    }

    fn vless_reality_inbound_json(network: &str) -> String {
        format!(
            r#"{{
            "inbounds": [{{
                "port": 443,
                "protocol": "vless",
                "settings": {{"clients": [], "decryption": "none"}},
                "streamSettings": {{
                    "network": "{network}",
                    "security": "reality",
                    "realitySettings": {{
                        "dest": "example.com:443",
                        "serverNames": ["example.com"],
                        "privateKey": "{TEST_REALITY_PRIVATE_KEY}",
                        "shortIds": [""]
                    }}
                }}
            }}]
        }}"#
        )
    }

    #[test]
    fn validate_reality_transport_network_accepts_tcp_as_legacy_raw_alias() {
        assert!(validate_reality_transport_network(Some("tcp")).is_ok());
        assert!(validate_reality_transport_network(Some("TCP")).is_ok());
    }

    #[test]
    fn validate_reality_transport_network_accepts_raw() {
        assert!(validate_reality_transport_network(Some("raw")).is_ok());
        assert!(validate_reality_transport_network(Some("RAW")).is_ok());
    }

    #[test]
    fn validate_reality_transport_network_accepts_xhttp_aliases() {
        assert!(validate_reality_transport_network(Some("xhttp")).is_ok());
        assert!(validate_reality_transport_network(Some("splithttp")).is_ok());
        assert!(validate_reality_transport_network(Some("splitHTTP")).is_ok());
    }

    #[test]
    fn validate_reality_transport_network_rejects_grpc_as_unimplemented() {
        let err = validate_reality_transport_network(Some("grpc")).unwrap_err();
        assert_eq!(err.kind(), std::io::ErrorKind::Unsupported);
        assert_eq!(
            err.to_string(),
            "REALITY over gRPC runtime is not implemented yet"
        );
    }

    #[test]
    fn validate_reality_transport_network_rejects_websocket_variants() {
        for network in ["ws", "websocket", "WebSocket"] {
            let err = validate_reality_transport_network(Some(network)).unwrap_err();
            assert_eq!(err.kind(), std::io::ErrorKind::InvalidInput);
            assert!(err.to_string().contains("WebSocket"));
        }
    }

    #[test]
    fn validate_reality_transport_network_rejects_mkcp_httpupgrade_and_hysteria() {
        let cases = [
            (
                "mkcp",
                "REALITY over mKCP transport (network=mkcp/kcp) is not supported",
            ),
            (
                "kcp",
                "REALITY over mKCP transport (network=mkcp/kcp) is not supported",
            ),
            (
                "httpupgrade",
                "REALITY over HTTPUpgrade transport (network=httpupgrade) is not supported",
            ),
            (
                "hysteria",
                "REALITY over Hysteria transport (network=hysteria) is not supported",
            ),
        ];
        for (network, message) in cases {
            let err = validate_reality_transport_network(Some(network)).unwrap_err();
            assert_eq!(err.kind(), std::io::ErrorKind::InvalidInput, "{network}");
            assert_eq!(err.to_string(), message, "{network}");
        }
    }

    #[test]
    fn validate_reality_stream_settings_skips_non_reality_security() {
        let stream = StreamSettingsObject {
            network: Some("ws".to_string()),
            security: Some("tls".to_string()),
            reality_settings: None,
            xhttp_settings: None,
            splithttp_settings: None,
            extra: BTreeMap::new(),
        };

        assert!(validate_reality_stream_settings(&stream).is_ok());
    }

    #[test]
    fn validate_reality_stream_settings_accepts_xhttp_with_reality_security() {
        let stream = StreamSettingsObject {
            network: Some("xhttp".to_string()),
            security: Some("reality".to_string()),
            reality_settings: None,
            xhttp_settings: Some(XHttpSettings {
                path: "/xhttp".to_string(),
                mode: Some("stream-one".to_string()),
                ..XHttpSettings::default()
            }),
            splithttp_settings: None,
            extra: BTreeMap::new(),
        };

        validate_reality_stream_settings(&stream).unwrap();
    }

    #[test]
    fn validate_reality_stream_settings_accepts_raw_with_reality_security() {
        let stream = StreamSettingsObject {
            network: Some("raw".to_string()),
            security: Some("reality".to_string()),
            reality_settings: None,
            xhttp_settings: None,
            splithttp_settings: None,
            extra: BTreeMap::new(),
        };

        assert!(validate_reality_stream_settings(&stream).is_ok());
    }

    #[test]
    fn first_reality_inbound_runtime_accepts_xhttp_transport() {
        let json = vless_reality_inbound_json("xhttp").replace(
            r#""realitySettings": {"#,
            r#""xhttpSettings": {"path": "/xhttp", "mode": "stream-one"}, "realitySettings": {"#,
        );
        let config: XrayConfig = serde_json::from_str(&json).unwrap();
        let runtime = first_reality_inbound_runtime(&config).unwrap();
        assert_eq!(runtime.transport, TransportNetwork::XHttp);
        assert_eq!(
            runtime.xhttp_settings.as_ref().unwrap().effective_path(),
            "/xhttp"
        );
        assert_eq!(
            runtime.xhttp_settings.as_ref().unwrap().effective_mode(),
            "stream-one"
        );
    }

    #[test]
    fn first_reality_inbound_runtime_accepts_splithttp_alias() {
        let json = vless_reality_inbound_json("splithttp").replace(
            r#""realitySettings": {"#,
            r#""splithttpSettings": {"path": "/legacy", "mode": "auto"}, "realitySettings": {"#,
        );
        let config: XrayConfig = serde_json::from_str(&json).unwrap();
        let runtime = first_reality_inbound_runtime(&config).unwrap();
        assert_eq!(runtime.transport, TransportNetwork::XHttp);
        assert_eq!(
            runtime.xhttp_settings.as_ref().unwrap().effective_path(),
            "/legacy"
        );
        assert_eq!(
            runtime.xhttp_settings.as_ref().unwrap().effective_mode(),
            "auto"
        );
    }

    #[test]
    fn first_reality_inbound_runtime_rejects_vision_flow_over_xhttp() {
        let json = vless_reality_inbound_json("xhttp")
            .replace(
                r#""settings": {"clients": [], "decryption": "none"}"#,
                r#""settings": {"clients": [{"id": "00000000-0000-0000-0000-000000000001", "flow": "xtls-rprx-vision"}], "decryption": "none"}"#,
            )
            .replace(
                r#""realitySettings": {"#,
                r#""xhttpSettings": {"path": "/xhttp", "mode": "stream-one"}, "realitySettings": {"#,
            );
        let config: XrayConfig = serde_json::from_str(&json).unwrap();
        let err = first_reality_inbound_runtime(&config).unwrap_err();
        assert_eq!(err.kind(), std::io::ErrorKind::Unsupported);
        assert!(err.to_string().contains("flow=xtls-rprx-vision over XHTTP"));
    }

    #[test]
    fn first_reality_inbound_runtime_rejects_grpc_transport() {
        let config: XrayConfig = serde_json::from_str(&vless_reality_inbound_json("grpc")).unwrap();
        let err = first_reality_inbound_runtime(&config).unwrap_err();
        assert_eq!(err.kind(), std::io::ErrorKind::Unsupported);
        assert_eq!(
            err.to_string(),
            "REALITY over gRPC runtime is not implemented yet"
        );
    }

    #[test]
    fn first_reality_inbound_runtime_rejects_websocket_transport() {
        let config: XrayConfig = serde_json::from_str(&vless_reality_inbound_json("ws")).unwrap();
        let err = first_reality_inbound_runtime(&config).unwrap_err();
        assert_eq!(err.kind(), std::io::ErrorKind::InvalidInput);
        assert!(err
            .to_string()
            .contains("REALITY over WebSocket transport (network=ws) is not supported"));
    }

    #[test]
    fn skips_unsupported_ws_reality_inbound_and_selects_next_tcp() {
        let json = r#"{
            "inbounds": [
                {
                    "tag": "ws-reality",
                    "port": 8443,
                    "protocol": "vless",
                    "settings": {"clients": [], "decryption": "none"},
                    "streamSettings": {
                        "network": "ws",
                        "security": "reality",
                        "realitySettings": {
                            "dest": "ws.example.com:443",
                            "serverNames": ["ws.example.com"],
                            "privateKey": "CMZoLYnNxeaUoLn7LwK4RzBIdpzBXI5TOIlZ3tEfOn4",
                            "shortIds": [""]
                        }
                    }
                },
                {
                    "tag": "tcp-reality",
                    "port": 443,
                    "protocol": "vless",
                    "settings": {
                        "clients": [{"id": "00000000-0000-0000-0000-000000000001"}],
                        "decryption": "none"
                    },
                    "streamSettings": {
                        "network": "tcp",
                        "security": "reality",
                        "realitySettings": {
                            "dest": "tcp.example.com:443",
                            "serverNames": ["tcp.example.com"],
                            "privateKey": "CMZoLYnNxeaUoLn7LwK4RzBIdpzBXI5TOIlZ3tEfOn4",
                            "shortIds": [""]
                        }
                    }
                }
            ]
        }"#;
        let config: XrayConfig = serde_json::from_str(json).unwrap();
        let inbounds = find_reality_inbounds(&config);
        assert_eq!(inbounds.len(), 1);
        assert_eq!(inbounds[0].tag.as_deref(), Some("tcp-reality"));
        let runtime = first_reality_inbound_runtime(&config).unwrap();
        assert_eq!(runtime.dest_addr, "tcp.example.com:443");
    }

    #[test]
    fn dest_without_port_defaults_to_443() {
        let settings: RealitySettingsObject = serde_json::from_value(serde_json::json!({
            "dest": "example.com",
            "serverNames": ["example.com"],
            "privateKey": "abc",
            "shortIds": [""]
        }))
        .unwrap();
        assert_eq!(reality_dest_addr(&settings).unwrap(), "example.com:443");
    }

    #[test]
    fn ipv6_dest_stays_bracketed() {
        let settings: RealitySettingsObject = serde_json::from_value(serde_json::json!({
            "dest": "[2606:4700:4700::1111]:443",
            "serverNames": ["example.com"],
            "privateKey": "abc",
            "shortIds": [""]
        }))
        .unwrap();
        assert_eq!(
            reality_dest_addr(&settings).unwrap(),
            "[2606:4700:4700::1111]:443"
        );
    }

    #[test]
    fn rejects_wildcard_server_names() {
        let settings: RealitySettingsObject = serde_json::from_value(serde_json::json!({
            "dest": "example.com:443",
            "serverNames": ["*"],
            "privateKey": "abc",
            "shortIds": [""]
        }))
        .unwrap();
        let err = reality_server_names(&settings).unwrap_err();
        assert!(err.to_string().contains("wildcard"));
    }

    #[test]
    fn rejects_empty_server_names_with_clear_error() {
        let settings: RealitySettingsObject = serde_json::from_value(serde_json::json!({
            "dest": "example.com:443",
            "serverNames": [],
            "privateKey": "abc",
            "shortIds": [""]
        }))
        .unwrap();
        let err = reality_server_names(&settings).unwrap_err();
        assert!(err
            .to_string()
            .contains("serverNames must contain at least one server name"));
    }

    #[test]
    fn accepts_uppercase_short_ids() {
        let settings: RealitySettingsObject = serde_json::from_value(serde_json::json!({
            "dest": "example.com:443",
            "serverNames": ["example.com"],
            "privateKey": "abc",
            "shortIds": ["0123456789ABCDEF"]
        }))
        .unwrap();
        assert_eq!(
            reality_short_ids(&settings).unwrap(),
            vec![vec![0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef]]
        );
    }

    #[test]
    fn rejects_odd_length_short_id() {
        let settings: RealitySettingsObject = serde_json::from_value(serde_json::json!({
            "dest": "example.com:443",
            "serverNames": ["example.com"],
            "privateKey": "abc",
            "shortIds": ["abc"]
        }))
        .unwrap();
        let err = reality_short_ids(&settings).unwrap_err();
        assert!(err.to_string().contains("abc"));
        assert!(err.to_string().contains("even"));
    }

    #[test]
    fn rejects_too_long_short_id() {
        let settings: RealitySettingsObject = serde_json::from_value(serde_json::json!({
            "dest": "example.com:443",
            "serverNames": ["example.com"],
            "privateKey": "abc",
            "shortIds": ["0123456789abcdef0"]
        }))
        .unwrap();
        let err = reality_short_ids(&settings).unwrap_err();
        assert!(err.to_string().contains("0123456789abcdef0"));
    }

    #[test]
    fn rejects_non_hex_short_id() {
        let settings: RealitySettingsObject = serde_json::from_value(serde_json::json!({
            "dest": "example.com:443",
            "serverNames": ["example.com"],
            "privateKey": "abc",
            "shortIds": ["012g"]
        }))
        .unwrap();
        let err = reality_short_ids(&settings).unwrap_err();
        assert!(err.to_string().contains("012g"));
    }

    #[test]
    fn defaults_missing_vless_decryption_to_none() {
        let inbound: InboundObject = serde_json::from_str(
            r#"{"protocol":"vless","settings":{"clients":[{"id":"00000000-0000-0000-0000-000000000001"}]}}"#,
        )
        .unwrap();
        let settings = inbound_vless_settings(&inbound).unwrap().unwrap();
        assert!(settings.decryption.is_none());

        let json = format!(
            r#"{{
            "inbounds": [{{
                "port": 443,
                "protocol": "vless",
                "settings": {{
                    "clients": [{{"id": "00000000-0000-0000-0000-000000000001"}}]
                }},
                "streamSettings": {{
                    "security": "reality",
                    "realitySettings": {{
                        "dest": "example.com:443",
                        "serverNames": ["example.com"],
                        "privateKey": "{TEST_REALITY_PRIVATE_KEY}",
                        "shortIds": [""]
                    }}
                }}
            }}]
        }}"#
        );
        let config: XrayConfig = serde_json::from_str(&json).unwrap();
        let runtime = first_reality_inbound_runtime(&config).unwrap();
        assert_eq!(runtime.vless_decryption, "none");
    }

    #[test]
    fn rejects_decryption_other_than_none() {
        let inbound: InboundObject = serde_json::from_str(
            r#"{"protocol":"vless","settings":{"clients":[],"decryption":"auto"}}"#,
        )
        .unwrap();
        let err = inbound_vless_settings(&inbound).unwrap_err();
        assert_eq!(err.kind(), std::io::ErrorKind::Unsupported);
    }

    #[test]
    fn validates_client_uuid_at_runtime() {
        let invalid_id = "a".repeat(31);
        let json = format!(
            r#"{{
            "inbounds": [{{
                "port": 443,
                "protocol": "vless",
                "settings": {{
                    "clients": [{{"id": "{invalid_id}"}}],
                    "decryption": "none"
                }},
                "streamSettings": {{
                    "security": "reality",
                    "realitySettings": {{
                        "dest": "example.com:443",
                        "serverNames": ["example.com"],
                        "privateKey": "{TEST_REALITY_PRIVATE_KEY}",
                        "shortIds": [""]
                    }}
                }}
            }}]
        }}"#
        );
        let config: XrayConfig = serde_json::from_str(&json).unwrap();
        let err = first_reality_inbound_runtime(&config).unwrap_err();
        assert!(err.to_string().contains("invalid VLESS client id"));
    }

    #[test]
    fn rejects_both_dest_and_target() {
        let settings: RealitySettingsObject = serde_json::from_value(serde_json::json!({
            "dest": "a.example.com:443",
            "target": "b.example.com:443",
            "serverNames": ["example.com"],
            "privateKey": "abc",
            "shortIds": [""]
        }))
        .unwrap();
        let err = reality_dest_addr(&settings).unwrap_err();
        assert_eq!(err.kind(), std::io::ErrorKind::InvalidInput);
        assert_eq!(
            err.to_string(),
            "realitySettings.dest and realitySettings.target are mutually exclusive"
        );
    }

    #[test]
    fn rejects_missing_dest_and_target() {
        let settings: RealitySettingsObject = serde_json::from_value(serde_json::json!({
            "serverNames": ["example.com"],
            "privateKey": "abc",
            "shortIds": [""]
        }))
        .unwrap();
        let err = reality_dest_addr(&settings).unwrap_err();
        assert_eq!(err.kind(), std::io::ErrorKind::InvalidInput);
        assert_eq!(
            err.to_string(),
            "realitySettings.dest or realitySettings.target is required"
        );
    }

    #[test]
    fn accepts_empty_short_id() {
        let settings: RealitySettingsObject = serde_json::from_value(serde_json::json!({
            "dest": "example.com:443",
            "serverNames": ["example.com"],
            "privateKey": "abc",
            "shortIds": [""]
        }))
        .unwrap();
        assert_eq!(
            reality_short_ids(&settings).unwrap(),
            vec![Vec::<u8>::new()]
        );
    }

    #[test]
    fn preserves_client_flow_vision() {
        let json = format!(
            r#"{{
            "inbounds": [{{
                "port": 443,
                "protocol": "vless",
                "settings": {{
                    "clients": [{{
                        "id": "00000000-0000-0000-0000-000000000001",
                        "flow": "xtls-rprx-vision"
                    }}],
                    "decryption": "none"
                }},
                "streamSettings": {{
                    "security": "reality",
                    "realitySettings": {{
                        "dest": "example.com:443",
                        "serverNames": ["example.com"],
                        "privateKey": "{TEST_REALITY_PRIVATE_KEY}",
                        "shortIds": [""]
                    }}
                }}
            }}]
        }}"#
        );
        let config: XrayConfig = serde_json::from_str(&json).unwrap();
        let settings = inbound_vless_settings(&config.inbounds[0])
            .unwrap()
            .unwrap();
        assert_eq!(
            settings.clients[0].flow.as_deref(),
            Some("xtls-rprx-vision")
        );

        let runtime = first_reality_inbound_runtime(&config).expect("vision runtime");
        assert_eq!(
            runtime.vless_clients[0].flow.as_deref(),
            Some("xtls-rprx-vision")
        );
    }

    #[test]
    fn missing_flow_is_empty_or_none() {
        let json = format!(
            r#"{{
            "inbounds": [{{
                "port": 443,
                "protocol": "vless",
                "settings": {{
                    "clients": [{{"id": "00000000-0000-0000-0000-000000000001"}}],
                    "decryption": "none"
                }},
                "streamSettings": {{
                    "security": "reality",
                    "realitySettings": {{
                        "dest": "example.com:443",
                        "serverNames": ["example.com"],
                        "privateKey": "{TEST_REALITY_PRIVATE_KEY}",
                        "shortIds": [""]
                    }}
                }}
            }}]
        }}"#
        );
        let config: XrayConfig = serde_json::from_str(&json).unwrap();
        let settings = inbound_vless_settings(&config.inbounds[0])
            .unwrap()
            .unwrap();
        assert!(settings.clients[0].flow.is_none());

        let runtime = first_reality_inbound_runtime(&config).unwrap();
        assert!(runtime.vless_clients[0].flow.is_none());
    }

    #[test]
    fn unknown_flow_returns_unsupported_at_runtime_validation() {
        let json = format!(
            r#"{{
            "inbounds": [{{
                "port": 443,
                "protocol": "vless",
                "settings": {{
                    "clients": [{{
                        "id": "00000000-0000-0000-0000-000000000001",
                        "flow": "unknown-flow"
                    }}],
                    "decryption": "none"
                }},
                "streamSettings": {{
                    "security": "reality",
                    "realitySettings": {{
                        "dest": "example.com:443",
                        "serverNames": ["example.com"],
                        "privateKey": "{TEST_REALITY_PRIVATE_KEY}",
                        "shortIds": [""]
                    }}
                }}
            }}]
        }}"#
        );
        let config: XrayConfig = serde_json::from_str(&json).unwrap();
        let settings = inbound_vless_settings(&config.inbounds[0])
            .unwrap()
            .unwrap();
        assert_eq!(settings.clients[0].flow.as_deref(), Some("unknown-flow"));

        let err = first_reality_inbound_runtime(&config).unwrap_err();
        assert_eq!(err.kind(), std::io::ErrorKind::Unsupported);
        assert_eq!(err.to_string(), "unsupported VLESS flow: unknown-flow");
    }

    #[test]
    fn vision_flow_runtime_accepts_when_implemented() {
        const VISION_FIXTURE: &str = include_str!(
            "../../scripts/live_reality_smoke/xray-compatible-server-vision.fixture.json"
        );
        let config: XrayConfig =
            serde_json::from_str(VISION_FIXTURE).expect("parse vision fixture");
        let settings = inbound_vless_settings(&config.inbounds[0])
            .unwrap()
            .unwrap();
        assert_eq!(
            settings.clients[0].flow.as_deref(),
            Some("xtls-rprx-vision")
        );

        let runtime = first_reality_inbound_runtime(&config).expect("vision runtime");
        assert_eq!(
            runtime.vless_clients[0].flow.as_deref(),
            Some("xtls-rprx-vision")
        );
    }

    #[test]
    fn preserves_unknown_fields() {
        let json = r#"{
            "log": {"loglevel": "debug"},
            "inbounds": [{
                "tag": "in",
                "port": 443,
                "protocol": "vless",
                "settings": {
                    "clients": [{
                        "id": "00000000-0000-0000-0000-000000000001",
                        "alterId": 0,
                        "customClientField": true
                    }],
                    "decryption": "none",
                    "fallbacks": [{"dest": 80}]
                },
                "streamSettings": {
                    "security": "reality",
                    "realitySettings": {
                        "dest": "example.com:443",
                        "serverNames": ["example.com"],
                        "privateKey": "CMZoLYnNxeaUoLn7LwK4RzBIdpzBXI5TOIlZ3tEfOn4",
                        "shortIds": [""],
                        "customRealityField": "keep"
                    },
                    "customStreamField": 1
                },
                "customInboundField": "keep"
            }],
            "routing": {"rules": []},
            "unknownTopLevel": true
        }"#;
        let config: XrayConfig = serde_json::from_str(json).unwrap();
        assert_eq!(
            config.log.as_ref().unwrap().loglevel.as_deref(),
            Some("debug")
        );
        assert!(config.routing.is_some());
        assert!(config.extra.contains_key("unknownTopLevel"));
        assert!(config.inbounds[0].extra.contains_key("customInboundField"));
        let stream = config.inbounds[0].stream_settings.as_ref().unwrap();
        assert!(stream.extra.contains_key("customStreamField"));
        let reality = stream.reality_settings.as_ref().unwrap();
        assert!(reality.extra.contains_key("customRealityField"));
        let settings = inbound_vless_settings(&config.inbounds[0])
            .unwrap()
            .unwrap();
        assert_eq!(settings.fallbacks.len(), 1);
        assert_eq!(settings.fallbacks[0].dest.addr, "127.0.0.1:80");
        assert!(settings.clients[0].extra.contains_key("alterId"));
        assert!(settings.clients[0].extra.contains_key("customClientField"));
    }

    fn minimal_reality_config_json(mldsa65_seed: Option<&str>) -> String {
        let mldsa65_seed_field = match mldsa65_seed {
            Some(seed) => format!(r#","mldsa65Seed": "{seed}""#),
            None => String::new(),
        };

        format!(
            r#"{{
            "inbounds": [{{
                "tag": "reality-in",
                "listen": "127.0.0.1",
                "port": 443,
                "protocol": "vless",
                "settings": {{
                    "clients": [{{"id": "00000000-0000-0000-0000-000000000001"}}],
                    "decryption": "none"
                }},
                "streamSettings": {{
                    "network": "tcp",
                    "security": "reality",
                    "realitySettings": {{
                        "dest": "www.example.com:443",
                        "serverNames": ["www.example.com"],
                        "privateKey": "{TEST_REALITY_PRIVATE_KEY}",
                        "shortIds": [""]
                        {mldsa65_seed_field}
                    }}
                }}
            }}]
        }}"#
        )
    }

    #[test]
    fn accepts_valid_mldsa65_seed_in_runtime_config() {
        let config: XrayConfig =
            serde_json::from_str(&minimal_reality_config_json(Some(TEST_MLDSA65_SEED))).unwrap();
        let runtime = first_reality_inbound_runtime(&config).unwrap();

        let seed = runtime.mldsa65_seed.expect("expected parsed mldsa65 seed");
        assert_eq!(seed.as_bytes().len(), crate::reality::MLDSA65_SEED_LEN);
    }

    #[test]
    fn rejects_invalid_mldsa65_seed_base64() {
        let config: XrayConfig =
            serde_json::from_str(&minimal_reality_config_json(Some("not-valid-base64!!!")))
                .unwrap();
        let err = first_reality_inbound_runtime(&config).unwrap_err();
        assert_eq!(err.kind(), std::io::ErrorKind::InvalidInput);
        assert!(err.to_string().contains("invalid mldsa65Seed base64"));
    }

    #[test]
    fn rejects_mldsa65_seed_with_31_decoded_bytes() {
        let config: XrayConfig = serde_json::from_str(&minimal_reality_config_json(Some(
            TEST_MLDSA65_SEED_31_BYTES,
        )))
        .unwrap();
        let err = first_reality_inbound_runtime(&config).unwrap_err();
        assert_eq!(err.kind(), std::io::ErrorKind::InvalidInput);
        assert!(err.to_string().contains("expected 32 bytes, got 31"));
    }

    #[test]
    fn rejects_mldsa65_seed_with_33_decoded_bytes() {
        let config: XrayConfig = serde_json::from_str(&minimal_reality_config_json(Some(
            TEST_MLDSA65_SEED_33_BYTES,
        )))
        .unwrap();
        let err = first_reality_inbound_runtime(&config).unwrap_err();
        assert_eq!(err.kind(), std::io::ErrorKind::InvalidInput);
        assert!(err.to_string().contains("expected 32 bytes, got 33"));
    }

    #[test]
    fn empty_mldsa65_seed_is_none_in_runtime() {
        let config: XrayConfig =
            serde_json::from_str(&minimal_reality_config_json(Some(""))).unwrap();
        let runtime = first_reality_inbound_runtime(&config).unwrap();
        assert!(runtime.mldsa65_seed.is_none());

        let config: XrayConfig = serde_json::from_str(&minimal_reality_config_json(None)).unwrap();
        let runtime = first_reality_inbound_runtime(&config).unwrap();
        assert!(runtime.mldsa65_seed.is_none());
    }

    #[test]
    fn rejects_mldsa65_seed_equal_to_private_key() {
        let config: XrayConfig =
            serde_json::from_str(&minimal_reality_config_json(Some(TEST_REALITY_PRIVATE_KEY)))
                .unwrap();
        let err = first_reality_inbound_runtime(&config).unwrap_err();
        assert_eq!(err.kind(), std::io::ErrorKind::InvalidInput);
        assert!(err.to_string().contains("must not equal privateKey"));
    }

    fn vless_reality_config_from_reality_json(reality: serde_json::Value) -> XrayConfig {
        let json = serde_json::json!({
            "inbounds": [{
                "port": 443,
                "protocol": "vless",
                "settings": {
                    "clients": [{"id": "00000000-0000-0000-0000-000000000001"}],
                    "decryption": "none"
                },
                "streamSettings": {
                    "network": "tcp",
                    "security": "reality",
                    "realitySettings": reality
                }
            }]
        });
        serde_json::from_value(json).expect("parse config")
    }

    fn vless_reality_config_from_stream_settings(stream: serde_json::Value) -> XrayConfig {
        let json = serde_json::json!({
            "inbounds": [{
                "port": 443,
                "protocol": "vless",
                "settings": {
                    "clients": [{"id": "00000000-0000-0000-0000-000000000001"}],
                    "decryption": "none"
                },
                "streamSettings": stream
            }]
        });
        serde_json::from_value(json).expect("parse config")
    }

    #[test]
    fn ignores_client_only_public_key_on_inbound_reality_settings() {
        let config = vless_reality_config_from_reality_json(serde_json::json!({
            "dest": "example.com:443",
            "serverNames": ["example.com"],
            "privateKey": TEST_REALITY_PRIVATE_KEY,
            "shortIds": [""],
            "publicKey": "oU1MbEgszawWQJa0S_DxLsNt9G2zyE4rF-CrqvJjTmg"
        }));
        let runtime = first_reality_inbound_runtime(&config).expect("runtime config");
        assert_eq!(runtime.private_key, TEST_REALITY_PRIVATE_KEY);
        assert!(runtime.mldsa65_seed.is_none());
    }

    #[test]
    fn ignores_client_only_mldsa65_verify_on_inbound_reality_settings() {
        let config = vless_reality_config_from_reality_json(serde_json::json!({
            "dest": "example.com:443",
            "serverNames": ["example.com"],
            "privateKey": TEST_REALITY_PRIVATE_KEY,
            "shortIds": [""],
            "mldsa65Verify": "AAECAwQ"
        }));
        let runtime = first_reality_inbound_runtime(&config).expect("runtime config");
        assert_eq!(runtime.private_key, TEST_REALITY_PRIVATE_KEY);
        assert!(runtime.mldsa65_seed.is_none());
    }

    #[test]
    fn rejects_limit_fallback_upload_at_startup() {
        let config = vless_reality_config_from_reality_json(serde_json::json!({
            "dest": "example.com:443",
            "serverNames": ["example.com"],
            "privateKey": TEST_REALITY_PRIVATE_KEY,
            "shortIds": [""],
            "limitFallbackUpload": {
                "afterBytes": 1024,
                "bytesPerSec": 100,
                "burstBytesPerSec": 200
            }
        }));
        let err = first_reality_inbound_runtime(&config).unwrap_err();
        assert_eq!(err.kind(), std::io::ErrorKind::Unsupported);
        assert!(err
            .to_string()
            .contains("realitySettings.limitFallbackUpload"));
    }

    #[test]
    fn rejects_limit_fallback_download_at_startup() {
        let config = vless_reality_config_from_reality_json(serde_json::json!({
            "dest": "example.com:443",
            "serverNames": ["example.com"],
            "privateKey": TEST_REALITY_PRIVATE_KEY,
            "shortIds": [""],
            "limitFallbackDownload": {
                "afterBytes": 2048,
                "bytesPerSec": 50,
                "burstBytesPerSec": 100
            }
        }));
        let err = first_reality_inbound_runtime(&config).unwrap_err();
        assert_eq!(err.kind(), std::io::ErrorKind::Unsupported);
        assert!(err
            .to_string()
            .contains("realitySettings.limitFallbackDownload"));
    }

    #[test]
    fn rejects_stream_settings_tls_settings_on_reality_inbound() {
        let config = vless_reality_config_from_stream_settings(serde_json::json!({
            "network": "tcp",
            "security": "reality",
            "realitySettings": {
                "dest": "example.com:443",
                "serverNames": ["example.com"],
                "privateKey": TEST_REALITY_PRIVATE_KEY,
                "shortIds": [""]
            },
            "tlsSettings": {
                "serverName": "example.com"
            }
        }));
        let err = first_reality_inbound_runtime(&config).unwrap_err();
        assert_eq!(err.kind(), std::io::ErrorKind::Unsupported);
        assert!(err.to_string().contains("streamSettings.tlsSettings"));
    }

    #[test]
    fn rejects_stream_settings_ws_settings_on_reality_inbound() {
        let config = vless_reality_config_from_stream_settings(serde_json::json!({
            "network": "tcp",
            "security": "reality",
            "realitySettings": {
                "dest": "example.com:443",
                "serverNames": ["example.com"],
                "privateKey": TEST_REALITY_PRIVATE_KEY,
                "shortIds": [""]
            },
            "wsSettings": {
                "path": "/"
            }
        }));
        let err = first_reality_inbound_runtime(&config).unwrap_err();
        assert_eq!(err.kind(), std::io::ErrorKind::Unsupported);
        assert!(err.to_string().contains("streamSettings.wsSettings"));
    }

    #[test]
    fn sockopt_in_stream_settings_extra_remains_valid() {
        let config = vless_reality_config_from_stream_settings(serde_json::json!({
            "network": "tcp",
            "security": "reality",
            "realitySettings": {
                "dest": "example.com:443",
                "serverNames": ["example.com"],
                "privateKey": TEST_REALITY_PRIVATE_KEY,
                "shortIds": [""]
            },
            "sockopt": {
                "tcpFastOpen": true
            }
        }));
        let runtime = first_reality_inbound_runtime(&config).expect("sockopt allowed");
        assert_eq!(runtime.dest_addr, "example.com:443");
    }

    #[test]
    fn reality_type_and_xver_remain_valid_at_startup() {
        let settings: RealitySettingsObject = serde_json::from_value(serde_json::json!({
            "dest": "example.com:443",
            "serverNames": ["example.com"],
            "privateKey": TEST_REALITY_PRIVATE_KEY,
            "shortIds": [""],
            "type": "tcp",
            "xver": 2
        }))
        .unwrap();

        assert_eq!(settings.transport_type.as_deref(), Some("tcp"));
        assert_eq!(settings.xver, 2);

        let config: XrayConfig = serde_json::from_str(&minimal_reality_config_json(None)).unwrap();
        let mut inbound = config.inbounds[0].clone();
        inbound.stream_settings = Some(StreamSettingsObject {
            network: Some("tcp".to_string()),
            security: Some("reality".to_string()),
            reality_settings: Some(settings),
            xhttp_settings: None,
            splithttp_settings: None,
            extra: BTreeMap::new(),
        });
        let config = XrayConfig {
            log: None,
            api: None,
            dns: None,
            stats: None,
            policy: None,
            routing: None,
            outbounds: Vec::new(),
            inbounds: vec![inbound],
            extra: BTreeMap::new(),
        };
        let runtime = first_reality_inbound_runtime(&config).expect("type and xver allowed");
        assert_eq!(runtime.dest_addr, "example.com:443");
    }

    #[test]
    fn mldsa65_seed_config_still_valid_with_explicit_reject_policy() {
        let config: XrayConfig =
            serde_json::from_str(&minimal_reality_config_json(Some(TEST_MLDSA65_SEED))).unwrap();
        let runtime = first_reality_inbound_runtime(&config).expect("valid seed");
        assert!(runtime.mldsa65_seed.is_some());
    }

    #[test]
    fn parse_http_unix_config_uri_splits_socket_and_redacts_token() {
        let source = "http+unix:///run/a.sock/internal/get-config?token=secret";
        let (socket, path) = parse_http_unix_config_uri(source).expect("parse");
        assert_eq!(socket, "/run/a.sock");
        assert_eq!(path, "/internal/get-config?token=secret");
        let redacted = redact_config_source(source);
        assert!(!redacted.contains("secret"));
        assert!(redacted.contains("?<redacted>"));
    }

    #[test]
    fn parse_http_unix_config_uri_requires_sock_suffix() {
        let err = parse_http_unix_config_uri("http+unix:///run/no-sock-path").unwrap_err();
        assert_eq!(err.kind(), std::io::ErrorKind::InvalidInput);
        assert!(err.to_string().contains(".sock"));
    }

    #[test]
    fn is_remnawave_http_unix_detects_internal_get_config() {
        let source = "http+unix:///run/a.sock/internal/get-config?token=secret";
        assert!(is_remnawave_http_unix_config_source(source));
        assert!(!is_remnawave_http_unix_config_source("/etc/xray.json"));
        assert!(!is_remnawave_http_unix_config_source(
            "http+unix:///run/a.sock/other/path"
        ));
    }

    #[test]
    fn parse_api_inbound_tls_settings_from_remnawave_shape() {
        let cert_lines = [
            "-----BEGIN CERTIFICATE-----",
            "TESTCERT",
            "-----END CERTIFICATE-----",
        ];
        let key_lines = [
            "-----BEGIN PRIVATE KEY-----",
            "TESTKEY",
            "-----END PRIVATE KEY-----",
        ];
        let inbound: InboundObject = serde_json::from_value(serde_json::json!({
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
                            "certificate": cert_lines,
                            "key": key_lines
                        },
                        {
                            "usage": "verify",
                            "certificate": cert_lines
                        }
                    ]
                }
            }
        }))
        .expect("parse inbound");
        let material = extract_tls_material_from_inbound(&inbound)
            .expect("extract")
            .expect("material");
        assert_eq!(
            String::from_utf8_lossy(&material.cert_pem),
            "-----BEGIN CERTIFICATE-----\nTESTCERT\n-----END CERTIFICATE-----"
        );
        assert_eq!(
            String::from_utf8_lossy(&material.key_pem),
            "-----BEGIN PRIVATE KEY-----\nTESTKEY\n-----END PRIVATE KEY-----"
        );
        assert_eq!(
            material.server_name.as_deref(),
            Some("internal.remnawave.local")
        );
    }

    #[test]
    fn merge_compatible_reality_inbounds_combines_users_and_flow() {
        let config: XrayConfig = serde_json::from_str(include_str!(
            "../../tests/fixtures/remna/remnawave_vless_reality_vision_users.json"
        ))
        .expect("parse fixture");
        let runtime = first_reality_inbound_runtime(&config).expect("runtime");
        assert_eq!(runtime.merged_inbound_tags.len(), 2);
        assert_eq!(runtime.vless_clients.len(), 3);
        let distribution = crate::vless::vless_flow_distribution(&runtime.vless_clients);
        assert_eq!(distribution.get("xtls-rprx-vision").copied(), Some(2));
    }

    #[test]
    fn reality_inbound_runtimes_serves_two_listen_addresses() {
        let config: XrayConfig = serde_json::from_str(include_str!(
            "../../tests/fixtures/remna/remnawave_two_reality_inbounds_flow.json"
        ))
        .expect("parse fixture");
        let runtimes = reality_inbound_runtimes(&config).expect("runtimes");
        assert_eq!(runtimes.len(), 2);
        let listens: Vec<_> = runtimes
            .iter()
            .map(|runtime| runtime.listen_addr.as_str())
            .collect();
        assert!(listens.contains(&"0.0.0.0:443"));
        assert!(listens.contains(&"0.0.0.0:8444"));
    }

    #[test]
    fn inbound_settings_flow_applies_to_clients_missing_flow() {
        let json = format!(
            r#"{{
            "inbounds": [{{
                "port": 443,
                "protocol": "vless",
                "settings": {{
                    "flow": "xtls-rprx-vision",
                    "clients": [{{"id": "00000000-0000-0000-0000-000000000001"}}],
                    "decryption": "none"
                }},
                "streamSettings": {{
                    "security": "reality",
                    "realitySettings": {{
                        "dest": "example.com:443",
                        "serverNames": ["example.com"],
                        "privateKey": "{TEST_REALITY_PRIVATE_KEY}",
                        "shortIds": [""]
                    }}
                }}
            }}]
        }}"#
        );
        let config: XrayConfig = serde_json::from_str(&json).unwrap();
        let runtime = first_reality_inbound_runtime(&config).expect("runtime");
        assert_eq!(
            runtime.vless_clients[0].flow.as_deref(),
            Some("xtls-rprx-vision")
        );
    }

    #[test]
    fn localhost_api_listen_detection() {
        assert!(is_localhost_api_listen("127.0.0.1:61000"));
        assert!(!is_localhost_api_listen("0.0.0.0:61000"));
    }

    #[test]
    fn reality_inbound_runtime_debug_does_not_expose_secrets() {
        let seed =
            crate::reality::decode_mldsa65_seed(Some(TEST_MLDSA65_SEED), TEST_REALITY_PRIVATE_KEY)
                .unwrap()
                .unwrap();
        let runtime = RealityInboundRuntime {
            tag: Some("reality-in".to_string()),
            merged_inbound_tags: vec!["reality-in".to_string()],
            protocol: Some("vless".to_string()),
            listen_addr: "127.0.0.1:443".to_string(),
            dest_addr: "www.example.com:443".to_string(),
            private_key: TEST_REALITY_PRIVATE_KEY.to_string(),
            server_names: vec!["www.example.com".to_string()],
            short_ids: vec![Vec::new()],
            max_time_diff: 0,
            min_client_ver: None,
            max_client_ver: None,
            show: false,
            mldsa65_seed: Some(seed),
            vless_clients: vec![VlessClientObject {
                id: "00000000-0000-0000-0000-000000000001".to_string(),
                email: None,
                flow: None,
                level: None,
                extra: BTreeMap::new(),
            }],
            vless_decryption: "none".to_string(),
            vless_fallbacks: Vec::new(),
            transport: TransportNetwork::RawTcp,
            xhttp_settings: None,
        };
        let debug = format!("{runtime:?}");

        assert!(debug.contains("mldsa65_seed"));
        assert!(debug.contains("private_key"));
        assert!(debug.contains("<redacted>"));
        assert!(!debug.contains(TEST_MLDSA65_SEED));
        assert!(!debug.contains(TEST_REALITY_PRIVATE_KEY));
    }
}
