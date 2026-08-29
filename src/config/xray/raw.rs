use std::collections::BTreeMap;

use crate::dns::DnsConfig;
use crate::vless::FallbackConfig;
use serde::Deserialize;
use serde_json::Value;

use super::LimitFallback;

#[derive(Debug, Clone, Deserialize, Default)]
pub struct LogConfig {
    pub loglevel: Option<String>,
    #[serde(default)]
    pub access: Option<String>,
    #[serde(default)]
    pub error: Option<String>,
    #[serde(rename = "dnsLog", default)]
    pub dns_log: bool,

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

    #[serde(rename = "limitFallbackUpload", default)]
    pub limit_fallback_upload: LimitFallback,

    #[serde(rename = "limitFallbackDownload", default)]
    pub limit_fallback_download: LimitFallback,

    #[serde(flatten)]
    pub extra: BTreeMap<String, Value>,
}
