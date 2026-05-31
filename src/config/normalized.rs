//! Typed, validated config model built from raw Xray panel JSON.

use crate::config::xray::validate::{eq_ignore_ascii_case, validate_vless_reality_inbound_stream};
use crate::config::xray::{
    api_dokodemo_inbound_tag, extract_api_inbound_tls_material, get_inbound_reality_settings,
    inbound_listen_addr, inbound_vless_settings, is_vless_reality_inbound, reality_dest_addr,
    reality_mldsa65_seed, reality_private_key, reality_server_names, reality_short_ids,
    resolve_api_listen, validate_reality_inbound_config_policy, ApiListenSource, ApiTlsMaterial,
    InboundObject, OutboundObject, RealityInboundRuntime, RoutingRuleObject, TransportNetwork,
    XHttpSettings, XrayConfig,
};
use crate::dns::{DnsConfig, DnsServerConfig, QueryStrategy};
use crate::reality::MLDSA65_SEED_LEN;
use crate::vless::{
    apply_inbound_vless_client_flows, build_vless_clients, validate_vless_client_flows,
    FallbackConfig, VlessClient,
};

pub type VlessUser = VlessClient;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NormalizedConfig {
    pub inbounds: Vec<NormalizedInbound>,
    pub outbounds: Vec<NormalizedOutbound>,
    pub api: Option<NormalizedApi>,
    pub dns: NormalizedDns,
    pub routing: NormalizedRouting,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum NormalizedInbound {
    VlessReality(VlessRealityInbound),
    Api(ApiInbound),
    Unsupported(UnsupportedInbound),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VlessRealityInbound {
    pub tag: Option<String>,
    pub listen_addr: String,
    pub users: Vec<VlessUser>,
    pub transport: InboundTransportConfig,
    pub reality: RealityServerConfig,
    pub fallbacks: Vec<FallbackConfig>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum InboundTransportConfig {
    RawTcp,
    XHttp(XHttpRuntimeConfig),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct XHttpRuntimeConfig {
    pub path: String,
    pub host: Option<String>,
    pub mode: String,
}

impl XHttpRuntimeConfig {
    pub fn from_settings(settings: &XHttpSettings) -> Self {
        Self {
            path: settings.effective_path().to_string(),
            host: settings
                .host
                .as_deref()
                .map(str::trim)
                .filter(|value| !value.is_empty())
                .map(str::to_string),
            mode: settings.effective_mode().to_ascii_lowercase(),
        }
    }

    pub fn to_settings(&self) -> XHttpSettings {
        XHttpSettings {
            path: self.path.clone(),
            host: self.host.clone(),
            mode: Some(self.mode.clone()),
            ..XHttpSettings::default()
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RealityServerConfig {
    pub dest_addr: String,
    pub private_key: String,
    pub server_names: Vec<String>,
    pub short_ids: Vec<Vec<u8>>,
    pub max_time_diff: u64,
    pub min_client_ver: Option<String>,
    pub max_client_ver: Option<String>,
    pub show: bool,
    pub mldsa65_seed: Option<[u8; MLDSA65_SEED_LEN]>,
    pub decryption: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ApiInbound {
    pub tag: Option<String>,
    pub listen_addr: String,
    pub protocol: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UnsupportedInbound {
    pub tag: Option<String>,
    pub protocol: Option<String>,
    pub reason: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NormalizedOutbound {
    pub tag: Option<String>,
    pub protocol: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NormalizedApi {
    pub tag: String,
    pub listen: String,
    pub listen_source: ApiListenSource,
    pub services: Vec<String>,
    pub dokodemo_inbound_tag: Option<String>,
    pub tls: Option<ApiTlsMaterial>,
}

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct NormalizedDns {
    pub servers: Vec<DnsServerConfig>,
    pub query_strategy: QueryStrategy,
    pub disable_cache: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NormalizedRouting {
    pub rules: Vec<NormalizedRoutingRule>,
    pub domain_strategy: Option<String>,
    /// Proxy traffic routing is parsed for compatibility but not enforced at runtime.
    pub enforced: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NormalizedRoutingRule {
    pub rule_type: Option<String>,
    pub inbound_tags: Vec<String>,
    pub outbound_tag: Option<String>,
    pub balancer_tag: Option<String>,
}

/// Build a typed config model from parsed raw Xray JSON.
///
/// Panel-level validation (`validate_xray_panel_config`) must have run before calling this.
pub fn normalize_config(config: &XrayConfig) -> std::io::Result<NormalizedConfig> {
    let api = normalize_api(config)?;
    let dns = normalize_dns(config.dns.as_ref());
    let routing = normalize_routing(config.routing.as_ref());
    let outbounds = config.outbounds.iter().map(normalize_outbound).collect();
    let api_dokodemo_tag = resolve_api_dokodemo_inbound_tag(config);
    let inbounds = config
        .inbounds
        .iter()
        .map(|inbound| normalize_inbound(inbound, config, api_dokodemo_tag.as_deref()))
        .collect::<std::io::Result<Vec<_>>>()?;

    Ok(NormalizedConfig {
        inbounds,
        outbounds,
        api,
        dns,
        routing,
    })
}

fn resolve_api_dokodemo_inbound_tag(config: &XrayConfig) -> Option<String> {
    let api = config.api.as_ref()?;
    if let Some((_, _, tag)) = resolve_api_listen(config).ok().flatten() {
        if let Some(tag) = tag {
            return Some(tag);
        }
    }
    if api
        .listen
        .as_deref()
        .is_some_and(|listen| !listen.trim().is_empty())
    {
        return config
            .inbounds
            .iter()
            .find(|inbound| inbound.tag.as_deref() == Some(api.tag.as_str()))
            .and_then(|inbound| inbound.tag.clone());
    }
    api_dokodemo_inbound_tag(config)
}

fn normalize_inbound(
    inbound: &InboundObject,
    config: &XrayConfig,
    api_dokodemo_tag: Option<&str>,
) -> std::io::Result<NormalizedInbound> {
    if is_vless_reality_inbound(inbound) {
        return Ok(NormalizedInbound::VlessReality(
            normalize_vless_reality_inbound(inbound)?,
        ));
    }

    if is_api_dokodemo_inbound(inbound, config, api_dokodemo_tag) {
        return Ok(NormalizedInbound::Api(normalize_api_inbound(inbound)?));
    }

    Ok(NormalizedInbound::Unsupported(UnsupportedInbound {
        tag: inbound.tag.clone(),
        protocol: inbound.protocol.clone(),
        reason: unsupported_inbound_reason(inbound),
    }))
}

fn is_api_dokodemo_inbound(
    inbound: &InboundObject,
    config: &XrayConfig,
    api_dokodemo_tag: Option<&str>,
) -> bool {
    let Some(protocol) = inbound.protocol.as_deref() else {
        return false;
    };
    if !eq_ignore_ascii_case(protocol, "dokodemo-door") {
        return false;
    }
    if api_dokodemo_tag.is_some_and(|tag| inbound.tag.as_deref() == Some(tag)) {
        return true;
    }
    config.api.as_ref().is_some_and(|api| {
        api.listen
            .as_deref()
            .is_some_and(|listen| !listen.trim().is_empty())
            && inbound.tag.as_deref() == Some(api.tag.as_str())
    })
}

fn unsupported_inbound_reason(inbound: &InboundObject) -> String {
    match inbound.protocol.as_deref() {
        Some(protocol) => format!("unsupported inbound protocol: {protocol}"),
        None => "inbound protocol is missing".to_string(),
    }
}

pub fn normalize_vless_reality_inbound(
    inbound: &InboundObject,
) -> std::io::Result<VlessRealityInbound> {
    validate_vless_reality_inbound_stream(inbound)?;

    let stream = inbound
        .stream_settings
        .as_ref()
        .expect("validated VLESS REALITY inbound has streamSettings");
    let settings = get_inbound_reality_settings(inbound)
        .expect("validated VLESS REALITY inbound has realitySettings");
    validate_reality_inbound_config_policy(stream, settings)?;

    let transport_network = TransportNetwork::parse(stream.network.as_deref())?;
    let transport = match transport_network {
        TransportNetwork::RawTcp => InboundTransportConfig::RawTcp,
        TransportNetwork::XHttp => {
            let xhttp = stream
                .xhttp_settings
                .as_ref()
                .or(stream.splithttp_settings.as_ref())
                .cloned()
                .unwrap_or_default();
            InboundTransportConfig::XHttp(normalize_xhttp_settings(&xhttp))
        }
    };

    let private_key = reality_private_key(settings)?.to_owned();
    crate::reality::validate_reality_private_key_b64(&private_key)?;
    let mldsa65_seed = reality_mldsa65_seed(settings, &private_key)?;

    let vless_settings = inbound_vless_settings(inbound)?;
    let (users, decryption, fallbacks) = match vless_settings {
        Some(settings) => {
            let mut clients = settings.clients;
            apply_inbound_vless_client_flows(
                &mut clients,
                settings.flow.as_deref(),
                stream.security.as_deref(),
                stream.network.as_deref(),
            )?;
            validate_vless_client_flows(&clients)?;
            if transport_network == TransportNetwork::XHttp
                && clients.iter().any(|client| {
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
            let users = build_vless_clients(&clients)?;
            (
                users,
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

    Ok(VlessRealityInbound {
        tag: inbound.tag.clone(),
        listen_addr: inbound_listen_addr(inbound)?,
        users,
        transport,
        reality: RealityServerConfig {
            dest_addr: reality_dest_addr(settings)?,
            private_key,
            server_names: reality_server_names(settings)?,
            short_ids: reality_short_ids(settings)?,
            max_time_diff: settings.max_time_diff,
            min_client_ver: settings.min_client_ver.clone(),
            max_client_ver: settings.max_client_ver.clone(),
            show: settings.show,
            mldsa65_seed: mldsa65_seed.map(|seed| *seed.as_bytes()),
            decryption,
        },
        fallbacks,
    })
}

fn normalize_xhttp_settings(settings: &XHttpSettings) -> XHttpRuntimeConfig {
    XHttpRuntimeConfig {
        path: settings.effective_path().to_string(),
        host: settings
            .host
            .as_deref()
            .map(str::trim)
            .filter(|value| !value.is_empty())
            .map(str::to_string),
        mode: settings.effective_mode().to_ascii_lowercase(),
    }
}

fn normalize_api_inbound(inbound: &InboundObject) -> std::io::Result<ApiInbound> {
    let protocol = inbound
        .protocol
        .clone()
        .unwrap_or_else(|| "dokodemo-door".to_string());
    Ok(ApiInbound {
        tag: inbound.tag.clone(),
        listen_addr: inbound_listen_addr(inbound)?,
        protocol,
    })
}

fn normalize_api(config: &XrayConfig) -> std::io::Result<Option<NormalizedApi>> {
    let Some(api) = config.api.as_ref() else {
        return Ok(None);
    };
    let Some((listen, listen_source, inbound_tag)) = resolve_api_listen(config)? else {
        return Ok(None);
    };
    let tls = extract_api_inbound_tls_material(config)?;
    Ok(Some(NormalizedApi {
        tag: api.tag.clone(),
        listen,
        listen_source,
        services: api.services.clone(),
        dokodemo_inbound_tag: inbound_tag.or_else(|| api_dokodemo_inbound_tag(config)),
        tls,
    }))
}

fn normalize_dns(dns: Option<&DnsConfig>) -> NormalizedDns {
    match dns {
        Some(dns) => NormalizedDns {
            servers: dns.servers.clone(),
            query_strategy: dns.query_strategy,
            disable_cache: dns.disable_cache,
        },
        None => NormalizedDns::default(),
    }
}

fn normalize_routing(routing: Option<&crate::config::xray::RoutingConfig>) -> NormalizedRouting {
    let Some(routing) = routing else {
        return NormalizedRouting {
            rules: Vec::new(),
            domain_strategy: None,
            enforced: false,
        };
    };
    NormalizedRouting {
        rules: routing.rules.iter().map(normalize_routing_rule).collect(),
        domain_strategy: routing.domain_strategy.clone(),
        enforced: false,
    }
}

fn normalize_routing_rule(rule: &RoutingRuleObject) -> NormalizedRoutingRule {
    NormalizedRoutingRule {
        rule_type: rule.rule_type.clone(),
        inbound_tags: routing_rule_inbound_tags(rule),
        outbound_tag: rule.outbound_tag.clone(),
        balancer_tag: rule.balancer_tag.clone(),
    }
}

fn routing_rule_inbound_tags(rule: &RoutingRuleObject) -> Vec<String> {
    use serde_json::Value;
    match rule.inbound_tag.as_ref() {
        Some(Value::String(tag)) => vec![tag.clone()],
        Some(Value::Array(tags)) => tags
            .iter()
            .filter_map(Value::as_str)
            .map(str::to_string)
            .collect(),
        _ => Vec::new(),
    }
}

fn normalize_outbound(outbound: &OutboundObject) -> NormalizedOutbound {
    NormalizedOutbound {
        tag: outbound.tag.clone(),
        protocol: outbound.protocol.clone(),
    }
}

/// Compare a normalized VLESS REALITY inbound with legacy runtime output (same merge group).
pub fn vless_reality_matches_runtime(
    normalized: &VlessRealityInbound,
    runtime: &RealityInboundRuntime,
) -> bool {
    normalized.tag == runtime.tag
        && normalized.listen_addr == runtime.listen_addr
        && normalized.reality.dest_addr == runtime.dest_addr
        && normalized.reality.private_key == runtime.private_key
        && normalized.reality.server_names == runtime.server_names
        && normalized.reality.short_ids == runtime.short_ids
        && normalized.reality.max_time_diff == runtime.max_time_diff
        && normalized.reality.min_client_ver == runtime.min_client_ver
        && normalized.reality.max_client_ver == runtime.max_client_ver
        && normalized.reality.show == runtime.show
        && normalized.reality.mldsa65_seed
            == runtime.mldsa65_seed.as_ref().map(|seed| *seed.as_bytes())
        && normalized.reality.decryption == runtime.vless_decryption
        && normalized.fallbacks == runtime.vless_fallbacks
        && normalized.users.len() == runtime.vless_clients.len()
        && transport_matches_runtime(&normalized.transport, runtime)
}

fn transport_matches_runtime(
    transport: &InboundTransportConfig,
    runtime: &RealityInboundRuntime,
) -> bool {
    match (transport, runtime.transport.clone()) {
        (InboundTransportConfig::RawTcp, TransportNetwork::RawTcp) => true,
        (InboundTransportConfig::XHttp(xhttp), TransportNetwork::XHttp) => {
            runtime.xhttp_settings.as_ref().is_some_and(|settings| {
                settings.effective_path() == xhttp.path
                    && settings.effective_mode().eq_ignore_ascii_case(&xhttp.mode)
                    && settings
                        .host
                        .as_deref()
                        .map(str::trim)
                        .filter(|s| !s.is_empty())
                        == xhttp.host.as_deref()
            })
        }
        _ => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{
        first_reality_inbound_runtime, load_xray_config_from_file, validate_xray_panel_config,
        XrayConfig,
    };

    const TEST_REALITY_PRIVATE_KEY: &str = "CMZoLYnNxeaUoLn7LwK4RzBIdpzBXI5TOIlZ3tEfOn4";

    fn vless_reality_json(network: &str, with_xhttp: bool) -> String {
        let xhttp = if with_xhttp {
            r#""xhttpSettings": {"path": "/xhttp", "mode": "stream-one"},"#
        } else {
            ""
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
                    "network": "{network}",
                    "security": "reality",
                    {xhttp}
                    "realitySettings": {{
                        "dest": "www.example.com:443",
                        "serverNames": ["www.example.com"],
                        "privateKey": "{TEST_REALITY_PRIVATE_KEY}",
                        "shortIds": [""]
                    }}
                }}
            }}]
        }}"#
        )
    }

    #[test]
    fn raw_tcp_reality_normalizes() {
        let config: XrayConfig = serde_json::from_str(&vless_reality_json("raw", false)).unwrap();
        validate_xray_panel_config(&config).unwrap();
        let normalized = normalize_config(&config).unwrap();
        assert_eq!(normalized.inbounds.len(), 1);
        let NormalizedInbound::VlessReality(inbound) = &normalized.inbounds[0] else {
            panic!("expected VlessReality inbound");
        };
        assert_eq!(inbound.listen_addr, "127.0.0.1:443");
        assert_eq!(inbound.transport, InboundTransportConfig::RawTcp);
        assert_eq!(inbound.reality.dest_addr, "www.example.com:443");
        assert_eq!(inbound.users.len(), 1);

        let runtime = first_reality_inbound_runtime(&config).unwrap();
        assert!(vless_reality_matches_runtime(inbound, &runtime));
    }

    #[test]
    fn xhttp_reality_normalizes() {
        let config: XrayConfig = serde_json::from_str(&vless_reality_json("xhttp", true)).unwrap();
        validate_xray_panel_config(&config).unwrap();
        let normalized = normalize_config(&config).unwrap();
        let NormalizedInbound::VlessReality(inbound) = &normalized.inbounds[0] else {
            panic!("expected VlessReality inbound");
        };
        assert_eq!(
            inbound.transport,
            InboundTransportConfig::XHttp(XHttpRuntimeConfig {
                path: "/xhttp".to_string(),
                host: None,
                mode: "stream-one".to_string(),
            })
        );

        let runtime = first_reality_inbound_runtime(&config).unwrap();
        assert!(vless_reality_matches_runtime(inbound, &runtime));
    }

    #[test]
    fn missing_private_key_fails() {
        let json = r#"{
            "inbounds": [{
                "port": 443,
                "protocol": "vless",
                "settings": {"clients": [], "decryption": "none"},
                "streamSettings": {
                    "network": "tcp",
                    "security": "reality",
                    "realitySettings": {
                        "dest": "example.com:443",
                        "serverNames": ["example.com"],
                        "shortIds": [""]
                    }
                }
            }]
        }"#;
        let config: XrayConfig = serde_json::from_str(json).unwrap();
        let err = normalize_config(&config).unwrap_err();
        assert!(err.to_string().contains("privateKey"));
    }

    #[test]
    fn missing_port_fails() {
        let json = r#"{
            "inbounds": [{
                "protocol": "vless",
                "settings": {"clients": [], "decryption": "none"},
                "streamSettings": {
                    "network": "tcp",
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
        let err = normalize_config(&config).unwrap_err();
        assert!(err.to_string().contains("port"));
    }

    #[test]
    fn unsupported_grpc_rejected() {
        let config: XrayConfig = serde_json::from_str(&vless_reality_json("grpc", false)).unwrap();
        let err = normalize_config(&config).unwrap_err();
        assert_eq!(err.kind(), std::io::ErrorKind::Unsupported);
    }

    #[test]
    fn api_dokodemo_door_normalizes() {
        let json = r#"{
            "api": {
                "tag": "api",
                "listen": "127.0.0.1:61000",
                "services": ["StatsService"]
            },
            "inbounds": [{
                "tag": "api",
                "listen": "127.0.0.1",
                "port": 61000,
                "protocol": "dokodemo-door",
                "settings": {"address": "127.0.0.1"}
            }]
        }"#;
        let config: XrayConfig = serde_json::from_str(json).unwrap();
        validate_xray_panel_config(&config).unwrap();
        let normalized = normalize_config(&config).unwrap();
        let api = normalized.api.as_ref().expect("api block");
        assert_eq!(api.tag, "api");
        assert_eq!(api.listen, "127.0.0.1:61000");
        assert_eq!(api.listen_source, ApiListenSource::ApiListenField);

        let NormalizedInbound::Api(inbound) = &normalized.inbounds[0] else {
            panic!("expected Api inbound");
        };
        assert_eq!(inbound.listen_addr, "127.0.0.1:61000");
        assert_eq!(inbound.protocol, "dokodemo-door");
    }

    #[test]
    fn remnawave_routing_api_normalizes() {
        let path = concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/tests/fixtures/remna/remnawave_node_minimal_61000.json"
        );
        let config = load_xray_config_from_file(path).expect("load fixture");
        let normalized = normalize_config(&config).unwrap();

        let api = normalized.api.as_ref().expect("api");
        assert_eq!(api.listen, "127.0.0.1:61000");
        assert_eq!(api.listen_source, ApiListenSource::RoutingRule);
        assert_eq!(api.dokodemo_inbound_tag.as_deref(), Some("api-inbound"));

        let api_inbounds: Vec<_> = normalized
            .inbounds
            .iter()
            .filter_map(|inbound| match inbound {
                NormalizedInbound::Api(api) => Some(api),
                _ => None,
            })
            .collect();
        assert_eq!(api_inbounds.len(), 1);
        assert_eq!(api_inbounds[0].tag.as_deref(), Some("api-inbound"));

        let reality_inbounds: Vec<_> = normalized
            .inbounds
            .iter()
            .filter_map(|inbound| match inbound {
                NormalizedInbound::VlessReality(vless) => Some(vless),
                _ => None,
            })
            .collect();
        assert_eq!(reality_inbounds.len(), 1);
        assert_eq!(reality_inbounds[0].listen_addr, "127.0.0.1:25443");

        let runtime = first_reality_inbound_runtime(&config).unwrap();
        assert!(vless_reality_matches_runtime(reality_inbounds[0], &runtime));

        assert!(!normalized.routing.enforced);
        assert_eq!(normalized.routing.rules.len(), 1);
        assert_eq!(
            normalized.routing.rules[0].outbound_tag.as_deref(),
            Some("api")
        );
    }
}
