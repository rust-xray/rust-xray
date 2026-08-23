use std::collections::HashMap;

use tracing::info;

use crate::vless::{validate_fallback_configs, FallbackConfig};
use serde_json::Value;

use super::raw::{
    InboundObject, RealitySettingsObject, VlessClientObject, VlessInboundSettings, XHttpSettings,
    XrayConfig,
};
use super::transport::TransportNetwork;
use super::validate::{
    format_listen_host, is_vless_protocol, is_vless_reality_inbound, parse_inbound_port,
    validate_reality_inbound_config_policy, validate_vless_decryption,
    validate_vless_reality_inbound_stream,
};

const REALITY_DEFAULT_DEST_PORT: u16 = 443;

/// Xray-core REALITY server default since [af7eb68](https://github.com/XTLS/Xray-core/commit/af7eb68028732a8ee3c0e5d6ab2b8a657bb2e770).
pub const DEFAULT_REALITY_MIN_CLIENT_VER: &str = "26.3.27";

/// Resolves Xray-compatible REALITY `minClientVer` for runtime policy.
///
/// Absent or empty JSON values use [`DEFAULT_REALITY_MIN_CLIENT_VER`]; explicit
/// non-empty strings are preserved verbatim (including `"0.0.0"`).
pub fn effective_reality_min_client_ver(raw: Option<String>) -> String {
    match raw {
        Some(value) if !value.is_empty() => value,
        _ => DEFAULT_REALITY_MIN_CLIENT_VER.to_string(),
    }
}

/// Resolves optional REALITY `maxClientVer`. Absent or empty means no upper bound.
pub fn effective_reality_max_client_ver(raw: Option<String>) -> Option<String> {
    raw.filter(|value| !value.is_empty())
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

pub fn find_vless_reality_inbounds(config: &XrayConfig) -> Vec<&InboundObject> {
    config
        .inbounds
        .iter()
        .filter(|inbound| is_vless_reality_inbound(inbound))
        .collect()
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
            min_client_ver: Some(effective_reality_min_client_ver(
                settings.min_client_ver.clone(),
            )),
            max_client_ver: effective_reality_max_client_ver(settings.max_client_ver.clone()),
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
