use std::collections::{BTreeMap, HashMap};

use crate::config::VlessClientObject;
use crate::vless::vision::vision_relay_supported;

/// Upstream default Vision `testseed` when fewer than four values are configured.
pub const UPSTREAM_DEFAULT_TESTSEED: [u32; 4] = [900, 500, 900, 256];

const VLESS_CUSTOM_ID_NAMESPACE: uuid::Uuid = uuid::Uuid::from_bytes([0; 16]);

/// Normalize config/account flow: missing and `""` both mean empty/default flow.
pub fn normalize_vless_flow(flow: Option<&str>) -> Option<String> {
    flow.map(str::trim)
        .filter(|value| !value.is_empty())
        .map(str::to_string)
}

/// Count users per flow label for startup diagnostics (no UUID/email).
pub fn vless_flow_distribution(clients: &[VlessClientObject]) -> BTreeMap<String, usize> {
    let mut distribution = BTreeMap::new();
    for client in clients {
        let label = normalize_vless_flow(client.flow.as_deref()).unwrap_or_default();
        *distribution.entry(label).or_default() += 1;
    }
    distribution
}

pub fn format_vless_flow_distribution(distribution: &BTreeMap<String, usize>) -> String {
    if distribution.is_empty() {
        return "flow=\"\" count=0".to_string();
    }
    distribution
        .iter()
        .map(|(flow, count)| {
            if flow.is_empty() {
                format!("flow=\"\" count={count}")
            } else {
                format!("flow=\"{flow}\" count={count}")
            }
        })
        .collect::<Vec<_>>()
        .join(", ")
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VlessClient {
    pub id: uuid::Uuid,
    pub email: Option<String>,
    pub flow: Option<String>,
    pub level: Option<u32>,
    pub testseed: [u32; 4],
}

impl Default for VlessClient {
    fn default() -> Self {
        Self {
            id: uuid::Uuid::nil(),
            email: None,
            flow: None,
            level: None,
            testseed: UPSTREAM_DEFAULT_TESTSEED,
        }
    }
}

/// Resolve effective per-user Vision test seed (upstream `proxy/proxy.go` default).
pub fn resolve_vless_testseed(
    client_seed: Option<&[u32]>,
    inbound_default: Option<&[u32]>,
) -> [u32; 4] {
    let source = client_seed.or(inbound_default);
    match source {
        Some(values) if values.len() >= 4 => [values[0], values[1], values[2], values[3]],
        _ => UPSTREAM_DEFAULT_TESTSEED,
    }
}

pub fn validate_vless_testseed(seed: Option<&[u32]>) -> std::io::Result<()> {
    if let Some(values) = seed {
        if values.len() > 4 {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "vless testseed supports at most four values",
            ));
        }
    }
    Ok(())
}

/// Parse a VLESS user id the same way as Xray-core `common/uuid.ParseString`.
pub fn parse_vless_user_id(input: &str) -> std::io::Result<uuid::Uuid> {
    let len = input.len();

    if (32..=36).contains(&len) {
        return input.parse::<uuid::Uuid>().map_err(|_| {
            std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                format!("invalid VLESS client id: {input}"),
            )
        });
    }

    if len == 0 || len > 30 {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            format!("invalid VLESS client id: {input}"),
        ));
    }

    Ok(uuid::Uuid::new_v5(
        &VLESS_CUSTOM_ID_NAMESPACE,
        input.as_bytes(),
    ))
}

pub fn validate_vless_client_flow(flow: Option<&str>) -> std::io::Result<()> {
    match flow.map(str::trim).filter(|value| !value.is_empty()) {
        None => Ok(()),
        Some("xtls-rprx-vision") if vision_relay_supported() => Ok(()),
        Some("xtls-rprx-vision") => Err(std::io::Error::new(
            std::io::ErrorKind::Unsupported,
            "xtls-rprx-vision is parsed but runtime support is not implemented yet",
        )),
        Some(value) => Err(std::io::Error::new(
            std::io::ErrorKind::Unsupported,
            format!("unsupported VLESS flow: {value}"),
        )),
    }
}

pub fn validate_vless_client_flows(clients: &[VlessClientObject]) -> std::io::Result<()> {
    for client in clients {
        validate_vless_client_flow(client.flow.as_deref())?;
    }
    Ok(())
}

/// Remnawave-compatible inbound default flow from `settings.flow` and stream transport.
pub fn resolve_inbound_default_vless_flow(
    inbound_flow: Option<&str>,
    security: Option<&str>,
    network: Option<&str>,
) -> Option<String> {
    if let Some(flow) = inbound_flow {
        return match flow.trim() {
            "xtls-rprx-vision" => Some("xtls-rprx-vision".to_string()),
            "" | "none" => None,
            other => Some(other.to_string()),
        };
    }

    let security = security?.to_ascii_lowercase();
    if security != "reality" && security != "tls" {
        return None;
    }

    let network = network.unwrap_or("").to_ascii_lowercase();
    if network == "raw" || network == "tcp" {
        return Some("xtls-rprx-vision".to_string());
    }

    None
}

/// Apply inbound-level / stream-inferred flow to clients that omit `clients[].flow`.
pub fn apply_inbound_vless_client_flows(
    clients: &mut [VlessClientObject],
    inbound_flow: Option<&str>,
    security: Option<&str>,
    network: Option<&str>,
) -> std::io::Result<()> {
    let default_flow = resolve_inbound_default_vless_flow(inbound_flow, security, network);
    for client in clients.iter_mut() {
        if client.flow.is_none() {
            client.flow = default_flow.clone();
        }
    }
    Ok(())
}

pub fn merge_vless_client_objects(
    clients: impl IntoIterator<Item = VlessClientObject>,
) -> std::io::Result<Vec<VlessClientObject>> {
    let mut merged: HashMap<String, VlessClientObject> = HashMap::new();
    for client in clients {
        match merged.remove(&client.id) {
            None => {
                merged.insert(client.id.clone(), client);
            }
            Some(existing) => {
                let flow = prefer_merged_client_flow(&existing, &client)?;
                let mut combined = existing;
                combined.flow = flow;
                merged.insert(combined.id.clone(), combined);
            }
        }
    }
    let mut clients: Vec<_> = merged.into_values().collect();
    clients.sort_by(|left, right| left.id.cmp(&right.id));
    Ok(clients)
}

fn prefer_merged_client_flow(
    left: &VlessClientObject,
    right: &VlessClientObject,
) -> std::io::Result<Option<String>> {
    let left_flow = normalize_vless_flow(left.flow.as_deref());
    let right_flow = normalize_vless_flow(right.flow.as_deref());
    match (left_flow, right_flow) {
        (None, None) => Ok(None),
        (Some(flow), None) | (None, Some(flow)) => Ok(Some(flow)),
        (Some(left_flow), Some(right_flow)) if left_flow == right_flow => Ok(Some(left_flow)),
        (Some(left_flow), Some(right_flow)) => Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            format!(
                "conflicting VLESS client flow for id {}: {left_flow:?} vs {right_flow:?}",
                user_id_hint_from_config_id(&left.id)
            ),
        )),
    }
}

fn user_id_hint_from_config_id(id: &str) -> String {
    id.chars()
        .filter(|ch| *ch != '-')
        .take(8)
        .collect::<String>()
        .to_ascii_lowercase()
}

pub fn build_vless_clients(clients: &[VlessClientObject]) -> std::io::Result<Vec<VlessClient>> {
    build_vless_clients_with_default(clients, None)
}

pub fn build_vless_clients_with_default(
    clients: &[VlessClientObject],
    inbound_default_testseed: Option<&[u32]>,
) -> std::io::Result<Vec<VlessClient>> {
    clients
        .iter()
        .map(|client| {
            validate_vless_testseed(client.testseed.as_deref())?;
            let id = parse_vless_user_id(&client.id)?;

            Ok(VlessClient {
                id,
                email: client.email.clone(),
                flow: normalize_vless_flow(client.flow.as_deref()),
                level: client.level,
                testseed: resolve_vless_testseed(
                    client.testseed.as_deref(),
                    inbound_default_testseed,
                ),
            })
        })
        .collect()
}

#[cfg(test)]
#[path = "../../tests/unit/vless/config.rs"]
mod tests;
