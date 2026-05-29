use std::collections::{BTreeMap, HashMap};

use crate::config::VlessClientObject;
use crate::vless::vision::vision_relay_supported;

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

#[derive(Debug, Clone)]
pub struct VlessClient {
    pub id: uuid::Uuid,
    pub email: Option<String>,
    pub flow: Option<String>,
    pub level: Option<u32>,
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
    clients
        .iter()
        .map(|client| {
            let id = parse_vless_user_id(&client.id)?;

            Ok(VlessClient {
                id,
                email: client.email.clone(),
                flow: normalize_vless_flow(client.flow.as_deref()),
                level: client.level,
            })
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeMap;

    fn client_object(id: &str, email: Option<&str>, flow: Option<&str>) -> VlessClientObject {
        VlessClientObject {
            id: id.to_string(),
            email: email.map(str::to_string),
            flow: flow.map(str::to_string),
            level: None,
            extra: BTreeMap::new(),
        }
    }

    #[test]
    fn build_vless_clients_parses_valid_uuid() {
        let clients = build_vless_clients(&[client_object(
            "00000000-0000-0000-0000-000000000001",
            None,
            None,
        )])
        .unwrap();

        assert_eq!(clients.len(), 1);
        assert_eq!(
            clients[0].id,
            uuid::Uuid::parse_str("00000000-0000-0000-0000-000000000001").unwrap()
        );
    }

    #[test]
    fn parse_vless_user_id_accepts_canonical_uuid_unchanged() {
        let id = parse_vless_user_id("00000000-0000-0000-0000-000000000001").unwrap();
        assert_eq!(
            id,
            uuid::Uuid::parse_str("00000000-0000-0000-0000-000000000001").unwrap()
        );
    }

    #[test]
    fn parse_vless_user_id_accepts_dashless_uuid_unchanged() {
        let id = parse_vless_user_id("00000000000000000000000000000001").unwrap();
        assert_eq!(
            id,
            uuid::Uuid::parse_str("00000000-0000-0000-0000-000000000001").unwrap()
        );
    }

    #[test]
    fn parse_vless_user_id_maps_custom_string_like_xray() {
        let id = parse_vless_user_id("example").unwrap();
        assert_eq!(
            id,
            uuid::Uuid::parse_str("feb54431-301b-52bb-a6dd-e1e93e81bb9e").unwrap()
        );

        let id = parse_vless_user_id("not-a-uuid").unwrap();
        assert_eq!(
            id,
            uuid::Uuid::parse_str("9b70e619-d7b3-55b1-b743-756ebd573b4e").unwrap()
        );
    }

    #[test]
    fn parse_vless_user_id_maps_utf8_custom_string_like_xray() {
        let id = parse_vless_user_id("我爱🍉老师1314").unwrap();
        assert_eq!(
            id,
            uuid::Uuid::parse_str("5783a3e7-e373-51cd-8642-c83782b807c5").unwrap()
        );
        assert_eq!("我爱🍉老师1314".len(), 20);
    }

    #[test]
    fn parse_vless_user_id_rejects_empty_and_too_long_custom_strings() {
        for input in ["", &"a".repeat(31)] {
            let err = parse_vless_user_id(input).unwrap_err();
            assert_eq!(
                err.kind(),
                std::io::ErrorKind::InvalidInput,
                "input len={}",
                input.len()
            );
        }
    }

    #[test]
    fn parse_vless_user_id_rejects_invalid_uuid_length_strings() {
        let err = parse_vless_user_id("00000000-0000-0000-0000-00000000000g").unwrap_err();
        assert_eq!(err.kind(), std::io::ErrorKind::InvalidInput);
    }

    #[test]
    fn build_vless_clients_maps_custom_string_id() {
        let clients = build_vless_clients(&[client_object("example", None, None)]).unwrap();
        assert_eq!(
            clients[0].id,
            uuid::Uuid::parse_str("feb54431-301b-52bb-a6dd-e1e93e81bb9e").unwrap()
        );
    }

    #[test]
    fn build_vless_clients_copies_email_and_flow() {
        let clients = build_vless_clients(&[client_object(
            "00000000-0000-0000-0000-000000000001",
            Some("user@example.com"),
            Some("xtls-rprx-vision"),
        )])
        .unwrap();

        assert_eq!(clients[0].email.as_deref(), Some("user@example.com"));
        assert_eq!(clients[0].flow.as_deref(), Some("xtls-rprx-vision"));
    }

    #[test]
    fn build_vless_clients_empty_input_returns_empty_vec() {
        let clients = build_vless_clients(&[]).unwrap();
        assert!(clients.is_empty());
    }

    #[test]
    fn validate_vless_client_flow_accepts_missing_and_empty() {
        assert!(validate_vless_client_flow(None).is_ok());
        assert!(validate_vless_client_flow(Some("")).is_ok());
    }

    #[test]
    fn validate_vless_client_flow_rejects_unknown_flow() {
        let err = validate_vless_client_flow(Some("unknown-flow")).unwrap_err();
        assert_eq!(err.kind(), std::io::ErrorKind::Unsupported);
        assert_eq!(err.to_string(), "unsupported VLESS flow: unknown-flow");
    }

    #[test]
    fn build_vless_clients_normalizes_empty_flow_to_none() {
        let clients = build_vless_clients(&[client_object(
            "00000000-0000-0000-0000-000000000001",
            None,
            Some(""),
        )])
        .unwrap();
        assert!(clients[0].flow.is_none());
    }

    #[test]
    fn merge_vless_client_objects_prefers_non_empty_flow() {
        let id = "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee";
        let merged = merge_vless_client_objects([
            client_object(id, None, None),
            client_object(id, None, Some("xtls-rprx-vision")),
        ])
        .expect("merge");
        assert_eq!(merged.len(), 1);
        assert_eq!(merged[0].flow.as_deref(), Some("xtls-rprx-vision"));
    }

    #[test]
    fn validate_vless_client_flow_accepts_vision_when_implemented() {
        assert!(vision_relay_supported());
        assert!(validate_vless_client_flow(Some("xtls-rprx-vision")).is_ok());
    }

    #[test]
    fn resolve_inbound_default_flow_from_raw_reality() {
        assert_eq!(
            resolve_inbound_default_vless_flow(None, Some("reality"), Some("raw")).as_deref(),
            Some("xtls-rprx-vision")
        );
        assert_eq!(
            resolve_inbound_default_vless_flow(None, Some("reality"), Some("tcp")).as_deref(),
            Some("xtls-rprx-vision")
        );
        assert_eq!(
            resolve_inbound_default_vless_flow(None, Some("reality"), Some("ws")).as_deref(),
            None
        );
    }

    #[test]
    fn resolve_inbound_default_flow_from_settings_flow() {
        assert_eq!(
            resolve_inbound_default_vless_flow(Some("xtls-rprx-vision"), None, None).as_deref(),
            Some("xtls-rprx-vision")
        );
        assert_eq!(
            resolve_inbound_default_vless_flow(Some(""), None, None).as_deref(),
            None
        );
    }

    #[test]
    fn apply_inbound_flow_preserves_explicit_empty_client_flow() {
        let mut clients = vec![client_object(
            "00000000-0000-0000-0000-000000000001",
            None,
            Some(""),
        )];
        apply_inbound_vless_client_flows(&mut clients, None, Some("reality"), Some("raw")).unwrap();
        assert_eq!(clients[0].flow.as_deref(), Some(""));
    }

    #[test]
    fn apply_inbound_flow_fills_missing_client_flow() {
        let mut clients = vec![client_object(
            "00000000-0000-0000-0000-000000000001",
            None,
            None,
        )];
        apply_inbound_vless_client_flows(&mut clients, None, Some("reality"), Some("raw")).unwrap();
        assert_eq!(clients[0].flow.as_deref(), Some("xtls-rprx-vision"));
    }
}
