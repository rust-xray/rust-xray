use crate::config::VlessClientObject;
use crate::vless::vision::vision_relay_supported;

const VLESS_CUSTOM_ID_NAMESPACE: uuid::Uuid = uuid::Uuid::from_bytes([0; 16]);

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

pub fn build_vless_clients(clients: &[VlessClientObject]) -> std::io::Result<Vec<VlessClient>> {
    clients
        .iter()
        .map(|client| {
            let id = parse_vless_user_id(&client.id)?;

            Ok(VlessClient {
                id,
                email: client.email.clone(),
                flow: client.flow.clone(),
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

    fn client_object_with_level(
        id: &str,
        email: Option<&str>,
        flow: Option<&str>,
        level: Option<u32>,
    ) -> VlessClientObject {
        VlessClientObject {
            id: id.to_string(),
            email: email.map(str::to_string),
            flow: flow.map(str::to_string),
            level,
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
    fn validate_vless_client_flow_accepts_vision_when_implemented() {
        assert!(vision_relay_supported());
        assert!(validate_vless_client_flow(Some("xtls-rprx-vision")).is_ok());
    }
}
