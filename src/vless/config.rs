use crate::config::VlessClientObject;

#[derive(Debug, Clone)]
pub struct VlessClient {
    pub id: uuid::Uuid,
    pub email: Option<String>,
    pub flow: Option<String>,
}

pub fn build_vless_clients(clients: &[VlessClientObject]) -> std::io::Result<Vec<VlessClient>> {
    clients
        .iter()
        .map(|client| {
            let id = client.id.parse::<uuid::Uuid>().map_err(|_| {
                std::io::Error::new(
                    std::io::ErrorKind::InvalidInput,
                    format!("invalid VLESS client id: {}", client.id),
                )
            })?;

            Ok(VlessClient {
                id,
                email: client.email.clone(),
                flow: client.flow.clone(),
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
    fn build_vless_clients_rejects_invalid_uuid() {
        let err = build_vless_clients(&[client_object("not-a-uuid", None, None)]).unwrap_err();
        assert_eq!(err.kind(), std::io::ErrorKind::InvalidInput);
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
}
