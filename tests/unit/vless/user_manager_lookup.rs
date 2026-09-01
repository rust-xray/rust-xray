use uuid::Uuid;

use crate::vless::config::VlessClient;
use crate::vless::protocol::{VlessCommand, VlessDestination, VlessRequest};
use crate::vless::user_manager::{ManagedUser, VlessUserManager};
use crate::vless::uuid_lookup::vless_lookup_uuid;
use crate::vless::UPSTREAM_DEFAULT_TESTSEED;

fn wire_uuid_with_variant(a: u8, b: u8) -> Uuid {
    let mut bytes = [0u8; 16];
    bytes[15] = 1;
    bytes[6] = a;
    bytes[7] = b;
    Uuid::from_bytes(bytes)
}

fn tcp_request(user_id: Uuid) -> VlessRequest {
    VlessRequest {
        version: 0,
        user_id,
        command: VlessCommand::Tcp,
        destination: VlessDestination::Ip(std::net::IpAddr::V4(std::net::Ipv4Addr::LOCALHOST), 443),
        additional_info: Vec::new(),
    }
}

#[test]
fn authenticate_matches_process_uuid_lookup_key() {
    let stored = wire_uuid_with_variant(0x00, 0x00);
    let wire = wire_uuid_with_variant(0xab, 0xcd);
    assert_eq!(vless_lookup_uuid(&stored), vless_lookup_uuid(&wire));

    let users = VlessUserManager::new(
        "test-in",
        vec![VlessClient {
            id: stored,
            email: Some("user@example.test".to_string()),
            flow: None,
            level: None,
            testseed: UPSTREAM_DEFAULT_TESTSEED,
        }],
    );

    let auth = users.authenticate(&tcp_request(wire)).expect("auth");
    assert_eq!(auth.id, wire);
}

#[test]
fn authenticate_rejects_unrelated_lookup_key() {
    let users = VlessUserManager::new(
        "test-in",
        vec![VlessClient {
            id: Uuid::from_bytes([0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2]),
            email: Some("other@example.test".to_string()),
            flow: None,
            level: None,
            testseed: UPSTREAM_DEFAULT_TESTSEED,
        }],
    );
    let err = users
        .authenticate(&tcp_request(Uuid::from_bytes([
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 3,
        ])))
        .unwrap_err();
    assert_eq!(err.kind(), std::io::ErrorKind::PermissionDenied);
}

#[test]
fn dynamic_add_user_uses_same_lookup_normalization() {
    let wire = wire_uuid_with_variant(0x12, 0x34);
    let manager = VlessUserManager::new("test-in", vec![]);
    manager
        .add_user(ManagedUser {
            id: vless_lookup_uuid(&wire),
            email: "dynamic@example.test".to_string(),
            flow: None,
            level: None,
            testseed: UPSTREAM_DEFAULT_TESTSEED,
            expiry_secs: None,
        })
        .expect("add");
    manager.authenticate(&tcp_request(wire)).expect("auth");
    manager
        .remove_user_by_email("dynamic@example.test")
        .expect("remove");
    assert!(manager.authenticate(&tcp_request(wire)).is_err());
}
