use rust_xray::vless::config::VlessClient;
use rust_xray::vless::protocol::{VlessCommand, VlessDestination, VlessRequest};
use rust_xray::vless::user_manager::{ManagedUser, UserManagerError, VlessUserManager};
use std::net::{IpAddr, Ipv4Addr};

const STATIC_ID: uuid::Uuid =
    uuid::Uuid::from_bytes([0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1]);
const DYNAMIC_ID: uuid::Uuid =
    uuid::Uuid::from_bytes([0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2]);

fn static_manager() -> VlessUserManager {
    VlessUserManager::new(
        "vless-reality-in",
        vec![VlessClient {
            id: STATIC_ID,
            email: Some("static@example.test".to_string()),
            flow: None,
            level: None,
        }],
    )
}

fn vless_request(user_id: uuid::Uuid) -> VlessRequest {
    VlessRequest {
        version: 0,
        user_id,
        command: VlessCommand::Tcp,
        destination: VlessDestination::Ip(IpAddr::V4(Ipv4Addr::LOCALHOST), 443),
        additional_info: Vec::new(),
    }
}

#[test]
fn add_user_preserves_vision_flow() {
    let manager = static_manager();
    manager
        .add_user(ManagedUser {
            id: DYNAMIC_ID,
            email: "vision@example.test".to_string(),
            flow: Some("xtls-rprx-vision".to_string()),
            level: None,
            expiry_secs: None,
        })
        .expect("add user");

    let auth = manager
        .authenticate(&vless_request(DYNAMIC_ID))
        .expect("auth");
    assert_eq!(auth.flow.as_deref(), Some("xtls-rprx-vision"));
}

#[test]
fn static_user_authenticates_by_uuid() {
    let manager = static_manager();
    let auth = manager
        .authenticate(&vless_request(STATIC_ID))
        .expect("static user auth");
    assert_eq!(auth.id, STATIC_ID);
    assert_eq!(auth.email.as_deref(), Some("static@example.test"));
}

#[test]
fn add_user_enables_authentication() {
    let manager = static_manager();
    manager
        .add_user(ManagedUser {
            id: DYNAMIC_ID,
            email: "dynamic@example.test".to_string(),
            flow: None,
            level: None,
            expiry_secs: None,
        })
        .expect("add user");

    let auth = manager
        .authenticate(&vless_request(DYNAMIC_ID))
        .expect("dynamic user auth");
    assert_eq!(auth.email.as_deref(), Some("dynamic@example.test"));
}

#[test]
fn remove_user_disables_future_authentication() {
    let manager = static_manager();
    manager
        .add_user(ManagedUser {
            id: DYNAMIC_ID,
            email: "dynamic@example.test".to_string(),
            flow: None,
            level: None,
            expiry_secs: None,
        })
        .expect("add user");
    manager
        .remove_user_by_email("dynamic@example.test")
        .expect("remove user");

    let err = manager
        .authenticate(&vless_request(DYNAMIC_ID))
        .unwrap_err();
    assert_eq!(err.kind(), std::io::ErrorKind::PermissionDenied);
}

#[test]
fn duplicate_uuid_is_rejected() {
    let manager = static_manager();
    let err = manager
        .add_user(ManagedUser {
            id: STATIC_ID,
            email: "other@example.test".to_string(),
            flow: None,
            level: None,
            expiry_secs: None,
        })
        .unwrap_err();
    assert!(matches!(err, UserManagerError::DuplicateUuid { .. }));
}

#[test]
fn add_user_updates_existing_user_flow() {
    let manager = static_manager();
    manager
        .add_user(ManagedUser {
            id: STATIC_ID,
            email: "static@example.test".to_string(),
            flow: Some("xtls-rprx-vision".to_string()),
            level: None,
            expiry_secs: None,
        })
        .expect("upsert flow");

    let auth = manager
        .authenticate(&vless_request(STATIC_ID))
        .expect("auth");
    assert_eq!(auth.flow.as_deref(), Some("xtls-rprx-vision"));
}

#[test]
fn duplicate_email_is_rejected() {
    let manager = static_manager();
    let err = manager
        .add_user(ManagedUser {
            id: DYNAMIC_ID,
            email: "static@example.test".to_string(),
            flow: None,
            level: None,
            expiry_secs: None,
        })
        .unwrap_err();
    assert!(matches!(err, UserManagerError::DuplicateEmail { .. }));
}

#[test]
fn list_managed_users_includes_static_and_dynamic_entries() {
    let manager = static_manager();
    manager
        .add_user(ManagedUser {
            id: DYNAMIC_ID,
            email: "dynamic@example.test".to_string(),
            flow: None,
            level: None,
            expiry_secs: None,
        })
        .expect("add user");

    let emails: Vec<_> = manager
        .list_managed_users()
        .into_iter()
        .map(|user| user.email)
        .collect();
    assert!(emails.contains(&"static@example.test".to_string()));
    assert!(emails.contains(&"dynamic@example.test".to_string()));
}

#[test]
fn remove_missing_user_returns_error() {
    let manager = static_manager();
    let err = manager
        .remove_user_by_email("missing@example.test")
        .unwrap_err();
    assert!(matches!(err, UserManagerError::UserNotFound { .. }));
}
