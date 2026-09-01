use std::collections::{BTreeMap, HashMap, HashSet};
use std::sync::RwLock;

use uuid::Uuid;

use crate::vless::config::{
    format_vless_flow_distribution, normalize_vless_flow, parse_vless_user_id,
    resolve_vless_testseed, validate_vless_client_flow, VlessClient,
};
use crate::vless::protocol::VlessRequest;
use crate::vless::uuid_lookup::vless_lookup_uuid;
use crate::vless::vision::vision_relay_supported;

/// Authenticated VLESS client metadata used by the inbound relay path.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VlessAuthenticatedClient {
    /// Wire UUID from the client request (routing hints, logs, stats).
    pub id: Uuid,
    pub email: Option<String>,
    pub flow: Option<String>,
    pub level: Option<u32>,
    pub testseed: [u32; 4],
    /// Logical inbound tag that authenticated this session.
    pub inbound_tag: String,
}

fn is_supported_vless_flow(flow: Option<&str>) -> bool {
    matches!(flow, None | Some("") | Some("xtls-rprx-vision") if vision_relay_supported())
}

/// Managed VLESS user (static config + dynamic HandlerService).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ManagedUser {
    /// Lookup UUID (`ProcessUUID` normalized key).
    pub id: Uuid,
    pub email: String,
    pub flow: Option<String>,
    pub level: Option<u32>,
    pub testseed: [u32; 4],
    /// Optional account validity in seconds (from VLESS `Account.seconds` when set).
    pub expiry_secs: Option<u32>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum UserManagerError {
    DuplicateUuid { id: Uuid },
    DuplicateEmail { email: String },
    UserNotFound { email: String },
    InvalidUser(String),
}

impl std::fmt::Display for UserManagerError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::DuplicateUuid { id } => write!(f, "duplicate vless user id: {id}"),
            Self::DuplicateEmail { email } => write!(f, "duplicate vless user email: {email}"),
            Self::UserNotFound { email } => write!(f, "vless user not found: {email}"),
            Self::InvalidUser(message) => write!(f, "{message}"),
        }
    }
}

impl std::error::Error for UserManagerError {}

/// Thread-safe VLESS user table for one inbound tag.
#[derive(Debug)]
pub struct VlessUserManager {
    pub inbound_tag: String,
    sniffing_enabled: bool,
    users_by_id: RwLock<HashMap<Uuid, ManagedUser>>,
    email_to_id: RwLock<HashMap<String, Uuid>>,
}

impl VlessUserManager {
    pub fn new(inbound_tag: impl Into<String>, static_clients: Vec<VlessClient>) -> Self {
        Self::new_with_sniffing(inbound_tag, static_clients, false)
    }

    pub fn new_with_sniffing(
        inbound_tag: impl Into<String>,
        static_clients: Vec<VlessClient>,
        sniffing_enabled: bool,
    ) -> Self {
        let manager = Self {
            inbound_tag: inbound_tag.into(),
            sniffing_enabled,
            users_by_id: RwLock::new(HashMap::new()),
            email_to_id: RwLock::new(HashMap::new()),
        };
        for client in static_clients {
            let lookup_id = vless_lookup_uuid(&client.id);
            if let Some(email) = client.email.as_deref().filter(|value| !value.is_empty()) {
                let _ = manager.insert_user(ManagedUser {
                    id: lookup_id,
                    email: email.to_string(),
                    flow: normalize_vless_flow(client.flow.as_deref()),
                    level: client.level,
                    testseed: client.testseed,
                    expiry_secs: None,
                });
            } else {
                let mut users = manager.users_by_id.write().expect("users lock");
                users.insert(
                    lookup_id,
                    ManagedUser {
                        id: lookup_id,
                        email: String::new(),
                        flow: normalize_vless_flow(client.flow.as_deref()),
                        level: client.level,
                        testseed: client.testseed,
                        expiry_secs: None,
                    },
                );
            }
        }
        manager
    }

    pub fn sniffing_enabled(&self) -> bool {
        self.sniffing_enabled
    }

    pub fn inbound_tag(&self) -> &str {
        &self.inbound_tag
    }

    pub fn user_count(&self) -> usize {
        self.users_by_id.read().expect("users lock").len()
    }

    /// Flow label counts for diagnostics (no UUID/email).
    pub fn flow_distribution(&self) -> BTreeMap<String, usize> {
        let users = self.users_by_id.read().expect("users lock");
        let mut distribution = BTreeMap::new();
        for user in users.values() {
            let label = normalize_vless_flow(user.flow.as_deref()).unwrap_or_default();
            *distribution.entry(label).or_default() += 1;
        }
        distribution
    }

    pub fn flow_distribution_log_label(&self) -> String {
        format_vless_flow_distribution(&self.flow_distribution())
    }

    pub fn contains_id(&self, id: Uuid) -> bool {
        self.users_by_id
            .read()
            .expect("users lock")
            .contains_key(&vless_lookup_uuid(&id))
    }

    pub fn contains_email(&self, email: &str) -> bool {
        self.email_to_id
            .read()
            .expect("email lock")
            .contains_key(email)
    }

    pub fn add_user(&self, user: ManagedUser) -> Result<(), UserManagerError> {
        if user.email.is_empty() {
            return Err(UserManagerError::InvalidUser(
                "vless user email is required for dynamic user management".to_string(),
            ));
        }

        validate_vless_client_flow(user.flow.as_deref())
            .map_err(|err| UserManagerError::InvalidUser(format!("invalid vless flow: {err}")))?;

        let mut users = self.users_by_id.write().expect("users lock");
        let mut emails = self.email_to_id.write().expect("email lock");

        if let Some(existing) = users.get(&user.id).cloned() {
            if existing.email != user.email {
                return Err(UserManagerError::DuplicateUuid { id: user.id });
            }
            users.insert(
                user.id,
                ManagedUser {
                    flow: user.flow,
                    level: user.level,
                    testseed: user.testseed,
                    expiry_secs: user.expiry_secs,
                    ..existing
                },
            );
            return Ok(());
        }

        if emails.contains_key(&user.email) {
            return Err(UserManagerError::DuplicateEmail {
                email: user.email.clone(),
            });
        }

        emails.insert(user.email.clone(), user.id);
        users.insert(user.id, user);
        Ok(())
    }

    pub fn remove_user_by_email(&self, email: &str) -> Result<(), UserManagerError> {
        let id = {
            let emails = self.email_to_id.read().expect("email lock");
            emails
                .get(email)
                .copied()
                .ok_or_else(|| UserManagerError::UserNotFound {
                    email: email.to_string(),
                })?
        };
        let mut users = self.users_by_id.write().expect("users lock");
        let mut emails = self.email_to_id.write().expect("email lock");
        users.remove(&id);
        emails.remove(email);
        Ok(())
    }

    pub fn authenticate(
        &self,
        request: &VlessRequest,
    ) -> Result<VlessAuthenticatedClient, std::io::Error> {
        let wire_id = request.user_id;
        let lookup_id = vless_lookup_uuid(&wire_id);
        let users = self.users_by_id.read().expect("users lock");
        let client = users.get(&lookup_id).ok_or_else(|| {
            std::io::Error::new(
                std::io::ErrorKind::PermissionDenied,
                "unknown vless client id",
            )
        })?;

        if !is_supported_vless_flow(client.flow.as_deref()) {
            return Err(std::io::Error::new(
                std::io::ErrorKind::Unsupported,
                format!(
                    "unsupported VLESS flow: {}",
                    client.flow.as_deref().unwrap_or("")
                ),
            ));
        }

        Ok(VlessAuthenticatedClient {
            id: wire_id,
            email: if client.email.is_empty() {
                None
            } else {
                Some(client.email.clone())
            },
            flow: client.flow.clone(),
            level: client.level,
            testseed: client.testseed,
            inbound_tag: self.inbound_tag.clone(),
        })
    }

    pub fn user_ids(&self) -> HashSet<Uuid> {
        self.users_by_id
            .read()
            .expect("users lock")
            .keys()
            .copied()
            .collect()
    }

    /// Returns all managed users (static + dynamic), sorted by email then UUID.
    pub fn list_managed_users(&self) -> Vec<ManagedUser> {
        let mut users: Vec<ManagedUser> = self
            .users_by_id
            .read()
            .expect("users lock")
            .values()
            .cloned()
            .collect();
        users.sort_by(|left, right| {
            left.email
                .cmp(&right.email)
                .then_with(|| left.id.cmp(&right.id))
        });
        users
    }

    pub fn get_managed_user_by_email(&self, email: &str) -> Option<ManagedUser> {
        let id = self
            .email_to_id
            .read()
            .expect("email lock")
            .get(email)
            .copied()?;
        self.users_by_id
            .read()
            .expect("users lock")
            .get(&id)
            .cloned()
    }

    pub fn snapshot_vless_clients(&self) -> Vec<VlessClient> {
        self.users_by_id
            .read()
            .expect("users lock")
            .values()
            .map(|user| VlessClient {
                id: user.id,
                email: if user.email.is_empty() {
                    None
                } else {
                    Some(user.email.clone())
                },
                flow: user.flow.clone(),
                level: user.level,
                testseed: user.testseed,
            })
            .collect()
    }

    fn insert_user(&self, user: ManagedUser) -> Result<(), UserManagerError> {
        if user.email.is_empty() {
            return Err(UserManagerError::InvalidUser(
                "vless user email is required for dynamic user management".to_string(),
            ));
        }

        validate_vless_client_flow(user.flow.as_deref())
            .map_err(|err| UserManagerError::InvalidUser(format!("invalid vless flow: {err}")))?;

        let mut users = self.users_by_id.write().expect("users lock");
        let mut emails = self.email_to_id.write().expect("email lock");

        if users.contains_key(&user.id) {
            return Err(UserManagerError::DuplicateUuid { id: user.id });
        }
        if emails.contains_key(&user.email) {
            return Err(UserManagerError::DuplicateEmail {
                email: user.email.clone(),
            });
        }

        emails.insert(user.email.clone(), user.id);
        users.insert(user.id, user);
        Ok(())
    }
}

/// Short non-reversible hint for logs (first 8 hex chars, no full UUID).
pub fn user_id_hint(id: &Uuid) -> String {
    id.to_string()
        .chars()
        .filter(|ch| *ch != '-')
        .take(8)
        .collect::<String>()
        .to_ascii_lowercase()
}

pub fn managed_user_from_vless_account(
    email: String,
    level: Option<u32>,
    account_id: &str,
    account_flow: &str,
    account_seconds: u32,
    account_testseed: Option<&[u32]>,
    inbound_default_testseed: Option<&[u32]>,
) -> Result<ManagedUser, UserManagerError> {
    if email.trim().is_empty() {
        return Err(UserManagerError::InvalidUser(
            "user email is required".to_string(),
        ));
    }

    let wire_id = parse_vless_user_id(account_id)
        .map_err(|err| UserManagerError::InvalidUser(format!("invalid vless account id: {err}")))?;
    let lookup_id = vless_lookup_uuid(&wire_id);

    let flow = normalize_vless_flow(Some(account_flow));
    let testseed = resolve_vless_testseed(account_testseed, inbound_default_testseed);

    Ok(ManagedUser {
        id: lookup_id,
        email,
        flow,
        level,
        testseed,
        expiry_secs: if account_seconds == 0 {
            None
        } else {
            Some(account_seconds)
        },
    })
}

#[cfg(test)]
#[path = "../../tests/unit/vless/user_manager_lookup.rs"]
mod lookup_tests;
