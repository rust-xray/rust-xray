//! Authentication registry for logical inbounds sharing one physical listener.

use std::collections::{BTreeMap, HashMap};
use std::sync::{Arc, RwLock};

use uuid::Uuid;

use crate::stats::StatsState;
use crate::vless::protocol::VlessRequest;
use crate::vless::user_manager::{VlessAuthenticatedClient, VlessUserManager};

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LogicalInboundAuthError {
    DuplicateUserId {
        id: Uuid,
        existing_tag: String,
        new_tag: String,
    },
    AmbiguousUserId {
        id: Uuid,
        tags: Vec<String>,
    },
}

impl std::fmt::Display for LogicalInboundAuthError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::DuplicateUserId {
                id,
                existing_tag,
                new_tag,
            } => write!(
                f,
                "duplicate vless user id {id} on merged listener: already registered under inbound {existing_tag}, cannot add under {new_tag}"
            ),
            Self::AmbiguousUserId { id, tags } => write!(
                f,
                "ambiguous vless user id {id} on merged listener: matches inbound tags {tags:?}"
            ),
        }
    }
}

impl std::error::Error for LogicalInboundAuthError {}

/// Shared authentication domain for one physical inbound listener.
#[derive(Debug, Default)]
pub struct LogicalInboundAuthSet {
    managers: RwLock<BTreeMap<String, Arc<VlessUserManager>>>,
}

impl LogicalInboundAuthSet {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn from_single(manager: Arc<VlessUserManager>) -> Self {
        let set = Self::new();
        let _ = set.register(manager);
        set
    }

    pub fn register(&self, manager: Arc<VlessUserManager>) -> Result<(), LogicalInboundAuthError> {
        let new_tag = manager.inbound_tag().to_string();
        let new_ids = manager.user_ids();
        {
            let existing = self.managers.read().expect("logical inbound auth lock");
            for (existing_tag, existing_manager) in existing.iter() {
                for id in existing_manager.user_ids() {
                    if new_ids.contains(&id) {
                        return Err(LogicalInboundAuthError::DuplicateUserId {
                            id,
                            existing_tag: existing_tag.clone(),
                            new_tag: new_tag.clone(),
                        });
                    }
                }
            }
        }
        self.managers
            .write()
            .expect("logical inbound auth lock")
            .insert(new_tag, manager);
        Ok(())
    }

    pub fn unregister(&self, tag: &str) {
        self.managers
            .write()
            .expect("logical inbound auth lock")
            .remove(tag);
    }

    pub fn tags(&self) -> Vec<String> {
        self.managers
            .read()
            .expect("logical inbound auth lock")
            .keys()
            .cloned()
            .collect()
    }

    pub fn manager_count(&self) -> usize {
        self.managers
            .read()
            .expect("logical inbound auth lock")
            .len()
    }

    pub fn get_manager(&self, tag: &str) -> Option<Arc<VlessUserManager>> {
        self.managers
            .read()
            .expect("logical inbound auth lock")
            .get(tag)
            .cloned()
    }

    pub fn reject_duplicate_user_id(
        &self,
        id: Uuid,
        target_tag: &str,
    ) -> Result<(), LogicalInboundAuthError> {
        let existing = self.managers.read().expect("logical inbound auth lock");
        for (existing_tag, manager) in existing.iter() {
            if existing_tag == target_tag {
                continue;
            }
            if manager.contains_id(id) {
                return Err(LogicalInboundAuthError::DuplicateUserId {
                    id,
                    existing_tag: existing_tag.clone(),
                    new_tag: target_tag.to_string(),
                });
            }
        }
        Ok(())
    }

    pub fn authenticate(
        &self,
        request: &VlessRequest,
    ) -> Result<(Arc<VlessUserManager>, VlessAuthenticatedClient), std::io::Error> {
        let snapshot: Vec<Arc<VlessUserManager>> = self
            .managers
            .read()
            .expect("logical inbound auth lock")
            .values()
            .cloned()
            .collect();

        let mut matches = Vec::new();
        for manager in snapshot {
            if let Ok(auth) = manager.authenticate(request) {
                matches.push((manager, auth));
            }
        }

        match matches.len() {
            0 => Err(std::io::Error::new(
                std::io::ErrorKind::PermissionDenied,
                "unknown vless client id",
            )),
            1 => Ok(matches.pop().expect("single match")),
            _ => {
                let tags: Vec<String> = matches
                    .iter()
                    .map(|(manager, _)| manager.inbound_tag().to_string())
                    .collect();
                Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidInput,
                    LogicalInboundAuthError::AmbiguousUserId {
                        id: request.user_id,
                        tags,
                    }
                    .to_string(),
                ))
            }
        }
    }
}

/// Shared VLESS authentication + per-logical-inbound stats lookup for one physical listener.
#[derive(Clone)]
pub struct VlessInboundAuthContext {
    auth_set: Arc<LogicalInboundAuthSet>,
    stats_by_tag: Arc<RwLock<HashMap<String, Arc<StatsState>>>>,
}

impl VlessInboundAuthContext {
    pub fn new(
        auth_set: Arc<LogicalInboundAuthSet>,
        stats_by_tag: Arc<RwLock<HashMap<String, Arc<StatsState>>>>,
    ) -> Self {
        Self {
            auth_set,
            stats_by_tag,
        }
    }

    pub fn from_single_manager(
        manager: Arc<VlessUserManager>,
        stats: Option<Arc<StatsState>>,
    ) -> Self {
        let auth_set = Arc::new(LogicalInboundAuthSet::from_single(Arc::clone(&manager)));
        let mut stats_by_tag = HashMap::new();
        if let Some(stats) = stats {
            stats_by_tag.insert(manager.inbound_tag().to_string(), stats);
        }
        Self::new(auth_set, Arc::new(RwLock::new(stats_by_tag)))
    }

    pub fn auth_set(&self) -> &Arc<LogicalInboundAuthSet> {
        &self.auth_set
    }

    pub fn stats_for(&self, inbound_tag: &str) -> Option<Arc<StatsState>> {
        self.stats_by_tag
            .read()
            .ok()
            .and_then(|map| map.get(inbound_tag).cloned())
    }

    pub fn insert_stats(&self, tag: &str, stats: Arc<StatsState>) {
        if let Ok(mut map) = self.stats_by_tag.write() {
            map.insert(tag.to_string(), stats);
        }
    }

    pub fn authenticate(
        &self,
        request: &VlessRequest,
    ) -> Result<(Arc<VlessUserManager>, VlessAuthenticatedClient), std::io::Error> {
        self.auth_set.authenticate(request)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::vless::config::VlessClient;
    use crate::vless::protocol::{VlessCommand, VlessDestination, VlessRequest};

    fn user_manager(tag: &str, id: Uuid, email: &str) -> Arc<VlessUserManager> {
        Arc::new(VlessUserManager::new(
            tag,
            vec![VlessClient {
                id,
                email: Some(email.to_string()),
                flow: None,
                level: None,
            }],
        ))
    }

    fn request(id: Uuid) -> VlessRequest {
        VlessRequest {
            version: 0,
            user_id: id,
            command: VlessCommand::Tcp,
            destination: VlessDestination::Ip(
                std::net::IpAddr::V4(std::net::Ipv4Addr::LOCALHOST),
                80,
            ),
            additional_info: Vec::new(),
        }
    }

    #[test]
    fn duplicate_uuid_registration_is_rejected() {
        let id = Uuid::from_bytes([1; 16]);
        let set = LogicalInboundAuthSet::new();
        set.register(user_manager("in-a", id, "a@example.test"))
            .expect("first");
        let err = set
            .register(user_manager("in-b", id, "b@example.test"))
            .expect_err("duplicate");
        assert!(matches!(
            err,
            LogicalInboundAuthError::DuplicateUserId { .. }
        ));
    }

    #[test]
    fn authenticate_returns_logical_manager_and_tag() {
        let id_a = Uuid::from_bytes([2; 16]);
        let id_b = Uuid::from_bytes([3; 16]);
        let set = LogicalInboundAuthSet::new();
        set.register(user_manager("in-a", id_a, "a@example.test"))
            .expect("a");
        set.register(user_manager("in-b", id_b, "b@example.test"))
            .expect("b");

        let (manager, auth) = set.authenticate(&request(id_b)).expect("auth");
        assert_eq!(manager.inbound_tag(), "in-b");
        assert_eq!(auth.inbound_tag, "in-b");
    }

    #[test]
    fn reject_duplicate_user_id_across_other_logical_inbounds() {
        let id = Uuid::from_bytes([4; 16]);
        let set = LogicalInboundAuthSet::new();
        set.register(user_manager("in-a", id, "a@example.test"))
            .expect("a");
        set.register(user_manager(
            "in-b",
            Uuid::from_bytes([5; 16]),
            "b@example.test",
        ))
        .expect("b");
        let err = set
            .reject_duplicate_user_id(id, "in-b")
            .expect_err("duplicate");
        assert!(matches!(
            err,
            LogicalInboundAuthError::DuplicateUserId { .. }
        ));
    }
}
