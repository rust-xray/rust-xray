use std::collections::HashMap;
use std::sync::{Arc, RwLock};

use crate::vless::user_manager::VlessUserManager;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum InboundUsersError {
    InboundNotFound { tag: String },
}

impl std::fmt::Display for InboundUsersError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::InboundNotFound { tag } => write!(f, "inbound tag not found: {tag}"),
        }
    }
}

impl std::error::Error for InboundUsersError {}

/// Registry of per-inbound-tag VLESS user managers.
#[derive(Debug, Default)]
pub struct InboundUserManagers {
    managers: RwLock<HashMap<String, Arc<VlessUserManager>>>,
}

impl InboundUserManagers {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn register(&self, manager: Arc<VlessUserManager>) {
        let tag = manager.inbound_tag().to_string();
        self.register_tag(&tag, manager);
    }

    /// Register the same user manager under an additional inbound tag (merged REALITY inbounds).
    pub fn register_tag(&self, tag: &str, manager: Arc<VlessUserManager>) {
        self.managers
            .write()
            .expect("inbound user managers lock")
            .insert(tag.to_string(), manager);
    }

    pub fn get(&self, tag: &str) -> Result<Arc<VlessUserManager>, InboundUsersError> {
        self.managers
            .read()
            .expect("inbound user managers lock")
            .get(tag)
            .cloned()
            .ok_or_else(|| InboundUsersError::InboundNotFound {
                tag: tag.to_string(),
            })
    }

    /// Returns registered inbound tags in stable sorted order.
    pub fn list_tags(&self) -> Vec<String> {
        let guard = self.managers.read().expect("inbound user managers lock");
        let mut tags: Vec<String> = guard.keys().cloned().collect();
        tags.sort();
        tags
    }

    pub fn unregister_tag(&self, tag: &str) {
        self.managers
            .write()
            .expect("inbound user managers lock")
            .remove(tag);
    }
}
