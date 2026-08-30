//! Runtime registry for static and dynamic outbound handlers.

use std::collections::HashMap;
use std::sync::{Arc, RwLock};

use crate::api::proto::core::OutboundHandlerConfig;
use crate::config::xray::raw::OutboundObject;
use crate::runtime::commander_listener::CommanderOutboundListener;
use crate::runtime::handler_config::{
    decode_outbound_handler_config, encode_commander_outbound, encode_outbound_from_startup,
    encode_outbound_handler_config, HandlerConfigError, OutboundProtocol,
};

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum OutboundManagerError {
    AlreadyExists { tag: String },
    NotFound { tag: String },
    InvalidConfig { message: String },
    Unsupported { message: String },
}

impl std::fmt::Display for OutboundManagerError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::AlreadyExists { tag } => write!(f, "outbound tag already exists: {tag}"),
            Self::NotFound { tag } => write!(f, "outbound tag not found: {tag}"),
            Self::InvalidConfig { message } | Self::Unsupported { message } => f.write_str(message),
        }
    }
}

impl std::error::Error for OutboundManagerError {}

#[derive(Debug, Clone)]
pub struct OutboundEntry {
    pub tag: String,
    pub protocol: OutboundProtocol,
    pub handler_config: OutboundHandlerConfig,
}

#[derive(Debug, Default)]
pub struct RuntimeOutboundManager {
    entries: RwLock<HashMap<String, OutboundEntry>>,
    default_tag: RwLock<Option<String>>,
    commander_listener: RwLock<Option<Arc<CommanderOutboundListener>>>,
}

impl RuntimeOutboundManager {
    pub fn new() -> Arc<Self> {
        Arc::new(Self {
            entries: RwLock::new(HashMap::new()),
            default_tag: RwLock::new(None),
            commander_listener: RwLock::new(None),
        })
    }

    pub fn register_startup_outbound(
        self: &Arc<Self>,
        outbound: &OutboundObject,
    ) -> Result<(), OutboundManagerError> {
        let config = encode_outbound_from_startup(outbound).map_err(map_config_error)?;
        self.insert_outbound(config, false)
    }

    pub fn add_outbound(
        self: &Arc<Self>,
        config: OutboundHandlerConfig,
    ) -> Result<(), OutboundManagerError> {
        let (protocol, config) =
            decode_outbound_handler_config(&config).map_err(map_config_error)?;
        let _ = protocol;
        self.insert_outbound(config, true)
    }

    pub fn remove_outbound(self: &Arc<Self>, tag: &str) -> Result<(), OutboundManagerError> {
        let tag = tag.trim();
        if tag.is_empty() {
            return Err(OutboundManagerError::InvalidConfig {
                message: "outbound tag is required".to_string(),
            });
        }
        let removed = self
            .entries
            .write()
            .expect("outbound entries lock")
            .remove(tag)
            .ok_or_else(|| OutboundManagerError::NotFound {
                tag: tag.to_string(),
            })?;

        let mut default = self.default_tag.write().expect("default outbound tag lock");
        if default.as_deref() == Some(tag) {
            *default = self
                .entries
                .read()
                .expect("outbound entries lock")
                .keys()
                .next()
                .cloned();
        }
        let _ = removed;
        Ok(())
    }

    pub fn list_outbounds(&self) -> Vec<OutboundHandlerConfig> {
        let entries = self.entries.read().expect("outbound entries lock");
        let mut outbounds: Vec<_> = entries
            .values()
            .filter(|entry| entry.protocol != OutboundProtocol::Commander)
            .map(|entry| entry.handler_config.clone())
            .collect();
        outbounds.sort_by(|left, right| left.tag.cmp(&right.tag));
        outbounds
    }

    pub fn is_commander_outbound(&self, tag: &str) -> bool {
        self.entries
            .read()
            .expect("outbound entries lock")
            .get(tag)
            .is_some_and(|entry| entry.protocol == OutboundProtocol::Commander)
    }

    pub fn commander_listener(&self) -> Option<Arc<CommanderOutboundListener>> {
        self.commander_listener
            .read()
            .expect("commander listener lock")
            .clone()
    }

    /// Install/replace the internal Commander outbound (Xray internal `api.listen == ""` mode).
    pub fn install_commander_outbound(
        self: &Arc<Self>,
        tag: &str,
        listener: Arc<CommanderOutboundListener>,
    ) -> Result<(), OutboundManagerError> {
        let tag = tag.trim().to_string();
        if tag.is_empty() {
            return Err(OutboundManagerError::InvalidConfig {
                message: "commander outbound tag is required".to_string(),
            });
        }

        let config = encode_commander_outbound(&tag);
        let mut entries = self.entries.write().expect("outbound entries lock");
        entries.insert(
            tag.clone(),
            OutboundEntry {
                tag: tag.clone(),
                protocol: OutboundProtocol::Commander,
                handler_config: config,
            },
        );

        let mut default = self.default_tag.write().expect("default outbound tag lock");
        if default.is_none() {
            *default = Some(tag);
        }
        *self
            .commander_listener
            .write()
            .expect("commander listener lock") = Some(listener);
        Ok(())
    }

    pub fn contains(&self, tag: &str) -> bool {
        self.entries
            .read()
            .expect("outbound entries lock")
            .contains_key(tag)
    }

    pub fn get_protocol(&self, tag: &str) -> Option<OutboundProtocol> {
        self.entries
            .read()
            .expect("outbound entries lock")
            .get(tag)
            .map(|entry| entry.protocol.clone())
    }

    pub fn default_tag(&self) -> Option<String> {
        self.default_tag
            .read()
            .expect("default outbound tag lock")
            .clone()
    }

    pub fn outbound_tags(&self) -> Vec<String> {
        let mut tags: Vec<_> = self
            .entries
            .read()
            .expect("outbound entries lock")
            .keys()
            .cloned()
            .collect();
        tags.sort();
        tags
    }

    /// Select outbound tags whose tag starts with any of the selector prefixes (Xray HandlerSelector).
    pub fn select_outbounds(&self, selectors: &[String]) -> Vec<String> {
        let tags = self.outbound_tags();
        if selectors.is_empty() {
            return tags;
        }
        tags.into_iter()
            .filter(|tag| selectors.iter().any(|selector| tag.starts_with(selector)))
            .collect()
    }

    fn insert_outbound(
        self: &Arc<Self>,
        config: OutboundHandlerConfig,
        strict_duplicate: bool,
    ) -> Result<(), OutboundManagerError> {
        let tag = config.tag.trim().to_string();
        if tag.is_empty() {
            return Err(OutboundManagerError::InvalidConfig {
                message: "outbound tag is required".to_string(),
            });
        }

        let (protocol, _) = decode_outbound_handler_config(&config).map_err(map_config_error)?;

        let mut entries = self.entries.write().expect("outbound entries lock");
        if entries.contains_key(&tag) {
            if strict_duplicate {
                return Err(OutboundManagerError::AlreadyExists { tag });
            }
            return Ok(());
        }

        entries.insert(
            tag.clone(),
            OutboundEntry {
                tag: tag.clone(),
                protocol,
                handler_config: config,
            },
        );

        let mut default = self.default_tag.write().expect("default outbound tag lock");
        if default.is_none() {
            *default = Some(tag);
        }
        Ok(())
    }
}

fn map_config_error(err: HandlerConfigError) -> OutboundManagerError {
    match err {
        HandlerConfigError::InvalidArgument(message) => {
            OutboundManagerError::InvalidConfig { message }
        }
        HandlerConfigError::Unsupported(message) => OutboundManagerError::Unsupported { message },
    }
}

pub fn encode_freedom_outbound(tag: &str) -> OutboundHandlerConfig {
    encode_outbound_handler_config(tag, OutboundProtocol::Freedom)
}

pub fn encode_blackhole_outbound(tag: &str) -> OutboundHandlerConfig {
    encode_outbound_handler_config(tag, OutboundProtocol::Blackhole)
}
