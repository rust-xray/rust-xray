//! Runtime registry for static and dynamic inbound handlers.

use std::collections::{HashMap, HashSet};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, RwLock};
use std::time::Instant;

use tokio::net::TcpListener;
use tokio::sync::watch;
use tokio::task::JoinHandle;
use tracing::{debug, warn};

use crate::api::proto::core::InboundHandlerConfig;
use crate::app::{
    normalized_reality_merge_key, plain_vless_merge_key, validate_reality_runtime_feature_gates,
    InboundListenerConfig,
};
use crate::config::XrayConfig;
use crate::routing::RuntimeRouter;
use crate::runtime::handler_config::{
    decode_inbound_handler_config, encode_inbound_handler_config, HandlerConfigError,
};
use crate::runtime::logical_inbound_auth::LogicalInboundAuthError;
use crate::runtime::logical_inbound_auth::VlessInboundAuthContext;
use crate::runtime::InboundUserManagers;
use crate::stats::{StatsRegistry, StatsState};
use crate::vless::user_manager::VlessUserManager;

static NEXT_CONN_ID: AtomicU64 = AtomicU64::new(1);

#[derive(Debug, Clone)]
pub enum InboundManagerError {
    AlreadyExists { tag: String },
    NotFound { tag: String },
    Protected { tag: String },
    BindFailed { message: String },
    InvalidConfig { message: String },
    Unsupported { message: String },
    Internal { message: String },
}

impl InboundManagerError {
    fn invalid(message: impl Into<String>) -> Self {
        Self::InvalidConfig {
            message: message.into(),
        }
    }
}

impl std::fmt::Display for InboundManagerError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::AlreadyExists { tag } => write!(f, "inbound tag already exists: {tag}"),
            Self::NotFound { tag } => write!(f, "inbound tag not found: {tag}"),
            Self::Protected { tag } => write!(f, "inbound tag is protected: {tag}"),
            Self::BindFailed { message }
            | Self::InvalidConfig { message }
            | Self::Unsupported { message }
            | Self::Internal { message } => f.write_str(message),
        }
    }
}

impl std::error::Error for InboundManagerError {}

struct SharedListener {
    tags: RwLock<HashSet<String>>,
    listener_config: RwLock<Arc<InboundListenerConfig>>,
    shutdown: watch::Sender<bool>,
    task: Mutex<Option<JoinHandle<()>>>,
    listen_addr: String,
}

#[derive(Debug)]
struct InboundEntry {
    tag: String,
    merge_key: String,
    #[allow(dead_code)]
    handler_config: InboundHandlerConfig,
    listener_config: Arc<InboundListenerConfig>,
    protected: bool,
}

pub struct RuntimeInboundManager {
    entries: RwLock<HashMap<String, Arc<InboundEntry>>>,
    listeners: RwLock<HashMap<String, Arc<SharedListener>>>,
    user_managers: InboundUserManagers,
    xray: Arc<XrayConfig>,
    stats_registry: Arc<StatsRegistry>,
    api_dokodemo_tag: Option<String>,
    router: Arc<RuntimeRouter>,
}

impl RuntimeInboundManager {
    pub fn new(
        xray: Arc<XrayConfig>,
        stats_registry: Arc<StatsRegistry>,
        api_dokodemo_tag: Option<String>,
        router: Arc<RuntimeRouter>,
    ) -> Arc<Self> {
        Arc::new(Self {
            entries: RwLock::new(HashMap::new()),
            listeners: RwLock::new(HashMap::new()),
            user_managers: InboundUserManagers::new(),
            xray,
            stats_registry,
            api_dokodemo_tag,
            router,
        })
    }

    pub fn user_managers(&self) -> &InboundUserManagers {
        &self.user_managers
    }

    pub fn router(&self) -> &Arc<RuntimeRouter> {
        &self.router
    }

    pub fn list_tags(&self) -> Vec<String> {
        let mut tags: Vec<String> = self
            .entries
            .read()
            .expect("inbound entries lock")
            .keys()
            .cloned()
            .collect();
        tags.sort();
        tags
    }

    pub fn physical_listener_count(&self) -> usize {
        self.listeners.read().expect("inbound listeners lock").len()
    }

    pub fn merge_key_for_tag(&self, tag: &str) -> Option<String> {
        self.entries
            .read()
            .expect("inbound entries lock")
            .get(tag)
            .map(|entry| entry.merge_key.clone())
    }

    pub fn logical_tags_for_merge_key(&self, merge_key: &str) -> Vec<String> {
        self.listeners
            .read()
            .expect("inbound listeners lock")
            .get(merge_key)
            .map(|shared| {
                let mut tags: Vec<String> = shared
                    .tags
                    .read()
                    .expect("shared listener tags lock")
                    .iter()
                    .cloned()
                    .collect();
                tags.sort();
                tags
            })
            .unwrap_or_default()
    }

    pub fn listener_config_for_tag(&self, tag: &str) -> Option<Arc<InboundListenerConfig>> {
        self.entries
            .read()
            .expect("inbound entries lock")
            .get(tag)
            .map(|entry| Arc::clone(&entry.listener_config))
    }

    pub fn physical_listen_addr_for_tag(&self, tag: &str) -> Option<String> {
        let merge_key = self
            .entries
            .read()
            .expect("inbound entries lock")
            .get(tag)?
            .merge_key
            .clone();
        self.listeners
            .read()
            .expect("inbound listeners lock")
            .get(&merge_key)
            .map(|shared| shared.listen_addr.clone())
    }

    fn is_protected_tag(&self, tag: &str) -> bool {
        self.api_dokodemo_tag
            .as_deref()
            .is_some_and(|api_tag| api_tag == tag)
    }

    pub async fn register_startup_inbound(
        self: &Arc<Self>,
        listener_config: Arc<InboundListenerConfig>,
        handler_config: InboundHandlerConfig,
    ) -> Result<(), InboundManagerError> {
        let primary_tag = listener_config
            .inbound
            .tag
            .clone()
            .filter(|tag| !tag.is_empty())
            .unwrap_or_else(|| "reality-in".to_string());

        let tag_set: HashSet<String> = listener_config
            .merged_inbound_tags
            .iter()
            .chain(std::iter::once(&primary_tag))
            .cloned()
            .collect();
        for tag in &tag_set {
            if self
                .entries
                .read()
                .expect("inbound entries lock")
                .contains_key(tag)
            {
                return Err(InboundManagerError::AlreadyExists { tag: tag.clone() });
            }
        }

        let merge_key = if listener_config.plain_vless {
            plain_vless_merge_key(&listener_config.inbound.listen_addr)
        } else {
            normalized_reality_merge_key(&listener_config.inbound)
        };

        self.ensure_shared_listener(&merge_key, Arc::clone(&listener_config))
            .await?;

        let shared = self
            .listeners
            .read()
            .expect("inbound listeners lock")
            .get(&merge_key)
            .cloned()
            .ok_or_else(|| InboundManagerError::Internal {
                message: "shared listener missing after startup registration".to_string(),
            })?;
        {
            let mut tags = shared.tags.write().expect("shared listener tags lock");
            tags.extend(tag_set.iter().cloned());
        }

        let entry = Arc::new(InboundEntry {
            tag: primary_tag.clone(),
            merge_key,
            handler_config,
            listener_config,
            protected: self.is_protected_tag(&primary_tag),
        });
        let mut entries = self.entries.write().expect("inbound entries lock");
        for tag in tag_set {
            entries.insert(tag, Arc::clone(&entry));
        }
        Ok(())
    }

    pub async fn add_inbound(
        self: &Arc<Self>,
        config: InboundHandlerConfig,
    ) -> Result<(), InboundManagerError> {
        let tag = config.tag.trim().to_string();
        if tag.is_empty() {
            return Err(InboundManagerError::invalid("inbound tag is required"));
        }
        if self.is_protected_tag(&tag) {
            return Err(InboundManagerError::Protected { tag });
        }
        if self
            .entries
            .read()
            .expect("inbound entries lock")
            .contains_key(&tag)
        {
            return Err(InboundManagerError::AlreadyExists { tag });
        }

        let decoded = decode_inbound_handler_config(&config).map_err(map_config_error)?;
        let mut inbound = decoded.inbound;
        inbound.tag = Some(tag.clone());

        let user_manager = Arc::new(VlessUserManager::new_with_sniffing(
            tag.clone(),
            inbound.users.clone(),
            inbound.sniffing_enabled,
        ));
        let stats_enabled =
            StatsState::from_xray_config(&self.xray, self.api_dokodemo_tag.clone()).enabled();
        let stats = if stats_enabled {
            Some(Arc::new(StatsState::from_xray_config_with_registry(
                &self.xray,
                Arc::clone(&self.stats_registry),
                tag.clone(),
            )))
        } else {
            None
        };
        let auth = VlessInboundAuthContext::from_single_manager(Arc::clone(&user_manager), stats);

        let encryption_server = crate::vless::encryption::build_encryption_server_from_decryption(
            &inbound.reality.decryption,
        )
        .map_err(|err| InboundManagerError::invalid(err.to_string()))?;
        let mut listener_config = Arc::new(InboundListenerConfig {
            inbound: inbound.clone(),
            merged_inbound_tags: vec![tag.clone()],
            auth,
            plain_vless: decoded.plain_vless,
            router: Some(Arc::clone(&self.router)),
            encryption_server,
        });
        if !listener_config.plain_vless {
            validate_reality_runtime_feature_gates(&listener_config)
                .map_err(|err| InboundManagerError::invalid(err.to_string()))?;
        }

        let merge_key = if listener_config.plain_vless {
            plain_vless_merge_key(&listener_config.inbound.listen_addr)
        } else {
            normalized_reality_merge_key(&listener_config.inbound)
        };

        if self
            .listeners
            .read()
            .expect("inbound listeners lock")
            .contains_key(&merge_key)
        {
            self.attach_logical_inbound(&merge_key, &tag, Arc::clone(&user_manager))
                .map_err(map_auth_error)?;
            listener_config = self
                .listeners
                .read()
                .expect("inbound listeners lock")
                .get(&merge_key)
                .map(|shared| {
                    shared
                        .listener_config
                        .read()
                        .expect("shared listener config lock")
                        .clone()
                })
                .unwrap_or(listener_config);
        } else {
            self.ensure_shared_listener(&merge_key, Arc::clone(&listener_config))
                .await?;
        }

        let shared = self
            .listeners
            .read()
            .expect("inbound listeners lock")
            .get(&merge_key)
            .cloned()
            .ok_or_else(|| InboundManagerError::Internal {
                message: "shared listener missing after add".to_string(),
            })?;
        shared
            .tags
            .write()
            .expect("shared listener tags lock")
            .insert(tag.clone());

        self.user_managers.register(Arc::clone(&user_manager));

        let entry = Arc::new(InboundEntry {
            tag: tag.clone(),
            merge_key,
            handler_config: config,
            listener_config,
            protected: false,
        });
        self.entries
            .write()
            .expect("inbound entries lock")
            .insert(tag, Arc::clone(&entry));

        Ok(())
    }

    fn attach_logical_inbound(
        &self,
        merge_key: &str,
        tag: &str,
        manager: Arc<VlessUserManager>,
    ) -> Result<(), LogicalInboundAuthError> {
        let shared = self
            .listeners
            .read()
            .expect("inbound listeners lock")
            .get(merge_key)
            .cloned()
            .ok_or_else(|| LogicalInboundAuthError::DuplicateUserId {
                id: uuid::Uuid::nil(),
                existing_tag: String::new(),
                new_tag: tag.to_string(),
            })?;

        let mut config = shared
            .listener_config
            .write()
            .expect("shared listener config lock");
        let updated = Arc::make_mut(&mut *config);
        updated.auth.auth_set().register(Arc::clone(&manager))?;
        if !updated
            .merged_inbound_tags
            .iter()
            .any(|existing| existing == tag)
        {
            updated.merged_inbound_tags.push(tag.to_string());
        }
        let stats_enabled =
            StatsState::from_xray_config(&self.xray, self.api_dokodemo_tag.clone()).enabled();
        if stats_enabled {
            updated.auth.insert_stats(
                tag,
                Arc::new(StatsState::from_xray_config_with_registry(
                    &self.xray,
                    Arc::clone(&self.stats_registry),
                    tag.to_string(),
                )),
            );
        }
        Ok(())
    }

    pub async fn remove_inbound(self: &Arc<Self>, tag: &str) -> Result<(), InboundManagerError> {
        let tag = tag.trim();
        if tag.is_empty() {
            return Err(InboundManagerError::invalid("inbound tag is required"));
        }
        if self.is_protected_tag(tag) {
            return Err(InboundManagerError::Protected {
                tag: tag.to_string(),
            });
        }

        let entry = self
            .entries
            .write()
            .expect("inbound entries lock")
            .remove(tag)
            .ok_or_else(|| InboundManagerError::NotFound {
                tag: tag.to_string(),
            })?;

        if entry.protected {
            return Err(InboundManagerError::Protected {
                tag: tag.to_string(),
            });
        }

        self.user_managers.unregister_tag(tag);

        if let Some(shared) = self
            .listeners
            .read()
            .expect("inbound listeners lock")
            .get(&entry.merge_key)
            .cloned()
        {
            shared
                .tags
                .write()
                .expect("shared listener tags lock")
                .remove(tag);
            if let Ok(mut config) = shared.listener_config.write() {
                let updated = Arc::make_mut(&mut *config);
                updated.auth.auth_set().unregister(tag);
                updated
                    .merged_inbound_tags
                    .retain(|existing| existing != tag);
            }
        }

        let remaining_tags = self
            .listeners
            .read()
            .expect("inbound listeners lock")
            .get(&entry.merge_key)
            .map(|shared| shared.tags.read().expect("shared listener tags lock").len())
            .unwrap_or(0);

        if remaining_tags == 0 {
            let shared = self
                .listeners
                .write()
                .expect("inbound listeners lock")
                .remove(&entry.merge_key);
            if let Some(shared) = shared {
                let _ = shared.shutdown.send(true);
                let task = shared.task.lock().expect("listener task lock").take();
                drop(shared);
                if let Some(task) = task {
                    let _ = task.await;
                }
            }
        }

        Ok(())
    }

    pub fn list_inbounds(
        &self,
        only_tags: bool,
    ) -> Result<Vec<InboundHandlerConfig>, InboundManagerError> {
        let entries = self.entries.read().expect("inbound entries lock");
        let mut seen = HashSet::new();
        let mut inbounds = Vec::new();

        if only_tags {
            for tag in self.user_managers.list_tags() {
                if seen.insert(tag.clone()) {
                    inbounds.push(InboundHandlerConfig {
                        tag,
                        receiver_settings: None,
                        proxy_settings: None,
                    });
                }
            }
            inbounds.sort_by(|left, right| left.tag.cmp(&right.tag));
            return Ok(inbounds);
        }

        for entry in entries.values() {
            if !seen.insert(entry.tag.clone()) {
                continue;
            }
            let users = self
                .user_managers
                .get(&entry.tag)
                .map(|manager| {
                    manager
                        .list_managed_users()
                        .into_iter()
                        .filter(|user| !user.email.is_empty())
                        .collect::<Vec<_>>()
                })
                .unwrap_or_default();
            let config = if entry.listener_config.plain_vless {
                crate::runtime::handler_config::encode_plain_vless_inbound_handler_config(
                    &entry.listener_config.inbound,
                    &users,
                )
                .map_err(map_config_error)?
            } else {
                encode_inbound_handler_config(&entry.listener_config.inbound, &users)
                    .map_err(map_config_error)?
            };
            inbounds.push(config);
        }
        inbounds.sort_by(|left, right| left.tag.cmp(&right.tag));
        Ok(inbounds)
    }

    async fn ensure_shared_listener(
        self: &Arc<Self>,
        merge_key: &str,
        listener_config: Arc<InboundListenerConfig>,
    ) -> Result<(), InboundManagerError> {
        if self
            .listeners
            .read()
            .expect("inbound listeners lock")
            .contains_key(merge_key)
        {
            return Ok(());
        }

        let listen_addr = listener_config.inbound.listen_addr.clone();
        let listener = TcpListener::bind(&listen_addr).await.map_err(|err| {
            InboundManagerError::BindFailed {
                message: format!("failed to bind inbound {listen_addr}: {err}"),
            }
        })?;

        let (shutdown_tx, shutdown_rx) = watch::channel(false);
        let shared = Arc::new(SharedListener {
            tags: RwLock::new(HashSet::new()),
            listener_config: RwLock::new(Arc::clone(&listener_config)),
            shutdown: shutdown_tx,
            task: Mutex::new(None),
            listen_addr: listen_addr.clone(),
        });

        let shared_for_task = Arc::clone(&shared);
        let listen_for_log = listen_addr.clone();
        let task = tokio::spawn(async move {
            run_inbound_accept_loop(listener, shared_for_task, listen_for_log, shutdown_rx).await;
        });
        *shared.task.lock().expect("listener task lock") = Some(task);

        self.listeners
            .write()
            .expect("inbound listeners lock")
            .insert(merge_key.to_string(), shared);
        Ok(())
    }
}

async fn run_inbound_accept_loop(
    listener: TcpListener,
    shared: Arc<SharedListener>,
    listen_addr: String,
    mut shutdown: watch::Receiver<bool>,
) {
    loop {
        tokio::select! {
            changed = shutdown.changed() => {
                if changed.is_ok() && *shutdown.borrow() {
                    break;
                }
            }
            accept = listener.accept() => {
                match accept {
                    Ok((stream, peer)) => {
                        let conn_id = NEXT_CONN_ID.fetch_add(1, Ordering::Relaxed);
                        let conn_started = Instant::now();
                        debug!(conn_id, %peer, listen_addr = %listen_addr, "inbound TCP client accepted");
                        let config = shared
                            .listener_config
                            .read()
                            .expect("listener config lock")
                            .clone();
                        tokio::spawn(async move {
                            if let Err(err) = crate::app::handle_inbound_client(
                                stream,
                                config,
                                conn_id,
                                conn_started,
                            )
                            .await
                            {
                                debug!(conn_id, %peer, error = %err, "connection closed with error");
                            }
                        });
                    }
                    Err(err) => {
                        warn!(error = %err, addr = %listen_addr, "failed to accept inbound TCP connection");
                    }
                }
            }
        }
    }
}

fn map_config_error(err: HandlerConfigError) -> InboundManagerError {
    match err {
        HandlerConfigError::InvalidArgument(message) => InboundManagerError::invalid(message),
        HandlerConfigError::Unsupported(message) => InboundManagerError::Unsupported { message },
    }
}

fn map_auth_error(err: LogicalInboundAuthError) -> InboundManagerError {
    InboundManagerError::invalid(err.to_string())
}
