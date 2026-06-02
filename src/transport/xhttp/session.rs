use std::collections::HashMap;
use std::sync::Mutex;
use std::time::{Duration, Instant};

use tracing::{debug, info, warn};

use super::mode::{effective_xhttp_mode_label, EffectiveXHttpMode, XHttpError};

pub const ENV_XHTTP_SESSION_IDLE_TIMEOUT_MS: &str = "RUST_XRAY_XHTTP_SESSION_IDLE_TIMEOUT_MS";
pub const ENV_XHTTP_MAX_SESSIONS: &str = "RUST_XRAY_XHTTP_MAX_SESSIONS";

const DEFAULT_IDLE_TIMEOUT_MS: u64 = 30_000;
const DEFAULT_MAX_SESSIONS: usize = 1024;
const MAX_SESSION_ID_LEN: usize = 128;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum XHttpSessionState {
    Opening,
    Active,
    Closing,
    Closed,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct XHttpSession {
    pub id: String,
    pub mode: EffectiveXHttpMode,
    pub created_at: Instant,
    pub last_seen: Instant,
    pub state: XHttpSessionState,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum XHttpSessionEnsureOutcome {
    Created,
    Reused,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum XHttpSessionError {
    EmptySessionId,
    SessionIdTooLong,
    InvalidSessionIdCharset,
    MaxSessionsReached,
    SessionNotFound,
    DownloadAlreadyAttached,
    UploadAlreadyAttached,
}

impl std::fmt::Display for XHttpSessionError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::EmptySessionId => write!(f, "xhttp session id is empty"),
            Self::SessionIdTooLong => {
                write!(
                    f,
                    "xhttp session id exceeds max length of {MAX_SESSION_ID_LEN}"
                )
            }
            Self::InvalidSessionIdCharset => {
                write!(f, "xhttp session id contains unsupported characters")
            }
            Self::MaxSessionsReached => write!(f, "xhttp session limit reached"),
            Self::SessionNotFound => write!(f, "xhttp session not found"),
            Self::DownloadAlreadyAttached => {
                write!(f, "xhttp packet-up download stream already attached")
            }
            Self::UploadAlreadyAttached => {
                write!(f, "xhttp stream-up upload stream already attached")
            }
        }
    }
}

impl std::error::Error for XHttpSessionError {}

pub struct XHttpSessionManager {
    sessions: Mutex<HashMap<String, XHttpSession>>,
    idle_timeout: Duration,
    max_sessions: usize,
}

impl XHttpSessionManager {
    pub fn from_env() -> Self {
        Self::new(parse_idle_timeout_from_env(), parse_max_sessions_from_env())
    }

    pub fn for_test(idle_timeout: Duration, max_sessions: usize) -> Self {
        Self::new(idle_timeout, max_sessions)
    }

    pub fn new(idle_timeout: Duration, max_sessions: usize) -> Self {
        Self {
            sessions: Mutex::new(HashMap::new()),
            idle_timeout,
            max_sessions: max_sessions.max(1),
        }
    }

    pub fn idle_timeout(&self) -> Duration {
        self.idle_timeout
    }

    pub fn max_sessions(&self) -> usize {
        self.max_sessions
    }

    pub fn session_count(&self) -> usize {
        self.sessions
            .lock()
            .expect("xhttp session manager lock poisoned")
            .len()
    }

    pub fn validate_session_id(id: &str) -> Result<(), XHttpSessionError> {
        let id = id.trim();
        if id.is_empty() {
            return Err(XHttpSessionError::EmptySessionId);
        }
        if id.len() > MAX_SESSION_ID_LEN {
            return Err(XHttpSessionError::SessionIdTooLong);
        }
        if !id
            .chars()
            .all(|ch| ch.is_ascii_alphanumeric() || matches!(ch, '-' | '_'))
        {
            return Err(XHttpSessionError::InvalidSessionIdCharset);
        }
        if id.contains("..") || id.contains('%') {
            return Err(XHttpSessionError::InvalidSessionIdCharset);
        }
        Ok(())
    }

    pub fn validate_session_id_as_xhttp_error(id: &str) -> Result<(), XHttpError> {
        Self::validate_session_id(id).map_err(|err| match err {
            XHttpSessionError::EmptySessionId => XHttpError::InvalidSessionId("empty".to_string()),
            XHttpSessionError::SessionIdTooLong => {
                XHttpError::InvalidSessionId(format!("exceeds max length of {MAX_SESSION_ID_LEN}"))
            }
            XHttpSessionError::InvalidSessionIdCharset => {
                XHttpError::InvalidSessionId("unsupported characters or path traversal".to_string())
            }
            XHttpSessionError::MaxSessionsReached => {
                XHttpError::InvalidSessionId("session limit reached".to_string())
            }
            XHttpSessionError::SessionNotFound => {
                XHttpError::InvalidSessionId("session not found".to_string())
            }
            XHttpSessionError::DownloadAlreadyAttached => {
                XHttpError::InvalidSessionId("download stream already attached".to_string())
            }
            XHttpSessionError::UploadAlreadyAttached => {
                XHttpError::InvalidSessionId("upload stream already attached".to_string())
            }
        })
    }

    pub fn ensure_session(
        &self,
        id: &str,
        mode: EffectiveXHttpMode,
    ) -> Result<XHttpSessionEnsureOutcome, XHttpSessionError> {
        Self::validate_session_id(id)?;
        self.cleanup_idle();

        let mut sessions = self
            .sessions
            .lock()
            .expect("xhttp session manager lock poisoned");
        if let Some(session) = sessions.get_mut(id) {
            session.last_seen = Instant::now();
            session.state = XHttpSessionState::Active;
            info!(
                session_id = id,
                mode = effective_xhttp_mode_label(session.mode),
                "xhttp session reused"
            );
            return Ok(XHttpSessionEnsureOutcome::Reused);
        }

        if sessions.len() >= self.max_sessions {
            return Err(XHttpSessionError::MaxSessionsReached);
        }

        let now = Instant::now();
        sessions.insert(
            id.to_string(),
            XHttpSession {
                id: id.to_string(),
                mode,
                created_at: now,
                last_seen: now,
                state: XHttpSessionState::Opening,
            },
        );
        info!(
            session_id = id,
            mode = effective_xhttp_mode_label(mode),
            max_sessions = self.max_sessions,
            "xhttp session created"
        );
        Ok(XHttpSessionEnsureOutcome::Created)
    }

    pub fn cleanup_idle(&self) -> usize {
        let now = Instant::now();
        let mut sessions = self
            .sessions
            .lock()
            .expect("xhttp session manager lock poisoned");
        let before = sessions.len();
        sessions.retain(|session_id, session| {
            let idle = now
                .checked_duration_since(session.last_seen)
                .unwrap_or(Duration::ZERO)
                >= self.idle_timeout;
            if idle {
                debug!(
                    session_id = %session_id,
                    mode = effective_xhttp_mode_label(session.mode),
                    idle_ms = session.last_seen.elapsed().as_millis(),
                    "xhttp session idle cleanup"
                );
                false
            } else {
                true
            }
        });
        before.saturating_sub(sessions.len())
    }

    pub fn close(&self, id: &str, reason: &str) -> Result<(), XHttpSessionError> {
        Self::validate_session_id(id)?;
        let mut sessions = self
            .sessions
            .lock()
            .expect("xhttp session manager lock poisoned");
        if sessions.remove(id).is_some() {
            info!(session_id = id, reason, "xhttp session closed");
            Ok(())
        } else {
            Err(XHttpSessionError::SessionNotFound)
        }
    }

    pub fn get(&self, id: &str) -> Result<XHttpSession, XHttpSessionError> {
        Self::validate_session_id(id)?;
        self.sessions
            .lock()
            .expect("xhttp session manager lock poisoned")
            .get(id)
            .cloned()
            .ok_or(XHttpSessionError::SessionNotFound)
    }

    pub fn touch(&self, id: &str) -> Result<(), XHttpSessionError> {
        Self::validate_session_id(id)?;
        let mut sessions = self
            .sessions
            .lock()
            .expect("xhttp session manager lock poisoned");
        if let Some(session) = sessions.get_mut(id) {
            session.last_seen = Instant::now();
            Ok(())
        } else {
            Err(XHttpSessionError::SessionNotFound)
        }
    }
}

fn parse_idle_timeout_from_env() -> Duration {
    parse_env_u64(
        ENV_XHTTP_SESSION_IDLE_TIMEOUT_MS,
        DEFAULT_IDLE_TIMEOUT_MS,
        "xhttp session idle timeout",
    )
}

fn parse_max_sessions_from_env() -> usize {
    match std::env::var(ENV_XHTTP_MAX_SESSIONS) {
        Ok(raw) => match raw.trim().parse::<usize>() {
            Ok(value) if value > 0 => value,
            Ok(_) => {
                warn!(
                    env = ENV_XHTTP_MAX_SESSIONS,
                    value = raw,
                    default = DEFAULT_MAX_SESSIONS,
                    "invalid xhttp max sessions env; using default"
                );
                DEFAULT_MAX_SESSIONS
            }
            Err(err) => {
                warn!(
                    env = ENV_XHTTP_MAX_SESSIONS,
                    value = raw,
                    error = %err,
                    default = DEFAULT_MAX_SESSIONS,
                    "invalid xhttp max sessions env; using default"
                );
                DEFAULT_MAX_SESSIONS
            }
        },
        Err(_) => DEFAULT_MAX_SESSIONS,
    }
}

fn parse_env_u64(env: &str, default: u64, label: &str) -> Duration {
    match std::env::var(env) {
        Ok(raw) => match raw.trim().parse::<u64>() {
            Ok(value) => Duration::from_millis(value),
            Err(err) => {
                warn!(
                    env,
                    value = raw,
                    error = %err,
                    default,
                    "{label} env invalid; using default"
                );
                Duration::from_millis(default)
            }
        },
        Err(_) => Duration::from_millis(default),
    }
}

#[cfg(test)]
#[path = "../../../tests/unit/transport/xhttp/session.rs"]
mod tests;
