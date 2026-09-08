//! Process-global environment synchronization for parallel lib tests.
//!
//! Hold the async mutex for the entire guard lifetime so env reads in code under
//! test cannot race with other tests toggling the same variable.

use std::sync::OnceLock;
use tokio::sync::Mutex;

static ENV_TEST_LOCK: OnceLock<Mutex<()>> = OnceLock::new();

fn env_test_lock() -> &'static Mutex<()> {
    ENV_TEST_LOCK.get_or_init(|| Mutex::new(()))
}

/// RAII guard: serializes env mutation and restores the previous value on drop.
pub struct EnvVarGuard {
    key: &'static str,
    previous: Option<String>,
    _lock: tokio::sync::MutexGuard<'static, ()>,
}

impl EnvVarGuard {
    pub async fn set(key: &'static str, value: &str) -> Self {
        let lock = env_test_lock().lock().await;
        let previous = std::env::var(key).ok();
        // SAFETY: the mutex is held until this guard drops.
        unsafe { std::env::set_var(key, value) };
        Self {
            key,
            previous,
            _lock: lock,
        }
    }
}

impl Drop for EnvVarGuard {
    fn drop(&mut self) {
        match &self.previous {
            Some(value) => unsafe { std::env::set_var(self.key, value) },
            None => unsafe { std::env::remove_var(self.key) },
        }
    }
}
