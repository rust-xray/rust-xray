use std::collections::HashSet;
use std::path::{Path, PathBuf};
use std::sync::Mutex;

/// Xray `xray.location.asset` environment variable.
pub const ASSET_LOCATION_ENV: &str = "xray.location.asset";
/// Normalized alias (`XRAY_LOCATION_ASSET`) accepted by upstream Xray-core.
pub const ASSET_LOCATION_ENV_ALT: &str = "XRAY_LOCATION_ASSET";

const SYSTEM_SHARE_ROOTS: [&str; 3] = [
    "/usr/local/share/xray",
    "/usr/share/xray",
    "/opt/share/xray",
];

/// Resolve a relative Xray asset filename using upstream `GetAssetLocation` semantics.
pub fn resolve_xray_asset(file: impl AsRef<Path>) -> PathBuf {
    XrayAssetResolver::from_runtime().resolve(file.as_ref())
}

/// Injectable Xray asset resolver for tests and production.
#[derive(Debug, Clone)]
pub struct XrayAssetResolver {
    configured_asset_dir: Option<PathBuf>,
    executable_dir: Option<PathBuf>,
    system_share_roots: Vec<PathBuf>,
}

impl XrayAssetResolver {
    pub fn from_runtime() -> Self {
        Self {
            configured_asset_dir: configured_asset_directory(),
            executable_dir: executable_directory(),
            system_share_roots: default_system_share_roots(),
        }
    }

    pub fn with_search_roots(
        configured_asset_dir: Option<PathBuf>,
        executable_dir: Option<PathBuf>,
        system_share_roots: Vec<PathBuf>,
    ) -> Self {
        Self {
            configured_asset_dir,
            executable_dir,
            system_share_roots,
        }
    }

    pub fn resolve(&self, file: &Path) -> PathBuf {
        if file.is_absolute() {
            return file.to_path_buf();
        }

        let default_path = self.default_asset_path(file);
        for candidate in self.candidates(file) {
            if candidate.exists() {
                log_resolved_asset_once(file, &candidate);
                return candidate;
            }
        }
        default_path
    }

    fn default_asset_directory(&self) -> PathBuf {
        if let Some(dir) = &self.configured_asset_dir {
            return dir.clone();
        }
        self.executable_dir
            .clone()
            .unwrap_or_else(|| PathBuf::from("."))
    }

    fn default_asset_path(&self, file: &Path) -> PathBuf {
        self.default_asset_directory().join(file)
    }

    fn candidates(&self, file: &Path) -> Vec<PathBuf> {
        let mut out = Vec::with_capacity(1 + self.system_share_roots.len());
        out.push(self.default_asset_path(file));
        for root in &self.system_share_roots {
            out.push(root.join(file));
        }
        out
    }
}

fn configured_asset_directory() -> Option<PathBuf> {
    for key in [ASSET_LOCATION_ENV, ASSET_LOCATION_ENV_ALT] {
        if let Ok(value) = std::env::var(key) {
            let trimmed = value.trim();
            if !trimmed.is_empty() {
                return Some(PathBuf::from(trimmed));
            }
        }
    }
    None
}

fn executable_directory() -> Option<PathBuf> {
    std::env::current_exe()
        .ok()
        .and_then(|path| path.parent().map(Path::to_path_buf))
}

fn default_system_share_roots() -> Vec<PathBuf> {
    SYSTEM_SHARE_ROOTS
        .iter()
        .map(|root| PathBuf::from(*root))
        .collect()
}

fn log_resolved_asset_once(file: &Path, path: &Path) {
    static LOGGED: Mutex<Option<HashSet<String>>> = Mutex::new(None);
    let asset = file.to_string_lossy().into_owned();
    let resolved = path.to_string_lossy().into_owned();
    let key = format!("{asset}={resolved}");
    let mut guard = LOGGED.lock().expect("asset log lock");
    let logged = guard.get_or_insert_with(HashSet::new);
    if logged.insert(key) {
        tracing::debug!(
            asset = %file.display(),
            path = %path.display(),
            "resolved Xray asset"
        );
    }
}

#[cfg(test)]
#[path = "../../tests/unit/platform/xray_assets.rs"]
mod xray_assets_tests;
