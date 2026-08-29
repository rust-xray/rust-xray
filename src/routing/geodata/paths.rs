use std::path::{Path, PathBuf};

const ASSET_ENV: &str = "XRAY_LOCATION_ASSET";

/// Resolve a geodata file path using Xray asset semantics.
///
/// Absolute paths are used as-is. Relative paths are resolved against
/// `XRAY_LOCATION_ASSET` when set, otherwise the process current directory.
pub fn resolve_geodata_path(file: &str) -> PathBuf {
    let path = Path::new(file);
    if path.is_absolute() {
        return path.to_path_buf();
    }
    if let Ok(asset_root) = std::env::var(ASSET_ENV) {
        let candidate = Path::new(&asset_root).join(file);
        if candidate.exists() {
            return candidate;
        }
    }
    std::env::current_dir()
        .unwrap_or_else(|_| PathBuf::from("."))
        .join(file)
}

pub fn default_geosite_file() -> &'static str {
    "geosite.dat"
}

pub fn default_geoip_file() -> &'static str {
    "geoip.dat"
}
