use std::path::{Path, PathBuf};

use crate::platform::resolve_xray_asset;

/// Resolve a geodata file path using Xray asset semantics.
///
/// Absolute paths are preserved. Relative filenames use [`resolve_xray_asset`].
pub fn resolve_geodata_path(file: &str) -> PathBuf {
    resolve_xray_asset(Path::new(file))
}

pub fn default_geosite_file() -> &'static str {
    "geosite.dat"
}

pub fn default_geoip_file() -> &'static str {
    "geoip.dat"
}
