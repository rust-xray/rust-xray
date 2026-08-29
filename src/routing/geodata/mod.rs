mod cache;
mod loader;
mod paths;

pub use cache::GeodataCache;
pub use loader::{domain_to_matcher_parts, GeodataError};
#[cfg(test)]
pub use loader::{encode_geoip_dat, encode_geosite_dat, load_geosite_domains};
