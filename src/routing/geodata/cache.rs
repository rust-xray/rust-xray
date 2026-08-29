use std::sync::{Arc, RwLock};

use crate::api::proto::common::geodata::Domain;
use crate::routing::conditions::IpNetwork;
use crate::routing::geodata::loader::{load_geoip_networks, load_geosite_domains, GeodataError};

type GeoSiteKey = (String, String, String);
type GeoIpKey = (String, String);

#[derive(Default)]
struct CacheInner {
    geosite: std::collections::HashMap<GeoSiteKey, Arc<Vec<Domain>>>,
    geoip: std::collections::HashMap<GeoIpKey, Arc<Vec<IpNetwork>>>,
    geosite_loads: usize,
    geoip_loads: usize,
}

/// Concurrency-safe geodata cache populated at rule compilation time.
#[derive(Clone, Default)]
pub struct GeodataCache {
    inner: Arc<RwLock<CacheInner>>,
}

impl GeodataCache {
    pub fn load_geosite(
        &self,
        file: &str,
        code: &str,
        attrs: &str,
    ) -> Result<Arc<Vec<Domain>>, GeodataError> {
        let key = (
            file.to_string(),
            code.to_ascii_uppercase(),
            attrs.to_string(),
        );
        if let Some(cached) = self
            .inner
            .read()
            .expect("geodata cache lock")
            .geosite
            .get(&key)
            .cloned()
        {
            return Ok(cached);
        }

        let domains = Arc::new(load_geosite_domains(file, &key.1, attrs)?);
        self.inner
            .write()
            .expect("geodata cache lock")
            .geosite
            .insert(key, Arc::clone(&domains));
        self.inner
            .write()
            .expect("geodata cache lock")
            .geosite_loads += 1;
        Ok(domains)
    }

    pub fn load_geoip(
        &self,
        file: &str,
        code: &str,
        reverse_match: bool,
    ) -> Result<Arc<Vec<(IpNetwork, bool)>>, GeodataError> {
        let key = (file.to_string(), code.to_ascii_uppercase());
        if let Some(cached) = self
            .inner
            .read()
            .expect("geodata cache lock")
            .geoip
            .get(&key)
            .cloned()
        {
            return Ok(Arc::new(
                cached
                    .iter()
                    .cloned()
                    .map(|network| (network, reverse_match))
                    .collect(),
            ));
        }

        let networks = Arc::new(load_geoip_networks(file, &key.1)?);
        let mut inner = self.inner.write().expect("geodata cache lock");
        inner.geoip.insert(key, Arc::clone(&networks));
        inner.geoip_loads += 1;
        Ok(Arc::new(
            networks
                .iter()
                .cloned()
                .map(|network| (network, reverse_match))
                .collect(),
        ))
    }

    #[cfg(test)]
    pub fn load_counts(&self) -> (usize, usize) {
        let inner = self.inner.read().expect("geodata cache lock");
        (inner.geosite_loads, inner.geoip_loads)
    }
}
