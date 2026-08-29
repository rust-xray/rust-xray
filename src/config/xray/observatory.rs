use crate::config::xray::raw::XrayConfig;

pub fn validate_observatory_config(config: &XrayConfig) -> std::io::Result<()> {
    if let Some(burst) = config.burst_observatory.as_ref() {
        if burst.ping_config.is_none() {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "BurstObservatory requires a valid pingConfig",
            ));
        }
        crate::observatory::BurstObservatoryRuntimeConfig::from_raw(burst)?;
    }
    Ok(())
}
