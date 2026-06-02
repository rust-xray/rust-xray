/// Parses an Xray REALITY client version string into four byte components.
///
/// Supported forms: `"1"`, `"1.8.0"`, `"1.8.0.0"`, `"24.9.30"`.
/// Missing components are zero-filled; each component must be 0..=255.
pub fn parse_reality_client_version(value: &str) -> std::io::Result<[u8; 4]> {
    let value = value.trim();
    if value.is_empty() {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "client version must not be empty",
        ));
    }

    let parts: Vec<&str> = value.split('.').collect();
    if parts.is_empty() || parts.len() > 4 {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            format!(
                "client version must have 1..=4 components, got {}",
                parts.len()
            ),
        ));
    }

    let mut version = [0u8; 4];
    for (i, part) in parts.iter().enumerate() {
        if part.is_empty() {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                format!("client version component must not be empty in {value:?}"),
            ));
        }

        let component: u16 = part.parse().map_err(|_| {
            std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                format!("client version component must be a number, got {part:?}"),
            )
        })?;

        if component > 255 {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                format!("client version component must be 0..=255, got {component}"),
            ));
        }

        version[i] = component as u8;
    }

    Ok(version)
}

pub fn version_ge(actual: [u8; 4], min: [u8; 4]) -> bool {
    actual >= min
}

pub fn version_le(actual: [u8; 4], max: [u8; 4]) -> bool {
    actual <= max
}

#[cfg(test)]
#[path = "../../tests/unit/reality/version.rs"]
mod tests;
