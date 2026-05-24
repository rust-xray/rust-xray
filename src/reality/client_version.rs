/// Parses an Xray REALITY client version string into four byte components.
///
/// Supported forms: `"1.8.0"`, `"1.8.0.0"`, `"24.9.30"`.
/// Missing components are zero-filled; each component must be 0..=255.
pub fn parse_reality_client_version(value: &str) -> std::io::Result<[u8; 4]> {
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

pub(crate) fn version_ge(a: [u8; 4], b: [u8; 4]) -> bool {
    a >= b
}

pub(crate) fn version_le(a: [u8; 4], b: [u8; 4]) -> bool {
    a <= b
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_reality_client_version_parses_three_components() {
        assert_eq!(parse_reality_client_version("1.8.0").unwrap(), [1, 8, 0, 0]);
    }

    #[test]
    fn parse_reality_client_version_parses_four_components() {
        assert_eq!(
            parse_reality_client_version("1.8.1.2").unwrap(),
            [1, 8, 1, 2]
        );
    }

    #[test]
    fn parse_reality_client_version_parses_date_style_version() {
        assert_eq!(
            parse_reality_client_version("24.9.30").unwrap(),
            [24, 9, 30, 0]
        );
    }

    #[test]
    fn parse_reality_client_version_rejects_component_above_255() {
        let err = parse_reality_client_version("1.300.0").unwrap_err();
        assert_eq!(err.kind(), std::io::ErrorKind::InvalidInput);
    }

    #[test]
    fn parse_reality_client_version_rejects_too_many_components() {
        let err = parse_reality_client_version("1.2.3.4.5").unwrap_err();
        assert_eq!(err.kind(), std::io::ErrorKind::InvalidInput);
    }

    #[test]
    fn parse_reality_client_version_rejects_empty_string() {
        let err = parse_reality_client_version("").unwrap_err();
        assert_eq!(err.kind(), std::io::ErrorKind::InvalidInput);
    }
}
