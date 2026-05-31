use std::fmt;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum XHttpMode {
    Auto,
    StreamOne,
    StreamUp,
    PacketUp,
    PacketDown,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EffectiveXHttpMode {
    StreamOne,
    StreamUp,
    PacketUp,
    PacketDown,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TransportSecurity {
    None,
    Tls,
    Reality,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum XHttpError {
    UnknownMode(String),
    UnsupportedMode(XHttpMode),
}

impl fmt::Display for XHttpError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::UnknownMode(mode) => write!(f, "unsupported XHTTP mode: {mode}"),
            Self::UnsupportedMode(mode) => {
                write!(
                    f,
                    "XHTTP mode {} is not supported in this MVP",
                    xhttp_mode_label(*mode)
                )
            }
        }
    }
}

impl std::error::Error for XHttpError {}

impl From<XHttpError> for std::io::Error {
    fn from(err: XHttpError) -> Self {
        std::io::Error::new(std::io::ErrorKind::Unsupported, err.to_string())
    }
}

pub fn parse_xhttp_mode(raw: &str) -> Result<XHttpMode, XHttpError> {
    match raw.trim().to_ascii_lowercase().as_str() {
        "auto" => Ok(XHttpMode::Auto),
        "stream-one" => Ok(XHttpMode::StreamOne),
        "stream-up" => Ok(XHttpMode::StreamUp),
        "packet-up" => Ok(XHttpMode::PacketUp),
        "packet-down" => Ok(XHttpMode::PacketDown),
        other => Err(XHttpError::UnknownMode(other.to_string())),
    }
}

pub fn configured_xhttp_mode(mode: Option<&str>) -> Result<Option<XHttpMode>, XHttpError> {
    match mode.map(str::trim).filter(|value| !value.is_empty()) {
        None => Ok(None),
        Some(raw) => Ok(Some(parse_xhttp_mode(raw)?)),
    }
}

pub fn resolve_xhttp_mode(
    configured_mode: Option<XHttpMode>,
    has_download_settings: bool,
    security: TransportSecurity,
) -> Result<EffectiveXHttpMode, XHttpError> {
    let configured = configured_mode.unwrap_or(XHttpMode::Auto);
    match configured {
        XHttpMode::Auto => resolve_auto_mode(has_download_settings, security),
        XHttpMode::StreamOne => Ok(EffectiveXHttpMode::StreamOne),
        XHttpMode::StreamUp => Ok(EffectiveXHttpMode::StreamUp),
        XHttpMode::PacketUp => Ok(EffectiveXHttpMode::PacketUp),
        XHttpMode::PacketDown => Ok(EffectiveXHttpMode::PacketDown),
    }
}

pub fn effective_xhttp_mode_is_supported(mode: EffectiveXHttpMode) -> bool {
    matches!(mode, EffectiveXHttpMode::StreamOne)
}

pub fn effective_xhttp_mode_unsupported_reason(mode: EffectiveXHttpMode) -> Option<&'static str> {
    match mode {
        EffectiveXHttpMode::StreamOne => None,
        EffectiveXHttpMode::StreamUp => Some("stream_up_not_implemented"),
        EffectiveXHttpMode::PacketUp => Some("packet_up_not_implemented"),
        EffectiveXHttpMode::PacketDown => Some("packet_down_not_implemented"),
    }
}

fn resolve_auto_mode(
    has_download_settings: bool,
    security: TransportSecurity,
) -> Result<EffectiveXHttpMode, XHttpError> {
    let _ = has_download_settings;
    let _ = security;
    Ok(EffectiveXHttpMode::StreamOne)
}

pub fn configured_xhttp_mode_label(configured_mode: Option<XHttpMode>) -> &'static str {
    match configured_mode {
        None => "absent",
        Some(mode) => xhttp_mode_label(mode),
    }
}

pub fn xhttp_mode_label(mode: XHttpMode) -> &'static str {
    match mode {
        XHttpMode::Auto => "auto",
        XHttpMode::StreamOne => "stream-one",
        XHttpMode::StreamUp => "stream-up",
        XHttpMode::PacketUp => "packet-up",
        XHttpMode::PacketDown => "packet-down",
    }
}

pub fn effective_xhttp_mode_label(mode: EffectiveXHttpMode) -> &'static str {
    match mode {
        EffectiveXHttpMode::StreamOne => "stream-one",
        EffectiveXHttpMode::StreamUp => "stream-up",
        EffectiveXHttpMode::PacketUp => "packet-up",
        EffectiveXHttpMode::PacketDown => "packet-down",
    }
}

pub fn transport_security_label(security: TransportSecurity) -> &'static str {
    match security {
        TransportSecurity::None => "none",
        TransportSecurity::Tls => "tls",
        TransportSecurity::Reality => "reality",
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn absent_mode_resolves_to_stream_one() {
        assert_eq!(
            resolve_xhttp_mode(None, false, TransportSecurity::Reality).unwrap(),
            EffectiveXHttpMode::StreamOne
        );
    }

    #[test]
    fn auto_with_reality_and_no_download_settings_resolves_to_stream_one() {
        assert_eq!(
            resolve_xhttp_mode(Some(XHttpMode::Auto), false, TransportSecurity::Reality).unwrap(),
            EffectiveXHttpMode::StreamOne
        );
    }

    #[test]
    fn auto_with_no_download_settings_resolves_to_stream_one() {
        assert_eq!(
            resolve_xhttp_mode(Some(XHttpMode::Auto), false, TransportSecurity::None).unwrap(),
            EffectiveXHttpMode::StreamOne
        );
    }

    #[test]
    fn stream_one_resolves_to_stream_one() {
        assert_eq!(
            resolve_xhttp_mode(
                Some(XHttpMode::StreamOne),
                false,
                TransportSecurity::Reality
            )
            .unwrap(),
            EffectiveXHttpMode::StreamOne
        );
    }

    #[test]
    fn stream_up_resolves_but_is_not_supported_at_runtime() {
        assert_eq!(
            resolve_xhttp_mode(Some(XHttpMode::StreamUp), false, TransportSecurity::Reality)
                .unwrap(),
            EffectiveXHttpMode::StreamUp
        );
        assert!(!effective_xhttp_mode_is_supported(
            EffectiveXHttpMode::StreamUp
        ));
        assert_eq!(
            effective_xhttp_mode_unsupported_reason(EffectiveXHttpMode::StreamUp),
            Some("stream_up_not_implemented")
        );
    }

    #[test]
    fn packet_up_resolves_but_is_not_supported_at_runtime() {
        assert_eq!(
            resolve_xhttp_mode(Some(XHttpMode::PacketUp), false, TransportSecurity::Reality)
                .unwrap(),
            EffectiveXHttpMode::PacketUp
        );
        assert!(!effective_xhttp_mode_is_supported(
            EffectiveXHttpMode::PacketUp
        ));
        assert_eq!(
            effective_xhttp_mode_unsupported_reason(EffectiveXHttpMode::PacketUp),
            Some("packet_up_not_implemented")
        );
    }

    #[test]
    fn packet_down_resolves_but_is_not_supported_at_runtime() {
        assert_eq!(
            resolve_xhttp_mode(
                Some(XHttpMode::PacketDown),
                false,
                TransportSecurity::Reality,
            )
            .unwrap(),
            EffectiveXHttpMode::PacketDown
        );
        assert!(!effective_xhttp_mode_is_supported(
            EffectiveXHttpMode::PacketDown
        ));
        assert_eq!(
            effective_xhttp_mode_unsupported_reason(EffectiveXHttpMode::PacketDown),
            Some("packet_down_not_implemented")
        );
    }

    #[test]
    fn unknown_mode_is_rejected_clearly() {
        let err = parse_xhttp_mode("not-a-mode").unwrap_err();
        assert_eq!(err, XHttpError::UnknownMode("not-a-mode".to_string()));
        assert_eq!(err.to_string(), "unsupported XHTTP mode: not-a-mode");
    }

    #[test]
    fn configured_xhttp_mode_treats_empty_as_absent() {
        assert_eq!(configured_xhttp_mode(None).unwrap(), None);
        assert_eq!(configured_xhttp_mode(Some("")).unwrap(), None);
        assert_eq!(configured_xhttp_mode(Some("  ")).unwrap(), None);
    }
}
