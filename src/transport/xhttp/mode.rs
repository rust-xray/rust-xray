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
    MissingSessionId,
    InvalidSessionId(String),
    MalformedPacketRequest(String),
    UnsupportedSessionSource { source: String, detail: String },
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
            Self::MissingSessionId => write!(f, "xhttp session id is missing"),
            Self::InvalidSessionId(detail) => write!(f, "invalid xhttp session id: {detail}"),
            Self::MalformedPacketRequest(detail) => {
                write!(f, "malformed xhttp packet request: {detail}")
            }
            Self::UnsupportedSessionSource { source, detail } => {
                write!(f, "unsupported xhttp session source {source}: {detail}")
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

/// Official Xray `packet-up` clients use a separate download GET (`/xhttp/{session}`).
pub fn packet_up_download_side_ready() -> bool {
    true
}

/// Official Xray `stream-up` clients use GET + POST on `/xhttp/{session}`.
pub fn stream_up_download_side_ready() -> bool {
    true
}

/// Gated switch for end-to-end download-side interop (GET response streaming).
pub fn xhttp_download_side_ready() -> bool {
    packet_up_download_side_ready() || stream_up_download_side_ready()
}

pub fn effective_xhttp_mode_is_supported(mode: EffectiveXHttpMode) -> bool {
    match mode {
        EffectiveXHttpMode::StreamOne => true,
        EffectiveXHttpMode::PacketUp => packet_up_download_side_ready(),
        EffectiveXHttpMode::StreamUp => stream_up_download_side_ready(),
        EffectiveXHttpMode::PacketDown => false,
    }
}

pub fn effective_xhttp_mode_unsupported_reason(mode: EffectiveXHttpMode) -> Option<&'static str> {
    match mode {
        EffectiveXHttpMode::StreamOne => None,
        EffectiveXHttpMode::PacketUp if packet_up_download_side_ready() => None,
        EffectiveXHttpMode::PacketUp => Some("packet_up_download_side_not_implemented"),
        EffectiveXHttpMode::StreamUp if stream_up_download_side_ready() => None,
        EffectiveXHttpMode::StreamUp => Some("stream_up_not_implemented"),
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
#[path = "../../../tests/unit/transport/xhttp/mode.rs"]
mod tests;
