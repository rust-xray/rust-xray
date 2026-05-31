#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum TransportNetwork {
    RawTcp,
    XHttp,
}

impl TransportNetwork {
    pub fn parse(network: Option<&str>) -> std::io::Result<Self> {
        let normalized = network
            .map(str::trim)
            .filter(|value| !value.is_empty())
            .map(str::to_ascii_lowercase);

        match normalized.as_deref() {
            None | Some("tcp") | Some("raw") => Ok(Self::RawTcp),
            Some("xhttp") | Some("splithttp") => Ok(Self::XHttp),
            Some("grpc") => Err(std::io::Error::new(
                std::io::ErrorKind::Unsupported,
                "REALITY over gRPC runtime is not implemented yet",
            )),
            Some("ws") | Some("websocket") => Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "REALITY over WebSocket transport (network=ws) is not supported",
            )),
            Some("mkcp") | Some("kcp") => Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "REALITY over mKCP transport (network=mkcp/kcp) is not supported",
            )),
            Some("httpupgrade") => Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "REALITY over HTTPUpgrade transport (network=httpupgrade) is not supported",
            )),
            Some("hysteria") => Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "REALITY over Hysteria transport (network=hysteria) is not supported",
            )),
            Some(value) => Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                format!("unsupported REALITY transport network: {value}"),
            )),
        }
    }

    pub fn as_log_label(&self) -> &'static str {
        match self {
            Self::RawTcp => "raw",
            Self::XHttp => "xhttp",
        }
    }
}

/// Validate REALITY inbound `streamSettings.network`.
///
/// `tcp` is the legacy alias for raw TCP transport; `raw` is the explicit form.
pub fn validate_reality_transport_network(network: Option<&str>) -> std::io::Result<()> {
    TransportNetwork::parse(network).map(|_| ())
}
