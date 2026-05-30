use serde::de::{self, Deserializer};
use serde::Deserialize;
use serde_json::Value;
use std::collections::BTreeMap;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DnsServerTransport {
    Udp,
    Tcp,
    Doh,
    TcpLocal,
    DohLocal,
    Unsupported(String),
}

impl DnsServerTransport {
    pub fn label(&self) -> &str {
        match self {
            Self::Udp => "udp",
            Self::Tcp => "tcp",
            Self::Doh => "doh",
            Self::TcpLocal => "tcp+local",
            Self::DohLocal => "https+local",
            Self::Unsupported(scheme) => scheme.as_str(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DnsServerConfig {
    pub original: String,
    pub transport: DnsServerTransport,
    pub host: String,
    pub port: u16,
    pub path: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum QueryStrategy {
    #[default]
    UseIP,
    UseIPv4,
    UseIPv6,
    UseSystem,
}

impl<'de> Deserialize<'de> for QueryStrategy {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let value = String::deserialize(deserializer)?;
        match value.as_str() {
            "UseIP" => Ok(Self::UseIP),
            "UseIPv4" => Ok(Self::UseIPv4),
            "UseIPv6" => Ok(Self::UseIPv6),
            "UseSystem" => Ok(Self::UseSystem),
            other => Err(de::Error::custom(format!(
                "unsupported dns.queryStrategy: {other}"
            ))),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
pub struct DnsConfig {
    #[serde(default, deserialize_with = "deserialize_dns_servers")]
    pub servers: Vec<DnsServerConfig>,
    #[serde(rename = "queryStrategy", default)]
    pub query_strategy: QueryStrategy,
    #[serde(rename = "disableCache", default)]
    pub disable_cache: bool,

    #[serde(flatten)]
    pub extra: BTreeMap<String, Value>,
}

fn deserialize_dns_servers<'de, D>(deserializer: D) -> Result<Vec<DnsServerConfig>, D::Error>
where
    D: Deserializer<'de>,
{
    let values = Vec::<Value>::deserialize(deserializer)?;
    values
        .into_iter()
        .map(|value| match value {
            Value::String(server) => parse_dns_server(&server).map_err(de::Error::custom),
            other => Err(de::Error::custom(format!(
                "dns.servers entry must be a string for this runtime: {other}"
            ))),
        })
        .collect()
}

pub fn parse_dns_server(input: &str) -> std::io::Result<DnsServerConfig> {
    let original = input.to_string();
    let trimmed = input.trim();
    if trimmed.is_empty() {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "dns server must not be empty",
        ));
    }

    if let Some(rest) = trimmed.strip_prefix("tcp://") {
        let (host, port, path) = parse_host_port_path(rest, 53)?;
        return Ok(DnsServerConfig {
            original,
            transport: DnsServerTransport::Tcp,
            host,
            port,
            path,
        });
    }
    if let Some(rest) = trimmed.strip_prefix("tcp+local://") {
        let (host, port, path) = parse_host_port_path(rest, 53)?;
        return Ok(DnsServerConfig {
            original,
            transport: DnsServerTransport::TcpLocal,
            host,
            port,
            path,
        });
    }
    if let Some(rest) = trimmed.strip_prefix("https+local://") {
        let (host, port, path) = parse_host_port_path(rest, 443)?;
        return Ok(DnsServerConfig {
            original,
            transport: DnsServerTransport::DohLocal,
            host,
            port,
            path,
        });
    }
    if let Some(rest) = trimmed.strip_prefix("https://") {
        let (host, port, path) = parse_host_port_path(rest, 443)?;
        return Ok(DnsServerConfig {
            original,
            transport: DnsServerTransport::Doh,
            host,
            port,
            path,
        });
    }
    if let Some((scheme, rest)) = trimmed.split_once("://") {
        let (host, port, path) = parse_host_port_path(rest, 53)?;
        return Ok(DnsServerConfig {
            original,
            transport: DnsServerTransport::Unsupported(scheme.to_string()),
            host,
            port,
            path,
        });
    }

    let (host, port, path) = parse_host_port_path(trimmed, 53)?;
    Ok(DnsServerConfig {
        original,
        transport: DnsServerTransport::Udp,
        host,
        port,
        path,
    })
}

fn parse_host_port_path(
    input: &str,
    default_port: u16,
) -> std::io::Result<(String, u16, Option<String>)> {
    let (authority, path) = match input.split_once('/') {
        Some((authority, path)) => (authority, Some(format!("/{path}"))),
        None => (input, None),
    };
    if authority.is_empty() {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "dns server host must not be empty",
        ));
    }

    if authority.starts_with('[') {
        let closing = authority.find(']').ok_or_else(|| {
            std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                format!("invalid dns server IPv6 authority: {authority:?}"),
            )
        })?;
        let host = authority[1..closing].to_string();
        let rest = &authority[closing + 1..];
        let port = if let Some(raw) = rest.strip_prefix(':') {
            parse_port(raw)?
        } else if rest.is_empty() {
            default_port
        } else {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                format!("invalid dns server authority: {authority:?}"),
            ));
        };
        return Ok((host, port, path));
    }

    let colon_count = authority.as_bytes().iter().filter(|&&b| b == b':').count();
    let (host, port) = if colon_count == 1 {
        let (host, raw_port) = authority.rsplit_once(':').expect("one colon");
        if host.is_empty() {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "dns server host must not be empty",
            ));
        }
        (host.to_string(), parse_port(raw_port)?)
    } else {
        (authority.to_string(), default_port)
    };
    Ok((host, port, path))
}

fn parse_port(raw: &str) -> std::io::Result<u16> {
    let port = raw.parse::<u16>().map_err(|_| {
        std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            format!("invalid dns server port: {raw:?}"),
        )
    })?;
    if port == 0 {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "dns server port must be greater than zero",
        ));
    }
    Ok(port)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_dns_tcp_with_port() {
        let server = parse_dns_server("tcp://1.1.1.1:5353").unwrap();
        assert_eq!(server.transport, DnsServerTransport::Tcp);
        assert_eq!(server.host, "1.1.1.1");
        assert_eq!(server.port, 5353);
    }

    #[test]
    fn parse_dns_tcp_default_port() {
        let server = parse_dns_server("tcp://dns.example.com").unwrap();
        assert_eq!(server.transport, DnsServerTransport::Tcp);
        assert_eq!(server.host, "dns.example.com");
        assert_eq!(server.port, 53);
    }

    #[test]
    fn parse_dns_udp_ip_default_port() {
        let server = parse_dns_server("1.1.1.1").unwrap();
        assert_eq!(server.transport, DnsServerTransport::Udp);
        assert_eq!(server.host, "1.1.1.1");
        assert_eq!(server.port, 53);
    }

    #[test]
    fn parse_dns_doh_unsupported_but_parsed() {
        let server = parse_dns_server("https://dns.google/dns-query").unwrap();
        assert_eq!(server.transport, DnsServerTransport::Doh);
        assert_eq!(server.host, "dns.google");
        assert_eq!(server.port, 443);
        assert_eq!(server.path.as_deref(), Some("/dns-query"));
    }

    #[test]
    fn parse_query_strategy_use_ipv4() {
        let config: DnsConfig =
            serde_json::from_str(r#"{"servers":["tcp://1.1.1.1:53"],"queryStrategy":"UseIPv4"}"#)
                .unwrap();
        assert_eq!(config.query_strategy, QueryStrategy::UseIPv4);
    }

    #[test]
    fn invalid_query_strategy_rejected() {
        let err = serde_json::from_str::<DnsConfig>(
            r#"{"servers":["tcp://1.1.1.1:53"],"queryStrategy":"PreferIPv4"}"#,
        )
        .unwrap_err();
        assert!(err.to_string().contains("unsupported dns.queryStrategy"));
    }
}
