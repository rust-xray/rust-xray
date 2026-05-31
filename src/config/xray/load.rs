use std::path::Path;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::UnixStream;

use crate::startup_log;

use super::raw::XrayConfig;

const HTTP_UNIX_SCHEME: &str = "http+unix://";
const REMNAWAVE_INTERNAL_CONFIG_PATH: &str = "/internal/get-config";

pub fn validate_xray_panel_config(config: &XrayConfig) -> std::io::Result<()> {
    super::api::validate_api_config(config)?;
    super::routing::validate_routing_config(config)?;
    Ok(())
}

/// Parse Remnawave `http+unix://` config source into `(socket_path, request_path)`.
pub fn parse_http_unix_config_uri(source: &str) -> std::io::Result<(String, String)> {
    let (socket_path, request_path) = parse_http_unix_source(source)?;
    Ok((socket_path.to_string(), request_path.to_string()))
}

pub fn load_xray_config_from_file(path: impl AsRef<Path>) -> std::io::Result<XrayConfig> {
    let path = path.as_ref();
    let contents = std::fs::read_to_string(path).map_err(|e| {
        std::io::Error::new(
            e.kind(),
            format!("failed to read config file {}: {e}", path.display()),
        )
    })?;

    let config: XrayConfig = serde_json::from_str(&contents).map_err(|e| {
        std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            format!("failed to parse config file {}: {e}", path.display()),
        )
    })?;
    validate_xray_panel_config(&config)?;
    Ok(config)
}

pub fn redact_config_source(source: &str) -> String {
    if let Some((before_query, _)) = source.split_once('?') {
        return format!("{before_query}?<redacted>");
    }
    source.to_string()
}

/// Config source kind for startup diagnostics.
pub fn config_source_kind(source: &str) -> &'static str {
    if source.starts_with(HTTP_UNIX_SCHEME) {
        "http+unix"
    } else {
        "file"
    }
}

/// True when config is loaded from Remnawave's internal `http+unix` socket API.
pub fn is_remnawave_http_unix_config_source(source: &str) -> bool {
    if config_source_kind(source) != "http+unix" {
        return false;
    }
    match parse_http_unix_config_uri(source) {
        Ok((_, path)) => path.starts_with(REMNAWAVE_INTERNAL_CONFIG_PATH),
        Err(_) => source.contains(REMNAWAVE_INTERNAL_CONFIG_PATH),
    }
}

/// Redacted Xray-style command line for logs (`rw-core -config ... -format json`).
pub fn format_redacted_run_command(
    program: &str,
    config_source: &str,
    format: Option<&str>,
) -> String {
    let mut parts = vec![
        program.to_string(),
        "-config".to_string(),
        redact_config_source(config_source),
    ];
    if let Some(format) = format {
        parts.push("-format".to_string());
        parts.push(format.to_string());
    }
    parts.join(" ")
}
pub async fn load_xray_config_from_source(source: &str) -> std::io::Result<XrayConfig> {
    let contents = if source.starts_with(HTTP_UNIX_SCHEME) {
        fetch_http_unix_config(source).await?
    } else {
        std::fs::read_to_string(source).map_err(|e| {
            std::io::Error::new(
                e.kind(),
                format!(
                    "failed to read config file {}: {e}",
                    redact_config_source(source)
                ),
            )
        })?
    };

    let config: XrayConfig = serde_json::from_str(&contents).map_err(|e| {
        std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            format!(
                "failed to parse config from {}: {e}",
                redact_config_source(source)
            ),
        )
    })?;
    validate_xray_panel_config(&config)?;
    Ok(config)
}

async fn fetch_http_unix_config(source: &str) -> std::io::Result<String> {
    let (socket_path, request_target) = parse_http_unix_source(source)?;
    startup_log::eprintln_bootstrap(format!(
        "http+unix config fetch: socket={} path={}",
        socket_path,
        redact_config_source(request_target)
    ));
    let mut stream = UnixStream::connect(socket_path).await.map_err(|e| {
        std::io::Error::new(
            e.kind(),
            format!(
                "failed to connect config unix socket {}: {e}",
                redact_config_source(source)
            ),
        )
    })?;
    let request = format!(
        "GET {request_target} HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\nAccept: application/json\r\n\r\n"
    );
    stream.write_all(request.as_bytes()).await?;

    let mut response = Vec::new();
    stream.read_to_end(&mut response).await?;
    decode_http_config_response(source, &response)
}

pub(crate) fn parse_http_unix_source(source: &str) -> std::io::Result<(&str, &str)> {
    let rest = source.strip_prefix(HTTP_UNIX_SCHEME).ok_or_else(|| {
        std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "config source is not http+unix",
        )
    })?;
    let sock_end = rest
        .find(".sock")
        .map(|idx| idx + ".sock".len())
        .ok_or_else(|| {
            std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                format!(
                    "invalid http+unix config source {}: missing .sock path",
                    redact_config_source(source)
                ),
            )
        })?;
    let socket_path = &rest[..sock_end];
    let request_target = &rest[sock_end..];
    let request_target = if request_target.is_empty() {
        "/"
    } else {
        request_target
    };
    if !request_target.starts_with('/') {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            format!(
                "invalid http+unix config source {}: request path must start with /",
                redact_config_source(source)
            ),
        ));
    }
    Ok((socket_path, request_target))
}

fn decode_http_config_response(source: &str, response: &[u8]) -> std::io::Result<String> {
    let header_end = response
        .windows(4)
        .position(|window| window == b"\r\n\r\n")
        .ok_or_else(|| {
            std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                format!(
                    "invalid config response from {}: missing HTTP headers",
                    redact_config_source(source)
                ),
            )
        })?;
    let headers = std::str::from_utf8(&response[..header_end]).map_err(|e| {
        std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            format!(
                "invalid config response headers from {}: {e}",
                redact_config_source(source)
            ),
        )
    })?;
    let mut lines = headers.lines();
    let status_line = lines.next().unwrap_or_default();
    if !status_line.contains(" 200 ") {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            format!(
                "config endpoint {} returned {status_line}",
                redact_config_source(source)
            ),
        ));
    }
    let chunked = lines.any(|line| {
        line.split_once(':')
            .map(|(name, value)| {
                name.eq_ignore_ascii_case("transfer-encoding")
                    && value.to_ascii_lowercase().contains("chunked")
            })
            .unwrap_or(false)
    });
    let body = &response[header_end + 4..];
    let body = if chunked {
        decode_chunked_body(source, body)?
    } else {
        body.to_vec()
    };
    let body = trim_http_body_by_content_length(headers, &body);
    String::from_utf8(body).map_err(|e| {
        std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            format!(
                "config endpoint {} returned non-UTF-8 body: {e}",
                redact_config_source(source)
            ),
        )
    })
}

fn trim_http_body_by_content_length(headers: &str, body: &[u8]) -> Vec<u8> {
    let content_length = headers.lines().skip(1).find_map(|line| {
        let (name, value) = line.split_once(':')?;
        name.trim()
            .eq_ignore_ascii_case("content-length")
            .then(|| value.trim().parse::<usize>().ok())?
    });
    if let Some(len) = content_length {
        body.get(..len.min(body.len())).unwrap_or(body).to_vec()
    } else {
        body.to_vec()
    }
}

fn decode_chunked_body(source: &str, mut body: &[u8]) -> std::io::Result<Vec<u8>> {
    let mut decoded = Vec::new();
    loop {
        let line_end = body
            .windows(2)
            .position(|window| window == b"\r\n")
            .ok_or_else(|| {
                std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    format!(
                        "invalid chunked config response from {}",
                        redact_config_source(source)
                    ),
                )
            })?;
        let size_line = std::str::from_utf8(&body[..line_end]).map_err(|e| {
            std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                format!("invalid chunk size: {e}"),
            )
        })?;
        let size_hex = size_line.split(';').next().unwrap_or("").trim();
        let size = usize::from_str_radix(size_hex, 16).map_err(|e| {
            std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                format!("invalid chunk size: {e}"),
            )
        })?;
        body = &body[line_end + 2..];
        if size == 0 {
            return Ok(decoded);
        }
        if body.len() < size + 2 || &body[size..size + 2] != b"\r\n" {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                format!(
                    "truncated chunked config response from {}",
                    redact_config_source(source)
                ),
            ));
        }
        decoded.extend_from_slice(&body[..size]);
        body = &body[size + 2..];
    }
}
