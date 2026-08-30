//! Canonical Xray Unix-socket HTTP config fetch (`@abstract:/path`, `/sock:/path`).

use std::path::Path;

#[cfg(unix)]
use std::os::unix::fs::FileTypeExt;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::UnixStream;

use crate::startup_log;

use super::load::{decode_http_config_response, redact_config_source};

/// Split Xray canonical Unix HTTP target into `(socket_spec, request_path)`.
///
/// Examples:
/// - `@xtls-api-abc:/internal/get-config?token=...`
/// - `/run/sock.sock:/api`
pub fn split_unix_http_target(target: &str) -> std::io::Result<(String, String)> {
    let target = target.trim();
    if target.is_empty() {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "unix http config target is empty",
        ));
    }

    if let Some(idx) = target.find(":/") {
        let socket_spec = target[..idx].to_string();
        let request_path = target[idx + 1..].to_string();
        if request_path.is_empty() || !request_path.starts_with('/') {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                format!(
                    "invalid unix http config target {}: request path must start with /",
                    redact_config_source(target)
                ),
            ));
        }
        return Ok((socket_spec, request_path));
    }

    if target.starts_with('@') || Path::new(target).exists() {
        return Ok((target.to_string(), "/".to_string()));
    }

    Err(std::io::Error::new(
        std::io::ErrorKind::InvalidInput,
        format!(
            "invalid unix http config target {}: expected ':/' separator or existing socket path",
            redact_config_source(target)
        ),
    ))
}

pub fn is_canonical_unix_http_config_source(source: &str) -> bool {
    let source = source.trim();
    if source.starts_with('@') {
        return true;
    }
    if !source.starts_with('/') {
        return false;
    }
    source.contains(":/") || {
        #[cfg(unix)]
        {
            std::fs::metadata(source)
                .ok()
                .is_some_and(|meta| meta.file_type().is_socket())
        }
        #[cfg(not(unix))]
        {
            false
        }
    }
}

pub fn is_remnawave_internal_config_path(path: &str) -> bool {
    path.starts_with("/internal/get-config")
}

pub async fn fetch_unix_http_config(source: &str) -> std::io::Result<String> {
    let (socket_spec, request_path) = split_unix_http_target(source)?;
    startup_log::eprintln_bootstrap(format!(
        "unix-http config fetch: socket={} path={}",
        socket_spec,
        redact_config_source(&request_path)
    ));

    let mut stream = connect_unix_socket(&socket_spec).await.map_err(|err| {
        std::io::Error::new(
            err.kind(),
            format!(
                "failed to connect config unix socket {}: {err}",
                redact_config_source(source)
            ),
        )
    })?;

    let request = format!(
        "GET {request_path} HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\nAccept: application/json\r\n\r\n"
    );
    stream.write_all(request.as_bytes()).await?;
    let mut response = Vec::new();
    stream.read_to_end(&mut response).await?;
    decode_http_config_response(source, &response)
}

pub async fn connect_unix_socket(socket_spec: &str) -> std::io::Result<UnixStream> {
    let socket_spec = socket_spec.trim();
    if socket_spec.starts_with('@') {
        #[cfg(all(unix, target_os = "linux"))]
        {
            return connect_linux_abstract(&socket_spec[1..]).await;
        }
        #[cfg(not(all(unix, target_os = "linux")))]
        {
            let _ = socket_spec;
            return Err(std::io::Error::new(
                std::io::ErrorKind::Unsupported,
                "linux abstract unix sockets are unsupported on this platform",
            ));
        }
    }

    UnixStream::connect(socket_spec).await
}

#[cfg(all(unix, target_os = "linux"))]
pub(crate) async fn connect_linux_abstract(name: &str) -> std::io::Result<UnixStream> {
    use std::os::unix::io::FromRawFd;

    let fd = unsafe { libc::socket(libc::AF_UNIX, libc::SOCK_STREAM, 0) };
    if fd < 0 {
        return Err(std::io::Error::last_os_error());
    }

    let mut addr: libc::sockaddr_un = unsafe { std::mem::zeroed() };
    addr.sun_family = libc::AF_UNIX as libc::sa_family_t;
    let path_len = name.len().min(addr.sun_path.len().saturating_sub(1));
    addr.sun_path[0] = 0;
    for (idx, byte) in name.as_bytes().iter().take(path_len).enumerate() {
        addr.sun_path[idx + 1] = *byte as libc::c_char;
    }

    let addr_len = std::mem::offset_of!(libc::sockaddr_un, sun_path) + 1 + path_len;
    let connect_result =
        unsafe { libc::connect(fd, (&raw const addr).cast(), addr_len as libc::socklen_t) };
    if connect_result != 0 {
        let err = std::io::Error::last_os_error();
        unsafe { libc::close(fd) };
        return Err(err);
    }

    let std_stream = unsafe { std::os::unix::net::UnixStream::from_raw_fd(fd) };
    std_stream.set_nonblocking(true)?;
    UnixStream::from_std(std_stream)
}
