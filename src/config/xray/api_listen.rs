//! Xray Commander API listen address parsing and binding.

use std::net::SocketAddr;
use std::path::Path;

use tokio::net::TcpListener;
use tracing::info;

/// How `api.listen` is interpreted.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ApiListenKind {
    /// `listen == ""` — internal Commander outbound, no network listener.
    InternalCommander,
    /// TCP `host:port` (default when listen does not start with `/` or `@`).
    Tcp,
    /// Filesystem Unix domain socket (`listen` starts with `/`).
    #[cfg(unix)]
    UnixPath,
    /// Linux abstract Unix socket (`listen` starts with `@`).
    #[cfg(all(unix, target_os = "linux"))]
    UnixAbstract,
}

pub fn api_listen_kind(listen: Option<&str>) -> ApiListenKind {
    let listen = listen.map(str::trim).unwrap_or("");
    if listen.is_empty() {
        return ApiListenKind::InternalCommander;
    }
    if listen.starts_with('/') {
        return ApiListenKind::UnixPath;
    }
    if listen.starts_with('@') {
        #[cfg(all(unix, target_os = "linux"))]
        return ApiListenKind::UnixAbstract;
        #[cfg(not(all(unix, target_os = "linux")))]
        return ApiListenKind::Tcp;
    }
    ApiListenKind::Tcp
}

pub fn is_internal_commander_listen(listen: Option<&str>) -> bool {
    matches!(api_listen_kind(listen), ApiListenKind::InternalCommander)
}

/// Parse TCP `api.listen` (`net.ResolveTCPAddr("tcp", listen)` parity).
pub fn parse_api_tcp_listen_addr(listen: &str) -> std::io::Result<SocketAddr> {
    let listen = listen.trim();
    if listen.is_empty() {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "api.listen must not be empty for TCP listen mode",
        ));
    }
    listen.parse().map_err(|err| {
        std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            format!("invalid api.listen TCP address {listen}: {err}"),
        )
    })
}

/// Bound API listener for direct-listen Commander mode.
pub enum BoundApiListener {
    Tcp(TcpListener, SocketAddr),
    #[cfg(unix)]
    Unix(tokio::net::UnixListener, String),
}

impl BoundApiListener {
    pub fn log_label(&self) -> String {
        match self {
            Self::Tcp(_, addr) => addr.to_string(),
            #[cfg(unix)]
            Self::Unix(_, path) => path.clone(),
        }
    }
}

/// Bind direct-listen API address (TCP, filesystem Unix, or Linux abstract Unix).
pub async fn bind_api_listen(listen: &str) -> std::io::Result<BoundApiListener> {
    let listen = listen.trim();
    match api_listen_kind(Some(listen)) {
        ApiListenKind::InternalCommander => Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "internal Commander mode does not bind a network listener",
        )),
        ApiListenKind::Tcp => {
            let socket_addr = parse_api_tcp_listen_addr(listen)?;
            let listener = TcpListener::bind(socket_addr).await.map_err(|err| {
                std::io::Error::new(
                    err.kind(),
                    format!(
                        "failed to bind Xray API listener on {socket_addr} (api.listen={listen}): {err}"
                    ),
                )
            })?;
            let bound = listener.local_addr()?;
            info!(api_bind_addr = %bound, "Xray API TCP listener bound");
            Ok(BoundApiListener::Tcp(listener, bound))
        }
        #[cfg(unix)]
        ApiListenKind::UnixPath => bind_unix_path(listen).await,
        #[cfg(all(unix, target_os = "linux"))]
        ApiListenKind::UnixAbstract => bind_linux_abstract(listen).await,
    }
}

#[cfg(unix)]
async fn bind_unix_path(path: &str) -> std::io::Result<BoundApiListener> {
    let path = path.trim();
    if path.is_empty() {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "unix api.listen path must not be empty",
        ));
    }
    if Path::new(path).exists() {
        let _ = std::fs::remove_file(path);
    }
    if let Some(parent) = Path::new(path).parent() {
        if !parent.as_os_str().is_empty() {
            std::fs::create_dir_all(parent).map_err(|err| {
                std::io::Error::new(
                    err.kind(),
                    format!("failed to create parent dir for unix api.listen {path}: {err}"),
                )
            })?;
        }
    }
    let listener = tokio::net::UnixListener::bind(path).map_err(|err| {
        std::io::Error::new(
            err.kind(),
            format!("failed to bind unix api.listen {path}: {err}"),
        )
    })?;
    info!(api_unix_path = %path, "Xray API Unix listener bound");
    Ok(BoundApiListener::Unix(listener, path.to_string()))
}

#[cfg(all(unix, target_os = "linux"))]
async fn bind_linux_abstract(name: &str) -> std::io::Result<BoundApiListener> {
    use std::os::unix::io::FromRawFd;

    let name = name.trim();
    if !name.starts_with('@') || name.len() <= 1 {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "abstract unix api.listen must start with @ followed by a name",
        ));
    }
    let abstract_name = &name[1..];

    let fd = unsafe { libc::socket(libc::AF_UNIX, libc::SOCK_STREAM, 0) };
    if fd < 0 {
        return Err(std::io::Error::last_os_error());
    }

    let mut addr: libc::sockaddr_un = unsafe { std::mem::zeroed() };
    addr.sun_family = libc::AF_UNIX as libc::sa_family_t;
    let path_len = abstract_name
        .len()
        .min(addr.sun_path.len().saturating_sub(1));
    addr.sun_path[0] = 0;
    for (idx, byte) in abstract_name.as_bytes().iter().take(path_len).enumerate() {
        addr.sun_path[idx + 1] = *byte as libc::c_char;
    }

    let bind_len = std::mem::offset_of!(libc::sockaddr_un, sun_path) + 1 + path_len;
    let bind_result =
        unsafe { libc::bind(fd, (&raw const addr).cast(), bind_len as libc::socklen_t) };
    if bind_result != 0 {
        let err = std::io::Error::last_os_error();
        unsafe { libc::close(fd) };
        return Err(std::io::Error::new(
            err.kind(),
            format!("failed to bind abstract unix api.listen {name}: {err}"),
        ));
    }
    if unsafe { libc::listen(fd, 128) } != 0 {
        let err = std::io::Error::last_os_error();
        unsafe { libc::close(fd) };
        return Err(err);
    }

    let std_listener = unsafe { std::os::unix::net::UnixListener::from_raw_fd(fd) };
    std_listener.set_nonblocking(true)?;
    let listener = tokio::net::UnixListener::from_std(std_listener)?;
    info!(api_abstract_unix = %name, "Xray API abstract Unix listener bound");
    Ok(BoundApiListener::Unix(listener, name.to_string()))
}

/// Legacy helper retained for existing call sites (TCP-only).
pub fn parse_api_grpc_listen_addr(listen: &str) -> std::io::Result<SocketAddr> {
    parse_api_tcp_listen_addr(listen)
}

/// Legacy TCP-only bind helper.
pub async fn bind_api_listener(listen: &str) -> std::io::Result<(TcpListener, SocketAddr)> {
    match bind_api_listen(listen).await? {
        BoundApiListener::Tcp(listener, addr) => Ok((listener, addr)),
        #[cfg(unix)]
        _ => Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "bind_api_listener requires a TCP api.listen address",
        )),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn api_listen_kind_internal_when_empty() {
        assert_eq!(api_listen_kind(Some("")), ApiListenKind::InternalCommander);
        assert_eq!(api_listen_kind(None), ApiListenKind::InternalCommander);
    }

    #[test]
    fn parse_tcp_listen_accepts_ipv4_and_bracket_ipv6() {
        assert!(parse_api_tcp_listen_addr("127.0.0.1:8080").is_ok());
        assert!(parse_api_tcp_listen_addr("0.0.0.0:8080").is_ok());
        assert!(parse_api_tcp_listen_addr("[::1]:8080").is_ok());
    }

    #[tokio::test]
    async fn bind_tcp_listen_on_ephemeral_port() {
        let bound = bind_api_listen("127.0.0.1:0").await.expect("bind");
        match bound {
            BoundApiListener::Tcp(listener, addr) => {
                assert!(addr.ip().is_loopback());
                assert_ne!(addr.port(), 0);
                drop(listener);
            }
            #[cfg(unix)]
            _ => panic!("expected tcp"),
        }
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn bind_filesystem_unix_listen() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("api.sock");
        let path_str = path.to_str().expect("utf8").to_string();
        let bound = bind_api_listen(&path_str).await.expect("bind unix");
        match bound {
            BoundApiListener::Unix(_listener, bound_path) => assert_eq!(bound_path, path_str),
            _ => panic!("expected unix"),
        }
        assert!(path.exists());
    }
}
