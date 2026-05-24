/// Placeholder entry point for future VLESS inbound handling.
pub async fn handle_vless_inbound<S>(stream: S) -> std::io::Result<()>
where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin,
{
    let _ = stream;

    Err(std::io::Error::new(
        std::io::ErrorKind::Unsupported,
        "VLESS inbound is not implemented yet",
    ))
}
