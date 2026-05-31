use std::io;

use tokio::io::{AsyncRead, AsyncWrite};
use tracing::info;

use crate::config::normalized::XHttpRuntimeConfig;
use crate::xhttp::transport::serve_xhttp_stream_one;

use super::VlessHandler;

pub async fn run_xhttp_transport<S>(
    stream: S,
    config: XHttpRuntimeConfig,
    handler: &VlessHandler,
) -> io::Result<()>
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    ensure_xhttp_users_supported(handler.users())?;

    info!(
        kind = "xhttp",
        inbound_tag = handler.inbound_tag(),
        path = %config.path,
        mode = %config.mode,
        "transport bridge started"
    );

    let settings = config.to_settings();
    let result =
        serve_xhttp_stream_one(stream, &settings, handler.users_arc(), handler.stats()).await;

    if result.is_ok() {
        info!(
            kind = "xhttp",
            inbound_tag = handler.inbound_tag(),
            "transport bridge completed"
        );
    }

    result
}

fn ensure_xhttp_users_supported(users: &crate::vless::VlessUserManager) -> io::Result<()> {
    if users
        .list_managed_users()
        .iter()
        .any(|user| user.flow.as_deref() == Some("xtls-rprx-vision"))
    {
        return Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "flow=xtls-rprx-vision over XHTTP is not supported in the stream-one MVP",
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::vless::config::VlessClient;
    use crate::vless::VlessUserManager;
    use uuid::Uuid;

    #[test]
    fn rejects_vision_flow_before_serving_xhttp() {
        let users = VlessUserManager::new(
            "xhttp-test",
            vec![VlessClient {
                id: Uuid::nil(),
                email: None,
                flow: Some("xtls-rprx-vision".to_string()),
                level: None,
            }],
        );
        let err = ensure_xhttp_users_supported(&users).unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::Unsupported);
        assert!(err.to_string().contains("flow=xtls-rprx-vision over XHTTP"));
    }

    #[tokio::test]
    async fn xhttp_transport_reads_http_preface_not_vless() {
        use tokio::io::AsyncWriteExt;

        let (client, server) = tokio::io::duplex(256);
        let handler = VlessHandler::new(
            std::sync::Arc::new(VlessUserManager::new("xhttp-test", Vec::new())),
            None,
            None,
        );

        let client_task = tokio::spawn(async move {
            let mut client = client;
            client.write_all(b"\x00").await.unwrap();
        });

        let config = XHttpRuntimeConfig {
            path: "/xhttp".to_string(),
            host: None,
            mode: "stream-one".to_string(),
        };
        let err = run_xhttp_transport(server, config, &handler)
            .await
            .unwrap_err();
        assert!(
            err.to_string().contains("XHTTP")
                || err.to_string().contains("HTTP")
                || err.to_string().contains("preface")
                || err.to_string().contains("header"),
            "{err}"
        );
        client_task.await.unwrap();
    }
}
