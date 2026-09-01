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
            testseed: crate::vless::UPSTREAM_DEFAULT_TESTSEED,
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
