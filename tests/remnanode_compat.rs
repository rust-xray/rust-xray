//! RemnaNode 3.3.2 tunnel API compatibility tests (config + Linux abstract E2E).

use rust_xray::config::{
    api_dokodemo_inbound_tag, config_source_kind, is_canonical_unix_http_config_source,
    is_internal_commander_listen, normalize_config, validate_xray_panel_config, ApiListenSource,
    NormalizedInbound, XrayConfig,
};

const REMNA_332_TUNNEL_FIXTURE: &str =
    include_str!("fixtures/remna/remnawave_node_332_tunnel_api.json");

#[test]
fn remnawave_node_332_tunnel_fixture_parses_and_validates() {
    let config: XrayConfig = serde_json::from_str(REMNA_332_TUNNEL_FIXTURE).expect("parse fixture");
    validate_xray_panel_config(&config).expect("panel validation");

    let api = config.api.as_ref().expect("api");
    assert_eq!(api.tag, "REMNAWAVE_API");
    assert!(is_internal_commander_listen(api.listen.as_deref()));
    assert_eq!(
        api_dokodemo_inbound_tag(&config).as_deref(),
        Some("REMNAWAVE_API_INBOUND")
    );

    let normalized = normalize_config(&config).expect("normalize");
    assert_eq!(
        normalized.api.as_ref().unwrap().listen_source,
        ApiListenSource::InternalCommander
    );

    let api_inbounds: Vec<_> = normalized
        .inbounds
        .iter()
        .filter_map(|inbound| match inbound {
            NormalizedInbound::Api(api) => Some(api),
            _ => None,
        })
        .collect();
    assert_eq!(api_inbounds.len(), 1);
    assert_eq!(api_inbounds[0].protocol, "tunnel");
    assert_eq!(api_inbounds[0].listen_addr, "@xtls-api-fixture");
}

#[test]
fn canonical_unix_http_config_source_detection() {
    assert_eq!(
        config_source_kind("@sock:/internal/get-config?token=abc"),
        "unix-http"
    );
    assert!(is_canonical_unix_http_config_source(
        "@rwint-abc:/internal/get-config?token=secret"
    ));
}

#[cfg(all(unix, target_os = "linux"))]
mod linux_tunnel_e2e {
    use super::*;
    use rust_xray::api::proto::app::stats::command::stats_service_client::StatsServiceClient;
    use rust_xray::api::proto::app::stats::command::SysStatsRequest;
    use rust_xray::api::server::{
        parse_enabled_services, serve_grpc_incoming, start_configured_api_server, ApiTransportMode,
    };
    use rust_xray::config::load_xray_config_from_source;
    use rust_xray::routing::route_context_from_tunnel;
    use rust_xray::runtime::HandlerRuntime;
    use rust_xray::stats::StatsRegistry;
    use rust_xray::tunnel::start_tunnel_inbound;
    use std::sync::Arc;
    use std::time::Duration;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::time::sleep;
    use tonic::Code;

    async fn connect_tonic_linux_abstract(name: &str) -> tonic::transport::Channel {
        use std::os::unix::io::FromRawFd;
        use tokio::net::UnixStream;

        let abstract_name = name.trim_start_matches('@').to_string();
        let endpoint = tonic::transport::Endpoint::try_from("http://[::]:50051")
            .expect("endpoint")
            .connect_with_connector(tower::service_fn(move |_| {
                let abstract_name = abstract_name.clone();
                async move {
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
                    let addr_len = std::mem::offset_of!(libc::sockaddr_un, sun_path) + 1 + path_len;
                    let connect_result = unsafe {
                        libc::connect(fd, (&raw const addr).cast(), addr_len as libc::socklen_t)
                    };
                    if connect_result != 0 {
                        let err = std::io::Error::last_os_error();
                        unsafe { libc::close(fd) };
                        return Err(err);
                    }
                    let std_stream = unsafe { std::os::unix::net::UnixStream::from_raw_fd(fd) };
                    std_stream.set_nonblocking(true)?;
                    UnixStream::from_std(std_stream)
                }
            }))
            .await
            .expect("connect abstract unix");
        endpoint
    }

    fn remna_332_config() -> XrayConfig {
        serde_json::from_str(REMNA_332_TUNNEL_FIXTURE).expect("parse")
    }

    #[tokio::test]
    async fn tunnel_route_context_selects_remna_api_outbound() {
        let config = remna_332_config();
        let registry = Arc::new(StatsRegistry::new());
        let runtime = HandlerRuntime::new(
            Arc::new(config),
            Arc::clone(&registry),
            Some("REMNAWAVE_API_INBOUND".to_string()),
            false,
        )
        .expect("runtime");

        let decision = runtime
            .router
            .pick_route_with_default(route_context_from_tunnel("REMNAWAVE_API_INBOUND"))
            .await
            .expect("route");
        assert_eq!(decision.outbound_tag, "REMNAWAVE_API");
        assert!(
            !decision.rule_tag.is_empty()
                || decision.context.inbound_tag == "REMNAWAVE_API_INBOUND",
            "expected routing rule match for REMNAWAVE_API_INBOUND"
        );
    }

    #[tokio::test]
    async fn tunnel_inbound_does_not_inject_commander_when_routed_to_direct() {
        let mut config = remna_332_config();
        config.routing.as_mut().expect("routing").rules[0].outbound_tag =
            Some("direct".to_string());

        let registry = Arc::new(StatsRegistry::new());
        let runtime = HandlerRuntime::new(
            Arc::new(config.clone()),
            Arc::clone(&registry),
            Some("REMNAWAVE_API_INBOUND".to_string()),
            false,
        )
        .expect("runtime");
        let xray = Arc::new(config);

        let startup = start_configured_api_server("", &xray, Arc::clone(&runtime), registry)
            .await
            .expect("start api")
            .expect("api startup");
        let commander = runtime
            .outbound
            .commander_listener()
            .expect("commander listener");
        assert_eq!(commander.queued_len(), 0);

        let socket_name = format!("@rust-xray-remna-route-b-{}", std::process::id());
        let api_inbound = rust_xray::config::ApiInbound {
            tag: Some("REMNAWAVE_API_INBOUND".to_string()),
            listen_addr: socket_name.clone(),
            protocol: "tunnel".to_string(),
        };
        let _tunnel = start_tunnel_inbound(api_inbound, Arc::clone(&runtime.router))
            .await
            .expect("tunnel inbound");

        sleep(Duration::from_millis(50)).await;

        let channel = connect_tonic_linux_abstract(&socket_name).await;
        let mut client = StatsServiceClient::new(channel);
        let err = client
            .get_sys_stats(SysStatsRequest {})
            .await
            .expect_err("direct route must not reach Commander gRPC");
        assert_ne!(err.code(), Code::Ok);
        assert_eq!(
            commander.queued_len(),
            0,
            "tunnel must not push to Commander when RuntimeRouter selects direct"
        );

        startup.task.abort();
    }

    #[tokio::test]
    async fn unix_http_config_loader_fetches_abstract_json() {
        let socket_name = format!("@rust-xray-unix-cfg-{}", std::process::id());
        let bound = rust_xray::config::bind_api_listen(&socket_name)
            .await
            .expect("bind abstract config server");
        let rust_xray::config::BoundApiListener::Unix(listener, _) = bound else {
            panic!("expected unix listener");
        };

        let config_json = r#"{"inbounds":[],"outbounds":[{"tag":"direct","protocol":"freedom"}]}"#;
        let body = config_json.as_bytes();
        let response = format!(
            "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
            body.len()
        );
        tokio::spawn(async move {
            if let Ok((mut stream, _)) = listener.accept().await {
                let mut buf = Vec::new();
                let _ = stream.read_to_end(&mut buf).await;
                let _ = stream.write_all(response.as_bytes()).await;
                let _ = stream.write_all(body).await;
                let _ = stream.shutdown().await;
            }
        });

        let source = format!("{socket_name}:/internal/get-config?token=test");
        let loaded = load_xray_config_from_source(&source)
            .await
            .expect("load from abstract unix http");
        assert_eq!(loaded.outbounds.len(), 1);
        assert_eq!(loaded.outbounds[0].tag.as_deref(), Some("direct"));
    }

    #[tokio::test]
    async fn tunnel_inbound_get_sys_stats_over_abstract_unix() {
        let config = remna_332_config();
        let registry = Arc::new(StatsRegistry::new());
        let runtime = HandlerRuntime::for_handler_tests(Arc::clone(&registry));
        let xray = Arc::new(config);

        let startup = start_configured_api_server("", &xray, Arc::clone(&runtime), registry)
            .await
            .expect("start api")
            .expect("api startup");

        let socket_name = format!("@rust-xray-remna-tunnel-{}", std::process::id());
        let api_inbound = rust_xray::config::ApiInbound {
            tag: Some("REMNAWAVE_API_INBOUND".to_string()),
            listen_addr: socket_name.clone(),
            protocol: "tunnel".to_string(),
        };
        let _tunnel = start_tunnel_inbound(api_inbound, Arc::clone(&runtime.router))
            .await
            .expect("tunnel inbound");

        sleep(Duration::from_millis(50)).await;

        let channel = connect_tonic_linux_abstract(&socket_name).await;
        let mut client = StatsServiceClient::new(channel);
        client
            .get_sys_stats(SysStatsRequest {})
            .await
            .expect("GetSysStats via tunnel -> commander");

        startup.task.abort();
    }

    #[tokio::test]
    async fn tunnel_inbound_persistent_grpc_channel_multiple_rpc() {
        let config = remna_332_config();
        let registry = Arc::new(StatsRegistry::new());
        let runtime = HandlerRuntime::for_handler_tests(Arc::clone(&registry));
        let xray = Arc::new(config);

        let api = xray.api.as_ref().unwrap();
        let enabled = parse_enabled_services(&api.services).expect("services");
        let (listener, incoming) = rust_xray::runtime::CommanderOutboundListener::pair();
        runtime
            .outbound
            .install_commander_outbound(&api.tag, Arc::clone(&listener))
            .expect("commander");
        let _api_task = tokio::spawn(serve_grpc_incoming(
            incoming,
            enabled,
            registry,
            Arc::clone(&runtime),
            ApiTransportMode::Plaintext,
        ));

        let socket_name = format!("@rust-xray-remna-persist-{}", std::process::id());
        let api_inbound = rust_xray::config::ApiInbound {
            tag: Some("REMNAWAVE_API_INBOUND".to_string()),
            listen_addr: socket_name.clone(),
            protocol: "tunnel".to_string(),
        };
        let _tunnel = start_tunnel_inbound(api_inbound, Arc::clone(&runtime.router))
            .await
            .expect("tunnel");

        sleep(Duration::from_millis(50)).await;
        let channel = connect_tonic_linux_abstract(&socket_name).await;
        let mut client = StatsServiceClient::new(channel);
        for _ in 0..3 {
            client
                .get_sys_stats(SysStatsRequest {})
                .await
                .expect("sequential GetSysStats");
        }
    }
}
