use std::sync::Arc;

use crate::api;
use crate::cli::{self, Command, RunOptions};
use tokio::io::AsyncReadExt;
use tokio::net::{TcpListener, TcpStream};
use tracing::{debug, error, info, warn};

use crate::codec::{Codec, Reader};
use crate::config::{
    api_dokodemo_inbound_tag, config_source_kind, format_redacted_run_command,
    load_xray_config_from_source, reality_inbound_runtimes, reality_mldsa65_runtime_mode,
    redact_config_source, resolve_api_listen, RealityInboundRuntime, RealityMldsa65RuntimeMode,
    XrayConfig,
};
use crate::protocol::structs::ClientHelloPayload;
use crate::proxy::relay_fallback_with_xver;
use crate::reality::{
    handle_accepted_reality_client, inspect_reality_client_hello, RealityDecision,
    RealityInspectConfig,
};
use crate::runtime::InboundUserManagers;
use crate::stats::{StatsRegistry, StatsState};
use crate::tls::{read_client_hello_record, PrefixedStream, TlsClientHelloRecord};
use crate::vless::{
    build_fallback_context, build_vless_clients, fallback_match_kind_label,
    looks_like_http_request, resolve_fallback_selection, VlessUserManager,
};

const TLS_CONTENT_TYPE_HANDSHAKE: u8 = 0x16;
const NON_TLS_PREAMBLE_READ_LIMIT: usize = 4096;

struct InboundListenerConfig {
    reality: RealityInboundRuntime,
    user_manager: Arc<VlessUserManager>,
    stats: Option<Arc<StatsState>>,
}

struct ServerRuntimeConfig {
    inbounds: Vec<InboundListenerConfig>,
    inbound_users: Arc<InboundUserManagers>,
}

enum InboundPreamble {
    Tls {
        stream: TcpStream,
        record: TlsClientHelloRecord,
    },
    RawFallback {
        stream: TcpStream,
        initial_bytes: Vec<u8>,
    },
}

async fn relay_vless_fallback_with_log(
    client: TcpStream,
    config: &InboundListenerConfig,
    initial_client_bytes: &[u8],
    hello: Option<&ClientHelloPayload>,
    reason: &str,
) -> std::io::Result<()> {
    let stats = config
        .stats
        .as_ref()
        .and_then(|state| state.session(None, None));
    let ctx = build_fallback_context(hello, initial_client_bytes);
    let selection = resolve_fallback_selection(
        &config.reality.vless_fallbacks,
        &config.reality.dest_addr,
        &ctx,
    )?;
    let dest_addr = selection.dest;
    let xver = selection.xver;

    info!(
        reason,
        fallback_count = config.reality.vless_fallbacks.len(),
        selected_reason = fallback_match_kind_label(selection.kind),
        used_configured_fallback = selection.used_configured_fallback,
        %dest_addr,
        xver,
        sni = ?ctx.sni,
        alpn = ?ctx.alpn,
        alpn_offers = ?ctx.alpn_offers,
        matched_alpn = ?selection.matched_alpn,
        http_path = ?ctx.http_path,
        initial_bytes = initial_client_bytes.len(),
        "VLESS fallback target selected"
    );

    relay_fallback_with_xver(
        client,
        &dest_addr,
        initial_client_bytes,
        xver,
        stats.as_ref(),
    )
    .await
    .map_err(|e| {
        error!(reason, %dest_addr, xver, error = %e, "fallback relay failed");
        std::io::Error::new(e.kind(), format!("fallback relay failed ({reason}): {e}"))
    })
}

async fn read_inbound_preamble(mut stream: TcpStream) -> std::io::Result<InboundPreamble> {
    let mut first = [0u8; 1];
    stream.read_exact(&mut first).await?;

    if first[0] == TLS_CONTENT_TYPE_HANDSHAKE {
        let mut prefixed = PrefixedStream::new(stream, first.to_vec());
        let record = read_client_hello_record(&mut prefixed).await?;
        stream = prefixed.into_inner();
        return Ok(InboundPreamble::Tls { stream, record });
    }

    let mut initial_bytes = first.to_vec();
    let mut chunk = [0u8; NON_TLS_PREAMBLE_READ_LIMIT - 1];
    let read = stream.read(&mut chunk).await?;
    initial_bytes.extend_from_slice(&chunk[..read]);

    if looks_like_http_request(&initial_bytes) {
        return Ok(InboundPreamble::RawFallback {
            stream,
            initial_bytes,
        });
    }

    Err(std::io::Error::new(
        std::io::ErrorKind::InvalidData,
        "inbound preamble is neither TLS ClientHello nor HTTP/1.x request",
    ))
}

async fn handle_client(
    stream: TcpStream,
    config: Arc<InboundListenerConfig>,
) -> std::io::Result<()> {
    let peer = stream.peer_addr().ok();

    match read_inbound_preamble(stream).await {
        Ok(InboundPreamble::RawFallback {
            stream,
            initial_bytes,
        }) => {
            debug!(
                ?peer,
                initial_bytes = initial_bytes.len(),
                "non-TLS inbound routed to VLESS fallback"
            );
            return relay_vless_fallback_with_log(
                stream,
                &config,
                &initial_bytes,
                None,
                "non-TLS inbound fallback",
            )
            .await;
        }
        Ok(InboundPreamble::Tls { stream, record }) => {
            handle_tls_client(stream, config, record, peer).await
        }
        Err(err) => {
            error!(?peer, error = %err, "failed to read inbound preamble");
            Err(err)
        }
    }
}

async fn handle_tls_client(
    stream: TcpStream,
    config: Arc<InboundListenerConfig>,
    record: TlsClientHelloRecord,
    peer: Option<std::net::SocketAddr>,
) -> std::io::Result<()> {
    debug!(
        ?peer,
        raw_record_len = record.raw_record.len(),
        handshake_payload_len = record.handshake_payload.len(),
        "ClientHello record read ok"
    );

    let mut rd = Reader::init(&record.handshake_payload);

    let ch = match ClientHelloPayload::read(&mut rd) {
        Ok(ch) => ch,
        Err(err) => {
            warn!(?peer, error = ?err, "ClientHello parse failed");
            return relay_vless_fallback_with_log(
                stream,
                &config,
                record.initial_client_bytes(),
                None,
                "ClientHello parse error",
            )
            .await;
        }
    };

    let inspect_cfg = RealityInspectConfig {
        private_key: &config.reality.private_key,
        server_names: &config.reality.server_names,
        short_ids: &config.reality.short_ids,
        max_time_diff_ms: config.reality.max_time_diff,
        min_client_ver: config.reality.min_client_ver.as_deref(),
        max_client_ver: config.reality.max_client_ver.as_deref(),
        now_unix_ms: None,
    };

    match inspect_reality_client_hello(&ch, &record.handshake_message, inspect_cfg) {
        Ok(RealityDecision::Accepted(accepted)) => {
            // Accepted REALITY clients must not be sent to fallback relay.
            if let Err(err) = handle_accepted_reality_client(
                stream,
                record,
                ch,
                accepted,
                &config.reality.dest_addr,
                &config.user_manager,
                config.reality.mldsa65_seed.as_ref(),
                config.stats.as_deref(),
            )
            .await
            {
                warn!(?peer, error = %err, "REALITY accepted path failed");
                return Err(err);
            }
            Ok(())
        }
        Ok(RealityDecision::Fallback) => {
            debug!(?peer, "REALITY inspect returned fallback");
            relay_vless_fallback_with_log(
                stream,
                &config,
                record.initial_client_bytes(),
                Some(&ch),
                "REALITY fallback",
            )
            .await
        }
        Err(err) => {
            warn!(?peer, error = %err, "REALITY inspect failed");
            relay_vless_fallback_with_log(
                stream,
                &config,
                record.initial_client_bytes(),
                Some(&ch),
                "REALITY inspect error",
            )
            .await
        }
    }
}

fn validate_reality_runtime_feature_gates(config: &InboundListenerConfig) -> std::io::Result<()> {
    match reality_mldsa65_runtime_mode(&config.reality) {
        RealityMldsa65RuntimeMode::Disabled => Ok(()),
        RealityMldsa65RuntimeMode::Enabled => Ok(()),
    }
}

#[cfg(test)]
fn runtime_config_from_xray(xray: &XrayConfig) -> std::io::Result<InboundListenerConfig> {
    load_runtime_config(xray, Arc::new(StatsRegistry::new()))?
        .inbounds
        .into_iter()
        .next()
        .ok_or_else(|| {
            std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "no supported VLESS TCP REALITY inbound found",
            )
        })
}

fn load_runtime_config(
    xray: &XrayConfig,
    stats_registry: Arc<StatsRegistry>,
) -> std::io::Result<ServerRuntimeConfig> {
    let runtimes = reality_inbound_runtimes(xray)?;
    let inbound_users = Arc::new(InboundUserManagers::new());
    let stats_enabled = StatsState::from_xray_config(xray, None).enabled();
    let mut inbounds = Vec::with_capacity(runtimes.len());

    for reality in runtimes {
        let inbound_tag = reality
            .tag
            .clone()
            .filter(|tag| !tag.is_empty())
            .unwrap_or_else(|| "reality-in".to_string());
        let vless_clients = build_vless_clients(&reality.vless_clients)?;
        let user_manager = Arc::new(VlessUserManager::new(inbound_tag.clone(), vless_clients));
        for tag in &reality.merged_inbound_tags {
            inbound_users.register_tag(tag, Arc::clone(&user_manager));
        }
        if reality.merged_inbound_tags.is_empty() {
            inbound_users.register(Arc::clone(&user_manager));
        }
        let stats = if stats_enabled {
            Some(Arc::new(StatsState::from_xray_config_with_registry(
                xray,
                Arc::clone(&stats_registry),
                inbound_tag.clone(),
            )))
        } else {
            None
        };
        let listener_config = InboundListenerConfig {
            reality,
            user_manager,
            stats,
        };
        validate_reality_runtime_feature_gates(&listener_config)?;

        if listener_config.reality.protocol.as_deref() == Some("vless") {
            info!(tag = ?listener_config.reality.tag, "using VLESS REALITY inbound");
        } else {
            warn!(
                tag = ?listener_config.reality.tag,
                protocol = ?listener_config.reality.protocol,
                "using REALITY inbound with non-vless protocol"
            );
        }

        if listener_config.reality.show {
            info!("REALITY show mode enabled in config");
        }

        info!(
            listen = %listener_config.reality.listen_addr,
            dest = %listener_config.reality.dest_addr,
            server_names = ?listener_config.reality.server_names,
            short_id_count = listener_config.reality.short_ids.len(),
            max_time_diff = listener_config.reality.max_time_diff,
            vless_client_count = listener_config.user_manager.user_count(),
            vless_flow_distribution = %listener_config.user_manager.flow_distribution_log_label(),
            merged_inbound_tags = ?listener_config.reality.merged_inbound_tags,
            vless_fallback_count = listener_config.reality.vless_fallbacks.len(),
            "loaded REALITY inbound settings"
        );

        for (index, fallback) in listener_config.reality.vless_fallbacks.iter().enumerate() {
            info!(
                index,
                name = fallback.name.as_deref().unwrap_or(""),
                alpn = fallback.alpn.as_deref().unwrap_or(""),
                path = fallback.path.as_deref().unwrap_or(""),
                dest = %fallback.dest.addr,
                xver = fallback.xver,
                "VLESS fallback entry"
            );
        }

        inbounds.push(listener_config);
    }

    Ok(ServerRuntimeConfig {
        inbounds,
        inbound_users,
    })
}

fn init_tracing(command: &Command) {
    let default_level = match command {
        Command::Version => "warn",
        _ => "info",
    };
    let filter = tracing_subscriber::EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new(default_level));
    tracing_subscriber::fmt().with_env_filter(filter).init();
}

fn stage_error(stage: &str, err: std::io::Error) -> std::io::Error {
    crate::startup_log::eprintln_stage(stage, &err);
    std::io::Error::new(err.kind(), format!("{stage}: {err}"))
}

pub async fn main_entry() -> std::io::Result<()> {
    let raw_args: Vec<String> = std::env::args().collect();

    let command = match cli::parse_args(raw_args.iter().map(|s| s.as_str())) {
        Ok(command) => command,
        Err(err) => {
            if !matches!(raw_args.get(1).map(String::as_str), Some("version")) {
                crate::startup_log::eprintln_bootstrap("main_entry start");
                crate::startup_log::eprintln_bootstrap(format!(
                    "argv: {}",
                    crate::startup_log::redact_argv(&raw_args)
                ));
            }
            crate::startup_log::eprintln_fatal_message(err.to_string());
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                err.to_string(),
            ));
        }
    };

    if let Command::Run(ref opts) = command {
        crate::startup_log::log_server_bootstrap(&raw_args, opts);
    }

    init_tracing(&command);
    dispatch(command).await
}

async fn dispatch(command: Command) -> std::io::Result<()> {
    match command {
        Command::Version => {
            cli::print_version();
            Ok(())
        }
        Command::Api(api) => api::execute(api).await.map_err(|err| {
            stage_error("api command failed", std::io::Error::other(err.to_string()))
        }),
        Command::Run(opts) => run_server(opts).await,
    }
}

async fn start_xray_api_server(
    config_source: &str,
    xray: &XrayConfig,
    inbound_users: Arc<InboundUserManagers>,
    stats_registry: Arc<StatsRegistry>,
) -> std::io::Result<tokio::task::JoinHandle<std::io::Result<()>>> {
    let Some(api) = xray.api.as_ref() else {
        info!("Xray API disabled (no api block in config)");
        return Ok(tokio::spawn(async { Ok(()) }));
    };

    info!(api_tag = %api.tag, api_services = ?api.services, "Xray API starting");

    let resolved = resolve_api_listen(xray)
        .map_err(|err| stage_error("failed to resolve API listener", err))?;
    let Some((listen, listen_source, dokodemo_tag)) = resolved else {
        let err = std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            format!(
                "API services configured for tag {:?} but no api.listen and no routed dokodemo-door API inbound was found",
                api.tag
            ),
        );
        return Err(stage_error("failed to resolve API listener", err));
    };

    crate::startup_log::eprintln_api_listen_resolved(
        &listen,
        listen_source.as_log_label(),
        dokodemo_tag.as_deref(),
        api.tag.as_str(),
    );
    info!(
        api_listen = %listen,
        api_listen_source = listen_source.as_log_label(),
        dokodemo_inbound_tag = ?dokodemo_tag,
        "detected Xray API listener address"
    );

    if let Some(tag) = dokodemo_tag.as_deref() {
        info!(
            inbound_tag = %tag,
            api_listen = %listen,
            "skipping normal inbound startup for API dokodemo-door inbound (API gRPC owns this listen/port)"
        );
        crate::startup_log::eprintln_bootstrap(format!(
            "skipped inbound tag {tag} (API gRPC owns {listen})"
        ));
    }

    let selection = api::server::resolve_api_transport_mode(api::server::ApiTransportContext {
        config_source,
        api_listen: Some(&listen),
        xray: Some(xray),
    })
    .map_err(|err| stage_error("failed to configure API transport", err))?;
    api::server::log_api_transport_selected(&selection);
    let transport = selection.mode;
    info!(api_transport = transport.as_log_label(), "Xray API mode");

    let enabled = api::server::parse_enabled_services(&api.services)
        .map_err(|err| stage_error("failed to parse API services", err))?;

    let (listener, bound_addr) = api::server::bind_api_listener(&listen)
        .await
        .map_err(|err| stage_error("failed to bind Xray API", err))?;
    info!(bind_addr = %bound_addr, "Xray API bind OK");

    api::server::log_api_listener_ready(&listen, bound_addr, &api.services, &transport);
    crate::startup_log::eprintln_api_listening(&listen, transport.as_log_label());

    let api_task = tokio::spawn(async move {
        api::server::serve_grpc_on(listener, enabled, stats_registry, inbound_users, transport)
            .await
    });

    Ok(api_task)
}

async fn run_server(opts: RunOptions) -> std::io::Result<()> {
    let program = std::env::args()
        .next()
        .unwrap_or_else(|| "rw-core".to_string());
    let config_source = opts.config.clone();
    let source_kind = config_source_kind(&config_source);

    info!(
        command_line = %format_redacted_run_command(&program, &config_source, opts.format.as_deref()),
        config_source_kind = source_kind,
        "rust-xray starting"
    );
    if let Some(format) = opts.format.as_deref() {
        info!(format = %format, "Xray config format");
    }

    info!(
        source = %redact_config_source(&config_source),
        config_source_kind = source_kind,
        "loading Xray config"
    );
    let xray = load_xray_config_from_source(&config_source)
        .await
        .map_err(|err| stage_error("failed to load config source", err))?;
    crate::startup_log::eprintln_bootstrap("config load success");
    info!(
        source = %redact_config_source(&config_source),
        config_source_kind = source_kind,
        inbound_count = xray.inbounds.len(),
        outbound_count = xray.outbounds.len(),
        has_api = xray.api.is_some(),
        "config loaded OK"
    );
    if let Some(api) = xray.api.as_ref() {
        info!(api_tag = %api.tag, api_services = ?api.services, "api block present");
        if let Ok(Some((listen, source, tag))) = resolve_api_listen(&xray) {
            crate::startup_log::eprintln_api_listen_resolved(
                &listen,
                source.as_log_label(),
                tag.as_deref(),
                api.tag.as_str(),
            );
            info!(
                api_listen = %listen,
                api_listen_source = source.as_log_label(),
                dokodemo_inbound_tag = ?tag,
                "API listener resolved from config"
            );
        }
    }

    let inbound_users = Arc::new(InboundUserManagers::new());
    let stats_state = StatsState::from_xray_config(&xray, api_dokodemo_inbound_tag(&xray));
    let stats_registry = Arc::clone(&stats_state.registry);

    let mut api_task = start_xray_api_server(
        &config_source,
        &xray,
        Arc::clone(&inbound_users),
        Arc::clone(&stats_registry),
    )
    .await?;

    info!("loading REALITY runtime");
    let server_config = load_runtime_config(&xray, stats_registry)
        .map_err(|err| stage_error("failed to load REALITY runtime", err))?;
    if server_config.inbounds.is_empty() {
        return Err(stage_error(
            "failed to load REALITY runtime",
            std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "no supported VLESS TCP REALITY inbound found",
            ),
        ));
    }
    crate::startup_log::eprintln_bootstrap(format!(
        "REALITY runtime loaded OK listener_count={}",
        server_config.inbounds.len()
    ));
    for inbound in &server_config.inbounds {
        info!(
            listen = %inbound.reality.listen_addr,
            tag = ?inbound.reality.tag,
            "REALITY runtime loaded OK"
        );
    }

    for inbound in &server_config.inbounds {
        inbound_users.register(Arc::clone(&inbound.user_manager));
        for tag in &inbound.reality.merged_inbound_tags {
            inbound_users.register_tag(tag, Arc::clone(&inbound.user_manager));
        }
    }

    for inbound in &server_config.inbounds {
        let listen_addr = inbound.reality.listen_addr.clone();
        let inbound_tag = inbound
            .reality
            .tag
            .clone()
            .unwrap_or_else(|| "reality-in".to_string());
        let config = Arc::new(InboundListenerConfig {
            reality: inbound.reality.clone(),
            user_manager: Arc::clone(&inbound.user_manager),
            stats: inbound.stats.clone(),
        });

        info!(addr = %listen_addr, inbound_tag = %inbound_tag, "REALITY inbound starting");
        let listener = TcpListener::bind(&listen_addr)
            .await
            .map_err(|err| stage_error("failed to bind inbound", err))?;
        crate::startup_log::eprintln_bootstrap(format!(
            "REALITY listener started addr={listen_addr} tag={inbound_tag}"
        ));
        info!(addr = %listen_addr, inbound_tag = %inbound_tag, "REALITY listener started");

        tokio::spawn(async move {
            loop {
                match listener.accept().await {
                    Ok((stream, peer)) => {
                        info!(%peer, "REALITY TCP client accepted");
                        let config = Arc::clone(&config);
                        tokio::spawn(async move {
                            if let Err(err) = handle_client(stream, config).await {
                                debug!(%peer, error = %err, "connection closed with error");
                            }
                        });
                    }
                    Err(err) => {
                        warn!(error = %err, addr = %listen_addr, "failed to accept REALITY TCP connection");
                    }
                }
            }
        });
    }

    loop {
        tokio::select! {
            api_result = &mut api_task => {
                match api_result {
                    Ok(Ok(())) => {
                        crate::startup_log::eprintln_bootstrap(
                            "critical task exited: api server returned",
                        );
                        error!("Xray API server task exited unexpectedly");
                    }
                    Ok(Err(err)) => {
                        crate::startup_log::eprintln_bootstrap(format!(
                            "critical task exited: api server error: {err}"
                        ));
                        error!(error = %err, "Xray API server task failed");
                        return Err(err);
                    }
                    Err(join_err) => {
                        crate::startup_log::eprintln_bootstrap(format!(
                            "critical task exited: api server join error: {join_err}"
                        ));
                        error!(error = %join_err, "Xray API server task join failed");
                        return Err(std::io::Error::other(join_err));
                    }
                }
                break;
            }
            _ = wait_shutdown_signal() => {
                info!("rust-xray shutting down after signal");
                crate::startup_log::eprintln_bootstrap("rust-xray shutting down after signal");
                api_task.abort();
                break;
            }
        }
    }

    crate::startup_log::eprintln_bootstrap("run_server returning");
    info!("rust-xray run_server exiting");
    Ok(())
}

async fn wait_shutdown_signal() {
    #[cfg(unix)]
    {
        use tokio::signal::unix::{signal, SignalKind};
        let mut sigterm = signal(SignalKind::terminate()).expect("install SIGTERM handler");
        let mut sigint = signal(SignalKind::interrupt()).expect("install SIGINT handler");
        tokio::select! {
            _ = tokio::signal::ctrl_c() => {}
            _ = sigterm.recv() => {}
            _ = sigint.recv() => {}
        }
    }
    #[cfg(not(unix))]
    {
        let _ = tokio::signal::ctrl_c().await;
    }
    info!("rust-xray received shutdown signal");
    crate::startup_log::eprintln_bootstrap("rust-xray received shutdown signal");
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::vless::{build_fallback_context, resolve_fallback_selection, FallbackContext};

    const VLESS_REALITY_CONFIG: &str = r#"{
        "inbounds": [{
            "tag": "reality-in",
            "listen": "127.0.0.1",
            "port": 443,
            "protocol": "vless",
            "settings": {
                "clients": [{"id": "00000000-0000-0000-0000-000000000001"}],
                "decryption": "none"
            },
            "streamSettings": {
                "network": "tcp",
                "security": "reality",
                "realitySettings": {
                    "show": false,
                    "dest": "www.example.com:443",
                    "serverNames": ["www.example.com"],
                    "privateKey": "CMZoLYnNxeaUoLn7LwK4RzBIdpzBXI5TOIlZ3tEfOn4",
                    "shortIds": [""]
                }
            }
        }]
    }"#;

    const TEST_MLDSA65_SEED: &str = "AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8";

    fn vless_reality_config_with_mldsa65_seed(seed: &str) -> String {
        VLESS_REALITY_CONFIG.replace(
            r#""shortIds": [""]"#,
            &format!(r#""shortIds": [""], "mldsa65Seed": "{seed}""#),
        )
    }

    #[test]
    fn runtime_config_from_xray_builds_vless_clients() {
        let xray: XrayConfig = serde_json::from_str(VLESS_REALITY_CONFIG).expect("parse config");
        let config = runtime_config_from_xray(&xray).expect("build runtime config");

        assert_eq!(config.user_manager.user_count(), 1);
        assert!(config
            .user_manager
            .contains_id(uuid::Uuid::parse_str("00000000-0000-0000-0000-000000000001").unwrap()));
        assert_eq!(config.reality.protocol.as_deref(), Some("vless"));
        assert!(config.reality.vless_fallbacks.is_empty());
    }

    #[test]
    fn runtime_gate_without_seed_is_ok() {
        let xray: XrayConfig = serde_json::from_str(VLESS_REALITY_CONFIG).expect("parse config");
        let config = runtime_config_from_xray(&xray).expect("build runtime config");

        assert!(config.reality.mldsa65_seed.is_none());
        validate_reality_runtime_feature_gates(&config).expect("gate allows absent seed");
    }

    #[test]
    fn mldsa65_runtime_mode_without_seed_is_disabled() {
        let xray: XrayConfig = serde_json::from_str(VLESS_REALITY_CONFIG).expect("parse config");
        let config = runtime_config_from_xray(&xray).expect("build runtime config");

        assert!(config.reality.mldsa65_seed.is_none());
        assert_eq!(
            reality_mldsa65_runtime_mode(&config.reality),
            RealityMldsa65RuntimeMode::Disabled
        );
        validate_reality_runtime_feature_gates(&config).expect("absent mldsa65Seed is unchanged");
    }

    #[test]
    fn runtime_gate_with_valid_mldsa65_seed_is_ok() {
        let json = vless_reality_config_with_mldsa65_seed(TEST_MLDSA65_SEED);
        let xray: XrayConfig = serde_json::from_str(&json).expect("parse config");
        let config = runtime_config_from_xray(&xray).expect("build runtime config");

        assert!(config.reality.mldsa65_seed.is_some());
        assert_eq!(
            reality_mldsa65_runtime_mode(&config.reality),
            RealityMldsa65RuntimeMode::Enabled
        );

        validate_reality_runtime_feature_gates(&config).expect("valid seed runtime gate");
    }

    #[test]
    fn invalid_mldsa65_seed_still_fails_before_runtime_gate() {
        let json = vless_reality_config_with_mldsa65_seed("not-valid-base64!!!");
        let xray: XrayConfig = serde_json::from_str(&json).expect("parse config");
        let err = match runtime_config_from_xray(&xray) {
            Ok(_) => panic!("invalid mldsa65Seed should fail before runtime feature gate"),
            Err(err) => err,
        };

        assert_eq!(err.kind(), std::io::ErrorKind::InvalidInput);
        assert!(err.to_string().contains("invalid mldsa65Seed base64"));
    }

    fn runtime_with_fallbacks() -> InboundListenerConfig {
        runtime_with_fallbacks_json("")
    }

    fn runtime_with_fallbacks_and_mldsa65_seed() -> InboundListenerConfig {
        runtime_with_fallbacks_json(&format!(r#","mldsa65Seed":"{TEST_MLDSA65_SEED}""#))
    }

    fn runtime_with_fallbacks_json(reality_extra: &str) -> InboundListenerConfig {
        let json = r#"{
            "inbounds": [{
                "tag": "reality-in",
                "listen": "127.0.0.1",
                "port": 443,
                "protocol": "vless",
                "settings": {
                    "clients": [{"id": "00000000-0000-0000-0000-000000000001"}],
                    "decryption": "none",
                    "fallbacks": [
                        {"dest": 19501},
                        {"name": "name-fallback.test", "dest": 19502},
                        {"path": "/smoke-path", "dest": 19503},
                        {"alpn": "http/1.1", "dest": 19505},
                        {"alpn": "h2", "dest": 19506},
                        {"name": "proxy-fallback.test", "dest": 19504, "xver": 1},
                        {"name": "proxy-v2-fallback.test", "dest": 19507, "xver": 2}
                    ]
                },
                "streamSettings": {
                    "network": "tcp",
                    "security": "reality",
                    "realitySettings": {
                        "show": false,
                        "dest": "www.example.com:443",
                        "serverNames": ["www.example.com"],
                        "privateKey": "CMZoLYnNxeaUoLn7LwK4RzBIdpzBXI5TOIlZ3tEfOn4",
                        "shortIds": [""]__REALITY_EXTRA__
                    }
                }
            }]
        }"#
        .replace("__REALITY_EXTRA__", reality_extra);
        let xray: XrayConfig = serde_json::from_str(&json).expect("parse config");
        runtime_config_from_xray(&xray).expect("build runtime config")
    }

    fn runtime_selection(config: &InboundListenerConfig, ctx: &FallbackContext) -> (String, u8) {
        let selection = resolve_fallback_selection(
            &config.reality.vless_fallbacks,
            &config.reality.dest_addr,
            ctx,
        )
        .expect("resolve fallback");
        (selection.dest, selection.xver)
    }

    #[test]
    fn runtime_resolves_default_fallback_over_reality_dest() {
        let config = runtime_with_fallbacks();

        assert_eq!(
            runtime_selection(&config, &FallbackContext::default()),
            ("127.0.0.1:19501".to_string(), 0)
        );
    }

    #[test]
    fn runtime_resolves_fallback_by_sni_name() {
        let config = runtime_with_fallbacks();
        let ctx = FallbackContext {
            sni: Some("name-fallback.test".to_string()),
            ..FallbackContext::default()
        };

        assert_eq!(
            runtime_selection(&config, &ctx),
            ("127.0.0.1:19502".to_string(), 0)
        );
    }

    #[test]
    fn runtime_resolves_fallback_by_alpn_http11() {
        let config = runtime_with_fallbacks();
        let ctx = FallbackContext {
            alpn: Some("http/1.1".to_string()),
            alpn_offers: vec!["http/1.1".to_string()],
            ..FallbackContext::default()
        };

        assert_eq!(
            runtime_selection(&config, &ctx),
            ("127.0.0.1:19505".to_string(), 0)
        );
    }

    #[test]
    fn runtime_resolves_fallback_by_alpn_h2() {
        let config = runtime_with_fallbacks();
        let ctx = FallbackContext {
            alpn: Some("http/1.1".to_string()),
            alpn_offers: vec!["http/1.1".to_string(), "h2".to_string()],
            ..FallbackContext::default()
        };

        assert_eq!(
            runtime_selection(&config, &ctx),
            ("127.0.0.1:19506".to_string(), 0)
        );
    }

    #[test]
    fn runtime_resolves_fallback_by_plain_http_path() {
        let config = runtime_with_fallbacks();
        let ctx = build_fallback_context(
            None,
            b"GET /smoke-path/resource HTTP/1.1\r\nHost: smoke.local\r\n\r\n",
        );

        assert_eq!(
            runtime_selection(&config, &ctx),
            ("127.0.0.1:19503".to_string(), 0)
        );
    }

    #[test]
    fn runtime_resolves_fallback_xver_values() {
        let config = runtime_with_fallbacks();
        let proxy_v1 = FallbackContext {
            sni: Some("proxy-fallback.test".to_string()),
            ..FallbackContext::default()
        };
        let proxy_v2 = FallbackContext {
            sni: Some("proxy-v2-fallback.test".to_string()),
            ..FallbackContext::default()
        };

        assert_eq!(
            runtime_selection(&config, &proxy_v1),
            ("127.0.0.1:19504".to_string(), 1)
        );
        assert_eq!(
            runtime_selection(&config, &proxy_v2),
            ("127.0.0.1:19507".to_string(), 2)
        );
    }

    #[test]
    fn runtime_fallback_selection_with_mldsa65_seed_stays_on_fallback_targets() {
        let config = runtime_with_fallbacks_and_mldsa65_seed();
        assert!(config.reality.mldsa65_seed.is_some());

        let path_ctx = build_fallback_context(
            None,
            b"GET /smoke-path/resource HTTP/1.1\r\nHost: smoke.local\r\n\r\n",
        );
        let h2_ctx = FallbackContext {
            alpn: Some("http/1.1".to_string()),
            alpn_offers: vec!["http/1.1".to_string(), "h2".to_string()],
            ..FallbackContext::default()
        };
        let proxy_v1_ctx = FallbackContext {
            sni: Some("proxy-fallback.test".to_string()),
            ..FallbackContext::default()
        };
        let proxy_v2_ctx = FallbackContext {
            sni: Some("proxy-v2-fallback.test".to_string()),
            ..FallbackContext::default()
        };

        assert_eq!(
            runtime_selection(&config, &FallbackContext::default()),
            ("127.0.0.1:19501".to_string(), 0)
        );
        assert_eq!(
            runtime_selection(&config, &path_ctx),
            ("127.0.0.1:19503".to_string(), 0)
        );
        assert_eq!(
            runtime_selection(&config, &h2_ctx),
            ("127.0.0.1:19506".to_string(), 0)
        );
        assert_eq!(
            runtime_selection(&config, &proxy_v1_ctx),
            ("127.0.0.1:19504".to_string(), 1)
        );
        assert_eq!(
            runtime_selection(&config, &proxy_v2_ctx),
            ("127.0.0.1:19507".to_string(), 2)
        );
    }
}
