use std::env;
use std::path::PathBuf;
use std::sync::Arc;

use tokio::net::{TcpListener, TcpStream};
use tracing::{debug, error, info, warn};

use rust_xray::codec::{Codec, Reader};
use rust_xray::config::{
    first_reality_inbound_runtime, load_xray_config_from_file, RealityInboundRuntime, XrayConfig,
};
use rust_xray::protocol::structs::ClientHelloPayload;
use rust_xray::proxy::relay_fallback;
use rust_xray::reality::{
    handle_accepted_reality_client, inspect_reality_client_hello, RealityDecision,
    RealityInspectConfig,
};
use rust_xray::tls::read_client_hello_record;
use rust_xray::vless::{build_vless_clients, VlessClient};

struct RuntimeConfig {
    reality: RealityInboundRuntime,
    vless_clients: Vec<VlessClient>,
}

async fn relay_fallback_with_log(
    client: TcpStream,
    dest_addr: &str,
    initial_client_bytes: &[u8],
    reason: &str,
) -> std::io::Result<()> {
    debug!(reason, %dest_addr, "starting fallback relay");
    relay_fallback(client, dest_addr, initial_client_bytes)
        .await
        .map_err(|e| {
            error!(reason, error = %e, "fallback relay failed");
            std::io::Error::new(e.kind(), format!("fallback relay failed ({reason}): {e}"))
        })
}

async fn handle_client(mut stream: TcpStream, config: Arc<RuntimeConfig>) -> std::io::Result<()> {
    let peer = stream.peer_addr().ok();

    let record = read_client_hello_record(&mut stream).await.map_err(|e| {
        error!(?peer, error = %e, "failed to read ClientHello record");
        e
    })?;

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
            return relay_fallback_with_log(
                stream,
                &config.reality.dest_addr,
                &record.raw_record,
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
                &config.vless_clients,
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
            relay_fallback_with_log(
                stream,
                &config.reality.dest_addr,
                &record.raw_record,
                "REALITY fallback",
            )
            .await
        }
        Err(err) => {
            warn!(?peer, error = %err, "REALITY inspect failed");
            relay_fallback_with_log(
                stream,
                &config.reality.dest_addr,
                &record.raw_record,
                "REALITY inspect error",
            )
            .await
        }
    }
}

fn config_path_from_args() -> PathBuf {
    env::args()
        .nth(1)
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("./config.json"))
}

fn runtime_config_from_xray(xray: &XrayConfig) -> std::io::Result<RuntimeConfig> {
    let reality = first_reality_inbound_runtime(xray)?;
    let vless_clients = build_vless_clients(&reality.vless_clients)?;

    Ok(RuntimeConfig {
        reality,
        vless_clients,
    })
}

fn load_runtime_config(path: &PathBuf) -> std::io::Result<RuntimeConfig> {
    let xray = load_xray_config_from_file(path)?;
    let config = runtime_config_from_xray(&xray)?;

    if config.reality.protocol.as_deref() == Some("vless") {
        info!(tag = ?config.reality.tag, "using VLESS REALITY inbound");
    } else {
        warn!(
            tag = ?config.reality.tag,
            protocol = ?config.reality.protocol,
            "using REALITY inbound with non-vless protocol"
        );
    }

    if config.reality.show {
        info!("REALITY show mode enabled in config");
    }

    info!(
        listen = %config.reality.listen_addr,
        dest = %config.reality.dest_addr,
        server_names = ?config.reality.server_names,
        short_id_count = config.reality.short_ids.len(),
        max_time_diff = config.reality.max_time_diff,
        vless_client_count = config.vless_clients.len(),
        "loaded REALITY inbound settings"
    );

    Ok(config)
}

#[tokio::main]
async fn main() {
    tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
        .init();

    if let Err(err) = run().await {
        error!(error = %err, "server error");
        std::process::exit(1);
    }
}

async fn run() -> std::io::Result<()> {
    let config_path = config_path_from_args();
    info!(path = %config_path.display(), "loading Xray config");

    let config = load_runtime_config(&config_path)?;
    let listen_addr = config.reality.listen_addr.clone();
    let config = Arc::new(config);

    let listener = TcpListener::bind(&listen_addr).await?;
    info!(addr = %listen_addr, "REALITY listener started");

    loop {
        let (stream, peer) = match listener.accept().await {
            Ok(conn) => conn,
            Err(err) => {
                warn!(error = %err, "failed to accept TCP connection");
                continue;
            }
        };

        info!(%peer, "TCP client accepted");

        let config = Arc::clone(&config);
        tokio::spawn(async move {
            if let Err(err) = handle_client(stream, config).await {
                debug!(%peer, error = %err, "connection closed with error");
            }
        });
    }
}

#[cfg(test)]
mod tests {
    use super::*;

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
                    "privateKey": "test-private-key",
                    "shortIds": [""]
                }
            }
        }]
    }"#;

    #[test]
    fn runtime_config_from_xray_builds_vless_clients() {
        let xray: XrayConfig = serde_json::from_str(VLESS_REALITY_CONFIG).expect("parse config");
        let config = runtime_config_from_xray(&xray).expect("build runtime config");

        assert_eq!(config.vless_clients.len(), 1);
        assert_eq!(
            config.vless_clients[0].id,
            uuid::Uuid::parse_str("00000000-0000-0000-0000-000000000001").unwrap()
        );
        assert_eq!(config.reality.protocol.as_deref(), Some("vless"));
    }
}
