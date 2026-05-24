use std::env;
use std::path::PathBuf;
use std::sync::Arc;

use tokio::net::{TcpListener, TcpStream};
use tracing::{debug, error, info, warn};

use rust_xray::codec::{Codec, Reader};
use rust_xray::config::{
    first_reality_inbound_runtime, load_xray_config_from_file, RealityInboundRuntime,
};
use rust_xray::protocol::structs::ClientHelloPayload;
use rust_xray::proxy::relay_fallback;
use rust_xray::reality::{
    handle_accepted_reality_client, inspect_reality_client_hello, RealityDecision,
    RealityInspectConfig,
};
use rust_xray::tls::read_client_hello_record;

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

async fn handle_client(
    mut stream: TcpStream,
    runtime: Arc<RealityInboundRuntime>,
) -> std::io::Result<()> {
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
                &runtime.dest_addr,
                &record.raw_record,
                "ClientHello parse error",
            )
            .await;
        }
    };

    let inspect_cfg = RealityInspectConfig {
        private_key: &runtime.private_key,
        server_names: &runtime.server_names,
        short_ids: &runtime.short_ids,
        max_time_diff_ms: runtime.max_time_diff,
        min_client_ver: runtime.min_client_ver.as_deref(),
        max_client_ver: runtime.max_client_ver.as_deref(),
        now_unix_ms: None,
    };

    match inspect_reality_client_hello(&ch, &record.handshake_message, inspect_cfg) {
        Ok(RealityDecision::Accepted(accepted)) => {
            // Accepted REALITY clients must not be sent to fallback relay.
            if let Err(err) =
                handle_accepted_reality_client(stream, record, accepted, &runtime.dest_addr).await
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
                &runtime.dest_addr,
                &record.raw_record,
                "REALITY fallback",
            )
            .await
        }
        Err(err) => {
            warn!(?peer, error = %err, "REALITY inspect failed");
            relay_fallback_with_log(
                stream,
                &runtime.dest_addr,
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

fn load_runtime_config(path: &PathBuf) -> std::io::Result<RealityInboundRuntime> {
    let xray = load_xray_config_from_file(path)?;
    let runtime = first_reality_inbound_runtime(&xray)?;

    if runtime.protocol.as_deref() == Some("vless") {
        info!(tag = ?runtime.tag, "using VLESS REALITY inbound");
    } else {
        warn!(
            tag = ?runtime.tag,
            protocol = ?runtime.protocol,
            "using REALITY inbound with non-vless protocol"
        );
    }

    if runtime.show {
        info!("REALITY show mode enabled in config");
    }

    info!(
        listen = %runtime.listen_addr,
        dest = %runtime.dest_addr,
        server_names = ?runtime.server_names,
        short_id_count = runtime.short_ids.len(),
        max_time_diff = runtime.max_time_diff,
        "loaded REALITY inbound settings"
    );

    Ok(runtime)
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

    let runtime = load_runtime_config(&config_path)?;
    let listen_addr = runtime.listen_addr.clone();
    let runtime = Arc::new(runtime);

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

        let runtime = Arc::clone(&runtime);
        tokio::spawn(async move {
            if let Err(err) = handle_client(stream, runtime).await {
                debug!(%peer, error = %err, "connection closed with error");
            }
        });
    }
}
