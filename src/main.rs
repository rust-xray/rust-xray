#[macro_use]
mod macros;
mod base;
mod codec;
mod config;
mod enums;
mod errors;
mod fallback;
mod rand;
mod reality;
mod structs;
mod tls_record;

/// Re-exports the contents of the [rustls-pki-types](https://docs.rs/rustls-pki-types) crate for easy access
pub mod pki_types {
    pub use rustls_pki_types::*;
}

use std::env;
use std::path::PathBuf;
use std::sync::Arc;

use tokio::net::{TcpListener, TcpStream};
use tracing::{debug, error, info, warn};

use crate::codec::{Codec, Reader};
use crate::config::{
    find_reality_inbounds, get_inbound_reality_settings, inbound_listen_addr,
    load_xray_config_from_file, reality_dest_addr, reality_private_key, reality_short_ids,
};
use crate::fallback::relay_fallback;
use crate::reality::{inspect_reality_client_hello, RealityAuthResult, RealityDecision};
use crate::structs::ClientHelloPayload;
use crate::tls_record::{read_client_hello_record, TlsClientHelloRecord};

#[derive(Clone)]
struct RuntimeConfig {
    dest_addr: String,
    private_key: String,
    server_names: Vec<String>,
    short_ids: Vec<Vec<u8>>,
    max_time_diff: u64,
    show: bool,
}

async fn handle_valid_reality_client(
    _client: TcpStream,
    _record: TlsClientHelloRecord,
    _auth: RealityAuthResult,
) -> std::io::Result<()> {
    info!("valid REALITY candidate accepted");
    // Stub: ServerHello patching and full REALITY handshake are not implemented yet.
    Ok(())
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

async fn handle_client(mut stream: TcpStream, runtime: Arc<RuntimeConfig>) -> std::io::Result<()> {
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

    match inspect_reality_client_hello(&ch, &record.handshake_payload, &runtime.private_key) {
        Ok(RealityDecision::Accepted(auth)) => {
            handle_valid_reality_client(stream, record, auth).await
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

fn load_runtime_config(path: &PathBuf) -> std::io::Result<(String, RuntimeConfig)> {
    let xray = load_xray_config_from_file(path)?;
    let inbounds = find_reality_inbounds(&xray);
    let inbound = inbounds.first().ok_or_else(|| {
        std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "no inbound with streamSettings.security == \"reality\" found",
        )
    })?;

    if inbound.protocol.as_deref() == Some("vless") {
        info!(tag = ?inbound.tag, "using VLESS REALITY inbound");
    } else {
        warn!(
            tag = ?inbound.tag,
            protocol = ?inbound.protocol,
            "using REALITY inbound with non-vless protocol"
        );
    }

    let settings = get_inbound_reality_settings(inbound).ok_or_else(|| {
        std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "reality inbound is missing realitySettings",
        )
    })?;

    let listen_addr = inbound_listen_addr(inbound)?;
    let dest_addr = reality_dest_addr(settings)?;
    let private_key = reality_private_key(settings)?.to_owned();
    let short_ids = reality_short_ids(settings)?;

    if settings.show {
        info!("REALITY show mode enabled in config");
    }

    info!(
        listen = %listen_addr,
        dest = %dest_addr,
        server_names = ?settings.server_names,
        short_id_count = short_ids.len(),
        max_time_diff = settings.max_time_diff,
        "loaded REALITY inbound settings"
    );

    Ok((
        listen_addr,
        RuntimeConfig {
            dest_addr,
            private_key,
            server_names: settings.server_names.clone(),
            short_ids,
            max_time_diff: settings.max_time_diff,
            show: settings.show,
        },
    ))
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

    let (listen_addr, runtime) = load_runtime_config(&config_path)?;
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
