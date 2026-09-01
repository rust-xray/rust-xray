use std::sync::Arc;

use tokio::io::{AsyncRead, AsyncWrite};

use super::config::Mlkem768X25519PlusConfig;
use super::config::VlessDecryption;
use super::handshake::HandshakeError;
use super::io::PrefixStream;
use super::server::{HandshakeRng, OsHandshakeRng, VlessEncryptionServer};
use super::stream::VlessEncryptedStream;

/// Shared inbound VLESS encryption server instance (built once per inbound).
pub type SharedVlessEncryptionServer = Arc<VlessEncryptionServer>;

pub fn build_encryption_server(
    config: &Mlkem768X25519PlusConfig,
) -> Result<SharedVlessEncryptionServer, HandshakeError> {
    Ok(Arc::new(VlessEncryptionServer::from_config(
        config.clone(),
    )?))
}

pub fn build_encryption_server_from_decryption(
    decryption: &VlessDecryption,
) -> Result<Option<SharedVlessEncryptionServer>, HandshakeError> {
    match decryption {
        VlessDecryption::None => Ok(None),
        VlessDecryption::Mlkem768X25519Plus { config, .. } => {
            Ok(Some(build_encryption_server(config)?))
        }
    }
}

pub async fn handshake_and_wrap_with_rng<S, R>(
    server: &VlessEncryptionServer,
    stream: S,
    rng: &mut R,
) -> Result<VlessEncryptedStream<PrefixStream<S>>, HandshakeError>
where
    S: AsyncRead + AsyncWrite + Unpin,
    R: HandshakeRng,
{
    let (result, prefixed) = server.handshake(stream, rng).await?;
    Ok(VlessEncryptedStream::from_handshake(prefixed, result))
}

pub async fn handshake_and_wrap<S>(
    server: &VlessEncryptionServer,
    stream: S,
) -> Result<VlessEncryptedStream<PrefixStream<S>>, HandshakeError>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    handshake_and_wrap_with_rng(server, stream, &mut OsHandshakeRng).await
}

pub fn map_handshake_error(err: HandshakeError) -> std::io::Error {
    err.into()
}
