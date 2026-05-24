use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

use super::decision::RealityAccepted;

const DEST_HANDSHAKE_READ_CAP: usize = 16 * 1024;

const PATCH_NOT_IMPLEMENTED_MSG: &str = "REALITY ServerHello patching is not implemented yet";

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RealityDestHandshake {
    pub raw_server_bytes: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PatchedRealityHandshake {
    pub raw_client_bytes: Vec<u8>,
}

/// Forwards the client ClientHello record to `dest` and reads the first response chunk.
pub async fn fetch_dest_handshake(
    dest: &mut TcpStream,
    client_hello_record: &[u8],
) -> std::io::Result<RealityDestHandshake> {
    dest.write_all(client_hello_record).await?;

    let mut raw_server_bytes = vec![0u8; DEST_HANDSHAKE_READ_CAP];
    let read_len = dest.read(&mut raw_server_bytes).await?;
    raw_server_bytes.truncate(read_len);

    Ok(RealityDestHandshake { raw_server_bytes })
}

/// Patches the destination TLS handshake for REALITY before sending it to the client.
pub fn patch_reality_server_hello(
    _dest_handshake: RealityDestHandshake,
    _accepted: &RealityAccepted,
) -> std::io::Result<PatchedRealityHandshake> {
    Err(std::io::Error::new(
        std::io::ErrorKind::Unsupported,
        PATCH_NOT_IMPLEMENTED_MSG,
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::reality::auth::RealityAuthResult;
    use crate::reality::decision::RealityAccepted;
    use crate::reality::session::RealityClientAuth;

    fn sample_accepted() -> RealityAccepted {
        RealityAccepted {
            auth: RealityAuthResult {
                auth_key: [0u8; 32],
                client_public_key: [0u8; 32],
            },
            client: RealityClientAuth {
                client_version: [1, 8, 0, 0],
                unix_time: 1_700_000_000,
                short_id: [0xAB, 0xCD, 0, 0, 0, 0, 0, 0],
            },
            sni: Some("example.com".to_string()),
        }
    }

    #[test]
    fn patch_reality_server_hello_returns_unsupported() {
        let dest_handshake = RealityDestHandshake {
            raw_server_bytes: vec![0x16, 0x03, 0x03, 0x00, 0x05, 0x02],
        };

        let err = patch_reality_server_hello(dest_handshake, &sample_accepted()).unwrap_err();

        assert_eq!(err.kind(), std::io::ErrorKind::Unsupported);
        assert_eq!(err.to_string(), PATCH_NOT_IMPLEMENTED_MSG);
    }
}
