use tracing::{debug, warn};

use crate::protocol::structs::ClientHelloPayload;

pub struct RealityClientAuth {
    pub short_id: Vec<u8>,
    pub unix_time: u64,
}

/// Minimum TLS Session ID length used by REALITY clients (32-byte AES-GCM ciphertext).
const REALITY_SESSION_ID_LEN: usize = 32;

pub fn open_reality_session_id(
    hello: &ClientHelloPayload,
    raw_client_hello_payload: &[u8],
    auth_key: &[u8; 42],
) -> std::io::Result<Option<RealityClientAuth>> {
    let session_id = hello.session_id.as_bytes();

    if session_id.len() < REALITY_SESSION_ID_LEN {
        debug!(
            len = session_id.len(),
            "REALITY session_id open skipped: session_id too short"
        );
        return Ok(None);
    }

    let _ = (raw_client_hello_payload, auth_key, &hello.random.0);

    // TODO: Port AES-GCM open 1:1 from XTLS/REALITY `tls.go` (server path, ~lines 236–249):
    //
    //   block, _ := aes.NewCipher(authKey)          // AES-256 key from HKDF output
    //   aead, _ := cipher.NewGCM(block)
    //   aead.Open(plainText[:0], hello.random[20:32], sessionIdCiphertext, hello.original)
    //
    // Wire parameters (must match Go exactly before returning Some):
    //   - nonce  = ClientHello.random bytes [20..32]
    //   - aad    = raw ClientHello bytes (`hello.original` / `raw_client_hello_payload`)
    //   - input  = session_id ciphertext (32 bytes)
    //   - key    = HKDF-derived AuthKey (verify 32 vs 42 byte split against Go)
    //
    // Plaintext layout after successful open:
    //   [0..3]   client version (x.y.z)
    //   [4..7]   unix timestamp (big-endian u32)
    //   [8..15]  short_id (up to 8 bytes)
    //
    // Do not guess nonce, AAD, or key slicing here.

    warn!("REALITY session_id open not implemented yet");
    Ok(None)
}
