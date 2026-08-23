use std::io::{Error, ErrorKind, Result};

pub const HANDSHAKE_TYPE_SERVER_HELLO: u8 = 0x02;
pub const HANDSHAKE_TYPE_ENCRYPTED_EXTENSIONS: u8 = 0x08;
pub const HANDSHAKE_TYPE_CERTIFICATE: u8 = 0x0b;
pub const HANDSHAKE_TYPE_CERTIFICATE_VERIFY: u8 = 0x0f;
pub const HANDSHAKE_TYPE_FINISHED: u8 = 0x14;
pub const HANDSHAKE_TYPE_KEY_UPDATE: u8 = 0x18;

pub const KEY_UPDATE_NOT_REQUESTED: u8 = 0x00;
pub const KEY_UPDATE_REQUESTED: u8 = 0x01;

const MAX_HANDSHAKE_BODY_LEN: usize = 0x00ff_ffff;
const MAX_SESSION_ID_ECHO_LEN: usize = 32;

pub const EXT_SUPPORTED_VERSIONS: u16 = 43;
pub const EXT_KEY_SHARE: u16 = 51;
pub const TLS_VERSION_1_2_LEGACY: [u8; 2] = [0x03, 0x03];
pub const TLS_VERSION_1_3: [u8; 2] = [0x03, 0x04];

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Tls13ServerHelloParams {
    pub random: [u8; 32],
    pub session_id_echo: Vec<u8>,
    pub cipher_suite: u16,
    pub key_share_extension_body: Vec<u8>,
}

pub fn build_handshake_message(handshake_type: u8, body: &[u8]) -> Result<Vec<u8>> {
    if body.len() > MAX_HANDSHAKE_BODY_LEN {
        return Err(Error::new(
            ErrorKind::InvalidInput,
            format!(
                "TLS 1.3 handshake body too long: {} bytes (max {MAX_HANDSHAKE_BODY_LEN})",
                body.len()
            ),
        ));
    }

    let body_len = u32::try_from(body.len()).expect("body length fits in u32 after max check");

    let mut message = Vec::with_capacity(1 + 3 + body.len());
    message.push(handshake_type);
    message.extend_from_slice(&body_len.to_be_bytes()[1..]);
    message.extend_from_slice(body);
    Ok(message)
}

pub fn build_key_update_message(request_update: u8) -> Result<Vec<u8>> {
    if request_update != KEY_UPDATE_NOT_REQUESTED && request_update != KEY_UPDATE_REQUESTED {
        return Err(Error::new(
            ErrorKind::InvalidInput,
            format!("TLS 1.3 KeyUpdate request_update must be 0 or 1, got {request_update}"),
        ));
    }

    build_handshake_message(HANDSHAKE_TYPE_KEY_UPDATE, &[request_update])
}

pub fn parse_key_update_handshake(message: &[u8]) -> Result<u8> {
    if message.first() != Some(&HANDSHAKE_TYPE_KEY_UPDATE) {
        return Err(Error::new(
            ErrorKind::InvalidData,
            "TLS 1.3 KeyUpdate handshake must start with type 0x18",
        ));
    }

    if message.len() != 5 {
        return Err(Error::new(
            ErrorKind::InvalidData,
            format!(
                "TLS 1.3 KeyUpdate handshake must be 5 bytes, got {}",
                message.len()
            ),
        ));
    }

    let body_len = u32::from_be_bytes([0, message[1], message[2], message[3]]) as usize;
    if body_len != 1 {
        return Err(Error::new(
            ErrorKind::InvalidData,
            format!("TLS 1.3 KeyUpdate handshake body must be 1 byte, got {body_len}"),
        ));
    }

    let request_update = message[4];
    if request_update != KEY_UPDATE_NOT_REQUESTED && request_update != KEY_UPDATE_REQUESTED {
        return Err(Error::new(
            ErrorKind::InvalidData,
            format!("TLS 1.3 KeyUpdate request_update must be 0 or 1, got {request_update}"),
        ));
    }

    Ok(request_update)
}

fn invalid_input(message: impl Into<String>) -> Error {
    Error::new(ErrorKind::InvalidInput, message.into())
}

fn encode_extension(extension_type: u16, data: &[u8]) -> Result<Vec<u8>> {
    if data.len() > u16::MAX as usize {
        return Err(invalid_input(format!(
            "TLS 1.3 extension data too long: {} bytes (max {})",
            data.len(),
            u16::MAX
        )));
    }

    let data_len =
        u16::try_from(data.len()).expect("extension data length fits in u16 after validation");

    let mut extension = Vec::with_capacity(4 + data.len());
    extension.extend_from_slice(&extension_type.to_be_bytes());
    extension.extend_from_slice(&data_len.to_be_bytes());
    extension.extend_from_slice(data);
    Ok(extension)
}

pub fn build_tls13_server_hello(params: &Tls13ServerHelloParams) -> Result<Vec<u8>> {
    if params.session_id_echo.len() > MAX_SESSION_ID_ECHO_LEN {
        return Err(invalid_input(format!(
            "TLS 1.3 ServerHello session_id_echo too long: {} bytes (max {MAX_SESSION_ID_ECHO_LEN})",
            params.session_id_echo.len()
        )));
    }

    let supported_versions = encode_extension(EXT_SUPPORTED_VERSIONS, &TLS_VERSION_1_3)?;
    let key_share = encode_extension(EXT_KEY_SHARE, &params.key_share_extension_body)?;

    let extensions_len = supported_versions
        .len()
        .checked_add(key_share.len())
        .ok_or_else(|| invalid_input("TLS 1.3 ServerHello extensions length overflow"))?;

    if extensions_len > u16::MAX as usize {
        return Err(invalid_input(format!(
            "TLS 1.3 ServerHello extensions too long: {extensions_len} bytes (max {})",
            u16::MAX
        )));
    }

    let session_id_len = u8::try_from(params.session_id_echo.len())
        .expect("session_id_echo length fits in u8 after max check");

    let mut body = Vec::with_capacity(
        TLS_VERSION_1_2_LEGACY.len()
            + params.random.len()
            + 1
            + params.session_id_echo.len()
            + 2
            + 1
            + 2
            + extensions_len,
    );
    body.extend_from_slice(&TLS_VERSION_1_2_LEGACY);
    body.extend_from_slice(&params.random);
    body.push(session_id_len);
    body.extend_from_slice(&params.session_id_echo);
    body.extend_from_slice(&params.cipher_suite.to_be_bytes());
    body.push(0);
    body.extend_from_slice(&(extensions_len as u16).to_be_bytes());
    body.extend_from_slice(&supported_versions);
    body.extend_from_slice(&key_share);

    build_handshake_message(HANDSHAKE_TYPE_SERVER_HELLO, &body)
}

pub fn build_encrypted_extensions_empty() -> Result<Vec<u8>> {
    build_handshake_message(HANDSHAKE_TYPE_ENCRYPTED_EXTENSIONS, &[0x00, 0x00])
}

pub fn build_finished(verify_data: &[u8]) -> Result<Vec<u8>> {
    build_handshake_message(HANDSHAKE_TYPE_FINISHED, verify_data)
}

#[cfg(test)]
#[path = "../../../tests/unit/reality/tls13/messages.rs"]
mod tests;
