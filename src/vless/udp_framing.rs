use std::io::{Error, ErrorKind};

use bytes::{Buf, Bytes, BytesMut};

/// Maximum payload size representable by the VLESS UDP 2-byte length field.
pub const VLESS_UDP_MAX_PACKET_LEN: usize = u16::MAX as usize;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum VlessUdpFramingError {
    UnexpectedEof,
    PayloadTooLarge { len: usize },
}

impl std::fmt::Display for VlessUdpFramingError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::UnexpectedEof => f.write_str("unexpected end of vless udp packet stream"),
            Self::PayloadTooLarge { len } => {
                write!(f, "vless udp payload length {len} exceeds u16 limit")
            }
        }
    }
}

impl std::error::Error for VlessUdpFramingError {}

impl From<VlessUdpFramingError> for Error {
    fn from(value: VlessUdpFramingError) -> Self {
        match value {
            VlessUdpFramingError::UnexpectedEof => Error::new(ErrorKind::UnexpectedEof, value),
            VlessUdpFramingError::PayloadTooLarge { .. } => {
                Error::new(ErrorKind::InvalidData, value)
            }
        }
    }
}

/// Streaming decoder for `[u16 be length][payload]` VLESS UDP packets.
#[derive(Debug, Default)]
pub struct VlessUdpPacketDecoder {
    buffer: BytesMut,
    eof: bool,
}

impl VlessUdpPacketDecoder {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn push(&mut self, data: &[u8]) {
        if !data.is_empty() {
            self.buffer.extend_from_slice(data);
        }
    }

    pub fn mark_eof(&mut self) {
        self.eof = true;
    }

    pub fn buffered_len(&self) -> usize {
        self.buffer.len()
    }

    /// Returns the next complete packet payload, skipping upstream-style zero-length packets.
    pub fn next_packet(&mut self) -> Result<Option<Bytes>, VlessUdpFramingError> {
        loop {
            if self.buffer.len() < 2 {
                if self.eof && !self.buffer.is_empty() {
                    return Err(VlessUdpFramingError::UnexpectedEof);
                }
                return Ok(None);
            }

            let packet_len = u16::from_be_bytes([self.buffer[0], self.buffer[1]]) as usize;
            if packet_len > VLESS_UDP_MAX_PACKET_LEN {
                return Err(VlessUdpFramingError::PayloadTooLarge { len: packet_len });
            }

            if self.buffer.len() < 2 + packet_len {
                if self.eof {
                    return Err(VlessUdpFramingError::UnexpectedEof);
                }
                return Ok(None);
            }

            self.buffer.advance(2);
            let payload = if packet_len == 0 {
                Bytes::new()
            } else {
                self.buffer.split_to(packet_len).freeze()
            };

            if payload.is_empty() {
                continue;
            }
            return Ok(Some(payload));
        }
    }
}

/// Encode one VLESS UDP packet. Empty payloads encode to an empty write (upstream skip).
pub fn encode_vless_udp_packet(payload: &[u8]) -> Result<Vec<u8>, VlessUdpFramingError> {
    if payload.len() > VLESS_UDP_MAX_PACKET_LEN {
        return Err(VlessUdpFramingError::PayloadTooLarge { len: payload.len() });
    }
    if payload.is_empty() {
        return Ok(Vec::new());
    }
    let mut out = Vec::with_capacity(2 + payload.len());
    out.extend_from_slice(&(payload.len() as u16).to_be_bytes());
    out.extend_from_slice(payload);
    Ok(out)
}

#[cfg(test)]
#[path = "../../tests/unit/vless/udp_framing.rs"]
mod tests;
