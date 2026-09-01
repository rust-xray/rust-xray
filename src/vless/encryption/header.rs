use std::fmt;

/// Minimum encrypted payload length including 16-byte AEAD tag.
pub const MIN_TRAFFIC_PAYLOAD_LEN: u16 = 17;
/// Maximum encrypted payload length (TLS 1.3 max record 16384 + 256).
pub const MAX_TRAFFIC_PAYLOAD_LEN: u16 = 16_640;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TrafficHeaderError {
    InvalidPrefix { header: [u8; 5] },
    InvalidLength { length: u16 },
    Truncated,
}

impl fmt::Display for TrafficHeaderError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidPrefix { header } => {
                write!(f, "invalid traffic header prefix: {header:?}")
            }
            Self::InvalidLength { length } => {
                write!(f, "invalid traffic payload length: {length}")
            }
            Self::Truncated => f.write_str("truncated traffic header"),
        }
    }
}

impl std::error::Error for TrafficHeaderError {}

/// Encode fake TLS 1.3 application-data record header (upstream `EncodeHeader`).
pub fn encode_traffic_header(out: &mut [u8; 5], payload_len_with_tag: u16) {
    out[0] = 23;
    out[1] = 3;
    out[2] = 3;
    out[3] = (payload_len_with_tag >> 8) as u8;
    out[4] = payload_len_with_tag as u8;
}

/// Decode fake TLS record header (upstream `DecodeHeader`).
pub fn decode_traffic_header(header: &[u8; 5]) -> Result<u16, TrafficHeaderError> {
    let length = u16::from_be_bytes([header[3], header[4]]);
    if header[0] != 23 || header[1] != 3 || header[2] != 3 {
        return Err(TrafficHeaderError::InvalidPrefix { header: *header });
    }
    if !(MIN_TRAFFIC_PAYLOAD_LEN..=MAX_TRAFFIC_PAYLOAD_LEN).contains(&length) {
        return Err(TrafficHeaderError::InvalidLength { length });
    }
    Ok(length)
}
