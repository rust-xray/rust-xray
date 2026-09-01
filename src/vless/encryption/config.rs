use std::fmt;
use std::time::Duration;

use super::keys::{
    decode_base64url_key, nfs_inbound_key_from_bytes, nfs_outbound_key_from_bytes,
    KeyMaterialError, NfsStaticKey, OutboundNfsKey,
};
use super::padding::{parse_padding_profile, PaddingProfile};

pub const SCHEME_MLKEM768X25519PLUS: &str = "mlkem768x25519plus";

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum VlessDecryption {
    None,
    Mlkem768X25519Plus {
        raw: String,
        config: Mlkem768X25519PlusConfig,
    },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum VlessEncryption {
    None,
    Mlkem768X25519Plus(Mlkem768X25519PlusOutboundConfig),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum XorMode {
    Native,
    XorPub,
    Random,
}

impl XorMode {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Native => "native",
            Self::XorPub => "xorpub",
            Self::Random => "random",
        }
    }

    pub fn from_str(value: &str) -> Option<Self> {
        match value {
            "native" => Some(Self::Native),
            "xorpub" => Some(Self::XorPub),
            "random" => Some(Self::Random),
            _ => None,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct TicketLifetimeRange {
    pub min_secs: u64,
    pub max_secs: u64,
}

impl TicketLifetimeRange {
    pub fn disabled() -> Self {
        Self {
            min_secs: 0,
            max_secs: 0,
        }
    }

    pub fn is_disabled(&self) -> bool {
        self.min_secs == 0 && self.max_secs == 0
    }

    pub fn allows_zero_rtt(&self) -> bool {
        !self.is_disabled()
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ClientHandshakeMode {
    ZeroRtt,
    OneRtt,
}

impl ClientHandshakeMode {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::ZeroRtt => "0rtt",
            Self::OneRtt => "1rtt",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct Mlkem768X25519PlusConfig {
    pub xor_mode: XorMode,
    pub ticket_lifetime: TicketLifetimeRange,
    pub nfs_keys: Vec<NfsStaticKey>,
    pub padding: PaddingProfile,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Mlkem768X25519PlusOutboundConfig {
    pub xor_mode: XorMode,
    pub handshake_mode: ClientHandshakeMode,
    pub nfs_keys: Vec<OutboundNfsKey>,
    pub padding: PaddingProfile,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DecryptionParseError {
    Empty,
    UnsupportedScheme(String),
    FallbackConflict,
    MalformedScheme,
    InvalidMode,
    InvalidTicketLifetime,
    InvalidKeyMaterial(KeyMaterialError),
    InvalidPadding(String),
}

impl fmt::Display for DecryptionParseError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Empty => f.write_str(
                "VLESS settings: please add/set \"decryption\":\"none\" to every settings",
            ),
            Self::UnsupportedScheme(value) => {
                write!(f, "VLESS settings: unsupported \"decryption\": {value}")
            }
            Self::FallbackConflict => f.write_str(
                "VLESS settings: \"fallbacks\" can not be used together with \"decryption\"",
            ),
            Self::MalformedScheme => f.write_str("malformed VLESS decryption scheme"),
            Self::InvalidMode => f.write_str("invalid VLESS encryption xor mode"),
            Self::InvalidTicketLifetime => f.write_str("invalid VLESS encryption ticket lifetime"),
            Self::InvalidKeyMaterial(err) => write!(f, "{err}"),
            Self::InvalidPadding(err) => {
                write!(f, "invalid VLESS encryption padding profile: {err}")
            }
        }
    }
}

impl std::error::Error for DecryptionParseError {}

impl VlessDecryption {
    pub fn is_none(&self) -> bool {
        matches!(self, Self::None)
    }

    pub fn label(&self) -> &'static str {
        match self {
            Self::None => "none",
            Self::Mlkem768X25519Plus { .. } => SCHEME_MLKEM768X25519PLUS,
        }
    }

    pub fn config_string(&self) -> &str {
        match self {
            Self::None => "none",
            Self::Mlkem768X25519Plus { raw, .. } => raw,
        }
    }
}

impl VlessEncryption {
    pub fn label(&self) -> &'static str {
        match self {
            Self::None => "none",
            Self::Mlkem768X25519Plus(_) => SCHEME_MLKEM768X25519PLUS,
        }
    }
}

pub fn parse_inbound_decryption(raw: &str) -> Result<VlessDecryption, DecryptionParseError> {
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        return Err(DecryptionParseError::Empty);
    }
    if trimmed.eq_ignore_ascii_case("none") {
        return Ok(VlessDecryption::None);
    }

    let config = parse_mlkem_inbound(trimmed)?;
    Ok(VlessDecryption::Mlkem768X25519Plus {
        raw: trimmed.to_string(),
        config,
    })
}

pub fn parse_outbound_encryption(raw: &str) -> Result<VlessEncryption, DecryptionParseError> {
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        return Err(DecryptionParseError::Empty);
    }
    if trimmed.eq_ignore_ascii_case("none") {
        return Ok(VlessEncryption::None);
    }

    let config = parse_mlkem_outbound(trimmed)?;
    Ok(VlessEncryption::Mlkem768X25519Plus(config))
}

fn parse_mlkem_inbound(raw: &str) -> Result<Mlkem768X25519PlusConfig, DecryptionParseError> {
    let parts: Vec<&str> = raw.split('.').collect();
    if parts.len() < 4 || parts[0] != SCHEME_MLKEM768X25519PLUS {
        return Err(DecryptionParseError::MalformedScheme);
    }

    let xor_mode = XorMode::from_str(parts[1]).ok_or(DecryptionParseError::InvalidMode)?;
    let ticket_lifetime = parse_ticket_lifetime(parts[2])?;
    let (padding, key_tokens) = split_padding_and_keys(raw, parts[2], InboundKeyPolicy)?;
    let nfs_keys = parse_inbound_keys(key_tokens)?;

    Ok(Mlkem768X25519PlusConfig {
        xor_mode,
        ticket_lifetime,
        nfs_keys,
        padding,
    })
}

fn parse_mlkem_outbound(
    raw: &str,
) -> Result<Mlkem768X25519PlusOutboundConfig, DecryptionParseError> {
    let parts: Vec<&str> = raw.split('.').collect();
    if parts.len() < 4 || parts[0] != SCHEME_MLKEM768X25519PLUS {
        return Err(DecryptionParseError::MalformedScheme);
    }

    let xor_mode = XorMode::from_str(parts[1]).ok_or(DecryptionParseError::InvalidMode)?;
    let handshake_mode = match parts[2] {
        "0rtt" => ClientHandshakeMode::ZeroRtt,
        "1rtt" => ClientHandshakeMode::OneRtt,
        _ => return Err(DecryptionParseError::MalformedScheme),
    };
    let (padding, key_tokens) = split_padding_and_keys(raw, parts[2], OutboundKeyPolicy)?;
    let nfs_keys = parse_outbound_keys(key_tokens)?;

    Ok(Mlkem768X25519PlusOutboundConfig {
        xor_mode,
        handshake_mode,
        nfs_keys,
        padding,
    })
}

fn parse_ticket_lifetime(token: &str) -> Result<TicketLifetimeRange, DecryptionParseError> {
    let trimmed = token.trim_end_matches('s');
    let values: Vec<&str> = trimmed.split('-').collect();
    let min_secs = values
        .first()
        .ok_or(DecryptionParseError::InvalidTicketLifetime)?
        .parse::<u64>()
        .map_err(|_| DecryptionParseError::InvalidTicketLifetime)?;
    let max_secs = if values.len() == 2 {
        values[1]
            .parse::<u64>()
            .map_err(|_| DecryptionParseError::InvalidTicketLifetime)?
    } else {
        0
    };
    if values.len() > 2 || min_secs == 0 && max_secs != 0 {
        return Err(DecryptionParseError::InvalidTicketLifetime);
    }
    if max_secs != 0 && max_secs < min_secs {
        return Err(DecryptionParseError::InvalidTicketLifetime);
    }
    Ok(TicketLifetimeRange { min_secs, max_secs })
}

#[derive(Copy, Clone)]
enum KeyPolicy {
    InboundKeyPolicy,
    OutboundKeyPolicy,
}

use KeyPolicy::{InboundKeyPolicy, OutboundKeyPolicy};

fn split_padding_and_keys(
    raw: &str,
    third_token: &str,
    policy: KeyPolicy,
) -> Result<(PaddingProfile, Vec<String>), DecryptionParseError> {
    let prefix_len = SCHEME_MLKEM768X25519PLUS.len() + 1 + 6 + 1 + third_token.len() + 1;
    if raw.len() <= prefix_len {
        return Err(DecryptionParseError::MalformedScheme);
    }
    let remainder = &raw[prefix_len..];
    let tail_parts: Vec<&str> = raw.split('.').skip(3).collect();

    let mut padding_len = 0usize;
    for token in &tail_parts {
        if token.len() < 20 {
            padding_len += token.len() + 1;
            continue;
        }
        validate_key_token(token, policy)?;
    }

    let (padding_str, keys_str) = if padding_len > 0 {
        if padding_len > remainder.len() {
            return Err(DecryptionParseError::MalformedScheme);
        }
        let padding = &remainder[..padding_len.saturating_sub(1)];
        let keys = &remainder[padding_len..];
        (padding, keys)
    } else {
        ("", remainder)
    };

    let padding = parse_padding_profile(padding_str)
        .map_err(|err| DecryptionParseError::InvalidPadding(err.to_string()))?;

    let key_tokens = if keys_str.is_empty() {
        Vec::new()
    } else {
        keys_str.split('.').map(str::to_string).collect()
    };

    Ok((padding, key_tokens))
}

fn validate_key_token(token: &str, policy: KeyPolicy) -> Result<(), DecryptionParseError> {
    let bytes = decode_base64url_key(token).map_err(DecryptionParseError::InvalidKeyMaterial)?;
    match policy {
        InboundKeyPolicy => {
            if bytes.len() != 32 && bytes.len() != 64 {
                return Err(DecryptionParseError::InvalidKeyMaterial(
                    KeyMaterialError::InvalidLength {
                        expected: "32 or 64",
                        actual: bytes.len(),
                    },
                ));
            }
        }
        OutboundKeyPolicy => {
            if bytes.len() != 32 && bytes.len() != 1184 {
                return Err(DecryptionParseError::InvalidKeyMaterial(
                    KeyMaterialError::InvalidLength {
                        expected: "32 or 1184",
                        actual: bytes.len(),
                    },
                ));
            }
        }
    }
    Ok(())
}

fn parse_inbound_keys(tokens: Vec<String>) -> Result<Vec<NfsStaticKey>, DecryptionParseError> {
    if tokens.is_empty() {
        return Err(DecryptionParseError::InvalidKeyMaterial(
            KeyMaterialError::EmptyKeyChain,
        ));
    }
    tokens
        .into_iter()
        .map(|token| {
            let bytes =
                decode_base64url_key(&token).map_err(DecryptionParseError::InvalidKeyMaterial)?;
            nfs_inbound_key_from_bytes(bytes).map_err(DecryptionParseError::InvalidKeyMaterial)
        })
        .collect()
}

fn parse_outbound_keys(tokens: Vec<String>) -> Result<Vec<OutboundNfsKey>, DecryptionParseError> {
    if tokens.is_empty() {
        return Err(DecryptionParseError::InvalidKeyMaterial(
            KeyMaterialError::EmptyKeyChain,
        ));
    }
    tokens
        .into_iter()
        .map(|token| {
            let bytes =
                decode_base64url_key(&token).map_err(DecryptionParseError::InvalidKeyMaterial)?;
            nfs_outbound_key_from_bytes(bytes).map_err(DecryptionParseError::InvalidKeyMaterial)
        })
        .collect()
}

/// Validate inbound decryption and fallback mutual exclusion (upstream config build).
pub fn validate_inbound_decryption_with_fallbacks(
    decryption: Option<&str>,
    has_fallbacks: bool,
) -> Result<VlessDecryption, DecryptionParseError> {
    let parsed = match decryption {
        None | Some("") => return Err(DecryptionParseError::Empty),
        Some(value) => parse_inbound_decryption(value)?,
    };
    if !parsed.is_none() && has_fallbacks {
        return Err(DecryptionParseError::FallbackConflict);
    }
    Ok(parsed)
}

impl TicketLifetimeRange {
    pub fn sample_secs(&self, draw_percent: u64) -> Duration {
        if self.is_disabled() {
            return Duration::from_secs(0);
        }
        let secs = if self.max_secs == 0 {
            self.min_secs
                .saturating_mul(draw_percent)
                .saturating_div(100)
        } else {
            let span = self.max_secs.saturating_sub(self.min_secs);
            self.min_secs + span.saturating_mul(draw_percent).saturating_div(100)
        };
        Duration::from_secs(secs)
    }
}
