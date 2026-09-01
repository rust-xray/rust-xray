//! Upstream-compatible VLESS UUID lookup normalization (`ProcessUUID`).

use uuid::Uuid;

/// Wire UUID bytes as sent by the client (used for routing hints and logs).
pub type WireUuid = Uuid;

/// Lookup key stored in the user table (`ProcessUUID` in Xray-core).
pub type LookupUuid = Uuid;

/// Normalize UUID bytes 6–7 to zero for validator lookup only.
///
/// Upstream: `proxy/vless/validator.go` `ProcessUUID`.
pub fn vless_lookup_uuid(wire: &WireUuid) -> LookupUuid {
    let mut bytes = *wire.as_bytes();
    bytes[6] = 0;
    bytes[7] = 0;
    Uuid::from_bytes(bytes)
}

#[cfg(test)]
#[path = "../../tests/unit/vless/uuid_lookup.rs"]
mod tests;
