/// Placeholder plan for generating the server-facing ServerHello message.
///
/// Upstream equivalent: ServerHello construction inside Go `hs.handshake()`.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct RealityServerHelloPlan {
    // TODO: legacy_version
    // TODO: random
    // TODO: cipher_suite
    // TODO: key_share
}

/// Placeholder plan for EncryptedExtensions.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct RealityEncryptedExtensionsPlan {
    // TODO: ALPN
    // TODO: other extensions required by REALITY camouflage
}

/// Placeholder plan for the server Certificate message.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct RealityCertificatePlan {
    // TODO: ephemeral / camouflage certificate chain
}

/// Placeholder plan for the server Finished message.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct RealityFinishedPlan {
    // TODO: verify_data derived from transcript + key schedule
}
