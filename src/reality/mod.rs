mod auth;
mod certificate;
mod decision;
pub mod handshake;
mod server;
mod session;
mod short_id;
mod sni;
pub mod tls13;
mod version;

pub use auth::RealityAuthResult;
pub use certificate::{patch_reality_certificate_der, RealityCertificatePatchInput};
pub use decision::{
    inspect_reality_client_hello, RealityAccepted, RealityDecision, RealityInspectConfig,
};
pub use handshake::{
    extract_observed_server_hello, fetch_dest_handshake, generate_partial_tls13_handshake,
    patch_reality_server_hello, prepare_reality_tls13_state, PartialTls13Handshake,
    PatchedRealityHandshake, RealityDestHandshake, RealityObservedServerHello,
};
pub use server::handle_accepted_reality_client;
pub use session::{
    short_id_prefix_len, validate_reality_client_auth, RealityClientAuth, RealityValidationConfig,
};
pub use short_id::parse_short_id_hex;
pub use sni::{extract_sni_hostname, server_name_allowed};
pub use version::{parse_reality_client_version, version_ge, version_le};
