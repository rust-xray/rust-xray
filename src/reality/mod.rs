mod auth;
mod client_version;
mod decision;
mod handshake;
mod server;
mod session;
mod short_id;
mod sni;

pub use auth::RealityAuthResult;
pub use client_version::parse_reality_client_version;
pub use decision::{
    inspect_reality_client_hello, RealityAccepted, RealityDecision, RealityInspectConfig,
};
pub use handshake::{
    fetch_dest_handshake, patch_reality_server_hello, PatchedRealityHandshake, RealityDestHandshake,
};
pub use server::handle_accepted_reality_client;
pub use session::{
    short_id_prefix_len, validate_reality_client_auth, RealityClientAuth, RealityValidationConfig,
};
pub use short_id::parse_short_id_hex;
pub use sni::extract_sni_hostname;
