pub mod config;
pub mod fallback;
pub mod inbound;
pub mod protocol;
pub(crate) mod relay_debug;
pub(crate) mod vision;

pub use config::{
    build_vless_clients, parse_vless_user_id, validate_vless_client_flow,
    validate_vless_client_flows, VlessClient,
};
pub use fallback::{
    build_fallback_context, build_proxy_protocol_v1, build_proxy_protocol_v2,
    fallback_match_kind_label, looks_like_http_request, parse_fallback_dest,
    resolve_fallback_selection, resolve_fallback_target, select_vless_fallback,
    validate_fallback_configs, validate_fallback_xver, FallbackConfig, FallbackContext,
    FallbackDest, FallbackMatchKind, FallbackSelection,
};
pub use inbound::{
    authenticate_vless_client, handle_reality_vless_tcp_inbound, handle_vless_tcp_inbound,
    is_supported_vless_flow, prepare_vless_tcp_response, read_vless_request,
    write_vless_response_header, VlessAuthenticatedClient, VlessInboundRequest,
};
pub use protocol::encode_vless_response_header;
