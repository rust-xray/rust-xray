//! XHTTP / SplitHTTP transport (server-side MVP).

pub mod bridge;
pub mod diagnostics;
pub mod extract;
pub mod matching;
pub mod mode;
pub mod packet_up;
pub mod packet_up_input;
pub mod session;
pub mod transport;

pub use bridge::{run_h2_stream_one_bridge, run_http1_stream_one_bridge, run_packet_up_bridge};
pub use diagnostics::{
    body_direction_for_leg, build_download_recon, build_request_shape, classify_request_leg,
    h2_content_length, h2_header_names, h2_request_target, header_names_from_lower_map,
    header_names_from_map, log_packet_up_request_shape, log_xhttp_download_reconnaissance,
    observe_download_reconnaissance, requires_h2_label, sample_h2_body_chunk_sizes,
    sample_http1_body_chunk_sizes, shape_redacts_payload, upload_download_relation_label,
    XHttpBodyDirection, XHttpDownloadRecon, XHttpRequestLeg, XHttpRequestShape,
    MAX_PACKET_UP_BODY_SAMPLE,
};
pub use extract::{
    extract_xhttp_packet_seq, extract_xhttp_packet_seq_for_settings, extract_xhttp_session_id,
    packet_up_body_hint,
};
pub use matching::{
    host_matches, method_matches_packet_up_download, method_matches_packet_up_upload,
    method_matches_stream_one, parse_packet_up_path, parse_packet_up_upload_seq_strict,
    path_matches, query_keys, request_path_component, validate_packet_up_request,
    validate_xhttp_stream_one_request, xhttp_match_reject_reason_label, PacketUpPathMatch,
    XHttpMatchRejectReason, XHttpMatchSettings, XHttpRequestDescriptor,
};
pub use mode::{
    configured_xhttp_mode, configured_xhttp_mode_label, effective_xhttp_mode_is_supported,
    effective_xhttp_mode_label, effective_xhttp_mode_unsupported_reason,
    packet_up_download_side_ready, parse_xhttp_mode, resolve_xhttp_mode, transport_security_label,
    xhttp_download_side_ready, EffectiveXHttpMode, TransportSecurity, XHttpError, XHttpMode,
};
pub use packet_up::{
    broadcast_download, shared_packet_up_manager, spawn_packet_up_bridge, PacketUpBridgeLaunch,
    PacketUpCommitOutcome, PacketUpUploadError, PacketUpUploadHandle, XHttpPacketUpManager,
};
pub use packet_up_input::{
    PacketUpBoundedInput, PacketUpInputError, PacketUpSessionInputReader,
    DEFAULT_PACKET_UP_INPUT_CHANNEL_SLOTS, DEFAULT_PACKET_UP_MAX_QUEUED_BYTES,
    ENV_XHTTP_PACKET_UP_MAX_QUEUED_BYTES,
};
pub use session::{
    XHttpSession, XHttpSessionEnsureOutcome, XHttpSessionError, XHttpSessionManager,
    XHttpSessionState,
};
pub use transport::serve_xhttp_stream_one;
