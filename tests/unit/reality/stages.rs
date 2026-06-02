
use super::*;
use std::io::ErrorKind;

#[test]
fn stage_error_includes_stage_name() {
    let err = stage_error(
        RealityAcceptedStage::ClientFinishedVerify,
        Error::new(ErrorKind::InvalidData, "bad verify"),
    );

    assert!(err.to_string().contains("ClientFinishedVerify"));
    assert!(err.to_string().contains("bad verify"));
    assert!(err.to_string().contains("REALITY accepted stage"));
}

#[test]
fn stage_error_preserves_source_kind() {
    let err = stage_error(
        RealityAcceptedStage::Vless,
        Error::new(ErrorKind::PermissionDenied, "unknown vless client id"),
    );

    assert_eq!(err.kind(), ErrorKind::PermissionDenied);
}
