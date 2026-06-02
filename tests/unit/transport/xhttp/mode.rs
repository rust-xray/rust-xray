use super::*;

#[test]
fn absent_mode_resolves_to_stream_one() {
    assert_eq!(
        resolve_xhttp_mode(None, false, TransportSecurity::Reality).unwrap(),
        EffectiveXHttpMode::StreamOne
    );
}

#[test]
fn auto_with_reality_and_no_download_settings_resolves_to_stream_one() {
    assert_eq!(
        resolve_xhttp_mode(Some(XHttpMode::Auto), false, TransportSecurity::Reality).unwrap(),
        EffectiveXHttpMode::StreamOne
    );
}

#[test]
fn auto_with_no_download_settings_resolves_to_stream_one() {
    assert_eq!(
        resolve_xhttp_mode(Some(XHttpMode::Auto), false, TransportSecurity::None).unwrap(),
        EffectiveXHttpMode::StreamOne
    );
}

#[test]
fn stream_one_resolves_to_stream_one() {
    assert_eq!(
        resolve_xhttp_mode(
            Some(XHttpMode::StreamOne),
            false,
            TransportSecurity::Reality
        )
        .unwrap(),
        EffectiveXHttpMode::StreamOne
    );
}

#[test]
fn stream_up_resolves_but_is_not_supported_at_runtime() {
    assert_eq!(
        resolve_xhttp_mode(Some(XHttpMode::StreamUp), false, TransportSecurity::Reality).unwrap(),
        EffectiveXHttpMode::StreamUp
    );
    assert!(!effective_xhttp_mode_is_supported(
        EffectiveXHttpMode::StreamUp
    ));
    assert_eq!(
        effective_xhttp_mode_unsupported_reason(EffectiveXHttpMode::StreamUp),
        Some("stream_up_not_implemented")
    );
}

#[test]
fn packet_up_parses_but_is_partially_unsupported_until_download_side() {
    assert_eq!(
        resolve_xhttp_mode(Some(XHttpMode::PacketUp), false, TransportSecurity::Reality).unwrap(),
        EffectiveXHttpMode::PacketUp
    );
    assert!(!packet_up_download_side_ready());
    assert!(!effective_xhttp_mode_is_supported(
        EffectiveXHttpMode::PacketUp
    ));
    assert_eq!(
        effective_xhttp_mode_unsupported_reason(EffectiveXHttpMode::PacketUp),
        Some("packet_up_download_side_not_implemented")
    );
}

#[test]
fn packet_down_resolves_but_is_not_supported_at_runtime() {
    assert_eq!(
        resolve_xhttp_mode(
            Some(XHttpMode::PacketDown),
            false,
            TransportSecurity::Reality,
        )
        .unwrap(),
        EffectiveXHttpMode::PacketDown
    );
    assert!(!effective_xhttp_mode_is_supported(
        EffectiveXHttpMode::PacketDown
    ));
    assert_eq!(
        effective_xhttp_mode_unsupported_reason(EffectiveXHttpMode::PacketDown),
        Some("packet_down_not_implemented")
    );
}

#[test]
fn unknown_mode_is_rejected_clearly() {
    let err = parse_xhttp_mode("not-a-mode").unwrap_err();
    assert_eq!(err, XHttpError::UnknownMode("not-a-mode".to_string()));
    assert_eq!(err.to_string(), "unsupported XHTTP mode: not-a-mode");
}

#[test]
fn configured_xhttp_mode_treats_empty_as_absent() {
    assert_eq!(configured_xhttp_mode(None).unwrap(), None);
    assert_eq!(configured_xhttp_mode(Some("")).unwrap(), None);
    assert_eq!(configured_xhttp_mode(Some("  ")).unwrap(), None);
}
