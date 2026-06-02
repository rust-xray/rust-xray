
use super::*;

#[test]
fn accepted_transport_from_normalized_raw_tcp() {
    let transport =
        AcceptedTransport::from_inbound_transport_config(&InboundTransportConfig::RawTcp).unwrap();
    assert_eq!(transport, AcceptedTransport::RawTcp);
}

#[test]
fn accepted_transport_from_normalized_xhttp() {
    let config = XHttpRuntimeConfig {
        path: "/xhttp".to_string(),
        host: Some("example.com".to_string()),
        mode: "stream-one".to_string(),
    };
    let transport = AcceptedTransport::from_inbound_transport_config(
        &InboundTransportConfig::XHttp(config.clone()),
    )
    .unwrap();
    assert_eq!(transport, AcceptedTransport::XHttp(config));
}

#[test]
fn accepted_transport_from_reality_runtime_raw_tcp() {
    let transport =
        AcceptedTransport::from_reality_runtime(&TransportNetwork::RawTcp, None).unwrap();
    assert_eq!(transport, AcceptedTransport::RawTcp);
}

#[test]
fn accepted_transport_from_reality_runtime_xhttp() {
    let settings = XHttpSettings {
        path: "/xhttp".to_string(),
        mode: Some("stream-one".to_string()),
        ..XHttpSettings::default()
    };
    let transport =
        AcceptedTransport::from_reality_runtime(&TransportNetwork::XHttp, Some(&settings)).unwrap();
    assert_eq!(
        transport,
        AcceptedTransport::XHttp(XHttpRuntimeConfig {
            path: "/xhttp".to_string(),
            host: None,
            mode: "stream-one".to_string(),
        })
    );
}

#[test]
fn dispatch_kind_labels() {
    assert_eq!(AcceptedTransport::RawTcp.kind_label(), "raw");
    assert_eq!(
        AcceptedTransport::XHttp(XHttpRuntimeConfig {
            path: "/".to_string(),
            host: None,
            mode: "auto".to_string(),
        })
        .kind_label(),
        "xhttp"
    );
}

#[test]
fn raw_transport_entrypoint_is_wired() {
    let raw = AcceptedTransport::RawTcp;
    assert_eq!(raw.kind_label(), "raw");
}
