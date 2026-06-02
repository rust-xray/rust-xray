
use super::*;
use crate::config::XrayConfig;
use crate::dns::tcp_codec::{decode_dns_tcp_frame, encode_dns_tcp_frame};
use std::sync::{Arc, Mutex};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

#[derive(Default)]
struct FakeOutboundManager {
    captured: Arc<Mutex<Vec<DialRequest>>>,
    response: Vec<u8>,
}

impl OutboundManager for FakeOutboundManager {
    fn dial_tcp<'a>(
        &'a self,
        req: DialRequest,
    ) -> Pin<Box<dyn Future<Output = std::io::Result<DialStream>> + Send + 'a>> {
        Box::pin(async move {
            self.captured.lock().unwrap().push(req);
            let (client, mut server) = tokio::io::duplex(4096);
            let response = self.response.clone();
            tokio::spawn(async move {
                let mut prefix = [0u8; 2];
                server.read_exact(&mut prefix).await.unwrap();
                let len = u16::from_be_bytes(prefix) as usize;
                let mut frame = vec![0u8; len + 2];
                frame[..2].copy_from_slice(&prefix);
                server.read_exact(&mut frame[2..]).await.unwrap();
                let raw = decode_dns_tcp_frame(&frame).unwrap();
                assert_eq!(raw[0], 0x12);
                let response_frame = encode_dns_tcp_frame(&response).unwrap();
                server.write_all(&response_frame).await.unwrap();
            });
            Ok(Box::new(client) as DialStream)
        })
    }
}

fn dns_query() -> Vec<u8> {
    let mut packet = vec![
        0x12, 0x34, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    ];
    packet.extend_from_slice(&[
        7, b'e', b'x', b'a', b'm', b'p', b'l', b'e', 3, b'c', b'o', b'm', 0, 0, 1, 0, 1,
    ]);
    packet
}

#[tokio::test]
async fn dns_client_uses_selected_proxy_outbound_and_returns_raw_response() {
    let config: XrayConfig = serde_json::from_str(
            r#"{
              "dns": {"servers":["tcp://1.1.1.1:53"],"queryStrategy":"UseIPv4"},
              "outbounds": [{"tag":"direct","protocol":"freedom"},{"tag":"proxy","protocol":"vless"}],
              "routing": {"rules": [{"type":"field","port":53,"network":"tcp","outboundTag":"proxy"}]}
            }"#,
        )
        .unwrap();
    let dns = config.dns.clone().unwrap();
    let router = Arc::new(DnsRouter::new(config.routing, config.outbounds));
    let fake = Arc::new(FakeOutboundManager {
        captured: Arc::new(Mutex::new(Vec::new())),
        response: vec![0x12, 0x34, 0x81, 0x80],
    });
    let client = DnsClient::new(dns, router, fake.clone());

    let response = client
        .query_raw(&dns_query(), Some("dns-in"))
        .await
        .unwrap();
    assert_eq!(response, vec![0x12, 0x34, 0x81, 0x80]);

    let captured = fake.captured.lock().unwrap();
    assert_eq!(captured.len(), 1);
    assert_eq!(captured[0].destination_host, "1.1.1.1");
    assert_eq!(captured[0].destination_port, 53);
    assert_eq!(captured[0].outbound_tag.as_deref(), Some("proxy"));
    assert_eq!(captured[0].purpose, DialPurpose::Dns);
}

#[tokio::test]
async fn unsupported_doh_is_explicit() {
    let config: XrayConfig = serde_json::from_str(
            r#"{"dns":{"servers":["https://dns.google/dns-query"]},"outbounds":[{"tag":"proxy","protocol":"vless"}]}"#,
        )
        .unwrap();
    let router = Arc::new(DnsRouter::new(config.routing, config.outbounds));
    let fake = Arc::new(FakeOutboundManager::default());
    let client = DnsClient::new(config.dns.unwrap(), router, fake);

    let err = client.query_raw(&dns_query(), None).await.unwrap_err();
    assert_eq!(err.kind(), std::io::ErrorKind::Unsupported);
    assert!(err
        .to_string()
        .contains("DNS transport doh is parsed but not implemented yet"));
}

#[tokio::test]
async fn standard_manager_rejects_proxy_outbound_without_direct_leak() {
    let manager = StandardOutboundManager::new(vec![OutboundObject {
        tag: Some("proxy".to_string()),
        protocol: Some("vless".to_string()),
        extra: Default::default(),
    }]);
    let req = DialRequest {
        network: Network::Tcp,
        destination_host: "1.1.1.1".to_string(),
        destination_port: 53,
        outbound_tag: Some("proxy".to_string()),
        source_inbound_tag: Some("dns-in".to_string()),
        purpose: DialPurpose::Dns,
    };
    let err = match manager.dial_tcp(req).await {
        Ok(_) => panic!("expected unsupported outbound"),
        Err(err) => err,
    };
    assert_eq!(err.kind(), std::io::ErrorKind::Unsupported);
}
