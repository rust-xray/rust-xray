
use crate::reality::tls13::RealityTls13ApplicationStream;
use tokio::io::{AsyncRead, AsyncWrite};

fn assert_vless_stream_bounds<S: AsyncRead + AsyncWrite + Unpin>() {}

#[test]
fn reality_application_stream_satisfies_vless_inbound_bounds() {
    assert_vless_stream_bounds::<RealityTls13ApplicationStream<tokio::io::DuplexStream>>();
}
