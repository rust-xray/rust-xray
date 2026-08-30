use bytes::Bytes;

use crate::vless::protocol::VlessDestination;

/// Immutable UDP datagram passed through association queues (XUDP and generic Mux UDP).
#[derive(Debug, Clone)]
pub(crate) struct UdpPacket {
    pub destination: Option<VlessDestination>,
    pub payload: Bytes,
}
