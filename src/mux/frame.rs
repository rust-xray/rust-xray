use std::io::{Error, ErrorKind};
use std::time::Instant;

use crate::vless::protocol::VlessDestination;

pub(crate) const MUX_OPT_DATA: u8 = 0x01;
pub(crate) const MUX_STATUS_NEW: u8 = 0x01;
pub(crate) const MUX_STATUS_KEEP: u8 = 0x02;
pub(crate) const MUX_STATUS_END: u8 = 0x03;
pub(crate) const MUX_STATUS_KEEPALIVE: u8 = 0x04;
pub(crate) const MUX_NETWORK_TCP: u8 = 0x01;
pub(crate) const MUX_NETWORK_UDP: u8 = 0x02;
pub(crate) const MAX_MUX_METADATA_LEN: usize = 512;
pub(crate) const MAX_MUX_DATA_LEN: usize = 65_535;
/// Server-side mux/XUDP packet acceptance bound (upstream `buf.Size` / PacketReader limit).
pub(crate) const XUDP_MAX_PACKET_LEN: usize = 8192;
/// Upstream XUDP client PacketWriter skips payload when `length + 666 > buf.Size`.
#[cfg(test)]
pub(crate) const XUDP_UPSTREAM_CLIENT_MAX_PAYLOAD: usize = XUDP_MAX_PACKET_LEN - 666;
pub(crate) const XUDP_GLOBAL_ID_LEN: usize = 8;

pub type MuxGlobalId = [u8; XUDP_GLOBAL_ID_LEN];

pub fn is_xudp_global_id(id: &MuxGlobalId) -> bool {
    id.iter().any(|byte| *byte != 0)
}
pub(crate) const ENV_MUX_UDP_SEND_CLOSE_AFTER_RESPONSE: &str =
    "RUST_XRAY_MUX_UDP_SEND_CLOSE_AFTER_RESPONSE";

#[derive(Clone, Copy)]
pub struct MuxSessionTrace {
    pub conn_id: u64,
    pub conn_started: Instant,
}

#[derive(Clone, Copy)]
pub(crate) struct MuxUdpDnsLatencyTrace {
    pub conn_id: Option<u64>,
    pub conn_started: Option<Instant>,
    pub mux_id: u16,
    pub received_at: Instant,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MuxStatus {
    New,
    Keep,
    End,
    KeepAlive,
}

impl MuxStatus {
    pub(crate) fn from_wire(value: u8) -> std::io::Result<Self> {
        match value {
            MUX_STATUS_NEW => Ok(Self::New),
            MUX_STATUS_KEEP => Ok(Self::Keep),
            MUX_STATUS_END => Ok(Self::End),
            MUX_STATUS_KEEPALIVE => Ok(Self::KeepAlive),
            other => Err(Error::new(
                ErrorKind::Unsupported,
                format!("unsupported mux frame status: 0x{other:02x}"),
            )),
        }
    }

    pub(crate) fn as_wire(self) -> u8 {
        match self {
            Self::New => MUX_STATUS_NEW,
            Self::Keep => MUX_STATUS_KEEP,
            Self::End => MUX_STATUS_END,
            Self::KeepAlive => MUX_STATUS_KEEPALIVE,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MuxOption {
    pub has_data: bool,
}

impl MuxOption {
    pub(crate) fn from_wire(value: u8) -> Self {
        Self {
            has_data: value & MUX_OPT_DATA != 0,
        }
    }

    pub(crate) fn as_wire(self) -> u8 {
        if self.has_data {
            MUX_OPT_DATA
        } else {
            0
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MuxNetwork {
    Tcp,
    Udp,
}

impl MuxNetwork {
    pub(crate) fn as_str(self) -> &'static str {
        match self {
            Self::Tcp => "tcp",
            Self::Udp => "udp",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MuxDestination {
    pub network: MuxNetwork,
    pub destination: VlessDestination,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MuxFrame {
    pub mux_id: u16,
    pub status: MuxStatus,
    pub option: MuxOption,
    pub command: MuxCommand,
}

impl MuxFrame {
    pub fn id(&self) -> u16 {
        self.mux_id
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MuxCommand {
    Tcp {
        destination: MuxDestination,
        initial_payload: Vec<u8>,
    },
    Udp {
        destination: MuxDestination,
        packet: Vec<u8>,
        /// Parsed from trailing New+UDP metadata when exactly 8 bytes remain and any byte is non-zero.
        global_id: Option<MuxGlobalId>,
    },
    Data {
        payload: Vec<u8>,
    },
    Close {
        payload: Vec<u8>,
    },
    KeepAlive,
}
