use std::io::{Error, ErrorKind};
use std::pin::Pin;
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll};

use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tracing::{debug, info, trace};

pub const FLOW_XTLS_RPRX_VISION: &str = "xtls-rprx-vision";

pub const COMMAND_PADDING_CONTINUE: u8 = 0x00;
pub const COMMAND_PADDING_END: u8 = 0x01;
pub const COMMAND_PADDING_DIRECT: u8 = 0x02;

const TLS_CLIENT_HANDSHAKE_START: [u8; 2] = [0x16, 0x03];
const TLS_SERVER_HANDSHAKE_START: [u8; 3] = [0x16, 0x03, 0x03];
const TLS_APPLICATION_DATA_START: [u8; 3] = [0x17, 0x03, 0x03];
const TLS13_SUPPORTED_VERSIONS: [u8; 6] = [0x00, 0x2b, 0x00, 0x02, 0x03, 0x04];
const TLS_HANDSHAKE_TYPE_CLIENT_HELLO: u8 = 0x01;
const TLS_HANDSHAKE_TYPE_SERVER_HELLO: u8 = 0x02;
const MAX_VISION_FRAME: usize = 8192;
#[cfg(test)]
use crate::vless::config::UPSTREAM_DEFAULT_TESTSEED;

/// Per-direction Vision padding / unpadding state.
#[derive(Debug, Clone)]
pub struct DirectionState {
    pub within_padding_buffers: bool,
    /// Uplink reader entered raw/direct mode after COMMAND_DIRECT from client.
    pub direct_copy: bool,
    /// Downlink writer should switch to raw mode on the next write (after DIRECT frame).
    pub downlink_writer_direct_pending: bool,
    pub remaining_command: i32,
    pub remaining_content: i32,
    pub remaining_padding: i32,
    pub current_command: i32,
    pub is_padding: bool,
    pub pending: Vec<u8>,
}

impl Default for DirectionState {
    fn default() -> Self {
        Self {
            within_padding_buffers: true,
            direct_copy: false,
            downlink_writer_direct_pending: false,
            remaining_command: -1,
            remaining_content: -1,
            remaining_padding: -1,
            current_command: 0,
            is_padding: true,
            pending: Vec::new(),
        }
    }
}

/// Shared Vision traffic analysis state for one VLESS connection.
#[derive(Debug, Clone)]
pub struct TrafficState {
    pub user_uuid: [u8; 16],
    pub testseed: [u32; 4],
    pub number_of_packet_to_filter: i32,
    pub enable_xtls: bool,
    pub is_tls12_or_above: bool,
    pub is_tls: bool,
    pub cipher: u16,
    pub remaining_server_hello: i32,
    pub inbound: DirectionState,
    pub outbound: DirectionState,
}

impl TrafficState {
    #[cfg(test)]
    pub fn new(user_uuid: [u8; 16]) -> Self {
        Self::with_testseed(user_uuid, UPSTREAM_DEFAULT_TESTSEED)
    }

    pub fn with_testseed(user_uuid: [u8; 16], testseed: [u32; 4]) -> Self {
        Self {
            user_uuid,
            testseed,
            number_of_packet_to_filter: 8,
            enable_xtls: false,
            is_tls12_or_above: false,
            is_tls: false,
            cipher: 0,
            remaining_server_hello: -1,
            inbound: DirectionState::default(),
            outbound: DirectionState::default(),
        }
    }

    pub fn unpad_uplink_chunk(&mut self, input: &[u8]) -> std::io::Result<Vec<u8>> {
        xtls_unpadding(input, self, true)
    }

    pub fn unpad_uplink_chunk_with_signal(
        &mut self,
        input: &[u8],
    ) -> std::io::Result<(Vec<u8>, Option<VisionDirectStarted>)> {
        let had_direct = self.inbound.direct_copy;
        let output = xtls_unpadding(input, self, true)?;
        let signal = if !had_direct && self.inbound.direct_copy {
            Some(VisionDirectStarted)
        } else {
            None
        };
        Ok((output, signal))
    }

    pub fn pad_downlink_chunk(
        &mut self,
        content: &[u8],
        write_once_uuid: &mut Option<[u8; 16]>,
    ) -> Vec<u8> {
        if self.number_of_packet_to_filter > 0 {
            xtls_filter_tls(content, self);
        }

        if !self.inbound.is_padding {
            return content.to_vec();
        }

        let long_padding = self.is_tls;
        let command = if content.is_empty() {
            COMMAND_PADDING_CONTINUE
        } else if self.is_tls
            && content.len() >= 6
            && content.starts_with(&TLS_APPLICATION_DATA_START)
            && is_complete_tls_application_records(content)
        {
            self.inbound.is_padding = false;
            if self.enable_xtls {
                self.inbound.downlink_writer_direct_pending = true;
                COMMAND_PADDING_DIRECT
            } else {
                COMMAND_PADDING_END
            }
        } else if !self.is_tls12_or_above && self.number_of_packet_to_filter <= 1 {
            self.inbound.is_padding = false;
            COMMAND_PADDING_END
        } else {
            COMMAND_PADDING_CONTINUE
        };

        xtls_padding(
            content,
            command,
            write_once_uuid,
            long_padding,
            self.testseed,
        )
    }

    pub fn take_downlink_writer_direct_pending(&mut self) -> bool {
        if self.inbound.downlink_writer_direct_pending {
            self.inbound.downlink_writer_direct_pending = false;
            true
        } else {
            false
        }
    }
}

pub type SharedTrafficState = Arc<Mutex<TrafficState>>;

#[cfg(test)]
pub fn new_shared_traffic_state(user_uuid: [u8; 16]) -> SharedTrafficState {
    new_shared_traffic_state_with_testseed(user_uuid, UPSTREAM_DEFAULT_TESTSEED)
}

pub fn new_shared_traffic_state_with_testseed(
    user_uuid: [u8; 16],
    testseed: [u32; 4],
) -> SharedTrafficState {
    Arc::new(Mutex::new(TrafficState::with_testseed(user_uuid, testseed)))
}

pub fn is_vision_flow(flow: Option<&str>) -> bool {
    matches!(flow.map(str::trim), Some(FLOW_XTLS_RPRX_VISION))
}

pub fn vision_relay_supported() -> bool {
    true
}

/// Signal that Vision uplink entered COMMAND_DIRECT / raw copy mode.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct VisionDirectStarted;

pub fn parse_vless_request_flow(additional_info: &[u8]) -> Option<String> {
    parse_protobuf_flow_field(additional_info)
}

fn parse_protobuf_flow_field(data: &[u8]) -> Option<String> {
    let mut offset = 0usize;
    while offset < data.len() {
        let tag = *data.get(offset)?;
        offset += 1;
        let field_number = tag >> 3;
        let wire_type = tag & 0x07;
        if wire_type != 2 {
            return None;
        }
        let (len, consumed) = read_protobuf_varint(&data[offset..])?;
        offset += consumed;
        let value = data.get(offset..offset + len as usize)?;
        offset += len as usize;
        if field_number == 1 {
            return String::from_utf8(value.to_vec()).ok();
        }
    }
    None
}

fn read_protobuf_varint(data: &[u8]) -> Option<(u64, usize)> {
    let mut value = 0u64;
    for (i, byte) in data.iter().enumerate() {
        value |= u64::from(byte & 0x7f) << (i * 7);
        if byte & 0x80 == 0 {
            return Some((value, i + 1));
        }
        if i >= 9 {
            return None;
        }
    }
    None
}

pub fn xtls_padding(
    content: &[u8],
    command: u8,
    write_once_uuid: &mut Option<[u8; 16]>,
    long_padding: bool,
    testseed: [u32; 4],
) -> Vec<u8> {
    let content_len = content.len();
    let mut padding_len = random_padding_len(content_len, long_padding, testseed);
    let max_padding = MAX_VISION_FRAME.saturating_sub(21 + content_len);
    padding_len = padding_len.min(max_padding);

    let mut out = Vec::with_capacity(16 + 5 + content_len + padding_len);
    if let Some(uuid) = write_once_uuid.take() {
        out.extend_from_slice(&uuid);
    }
    out.push(command);
    out.extend_from_slice(&(content_len as u16).to_be_bytes());
    out.extend_from_slice(&(padding_len as u16).to_be_bytes());
    out.extend_from_slice(content);
    if padding_len > 0 {
        let mut pad = vec![0u8; padding_len];
        let _ = getrandom::getrandom(&mut pad);
        out.extend_from_slice(&pad);
    }

    trace!(
        command,
        content_len,
        padding_len,
        first_uuid = out.len() >= 16,
        "vision padding block written"
    );
    out
}

pub fn xtls_unpadding(
    input: &[u8],
    state: &mut TrafficState,
    is_uplink: bool,
) -> std::io::Result<Vec<u8>> {
    let direction = if is_uplink {
        &mut state.inbound
    } else {
        &mut state.outbound
    };

    if direction.direct_copy {
        return Ok(input.to_vec());
    }

    if !direction.within_padding_buffers && state.number_of_packet_to_filter <= 0 {
        return Ok(input.to_vec());
    }

    let mut data = direction.pending.clone();
    direction.pending.clear();
    data.extend_from_slice(input);

    if direction.remaining_command == -1
        && direction.remaining_content == -1
        && direction.remaining_padding == -1
    {
        if data.len() < 21 {
            if data.is_empty() {
                return Ok(Vec::new());
            }
            if data.len() <= state.user_uuid.len() && data == state.user_uuid[..data.len()] {
                direction.pending = data;
                return Ok(Vec::new());
            }
            direction.within_padding_buffers = false;
            return Ok(data);
        }
        if data[..16] != state.user_uuid {
            direction.within_padding_buffers = false;
            return Ok(data);
        }
    }

    let input = data.as_slice();
    let mut output = Vec::new();
    let mut pos = 0usize;

    if direction.remaining_command == -1
        && direction.remaining_content == -1
        && direction.remaining_padding == -1
    {
        pos = 16;
        direction.remaining_command = 5;
    }

    loop {
        if direction.remaining_command > 0 {
            let Some(data) = input.get(pos) else {
                direction.pending = input[pos..].to_vec();
                break;
            };
            pos += 1;
            match direction.remaining_command {
                5 => direction.current_command = i32::from(*data),
                4 => direction.remaining_content = i32::from(*data) << 8,
                3 => direction.remaining_content |= i32::from(*data),
                2 => direction.remaining_padding = i32::from(*data) << 8,
                1 => direction.remaining_padding |= i32::from(*data),
                _ => {}
            }
            direction.remaining_command -= 1;
            continue;
        }

        if direction.remaining_content > 0 {
            let available = input.len().saturating_sub(pos);
            if available == 0 {
                direction.pending = input[pos..].to_vec();
                break;
            }
            let take = (direction.remaining_content as usize).min(available);
            output.extend_from_slice(&input[pos..pos + take]);
            pos += take;
            direction.remaining_content -= take as i32;
            continue;
        }

        if direction.remaining_padding > 0 {
            let available = input.len().saturating_sub(pos);
            if available == 0 {
                direction.pending = input[pos..].to_vec();
                break;
            }
            let skip = (direction.remaining_padding as usize).min(available);
            pos += skip;
            direction.remaining_padding -= skip as i32;
            continue;
        }

        if direction.remaining_command == -1
            && direction.remaining_content == -1
            && direction.remaining_padding == -1
        {
            break;
        }

        trace!(
            command = direction.current_command,
            content_len = output.len(),
            "vision unpadding block read"
        );

        match direction.current_command {
            cmd if cmd == i32::from(COMMAND_PADDING_CONTINUE) => {
                direction.remaining_command = 5;
                if pos >= input.len() {
                    break;
                }
            }
            cmd if cmd == i32::from(COMMAND_PADDING_END) => {
                direction.within_padding_buffers = false;
                direction.remaining_command = -1;
                direction.remaining_content = -1;
                direction.remaining_padding = -1;
                if pos < input.len() {
                    output.extend_from_slice(&input[pos..]);
                }
                break;
            }
            cmd if cmd == i32::from(COMMAND_PADDING_DIRECT) => {
                debug!("vision direct command received");
                direction.within_padding_buffers = false;
                direction.direct_copy = true;
                direction.remaining_command = -1;
                direction.remaining_content = -1;
                direction.remaining_padding = -1;
                if pos < input.len() {
                    output.extend_from_slice(&input[pos..]);
                }
                break;
            }
            command => {
                return Err(Error::new(
                    ErrorKind::InvalidData,
                    format!("unknown vision padding command: {command}"),
                ));
            }
        }
    }

    if state.number_of_packet_to_filter > 0 && !output.is_empty() {
        xtls_filter_tls(&output, state);
    }

    Ok(output)
}

pub fn xtls_filter_tls(data: &[u8], state: &mut TrafficState) {
    if state.number_of_packet_to_filter <= 0 {
        return;
    }
    state.number_of_packet_to_filter -= 1;

    if data.len() >= 6 {
        if data.starts_with(&TLS_SERVER_HANDSHAKE_START)
            && data[5] == TLS_HANDSHAKE_TYPE_SERVER_HELLO
        {
            state.remaining_server_hello = i32::from(data[3]) << 8 | i32::from(data[4]) + 5;
            state.is_tls12_or_above = true;
            state.is_tls = true;
            if data.len() >= 79 && state.remaining_server_hello >= 79 {
                let session_id_len = usize::from(data[43]);
                let offset = 43 + session_id_len + 1;
                if data.len() >= offset + 2 {
                    state.cipher = u16::from_be_bytes([data[offset], data[offset + 1]]);
                }
            }
        } else if data.starts_with(&TLS_CLIENT_HANDSHAKE_START)
            && data.len() > 5
            && data[5] == TLS_HANDSHAKE_TYPE_CLIENT_HELLO
        {
            state.is_tls = true;
        }
    }

    if state.remaining_server_hello > 0 {
        let end = state.remaining_server_hello.min(data.len() as i32) as usize;
        if data[..end]
            .windows(TLS13_SUPPORTED_VERSIONS.len())
            .any(|w| w == TLS13_SUPPORTED_VERSIONS)
        {
            state.enable_xtls = true;
        }
        state.remaining_server_hello -= data.len() as i32;
    }

    trace!(
        enable_xtls = state.enable_xtls,
        is_tls = state.is_tls,
        is_tls12_or_above = state.is_tls12_or_above,
        cipher = state.cipher,
        remaining_packets = state.number_of_packet_to_filter,
        "vision tls filter result"
    );
}

fn is_complete_tls_application_records(data: &[u8]) -> bool {
    let mut i = 0usize;
    while i < data.len() {
        if data.len() - i < 5 {
            return false;
        }
        if data[i] != 0x17 || data[i + 1] != 0x03 || data[i + 2] != 0x03 {
            return false;
        }
        let record_len = usize::from(data[i + 3]) << 8 | usize::from(data[i + 4]);
        i += 5;
        if data.len() - i < record_len {
            return false;
        }
        i += record_len;
    }
    true
}

fn random_padding_len(content_len: usize, long_padding: bool, testseed: [u32; 4]) -> usize {
    let mut bytes = [0u8; 2];
    let _ = getrandom::getrandom(&mut bytes);
    let random = u16::from_be_bytes(bytes) as usize;
    if content_len < testseed[0] as usize && long_padding {
        random
            .saturating_add(testseed[2] as usize)
            .saturating_sub(content_len)
    } else {
        random % (testseed[3] as usize + 1)
    }
}

/// Whether Vision may enable REALITY TLS 1.3 direct relay on `COMMAND_DIRECT`.
///
/// Unencrypted REALITY Vision keeps upstream DIRECT splice behavior. Encrypted VLESS
/// must never bypass the CommonConn layer even after padding ends.
#[derive(Debug, Clone)]
pub(crate) enum VisionDirectCapability {
    Allowed(crate::reality::tls13::ApplicationStreamDirectRelay),
    BlockedByVlessEncryption,
}

impl VisionDirectCapability {
    pub fn from_reality_tls_split(
        direct_relay: crate::reality::tls13::ApplicationStreamDirectRelay,
    ) -> Self {
        Self::Allowed(direct_relay)
    }

    pub fn blocked_by_vless_encryption() -> Self {
        Self::BlockedByVlessEncryption
    }

    pub fn direct_relay(&self) -> Option<crate::reality::tls13::ApplicationStreamDirectRelay> {
        match self {
            Self::Allowed(relay) => Some(relay.clone()),
            Self::BlockedByVlessEncryption => None,
        }
    }

    #[cfg(test)]
    pub fn is_blocked(&self) -> bool {
        matches!(self, Self::BlockedByVlessEncryption)
    }
}

/// Vision uplink reader: unpads client-to-server plaintext before relay.
pub struct VisionRelayReader<R> {
    inner: R,
    traffic: SharedTrafficState,
    pending_read: Vec<u8>,
    direct_relay: Option<crate::reality::tls13::ApplicationStreamDirectRelay>,
}

impl<R> VisionRelayReader<R> {
    pub fn new(
        inner: R,
        traffic: SharedTrafficState,
        direct_relay: Option<crate::reality::tls13::ApplicationStreamDirectRelay>,
    ) -> Self {
        Self {
            inner,
            traffic,
            pending_read: Vec::new(),
            direct_relay,
        }
    }

    fn maybe_start_direct_relay(&self, signal: Option<VisionDirectStarted>) {
        if signal != Some(VisionDirectStarted) {
            return;
        }
        if let Some(direct_relay) = self.direct_relay.as_ref() {
            direct_relay.enable_reader();
        }
        info!("vision direct relay started");
    }
}

impl<R> AsyncRead for VisionRelayReader<R>
where
    R: AsyncRead + Unpin,
{
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        loop {
            if !self.pending_read.is_empty() {
                let to_copy = self.pending_read.len().min(buf.remaining());
                buf.put_slice(&self.pending_read[..to_copy]);
                self.pending_read.drain(..to_copy);
                return Poll::Ready(Ok(()));
            }

            {
                let (direct_copy, within) = {
                    let traffic = self.traffic.lock().expect("vision traffic lock");
                    (
                        traffic.inbound.direct_copy,
                        traffic.inbound.within_padding_buffers
                            || traffic.number_of_packet_to_filter > 0,
                    )
                };
                if direct_copy || !within {
                    return Pin::new(&mut self.inner).poll_read(cx, buf);
                }
            }

            let mut chunk = [0u8; 4096];
            let mut read_buf = ReadBuf::new(&mut chunk);
            match Pin::new(&mut self.inner).poll_read(cx, &mut read_buf) {
                Poll::Ready(Ok(())) if read_buf.filled().is_empty() => return Poll::Ready(Ok(())),
                Poll::Ready(Ok(())) => {
                    let (unpadded, direct_started) = {
                        let mut traffic = self.traffic.lock().expect("vision traffic lock");
                        traffic.unpad_uplink_chunk_with_signal(read_buf.filled())?
                    };
                    self.maybe_start_direct_relay(direct_started);
                    if unpadded.is_empty() {
                        continue;
                    }
                    let to_copy = unpadded.len().min(buf.remaining());
                    buf.put_slice(&unpadded[..to_copy]);
                    self.pending_read.extend_from_slice(&unpadded[to_copy..]);
                    return Poll::Ready(Ok(()));
                }
                Poll::Ready(Err(err)) => return Poll::Ready(Err(err)),
                Poll::Pending => return Poll::Pending,
            }
        }
    }
}

/// Vision downlink writer: pads server-to-client plaintext before TLS encryption.
pub struct VisionRelayWriter<W> {
    inner: W,
    traffic: SharedTrafficState,
    write_once_uuid: Option<[u8; 16]>,
    pending_write: Vec<u8>,
    pending_original_len: Option<usize>,
    direct_relay: Option<crate::reality::tls13::ApplicationStreamDirectRelay>,
}

impl<W> VisionRelayWriter<W> {
    pub fn new(
        inner: W,
        traffic: SharedTrafficState,
        user_uuid: [u8; 16],
        direct_relay: Option<crate::reality::tls13::ApplicationStreamDirectRelay>,
    ) -> Self {
        Self {
            inner,
            traffic,
            write_once_uuid: Some(user_uuid),
            pending_write: Vec::new(),
            pending_original_len: None,
            direct_relay,
        }
    }

    fn maybe_enable_downlink_writer_direct(&mut self) {
        let pending = {
            let mut traffic = self.traffic.lock().expect("vision traffic lock");
            traffic.take_downlink_writer_direct_pending()
        };
        if pending {
            if let Some(direct_relay) = self.direct_relay.as_ref() {
                direct_relay.enable_writer();
            }
        }
    }
}

impl<W> AsyncWrite for VisionRelayWriter<W>
where
    W: AsyncWrite + Unpin,
{
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        if buf.is_empty() {
            return Poll::Ready(Ok(0));
        }

        if !self.pending_write.is_empty() {
            let original_len = self
                .pending_original_len
                .expect("pending original length while pending write buffer is non-empty");

            let pending = self.pending_write.clone();
            match Pin::new(&mut self.inner).poll_write(cx, &pending) {
                Poll::Ready(Ok(0)) => {
                    return Poll::Ready(Err(Error::new(
                        ErrorKind::WriteZero,
                        "vision relay underlying write zero",
                    )));
                }
                Poll::Ready(Ok(n)) => {
                    let _ = self.pending_write.drain(..n);
                    if self.pending_write.is_empty() {
                        self.pending_original_len = None;
                        return Poll::Ready(Ok(original_len));
                    }
                    return Poll::Pending;
                }
                Poll::Ready(Err(err)) => {
                    self.pending_write.clear();
                    self.pending_original_len = None;
                    return Poll::Ready(Err(err));
                }
                Poll::Pending => return Poll::Pending,
            }
        }

        self.maybe_enable_downlink_writer_direct();

        let writer_direct = self
            .direct_relay
            .as_ref()
            .is_some_and(|direct_relay| direct_relay.is_writer_enabled());
        if writer_direct {
            return Pin::new(&mut self.inner).poll_write(cx, buf);
        }

        let padded = {
            let mut write_once = self.write_once_uuid;
            let padded = {
                let mut traffic = self.traffic.lock().expect("vision traffic lock");
                traffic.pad_downlink_chunk(buf, &mut write_once)
            };
            self.write_once_uuid = write_once;
            padded
        };

        self.pending_write = padded;
        self.pending_original_len = Some(buf.len());

        let original_len = self.pending_original_len.expect("pending original len");
        let pending = self.pending_write.clone();
        match Pin::new(&mut self.inner).poll_write(cx, &pending) {
            Poll::Ready(Ok(0)) => Poll::Ready(Err(Error::new(
                ErrorKind::WriteZero,
                "vision relay underlying write zero",
            ))),
            Poll::Ready(Ok(n)) => {
                let _ = self.pending_write.drain(..n);
                if self.pending_write.is_empty() {
                    self.pending_original_len = None;
                    Poll::Ready(Ok(original_len))
                } else {
                    Poll::Pending
                }
            }
            Poll::Ready(Err(err)) => {
                self.pending_write.clear();
                self.pending_original_len = None;
                Poll::Ready(Err(err))
            }
            Poll::Pending => Poll::Pending,
        }
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.inner).poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.inner).poll_shutdown(cx)
    }
}

impl<S> crate::reality::tls13::Tls13OverflowAlertWriter
    for VisionRelayWriter<crate::reality::tls13::RealityTls13ClientWriter<S>>
where
    S: AsyncWrite + Unpin,
{
    fn send_useless_overflow_fatal_alert(
        &mut self,
    ) -> impl std::future::Future<Output = std::io::Result<()>> {
        self.inner.send_useless_overflow_fatal_alert()
    }
}

/// Bidirectional Vision relay adapter: unpads reads, pads writes.
pub struct VisionRelayStream<S> {
    inner: S,
    traffic: SharedTrafficState,
    write_once_uuid: Option<[u8; 16]>,
    pending_read: Vec<u8>,
    pending_write: Vec<u8>,
    pending_original_len: Option<usize>,
    direct_relay: Option<crate::reality::tls13::ApplicationStreamDirectRelay>,
}

impl<S> VisionRelayStream<S> {
    pub fn new(
        inner: S,
        traffic: SharedTrafficState,
        user_uuid: [u8; 16],
        direct_relay: Option<crate::reality::tls13::ApplicationStreamDirectRelay>,
    ) -> Self {
        Self {
            inner,
            traffic,
            write_once_uuid: Some(user_uuid),
            pending_read: Vec::new(),
            pending_write: Vec::new(),
            pending_original_len: None,
            direct_relay,
        }
    }

    fn maybe_start_direct_relay(&mut self, signal: Option<VisionDirectStarted>) {
        if signal != Some(VisionDirectStarted) {
            return;
        }
        if let Some(direct_relay) = self.direct_relay.as_ref() {
            direct_relay.enable_reader();
        }
        info!("vision direct relay started");
    }

    fn maybe_enable_downlink_writer_direct(&mut self) {
        let pending = {
            let mut traffic = self.traffic.lock().expect("vision traffic lock");
            traffic.take_downlink_writer_direct_pending()
        };
        if pending {
            if let Some(direct_relay) = self.direct_relay.as_ref() {
                direct_relay.enable_writer();
            }
        }
    }
}

impl<S> AsyncRead for VisionRelayStream<S>
where
    S: AsyncRead + Unpin,
{
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        loop {
            if !self.pending_read.is_empty() {
                let to_copy = self.pending_read.len().min(buf.remaining());
                buf.put_slice(&self.pending_read[..to_copy]);
                self.pending_read.drain(..to_copy);
                return Poll::Ready(Ok(()));
            }

            {
                let (direct_copy, within) = {
                    let traffic = self.traffic.lock().expect("vision traffic lock");
                    (
                        traffic.inbound.direct_copy,
                        traffic.inbound.within_padding_buffers
                            || traffic.number_of_packet_to_filter > 0,
                    )
                };
                if direct_copy || !within {
                    return Pin::new(&mut self.inner).poll_read(cx, buf);
                }
            }

            let mut chunk = [0u8; 4096];
            let mut read_buf = ReadBuf::new(&mut chunk);
            match Pin::new(&mut self.inner).poll_read(cx, &mut read_buf) {
                Poll::Ready(Ok(())) if read_buf.filled().is_empty() => return Poll::Ready(Ok(())),
                Poll::Ready(Ok(())) => {
                    let (unpadded, direct_started) = {
                        let mut traffic = self.traffic.lock().expect("vision traffic lock");
                        traffic.unpad_uplink_chunk_with_signal(read_buf.filled())?
                    };
                    self.maybe_start_direct_relay(direct_started);
                    if unpadded.is_empty() {
                        continue;
                    }
                    let to_copy = unpadded.len().min(buf.remaining());
                    buf.put_slice(&unpadded[..to_copy]);
                    self.pending_read.extend_from_slice(&unpadded[to_copy..]);
                    return Poll::Ready(Ok(()));
                }
                Poll::Ready(Err(err)) => return Poll::Ready(Err(err)),
                Poll::Pending => return Poll::Pending,
            }
        }
    }
}

impl<S> AsyncWrite for VisionRelayStream<S>
where
    S: AsyncWrite + Unpin,
{
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        if buf.is_empty() {
            return Poll::Ready(Ok(0));
        }

        if !self.pending_write.is_empty() {
            let original_len = self
                .pending_original_len
                .expect("pending original length while pending write buffer is non-empty");

            let pending = self.pending_write.clone();
            match Pin::new(&mut self.inner).poll_write(cx, &pending) {
                Poll::Ready(Ok(0)) => {
                    return Poll::Ready(Err(Error::new(
                        ErrorKind::WriteZero,
                        "vision relay underlying write zero",
                    )));
                }
                Poll::Ready(Ok(n)) => {
                    let _ = self.pending_write.drain(..n);
                    if self.pending_write.is_empty() {
                        self.pending_original_len = None;
                        return Poll::Ready(Ok(original_len));
                    }
                    return Poll::Pending;
                }
                Poll::Ready(Err(err)) => {
                    self.pending_write.clear();
                    self.pending_original_len = None;
                    return Poll::Ready(Err(err));
                }
                Poll::Pending => return Poll::Pending,
            }
        }

        self.maybe_enable_downlink_writer_direct();

        let writer_direct = self
            .direct_relay
            .as_ref()
            .is_some_and(|direct_relay| direct_relay.is_writer_enabled());
        if writer_direct {
            return Pin::new(&mut self.inner).poll_write(cx, buf);
        }

        let padded = {
            let mut write_once = self.write_once_uuid;
            let padded = {
                let mut traffic = self.traffic.lock().expect("vision traffic lock");
                traffic.pad_downlink_chunk(buf, &mut write_once)
            };
            self.write_once_uuid = write_once;
            padded
        };

        self.pending_write = padded;
        self.pending_original_len = Some(buf.len());

        let original_len = self.pending_original_len.expect("pending original len");
        let pending = self.pending_write.clone();
        match Pin::new(&mut self.inner).poll_write(cx, &pending) {
            Poll::Ready(Ok(0)) => Poll::Ready(Err(Error::new(
                ErrorKind::WriteZero,
                "vision relay underlying write zero",
            ))),
            Poll::Ready(Ok(n)) => {
                let _ = self.pending_write.drain(..n);
                if self.pending_write.is_empty() {
                    self.pending_original_len = None;
                    Poll::Ready(Ok(original_len))
                } else {
                    Poll::Pending
                }
            }
            Poll::Ready(Err(err)) => {
                self.pending_write.clear();
                self.pending_original_len = None;
                Poll::Ready(Err(err))
            }
            Poll::Pending => Poll::Pending,
        }
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.inner).poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.inner).poll_shutdown(cx)
    }
}

#[cfg(test)]
pub fn encode_vision_flow_addons_protobuf() -> Vec<u8> {
    let flow = FLOW_XTLS_RPRX_VISION.as_bytes();
    let mut addons = Vec::with_capacity(2 + flow.len());
    addons.push(0x0a);
    addons.push(flow.len() as u8);
    addons.extend_from_slice(flow);
    addons
}

#[cfg(test)]
pub fn wrap_vision_uplink_block(user_uuid: &[u8; 16], content: &[u8]) -> Vec<u8> {
    let mut write_once = Some(*user_uuid);
    xtls_padding(
        content,
        COMMAND_PADDING_END,
        &mut write_once,
        false,
        UPSTREAM_DEFAULT_TESTSEED,
    )
}

#[cfg(test)]
#[path = "../../tests/unit/vless/vision.rs"]
mod tests;
