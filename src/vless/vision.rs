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
const DEFAULT_TESTSEED: [u32; 4] = [900, 500, 6, 900];

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
    pub fn new(user_uuid: [u8; 16]) -> Self {
        Self {
            user_uuid,
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

        xtls_padding(content, command, write_once_uuid, long_padding)
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

pub fn new_shared_traffic_state(user_uuid: [u8; 16]) -> SharedTrafficState {
    Arc::new(Mutex::new(TrafficState::new(user_uuid)))
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
) -> Vec<u8> {
    let content_len = content.len();
    let mut padding_len = random_padding_len(content_len, long_padding);
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

    debug!(
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

        debug!(
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
                info!("vision direct command received");
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

fn random_padding_len(content_len: usize, long_padding: bool) -> usize {
    let mut bytes = [0u8; 2];
    let _ = getrandom::getrandom(&mut bytes);
    let random = u16::from_be_bytes(bytes) as usize;
    if content_len < DEFAULT_TESTSEED[0] as usize && long_padding {
        random
            .saturating_add(DEFAULT_TESTSEED[2] as usize)
            .saturating_sub(content_len)
    } else {
        random % (DEFAULT_TESTSEED[3] as usize + 1)
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
    xtls_padding(content, COMMAND_PADDING_END, &mut write_once, false)
}

#[cfg(test)]
mod tests {
    use super::*;

    const USER_UUID: [u8; 16] = [0x11; 16];

    #[test]
    fn vision_padding_roundtrip_single_block() {
        let content = b"hello-vision-payload";
        let framed = wrap_vision_uplink_block(&USER_UUID, content);
        let mut state = TrafficState::new(USER_UUID);
        let plain = state.unpad_uplink_chunk(&framed).unwrap();
        assert_eq!(plain, content);
        assert!(!state.inbound.within_padding_buffers);
    }

    #[test]
    fn vision_padding_roundtrip_multiple_blocks() {
        let mut state = TrafficState::new(USER_UUID);
        let mut write_once = Some(USER_UUID);
        let first = xtls_padding(
            b"part-one",
            COMMAND_PADDING_CONTINUE,
            &mut write_once,
            false,
        );
        let second = xtls_padding(b"part-two", COMMAND_PADDING_END, &mut None, false);

        let out1 = state.unpad_uplink_chunk(&first).unwrap();
        assert_eq!(out1, b"part-one");
        assert!(state.inbound.within_padding_buffers);
        let out2 = state.unpad_uplink_chunk(&second).unwrap();
        assert_eq!(out2, b"part-two");
        assert!(!state.inbound.within_padding_buffers);
    }

    #[test]
    fn unpad_inbound_test_shape_roundtrip() {
        let user_id = [0x11; 16];
        let tls_client_hello = [0x16, 0x03, 0x01, 0x00, 0x10, 0x01, 0x02];
        let framed = wrap_vision_uplink_block(&user_id, &tls_client_hello);
        let mut state = TrafficState::new(user_id);
        assert_eq!(
            state.unpad_uplink_chunk(&framed).unwrap(),
            tls_client_hello.to_vec()
        );
    }

    #[test]
    fn vision_unpadding_fragmented_frame() {
        let mut write_once = Some(USER_UUID);
        let framed = xtls_padding(b"fragment-me", COMMAND_PADDING_END, &mut write_once, false);
        let mut state = TrafficState::new(USER_UUID);
        let split = 10;
        let part1 = state.unpad_uplink_chunk(&framed[..split]).unwrap();
        assert!(part1.is_empty());
        let part2 = state.unpad_uplink_chunk(&framed[split..]).unwrap();
        assert_eq!(part2, b"fragment-me");
    }

    #[test]
    fn vision_unpadding_direct_command() {
        let mut framed = Vec::new();
        framed.extend_from_slice(&USER_UUID);
        framed.push(COMMAND_PADDING_DIRECT);
        framed.extend_from_slice(&(4u16).to_be_bytes());
        framed.extend_from_slice(&0u16.to_be_bytes());
        framed.extend_from_slice(b"tail");

        let mut state = TrafficState::new(USER_UUID);
        let plain = state.unpad_uplink_chunk(&framed).unwrap();
        assert_eq!(plain, b"tail");
        assert!(!state.inbound.within_padding_buffers);
        assert!(state.inbound.direct_copy);
    }

    #[test]
    fn vision_unpadding_direct_command_sets_signal() {
        let mut framed = Vec::new();
        framed.extend_from_slice(&USER_UUID);
        framed.push(COMMAND_PADDING_DIRECT);
        framed.extend_from_slice(&(4u16).to_be_bytes());
        framed.extend_from_slice(&0u16.to_be_bytes());
        framed.extend_from_slice(b"tail");

        let mut state = TrafficState::new(USER_UUID);
        let (plain, signal) = state.unpad_uplink_chunk_with_signal(&framed).unwrap();
        assert_eq!(plain, b"tail");
        assert_eq!(signal, Some(VisionDirectStarted));
    }

    #[test]
    fn vision_downlink_sends_direct_when_xtls_enabled() {
        let mut state = TrafficState::new(USER_UUID);
        state.enable_xtls = true;
        state.is_tls = true;
        state.is_tls12_or_above = true;
        let tls_app = [0x17, 0x03, 0x03, 0x00, 0x05, 0x01, 0x02, 0x03, 0x04, 0x05];
        let padded = state.pad_downlink_chunk(&tls_app, &mut Some(USER_UUID));
        assert!(padded.starts_with(&USER_UUID));
        assert_eq!(padded[16], COMMAND_PADDING_DIRECT);
        assert!(state.inbound.downlink_writer_direct_pending);
        assert!(!state.inbound.is_padding);
    }

    #[test]
    fn vision_downlink_keeps_padding_after_uplink_direct() {
        let mut state = TrafficState::new(USER_UUID);
        state.inbound.direct_copy = true;
        state.inbound.is_padding = true;
        let padded = state.pad_downlink_chunk(b"still-padded", &mut Some(USER_UUID));
        assert_ne!(padded, b"still-padded");
        assert!(state.inbound.is_padding);
    }

    #[test]
    fn vision_reject_udp_is_inbound_validation() {
        use crate::vless::protocol::VlessCommand;

        let err = crate::vless::inbound::validate_vless_flow_for_command(
            Some(FLOW_XTLS_RPRX_VISION),
            Some(FLOW_XTLS_RPRX_VISION),
            VlessCommand::Udp,
        )
        .unwrap_err();
        assert!(err.to_string().contains("UDP"));
    }

    #[test]
    fn account_requires_vision_rejects_empty_flow() {
        use crate::vless::protocol::VlessCommand;

        let err = crate::vless::inbound::validate_vless_flow_for_command(
            None,
            Some(FLOW_XTLS_RPRX_VISION),
            VlessCommand::Tcp,
        )
        .unwrap_err();
        assert!(err.to_string().contains("empty"));
    }

    #[test]
    fn parse_vision_flow_from_protobuf_addons() {
        let addons = encode_vision_flow_addons_protobuf();
        assert_eq!(
            parse_vless_request_flow(&addons).as_deref(),
            Some(FLOW_XTLS_RPRX_VISION)
        );
    }

    #[test]
    fn xtls_filter_detects_client_hello() {
        let mut state = TrafficState::new(USER_UUID);
        let client_hello = [0x16, 0x03, 0x01, 0x00, 0x05, 0x01, 0x00, 0x00, 0x01];
        xtls_filter_tls(&client_hello, &mut state);
        assert!(state.is_tls);
    }

    /// Underlying writer that performs one partial write, stalls once on the next
    /// attempt, then accepts the full remainder — simulating backpressure without
    /// hanging the test.
    struct PartialWriteMock {
        data: Vec<u8>,
        chunk_size: usize,
        writes: usize,
    }

    impl PartialWriteMock {
        fn new(chunk_size: usize) -> Self {
            Self {
                data: Vec::new(),
                chunk_size,
                writes: 0,
            }
        }
    }

    impl AsyncWrite for PartialWriteMock {
        fn poll_write(
            mut self: Pin<&mut Self>,
            _cx: &mut Context<'_>,
            buf: &[u8],
        ) -> Poll<std::io::Result<usize>> {
            if buf.is_empty() {
                return Poll::Ready(Ok(0));
            }

            if self.writes == 1 {
                self.writes += 1;
                return Poll::Pending;
            }

            let n = if self.writes == 0 {
                buf.len().min(self.chunk_size)
            } else {
                buf.len()
            };
            self.data.extend_from_slice(&buf[..n]);
            self.writes += 1;
            Poll::Ready(Ok(n))
        }

        fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
            Poll::Ready(Ok(()))
        }

        fn poll_shutdown(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
            Poll::Ready(Ok(()))
        }
    }

    fn noop_waker() -> std::task::Waker {
        use std::task::{RawWaker, RawWakerVTable, Waker};
        static VTABLE: RawWakerVTable = RawWakerVTable::new(
            |_| RawWaker::new(std::ptr::null(), &VTABLE),
            |_| {},
            |_| {},
            |_| {},
        );
        unsafe { Waker::from_raw(RawWaker::new(std::ptr::null(), &VTABLE)) }
    }

    #[test]
    fn vision_relay_write_survives_partial_write_backpressure() {
        let traffic = new_shared_traffic_state(USER_UUID);
        let inner = PartialWriteMock::new(7);
        let mut relay = VisionRelayStream::new(inner, Arc::clone(&traffic), USER_UUID, None);

        let waker = noop_waker();
        let mut cx = Context::from_waker(&waker);
        let payload = b"downlink-payload-for-partial-write-test";

        match Pin::new(&mut relay).poll_write(&mut cx, payload) {
            Poll::Pending => {}
            other => panic!("expected Pending while padded frame incomplete, got {other:?}"),
        }

        assert!(
            !relay.pending_write.is_empty(),
            "partial write must retain pending padded bytes"
        );
        assert_eq!(relay.pending_original_len, Some(payload.len()));
        let mut expected_frame = relay.inner.data.clone();
        expected_frame.extend_from_slice(&relay.pending_write);

        let mut completed = false;
        for _ in 0..8 {
            match Pin::new(&mut relay).poll_write(&mut cx, payload) {
                Poll::Ready(Ok(written)) => {
                    assert_eq!(written, payload.len());
                    completed = true;
                    break;
                }
                Poll::Pending => continue,
                other => panic!("expected completed write, got {other:?}"),
            }
        }
        assert!(
            completed,
            "vision relay write must complete after backpressure"
        );

        assert!(relay.pending_write.is_empty());
        assert_eq!(
            relay.inner.data, expected_frame,
            "partial writes must deliver the full padded Vision frame"
        );
    }
}
