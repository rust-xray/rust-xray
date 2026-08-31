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

#[tokio::test]
async fn vision_relay_reader_enables_tls_direct_relay_on_direct_command() {
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::sync::Arc;

    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    use crate::reality::tls13::ApplicationStreamDirectRelay;

    let traffic = new_shared_traffic_state(USER_UUID);
    let reader_flag = Arc::new(AtomicBool::new(false));
    let writer_flag = Arc::new(AtomicBool::new(false));
    let direct_relay =
        ApplicationStreamDirectRelay::from_shared(Arc::clone(&reader_flag), writer_flag);

    let mut framed = Vec::new();
    framed.extend_from_slice(&USER_UUID);
    framed.push(COMMAND_PADDING_DIRECT);
    framed.extend_from_slice(&(4u16).to_be_bytes());
    framed.extend_from_slice(&0u16.to_be_bytes());
    framed.extend_from_slice(b"tail");

    let (mut client, server) = tokio::io::duplex(4096);
    client.write_all(&framed).await.expect("write framed");
    drop(client);

    let mut reader = VisionRelayReader::new(server, traffic, Some(direct_relay));
    let mut out = [0u8; 16];
    let read = reader.read(&mut out).await.expect("read unpadded");
    assert_eq!(&out[..read], b"tail");
    assert!(reader_flag.load(Ordering::SeqCst));
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
