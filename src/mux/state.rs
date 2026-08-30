use std::time::Instant;

use tokio::io::{AsyncWrite, AsyncWriteExt};
use tokio::sync::mpsc;
use tracing::debug;

use crate::mux::frame::MuxUdpDnsLatencyTrace;
use crate::mux::routed_udp::MUX_UDP_RESPONSE_QUEUE_CAPACITY;

pub(crate) type MuxOutTx = mpsc::Sender<MuxFrameActions>;

pub(crate) fn mux_response_channel() -> (MuxOutTx, mpsc::Receiver<MuxFrameActions>) {
    mpsc::channel(MUX_UDP_RESPONSE_QUEUE_CAPACITY)
}

/// Outbound mux frames plus optional first-DNS latency trace for DEBUG diagnostics.
pub(crate) struct MuxFrameActions {
    pub frames: Vec<Vec<u8>>,
    pub dns_latency_trace: Option<MuxUdpDnsLatencyTrace>,
}

pub(crate) fn mux_actions(frames: Vec<Vec<u8>>) -> MuxFrameActions {
    MuxFrameActions {
        frames,
        dns_latency_trace: None,
    }
}

pub(crate) fn mux_dns_actions(
    response: Vec<u8>,
    end: Option<Vec<u8>>,
    trace: MuxUdpDnsLatencyTrace,
) -> MuxFrameActions {
    let mut frames = vec![response];
    if let Some(end) = end {
        frames.push(end);
    }
    MuxFrameActions {
        frames,
        dns_latency_trace: Some(trace),
    }
}

pub(crate) async fn write_mux_out_frames<S>(
    stream: &mut S,
    actions: &MuxFrameActions,
) -> std::io::Result<()>
where
    S: AsyncWrite + Unpin,
{
    let frames = &actions.frames;
    if frames.is_empty() {
        return Ok(());
    }
    if let Some(trace) = actions.dns_latency_trace {
        let response_started = Instant::now();
        debug!(
            conn_id = trace.conn_id,
            mux_id = trace.mux_id,
            frame_bytes = frames[0].len(),
            elapsed_ms_since_conn_start = trace
                .conn_started
                .map(|started| started.elapsed().as_millis()),
            total_latency_ms = trace.received_at.elapsed().as_millis(),
            "mux udp dns response frame write started"
        );
        stream.write_all(&frames[0]).await?;
        stream.flush().await?;
        debug!(
            conn_id = trace.conn_id,
            mux_id = trace.mux_id,
            frame_bytes = frames[0].len(),
            write_ms = response_started.elapsed().as_millis(),
            total_latency_ms = trace.received_at.elapsed().as_millis(),
            elapsed_ms_since_conn_start = trace
                .conn_started
                .map(|started| started.elapsed().as_millis()),
            "mux udp dns response frame write done"
        );
        debug!(
            conn_id = trace.conn_id,
            mux_id = trace.mux_id,
            frame_bytes = frames[0].len(),
            write_ms = response_started.elapsed().as_millis(),
            total_latency_ms = trace.received_at.elapsed().as_millis(),
            elapsed_ms_since_conn_start = trace
                .conn_started
                .map(|started| started.elapsed().as_millis()),
            "mux udp dns response frame written"
        );
        if frames.len() > 1 {
            for close_frame in &frames[1..] {
                let close_started = Instant::now();
                stream.write_all(close_frame).await?;
                stream.flush().await?;
                debug!(
                    conn_id = trace.conn_id,
                    mux_id = trace.mux_id,
                    frame_bytes = close_frame.len(),
                    write_ms = close_started.elapsed().as_millis(),
                    elapsed_ms_since_conn_start = trace
                        .conn_started
                        .map(|started| started.elapsed().as_millis()),
                    "mux udp dns close frame sent"
                );
            }
        } else {
            debug!(
                conn_id = trace.conn_id,
                mux_id = trace.mux_id,
                reason = "success_response_default",
                "mux udp dns close frame skipped"
            );
        }
        debug!(
            conn_id = trace.conn_id,
            mux_id = trace.mux_id,
            elapsed_ms_since_conn_start = trace
                .conn_started
                .map(|started| started.elapsed().as_millis()),
            "mux session remains open after udp dns response"
        );
        return Ok(());
    }
    if frames.len() == 1 {
        stream.write_all(&frames[0]).await?;
    } else {
        let total: usize = frames.iter().map(Vec::len).sum();
        let mut buf = Vec::with_capacity(total);
        for frame in frames {
            buf.extend_from_slice(frame);
        }
        stream.write_all(&buf).await?;
    }
    stream.flush().await?;
    Ok(())
}
