use super::*;
use std::thread;
use std::time::Duration as StdDuration;
use tokio::io::AsyncReadExt;

fn test_limits() -> PacketUpLimits {
    PacketUpLimits {
        max_each_post_bytes: 1_000_000,
        max_buffered_posts: 30,
    }
}

async fn take_reader_from_launch(launch: PacketUpBridgeLaunch) -> PacketUpSessionInputReader {
    launch.reader
}

#[test]
fn first_packet_creates_session_second_reuses() {
    let manager = XHttpPacketUpManager::for_test(std::time::Duration::from_secs(30), 8);
    let first = manager
        .begin_upload_packet("session-a", Some(0), test_limits())
        .expect("first");
    assert_eq!(first.session_outcome, XHttpSessionEnsureOutcome::Created);
    assert_eq!(manager.meta_session_count(), 1);

    let second = manager
        .begin_upload_packet("session-a", Some(1), test_limits())
        .expect("second");
    assert_eq!(second.session_outcome, XHttpSessionEnsureOutcome::Reused);
    assert_eq!(manager.meta_session_count(), 1);
}

#[tokio::test]
async fn multiple_packet_bodies_form_continuous_input_stream() {
    let manager = XHttpPacketUpManager::for_test_with_input(
        std::time::Duration::from_secs(30),
        8,
        64 * 1024,
        8,
    );
    let mut p0 = manager
        .begin_upload_packet("session-a", Some(0), test_limits())
        .expect("p0");
    let launch = manager
        .append_upload_chunk(&mut p0, Bytes::from_static(b"hel"))
        .expect("c0")
        .expect("bridge");
    manager.commit_upload_packet(&p0).expect("commit0");
    manager.finish_upload_packet("session-a");

    let mut p1 = manager
        .begin_upload_packet("session-a", Some(1), test_limits())
        .expect("p1");
    manager
        .append_upload_chunk(&mut p1, Bytes::from_static(b"lo"))
        .expect("c1");
    manager.commit_upload_packet(&p1).expect("commit1");
    manager.finish_upload_packet("session-a");
    assert!(!manager.session_input_closed("session-a"));

    let mut reader = take_reader_from_launch(launch).await;
    manager.close_session("session-a", "test_done");
    let mut out = Vec::new();
    reader.read_to_end(&mut out).await.expect("read");
    assert_eq!(out, b"hello");
}

#[tokio::test]
async fn per_request_eof_does_not_close_session() {
    let manager = XHttpPacketUpManager::for_test_with_input(
        std::time::Duration::from_secs(30),
        8,
        64 * 1024,
        8,
    );
    let mut p0 = manager
        .begin_upload_packet("session-a", Some(0), test_limits())
        .expect("p0");
    let bridge_on_append = manager
        .append_upload_chunk(&mut p0, Bytes::from_static(b"aa"))
        .expect("append");
    manager.commit_upload_packet(&p0).expect("commit");
    manager.finish_upload_packet("session-a");
    assert!(!manager.session_input_closed("session-a"));

    let mut p1 = manager
        .begin_upload_packet("session-a", Some(1), test_limits())
        .expect("p1");
    manager
        .append_upload_chunk(&mut p1, Bytes::from_static(b"bb"))
        .expect("append2");
    manager.commit_upload_packet(&p1).expect("commit2");
    manager.finish_upload_packet("session-a");
    assert!(!manager.session_input_closed("session-a"));
    assert!(bridge_on_append.is_some());
}

#[test]
fn idle_timeout_closes_session() {
    let manager = XHttpPacketUpManager::for_test_with_input(
        std::time::Duration::from_millis(20),
        8,
        64 * 1024,
        8,
    );
    manager
        .begin_upload_packet("session-a", Some(0), test_limits())
        .expect("begin");
    thread::sleep(StdDuration::from_millis(30));
    let removed = manager.cleanup_idle_sessions();
    assert_eq!(removed, 1);
    assert!(manager.meta.get("session-a").is_err());
}

#[tokio::test]
async fn backpressure_is_bounded() {
    let manager =
        XHttpPacketUpManager::for_test_with_input(std::time::Duration::from_secs(30), 8, 64, 2);
    let mut handle = manager
        .begin_upload_packet("session-a", Some(0), test_limits())
        .expect("begin");
    let _launch = manager
        .append_upload_chunk(&mut handle, Bytes::from(vec![0u8; 32]))
        .expect("chunk1")
        .expect("bridge");
    manager
        .append_upload_chunk(&mut handle, Bytes::from(vec![0u8; 32]))
        .expect("chunk2");
    assert!(matches!(
        manager.append_upload_chunk(&mut handle, Bytes::from(vec![0u8; 16])),
        Err(PacketUpUploadError::Backpressure)
    ));
}

#[tokio::test]
async fn vless_bridge_starts_once_per_session() {
    let manager = XHttpPacketUpManager::for_test_with_input(
        std::time::Duration::from_secs(30),
        8,
        64 * 1024,
        8,
    );
    let mut first = manager
        .begin_upload_packet("session-a", Some(0), test_limits())
        .expect("begin");
    let bridge_on_first_append = manager
        .append_upload_chunk(&mut first, Bytes::from_static(b"a"))
        .expect("append");
    let outcome = manager.commit_upload_packet(&first).expect("commit");
    assert!(bridge_on_first_append.is_some());
    assert!(outcome.bridge_launch.is_none());
    assert!(manager.bridge_started_for("session-a"));

    let mut second = manager
        .begin_upload_packet("session-a", Some(1), test_limits())
        .expect("begin2");
    manager
        .append_upload_chunk(&mut second, Bytes::from_static(b"b"))
        .expect("append2");
    let outcome = manager.commit_upload_packet(&second).expect("commit2");
    assert!(outcome.bridge_launch.is_none());
}

#[tokio::test]
async fn body_chunks_appended_in_seq_order() {
    let manager = XHttpPacketUpManager::for_test_with_input(
        std::time::Duration::from_secs(30),
        8,
        64 * 1024,
        8,
    );
    let mut seq1 = manager
        .begin_upload_packet("session-a", Some(1), test_limits())
        .expect("begin1");
    manager
        .append_upload_chunk(&mut seq1, Bytes::from_static(b"b"))
        .expect("append1");
    manager.commit_upload_packet(&seq1).expect("commit1");

    let mut seq0 = manager
        .begin_upload_packet("session-a", Some(0), test_limits())
        .expect("begin0");
    let launch = manager
        .append_upload_chunk(&mut seq0, Bytes::from_static(b"a"))
        .expect("append0")
        .expect("bridge");
    manager.commit_upload_packet(&seq0).expect("commit0");
    let mut reader = take_reader_from_launch(launch).await;
    manager.close_session("session-a", "test_done");
    let mut out = Vec::new();
    reader.read_to_end(&mut out).await.expect("read");
    assert_eq!(out, b"ab");
}

#[tokio::test]
async fn vless_handler_close_cleans_session() {
    let manager = XHttpPacketUpManager::for_test_with_input(
        std::time::Duration::from_secs(30),
        8,
        64 * 1024,
        8,
    );
    let mut handle = manager
        .begin_upload_packet("session-a", Some(0), test_limits())
        .expect("begin");
    let launch = manager
        .append_upload_chunk(&mut handle, Bytes::from_static(b"x"))
        .expect("append")
        .expect("launch");
    manager.commit_upload_packet(&handle).expect("commit");
    drop(launch.reader);
    manager.close_session("session-a", "test_reader_drop");
    assert!(manager.meta.get("session-a").is_err());
}

#[tokio::test]
async fn buffered_posts_limit_is_enforced() {
    let manager = XHttpPacketUpManager::for_test_with_input(
        std::time::Duration::from_secs(30),
        8,
        64 * 1024,
        8,
    );
    let limits = PacketUpLimits {
        max_each_post_bytes: 1_000_000,
        max_buffered_posts: 1,
    };
    let _ = manager
        .begin_upload_packet("session-a", Some(0), limits)
        .expect("seq0");
    let _ = manager
        .begin_upload_packet("session-a", Some(2), limits)
        .expect("seq2");
    let err = manager
        .begin_upload_packet("session-a", Some(3), limits)
        .unwrap_err();
    assert_eq!(err, XHttpSessionError::MaxSessionsReached);
}

#[tokio::test]
async fn download_bind_and_broadcast_delivers_bytes() {
    let manager = XHttpPacketUpManager::for_test(std::time::Duration::from_secs(30), 8);
    let runtime = manager.get_or_create_runtime("session-a");
    let mut rx = manager.bind_download_session("session-a").expect("bind");
    broadcast_download(&runtime, Bytes::from_static(b"down"));
    let chunk = rx.recv().await.expect("chunk");
    assert_eq!(&chunk[..], b"down");
}

#[tokio::test]
async fn disconnect_cleans_download_listener() {
    let manager = XHttpPacketUpManager::for_test(std::time::Duration::from_secs(30), 8);
    let _ = manager.bind_download_session("session-a").expect("bind");
    manager.detach_download_session("session-a");
    let _ = manager
        .bind_download_session("session-a")
        .expect("rebind after detach");
}
#[tokio::test]
async fn large_packet_stream_does_not_full_buffer() {
    let manager = XHttpPacketUpManager::for_test_with_input(
        std::time::Duration::from_secs(30),
        8,
        8 * 1024,
        4,
    );
    let mut handle = manager
        .begin_upload_packet("session-a", Some(0), test_limits())
        .expect("begin");
    let launch = manager
        .append_upload_chunk(&mut handle, Bytes::from(vec![0xCDu8; 512]))
        .expect("first chunk")
        .expect("bridge");
    let mut reader = take_reader_from_launch(launch).await;

    let read_task = tokio::spawn(async move {
        let mut total = 0usize;
        let mut buf = [0u8; 1024];
        loop {
            let n = reader.read(&mut buf).await.expect("read");
            if n == 0 {
                break;
            }
            total += n;
        }
        total
    });

    for _ in 1..64 {
        loop {
            match manager.append_upload_chunk(&mut handle, Bytes::from(vec![0xCDu8; 512])) {
                Ok(_) => break,
                Err(PacketUpUploadError::Backpressure) => {
                    tokio::task::yield_now().await;
                }
                Err(err) => panic!("chunk: {err}"),
            }
        }
    }
    manager.commit_upload_packet(&handle).expect("commit");
    manager.finish_upload_packet("session-a");
    manager.close_session("session-a", "test_done");

    let total = read_task.await.expect("read task");
    assert_eq!(total, 64 * 512);
}
