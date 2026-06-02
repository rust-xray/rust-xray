use super::*;
use crate::transport::xhttp::session::{XHttpSessionEnsureOutcome, XHttpSessionError};
use std::thread;
use std::time::Duration as StdDuration;
use tokio::io::AsyncReadExt;

fn test_limits() -> StreamUpLimits {
    StreamUpLimits {
        max_upload_bytes: 1_000_000,
    }
}

async fn take_reader_from_launch(launch: StreamUpBridgeLaunch) -> PacketUpSessionInputReader {
    launch.reader
}

#[test]
fn first_upload_creates_session_second_reuses() {
    let manager = XHttpStreamUpManager::for_test(std::time::Duration::from_secs(30), 8);
    let first = manager
        .attach_upload("session-a", test_limits())
        .expect("first");
    assert_eq!(first.session_outcome, XHttpSessionEnsureOutcome::Created);
    manager.finish_upload("session-a");

    let second = manager
        .attach_upload("session-a", test_limits())
        .expect("second");
    assert_eq!(second.session_outcome, XHttpSessionEnsureOutcome::Reused);
}

#[tokio::test]
async fn valid_get_download_attaches_to_session() {
    let manager = XHttpStreamUpManager::for_test(std::time::Duration::from_secs(30), 8);
    let mut rx = manager.bind_download_session("session-a").expect("bind");
    let runtime = manager.get_or_create_runtime("session-a");
    broadcast_download(&runtime, Bytes::from_static(b"down"));
    let chunk = rx.recv().await.expect("chunk");
    assert_eq!(&chunk[..], b"down");
}

#[tokio::test]
async fn valid_post_upload_attaches_to_same_session() {
    let manager = XHttpStreamUpManager::for_test_with_input(
        std::time::Duration::from_secs(30),
        8,
        64 * 1024,
        8,
    );
    let mut upload = manager
        .attach_upload("session-a", test_limits())
        .expect("attach");
    let launch = manager
        .launch_upload_bridge("session-a")
        .expect("launch result")
        .expect("bridge");
    manager
        .append_upload_chunk(&mut upload, Bytes::from_static(b"up"))
        .expect("append");
    manager.finish_upload("session-a");
    let mut reader = take_reader_from_launch(launch).await;
    manager.close_session("session-a", "test_done");
    let mut out = Vec::new();
    reader.read_to_end(&mut out).await.expect("read");
    assert_eq!(out, b"up");
}

#[tokio::test]
async fn get_before_post_does_not_hang_forever() {
    let manager = XHttpStreamUpManager::for_test(std::time::Duration::from_secs(30), 8);
    let mut rx = manager.bind_download_session("session-a").expect("bind");
    let recv = tokio::time::timeout(std::time::Duration::from_millis(50), rx.recv()).await;
    assert!(
        recv.is_err(),
        "GET should not block forever without downstream data"
    );
}

#[tokio::test]
async fn post_before_get_does_not_lose_downstream() {
    let manager = XHttpStreamUpManager::for_test(std::time::Duration::from_secs(30), 8);
    let runtime = manager.get_or_create_runtime("session-a");
    broadcast_download(&runtime, Bytes::from_static(b"early"));
    let mut rx = manager.bind_download_session("session-a").expect("bind");
    let chunk = rx.recv().await.expect("chunk");
    assert_eq!(&chunk[..], b"early");
}

#[tokio::test]
async fn duplicate_get_is_rejected_deterministically() {
    let manager = XHttpStreamUpManager::for_test(std::time::Duration::from_secs(30), 8);
    let _first = manager.bind_download_session("session-dup").expect("first");
    let err = manager.bind_download_session("session-dup").unwrap_err();
    assert_eq!(err, XHttpSessionError::DownloadAlreadyAttached);
}

#[tokio::test]
async fn duplicate_post_is_rejected_deterministically() {
    let manager = XHttpStreamUpManager::for_test(std::time::Duration::from_secs(30), 8);
    let _first = manager
        .attach_upload("session-dup", test_limits())
        .expect("first");
    let err = manager
        .attach_upload("session-dup", test_limits())
        .unwrap_err();
    assert_eq!(err, XHttpSessionError::UploadAlreadyAttached);
}

#[tokio::test]
async fn disconnect_get_cleans_session() {
    let manager = XHttpStreamUpManager::for_test(std::time::Duration::from_secs(30), 8);
    let _rx = manager.bind_download_session("session-a").expect("bind");
    manager.detach_download_session("session-a");
    manager.close_session("session-a", "download_disconnected");
    assert!(manager.meta.get("session-a").is_err());
}

#[tokio::test]
async fn disconnect_post_cleans_session() {
    let manager = XHttpStreamUpManager::for_test_with_input(
        std::time::Duration::from_secs(30),
        8,
        64 * 1024,
        8,
    );
    let mut upload = manager
        .attach_upload("session-a", test_limits())
        .expect("attach");
    let _launch = manager
        .launch_upload_bridge("session-a")
        .expect("launch result")
        .expect("launch");
    manager
        .append_upload_chunk(&mut upload, Bytes::from_static(b"x"))
        .expect("append");
    manager.finish_upload("session-a");
    manager.close_session("session-a", "upload_disconnected");
    assert!(manager.meta.get("session-a").is_err());
}

#[test]
fn idle_timeout_closes_session() {
    let manager = XHttpStreamUpManager::for_test_with_input(
        std::time::Duration::from_millis(20),
        8,
        64 * 1024,
        8,
    );
    manager
        .attach_upload("session-a", test_limits())
        .expect("attach");
    manager.finish_upload("session-a");
    thread::sleep(StdDuration::from_millis(30));
    let removed = manager.cleanup_idle_sessions();
    assert_eq!(removed, 1);
    assert!(manager.meta.get("session-a").is_err());
}

#[tokio::test]
async fn backpressure_is_bounded() {
    let manager =
        XHttpStreamUpManager::for_test_with_input(std::time::Duration::from_secs(30), 8, 64, 2);
    let mut handle = manager
        .attach_upload("session-a", test_limits())
        .expect("attach");
    let _launch = manager
        .launch_upload_bridge("session-a")
        .expect("launch result")
        .expect("bridge");
    manager
        .append_upload_chunk(&mut handle, Bytes::from(vec![0u8; 32]))
        .expect("chunk1");
    manager
        .append_upload_chunk(&mut handle, Bytes::from(vec![0u8; 32]))
        .expect("chunk2");
    assert!(matches!(
        manager.append_upload_chunk(&mut handle, Bytes::from(vec![0u8; 16])),
        Err(StreamUpUploadError::Backpressure)
    ));
}
