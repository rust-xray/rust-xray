
use super::*;
use tokio::io::AsyncReadExt;

#[tokio::test]
async fn multiple_packet_bodies_form_continuous_input_stream() {
    let input = PacketUpBoundedInput::for_test(16 * 1024, 8);
    let mut reader = input.take_reader().expect("reader");

    input
        .try_write_chunk(Bytes::from_static(b"hel"))
        .expect("chunk1");
    input
        .try_write_chunk(Bytes::from_static(b"lo"))
        .expect("chunk2");
    input
        .try_write_chunk(Bytes::from_static(b" world"))
        .expect("chunk3");
    input.close();

    let mut out = Vec::new();
    reader.read_to_end(&mut out).await.expect("read");
    assert_eq!(out, b"hello world");
}

#[tokio::test]
async fn per_request_eof_does_not_close_session_input() {
    let input = PacketUpBoundedInput::for_test(16 * 1024, 8);
    let mut reader = input.take_reader().expect("reader");

    input
        .try_write_chunk(Bytes::from_static(b"first"))
        .expect("first packet");
    let mut buf = [0u8; 16];
    let n = reader.read(&mut buf).await.expect("read first");
    assert_eq!(n, 5);
    assert_eq!(&buf[..n], b"first");
    assert!(!input.is_closed());

    input
        .try_write_chunk(Bytes::from_static(b"second"))
        .expect("second packet");
    let n = reader.read(&mut buf).await.expect("read second");
    assert_eq!(n, 6);
    assert_eq!(&buf[..n], b"second");
    assert!(!input.is_closed());
}

#[tokio::test]
async fn explicit_close_ends_reader_stream() {
    let input = PacketUpBoundedInput::for_test(16 * 1024, 8);
    let mut reader = input.take_reader().expect("reader");
    input
        .try_write_chunk(Bytes::from_static(b"abc"))
        .expect("chunk");
    input.close();
    assert!(input.is_closed());
    assert!(matches!(
        input.try_write_chunk(Bytes::from_static(b"x")),
        Err(PacketUpInputError::SessionClosed)
    ));

    let mut out = Vec::new();
    reader.read_to_end(&mut out).await.expect("read");
    assert_eq!(out, b"abc");
}

#[tokio::test]
async fn backpressure_is_bounded() {
    let input = PacketUpBoundedInput::for_test(64, 2);
    let _reader = input.take_reader().expect("reader");
    input
        .try_write_chunk(Bytes::from(vec![0u8; 32]))
        .expect("chunk1");
    input
        .try_write_chunk(Bytes::from(vec![0u8; 32]))
        .expect("chunk2");
    assert!(matches!(
        input.try_write_chunk(Bytes::from(vec![0u8; 16])),
        Err(PacketUpInputError::Backpressure)
    ));
    assert!(input.queued_bytes() <= 64);
}

#[tokio::test]
async fn large_packet_stream_does_not_require_full_buffer() {
    let input = PacketUpBoundedInput::for_test(8 * 1024, 4);
    let mut reader = input.take_reader().expect("reader");
    let write_task = tokio::spawn(async move {
        for part in (0..64).map(|_| Bytes::from(vec![0xABu8; 512])) {
            loop {
                match input.try_write_chunk(part.clone()) {
                    Ok(()) => break,
                    Err(PacketUpInputError::Backpressure) => {
                        tokio::task::yield_now().await;
                    }
                    Err(err) => panic!("write failed: {err}"),
                }
            }
        }
        input.close();
    });

    let mut total = 0usize;
    let mut buf = [0u8; 4096];
    loop {
        let n = reader.read(&mut buf).await.expect("read");
        if n == 0 {
            break;
        }
        total += n;
    }
    write_task.await.expect("write task");
    assert_eq!(total, 64 * 512);
}

#[tokio::test]
async fn reader_drop_releases_queued_byte_accounting() {
    let input = PacketUpBoundedInput::for_test(16 * 1024, 4);
    {
        let _reader = input.take_reader().expect("reader");
        input
            .try_write_chunk(Bytes::from_static(b"abc"))
            .expect("chunk");
        assert_eq!(input.queued_bytes(), 3);
    }
    // writer still open; queued bytes remain until consumed or session closed
    assert_eq!(input.queued_bytes(), 3);
}
