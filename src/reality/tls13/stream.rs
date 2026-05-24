//! TLS 1.3 application-data stream adapter skeleton for the REALITY accepted path.
//!
//! This wraps an underlying byte stream, decrypting client ApplicationData records into
//! plaintext reads and encrypting plaintext writes into server ApplicationData records.
//!
//! # Limitations
//!
//! - One TLS record per [`AsyncWrite::poll_write`] call; no coalescing or partial-plaintext
//!   write buffering beyond the encrypted record write buffer.
//! - Reads at least one full TLS record before returning decrypted plaintext.
//! - No KeyUpdate, post-handshake messages, or alert handling.
//! - Wired into VLESS via `handle_vless_tcp_inbound` on the REALITY accepted path.

use std::io;
use std::pin::Pin;
use std::task::{Context, Poll};

use bytes::BytesMut;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadBuf};

use crate::tls::{TlsRecord, TlsRecordContentType};

use super::record_crypto::{Tls13RecordDecryptor, Tls13RecordEncryptor};

const TLS_RECORD_HEADER_LEN: usize = 5;

fn parse_tls_record_content_type(byte: u8) -> TlsRecordContentType {
    match byte {
        20 => TlsRecordContentType::ChangeCipherSpec,
        21 => TlsRecordContentType::Alert,
        22 => TlsRecordContentType::Handshake,
        23 => TlsRecordContentType::ApplicationData,
        other => TlsRecordContentType::Unknown(other),
    }
}

/// Reads one complete TLS record from an async byte stream.
pub(crate) async fn read_tls_record_from_stream<S>(stream: &mut S) -> io::Result<TlsRecord>
where
    S: AsyncRead + Unpin,
{
    let mut header = [0u8; TLS_RECORD_HEADER_LEN];
    stream.read_exact(&mut header).await?;

    let payload_len = u16::from_be_bytes([header[3], header[4]]) as usize;
    let mut payload = vec![0u8; payload_len];
    stream.read_exact(&mut payload).await?;

    let mut raw = Vec::with_capacity(TLS_RECORD_HEADER_LEN + payload.len());
    raw.extend_from_slice(&header);
    raw.extend_from_slice(&payload);

    Ok(TlsRecord {
        content_type: parse_tls_record_content_type(header[0]),
        legacy_version: [header[1], header[2]],
        payload,
        raw,
    })
}

/// REALITY TLS 1.3 application-data stream adapter.
pub struct RealityTls13ApplicationStream<S> {
    inner: S,
    read_decryptor: Tls13RecordDecryptor,
    write_encryptor: Tls13RecordEncryptor,
    plaintext_read_buf: BytesMut,
    ciphertext_read_buf: BytesMut,
    ciphertext_write_buf: BytesMut,
    pending_write_plaintext_len: Option<usize>,
}

impl<S> RealityTls13ApplicationStream<S> {
    pub fn new(
        inner: S,
        read_decryptor: Tls13RecordDecryptor,
        write_encryptor: Tls13RecordEncryptor,
    ) -> Self {
        Self {
            inner,
            read_decryptor,
            write_encryptor,
            plaintext_read_buf: BytesMut::new(),
            ciphertext_read_buf: BytesMut::new(),
            ciphertext_write_buf: BytesMut::new(),
            pending_write_plaintext_len: None,
        }
    }

    pub fn inner(&self) -> &S {
        &self.inner
    }

    pub fn inner_mut(&mut self) -> &mut S {
        &mut self.inner
    }

    pub fn into_inner(self) -> S {
        self.inner
    }

    /// Reads and decrypts one client ApplicationData record.
    pub async fn read_plaintext_chunk(&mut self) -> io::Result<Vec<u8>>
    where
        S: AsyncRead + Unpin,
    {
        let record = self.read_tls_record().await?;
        self.read_decryptor.decrypt_application_data_record(&record)
    }

    /// Encrypts and writes one server ApplicationData record.
    pub async fn write_plaintext_all(&mut self, data: &[u8]) -> io::Result<()>
    where
        S: AsyncWrite + Unpin,
    {
        let record = self.write_encryptor.encrypt_application_data(data)?;
        self.inner.write_all(&record).await?;
        Ok(())
    }

    async fn read_tls_record(&mut self) -> io::Result<TlsRecord>
    where
        S: AsyncRead + Unpin,
    {
        loop {
            if let Some(record) = try_take_tls_record(&mut self.ciphertext_read_buf)? {
                return Ok(record);
            }

            let mut chunk = [0u8; 4096];
            let read = self.inner.read(&mut chunk).await?;
            if read == 0 {
                return Err(io::Error::new(
                    io::ErrorKind::UnexpectedEof,
                    "TLS 1.3 application stream closed before a complete record",
                ));
            }
            self.ciphertext_read_buf.extend_from_slice(&chunk[..read]);
        }
    }

    fn fill_plaintext_read_buf(&mut self, cx: &mut Context<'_>) -> Poll<io::Result<()>>
    where
        S: AsyncRead + Unpin,
    {
        if !self.plaintext_read_buf.is_empty() {
            return Poll::Ready(Ok(()));
        }

        let record = match poll_read_tls_record(
            Pin::new(&mut self.inner),
            &mut self.ciphertext_read_buf,
            cx,
        )? {
            Poll::Pending => return Poll::Pending,
            Poll::Ready(record) => record,
        };

        let plaintext = self
            .read_decryptor
            .decrypt_application_data_record(&record)?;
        self.plaintext_read_buf.extend_from_slice(&plaintext);
        Poll::Ready(Ok(()))
    }

    fn poll_write_encrypted_record(
        &mut self,
        cx: &mut Context<'_>,
        plaintext_len: usize,
    ) -> Poll<io::Result<usize>>
    where
        S: AsyncWrite + Unpin,
    {
        while !self.ciphertext_write_buf.is_empty() {
            match Pin::new(&mut self.inner).poll_write(cx, &self.ciphertext_write_buf) {
                Poll::Pending => return Poll::Pending,
                Poll::Ready(Ok(0)) => {
                    return Poll::Ready(Err(io::Error::new(
                        io::ErrorKind::WriteZero,
                        "TLS 1.3 application stream write returned zero",
                    )));
                }
                Poll::Ready(Ok(written)) => {
                    let _ = self.ciphertext_write_buf.split_to(written);
                }
                Poll::Ready(Err(err)) => return Poll::Ready(Err(err)),
            }
        }

        self.pending_write_plaintext_len = None;
        Poll::Ready(Ok(plaintext_len))
    }
}

impl<S> AsyncRead for RealityTls13ApplicationStream<S>
where
    S: AsyncRead + Unpin,
{
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let this = self.as_mut().get_mut();

        if this.plaintext_read_buf.is_empty() {
            match this.fill_plaintext_read_buf(cx)? {
                Poll::Pending => return Poll::Pending,
                Poll::Ready(()) => {}
            }
        }

        if this.plaintext_read_buf.is_empty() {
            return Poll::Ready(Ok(()));
        }

        let to_copy = this.plaintext_read_buf.len().min(buf.remaining());
        buf.put_slice(&this.plaintext_read_buf[..to_copy]);
        let _ = this.plaintext_read_buf.split_to(to_copy);
        Poll::Ready(Ok(()))
    }
}

impl<S> AsyncWrite for RealityTls13ApplicationStream<S>
where
    S: AsyncWrite + Unpin,
{
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        let this = self.as_mut().get_mut();

        if !this.ciphertext_write_buf.is_empty() {
            let pending = this
                .pending_write_plaintext_len
                .expect("pending plaintext length while encrypted write buffer is non-empty");
            return this.poll_write_encrypted_record(cx, pending);
        }

        if buf.is_empty() {
            return Poll::Ready(Ok(0));
        }

        let record = this.write_encryptor.encrypt_application_data(buf)?;
        this.ciphertext_write_buf.extend_from_slice(&record);
        this.pending_write_plaintext_len = Some(buf.len());
        this.poll_write_encrypted_record(cx, buf.len())
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.as_mut().get_mut().inner).poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.as_mut().get_mut().inner).poll_shutdown(cx)
    }
}

fn try_take_tls_record(buf: &mut BytesMut) -> io::Result<Option<TlsRecord>> {
    if buf.len() < TLS_RECORD_HEADER_LEN {
        return Ok(None);
    }

    let payload_len = u16::from_be_bytes([buf[3], buf[4]]) as usize;
    let record_len = TLS_RECORD_HEADER_LEN
        .checked_add(payload_len)
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "TLS record length overflow"))?;

    if buf.len() < record_len {
        return Ok(None);
    }

    let raw = buf.split_to(record_len).to_vec();
    let content_type = parse_tls_record_content_type(raw[0]);
    let legacy_version = [raw[1], raw[2]];
    let payload = raw[TLS_RECORD_HEADER_LEN..].to_vec();

    Ok(Some(TlsRecord {
        content_type,
        legacy_version,
        payload,
        raw,
    }))
}

fn poll_read_tls_record<S>(
    mut inner: Pin<&mut S>,
    ciphertext_read_buf: &mut BytesMut,
    cx: &mut Context<'_>,
) -> Poll<io::Result<TlsRecord>>
where
    S: AsyncRead + Unpin,
{
    loop {
        if let Some(record) = try_take_tls_record(ciphertext_read_buf)? {
            return Poll::Ready(Ok(record));
        }

        let mut chunk = [0u8; 4096];
        let mut read_buf = ReadBuf::new(&mut chunk);
        match inner.as_mut().poll_read(cx, &mut read_buf) {
            Poll::Pending => return Poll::Pending,
            Poll::Ready(Err(err)) => return Poll::Ready(Err(err)),
            Poll::Ready(Ok(())) => {
                if read_buf.filled().is_empty() {
                    return Poll::Ready(Err(io::Error::new(
                        io::ErrorKind::UnexpectedEof,
                        "TLS 1.3 application stream closed before a complete record",
                    )));
                }
                ciphertext_read_buf.extend_from_slice(read_buf.filled());
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use std::future::Future;

    use tokio::io::{duplex, AsyncReadExt, AsyncWriteExt};

    use crate::reality::tls13::{tls13_cipher_suite, Tls13TrafficKeys, TLS_AES_128_GCM_SHA256};
    use crate::tls::records::{
        build_tls_record, parse_tls_records, TLS_LEGACY_VERSION_1_2, TLS_RECORD_APPLICATION_DATA,
    };

    use super::*;

    fn aes128_keys(seed: u8) -> Tls13TrafficKeys {
        Tls13TrafficKeys {
            key: (seed..seed + 16).collect(),
            iv: (0x01..0x0d).collect(),
        }
    }

    fn client_to_server_keys() -> (Tls13RecordEncryptor, Tls13RecordDecryptor) {
        let suite = tls13_cipher_suite(TLS_AES_128_GCM_SHA256).expect("known suite");
        let keys = aes128_keys(0x10);
        let encryptor = Tls13RecordEncryptor::new(suite, keys.clone()).expect("encryptor");
        let decryptor = Tls13RecordDecryptor::new(suite, keys).expect("decryptor");
        (encryptor, decryptor)
    }

    fn server_to_client_keys() -> (Tls13RecordEncryptor, Tls13RecordDecryptor) {
        let suite = tls13_cipher_suite(TLS_AES_128_GCM_SHA256).expect("known suite");
        let keys = aes128_keys(0x20);
        let encryptor = Tls13RecordEncryptor::new(suite, keys.clone()).expect("encryptor");
        let decryptor = Tls13RecordDecryptor::new(suite, keys).expect("decryptor");
        (encryptor, decryptor)
    }

    fn block_on<F: Future>(future: F) -> F::Output {
        tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("tokio runtime")
            .block_on(future)
    }

    #[test]
    fn read_plaintext_chunk_decrypts_one_record() {
        block_on(async {
            let (mut client_io, server_io) = duplex(4096);
            let (mut client_encryptor, server_decryptor) = client_to_server_keys();
            let (server_encryptor, _client_decryptor) = server_to_client_keys();

            let mut stream =
                RealityTls13ApplicationStream::new(server_io, server_decryptor, server_encryptor);

            let encrypted = client_encryptor
                .encrypt_application_data(b"vless-payload")
                .expect("encrypted record");
            client_io.write_all(&encrypted).await.expect("write");

            let plaintext = stream
                .read_plaintext_chunk()
                .await
                .expect("decrypted plaintext");

            assert_eq!(plaintext, b"vless-payload");
            assert_eq!(stream.read_decryptor.sequence, 1);
        });
    }

    #[test]
    fn async_write_produces_tls_application_record() {
        block_on(async {
            let (mut client_io, server_io) = duplex(4096);
            let (_client_encryptor, server_decryptor) = client_to_server_keys();
            let (server_encryptor, mut client_decryptor) = server_to_client_keys();

            let mut stream =
                RealityTls13ApplicationStream::new(server_io, server_decryptor, server_encryptor);

            let written = stream
                .write_all(b"server response")
                .await
                .expect("write plaintext");
            assert_eq!(written, ());

            let mut encrypted = vec![0u8; 4096];
            let read = client_io
                .read(&mut encrypted)
                .await
                .expect("read encrypted record");
            encrypted.truncate(read);

            let records = parse_tls_records(&encrypted).expect("parsable record");
            assert_eq!(records.len(), 1);
            assert_eq!(
                records[0].content_type,
                TlsRecordContentType::ApplicationData
            );

            let plaintext = client_decryptor
                .decrypt_application_data_record(&records[0])
                .expect("decrypted application data");
            assert_eq!(plaintext, b"server response");
        });
    }

    #[test]
    fn duplex_encrypt_decrypt_roundtrip() {
        block_on(async {
            let (mut client_io, server_io) = duplex(8192);
            let (mut client_encryptor, server_decryptor) = client_to_server_keys();
            let (server_encryptor, mut client_decryptor) = server_to_client_keys();

            let mut server_stream =
                RealityTls13ApplicationStream::new(server_io, server_decryptor, server_encryptor);

            let client_to_server = client_encryptor
                .encrypt_application_data(b"client->server")
                .expect("encrypted");
            client_io
                .write_all(&client_to_server)
                .await
                .expect("client write");

            let mut read_buf = [0u8; 64];
            let read = server_stream
                .read(&mut read_buf)
                .await
                .expect("server read");
            assert_eq!(&read_buf[..read], b"client->server");

            server_stream
                .write_all(b"server->client")
                .await
                .expect("server write");

            let mut encrypted = vec![0u8; 4096];
            let read = client_io
                .read(&mut encrypted)
                .await
                .expect("client read encrypted");
            encrypted.truncate(read);

            let records = parse_tls_records(&encrypted).expect("parsable record");
            let plaintext = client_decryptor
                .decrypt_application_data_record(&records[0])
                .expect("decrypted");
            assert_eq!(plaintext, b"server->client");
        });
    }

    #[test]
    fn fragmented_tls_record_read_waits_for_full_record() {
        block_on(async {
            let (mut client_io, server_io) = duplex(4096);
            let (mut client_encryptor, server_decryptor) = client_to_server_keys();
            let (server_encryptor, _client_decryptor) = server_to_client_keys();

            let mut stream =
                RealityTls13ApplicationStream::new(server_io, server_decryptor, server_encryptor);

            let encrypted = client_encryptor
                .encrypt_application_data(b"fragmented")
                .expect("encrypted record");
            let split_at = 3;
            client_io
                .write_all(&encrypted[..split_at])
                .await
                .expect("first fragment");
            client_io
                .write_all(&encrypted[split_at..])
                .await
                .expect("second fragment");

            let plaintext = stream
                .read_plaintext_chunk()
                .await
                .expect("decrypted plaintext");
            assert_eq!(plaintext, b"fragmented");
        });
    }

    #[test]
    fn read_tls_record_from_stream_reads_one_record() {
        block_on(async {
            let record_bytes = build_tls_record(
                TLS_RECORD_APPLICATION_DATA,
                TLS_LEGACY_VERSION_1_2,
                b"payload",
            )
            .expect("valid record");
            let mut cursor = std::io::Cursor::new(record_bytes.clone());

            let record = read_tls_record_from_stream(&mut cursor)
                .await
                .expect("valid TLS record");

            assert_eq!(record.raw, record_bytes);
            assert_eq!(record.payload, b"payload");
            assert_eq!(record.content_type, TlsRecordContentType::ApplicationData);
        });
    }

    #[test]
    fn try_take_tls_record_requires_complete_record() {
        let mut buf = BytesMut::from(&[TLS_RECORD_APPLICATION_DATA, 0x03, 0x03, 0x00, 0x02][..]);
        assert!(try_take_tls_record(&mut buf)
            .expect("valid parse")
            .is_none());

        buf.extend_from_slice(&[0x01, 0x02]);
        let record = try_take_tls_record(&mut buf)
            .expect("valid parse")
            .expect("complete record");
        assert_eq!(record.payload, vec![0x01, 0x02]);
        assert!(buf.is_empty());
    }
}
