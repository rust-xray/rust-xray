//! Client-side 1-RTT session material and handshake response boundaries.
//!
//! Mirrors upstream client wrapping order after handshake:
//! write: plaintext → CommonConn AEAD → optional random XorConn (united+IV) → socket
//! read:  socket → optional random XorConn (united+ticket) → CommonConn AEAD → plaintext

use std::io;
use std::pin::Pin;
use std::task::{Context, Poll};

use bytes::Bytes;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, ReadBuf};
use x25519_dalek::{PublicKey, StaticSecret};

use crate::reality::key_share::MLKEM768_CIPHERTEXT_LEN;

use super::aead::TrafficAead;
use super::config::{Mlkem768X25519PlusConfig, XorMode};
use super::handshake::{
    prefer_aes_hardware, TrafficDirectionKeys, ENCRYPTED_TICKET_LEN, NFS_ENCRYPTED_LENGTH_LEN,
    PFS_SERVER_EXCHANGE_LEN,
};
use super::hybrid::{compose_pfs_key, compose_united_key, UNITED_KEY_LEN};
use super::mlkem::decapsulate_mlkem768;
use super::nonce::MAX_NONCE;
use super::padding::{create_padding_lengths, SeededRng};
use super::stream::{
    poll_encrypted_flush, poll_encrypted_read, poll_encrypted_write, EncryptedReader,
    EncryptedWriter, XorTrafficReader, XorTrafficWriter,
};

/// Material captured while building a client hello (test/outbound handshake helpers).
#[derive(Debug, Clone)]
pub struct ClientHelloMaterial {
    pub iv: [u8; 16],
    pub nfs_key: [u8; 32],
    pub client_pfs_public: Vec<u8>,
    pub client_x25519_secret: [u8; 32],
    pub mlkem_seed: [u8; 64],
}

/// Derived 1-RTT traffic keys after reading the full server handshake response.
#[derive(Debug)]
pub struct ClientSessionMaterial {
    pub upload: TrafficDirectionKeys,
    pub download: TrafficDirectionKeys,
    pub united: [u8; UNITED_KEY_LEN],
    pub use_aes: bool,
    pub ticket: [u8; 16],
    pub client_iv: [u8; 16],
}

/// Total server 1-RTT response length (PFS exchange + encrypted ticket + server padding).
pub fn server_1rtt_response_len(config: &Mlkem768X25519PlusConfig, server_rng_seed: u64) -> usize {
    let (padding_total, _, _) =
        create_padding_lengths(&config.padding, &mut SeededRng::new(server_rng_seed));
    PFS_SERVER_EXCHANGE_LEN + ENCRYPTED_TICKET_LEN + padding_total
}

/// Read exactly the upstream server handshake response, including trailing server padding.
pub async fn read_server_1rtt_response<S>(
    stream: &mut S,
    config: &Mlkem768X25519PlusConfig,
    server_rng_seed: u64,
) -> io::Result<Vec<u8>>
where
    S: AsyncRead + Unpin,
{
    let len = server_1rtt_response_len(config, server_rng_seed);
    let mut buf = vec![0u8; len];
    stream.read_exact(&mut buf).await?;
    Ok(buf)
}

pub fn derive_client_session(
    parts: &ClientHelloMaterial,
    server_response: &[u8],
) -> io::Result<ClientSessionMaterial> {
    let min_len = PFS_SERVER_EXCHANGE_LEN + ENCRYPTED_TICKET_LEN;
    if server_response.len() < min_len {
        return Err(io::Error::new(
            io::ErrorKind::UnexpectedEof,
            "server handshake response too short",
        ));
    }

    let prefer_aes = prefer_aes_hardware();
    let mut nfs_aead = TrafficAead::new(&parts.iv, &parts.nfs_key, prefer_aes);
    let pfs_public = nfs_aead
        .open_with_nonce(&MAX_NONCE, &server_response[..PFS_SERVER_EXCHANGE_LEN], &[])
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "PFS exchange open failed"))?;
    let use_aes = matches!(nfs_aead.kind(), super::aead::TrafficAeadKind::Aes256Gcm);

    let ct = &pfs_public[..MLKEM768_CIPHERTEXT_LEN];
    let mlkem_shared = decapsulate_mlkem768(&parts.mlkem_seed, ct)
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "ML-KEM decaps failed"))?;
    let mut server_x25519 = [0u8; 32];
    server_x25519.copy_from_slice(&pfs_public[MLKEM768_CIPHERTEXT_LEN..]);
    let client_x25519 = StaticSecret::from(parts.client_x25519_secret);
    let server_public = PublicKey::from(server_x25519);
    let x25519_shared = client_x25519.diffie_hellman(&server_public);
    let pfs_key = compose_pfs_key(mlkem_shared.as_bytes(), x25519_shared.as_bytes());
    let united = compose_united_key(&pfs_key, &parts.nfs_key);

    let upload = TrafficDirectionKeys {
        aead: TrafficAead::new(&parts.client_pfs_public, united.as_bytes(), use_aes),
        context_label: parts.client_pfs_public.clone(),
    };
    let mut download = TrafficDirectionKeys {
        aead: TrafficAead::new(&pfs_public, united.as_bytes(), use_aes),
        context_label: pfs_public,
    };

    let enc_ticket =
        &server_response[PFS_SERVER_EXCHANGE_LEN..PFS_SERVER_EXCHANGE_LEN + ENCRYPTED_TICKET_LEN];
    let plain = download
        .aead
        .open(enc_ticket, &[])
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "ticket open failed"))?;
    if plain.len() != 16 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "unexpected ticket length",
        ));
    }
    let mut ticket = [0u8; 16];
    ticket.copy_from_slice(&plain);

    let server_padding = &server_response[PFS_SERVER_EXCHANGE_LEN + ENCRYPTED_TICKET_LEN..];
    consume_upload_direction_padding(&mut download, server_padding)?;

    Ok(ClientSessionMaterial {
        upload,
        download,
        united: *united.as_bytes(),
        use_aes,
        ticket,
        client_iv: parts.iv,
    })
}

/// Advance client download AEAD nonce across server-hello padding sealed with upload keys.
fn consume_upload_direction_padding(
    download: &mut TrafficDirectionKeys,
    padding: &[u8],
) -> io::Result<()> {
    if padding.is_empty() {
        return Ok(());
    }
    if padding.len() < NFS_ENCRYPTED_LENGTH_LEN {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "server padding shorter than length record",
        ));
    }
    let _ = download
        .aead
        .open(&padding[..NFS_ENCRYPTED_LENGTH_LEN], &[])
        .map_err(|_| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                "server padding length open failed",
            )
        })?;
    if padding.len() > NFS_ENCRYPTED_LENGTH_LEN {
        let _ = download
            .aead
            .open(&padding[NFS_ENCRYPTED_LENGTH_LEN..], &[])
            .map_err(|_| {
                io::Error::new(
                    io::ErrorKind::InvalidData,
                    "server padding body open failed",
                )
            })?;
    }
    Ok(())
}

/// Client-side CommonConn (+ optional random XorConn) traffic adapter.
pub struct ClientEncryptedStream<S> {
    inner: S,
    reader: EncryptedReader,
    writer: EncryptedWriter,
    xor_reader: Option<XorTrafficReader>,
    xor_writer: Option<XorTrafficWriter>,
    pending_frame: Option<Bytes>,
}

impl<S> ClientEncryptedStream<S> {
    pub fn from_session(
        inner: S,
        session: ClientSessionMaterial,
        xor_mode: XorMode,
    ) -> io::Result<Self> {
        Self::from_session_inner(inner, session, xor_mode, false)
    }

    /// 0-RTT resume client session (mirrors server `outbound_skip: 16` on download).
    pub fn from_zero_rtt_session(
        inner: S,
        session: ClientSessionMaterial,
        xor_mode: XorMode,
    ) -> io::Result<Self> {
        Self::from_session_inner(inner, session, xor_mode, true)
    }

    fn from_session_inner(
        inner: S,
        session: ClientSessionMaterial,
        xor_mode: XorMode,
        zero_rtt_resume: bool,
    ) -> io::Result<Self> {
        let download_xor_skip = if xor_mode == XorMode::Random && zero_rtt_resume {
            16
        } else {
            0
        };
        let (xor_reader, xor_writer) = if xor_mode == XorMode::Random {
            (
                Some(XorTrafficReader::new_client_download_with_skip(
                    &session.united,
                    &session.ticket,
                    download_xor_skip,
                )),
                Some(XorTrafficWriter::new_client_upload(
                    &session.united,
                    &session.client_iv,
                )),
            )
        } else {
            (None, None)
        };

        let reader = if zero_rtt_resume && xor_mode != XorMode::Random {
            EncryptedReader::new(session.download, session.united, session.use_aes)
        } else {
            EncryptedReader::new_post_handshake(session.download, session.united, session.use_aes)
        };
        Ok(Self {
            inner,
            reader,
            writer: EncryptedWriter::new(session.upload),
            xor_reader,
            xor_writer,
            pending_frame: None,
        })
    }

    pub fn inner_mut(&mut self) -> &mut S {
        &mut self.inner
    }

    pub fn into_inner(self) -> S {
        self.inner
    }
}

impl<S> AsyncRead for ClientEncryptedStream<S>
where
    S: AsyncRead + Unpin,
{
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        poll_encrypted_read(
            Pin::new(&mut this.inner),
            cx,
            &mut this.reader,
            this.xor_reader.as_mut(),
            buf,
        )
    }
}

impl<S> AsyncWrite for ClientEncryptedStream<S>
where
    S: AsyncWrite + Unpin,
{
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        let this = self.get_mut();
        poll_encrypted_write(
            Pin::new(&mut this.inner),
            cx,
            &mut this.writer,
            this.xor_writer.as_mut(),
            &mut this.pending_frame,
            &mut None,
            buf,
        )
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        poll_encrypted_flush(
            Pin::new(&mut this.inner),
            cx,
            &mut this.writer,
            this.xor_writer.as_mut(),
            &mut this.pending_frame,
            &mut None,
        )
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = self.as_mut().get_mut();
        match poll_encrypted_flush(
            Pin::new(&mut this.inner),
            cx,
            &mut this.writer,
            this.xor_writer.as_mut(),
            &mut this.pending_frame,
            &mut None,
        ) {
            Poll::Ready(Ok(())) => Pin::new(&mut this.inner).poll_shutdown(cx),
            other => other,
        }
    }
}
