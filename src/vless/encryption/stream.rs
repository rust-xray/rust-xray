use std::io;
use std::pin::Pin;
use std::task::{Context, Poll};

use bytes::{Bytes, BytesMut};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

use super::aead::TrafficAead;
use super::handshake::{ServerHandshakeResult, TrafficDirectionKeys, XorConnState};
use super::header::{decode_traffic_header, encode_traffic_header, TrafficHeaderError};
use super::hybrid::UNITED_KEY_LEN;
use super::io::PrefixStream;
use super::xor::CtrStream;

/// Maximum plaintext bytes per upstream `CommonConn.Write` record.
pub const MAX_TRAFFIC_PLAINTEXT_PER_RECORD: usize = 8192;
const TRAFFIC_HEADER_LEN: usize = 5;
const AEAD_TAG_LEN: usize = 16;

/// Encrypted VLESS traffic adapter (upstream `CommonConn`) over any AsyncRead+AsyncWrite transport.
pub struct VlessEncryptedStream<S> {
    inner: S,
    reader: EncryptedReader,
    writer: EncryptedWriter,
    xor_reader: Option<XorTrafficReader>,
    xor_writer: Option<XorTrafficWriter>,
    pending_frame: Option<Bytes>,
    pending_prewrite: Option<[u8; 16]>,
}

impl<S> VlessEncryptedStream<S> {
    pub fn from_handshake(
        stream: PrefixStream<S>,
        result: ServerHandshakeResult,
    ) -> VlessEncryptedStream<PrefixStream<S>> {
        let prefer_aes = result.use_aes;
        let united_key = *result.united_key.as_bytes();
        let (xor_reader, xor_writer) = result
            .xor_conn
            .map(XorTrafficConn::from_state)
            .map(XorTrafficConn::split)
            .unwrap_or((None, None));
        VlessEncryptedStream {
            inner: stream,
            reader: EncryptedReader::new(result.download_keys, united_key, prefer_aes),
            writer: EncryptedWriter::new(result.upload_keys),
            xor_reader,
            xor_writer,
            pending_frame: None,
            pending_prewrite: result.server_prewrite,
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

    #[cfg(test)]
    pub fn reader_aead_kind_for_test(&self) -> super::aead::TrafficAeadKind {
        self.reader.aead_kind()
    }

    #[cfg(test)]
    pub fn reader_is_first_record_for_test(&self) -> bool {
        self.reader.is_first_record()
    }

    #[cfg(test)]
    pub fn set_writer_nonce_for_test(&mut self, nonce: [u8; 12]) {
        self.writer.set_nonce_for_test(nonce);
    }

    pub fn split_for_relay<R, W, D>(
        self,
        split: impl FnOnce(S) -> io::Result<(R, W, D)>,
    ) -> io::Result<VlessEncryptedRelaySplit<R, W, D>> {
        let Self {
            inner,
            reader,
            writer,
            xor_reader,
            xor_writer,
            pending_frame,
            pending_prewrite,
        } = self;
        let (reader_inner, writer_inner, direct_relay) = split(inner)?;
        Ok(VlessEncryptedRelaySplit {
            reader: VlessEncryptedReader {
                inner: reader_inner,
                state: reader,
                xor: xor_reader,
            },
            writer: VlessEncryptedWriter {
                inner: writer_inner,
                state: writer,
                xor: xor_writer,
                pending_frame,
            },
            direct_relay,
        })
    }
}

pub struct VlessEncryptedReader<R> {
    inner: R,
    state: EncryptedReader,
    xor: Option<XorTrafficReader>,
}

pub struct VlessEncryptedWriter<W> {
    inner: W,
    state: EncryptedWriter,
    xor: Option<XorTrafficWriter>,
    pending_frame: Option<Bytes>,
}

pub struct VlessEncryptedRelaySplit<R, W, D> {
    pub reader: VlessEncryptedReader<R>,
    pub writer: VlessEncryptedWriter<W>,
    pub direct_relay: D,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ReadPhase {
    NeedHeader,
    NeedBody { payload_len: usize },
}

pub(crate) struct EncryptedReader {
    aead: TrafficAead,
    context_label: Vec<u8>,
    united_key: [u8; UNITED_KEY_LEN],
    prefer_aes: bool,
    first_record: bool,
    phase: ReadPhase,
    header: [u8; TRAFFIC_HEADER_LEN],
    header_filled: usize,
    body: BytesMut,
    plaintext: Bytes,
    plaintext_offset: usize,
    eof: bool,
}

impl EncryptedReader {
    pub(crate) fn new(
        keys: TrafficDirectionKeys,
        united_key: [u8; UNITED_KEY_LEN],
        prefer_aes: bool,
    ) -> Self {
        Self::from_keys(keys, united_key, prefer_aes, true)
    }

    /// Reader for client-side post-1RTT traffic when cipher choice is known and
    /// the directional AEAD may already have advanced (e.g. after ticket open).
    pub(crate) fn new_post_handshake(
        keys: TrafficDirectionKeys,
        united_key: [u8; UNITED_KEY_LEN],
        prefer_aes: bool,
    ) -> Self {
        Self::from_keys(keys, united_key, prefer_aes, false)
    }

    fn from_keys(
        keys: TrafficDirectionKeys,
        united_key: [u8; UNITED_KEY_LEN],
        prefer_aes: bool,
        first_record: bool,
    ) -> Self {
        Self {
            aead: keys.aead,
            context_label: keys.context_label,
            united_key,
            prefer_aes,
            first_record,
            phase: ReadPhase::NeedHeader,
            header: [0u8; TRAFFIC_HEADER_LEN],
            header_filled: 0,
            body: BytesMut::new(),
            plaintext: Bytes::new(),
            plaintext_offset: 0,
            eof: false,
        }
    }

    #[cfg(test)]
    pub(crate) fn aead_kind(&self) -> super::aead::TrafficAeadKind {
        self.aead.kind()
    }

    #[cfg(test)]
    pub(crate) fn is_first_record(&self) -> bool {
        self.first_record
    }

    #[cfg(test)]
    pub(crate) fn clear_first_record_for_test(&mut self) {
        self.first_record = false;
    }

    #[cfg(test)]
    pub(crate) fn set_nonce_for_test(&mut self, nonce: [u8; 12]) {
        self.aead.set_nonce_for_test(nonce);
    }

    fn pop_plaintext(&mut self, buf: &mut ReadBuf<'_>) -> bool {
        if self.plaintext_offset >= self.plaintext.len() {
            return false;
        }
        let to_copy = (self.plaintext.len() - self.plaintext_offset).min(buf.remaining());
        buf.put_slice(&self.plaintext[self.plaintext_offset..self.plaintext_offset + to_copy]);
        self.plaintext_offset += to_copy;
        if self.plaintext_offset >= self.plaintext.len() {
            self.plaintext = Bytes::new();
            self.plaintext_offset = 0;
        }
        true
    }

    fn map_header_err(err: TrafficHeaderError) -> io::Error {
        io::Error::new(io::ErrorKind::InvalidData, err.to_string())
    }

    pub(crate) fn decrypt_record(
        &mut self,
        header: &[u8; TRAFFIC_HEADER_LEN],
        body: &[u8],
    ) -> io::Result<Bytes> {
        if body.len() < AEAD_TAG_LEN {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "encrypted traffic record shorter than AEAD tag",
            ));
        }
        let aad = &header[..];
        let plaintext = if self.first_record {
            self.first_record = false;
            let (opened, aead) = TrafficAead::open_auto_kind_with_state(
                &self.context_label,
                &self.united_key,
                self.prefer_aes,
                body,
                aad,
            )
            .map_err(|_| {
                io::Error::new(
                    io::ErrorKind::InvalidData,
                    "encrypted traffic AEAD open failed",
                )
            })?;
            self.aead = aead;
            opened
        } else {
            let mut buffer = body.to_vec();
            let ciphertext_len = body.len() - AEAD_TAG_LEN;
            let opened_len = self
                .aead
                .open_in_place(&mut buffer, ciphertext_len, aad)
                .map_err(|_| {
                    io::Error::new(
                        io::ErrorKind::InvalidData,
                        "encrypted traffic AEAD open failed",
                    )
                })?;
            buffer.truncate(opened_len);
            buffer
        };
        Ok(Bytes::from(plaintext))
    }
}

pub(crate) struct EncryptedWriter {
    aead: TrafficAead,
    plaintext_buf: Vec<u8>,
}

#[cfg(test)]
pub(crate) static TEST_SEAL_COUNT: std::sync::atomic::AtomicUsize =
    std::sync::atomic::AtomicUsize::new(0);

#[cfg(test)]
pub(crate) fn reset_test_seal_count() {
    TEST_SEAL_COUNT.store(0, std::sync::atomic::Ordering::SeqCst);
}

#[cfg(test)]
pub(crate) fn test_seal_count() -> usize {
    TEST_SEAL_COUNT.load(std::sync::atomic::Ordering::SeqCst)
}

impl EncryptedWriter {
    pub(crate) fn new(keys: TrafficDirectionKeys) -> Self {
        Self {
            aead: keys.aead,
            plaintext_buf: Vec::new(),
        }
    }

    #[cfg(test)]
    pub(crate) fn set_nonce_for_test(&mut self, nonce: [u8; 12]) {
        self.aead.set_nonce_for_test(nonce);
    }

    fn take_plaintext_chunk(&mut self, max: usize) -> Option<Vec<u8>> {
        if self.plaintext_buf.is_empty() {
            return None;
        }
        let chunk_len = self.plaintext_buf.len().min(max);
        Some(self.plaintext_buf.drain(..chunk_len).collect())
    }

    pub(crate) fn build_record(&mut self, plaintext: &[u8]) -> io::Result<BytesMut> {
        #[cfg(test)]
        TEST_SEAL_COUNT.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        let payload_len = plaintext.len().checked_add(AEAD_TAG_LEN).ok_or_else(|| {
            io::Error::new(io::ErrorKind::InvalidInput, "record payload overflow")
        })?;
        let payload_len = u16::try_from(payload_len).map_err(|_| {
            io::Error::new(io::ErrorKind::InvalidInput, "record payload exceeds u16")
        })?;

        let mut header = [0u8; TRAFFIC_HEADER_LEN];
        encode_traffic_header(&mut header, payload_len);

        let mut buffer = plaintext.to_vec();
        let encrypted_len = self.aead.seal_in_place(&mut buffer, &header).map_err(|_| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                "encrypted traffic AEAD seal failed",
            )
        })?;

        let mut frame = BytesMut::with_capacity(TRAFFIC_HEADER_LEN + encrypted_len);
        frame.extend_from_slice(&header);
        frame.extend_from_slice(&buffer[..encrypted_len]);
        Ok(frame)
    }
}

struct XorTrafficConn {
    outbound: CtrStream,
    inbound: CtrStream,
    outbound_skip: usize,
    inbound_skip: usize,
    out_header: Vec<u8>,
    in_header: Vec<u8>,
}

impl XorTrafficConn {
    fn from_state(state: XorConnState) -> Self {
        Self {
            outbound: state.outbound_ctr,
            inbound: state.inbound_ctr,
            outbound_skip: state.outbound_skip,
            inbound_skip: state.inbound_skip,
            out_header: Vec::with_capacity(5),
            in_header: Vec::with_capacity(5),
        }
    }

    fn split(self) -> (Option<XorTrafficReader>, Option<XorTrafficWriter>) {
        (
            Some(XorTrafficReader {
                ctr: self.inbound,
                skip: self.inbound_skip,
                header: self.in_header,
            }),
            Some(XorTrafficWriter {
                ctr: self.outbound,
                skip: self.outbound_skip,
                header: self.out_header,
            }),
        )
    }
}

pub(crate) struct XorTrafficReader {
    ctr: CtrStream,
    skip: usize,
    header: Vec<u8>,
}

pub(crate) struct XorTrafficWriter {
    ctr: CtrStream,
    skip: usize,
    header: Vec<u8>,
}

impl XorTrafficReader {
    pub(crate) fn new_client_download(united: &[u8; UNITED_KEY_LEN], ticket: &[u8; 16]) -> Self {
        Self::new_client_download_with_skip(united, ticket, 0)
    }

    pub(crate) fn new_client_download_with_skip(
        united: &[u8; UNITED_KEY_LEN],
        ticket: &[u8; 16],
        skip: usize,
    ) -> Self {
        Self {
            ctr: CtrStream::new(united, ticket),
            skip,
            header: Vec::with_capacity(TRAFFIC_HEADER_LEN),
        }
    }
}

impl XorTrafficWriter {
    pub(crate) fn new_client_upload(united: &[u8; UNITED_KEY_LEN], client_iv: &[u8; 16]) -> Self {
        Self {
            ctr: CtrStream::new(united, client_iv),
            skip: 0,
            header: Vec::with_capacity(TRAFFIC_HEADER_LEN),
        }
    }
}

fn apply_xor_read(ctr: &mut CtrStream, header: &mut Vec<u8>, skip: &mut usize, buf: &mut [u8]) {
    let mut offset = 0usize;
    while offset < buf.len() {
        let mut p = &mut buf[offset..];
        if *skip > 0 {
            if p.len() <= *skip {
                *skip -= p.len();
                break;
            }
            p = &mut p[*skip..];
            *skip = 0;
        }
        let need = TRAFFIC_HEADER_LEN.saturating_sub(header.len());
        if p.len() < need {
            ctr.apply_keystream(p);
            header.extend_from_slice(p);
            break;
        }
        ctr.apply_keystream(&mut p[..need]);
        header.extend_from_slice(&p[..need]);
        if let Ok(payload_len) = decode_traffic_header(&{
            let mut arr = [0u8; TRAFFIC_HEADER_LEN];
            arr.copy_from_slice(header);
            arr
        }) {
            *skip = payload_len as usize;
        }
        header.clear();
        offset += need;
    }
}

fn apply_xor_write(ctr: &mut CtrStream, header: &mut Vec<u8>, skip: &mut usize, buf: &mut [u8]) {
    let mut offset = 0usize;
    while offset < buf.len() {
        let mut p = &mut buf[offset..];
        if *skip > 0 {
            if p.len() <= *skip {
                *skip -= p.len();
                break;
            }
            p = &mut p[*skip..];
            *skip = 0;
        }
        let need = TRAFFIC_HEADER_LEN.saturating_sub(header.len());
        if p.len() < need {
            header.extend_from_slice(p);
            ctr.apply_keystream(p);
            break;
        }
        let mut header_plain = header.clone();
        header_plain.extend_from_slice(&p[..need]);
        if let Ok(payload_len) = decode_traffic_header(&{
            let mut arr = [0u8; TRAFFIC_HEADER_LEN];
            arr.copy_from_slice(&header_plain[..TRAFFIC_HEADER_LEN]);
            arr
        }) {
            *skip = payload_len as usize;
        }
        header.clear();
        ctr.apply_keystream(&mut p[..need]);
        offset += need;
    }
}

#[cfg(test)]
pub(crate) fn apply_xor_write_for_test(xor: &mut XorTrafficWriter, frame: &mut [u8]) {
    apply_xor_write(&mut xor.ctr, &mut xor.header, &mut xor.skip, frame);
}

#[cfg(test)]
pub(crate) fn apply_xor_read_for_test(xor: &mut XorTrafficReader, frame: &mut [u8]) {
    apply_xor_read(&mut xor.ctr, &mut xor.header, &mut xor.skip, frame);
}

pub(crate) fn poll_encrypted_read<R>(
    mut inner: Pin<&mut R>,
    cx: &mut Context<'_>,
    state: &mut EncryptedReader,
    mut xor: Option<&mut XorTrafficReader>,
    buf: &mut ReadBuf<'_>,
) -> Poll<io::Result<()>>
where
    R: AsyncRead,
{
    loop {
        if state.pop_plaintext(buf) {
            return Poll::Ready(Ok(()));
        }
        if state.eof {
            return Poll::Ready(Ok(()));
        }

        match state.phase {
            ReadPhase::NeedHeader => {
                if state.header_filled < TRAFFIC_HEADER_LEN {
                    let mut tmp = [0u8; TRAFFIC_HEADER_LEN];
                    let mut read_buf = ReadBuf::new(&mut tmp[state.header_filled..]);
                    match inner.as_mut().poll_read(cx, &mut read_buf) {
                        Poll::Ready(Ok(())) => {
                            if read_buf.filled().is_empty() {
                                state.eof = true;
                                if state.header_filled > 0 {
                                    return Poll::Ready(Err(io::Error::new(
                                        io::ErrorKind::UnexpectedEof,
                                        "truncated encrypted traffic header",
                                    )));
                                }
                                return Poll::Ready(Ok(()));
                            }
                            let mut chunk = read_buf.filled().to_vec();
                            if let Some(xor) = xor.as_mut() {
                                apply_xor_read(
                                    &mut xor.ctr,
                                    &mut xor.header,
                                    &mut xor.skip,
                                    &mut chunk,
                                );
                            }
                            let to_copy = chunk.len().min(TRAFFIC_HEADER_LEN - state.header_filled);
                            state.header[state.header_filled..state.header_filled + to_copy]
                                .copy_from_slice(&chunk[..to_copy]);
                            state.header_filled += to_copy;
                        }
                        Poll::Ready(Err(err)) => return Poll::Ready(Err(err)),
                        Poll::Pending => {
                            if state.header_filled > 0 || !buf.filled().is_empty() {
                                return Poll::Ready(Ok(()));
                            }
                            return Poll::Pending;
                        }
                    }
                    continue;
                }

                let payload_len = decode_traffic_header(&state.header)
                    .map_err(EncryptedReader::map_header_err)?
                    as usize;
                state.body.clear();
                state.body.reserve(payload_len);
                state.phase = ReadPhase::NeedBody { payload_len };
            }
            ReadPhase::NeedBody { payload_len } => {
                if state.body.len() < payload_len {
                    let need = payload_len - state.body.len();
                    let mut tmp = vec![0u8; need.min(4096)];
                    let mut read_buf = ReadBuf::new(&mut tmp);
                    match inner.as_mut().poll_read(cx, &mut read_buf) {
                        Poll::Ready(Ok(())) => {
                            if read_buf.filled().is_empty() {
                                return Poll::Ready(Err(io::Error::new(
                                    io::ErrorKind::UnexpectedEof,
                                    "truncated encrypted traffic body",
                                )));
                            }
                            let mut chunk = read_buf.filled().to_vec();
                            if let Some(xor) = xor.as_mut() {
                                apply_xor_read(
                                    &mut xor.ctr,
                                    &mut xor.header,
                                    &mut xor.skip,
                                    &mut chunk,
                                );
                            }
                            state.body.extend_from_slice(&chunk);
                        }
                        Poll::Ready(Err(err)) => return Poll::Ready(Err(err)),
                        Poll::Pending => {
                            if !buf.filled().is_empty() {
                                return Poll::Ready(Ok(()));
                            }
                            return Poll::Pending;
                        }
                    }
                    continue;
                }

                let header = state.header;
                let body = state.body.split().freeze();
                state.header_filled = 0;
                state.phase = ReadPhase::NeedHeader;
                state.plaintext = state.decrypt_record(&header, body.as_ref())?;
                state.plaintext_offset = 0;
            }
        }
    }
}

fn write_frame<W>(
    inner: &mut Pin<&mut W>,
    cx: &mut Context<'_>,
    frame: &BytesMut,
    pending_frame: &mut Option<Bytes>,
) -> Poll<io::Result<bool>>
where
    W: AsyncWrite,
{
    match inner.as_mut().poll_write(cx, frame.as_ref()) {
        Poll::Ready(Ok(0)) => {
            Poll::Ready(Err(io::Error::new(io::ErrorKind::WriteZero, "write zero")))
        }
        Poll::Ready(Ok(n)) if n >= frame.len() => Poll::Ready(Ok(true)),
        Poll::Ready(Ok(n)) => {
            *pending_frame = Some(frame.clone().split_off(n).freeze());
            Poll::Ready(Ok(false))
        }
        Poll::Ready(Err(err)) => Poll::Ready(Err(err)),
        Poll::Pending => {
            *pending_frame = Some(frame.clone().freeze());
            Poll::Ready(Ok(false))
        }
    }
}

fn flush_pending<W>(
    inner: &mut Pin<&mut W>,
    cx: &mut Context<'_>,
    pending_frame: &mut Option<Bytes>,
) -> Poll<io::Result<bool>>
where
    W: AsyncWrite,
{
    let frame = pending_frame.as_ref().expect("pending frame");
    match inner.as_mut().poll_write(cx, frame.as_ref()) {
        Poll::Ready(Ok(0)) => {
            Poll::Ready(Err(io::Error::new(io::ErrorKind::WriteZero, "write zero")))
        }
        Poll::Ready(Ok(n)) => {
            if n >= frame.len() {
                *pending_frame = None;
                Poll::Ready(Ok(true))
            } else {
                *pending_frame = Some(frame.slice(n..));
                Poll::Ready(Ok(false))
            }
        }
        Poll::Ready(Err(err)) => Poll::Ready(Err(err)),
        Poll::Pending => Poll::Ready(Ok(false)),
    }
}

const PARTIAL_WRITE_COOP_BUDGET: usize = 4096;

fn yield_after_partial(cx: &mut Context<'_>) {
    cx.waker().wake_by_ref();
}

fn drain_pending_frame<W>(
    inner: &mut Pin<&mut W>,
    cx: &mut Context<'_>,
    pending_frame: &mut Option<Bytes>,
    coop: &mut usize,
) -> Poll<io::Result<()>>
where
    W: AsyncWrite,
{
    while pending_frame.is_some() {
        if *coop == 0 {
            yield_after_partial(cx);
            return Poll::Pending;
        }
        *coop -= 1;
        match flush_pending(inner, cx, pending_frame) {
            Poll::Ready(Ok(true)) => {}
            Poll::Ready(Ok(false)) => continue,
            Poll::Ready(Err(err)) => return Poll::Ready(Err(err)),
            Poll::Pending => return Poll::Pending,
        }
    }
    Poll::Ready(Ok(()))
}

fn maybe_prepend_prewrite(frame: &mut BytesMut, pending_prewrite: &mut Option<[u8; 16]>) {
    if let Some(prewrite) = pending_prewrite.take() {
        let mut combined = BytesMut::with_capacity(16 + frame.len());
        combined.extend_from_slice(&prewrite);
        combined.extend_from_slice(frame);
        *frame = combined;
    }
}

pub(crate) fn poll_encrypted_write<W>(
    mut inner: Pin<&mut W>,
    cx: &mut Context<'_>,
    state: &mut EncryptedWriter,
    mut xor: Option<&mut XorTrafficWriter>,
    pending_frame: &mut Option<Bytes>,
    pending_prewrite: &mut Option<[u8; 16]>,
    buf: &[u8],
) -> Poll<io::Result<usize>>
where
    W: AsyncWrite,
{
    if !buf.is_empty() {
        let accept = buf.len();
        state.plaintext_buf.extend_from_slice(buf);
        let mut coop = PARTIAL_WRITE_COOP_BUDGET;
        match drain_pending_frame(&mut inner, cx, pending_frame, &mut coop) {
            Poll::Ready(Ok(())) => {}
            Poll::Ready(Err(err)) => return Poll::Ready(Err(err)),
            Poll::Pending => return Poll::Ready(Ok(accept)),
        }
        while pending_frame.is_none() {
            let Some(chunk) = state.take_plaintext_chunk(MAX_TRAFFIC_PLAINTEXT_PER_RECORD) else {
                break;
            };
            let mut frame = state.build_record(&chunk)?;
            if let Some(xor) = xor.as_mut() {
                apply_xor_write(&mut xor.ctr, &mut xor.header, &mut xor.skip, frame.as_mut());
            }
            maybe_prepend_prewrite(&mut frame, pending_prewrite);
            match write_frame(&mut inner, cx, &frame, pending_frame) {
                Poll::Ready(Ok(true)) => {}
                Poll::Ready(Ok(false)) => return Poll::Ready(Ok(accept)),
                Poll::Ready(Err(err)) => return Poll::Ready(Err(err)),
                Poll::Pending => return Poll::Ready(Ok(accept)),
            }
        }
        return Poll::Ready(Ok(accept));
    }

    let mut coop = PARTIAL_WRITE_COOP_BUDGET;
    match drain_pending_frame(&mut inner, cx, pending_frame, &mut coop) {
        Poll::Ready(Ok(())) => {}
        Poll::Ready(Err(err)) => return Poll::Ready(Err(err)),
        Poll::Pending => return Poll::Pending,
    }

    while pending_frame.is_none() {
        let Some(chunk) = state.take_plaintext_chunk(MAX_TRAFFIC_PLAINTEXT_PER_RECORD) else {
            break;
        };
        let mut frame = state.build_record(&chunk)?;
        if let Some(xor) = xor.as_mut() {
            apply_xor_write(&mut xor.ctr, &mut xor.header, &mut xor.skip, frame.as_mut());
        }
        maybe_prepend_prewrite(&mut frame, pending_prewrite);
        match write_frame(&mut inner, cx, &frame, pending_frame) {
            Poll::Ready(Ok(true)) => {}
            Poll::Ready(Ok(false)) => {
                yield_after_partial(cx);
                return Poll::Pending;
            }
            Poll::Ready(Err(err)) => return Poll::Ready(Err(err)),
            Poll::Pending => return Poll::Pending,
        }
    }

    Poll::Ready(Ok(0))
}

pub(crate) fn poll_encrypted_flush<W>(
    mut inner: Pin<&mut W>,
    cx: &mut Context<'_>,
    state: &mut EncryptedWriter,
    mut xor: Option<&mut XorTrafficWriter>,
    pending_frame: &mut Option<Bytes>,
    pending_prewrite: &mut Option<[u8; 16]>,
) -> Poll<io::Result<()>>
where
    W: AsyncWrite,
{
    let mut coop = PARTIAL_WRITE_COOP_BUDGET;
    loop {
        match drain_pending_frame(&mut inner, cx, pending_frame, &mut coop) {
            Poll::Ready(Ok(())) => {}
            Poll::Ready(Err(err)) => return Poll::Ready(Err(err)),
            Poll::Pending => return Poll::Pending,
        }

        let Some(chunk) = state.take_plaintext_chunk(MAX_TRAFFIC_PLAINTEXT_PER_RECORD) else {
            break;
        };
        let mut frame = state.build_record(&chunk)?;
        if let Some(xor) = xor.as_mut() {
            apply_xor_write(&mut xor.ctr, &mut xor.header, &mut xor.skip, frame.as_mut());
        }
        maybe_prepend_prewrite(&mut frame, pending_prewrite);
        match write_frame(&mut inner, cx, &frame, pending_frame) {
            Poll::Ready(Ok(true)) => {
                coop = PARTIAL_WRITE_COOP_BUDGET;
                continue;
            }
            Poll::Ready(Ok(false)) | Poll::Pending => {
                yield_after_partial(cx);
                return Poll::Pending;
            }
            Poll::Ready(Err(err)) => return Poll::Ready(Err(err)),
        }
    }

    match drain_pending_frame(&mut inner, cx, pending_frame, &mut coop) {
        Poll::Ready(Ok(())) => {}
        Poll::Ready(Err(err)) => return Poll::Ready(Err(err)),
        Poll::Pending => return Poll::Pending,
    }

    inner.poll_flush(cx)
}

impl<S> AsyncRead for VlessEncryptedStream<S>
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

impl<S> AsyncWrite for VlessEncryptedStream<S>
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
            &mut this.pending_prewrite,
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
            &mut this.pending_prewrite,
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
            &mut this.pending_prewrite,
        ) {
            Poll::Ready(Ok(())) => Pin::new(&mut this.inner).poll_shutdown(cx),
            other => other,
        }
    }
}

impl<R> AsyncRead for VlessEncryptedReader<R>
where
    R: AsyncRead + Unpin,
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
            &mut this.state,
            this.xor.as_mut(),
            buf,
        )
    }
}

impl<W> AsyncWrite for VlessEncryptedWriter<W>
where
    W: AsyncWrite + Unpin,
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
            &mut this.state,
            this.xor.as_mut(),
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
            &mut this.state,
            this.xor.as_mut(),
            &mut this.pending_frame,
            &mut None,
        )
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = self.as_mut().get_mut();
        match poll_encrypted_flush(
            Pin::new(&mut this.inner),
            cx,
            &mut this.state,
            this.xor.as_mut(),
            &mut this.pending_frame,
            &mut None,
        ) {
            Poll::Ready(Ok(())) => Pin::new(&mut this.inner).poll_shutdown(cx),
            other => other,
        }
    }
}
