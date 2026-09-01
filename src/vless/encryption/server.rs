use std::sync::Arc;
use std::time::Duration;

use tokio::io::{AsyncRead, AsyncWrite, AsyncWriteExt};
use tokio::time::{timeout, Duration as TokioDuration};
use x25519_dalek::{PublicKey, StaticSecret};

use super::aead::{TrafficAead, TrafficAeadKind};
use super::config::{Mlkem768X25519PlusConfig, TicketLifetimeRange, XorMode};
use super::encapsulate_mlkem768;
use super::handshake::{
    map_crypto_err, prefer_aes_hardware, HandshakeError, ServerHandshakeResult,
    TrafficDirectionKeys, XorConnState, DEFAULT_HANDSHAKE_TIMEOUT, ENCRYPTED_TICKET_LEN, IV_LEN,
    NFS_ENCRYPTED_LENGTH_LEN, PFS_CLIENT_BUNDLE_MIN, PFS_CLIENT_PUBLIC_KEY_LEN,
    PFS_SERVER_EXCHANGE_LEN, ZERO_RTT_LENGTH,
};
use super::hybrid::{compose_pfs_key, compose_united_key, encode_length};
use super::io::{HandshakeStream, PrefixStream};
use super::nfs::NfsServerChain;
use super::nonce::MAX_NONCE;
use super::padding::{create_padding_lengths, RngDraw};
use super::resume_noise::generate_invalid_ticket_noise;
use super::session_cache::{SessionCache, SessionLookupError};
use super::xor::CtrStream;
use crate::reality::key_share::{MLKEM768_CIPHERTEXT_LEN, MLKEM768_ENCAPSULATION_KEY_LEN};

/// Injectable randomness for deterministic tests.
pub trait HandshakeRng: Send {
    fn fill(&mut self, buf: &mut [u8]);
    fn gen_u32(&mut self) -> u32;
}

/// Production handshake RNG.
pub struct OsHandshakeRng;

impl HandshakeRng for OsHandshakeRng {
    fn fill(&mut self, buf: &mut [u8]) {
        getrandom::getrandom(buf).expect("OS RNG");
    }

    fn gen_u32(&mut self) -> u32 {
        let mut buf = [0u8; 4];
        self.fill(&mut buf);
        u32::from_le_bytes(buf)
    }
}

struct RngAdapter<'a>(&'a mut dyn HandshakeRng);

impl RngDraw for RngAdapter<'_> {
    fn draw_percent(&mut self) -> u32 {
        self.0.gen_u32() % 101
    }

    fn draw_between(&mut self, min: i32, max: i32) -> u32 {
        if max <= min {
            return min.max(0) as u32;
        }
        min as u32 + (self.0.gen_u32() % ((max - min + 1) as u32))
    }
}

/// Inbound VLESS Encryption server (upstream `ServerInstance` 1-RTT + 0-RTT paths).
#[derive(Clone)]
pub struct VlessEncryptionServer {
    config: Mlkem768X25519PlusConfig,
    nfs_chain: NfsServerChain,
    session_cache: Arc<SessionCache>,
}

impl VlessEncryptionServer {
    pub fn from_config(config: Mlkem768X25519PlusConfig) -> Result<Self, HandshakeError> {
        let nfs_chain = NfsServerChain::from_config(&config)?;
        Ok(Self {
            config: config.clone(),
            nfs_chain,
            session_cache: Arc::new(SessionCache::new(config.ticket_lifetime)),
        })
    }

    pub fn xor_mode(&self) -> XorMode {
        self.nfs_chain.xor_mode()
    }

    pub fn nfs_key_count(&self) -> usize {
        self.nfs_chain.key_count()
    }

    pub fn session_cache(&self) -> &SessionCache {
        &self.session_cache
    }

    #[cfg(test)]
    pub fn from_config_with_session_cache(
        config: Mlkem768X25519PlusConfig,
        session_cache: SessionCache,
    ) -> Result<Self, HandshakeError> {
        let nfs_chain = NfsServerChain::from_config(&config)?;
        Ok(Self {
            config: config.clone(),
            nfs_chain,
            session_cache: Arc::new(session_cache),
        })
    }

    pub async fn handshake<S, R>(
        &self,
        stream: S,
        rng: &mut R,
    ) -> Result<(ServerHandshakeResult, PrefixStream<S>), HandshakeError>
    where
        S: AsyncRead + AsyncWrite + Unpin,
        R: HandshakeRng,
    {
        self.handshake_with_timeout(stream, rng, DEFAULT_HANDSHAKE_TIMEOUT)
            .await
    }

    pub async fn handshake_with_timeout<S, R>(
        &self,
        stream: S,
        rng: &mut R,
        handshake_timeout: Duration,
    ) -> Result<(ServerHandshakeResult, PrefixStream<S>), HandshakeError>
    where
        S: AsyncRead + AsyncWrite + Unpin,
        R: HandshakeRng,
    {
        timeout(
            TokioDuration::from_secs(handshake_timeout.as_secs()),
            self.handshake_inner(stream, rng),
        )
        .await
        .map_err(|_| HandshakeError::Timeout)?
    }

    async fn handshake_inner<S, R>(
        &self,
        stream: S,
        rng: &mut R,
    ) -> Result<(ServerHandshakeResult, PrefixStream<S>), HandshakeError>
    where
        S: AsyncRead + AsyncWrite + Unpin,
        R: HandshakeRng,
    {
        let mut io = HandshakeStream::new(stream);
        let prefer_aes = prefer_aes_hardware();

        let iv_and_relays_len = IV_LEN + self.nfs_chain.relays_length();
        let iv_and_relays = io
            .read_exact(iv_and_relays_len)
            .await
            .map_err(HandshakeError::from)?;
        let mut iv = [0u8; IV_LEN];
        iv.copy_from_slice(&iv_and_relays[..IV_LEN]);
        let mut relays = iv_and_relays[IV_LEN..].to_vec();
        let nfs_key = self.nfs_chain.derive_nfs_key(&iv, &mut relays)?;

        let enc_len = io
            .read_exact(NFS_ENCRYPTED_LENGTH_LEN)
            .await
            .map_err(HandshakeError::from)?;
        let (plaintext_len, mut nfs_aead) = TrafficAead::open_auto_kind_with_state(
            &iv,
            nfs_key.as_bytes(),
            prefer_aes,
            &enc_len,
            &[],
        )
        .map_err(map_crypto_err)?;
        let plaintext_len = u16::from_be_bytes([plaintext_len[0], plaintext_len[1]]);

        if plaintext_len == ZERO_RTT_LENGTH {
            return self
                .handshake_zero_rtt(io, rng, iv, nfs_key, nfs_aead, prefer_aes)
                .await;
        }
        if usize::from(plaintext_len) < PFS_CLIENT_BUNDLE_MIN {
            return Err(HandshakeError::LengthExceeded);
        }

        self.handshake_one_rtt(io, rng, iv, nfs_key, nfs_aead, prefer_aes, plaintext_len)
            .await
    }

    async fn handshake_zero_rtt<S, R>(
        &self,
        mut io: HandshakeStream<S>,
        rng: &mut R,
        iv: [u8; IV_LEN],
        nfs_key: super::keys::SecretBytes<32>,
        mut nfs_aead: TrafficAead,
        prefer_aes: bool,
    ) -> Result<(ServerHandshakeResult, PrefixStream<S>), HandshakeError>
    where
        S: AsyncRead + AsyncWrite + Unpin,
        R: HandshakeRng,
    {
        if !self.session_cache.allows_zero_rtt() {
            return Err(HandshakeError::ResumeNotAllowed);
        }

        let enc_ticket = io
            .read_exact(ENCRYPTED_TICKET_LEN)
            .await
            .map_err(HandshakeError::from)?;
        let ticket_plain = nfs_aead.open(&enc_ticket, &[]).map_err(map_crypto_err)?;
        if ticket_plain.len() != 16 {
            return Err(HandshakeError::Malformed("unexpected ticket length"));
        }
        let mut ticket = [0u8; 16];
        ticket.copy_from_slice(&ticket_plain);

        let cached_pfs = match self
            .session_cache
            .lookup_for_resume(&ticket, nfs_key.as_bytes())
        {
            Ok(pfs) => pfs,
            Err(SessionLookupError::ReplayDetected) => {
                tracing::info!("VLESS encryption 0-RTT resume rejected: replay");
                return Err(HandshakeError::ReplayRejected);
            }
            Err(SessionLookupError::ExpiredSession) => {
                tracing::info!("VLESS encryption 0-RTT resume rejected: expired");
                write_invalid_ticket_noise(&mut io, rng).await?;
                return Err(HandshakeError::ExpiredSession);
            }
            Err(SessionLookupError::UnknownSession) => {
                tracing::info!("VLESS encryption 0-RTT resume rejected: unknown ticket");
                write_invalid_ticket_noise(&mut io, rng).await?;
                return Err(HandshakeError::UnknownSession);
            }
            Err(SessionLookupError::ResumeNotAllowed) => {
                return Err(HandshakeError::ResumeNotAllowed);
            }
        };

        tracing::info!("VLESS encryption 0-RTT resume accepted");

        let united_key = compose_united_key(&cached_pfs, nfs_key.as_bytes());
        let use_aes = matches!(nfs_aead.kind(), TrafficAeadKind::Aes256Gcm);

        let mut server_random = [0u8; 16];
        rng.fill(&mut server_random);

        let upload_keys = TrafficDirectionKeys {
            aead: TrafficAead::new(&server_random, united_key.as_bytes(), use_aes),
            context_label: server_random.to_vec(),
        };
        let download_keys = TrafficDirectionKeys {
            aead: TrafficAead::new(&enc_ticket, united_key.as_bytes(), use_aes),
            context_label: enc_ticket.to_vec(),
        };

        let xor_conn = if self.nfs_chain.xor_mode() == XorMode::Random {
            Some(XorConnState {
                outbound_ctr: CtrStream::new(united_key.as_bytes(), &server_random),
                inbound_ctr: CtrStream::new(united_key.as_bytes(), &iv),
                outbound_skip: 16,
                inbound_skip: 0,
            })
        } else {
            None
        };

        let prefix_stream = io.into_prefix_stream();
        let result = ServerHandshakeResult {
            united_key,
            pfs_key: cached_pfs,
            nfs_key,
            xor_mode: self.nfs_chain.xor_mode(),
            use_aes,
            client_iv: iv,
            upload_keys,
            download_keys,
            xor_conn,
            issued_ticket: ticket,
            ticket_lifetime_secs: 0,
            is_zero_rtt: true,
            server_prewrite: Some(server_random),
        };
        Ok((result, prefix_stream))
    }

    async fn handshake_one_rtt<S, R>(
        &self,
        mut io: HandshakeStream<S>,
        rng: &mut R,
        iv: [u8; IV_LEN],
        nfs_key: super::keys::SecretBytes<32>,
        mut nfs_aead: TrafficAead,
        prefer_aes: bool,
        plaintext_len: u16,
    ) -> Result<(ServerHandshakeResult, PrefixStream<S>), HandshakeError>
    where
        S: AsyncRead + AsyncWrite + Unpin,
        R: HandshakeRng,
    {
        let enc_pfs = io
            .read_exact(usize::from(plaintext_len))
            .await
            .map_err(HandshakeError::from)?;
        let client_pfs_public = open_nfs_plaintext_bytes(&mut nfs_aead, &enc_pfs, None)?;
        if client_pfs_public.len() != PFS_CLIENT_PUBLIC_KEY_LEN {
            return Err(HandshakeError::Malformed(
                "invalid PFS client public key length",
            ));
        }

        let mut client_ek = [0u8; MLKEM768_ENCAPSULATION_KEY_LEN];
        client_ek.copy_from_slice(&client_pfs_public[..MLKEM768_ENCAPSULATION_KEY_LEN]);
        let (pfs_ct, mlkem_shared) = encapsulate_mlkem768(&client_ek)
            .map_err(|_| HandshakeError::CryptoFailure("ML-KEM encapsulation failed"))?;

        let mut client_x25519 = [0u8; 32];
        client_x25519.copy_from_slice(&client_pfs_public[MLKEM768_ENCAPSULATION_KEY_LEN..]);
        super::x25519::validate_x25519_public_key(&client_x25519)
            .map_err(|_| HandshakeError::AuthenticationFailed)?;

        let mut server_x25519_secret = [0u8; 32];
        rng.fill(&mut server_x25519_secret);
        let server_x25519 = StaticSecret::from(server_x25519_secret);
        let server_x25519_public = PublicKey::from(&server_x25519);
        let peer_public = PublicKey::from(client_x25519);
        let x25519_shared = *server_x25519.diffie_hellman(&peer_public).as_bytes();

        let pfs_key = compose_pfs_key(mlkem_shared.as_bytes(), &x25519_shared);
        let united_key = compose_united_key(&pfs_key, nfs_key.as_bytes());
        let use_aes = matches!(nfs_aead.kind(), TrafficAeadKind::Aes256Gcm);

        let mut pfs_public_key = Vec::with_capacity(MLKEM768_CIPHERTEXT_LEN + 32);
        pfs_public_key.extend_from_slice(&pfs_ct);
        pfs_public_key.extend_from_slice(server_x25519_public.as_bytes());

        let mut upload_aead = TrafficAead::new(&pfs_public_key, united_key.as_bytes(), use_aes);
        let mut download_aead =
            TrafficAead::new(&client_pfs_public, united_key.as_bytes(), use_aes);

        let mut ticket = [0u8; 16];
        rng.fill(&mut ticket);
        let ticket_lifetime_secs = sample_ticket_lifetime(&self.config.ticket_lifetime, rng);
        if ticket_lifetime_secs > 0 {
            let encoded = super::hybrid::encode_ticket_lifetime_seconds(ticket_lifetime_secs)
                .map_err(|_| HandshakeError::Malformed("ticket lifetime out of range"))?;
            ticket[..2].copy_from_slice(&encoded);
            self.session_cache
                .insert(ticket, pfs_key.clone(), ticket_lifetime_secs);
        }

        let (padding_total, padding_lens, padding_gaps) =
            create_padding_lengths(&self.config.padding, &mut RngAdapter(rng));
        let mut server_hello =
            vec![0u8; PFS_SERVER_EXCHANGE_LEN + ENCRYPTED_TICKET_LEN + padding_total];

        let pfs_exchange = nfs_aead
            .seal_with_nonce(&MAX_NONCE, &pfs_public_key, &[])
            .map_err(map_crypto_err)?;
        if pfs_exchange.len() != PFS_SERVER_EXCHANGE_LEN {
            return Err(HandshakeError::Malformed("unexpected PFS exchange length"));
        }
        server_hello[..PFS_SERVER_EXCHANGE_LEN].copy_from_slice(&pfs_exchange);

        let enc_ticket = upload_aead.seal(&ticket, &[]).map_err(map_crypto_err)?;
        if enc_ticket.len() != ENCRYPTED_TICKET_LEN {
            return Err(HandshakeError::Malformed(
                "unexpected encrypted ticket length",
            ));
        }
        server_hello[PFS_SERVER_EXCHANGE_LEN..PFS_SERVER_EXCHANGE_LEN + ENCRYPTED_TICKET_LEN]
            .copy_from_slice(&enc_ticket);

        if padding_total > 0 {
            let padding = &mut server_hello[PFS_SERVER_EXCHANGE_LEN + ENCRYPTED_TICKET_LEN..];
            seal_padding_block(&mut upload_aead, padding, padding_total)?;
        }

        let mut write_lens = padding_lens;
        if !write_lens.is_empty() {
            write_lens[0] = PFS_SERVER_EXCHANGE_LEN + ENCRYPTED_TICKET_LEN + write_lens[0];
        }

        write_fragmented(&mut io, &server_hello, &write_lens, &padding_gaps).await?;

        let client_pad_len_record = io
            .read_exact(NFS_ENCRYPTED_LENGTH_LEN)
            .await
            .map_err(HandshakeError::from)?;
        let client_pad_len = open_nfs_plaintext(&mut nfs_aead, &client_pad_len_record, None)?;
        if client_pad_len == 0 {
            return Err(HandshakeError::Malformed("invalid client padding length"));
        }
        let enc_client_padding = io
            .read_exact(usize::from(client_pad_len))
            .await
            .map_err(HandshakeError::from)?;
        let _ = open_nfs_plaintext_bytes(&mut nfs_aead, &enc_client_padding, None)?;

        let prefix_stream = io.into_prefix_stream();

        let xor_conn = if self.nfs_chain.xor_mode() == XorMode::Random {
            Some(XorConnState {
                outbound_ctr: CtrStream::new(united_key.as_bytes(), &ticket),
                inbound_ctr: CtrStream::new(united_key.as_bytes(), &iv),
                outbound_skip: 0,
                inbound_skip: 0,
            })
        } else {
            None
        };

        tracing::info!("VLESS encryption 1-RTT handshake complete");

        let result = ServerHandshakeResult {
            united_key,
            pfs_key,
            nfs_key,
            xor_mode: self.nfs_chain.xor_mode(),
            use_aes,
            client_iv: iv,
            upload_keys: TrafficDirectionKeys {
                aead: upload_aead,
                context_label: pfs_public_key,
            },
            download_keys: TrafficDirectionKeys {
                aead: download_aead,
                context_label: client_pfs_public,
            },
            xor_conn,
            issued_ticket: ticket,
            ticket_lifetime_secs,
            is_zero_rtt: false,
            server_prewrite: None,
        };

        Ok((result, prefix_stream))
    }
}

async fn write_invalid_ticket_noise<S, R>(
    io: &mut HandshakeStream<S>,
    rng: &mut R,
) -> Result<(), HandshakeError>
where
    S: AsyncRead + AsyncWrite + Unpin,
    R: HandshakeRng,
{
    let (noise, _) = generate_invalid_ticket_noise(rng);
    io.write_all(&noise).await.map_err(HandshakeError::from)
}

fn open_nfs_plaintext(
    nfs_aead: &mut TrafficAead,
    ciphertext: &[u8],
    aad: Option<&[u8]>,
) -> Result<u16, HandshakeError> {
    let plaintext = nfs_aead
        .open(ciphertext, aad.unwrap_or(&[]))
        .map_err(map_crypto_err)?;
    if plaintext.len() != 2 {
        return Err(HandshakeError::Malformed("invalid NFS length plaintext"));
    }
    Ok(u16::from_be_bytes([plaintext[0], plaintext[1]]))
}

fn open_nfs_plaintext_bytes(
    nfs_aead: &mut TrafficAead,
    ciphertext: &[u8],
    aad: Option<&[u8]>,
) -> Result<Vec<u8>, HandshakeError> {
    nfs_aead
        .open(ciphertext, aad.unwrap_or(&[]))
        .map_err(map_crypto_err)
}

fn seal_padding_block(
    aead: &mut TrafficAead,
    padding: &mut [u8],
    padding_total: usize,
) -> Result<(), HandshakeError> {
    if padding_total < 18 + 16 {
        return Err(HandshakeError::Malformed("padding block too short"));
    }
    let len_plain = encode_length((padding_total - 18) as u16);
    let len_cipher = aead.seal(&len_plain, &[]).map_err(map_crypto_err)?;
    padding[..len_cipher.len()].copy_from_slice(&len_cipher);
    let body_plain = padding[18..padding_total - 16].to_vec();
    let body_cipher = aead.seal(&body_plain, &[]).map_err(map_crypto_err)?;
    padding[18..18 + body_cipher.len()].copy_from_slice(&body_cipher);
    Ok(())
}

fn sample_ticket_lifetime(range: &TicketLifetimeRange, rng: &mut impl HandshakeRng) -> u64 {
    if range.is_disabled() {
        return 0;
    }
    if range.max_secs == 0 {
        let factor = 50 + (rng.gen_u32() % 51);
        range.min_secs.saturating_mul(u64::from(factor)) / 100
    } else {
        let span = range.max_secs.saturating_sub(range.min_secs);
        range.min_secs + u64::from(rng.gen_u32() % (span as u32 + 1))
    }
}

async fn write_fragmented<S>(
    writer: &mut S,
    mut data: &[u8],
    lens: &[usize],
    gaps: &[Duration],
) -> Result<(), HandshakeError>
where
    S: AsyncWrite + Unpin,
{
    for (index, len) in lens.iter().copied().enumerate() {
        if len > 0 {
            if len > data.len() {
                return Err(HandshakeError::Malformed("padding write length overflow"));
            }
            writer
                .write_all(&data[..len])
                .await
                .map_err(HandshakeError::from)?;
            data = &data[len..];
        }
        if gaps.len() > index && !gaps[index].is_zero() {
            tokio::time::sleep(gaps[index]).await;
        }
    }
    Ok(())
}
