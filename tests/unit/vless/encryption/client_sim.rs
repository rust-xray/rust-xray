//! Minimal upstream-compatible 1-RTT client hello builder for server handshake tests.

use std::io;

use crate::reality::key_share::{MLKEM768_CIPHERTEXT_LEN, MLKEM768_ENCAPSULATION_KEY_LEN};
use crate::vless::encryption::HandshakeRng;
use crate::vless::encryption::{
    compose_pfs_key, compose_united_key, create_padding_lengths, decapsulate_mlkem768,
    encapsulate_mlkem768, encode_length, nfs_public_key_hash, prefer_aes_hardware,
    Mlkem768X25519PlusConfig, TrafficAead, TrafficDirectionKeys, VlessEncryptionServer,
    X25519SecretKey, XorMode,
};
use tokio::io::{duplex, AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use x25519_dalek::{PublicKey, StaticSecret};

use super::test_rng::TestHandshakeRng;
use crate::vless::encryption::client_session::{
    derive_client_session, read_server_1rtt_response, ClientEncryptedStream, ClientHelloMaterial,
    ClientSessionMaterial,
};
pub use crate::vless::encryption::client_session::{
    read_server_1rtt_response as read_server_handshake_response, server_1rtt_response_len,
};
use crate::vless::encryption::handshake::{ENCRYPTED_TICKET_LEN, PFS_SERVER_EXCHANGE_LEN};
use crate::vless::encryption::header::decode_traffic_header;
use crate::vless::encryption::hybrid::PFS_KEY_LEN;
use crate::vless::encryption::nfs::NfsServerChain;
use crate::vless::encryption::nonce::MAX_NONCE;
use crate::vless::encryption::xor::CtrStream;
use crate::vless::encryption::EncryptedWriter;

const TRAFFIC_HEADER_LEN: usize = 5;

pub struct ClientHelloParts {
    pub iv: [u8; 16],
    pub nfs_key: [u8; 32],
    pub client_pfs_public: Vec<u8>,
    pub client_x25519_secret: [u8; 32],
    pub mlkem_seed: [u8; 64],
}

impl ClientHelloParts {
    pub fn as_material(&self) -> ClientHelloMaterial {
        ClientHelloMaterial {
            iv: self.iv,
            nfs_key: self.nfs_key,
            client_pfs_public: self.client_pfs_public.clone(),
            client_x25519_secret: self.client_x25519_secret,
            mlkem_seed: self.mlkem_seed,
        }
    }
}

pub fn build_native_x25519_client_hello(
    config: &Mlkem768X25519PlusConfig,
    server_secret: &X25519SecretKey,
    rng: &mut TestHandshakeRng,
) -> (Vec<u8>, ClientHelloParts) {
    let server_public = crate::vless::encryption::x25519_public_key(server_secret);
    let mut iv = [0u8; 16];
    rng.fill(&mut iv);
    let mut client_secret = [0u8; 32];
    rng.fill(&mut client_secret);
    let client_static = StaticSecret::from(client_secret);
    let client_public = PublicKey::from(&client_static);
    let nfs_key = *client_static
        .diffie_hellman(&PublicKey::from(*server_public.as_bytes()))
        .as_bytes();
    let mut relays = vec![0u8; 32];
    relays.copy_from_slice(client_public.as_bytes());
    if config.xor_mode != XorMode::Native {
        let mut stream = CtrStream::new(server_public.as_bytes(), &iv);
        stream.apply_keystream(&mut relays);
    }
    build_client_hello_with_relays(config, rng, &iv, &relays, nfs_key, true)
}

/// ML-KEM-only NFS chain client hello (single static ML-KEM decapsulation key on server).
pub fn build_mlkem_only_client_hello(
    config: &Mlkem768X25519PlusConfig,
    rng: &mut TestHandshakeRng,
) -> (Vec<u8>, ClientHelloParts) {
    let chain = NfsServerChain::from_config(config).expect("nfs chain");
    let mlkem_public = config.nfs_keys[0].public_key_bytes().expect("mlkem public");
    let ek: [u8; MLKEM768_ENCAPSULATION_KEY_LEN] = mlkem_public.as_slice().try_into().expect("ek");
    let (ciphertext, shared) = encapsulate_mlkem768(&ek).expect("encapsulate");
    assert_eq!(ciphertext.len(), chain.relays_length());

    let mut iv = [0u8; 16];
    rng.fill(&mut iv);
    let mut relays = ciphertext;
    if config.xor_mode != XorMode::Native {
        let mut stream = CtrStream::new(mlkem_public.as_slice(), &iv);
        stream.apply_keystream(&mut relays);
    }
    build_client_hello_with_relays(config, rng, &iv, &relays, *shared.as_bytes(), true)
}

/// X25519 → ML-KEM mixed NFS chain client hello.
pub fn build_mixed_nfs_client_hello(
    config: &Mlkem768X25519PlusConfig,
    server_x25519_secret: &X25519SecretKey,
    rng: &mut TestHandshakeRng,
) -> (Vec<u8>, ClientHelloParts) {
    let chain = NfsServerChain::from_config(config).expect("nfs chain");
    let server_x25519_public = crate::vless::encryption::x25519_public_key(server_x25519_secret);
    let mlkem_public = config.nfs_keys[1].public_key_bytes().expect("mlkem public");

    let mut iv = [0u8; 16];
    rng.fill(&mut iv);

    let mut client_nfs_secret = [0u8; 32];
    rng.fill(&mut client_nfs_secret);
    let client_nfs = StaticSecret::from(client_nfs_secret);
    let client_nfs_public = PublicKey::from(&client_nfs);
    let x25519_shared =
        client_nfs.diffie_hellman(&PublicKey::from(*server_x25519_public.as_bytes()));

    let ek: [u8; MLKEM768_ENCAPSULATION_KEY_LEN] = mlkem_public.as_slice().try_into().expect("ek");
    let (mut ciphertext, mlkem_shared) = encapsulate_mlkem768(&ek).expect("encapsulate");
    {
        let mut stream = CtrStream::new(x25519_shared.as_bytes(), &iv);
        stream.apply_keystream(&mut ciphertext[..32]);
    }

    let mut relays = vec![0u8; chain.relays_length()];
    relays[..32].copy_from_slice(client_nfs_public.as_bytes());
    if config.xor_mode != XorMode::Native {
        let mut stream = CtrStream::new(server_x25519_public.as_bytes(), &iv);
        stream.apply_keystream(&mut relays[..32]);
    }

    let mut hash_region = nfs_public_key_hash(&mlkem_public);
    let mut ctr = CtrStream::new(x25519_shared.as_bytes(), &iv);
    ctr.apply_keystream(&mut hash_region);
    relays[32..64].copy_from_slice(&hash_region);
    relays[64..64 + MLKEM768_CIPHERTEXT_LEN].copy_from_slice(&ciphertext);
    if config.xor_mode != XorMode::Native {
        let mut stream = CtrStream::new(mlkem_public.as_slice(), &iv);
        stream.apply_keystream(&mut relays[64..64 + MLKEM768_CIPHERTEXT_LEN]);
    }

    build_client_hello_with_relays(config, rng, &iv, &relays, *mlkem_shared.as_bytes(), true)
}

fn build_client_hello_with_relays(
    config: &Mlkem768X25519PlusConfig,
    rng: &mut TestHandshakeRng,
    iv: &[u8; 16],
    relays: &[u8],
    nfs_key: [u8; 32],
    empty_padding: bool,
) -> (Vec<u8>, ClientHelloParts) {
    let relays_len = relays.len();
    let pfs_exchange_len = 18 + MLKEM768_ENCAPSULATION_KEY_LEN + 32 + 16;
    let padding_total = if empty_padding {
        34usize
    } else {
        create_padding_lengths(&config.padding, rng).0
    };
    let mut hello = vec![0u8; 16 + relays_len + pfs_exchange_len + padding_total];

    hello[..16].copy_from_slice(iv);
    hello[16..16 + relays_len].copy_from_slice(relays);

    let mut nfs_aead = TrafficAead::new(iv, &nfs_key, true);

    let mut mlkem_seed = [0u8; 64];
    rng.fill(&mut mlkem_seed);
    let mlkem_ek = {
        use ml_kem::ml_kem_768::MlKem768;
        use ml_kem::{FromSeed, KeyExport, Seed};
        let seed = Seed::from(mlkem_seed);
        let (_, ek) = MlKem768::from_seed(&seed);
        ek.to_bytes().to_vec()
    };

    let mut client_x25519_secret = [0u8; 32];
    rng.fill(&mut client_x25519_secret);
    let client_x25519 = StaticSecret::from(client_x25519_secret);
    let client_x25519_public = PublicKey::from(&client_x25519);

    let mut client_pfs_public = Vec::with_capacity(MLKEM768_ENCAPSULATION_KEY_LEN + 32);
    client_pfs_public.extend_from_slice(&mlkem_ek);
    client_pfs_public.extend_from_slice(client_x25519_public.as_bytes());

    let pfs_start = 16 + relays_len;
    let len_cipher = nfs_aead
        .seal(&encode_length((pfs_exchange_len - 18) as u16), &[])
        .expect("seal pfs length");
    hello[pfs_start..pfs_start + len_cipher.len()].copy_from_slice(&len_cipher);

    let body_cipher = nfs_aead
        .seal(&client_pfs_public, &[])
        .expect("seal pfs body");
    hello[pfs_start + 18..pfs_start + 18 + body_cipher.len()].copy_from_slice(&body_cipher);

    if padding_total > 0 {
        let pad_start = pfs_start + pfs_exchange_len;
        let padding = &mut hello[pad_start..];
        let len_plain = encode_length((padding_total.saturating_sub(18)) as u16);
        let len_pad_cipher = nfs_aead.seal(&len_plain, &[]).expect("pad len");
        padding[..len_pad_cipher.len()].copy_from_slice(&len_pad_cipher);
        let body_len = padding_total.saturating_sub(18 + 16);
        let body = vec![0u8; body_len];
        let body_cipher = nfs_aead.seal(&body, &[]).expect("pad body");
        padding[18..18 + body_cipher.len()].copy_from_slice(&body_cipher);
    }

    (
        hello,
        ClientHelloParts {
            iv: *iv,
            nfs_key,
            client_pfs_public,
            client_x25519_secret,
            mlkem_seed,
        },
    )
}

/// Client-side random-mode wire XOR (mirrors server `XorConnState` from the peer perspective).
pub struct ClientRandomXor {
    upload: ClientXorDirection,
    download: ClientXorDirection,
}

struct ClientXorDirection {
    ctr: CtrStream,
    skip: usize,
    header: Vec<u8>,
}

impl ClientRandomXor {
    pub fn new(united_key: &[u8; 96], client_iv: &[u8; 16], ticket: &[u8; 16]) -> Self {
        Self {
            upload: ClientXorDirection {
                ctr: CtrStream::new(united_key, client_iv),
                skip: 0,
                header: Vec::with_capacity(TRAFFIC_HEADER_LEN),
            },
            download: ClientXorDirection {
                ctr: CtrStream::new(united_key, ticket),
                skip: 0,
                header: Vec::with_capacity(TRAFFIC_HEADER_LEN),
            },
        }
    }

    pub fn transform_upload(&mut self, buf: &mut [u8]) {
        apply_client_xor(&mut self.upload, buf);
    }

    pub fn transform_download(&mut self, buf: &mut [u8]) {
        apply_client_xor(&mut self.download, buf);
    }
}

fn apply_client_xor(state: &mut ClientXorDirection, buf: &mut [u8]) {
    let mut offset = 0usize;
    while offset < buf.len() {
        let mut p = &mut buf[offset..];
        if state.skip > 0 {
            if p.len() <= state.skip {
                state.skip -= p.len();
                break;
            }
            p = &mut p[state.skip..];
            state.skip = 0;
        }
        let need = TRAFFIC_HEADER_LEN.saturating_sub(state.header.len());
        if p.len() < need {
            state.ctr.apply_keystream(p);
            state.header.extend_from_slice(p);
            break;
        }
        state.ctr.apply_keystream(&mut p[..need]);
        state.header.extend_from_slice(&p[..need]);
        if let Ok(payload_len) = decode_traffic_header(&{
            let mut arr = [0u8; TRAFFIC_HEADER_LEN];
            arr.copy_from_slice(&state.header);
            arr
        }) {
            state.skip = payload_len as usize;
        }
        state.header.clear();
        offset += need;
    }
}

pub fn open_server_ticket(
    parts: &ClientHelloParts,
    server_response: &[u8],
) -> io::Result<[u8; 16]> {
    Ok(derive_client_session(&parts.as_material(), server_response)?.ticket)
}

pub fn client_random_xor_from_response(
    parts: &ClientHelloParts,
    server_response: &[u8],
) -> io::Result<ClientRandomXor> {
    let session = derive_client_session(&parts.as_material(), server_response)?;
    Ok(ClientRandomXor::new(
        &session.united,
        &session.client_iv,
        &session.ticket,
    ))
}

pub fn seal_client_traffic_random(
    writer: &mut EncryptedWriter,
    xor: &mut ClientRandomXor,
    plaintext: &[u8],
) -> io::Result<Vec<u8>> {
    let mut frame = seal_client_traffic(writer, plaintext)?.to_vec();
    xor.transform_upload(&mut frame);
    Ok(frame)
}

/// Whole-frame random-mode XOR (test fallback matching upstream `XorConn` stream obfuscation).
pub fn seal_client_traffic_random_whole_frame(
    united_key: &[u8; 96],
    client_iv: &[u8; 16],
    writer: &mut EncryptedWriter,
    plaintext: &[u8],
) -> io::Result<Vec<u8>> {
    let mut frame = seal_client_traffic(writer, plaintext)?.to_vec();
    crate::vless::encryption::ctr_xor(united_key, client_iv, &mut frame);
    Ok(frame)
}

pub fn server_config_from_single_x25519(secret: &X25519SecretKey) -> Mlkem768X25519PlusConfig {
    use crate::vless::encryption::{
        NfsStaticKey, PaddingProfile, SecretBytes, TicketLifetimeRange,
    };
    Mlkem768X25519PlusConfig {
        xor_mode: XorMode::Native,
        ticket_lifetime: TicketLifetimeRange {
            min_secs: 0,
            max_secs: 0,
        },
        nfs_keys: vec![NfsStaticKey::X25519(SecretBytes::new(*secret.as_bytes()))],
        padding: PaddingProfile {
            // Threshold 101 => deterministic zero server padding in tests.
            length_ranges: vec![[101, 35, 35]],
            gap_ranges: vec![],
        },
    }
}

pub fn relay_hash_for_next(public_key: &[u8]) -> [u8; 32] {
    nfs_public_key_hash(public_key)
}

pub fn client_traffic_keys_for_test(
    parts: &ClientHelloParts,
    server_response: &[u8],
) -> io::Result<(TrafficDirectionKeys, TrafficDirectionKeys, [u8; 96], bool)> {
    let session = derive_client_session(&parts.as_material(), server_response)?;
    Ok((
        session.upload,
        session.download,
        session.united,
        session.use_aes,
    ))
}

pub fn client_download_reader(
    parts: &ClientHelloParts,
    server_response: &[u8],
) -> io::Result<crate::vless::encryption::EncryptedReader> {
    let session = derive_client_session(&parts.as_material(), server_response)?;
    Ok(
        crate::vless::encryption::EncryptedReader::new_post_handshake(
            session.download,
            session.united,
            session.use_aes,
        ),
    )
}

pub fn client_upload_writer(
    parts: &ClientHelloParts,
    server_response: &[u8],
) -> io::Result<EncryptedWriter> {
    let session = derive_client_session(&parts.as_material(), server_response)?;
    Ok(EncryptedWriter::new(session.upload))
}

pub fn client_encrypted_stream<S>(
    inner: S,
    parts: &ClientHelloParts,
    server_response: &[u8],
    xor_mode: XorMode,
) -> io::Result<ClientEncryptedStream<S>> {
    let session = derive_client_session(&parts.as_material(), server_response)?;
    ClientEncryptedStream::from_session(inner, session, xor_mode)
}

pub async fn client_complete_1rtt_handshake<S>(
    mut stream: S,
    hello: &[u8],
    parts: &ClientHelloParts,
    config: &Mlkem768X25519PlusConfig,
    server_rng_seed: u64,
    xor_mode: XorMode,
) -> io::Result<ClientEncryptedStream<S>>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    stream.write_all(hello).await?;
    let response = read_server_1rtt_response(&mut stream, config, server_rng_seed).await?;
    client_encrypted_stream(stream, parts, &response, xor_mode)
}

pub fn seal_client_traffic(writer: &mut EncryptedWriter, plaintext: &[u8]) -> io::Result<Vec<u8>> {
    writer.build_record(plaintext).map(|b| b.to_vec())
}

/// Write client hello, read server response, and send encrypted application bytes.
pub async fn client_1rtt_handshake_and_write<S>(
    stream: S,
    hello: &[u8],
    parts: &ClientHelloParts,
    config: &Mlkem768X25519PlusConfig,
    server_rng_seed: u64,
    xor_mode: XorMode,
    traffic_plaintext: &[u8],
) -> io::Result<()>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let mut encrypted =
        client_complete_1rtt_handshake(stream, hello, parts, config, server_rng_seed, xor_mode)
            .await?;
    encrypted.write_all(traffic_plaintext).await?;
    encrypted.flush().await?;
    // Hold the encrypted session open briefly so the server can finish reading
    // application records before the duplex write half closes.
    tokio::time::sleep(std::time::Duration::from_millis(500)).await;
    Ok(())
}

/// Client resume state captured after a successful 1-RTT handshake.
#[derive(Debug, Clone)]
pub struct ClientResumeState {
    pub ticket: [u8; 16],
    pub pfs_key: [u8; PFS_KEY_LEN],
    pub client_iv: [u8; 16],
    pub use_aes: bool,
}

pub fn client_resume_state_from_1rtt(
    parts: &ClientHelloParts,
    server_response: &[u8],
) -> io::Result<ClientResumeState> {
    let session = derive_client_session(&parts.as_material(), server_response)?;
    let mut pfs_key = [0u8; PFS_KEY_LEN];
    pfs_key.copy_from_slice(&session.united[..PFS_KEY_LEN]);
    Ok(ClientResumeState {
        ticket: session.ticket,
        pfs_key,
        client_iv: session.client_iv,
        use_aes: session.use_aes,
    })
}

/// Build upstream-compatible 0-RTT client hello (IV + relays + enc_len=32 + enc_ticket).
pub fn build_zero_rtt_client_hello(
    config: &Mlkem768X25519PlusConfig,
    resume: &ClientResumeState,
    server_secret: &X25519SecretKey,
    rng: &mut TestHandshakeRng,
) -> (Vec<u8>, ClientHelloParts, Vec<u8>) {
    let (hello, parts) = build_native_x25519_client_hello(config, server_secret, rng);
    let use_aes = prefer_aes_hardware();
    let mut nfs_aead = TrafficAead::new(&parts.iv, &parts.nfs_key, use_aes);
    let len_cipher = nfs_aead
        .seal(&encode_length(32), &[])
        .expect("0rtt length seal");
    let ticket_cipher = nfs_aead
        .seal(&resume.ticket, &[])
        .expect("0rtt ticket seal");

    let iv_and_relays_len = 16
        + NfsServerChain::from_config(config)
            .expect("nfs")
            .relays_length();
    let mut out = vec![0u8; iv_and_relays_len + len_cipher.len() + ticket_cipher.len()];
    out[..iv_and_relays_len].copy_from_slice(&hello[..iv_and_relays_len]);
    out[iv_and_relays_len..iv_and_relays_len + len_cipher.len()].copy_from_slice(&len_cipher);
    out[iv_and_relays_len + len_cipher.len()..].copy_from_slice(&ticket_cipher);
    (out, parts, ticket_cipher)
}

/// Build coalesced 0-RTT hello prefix + encrypted application record(s).
pub fn build_zero_rtt_coalesced_wire(
    config: &Mlkem768X25519PlusConfig,
    resume: &ClientResumeState,
    server_secret: &X25519SecretKey,
    rng: &mut TestHandshakeRng,
    plaintext_chunks: &[&[u8]],
) -> (Vec<u8>, ClientHelloParts, Vec<u8>) {
    build_zero_rtt_coalesced_wire_inner(config, resume, server_secret, rng, plaintext_chunks)
        .expect("coalesced wire")
}

fn build_zero_rtt_coalesced_wire_inner(
    config: &Mlkem768X25519PlusConfig,
    resume: &ClientResumeState,
    server_secret: &X25519SecretKey,
    rng: &mut TestHandshakeRng,
    plaintext_chunks: &[&[u8]],
) -> io::Result<(Vec<u8>, ClientHelloParts, Vec<u8>)> {
    let (hello, parts, enc_ticket) =
        build_zero_rtt_client_hello(config, resume, server_secret, rng);
    let mut writer = client_zero_rtt_upload_writer(resume, &parts, &enc_ticket);
    let mut wire = hello;
    for chunk in plaintext_chunks {
        let frame = if config.xor_mode == XorMode::Random {
            seal_client_traffic_random_upload_frame(&mut writer, resume, &parts, chunk)?
        } else {
            seal_client_traffic(&mut writer, chunk)?
        };
        wire.extend_from_slice(&frame);
    }
    Ok((wire, parts, enc_ticket))
}

fn seal_client_traffic_random_upload_frame(
    writer: &mut crate::vless::encryption::EncryptedWriter,
    resume: &ClientResumeState,
    parts: &ClientHelloParts,
    plaintext: &[u8],
) -> io::Result<Vec<u8>> {
    use crate::vless::encryption::stream::XorTrafficWriter;
    let mut frame = seal_client_traffic(writer, plaintext)?;
    let united = zero_rtt_united_key(resume, parts);
    let mut xor = XorTrafficWriter::new_client_upload(&united, &parts.iv);
    crate::vless::encryption::stream::apply_xor_write_for_test(&mut xor, &mut frame);
    Ok(frame)
}

fn zero_rtt_united_key(
    resume: &ClientResumeState,
    parts: &ClientHelloParts,
) -> [u8; crate::vless::encryption::hybrid::UNITED_KEY_LEN] {
    use crate::reality::key_share::MLKEM768_SHARED_SECRET_LEN;
    let pfs = compose_pfs_key(
        resume.pfs_key[..MLKEM768_SHARED_SECRET_LEN]
            .try_into()
            .expect("mlkem"),
        resume.pfs_key[MLKEM768_SHARED_SECRET_LEN..]
            .try_into()
            .expect("x25519"),
    );
    *compose_united_key(&pfs, &parts.nfs_key).as_bytes()
}

pub fn server_secret_for_tests() -> X25519SecretKey {
    X25519SecretKey::from_bytes(core::array::from_fn(|i| (i + 1) as u8))
}

pub fn config_with_ticket_lifetime_and_xor(
    secret: &X25519SecretKey,
    min_secs: u64,
    max_secs: u64,
    xor_mode: XorMode,
) -> Mlkem768X25519PlusConfig {
    let mut config = server_config_with_ticket_lifetime(secret, min_secs, max_secs);
    config.xor_mode = xor_mode;
    config
}

/// Client-side 0-RTT encrypted stream after hello bytes were written separately.
pub fn client_zero_rtt_stream<S>(
    inner: S,
    resume: &ClientResumeState,
    parts: &ClientHelloParts,
    enc_ticket: &[u8],
    xor_mode: XorMode,
) -> io::Result<ClientEncryptedStream<S>> {
    use crate::reality::key_share::MLKEM768_SHARED_SECRET_LEN;
    let pfs = compose_pfs_key(
        resume.pfs_key[..MLKEM768_SHARED_SECRET_LEN]
            .try_into()
            .expect("mlkem"),
        resume.pfs_key[MLKEM768_SHARED_SECRET_LEN..]
            .try_into()
            .expect("x25519"),
    );
    let united = compose_united_key(&pfs, &parts.nfs_key);
    let upload = TrafficDirectionKeys {
        aead: TrafficAead::new(enc_ticket, united.as_bytes(), resume.use_aes),
        context_label: enc_ticket.to_vec(),
    };
    let download = TrafficDirectionKeys {
        aead: TrafficAead::new(enc_ticket, united.as_bytes(), resume.use_aes),
        context_label: enc_ticket.to_vec(),
    };
    let session = ClientSessionMaterial {
        upload,
        download,
        united: *united.as_bytes(),
        use_aes: resume.use_aes,
        ticket: resume.ticket,
        client_iv: parts.iv,
    };
    ClientEncryptedStream::from_session(inner, session, xor_mode)
}

/// 0-RTT client stream with correct server-random download AEAD context.
pub fn client_zero_rtt_duplex_stream<S>(
    inner: S,
    resume: &ClientResumeState,
    parts: &ClientHelloParts,
    enc_ticket: &[u8],
    server_random: &[u8; 16],
    xor_mode: XorMode,
) -> io::Result<ClientEncryptedStream<S>> {
    use crate::reality::key_share::MLKEM768_SHARED_SECRET_LEN;
    let pfs = compose_pfs_key(
        resume.pfs_key[..MLKEM768_SHARED_SECRET_LEN]
            .try_into()
            .expect("mlkem"),
        resume.pfs_key[MLKEM768_SHARED_SECRET_LEN..]
            .try_into()
            .expect("x25519"),
    );
    let united = compose_united_key(&pfs, &parts.nfs_key);
    let upload = TrafficDirectionKeys {
        aead: TrafficAead::new(enc_ticket, united.as_bytes(), resume.use_aes),
        context_label: enc_ticket.to_vec(),
    };
    let download = TrafficDirectionKeys {
        aead: TrafficAead::new(server_random, united.as_bytes(), resume.use_aes),
        context_label: server_random.to_vec(),
    };
    let session = ClientSessionMaterial {
        upload,
        download,
        united: *united.as_bytes(),
        use_aes: resume.use_aes,
        ticket: *server_random,
        client_iv: parts.iv,
    };
    ClientEncryptedStream::from_zero_rtt_session(inner, session, xor_mode)
}

pub fn client_zero_rtt_upload_writer(
    resume: &ClientResumeState,
    parts: &ClientHelloParts,
    enc_ticket: &[u8],
) -> crate::vless::encryption::EncryptedWriter {
    use crate::reality::key_share::MLKEM768_SHARED_SECRET_LEN;
    let pfs = compose_pfs_key(
        resume.pfs_key[..MLKEM768_SHARED_SECRET_LEN]
            .try_into()
            .expect("mlkem"),
        resume.pfs_key[MLKEM768_SHARED_SECRET_LEN..]
            .try_into()
            .expect("x25519"),
    );
    let united = compose_united_key(&pfs, &parts.nfs_key);
    let upload = TrafficDirectionKeys {
        aead: TrafficAead::new(enc_ticket, united.as_bytes(), resume.use_aes),
        context_label: enc_ticket.to_vec(),
    };
    crate::vless::encryption::EncryptedWriter::new(upload)
}

pub fn seal_client_zero_rtt_traffic(
    writer: &mut crate::vless::encryption::EncryptedWriter,
    xor_mode: XorMode,
    united: &[u8; crate::vless::encryption::hybrid::UNITED_KEY_LEN],
    iv: &[u8; 16],
    plaintext: &[u8],
) -> io::Result<Vec<u8>> {
    let mut frame = seal_client_traffic(writer, plaintext)?;
    if xor_mode == XorMode::Random {
        let mut xor = ClientRandomXor::new(united, iv, &[0u8; 16]);
        xor.transform_upload(&mut frame);
    }
    Ok(frame)
}

pub async fn read_zero_rtt_random_download_payload<S>(
    mut io: S,
    server_random: &[u8; 16],
    resume: &ClientResumeState,
    parts: &ClientHelloParts,
    expected_len: usize,
) -> io::Result<Vec<u8>>
where
    S: AsyncRead + Unpin,
{
    use crate::reality::key_share::MLKEM768_SHARED_SECRET_LEN;
    use crate::vless::encryption::handshake::TrafficDirectionKeys;
    use crate::vless::encryption::header::decode_traffic_header;
    use crate::vless::encryption::stream::{
        apply_xor_read_for_test, EncryptedReader, XorTrafficReader,
    };

    let mut raw = Vec::new();
    io.read_to_end(&mut raw).await?;
    if raw.len() <= 16 {
        return Err(io::Error::new(
            io::ErrorKind::UnexpectedEof,
            "missing 0-RTT server prewrite",
        ));
    }
    if raw[..16] != *server_random {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "unexpected 0-RTT server prewrite",
        ));
    }
    let mut frame = raw[16..].to_vec();
    let pfs = compose_pfs_key(
        resume.pfs_key[..MLKEM768_SHARED_SECRET_LEN]
            .try_into()
            .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "mlkem"))?,
        resume.pfs_key[MLKEM768_SHARED_SECRET_LEN..]
            .try_into()
            .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "x25519"))?,
    );
    let united = *compose_united_key(&pfs, &parts.nfs_key).as_bytes();
    let mut xor = XorTrafficReader::new_client_download_with_skip(&united, server_random, 16);
    apply_xor_read_for_test(&mut xor, &mut frame);
    if frame.len() < 5 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "truncated 0-RTT download frame",
        ));
    }
    let header: [u8; 5] = frame[..5]
        .try_into()
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "header"))?;
    let payload_len = decode_traffic_header(&header).map_err(|err| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            format!("invalid 0-RTT download header: {err}"),
        )
    })? as usize;
    if frame.len() < 5 + payload_len {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "truncated 0-RTT download body",
        ));
    }
    let body = &frame[5..5 + payload_len];
    let download = TrafficDirectionKeys {
        aead: TrafficAead::new(server_random, &united, resume.use_aes),
        context_label: server_random.to_vec(),
    };
    let mut reader = EncryptedReader::new_post_handshake(download, united, resume.use_aes);
    let opened = reader
        .decrypt_record(&header, body)
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "0-RTT download open failed"))?;
    if opened.len() != expected_len {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "unexpected 0-RTT download length",
        ));
    }
    Ok(opened.to_vec())
}

pub async fn perform_1rtt_and_capture_resume(
    server: &VlessEncryptionServer,
    config: &Mlkem768X25519PlusConfig,
    server_rng_seed: u64,
) -> (ClientResumeState, ClientHelloParts) {
    let secret = server_secret_for_tests();
    let (hello, parts) =
        build_native_x25519_client_hello(config, &secret, &mut TestHandshakeRng::new(42));
    let (mut client_io, server_io) = duplex(65536);
    let server = server.clone();
    let server_task = tokio::spawn(async move {
        server
            .handshake(server_io, &mut TestHandshakeRng::new(server_rng_seed))
            .await
            .expect("1rtt")
    });
    client_io.write_all(&hello).await.expect("hello");
    let response = read_server_1rtt_response(&mut client_io, config, server_rng_seed)
        .await
        .expect("response");
    let (result, _) = server_task.await.expect("task");
    assert!(!result.is_zero_rtt);
    let resume = client_resume_state_from_1rtt(&parts, &response).expect("resume");
    (resume, parts)
}

pub fn server_config_with_ticket_lifetime(
    secret: &X25519SecretKey,
    min_secs: u64,
    max_secs: u64,
) -> Mlkem768X25519PlusConfig {
    use crate::vless::encryption::{
        NfsStaticKey, PaddingProfile, SecretBytes, TicketLifetimeRange,
    };
    Mlkem768X25519PlusConfig {
        xor_mode: XorMode::Native,
        ticket_lifetime: TicketLifetimeRange { min_secs, max_secs },
        nfs_keys: vec![NfsStaticKey::X25519(SecretBytes::new(*secret.as_bytes()))],
        padding: PaddingProfile {
            length_ranges: vec![[101, 35, 35]],
            gap_ranges: vec![],
        },
    }
}
