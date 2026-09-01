use bytes::Bytes;

use crate::reality::key_share::MLKEM768_SHARED_SECRET_LEN;
use crate::vless::encryption::aead::TrafficAead;
use crate::vless::encryption::handshake::{ServerHandshakeResult, TrafficDirectionKeys};
use crate::vless::encryption::hybrid::{compose_pfs_key, compose_united_key};
use crate::vless::encryption::io::PrefixStream;
use crate::vless::encryption::keys::SecretBytes;
use crate::vless::encryption::stream::VlessEncryptedStream;
use crate::vless::encryption::{reset_test_seal_count, EncryptedWriter, XorMode};

use super::stream_helpers::ScriptStream;

pub fn test_united() -> [u8; 96] {
    [0x5au8; 96]
}

pub fn test_context_labels() -> (Vec<u8>, Vec<u8>) {
    (
        b"client-pfs-public-key-32-bytes!!".to_vec(),
        b"server-pfs-public-key-32-bytes!!".to_vec(),
    )
}

pub fn test_direction_keys() -> (TrafficDirectionKeys, TrafficDirectionKeys, [u8; 96]) {
    let united = test_united();
    let (client_ctx, server_ctx) = test_context_labels();
    let upload = TrafficDirectionKeys {
        aead: TrafficAead::new(&server_ctx, &united, true),
        context_label: server_ctx,
    };
    let download = TrafficDirectionKeys {
        aead: TrafficAead::new(&client_ctx, &united, true),
        context_label: client_ctx,
    };
    (upload, download, united)
}

pub fn client_writer_keys() -> (TrafficDirectionKeys, [u8; 96]) {
    let united = test_united();
    let (client_ctx, _) = test_context_labels();
    (
        TrafficDirectionKeys {
            aead: TrafficAead::new(&client_ctx, &united, true),
            context_label: client_ctx,
        },
        united,
    )
}

pub fn dummy_handshake_result(
    upload: TrafficDirectionKeys,
    download: TrafficDirectionKeys,
    united: [u8; 96],
    use_aes: bool,
) -> ServerHandshakeResult {
    let mut mlkem = [0u8; MLKEM768_SHARED_SECRET_LEN];
    let mut x25519 = [0u8; 32];
    let mut nfs = [0u8; 32];
    mlkem.copy_from_slice(&united[..MLKEM768_SHARED_SECRET_LEN]);
    x25519.copy_from_slice(&united[MLKEM768_SHARED_SECRET_LEN..MLKEM768_SHARED_SECRET_LEN + 32]);
    nfs.copy_from_slice(&united[MLKEM768_SHARED_SECRET_LEN + 32..]);
    let pfs_key = compose_pfs_key(&mlkem, &x25519);
    ServerHandshakeResult {
        united_key: compose_united_key(&pfs_key, &nfs),
        pfs_key,
        nfs_key: SecretBytes::new(nfs),
        xor_mode: XorMode::Native,
        use_aes: use_aes,
        client_iv: [0x44u8; 16],
        upload_keys: upload,
        download_keys: download,
        xor_conn: None,
        issued_ticket: [0u8; 16],
        ticket_lifetime_secs: 0,
        is_zero_rtt: false,
        server_prewrite: None,
    }
}

pub fn make_encrypted_on<S>(inner: S, use_aes: bool) -> VlessEncryptedStream<PrefixStream<S>> {
    let (upload, download, united) = test_direction_keys();
    let result = dummy_handshake_result(upload, download, united, use_aes);
    VlessEncryptedStream::from_handshake(PrefixStream::new(inner, Bytes::new()), result)
}

pub fn make_encrypted_on_with_result<S>(
    inner: S,
    result: ServerHandshakeResult,
) -> VlessEncryptedStream<PrefixStream<S>> {
    VlessEncryptedStream::from_handshake(PrefixStream::new(inner, Bytes::new()), result)
}

pub fn make_encrypted_stream(
    read_data: Vec<u8>,
    prefix: Vec<u8>,
) -> VlessEncryptedStream<PrefixStream<ScriptStream>> {
    let inner = ScriptStream::from_read(read_data);
    let (upload, download, united) = test_direction_keys();
    let result = dummy_handshake_result(upload, download, united, true);
    VlessEncryptedStream::from_handshake(PrefixStream::new(inner, Bytes::from(prefix)), result)
}

pub fn make_encrypted_stream_with_keys(
    read_data: Vec<u8>,
    download: TrafficDirectionKeys,
    upload: TrafficDirectionKeys,
    united: [u8; 96],
    use_aes: bool,
) -> VlessEncryptedStream<PrefixStream<ScriptStream>> {
    let result = dummy_handshake_result(upload, download, united, use_aes);
    VlessEncryptedStream::from_handshake(
        PrefixStream::new(ScriptStream::from_read(read_data), Bytes::new()),
        result,
    )
}

pub fn build_client_frames(plaintexts: &[&[u8]]) -> Vec<u8> {
    let (keys, united) = client_writer_keys();
    let mut writer = EncryptedWriter::new(keys);
    let mut out = Vec::new();
    for plain in plaintexts {
        let frame = writer.build_record(plain).expect("seal");
        out.extend_from_slice(&frame);
    }
    let _ = united;
    out
}

pub fn expected_server_frame(plaintext: &[u8]) -> Vec<u8> {
    let (upload, _, _) = test_direction_keys();
    let mut writer = EncryptedWriter::new(upload);
    let frame = writer.build_record(plaintext).expect("seal").to_vec();
    reset_test_seal_count();
    frame
}

pub fn expected_client_frame(plaintext: &[u8]) -> Vec<u8> {
    let (keys, _) = client_writer_keys();
    let mut writer = EncryptedWriter::new(keys);
    writer.build_record(plaintext).expect("seal").to_vec()
}
