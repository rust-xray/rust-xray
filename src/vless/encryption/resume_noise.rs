use super::header::decode_traffic_header;
use super::server::HandshakeRng;
use super::session_cache::{INVALID_TICKET_NOISE_MAX, INVALID_TICKET_NOISE_MIN};

/// Generate invalid-ticket noise bytes (upstream server.go expired-ticket path).
pub(crate) fn generate_invalid_ticket_noise<R: HandshakeRng>(rng: &mut R) -> (Vec<u8>, usize) {
    let len = invalid_ticket_noise_length(rng);
    let mut noise = vec![0u8; len];
    loop {
        rng.fill(&mut noise);
        if len >= 5 {
            if decode_traffic_header(noise[..5].try_into().expect("header slice")).is_err() {
                break;
            }
        } else {
            break;
        }
    }
    (noise, len)
}

pub(crate) fn invalid_ticket_noise_length<R: HandshakeRng>(rng: &mut R) -> usize {
    INVALID_TICKET_NOISE_MIN
        + (rng.gen_u32() as usize % (INVALID_TICKET_NOISE_MAX - INVALID_TICKET_NOISE_MIN + 1))
}
