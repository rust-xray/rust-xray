use super::*;
use crate::codec::Codec;

#[test]
fn payload_u16_bytes_vs_get_encoding_length() {
    let payload = PayloadU16::new(vec![0xAB; 32]);

    assert_eq!(payload.bytes().len(), 32);
    assert_eq!(payload.get_encoding().len(), 34);
    assert_eq!(&payload.get_encoding()[..2], &32u16.to_be_bytes());
    assert_eq!(&payload.get_encoding()[2..], payload.bytes());
}
