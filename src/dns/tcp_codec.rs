use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

pub const DNS_TCP_MAX_FRAME_LEN: usize = 65_535;

pub fn encode_dns_tcp_frame(query: &[u8]) -> std::io::Result<Vec<u8>> {
    if query.is_empty() {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "DNS TCP query frame must not be empty",
        ));
    }
    if query.len() > DNS_TCP_MAX_FRAME_LEN {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            format!("DNS TCP query frame too large: {}", query.len()),
        ));
    }
    let mut frame = Vec::with_capacity(query.len() + 2);
    frame.extend_from_slice(&(query.len() as u16).to_be_bytes());
    frame.extend_from_slice(query);
    Ok(frame)
}

pub fn decode_dns_tcp_frame(buf: &[u8]) -> std::io::Result<Vec<u8>> {
    if buf.len() < 2 {
        return Err(std::io::Error::new(
            std::io::ErrorKind::UnexpectedEof,
            "truncated DNS TCP length prefix",
        ));
    }
    let len = u16::from_be_bytes([buf[0], buf[1]]) as usize;
    if len == 0 {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "DNS TCP frame length must not be zero",
        ));
    }
    if buf.len() < len + 2 {
        return Err(std::io::Error::new(
            std::io::ErrorKind::UnexpectedEof,
            "truncated DNS TCP frame payload",
        ));
    }
    Ok(buf[2..2 + len].to_vec())
}

pub async fn write_dns_tcp_query<W>(writer: &mut W, query: &[u8]) -> std::io::Result<()>
where
    W: AsyncWrite + Unpin,
{
    let frame = encode_dns_tcp_frame(query)?;
    writer.write_all(&frame).await
}

pub async fn read_dns_tcp_response<R>(reader: &mut R, max_len: usize) -> std::io::Result<Vec<u8>>
where
    R: AsyncRead + Unpin,
{
    if max_len == 0 || max_len > DNS_TCP_MAX_FRAME_LEN {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            format!("invalid DNS TCP max response length: {max_len}"),
        ));
    }
    let mut prefix = [0u8; 2];
    reader.read_exact(&mut prefix).await?;
    let len = u16::from_be_bytes(prefix) as usize;
    if len == 0 {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "DNS TCP response frame length must not be zero",
        ));
    }
    if len > max_len {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            format!("DNS TCP response frame too large: {len}"),
        ));
    }
    let mut payload = vec![0u8; len];
    reader.read_exact(&mut payload).await?;
    Ok(payload)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn dns_tcp_encode_decode() {
        let query = [0x12, 0x34, 0x01, 0x00];
        let frame = encode_dns_tcp_frame(&query).unwrap();
        assert_eq!(&frame[..2], &[0x00, 0x04]);
        assert_eq!(decode_dns_tcp_frame(&frame).unwrap(), query);
    }

    #[test]
    fn dns_tcp_reject_truncated() {
        assert!(decode_dns_tcp_frame(&[0x00]).is_err());
        assert!(decode_dns_tcp_frame(&[0x00, 0x04, 0x12]).is_err());
    }

    #[test]
    fn dns_tcp_reject_zero_length() {
        assert!(encode_dns_tcp_frame(&[]).is_err());
        assert!(decode_dns_tcp_frame(&[0x00, 0x00]).is_err());
    }
}
