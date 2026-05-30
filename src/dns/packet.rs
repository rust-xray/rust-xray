use std::net::{Ipv4Addr, Ipv6Addr};

use crate::dns::error::DnsError;

const DNS_HEADER_LEN: usize = 12;
const MAX_QNAME_LEN: usize = 253;
const MAX_LABEL_LEN: usize = 63;

pub const DNS_RCODE_NXDOMAIN: u8 = 3;
pub const DNS_RCODE_SERVFAIL: u8 = 2;

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct DnsQuestionKey {
    pub qname: String,
    pub qtype: u16,
    pub qclass: u16,
    pub server_id: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct DnsInflightKey {
    pub qname: String,
    pub qtype: u16,
    pub qclass: u16,
}

pub fn dns_query_id(packet: &[u8]) -> Option<u16> {
    if packet.len() < 2 {
        return None;
    }
    Some(u16::from_be_bytes([packet[0], packet[1]]))
}

/// Clone a cached DNS response and rewrite the 16-bit transaction ID to match `current_query`.
pub fn rewrite_dns_response_id_for_query(
    cached_response: &[u8],
    current_query: &[u8],
) -> Result<Vec<u8>, DnsError> {
    if current_query.len() < 2 || cached_response.len() < 2 {
        return Err(DnsError::MalformedQuery);
    }
    let mut response = cached_response.to_vec();
    response[0] = current_query[0];
    response[1] = current_query[1];
    Ok(response)
}

pub fn parse_dns_question_key(
    packet: &[u8],
    server_id: impl Into<String>,
) -> Result<DnsQuestionKey, DnsError> {
    if packet.len() < DNS_HEADER_LEN {
        return Err(DnsError::MalformedQuery);
    }
    let qdcount = u16::from_be_bytes([packet[4], packet[5]]);
    if qdcount == 0 {
        return Err(DnsError::MalformedQuery);
    }

    let mut offset = DNS_HEADER_LEN;
    let mut labels = Vec::new();
    let mut qname_len = 0usize;
    loop {
        let len = *packet.get(offset).ok_or(DnsError::MalformedQuery)? as usize;
        offset += 1;
        if len & 0xC0 == 0xC0 {
            return Err(DnsError::MalformedQuery);
        }
        if len == 0 {
            break;
        }
        if len > MAX_LABEL_LEN {
            return Err(DnsError::MalformedQuery);
        }
        let end = offset.checked_add(len).ok_or(DnsError::MalformedQuery)?;
        let label = packet.get(offset..end).ok_or(DnsError::MalformedQuery)?;
        let label = std::str::from_utf8(label).map_err(|_| DnsError::MalformedQuery)?;
        qname_len = qname_len
            .checked_add(len + usize::from(!labels.is_empty()))
            .ok_or(DnsError::MalformedQuery)?;
        if qname_len > MAX_QNAME_LEN {
            return Err(DnsError::MalformedQuery);
        }
        labels.push(label.to_ascii_lowercase());
        offset = end;
    }

    let trailer = packet
        .get(offset..offset + 4)
        .ok_or(DnsError::MalformedQuery)?;
    let qtype = u16::from_be_bytes([trailer[0], trailer[1]]);
    let qclass = u16::from_be_bytes([trailer[2], trailer[3]]);
    let qname = if labels.is_empty() {
        ".".to_string()
    } else {
        labels.join(".")
    };

    Ok(DnsQuestionKey {
        qname,
        qtype,
        qclass,
        server_id: server_id.into(),
    })
}

pub fn inflight_key_from_packet(packet: &[u8]) -> Result<DnsInflightKey, DnsError> {
    let key = parse_dns_question_key(packet, "")?;
    Ok(DnsInflightKey {
        qname: key.qname,
        qtype: key.qtype,
        qclass: key.qclass,
    })
}

pub fn dns_response_rcode(packet: &[u8]) -> Option<u8> {
    if packet.len() < DNS_HEADER_LEN {
        return None;
    }
    Some(packet[3] & 0x0f)
}

pub fn is_negative_dns_response(packet: &[u8]) -> bool {
    matches!(
        dns_response_rcode(packet),
        Some(DNS_RCODE_NXDOMAIN) | Some(DNS_RCODE_SERVFAIL)
    )
}

pub fn parse_response_min_ttl(packet: &[u8]) -> Option<u32> {
    if packet.len() < DNS_HEADER_LEN {
        return None;
    }
    let ancount = u16::from_be_bytes([packet[6], packet[7]]) as usize;
    let nscount = u16::from_be_bytes([packet[8], packet[9]]) as usize;
    let arcount = u16::from_be_bytes([packet[10], packet[11]]) as usize;
    let mut offset = DNS_HEADER_LEN;
    offset = skip_question_section(packet, offset, 1)?;
    let mut min_ttl = None;
    for _ in 0..(ancount + nscount + arcount) {
        let (ttl, next) = parse_rr_ttl(packet, offset)?;
        min_ttl = Some(min_ttl.map_or(ttl, |current: u32| current.min(ttl)));
        offset = next;
    }
    min_ttl
}

fn skip_question_section(packet: &[u8], mut offset: usize, qdcount: usize) -> Option<usize> {
    for _ in 0..qdcount {
        loop {
            let len = *packet.get(offset)? as usize;
            offset += 1;
            if len & 0xC0 == 0xC0 {
                offset += 1;
                break;
            }
            if len == 0 {
                break;
            }
            offset = offset.checked_add(len)?;
        }
        offset = offset.checked_add(4)?;
    }
    Some(offset)
}

fn parse_rr_ttl(packet: &[u8], mut offset: usize) -> Option<(u32, usize)> {
    loop {
        let len = *packet.get(offset)? as usize;
        offset += 1;
        if len & 0xC0 == 0xC0 {
            offset += 1;
            break;
        }
        if len == 0 {
            break;
        }
        offset = offset.checked_add(len)?;
    }
    let trailer = packet.get(offset..offset + 10)?;
    let ttl = u32::from_be_bytes([trailer[4], trailer[5], trailer[6], trailer[7]]);
    let rdlength = u16::from_be_bytes([trailer[8], trailer[9]]) as usize;
    Some((ttl, offset + 10 + rdlength))
}

pub fn extract_ipv4_addresses(packet: &[u8]) -> Vec<std::net::IpAddr> {
    extract_addresses(packet, 1)
}

pub fn extract_ipv6_addresses(packet: &[u8]) -> Vec<std::net::IpAddr> {
    extract_addresses(packet, 28)
}

fn extract_addresses(packet: &[u8], qtype: u16) -> Vec<std::net::IpAddr> {
    if packet.len() < DNS_HEADER_LEN {
        return Vec::new();
    }
    let ancount = u16::from_be_bytes([packet[6], packet[7]]) as usize;
    let mut offset = match skip_question_section(packet, DNS_HEADER_LEN, 1) {
        Some(offset) => offset,
        None => return Vec::new(),
    };
    let mut out = Vec::new();
    for _ in 0..ancount {
        let Some((record_type, rdlength, next)) = parse_rr_type_and_rdata(packet, offset) else {
            break;
        };
        if record_type == qtype {
            if qtype == 1 && rdlength == 4 {
                if let Some(rdata) = packet.get(next - rdlength..next) {
                    let octets: [u8; 4] = rdata.try_into().unwrap_or([0; 4]);
                    out.push(std::net::IpAddr::V4(Ipv4Addr::from(octets)));
                }
            } else if qtype == 28 && rdlength == 16 {
                if let Some(rdata) = packet.get(next - rdlength..next) {
                    let octets: [u8; 16] = rdata.try_into().unwrap_or([0; 16]);
                    out.push(std::net::IpAddr::V6(Ipv6Addr::from(octets)));
                }
            }
        }
        offset = next;
    }
    out
}

fn parse_rr_type_and_rdata(packet: &[u8], mut offset: usize) -> Option<(u16, usize, usize)> {
    loop {
        let len = *packet.get(offset)? as usize;
        offset += 1;
        if len & 0xC0 == 0xC0 {
            offset += 1;
            break;
        }
        if len == 0 {
            break;
        }
        offset = offset.checked_add(len)?;
    }
    let trailer = packet.get(offset..offset + 10)?;
    let record_type = u16::from_be_bytes([trailer[0], trailer[1]]);
    let rdlength = u16::from_be_bytes([trailer[8], trailer[9]]) as usize;
    Some((record_type, rdlength, offset + 10 + rdlength))
}

pub fn build_dns_query(domain: &str, qtype: u16) -> Result<Vec<u8>, DnsError> {
    let mut labels = Vec::new();
    if domain == "." {
        labels.push(String::new());
    } else {
        for label in domain.split('.') {
            if label.is_empty() {
                return Err(DnsError::MalformedQuery);
            }
            if label.len() > MAX_LABEL_LEN {
                return Err(DnsError::MalformedQuery);
            }
            labels.push(label.to_ascii_lowercase());
        }
    }

    let mut packet = Vec::with_capacity(64);
    packet.extend_from_slice(&[
        0xab, 0xcd, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    ]);
    for label in labels {
        packet.push(label.len() as u8);
        packet.extend_from_slice(label.as_bytes());
    }
    packet.push(0);
    packet.extend_from_slice(&qtype.to_be_bytes());
    packet.extend_from_slice(&1u16.to_be_bytes());
    Ok(packet)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{IpAddr, Ipv4Addr};

    fn example_query() -> Vec<u8> {
        let mut packet = vec![
            0x12, 0x34, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        ];
        packet.extend_from_slice(&[
            7, b'e', b'x', b'a', b'm', b'p', b'l', b'e', 3, b'c', b'o', b'm', 0, 0, 1, 0, 1,
        ]);
        packet
    }

    #[test]
    fn parse_question_key_normalizes_qname() {
        let key = parse_dns_question_key(&example_query(), "1.1.1.1:53").unwrap();
        assert_eq!(key.qname, "example.com");
        assert_eq!(key.qtype, 1);
        assert_eq!(key.qclass, 1);
    }

    #[test]
    fn malformed_query_rejected() {
        assert!(parse_dns_question_key(&[0x00], "127.0.0.1:53").is_err());
    }

    #[test]
    fn parse_response_ttl_from_answer() {
        let mut packet = example_query();
        packet[2] = 0x81;
        packet[3] = 0x80;
        packet[6] = 0x00;
        packet[7] = 0x01;
        packet.extend_from_slice(&[
            0xc0, 0x0c, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00, 0x3c, 0x00, 0x04, 192, 168, 0, 1,
        ]);
        assert_eq!(parse_response_min_ttl(&packet), Some(60));
    }

    #[test]
    fn rewrite_dns_response_id_for_query_rewrites_transaction_id() {
        let current_query = [0xab, 0xcd, 0x01, 0x00];
        let cached_response = [0x12, 0x34, 0x81, 0x80];
        let rewritten =
            rewrite_dns_response_id_for_query(&cached_response, &current_query).unwrap();
        assert_eq!(&rewritten[..2], &[0xab, 0xcd]);
        assert_eq!(&rewritten[2..], &cached_response[2..]);
    }

    #[test]
    fn rewrite_dns_response_id_rejects_short_packets() {
        assert!(rewrite_dns_response_id_for_query(&[0x12, 0x34], &[0xab]).is_err());
        assert!(rewrite_dns_response_id_for_query(&[0x12], &[0xab, 0xcd]).is_err());
    }

    #[test]
    fn extract_ipv4_from_response() {
        let mut packet = example_query();
        packet[2] = 0x81;
        packet[3] = 0x80;
        packet[6] = 0x00;
        packet[7] = 0x01;
        packet.extend_from_slice(&[
            0xc0, 0x0c, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00, 0x3c, 0x00, 0x04, 1, 1, 1, 1,
        ]);
        let ips = extract_ipv4_addresses(&packet);
        assert_eq!(ips, vec![IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1))]);
    }
}
