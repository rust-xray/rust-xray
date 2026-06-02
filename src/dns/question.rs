const DNS_HEADER_LEN: usize = 12;
const MAX_QNAME_LEN: usize = 253;
const MAX_LABEL_LEN: usize = 63;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DnsQuestionLog {
    pub qname: String,
    pub qtype: u16,
}

pub fn parse_dns_question_for_log(packet: &[u8]) -> Option<DnsQuestionLog> {
    if packet.len() < DNS_HEADER_LEN {
        return None;
    }
    let qdcount = u16::from_be_bytes([packet[4], packet[5]]);
    if qdcount == 0 {
        return None;
    }

    let mut offset = DNS_HEADER_LEN;
    let mut labels = Vec::new();
    let mut qname_len = 0usize;
    loop {
        let len = *packet.get(offset)? as usize;
        offset += 1;
        if len & 0xC0 == 0xC0 {
            return None;
        }
        if len == 0 {
            break;
        }
        if len > MAX_LABEL_LEN {
            return None;
        }
        let end = offset.checked_add(len)?;
        let label = packet.get(offset..end)?;
        let label = std::str::from_utf8(label).ok()?;
        qname_len = qname_len.checked_add(len + usize::from(!labels.is_empty()))?;
        if qname_len > MAX_QNAME_LEN {
            return None;
        }
        labels.push(label.to_ascii_lowercase());
        offset = end;
    }

    let qtype_end = offset.checked_add(4)?;
    let trailer = packet.get(offset..qtype_end)?;
    let qtype = u16::from_be_bytes([trailer[0], trailer[1]]);
    let qname = if labels.is_empty() {
        ".".to_string()
    } else {
        labels.join(".")
    };
    Some(DnsQuestionLog { qname, qtype })
}

#[cfg(test)]
#[path = "../../tests/unit/dns/question.rs"]
mod tests;
