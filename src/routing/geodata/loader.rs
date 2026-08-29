use std::fs::File;
use std::io::{BufReader, Read};

use prost::Message;

use crate::api::proto::common::geodata::{domain, Domain, GeoIp, GeoSite};
use crate::routing::conditions::IpNetwork;
use crate::routing::geodata::paths::{
    default_geoip_file, default_geosite_file, resolve_geodata_path,
};

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum GeodataError {
    EmptyCode,
    OpenFailed(String),
    CodeNotFound { file: String, code: String },
    InvalidFormat(String),
    DecodeFailed(String),
}

impl std::fmt::Display for GeodataError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::EmptyCode => f.write_str("empty geodata code"),
            Self::OpenFailed(message) => write!(f, "failed to open geodata file: {message}"),
            Self::CodeNotFound { file, code } => {
                write!(f, "failed to load code {code} from {file}")
            }
            Self::InvalidFormat(message) => f.write_str(message),
            Self::DecodeFailed(message) => f.write_str(message),
        }
    }
}

impl std::error::Error for GeodataError {}

pub fn load_geosite_domains(
    file: &str,
    code: &str,
    attrs: &str,
) -> Result<Vec<Domain>, GeodataError> {
    let file = normalize_geosite_file(file);
    let path = resolve_geodata_path(&file);
    let domains = load_geosite_from_path(&path, code)?;
    Ok(filter_domains_by_attrs(domains, attrs))
}

pub fn load_geoip_networks(file: &str, code: &str) -> Result<Vec<IpNetwork>, GeodataError> {
    let file = normalize_geoip_file(file);
    let path = resolve_geodata_path(&file);
    let cidrs = load_geoip_from_path(&path, code)?;
    Ok(cidrs
        .into_iter()
        .filter_map(|cidr| {
            let network = IpNetwork::from_bytes(&cidr.ip, cidr.prefix)?;
            Some(network)
        })
        .collect())
}

fn normalize_geosite_file(file: &str) -> String {
    if file.is_empty() {
        default_geosite_file().to_string()
    } else {
        file.to_string()
    }
}

fn normalize_geoip_file(file: &str) -> String {
    if file.is_empty() {
        default_geoip_file().to_string()
    } else {
        file.to_string()
    }
}

fn load_geosite_from_path(path: &std::path::Path, code: &str) -> Result<Vec<Domain>, GeodataError> {
    let file = path.to_str().unwrap_or("geosite.dat").to_string();
    let bytes = load_record_bytes(path, code).map_err(|err| match err {
        GeodataError::CodeNotFound { .. } => GeodataError::CodeNotFound {
            file: file.clone(),
            code: code.to_string(),
        },
        other => other,
    })?;
    let geosite = GeoSite::decode(bytes.as_slice()).map_err(|err| {
        GeodataError::DecodeFailed(format!("error unmarshal Site in {file}:{code}: {err}"))
    })?;
    Ok(geosite.domain)
}

fn load_geoip_from_path(
    path: &std::path::Path,
    code: &str,
) -> Result<Vec<crate::api::proto::common::geodata::Cidr>, GeodataError> {
    let file = path.to_str().unwrap_or("geoip.dat").to_string();
    let bytes = load_record_bytes(path, code).map_err(|err| match err {
        GeodataError::CodeNotFound { .. } => GeodataError::CodeNotFound {
            file: file.clone(),
            code: code.to_string(),
        },
        other => other,
    })?;
    let geoip = GeoIp::decode(bytes.as_slice()).map_err(|err| {
        GeodataError::DecodeFailed(format!("error unmarshal IP in {file}:{code}: {err}"))
    })?;
    Ok(geoip.cidr)
}

fn load_record_bytes(path: &std::path::Path, code: &str) -> Result<Vec<u8>, GeodataError> {
    let file = File::open(path)
        .map_err(|err| GeodataError::OpenFailed(format!("{}: {err}", path.display())))?;
    find_record(BufReader::new(file), code.as_bytes(), true)
}

fn find_record<R: Read>(
    mut reader: R,
    code: &[u8],
    read_body: bool,
) -> Result<Vec<u8>, GeodataError> {
    if code.is_empty() {
        return Err(GeodataError::EmptyCode);
    }

    let code_len = code.len();
    let need = 2 + code_len;
    let mut prefix_buf = vec![0u8; need];
    let mut read_byte = [0u8; 1];

    loop {
        if reader.read_exact(&mut read_byte).is_err() {
            let file_hint = "geodata file";
            return Err(GeodataError::CodeNotFound {
                file: file_hint.to_string(),
                code: String::from_utf8_lossy(code).into_owned(),
            });
        }

        let body_len = decode_varint(&mut reader)?;
        if body_len == 0 {
            return Err(GeodataError::InvalidFormat(format!(
                "invalid body length: {body_len}"
            )));
        }

        let prefix_len = need.min(body_len as usize);
        reader
            .read_exact(&mut prefix_buf[..prefix_len])
            .map_err(|err| GeodataError::InvalidFormat(err.to_string()))?;

        let mut matched = false;
        if body_len >= need as u64
            && prefix_buf[1] as usize == code_len
            && prefix_buf[2..need] == *code
        {
            if !read_body {
                return Ok(Vec::new());
            }
            matched = true;
        }

        let remain = body_len as usize - prefix_len;
        if matched {
            let mut out = vec![0u8; body_len as usize];
            out[..prefix_len].copy_from_slice(&prefix_buf[..prefix_len]);
            if remain > 0 {
                reader
                    .read_exact(&mut out[prefix_len..])
                    .map_err(|err| GeodataError::InvalidFormat(err.to_string()))?;
            }
            return Ok(out);
        }

        if remain > 0 {
            let mut sink = [0u8; 4096];
            let mut left = remain;
            while left > 0 {
                let chunk = left.min(sink.len());
                reader
                    .read_exact(&mut sink[..chunk])
                    .map_err(|err| GeodataError::InvalidFormat(err.to_string()))?;
                left -= chunk;
            }
        }
    }
}

fn decode_varint<R: Read>(reader: &mut R) -> Result<u64, GeodataError> {
    let mut value = 0u64;
    for shift in (0..64).step_by(7) {
        let mut byte = [0u8; 1];
        reader
            .read_exact(&mut byte)
            .map_err(|err| GeodataError::InvalidFormat(err.to_string()))?;
        value |= u64::from(byte[0] & 0x7f) << shift;
        if byte[0] & 0x80 == 0 {
            return Ok(value);
        }
    }
    Err(GeodataError::InvalidFormat("varint overflow".to_string()))
}

fn filter_domains_by_attrs(domains: Vec<Domain>, attrs: &str) -> Vec<Domain> {
    if attrs.is_empty() {
        return domains;
    }
    let required: Vec<&str> = attrs.split('@').filter(|part| !part.is_empty()).collect();
    if required.is_empty() {
        return domains;
    }
    domains
        .into_iter()
        .filter(|domain| required.iter().all(|key| domain_has_attr(domain, key)))
        .collect()
}

fn domain_has_attr(domain: &Domain, key: &str) -> bool {
    domain.attribute.iter().any(|attr| attr.key == key)
}

pub fn domain_to_matcher_parts(domain: &Domain) -> Result<DomainParts, GeodataError> {
    let value = domain.value.clone();
    let kind = domain::Type::try_from(domain.r#type).unwrap_or(domain::Type::Substr);
    Ok(DomainParts { kind, value })
}

#[derive(Debug, Clone)]
pub struct DomainParts {
    pub kind: domain::Type,
    pub value: String,
}

#[cfg(test)]
pub fn encode_geosite_dat(code: &str, domains: &[Domain]) -> Vec<u8> {
    let geosite = GeoSite {
        code: code.to_string(),
        domain: domains.to_vec(),
    };
    let body = geosite.encode_to_vec();
    let mut out = Vec::with_capacity(1 + 5 + body.len());
    out.push(0);
    out.extend(encode_varint_to_bytes(body.len() as u64));
    out.extend(body);
    out
}

#[cfg(test)]
pub fn encode_geoip_dat(
    code: &str,
    cidrs: Vec<crate::api::proto::common::geodata::Cidr>,
) -> Vec<u8> {
    let geoip = GeoIp {
        code: code.to_string(),
        cidr: cidrs,
        reverse_match: false,
    };
    let body = geoip.encode_to_vec();
    let mut out = Vec::with_capacity(1 + 5 + body.len());
    out.push(0);
    out.extend(encode_varint_to_bytes(body.len() as u64));
    out.extend(body);
    out
}

#[cfg(test)]
fn encode_varint_to_bytes(mut value: u64) -> Vec<u8> {
    let mut out = Vec::new();
    loop {
        let mut byte = (value & 0x7f) as u8;
        value >>= 7;
        if value != 0 {
            byte |= 0x80;
        }
        out.push(byte);
        if value == 0 {
            break;
        }
    }
    out
}
