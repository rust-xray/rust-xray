use std::collections::BTreeSet;
use crate::codec::{Reader, Codec, LengthPrefixedBuffer, ListLength, TlsListElement};
use crate::enums::{CertificateCompressionAlgorithm, ProtocolVersion, SignatureScheme, PSKKeyExchangeMode,
                   CertificateStatusType, ServerNameType, NamedGroup, ECPointFormat, ExtensionType, EchClientHelloType, 
                   HpkeKdf, HpkeAead, Compression, CipherSuite};
use crate::pki_types::DnsName;
use crate::base::{Payload, PayloadU8, PayloadU16};
use crate::errors::InvalidMessage;
use std::fmt;
use crate::rand::{self, SecureRandom};

// #[derive(Debug)]
// pub(super) struct ClientHello {
//     pub version: u16,
//     pub random: Vec<u8>,
//     pub session_id: Vec<u8>,
//     pub chiper_suites: Vec<u16>,
//     pub compression_method: Vec<u8>,
//     pub extetensions: Vec<ClientExtension>
// }
//
// impl ClientHello {
//   pub fn new() -> ClientHello {
//         ClientHello {
//             version: 0,
//             random: vec![0; 32],
//             session_id: vec![],
//             chiper_suites: vec![],
//             compression_method: vec![],
//             extetensions: vec![],
//         }
//         
//     }
// }

/// Create a newtype wrapper around a given type.
///
/// This is used to create newtypes for the various TLS message types which is used to wrap
/// the `PayloadU8` or `PayloadU16` types. This is typically used for types where we don't need
/// anything other than access to the underlying bytes.
macro_rules! wrapped_payload(
  ($(#[$comment:meta])* $vis:vis struct $name:ident, $inner:ident,) => {
    $(#[$comment])*
    #[derive(Clone, Debug)]
    $vis struct $name($inner);

    impl From<Vec<u8>> for $name {
        fn from(v: Vec<u8>) -> Self {
            Self($inner::new(v))
        }
    }

    impl AsRef<[u8]> for $name {
        fn as_ref(&self) -> &[u8] {
            self.0.0.as_slice()
        }
    }

    impl Codec<'_> for $name {
        fn encode(&self, bytes: &mut Vec<u8>) {
            self.0.encode(bytes);
        }

        fn read(r: &mut Reader<'_>) -> Result<Self, InvalidMessage> {
            Ok(Self($inner::read(r)?))
        }
    }
  }
);

#[derive(Clone, Copy, Eq, PartialEq)]
pub struct Random(pub(crate) [u8; 32]);

impl fmt::Debug for Random {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        super::base::hex(f, &self.0)
    }
}

static HELLO_RETRY_REQUEST_RANDOM: Random = Random([
    0xcf, 0x21, 0xad, 0x74, 0xe5, 0x9a, 0x61, 0x11, 0xbe, 0x1d, 0x8c, 0x02, 0x1e, 0x65, 0xb8, 0x91,
    0xc2, 0xa2, 0x11, 0x16, 0x7a, 0xbb, 0x8c, 0x5e, 0x07, 0x9e, 0x09, 0xe2, 0xc8, 0xa8, 0x33, 0x9c,
]);

static ZERO_RANDOM: Random = Random([0u8; 32]);

impl Codec<'_> for Random {
    fn encode(&self, bytes: &mut Vec<u8>) {
        bytes.extend_from_slice(&self.0);
    }

    fn read(r: &mut Reader<'_>) -> Result<Self, InvalidMessage> {
        let bytes = match r.take(32) {
            Some(bytes) => bytes,
            None => return Err(InvalidMessage::MissingData("Random")),
        };

        let mut opaque = [0; 32];
        opaque.clone_from_slice(bytes);
        Ok(Self(opaque))
    }
}

impl Random {
    pub(crate) fn new(secure_random: &dyn SecureRandom) -> Result<Self, crate::rand::GetRandomFailed> {
        let mut data = [0u8; 32];
        secure_random.fill(&mut data)?;
        Ok(Self(data))
    }
}

impl From<[u8; 32]> for Random {
    #[inline]
    fn from(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }
}

#[derive(Copy, Clone)]
pub struct SessionId {
    len: usize,
    data: [u8; 32],
}

impl fmt::Debug for SessionId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        super::base::hex(f, &self.data[..self.len])
    }
}

impl PartialEq for SessionId {
    fn eq(&self, other: &Self) -> bool {
        if self.len != other.len {
            return false;
        }

        let mut diff = 0u8;
        for i in 0..self.len {
            diff |= self.data[i] ^ other.data[i];
        }

        diff == 0u8
    }
}

impl Codec<'_> for SessionId {
    fn encode(&self, bytes: &mut Vec<u8>) {
        debug_assert!(self.len <= 32);
        bytes.push(self.len as u8);
        bytes.extend_from_slice(&self.data[..self.len]);
    }

    fn read(r: &mut Reader<'_>) -> Result<Self, InvalidMessage> {
        let len = u8::read(r)? as usize;
        if len > 32 {
            return Err(InvalidMessage::TrailingData("SessionID"));
        }

        let bytes = match r.take(len) {
            Some(bytes) => bytes,
            None => return Err(InvalidMessage::MissingData("SessionID")),
        };

        let mut out = [0u8; 32];
        out[..len].clone_from_slice(&bytes[..len]);
        Ok(Self { data: out, len })
    }
}

impl SessionId {
    pub fn random(secure_random: &dyn SecureRandom) -> Result<Self, rand::GetRandomFailed> {
        let mut data = [0u8; 32];
        secure_random.fill(&mut data)?;
        Ok(Self { data, len: 32 })
    }

    pub(crate) fn empty() -> Self {
        Self {
            data: [0u8; 32],
            len: 0,
        }
    }
}

#[derive(Clone, Debug, PartialEq)]
pub struct UnknownExtension {
    pub(crate) typ: ExtensionType,
    pub(crate) payload: Payload<'static>,
}

impl UnknownExtension {
    fn encode(&self, bytes: &mut Vec<u8>) {
        self.payload.encode(bytes);
    }

    fn read(typ: ExtensionType, r: &mut Reader<'_>) -> Self {
        let payload = Payload::read(r).into_owned();
        Self { typ, payload }
    }
}

impl TlsListElement for ECPointFormat {
    const SIZE_LEN: ListLength = ListLength::U8;
}

impl TlsListElement for NamedGroup {
    const SIZE_LEN: ListLength = ListLength::U16;
}

impl TlsListElement for SignatureScheme {
    const SIZE_LEN: ListLength = ListLength::U16;
}

#[derive(Clone, Debug)]
pub(crate) enum ServerNamePayload {
    HostName(DnsName<'static>),
    IpAddress(PayloadU16),
    Unknown(Payload<'static>),
}

impl ServerNamePayload {
    pub(crate) fn new_hostname(hostname: DnsName<'static>) -> Self {
        Self::HostName(hostname)
    }

    fn read_hostname(r: &mut Reader<'_>) -> Result<Self, InvalidMessage> {
        use crate::pki_types::ServerName;
        let raw = PayloadU16::read(r)?;

        match ServerName::try_from(raw.0.as_slice()) {
            Ok(ServerName::DnsName(d)) => Ok(Self::HostName(d.to_owned())),
            Ok(ServerName::IpAddress(_)) => Ok(Self::IpAddress(raw)),
            Ok(_) | Err(_) => {
                // warn!(
                //     "Illegal SNI hostname received {:?}",
                //     String::from_utf8_lossy(&raw.0)
                // );
                Err(InvalidMessage::InvalidServerName)
            }
        }
    }

    fn encode(&self, bytes: &mut Vec<u8>) {
        match *self {
            Self::HostName(ref name) => {
                (name.as_ref().len() as u16).encode(bytes);
                bytes.extend_from_slice(name.as_ref().as_bytes());
            }
            Self::IpAddress(ref r) => r.encode(bytes),
            Self::Unknown(ref r) => r.encode(bytes),
        }
    }
}

#[derive(Clone, Debug)]
pub struct ServerName {
    pub(crate) typ: ServerNameType,
    pub(crate) payload: ServerNamePayload,
}

impl Codec<'_> for ServerName {
    fn encode(&self, bytes: &mut Vec<u8>) {
        self.typ.encode(bytes);
        self.payload.encode(bytes);
    }

    fn read(r: &mut Reader<'_>) -> Result<Self, InvalidMessage> {
        let typ = ServerNameType::read(r)?;

        let payload = match typ {
            ServerNameType::HostName => ServerNamePayload::read_hostname(r)?,
            _ => ServerNamePayload::Unknown(Payload::read(r).into_owned()),
        };

        Ok(Self { typ, payload })
    }
}

impl TlsListElement for ServerName {
    const SIZE_LEN: ListLength = ListLength::U16;
}

pub(crate) trait ConvertServerNameList {
    fn has_duplicate_names_for_type(&self) -> bool;
    fn single_hostname(&self) -> Option<DnsName<'_>>;
}

impl ConvertServerNameList for [ServerName] {
    /// RFC6066: "The ServerNameList MUST NOT contain more than one name of the same name_type."
    fn has_duplicate_names_for_type(&self) -> bool {
        has_duplicates::<_, _, u8>(self.iter().map(|name| name.typ))
    }

    fn single_hostname(&self) -> Option<DnsName<'_>> {
        fn only_dns_hostnames(name: &ServerName) -> Option<DnsName<'_>> {
            if let ServerNamePayload::HostName(ref dns) = name.payload {
                Some(dns.borrow())
            } else {
                None
            }
        }

        self.iter()
            .filter_map(only_dns_hostnames)
            .next()
    }
}

wrapped_payload!(pub struct ProtocolName, PayloadU8,);

impl TlsListElement for ProtocolName {
    const SIZE_LEN: ListLength = ListLength::U16;
}

pub(crate) trait ConvertProtocolNameList {
    fn from_slices(names: &[&[u8]]) -> Self;
    fn to_slices(&self) -> Vec<&[u8]>;
    fn as_single_slice(&self) -> Option<&[u8]>;
}

impl ConvertProtocolNameList for Vec<ProtocolName> {
    fn from_slices(names: &[&[u8]]) -> Self {
        let mut ret = Self::new();

        for name in names {
            ret.push(ProtocolName::from(name.to_vec()));
        }

        ret
    }

    fn to_slices(&self) -> Vec<&[u8]> {
        self.iter()
            .map(|proto| proto.as_ref())
            .collect::<Vec<&[u8]>>()
    }

    fn as_single_slice(&self) -> Option<&[u8]> {
        if self.len() == 1 {
            Some(self[0].as_ref())
        } else {
            None
        }
    }
}

// --- TLS 1.3 Key shares ---
#[derive(Clone, Debug)]
pub struct KeyShareEntry {
    pub(crate) group: NamedGroup,
    pub(crate) payload: PayloadU16,
}

impl KeyShareEntry {
    pub fn new(group: NamedGroup, payload: impl Into<Vec<u8>>) -> Self {
        Self {
            group,
            payload: PayloadU16::new(payload.into()),
        }
    }

    pub fn group(&self) -> NamedGroup {
        self.group
    }
}

impl Codec<'_> for KeyShareEntry {
    fn encode(&self, bytes: &mut Vec<u8>) {
        self.group.encode(bytes);
        self.payload.encode(bytes);
    }

    fn read(r: &mut Reader<'_>) -> Result<Self, InvalidMessage> {
        let group = NamedGroup::read(r)?;
        let payload = PayloadU16::read(r)?;

        Ok(Self { group, payload })
    }
}

// --- TLS 1.3 PresharedKey offers ---
#[derive(Clone, Debug)]
pub(crate) struct PresharedKeyIdentity {
    pub(crate) identity: PayloadU16,
    pub(crate) obfuscated_ticket_age: u32,
}

impl PresharedKeyIdentity {
    pub(crate) fn new(id: Vec<u8>, age: u32) -> Self {
        Self {
            identity: PayloadU16::new(id),
            obfuscated_ticket_age: age,
        }
    }
}

impl Codec<'_> for PresharedKeyIdentity {
    fn encode(&self, bytes: &mut Vec<u8>) {
        self.identity.encode(bytes);
        self.obfuscated_ticket_age.encode(bytes);
    }

    fn read(r: &mut Reader<'_>) -> Result<Self, InvalidMessage> {
        Ok(Self {
            identity: PayloadU16::read(r)?,
            obfuscated_ticket_age: u32::read(r)?,
        })
    }
}

impl TlsListElement for PresharedKeyIdentity {
    const SIZE_LEN: ListLength = ListLength::U16;
}

wrapped_payload!(pub(crate) struct PresharedKeyBinder, PayloadU8,);

impl TlsListElement for PresharedKeyBinder {
    const SIZE_LEN: ListLength = ListLength::U16;
}

#[derive(Clone, Debug)]
pub struct PresharedKeyOffer {
    pub(crate) identities: Vec<PresharedKeyIdentity>,
    pub(crate) binders: Vec<PresharedKeyBinder>,
}

impl PresharedKeyOffer {
    /// Make a new one with one entry.
    pub(crate) fn new(id: PresharedKeyIdentity, binder: Vec<u8>) -> Self {
        Self {
            identities: vec![id],
            binders: vec![PresharedKeyBinder::from(binder)],
        }
    }
}

impl Codec<'_> for PresharedKeyOffer {
    fn encode(&self, bytes: &mut Vec<u8>) {
        self.identities.encode(bytes);
        self.binders.encode(bytes);
    }

    fn read(r: &mut Reader<'_>) -> Result<Self, InvalidMessage> {
        Ok(Self {
            identities: Vec::read(r)?,
            binders: Vec::read(r)?,
        })
    }
}

// --- RFC6066 certificate status request ---
wrapped_payload!(pub(crate) struct ResponderId, PayloadU16,);

impl TlsListElement for ResponderId {
    const SIZE_LEN: ListLength = ListLength::U16;
}

#[derive(Clone, Debug)]
pub struct OcspCertificateStatusRequest {
    pub(crate) responder_ids: Vec<ResponderId>,
    pub(crate) extensions: PayloadU16,
}

impl Codec<'_> for OcspCertificateStatusRequest {
    fn encode(&self, bytes: &mut Vec<u8>) {
        CertificateStatusType::OCSP.encode(bytes);
        self.responder_ids.encode(bytes);
        self.extensions.encode(bytes);
    }

    fn read(r: &mut Reader<'_>) -> Result<Self, InvalidMessage> {
        Ok(Self {
            responder_ids: Vec::read(r)?,
            extensions: PayloadU16::read(r)?,
        })
    }
}

#[derive(Clone, Debug)]
pub enum CertificateStatusRequest {
    Ocsp(OcspCertificateStatusRequest),
    Unknown((CertificateStatusType, Payload<'static>)),
}

impl Codec<'_> for CertificateStatusRequest {
    fn encode(&self, bytes: &mut Vec<u8>) {
        match self {
            Self::Ocsp(ref r) => r.encode(bytes),
            Self::Unknown((typ, payload)) => {
                typ.encode(bytes);
                payload.encode(bytes);
            }
        }
    }

    fn read(r: &mut Reader<'_>) -> Result<Self, InvalidMessage> {
        let typ = CertificateStatusType::read(r)?;

        match typ {
            CertificateStatusType::OCSP => {
                let ocsp_req = OcspCertificateStatusRequest::read(r)?;
                Ok(Self::Ocsp(ocsp_req))
            }
            _ => {
                let data = Payload::read(r).into_owned();
                Ok(Self::Unknown((typ, data)))
            }
        }
    }
}

impl CertificateStatusRequest {
    pub(crate) fn build_ocsp() -> Self {
        let ocsp = OcspCertificateStatusRequest {
            responder_ids: Vec::new(),
            extensions: PayloadU16::empty(),
        };
        Self::Ocsp(ocsp)
    }
}

// ---

impl TlsListElement for PSKKeyExchangeMode {
    const SIZE_LEN: ListLength = ListLength::U8;
}

impl TlsListElement for KeyShareEntry {
    const SIZE_LEN: ListLength = ListLength::U16;
}

impl TlsListElement for ProtocolVersion {
    const SIZE_LEN: ListLength = ListLength::U8;
}

impl TlsListElement for CertificateCompressionAlgorithm {
    const SIZE_LEN: ListLength = ListLength::U8;
}

#[derive(Clone, Debug)]
pub enum ClientExtension {
    EcPointFormats(Vec<ECPointFormat>),
    NamedGroups(Vec<NamedGroup>),
    SignatureAlgorithms(Vec<SignatureScheme>),
    ServerName(Vec<ServerName>),
    SessionTicket(ClientSessionTicket),
    Protocols(Vec<ProtocolName>),
    SupportedVersions(Vec<ProtocolVersion>),
    KeyShare(Vec<KeyShareEntry>),
    PresharedKeyModes(Vec<PSKKeyExchangeMode>),
    PresharedKey(PresharedKeyOffer),
    Cookie(PayloadU16),
    ExtendedMasterSecretRequest,
    CertificateStatusRequest(CertificateStatusRequest),
    TransportParameters(Vec<u8>),
    TransportParametersDraft(Vec<u8>),
    EarlyData,
    CertificateCompressionAlgorithms(Vec<CertificateCompressionAlgorithm>),
    EncryptedClientHello(EncryptedClientHello),
    EncryptedClientHelloOuterExtensions(Vec<ExtensionType>),
    Unknown(UnknownExtension),
}

impl ClientExtension {
    pub(crate) fn ext_type(&self) -> ExtensionType {
        match *self {
            Self::EcPointFormats(_) => ExtensionType::ECPointFormats,
            Self::NamedGroups(_) => ExtensionType::EllipticCurves,
            Self::SignatureAlgorithms(_) => ExtensionType::SignatureAlgorithms,
            Self::ServerName(_) => ExtensionType::ServerName,
            Self::SessionTicket(_) => ExtensionType::SessionTicket,
            Self::Protocols(_) => ExtensionType::ALProtocolNegotiation,
            Self::SupportedVersions(_) => ExtensionType::SupportedVersions,
            Self::KeyShare(_) => ExtensionType::KeyShare,
            Self::PresharedKeyModes(_) => ExtensionType::PSKKeyExchangeModes,
            Self::PresharedKey(_) => ExtensionType::PreSharedKey,
            Self::Cookie(_) => ExtensionType::Cookie,
            Self::ExtendedMasterSecretRequest => ExtensionType::ExtendedMasterSecret,
            Self::CertificateStatusRequest(_) => ExtensionType::StatusRequest,
            Self::TransportParameters(_) => ExtensionType::TransportParameters,
            Self::TransportParametersDraft(_) => ExtensionType::TransportParametersDraft,
            Self::EarlyData => ExtensionType::EarlyData,
            Self::CertificateCompressionAlgorithms(_) => ExtensionType::CompressCertificate,
            Self::EncryptedClientHello(_) => ExtensionType::EncryptedClientHello,
            Self::EncryptedClientHelloOuterExtensions(_) => {
                ExtensionType::EncryptedClientHelloOuterExtensions
            }
            Self::Unknown(ref r) => r.typ,
        }
    }
}

impl Codec<'_> for ClientExtension {
    fn encode(&self, bytes: &mut Vec<u8>) {
        self.ext_type().encode(bytes);

        let nested = LengthPrefixedBuffer::new(ListLength::U16, bytes);
        match *self {
            Self::EcPointFormats(ref r) => r.encode(nested.buf),
            Self::NamedGroups(ref r) => r.encode(nested.buf),
            Self::SignatureAlgorithms(ref r) => r.encode(nested.buf),
            Self::ServerName(ref r) => r.encode(nested.buf),
            Self::SessionTicket(ClientSessionTicket::Request)
            | Self::ExtendedMasterSecretRequest
            | Self::EarlyData => {}
            Self::SessionTicket(ClientSessionTicket::Offer(ref r)) => r.encode(nested.buf),
            Self::Protocols(ref r) => r.encode(nested.buf),
            Self::SupportedVersions(ref r) => r.encode(nested.buf),
            Self::KeyShare(ref r) => r.encode(nested.buf),
            Self::PresharedKeyModes(ref r) => r.encode(nested.buf),
            Self::PresharedKey(ref r) => r.encode(nested.buf),
            Self::Cookie(ref r) => r.encode(nested.buf),
            Self::CertificateStatusRequest(ref r) => r.encode(nested.buf),
            Self::TransportParameters(ref r) | Self::TransportParametersDraft(ref r) => {
                nested.buf.extend_from_slice(r);
            }
            Self::CertificateCompressionAlgorithms(ref r) => r.encode(nested.buf),
            Self::EncryptedClientHello(ref r) => r.encode(nested.buf),
            Self::EncryptedClientHelloOuterExtensions(ref r) => r.encode(nested.buf),
            Self::Unknown(ref r) => r.encode(nested.buf),
        }
    }

    fn read(r: &mut Reader<'_>) -> Result<Self, InvalidMessage> {
        let typ = ExtensionType::read(r)?;
        let len = u16::read(r)? as usize;
        let mut sub = r.sub(len)?;

        let ext = match typ {
            ExtensionType::ECPointFormats => Self::EcPointFormats(Vec::read(&mut sub)?),
            ExtensionType::EllipticCurves => Self::NamedGroups(Vec::read(&mut sub)?),
            ExtensionType::SignatureAlgorithms => Self::SignatureAlgorithms(Vec::read(&mut sub)?),
            ExtensionType::ServerName => Self::ServerName(Vec::read(&mut sub)?),
            ExtensionType::SessionTicket => {
                if sub.any_left() {
                    let contents = Payload::read(&mut sub).into_owned();
                    Self::SessionTicket(ClientSessionTicket::Offer(contents))
                } else {
                    Self::SessionTicket(ClientSessionTicket::Request)
                }
            }
            ExtensionType::ALProtocolNegotiation => Self::Protocols(Vec::read(&mut sub)?),
            ExtensionType::SupportedVersions => Self::SupportedVersions(Vec::read(&mut sub)?),
            ExtensionType::KeyShare => Self::KeyShare(Vec::read(&mut sub)?),
            ExtensionType::PSKKeyExchangeModes => Self::PresharedKeyModes(Vec::read(&mut sub)?),
            ExtensionType::PreSharedKey => Self::PresharedKey(PresharedKeyOffer::read(&mut sub)?),
            ExtensionType::Cookie => Self::Cookie(PayloadU16::read(&mut sub)?),
            ExtensionType::ExtendedMasterSecret if !sub.any_left() => {
                Self::ExtendedMasterSecretRequest
            }
            ExtensionType::StatusRequest => {
                let csr = CertificateStatusRequest::read(&mut sub)?;
                Self::CertificateStatusRequest(csr)
            }
            ExtensionType::TransportParameters => Self::TransportParameters(sub.rest().to_vec()),
            ExtensionType::TransportParametersDraft => {
                Self::TransportParametersDraft(sub.rest().to_vec())
            }
            ExtensionType::EarlyData if !sub.any_left() => Self::EarlyData,
            ExtensionType::CompressCertificate => {
                Self::CertificateCompressionAlgorithms(Vec::read(&mut sub)?)
            }
            ExtensionType::EncryptedClientHelloOuterExtensions => {
                Self::EncryptedClientHelloOuterExtensions(Vec::read(&mut sub)?)
            }
            _ => Self::Unknown(UnknownExtension::read(typ, &mut sub)),
        };

        sub.expect_empty("ClientExtension")
            .map(|_| ext)
    }
}

/// Describes supported key exchange mechanisms.
#[derive(Clone, Copy, Debug, PartialEq)]
#[non_exhaustive]
pub enum KeyExchangeAlgorithm {
    /// Diffie-Hellman Key exchange (with only known parameters as defined in [RFC 7919]).
    ///
    /// [RFC 7919]: https://datatracker.ietf.org/doc/html/rfc7919
    DHE,
    /// Key exchange performed via elliptic curve Diffie-Hellman.
    ECDHE,
}

fn has_duplicates<I: IntoIterator<Item = E>, E: Into<T>, T: Eq + Ord>(iter: I) -> bool {
    let mut seen = BTreeSet::new();

    for x in iter {
        if !seen.insert(x.into()) {
            return true;
        }
    }

    false
}

fn trim_hostname_trailing_dot_for_sni(dns_name: &DnsName<'_>) -> DnsName<'static> {
    let dns_name_str = dns_name.as_ref();

    // RFC6066: "The hostname is represented as a byte string using
    // ASCII encoding without a trailing dot"
    if dns_name_str.ends_with('.') {
        let trimmed = &dns_name_str[0..dns_name_str.len() - 1];
        DnsName::try_from(trimmed)
            .unwrap()
            .to_owned()
    } else {
        dns_name.to_owned()
    }
}

impl ClientExtension {
    /// Make a basic SNI ServerNameRequest quoting `hostname`.
    pub(crate) fn make_sni(dns_name: &DnsName<'_>) -> Self {
        let name = ServerName {
            typ: ServerNameType::HostName,
            payload: ServerNamePayload::new_hostname(trim_hostname_trailing_dot_for_sni(dns_name)),
        };

        Self::ServerName(vec![name])
    }
}

#[derive(Clone, Debug)]
pub enum ClientSessionTicket {
    Request,
    Offer(Payload<'static>),
}

/// Representation of the `ECHClientHello` client extension specified in
/// [draft-ietf-tls-esni Section 5].
///
/// [draft-ietf-tls-esni Section 5]: <https://www.ietf.org/archive/id/draft-ietf-tls-esni-18.html#section-5>
#[derive(Clone, Debug)]
pub enum EncryptedClientHello {
    /// A `ECHClientHello` with type [EchClientHelloType::ClientHelloOuter].
    Outer(EncryptedClientHelloOuter),
    /// An empty `ECHClientHello` with type [EchClientHelloType::ClientHelloInner].
    ///
    /// This variant has no payload.
    Inner,
}

impl Codec<'_> for EncryptedClientHello {
    fn encode(&self, bytes: &mut Vec<u8>) {
        match self {
            Self::Outer(payload) => {
                EchClientHelloType::ClientHelloOuter.encode(bytes);
                payload.encode(bytes);
            }
            Self::Inner => {
                EchClientHelloType::ClientHelloInner.encode(bytes);
                // Empty payload.
            }
        }
    }

    fn read(r: &mut Reader<'_>) -> Result<Self, InvalidMessage> {
        match EchClientHelloType::read(r)? {
            EchClientHelloType::ClientHelloOuter => {
                Ok(Self::Outer(EncryptedClientHelloOuter::read(r)?))
            }
            EchClientHelloType::ClientHelloInner => Ok(Self::Inner),
            _ => Err(InvalidMessage::InvalidContentType),
        }
    }
}

/// Representation of the ECHClientHello extension with type outer specified in
/// [draft-ietf-tls-esni Section 5].
///
/// [draft-ietf-tls-esni Section 5]: <https://www.ietf.org/archive/id/draft-ietf-tls-esni-18.html#section-5>
#[derive(Clone, Debug)]
pub struct EncryptedClientHelloOuter {
    /// The cipher suite used to encrypt ClientHelloInner. Must match a value from
    /// ECHConfigContents.cipher_suites list.
    pub cipher_suite: HpkeSymmetricCipherSuite,
    /// The ECHConfigContents.key_config.config_id for the chosen ECHConfig.
    pub config_id: u8,
    /// The HPKE encapsulated key, used by servers to decrypt the corresponding payload field.
    /// This field is empty in a ClientHelloOuter sent in response to a HelloRetryRequest.
    pub enc: PayloadU16,
    /// The serialized and encrypted ClientHelloInner structure, encrypted using HPKE.
    pub payload: PayloadU16,
}

impl Codec<'_> for EncryptedClientHelloOuter {
    fn encode(&self, bytes: &mut Vec<u8>) {
        self.cipher_suite.encode(bytes);
        self.config_id.encode(bytes);
        self.enc.encode(bytes);
        self.payload.encode(bytes);
    }

    fn read(r: &mut Reader<'_>) -> Result<Self, InvalidMessage> {
        Ok(Self {
            cipher_suite: HpkeSymmetricCipherSuite::read(r)?,
            config_id: u8::read(r)?,
            enc: PayloadU16::read(r)?,
            payload: PayloadU16::read(r)?,
        })
    }
}


#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct HpkeSymmetricCipherSuite {
    pub kdf_id: HpkeKdf,
    pub aead_id: HpkeAead,
}

impl Codec<'_> for HpkeSymmetricCipherSuite {
    fn encode(&self, bytes: &mut Vec<u8>) {
        self.kdf_id.encode(bytes);
        self.aead_id.encode(bytes);
    }

    fn read(r: &mut Reader<'_>) -> Result<Self, InvalidMessage> {
        Ok(Self {
            kdf_id: HpkeKdf::read(r)?,
            aead_id: HpkeAead::read(r)?,
        })
    }
}

impl TlsListElement for HpkeSymmetricCipherSuite {
    const SIZE_LEN: ListLength = ListLength::U16;
}


impl TlsListElement for CipherSuite {
    const SIZE_LEN: ListLength = ListLength::U16;
}

impl TlsListElement for Compression {
    const SIZE_LEN: ListLength = ListLength::U8;
}

impl TlsListElement for ClientExtension {
    const SIZE_LEN: ListLength = ListLength::U16;
}

impl TlsListElement for ExtensionType {
    const SIZE_LEN: ListLength = ListLength::U8;
}

#[derive(Clone, Debug)]
pub struct ClientHelloPayload {
    pub client_version: ProtocolVersion,
    pub random: Random,
    pub session_id: SessionId,
    pub cipher_suites: Vec<CipherSuite>,
    pub compression_methods: Vec<Compression>,
    pub extensions: Vec<ClientExtension>,
}

impl Codec<'_> for ClientHelloPayload {
    fn encode(&self, bytes: &mut Vec<u8>) {
        self.payload_encode(bytes, Encoding::Standard)
    }

    fn read(r: &mut Reader<'_>) -> Result<Self, InvalidMessage> {
        let mut ret = Self {
            client_version: ProtocolVersion::read(r)?,
            random: Random::read(r)?,
            session_id: SessionId::read(r)?,
            cipher_suites: Vec::read(r)?,
            compression_methods: Vec::read(r)?,
            extensions: Vec::new(),
        };

        if r.any_left() {
            ret.extensions = Vec::read(r)?;
        }

        match (r.any_left(), ret.extensions.is_empty()) {
            (true, _) => Err(InvalidMessage::TrailingData("ClientHelloPayload")),
            (_, true) => Err(InvalidMessage::MissingData("ClientHelloPayload")),
            _ => Ok(ret),
        }
    }
}

impl ClientHelloPayload {
    pub(crate) fn ech_inner_encoding(&self, to_compress: Vec<ExtensionType>) -> Vec<u8> {
        let mut bytes = Vec::new();
        self.payload_encode(&mut bytes, Encoding::EchInnerHello { to_compress });
        bytes
    }

    pub(crate) fn payload_encode(&self, bytes: &mut Vec<u8>, purpose: Encoding) {
        self.client_version.encode(bytes);
        self.random.encode(bytes);

        match purpose {
            // SessionID is required to be empty in the encoded inner client hello.
            Encoding::EchInnerHello { .. } => SessionId::empty().encode(bytes),
            _ => self.session_id.encode(bytes),
        }

        self.cipher_suites.encode(bytes);
        self.compression_methods.encode(bytes);

        let to_compress = match purpose {
            // Compressed extensions must be replaced in the encoded inner client hello.
            Encoding::EchInnerHello { to_compress } if !to_compress.is_empty() => to_compress,
            _ => {
                if !self.extensions.is_empty() {
                    self.extensions.encode(bytes);
                }
                return;
            }
        };

        // Safety: not empty check in match guard.
        let first_compressed_type = *to_compress.first().unwrap();

        // Compressed extensions are in a contiguous range and must be replaced
        // with a marker extension.
        let compressed_start_idx = self
            .extensions
            .iter()
            .position(|ext| ext.ext_type() == first_compressed_type);
        let compressed_end_idx = compressed_start_idx.map(|start| start + to_compress.len());
        let marker_ext = ClientExtension::EncryptedClientHelloOuterExtensions(to_compress);

        let exts = self
            .extensions
            .iter()
            .enumerate()
            .filter_map(|(i, ext)| {
                if Some(i) == compressed_start_idx {
                    Some(&marker_ext)
                } else if Some(i) > compressed_start_idx && Some(i) < compressed_end_idx {
                    None
                } else {
                    Some(ext)
                }
            });

        let nested = LengthPrefixedBuffer::new(ListLength::U16, bytes);
        for ext in exts {
            ext.encode(nested.buf);
        }
    }

    /// Returns true if there is more than one extension of a given
    /// type.
    pub(crate) fn has_duplicate_extension(&self) -> bool {
        has_duplicates::<_, _, u16>(
            self.extensions
                .iter()
                .map(|ext| ext.ext_type()),
        )
    }

    pub(crate) fn find_extension(&self, ext: ExtensionType) -> Option<&ClientExtension> {
        self.extensions
            .iter()
            .find(|x| x.ext_type() == ext)
    }

    pub(crate) fn sni_extension(&self) -> Option<&[ServerName]> {
        let ext = self.find_extension(ExtensionType::ServerName)?;
        match *ext {
            // Does this comply with RFC6066?
            //
            // [RFC6066][] specifies that literal IP addresses are illegal in
            // `ServerName`s with a `name_type` of `host_name`.
            //
            // Some clients incorrectly send such extensions: we choose to
            // successfully parse these (into `ServerNamePayload::IpAddress`)
            // but then act like the client sent no `server_name` extension.
            //
            // [RFC6066]: https://datatracker.ietf.org/doc/html/rfc6066#section-3
            ClientExtension::ServerName(ref req)
                if !req
                    .iter()
                    .any(|name| matches!(name.payload, ServerNamePayload::IpAddress(_))) =>
            {
                Some(req)
            }
            _ => None,
        }
    }

    pub fn sigalgs_extension(&self) -> Option<&[SignatureScheme]> {
        let ext = self.find_extension(ExtensionType::SignatureAlgorithms)?;
        match *ext {
            ClientExtension::SignatureAlgorithms(ref req) => Some(req),
            _ => None,
        }
    }

    pub(crate) fn namedgroups_extension(&self) -> Option<&[NamedGroup]> {
        let ext = self.find_extension(ExtensionType::EllipticCurves)?;
        match *ext {
            ClientExtension::NamedGroups(ref req) => Some(req),
            _ => None,
        }
    }

    #[cfg(feature = "tls12")]
    pub(crate) fn ecpoints_extension(&self) -> Option<&[ECPointFormat]> {
        let ext = self.find_extension(ExtensionType::ECPointFormats)?;
        match *ext {
            ClientExtension::EcPointFormats(ref req) => Some(req),
            _ => None,
        }
    }

    pub(crate) fn alpn_extension(&self) -> Option<&Vec<ProtocolName>> {
        let ext = self.find_extension(ExtensionType::ALProtocolNegotiation)?;
        match *ext {
            ClientExtension::Protocols(ref req) => Some(req),
            _ => None,
        }
    }

    pub(crate) fn quic_params_extension(&self) -> Option<Vec<u8>> {
        let ext = self
            .find_extension(ExtensionType::TransportParameters)
            .or_else(|| self.find_extension(ExtensionType::TransportParametersDraft))?;
        match *ext {
            ClientExtension::TransportParameters(ref bytes)
            | ClientExtension::TransportParametersDraft(ref bytes) => Some(bytes.to_vec()),
            _ => None,
        }
    }

    #[cfg(feature = "tls12")]
    pub(crate) fn ticket_extension(&self) -> Option<&ClientExtension> {
        self.find_extension(ExtensionType::SessionTicket)
    }

    pub(crate) fn versions_extension(&self) -> Option<&[ProtocolVersion]> {
        let ext = self.find_extension(ExtensionType::SupportedVersions)?;
        match *ext {
            ClientExtension::SupportedVersions(ref vers) => Some(vers),
            _ => None,
        }
    }

    pub fn keyshare_extension(&self) -> Option<&[KeyShareEntry]> {
        let ext = self.find_extension(ExtensionType::KeyShare)?;
        match *ext {
            ClientExtension::KeyShare(ref shares) => Some(shares),
            _ => None,
        }
    }

    pub(crate) fn has_keyshare_extension_with_duplicates(&self) -> bool {
        self.keyshare_extension()
            .map(|entries| {
                has_duplicates::<_, _, u16>(
                    entries
                        .iter()
                        .map(|kse| u16::from(kse.group)),
                )
            })
            .unwrap_or_default()
    }

    pub(crate) fn psk(&self) -> Option<&PresharedKeyOffer> {
        let ext = self.find_extension(ExtensionType::PreSharedKey)?;
        match *ext {
            ClientExtension::PresharedKey(ref psk) => Some(psk),
            _ => None,
        }
    }

    pub(crate) fn check_psk_ext_is_last(&self) -> bool {
        self.extensions
            .last()
            .map_or(false, |ext| ext.ext_type() == ExtensionType::PreSharedKey)
    }

    pub(crate) fn psk_modes(&self) -> Option<&[PSKKeyExchangeMode]> {
        let ext = self.find_extension(ExtensionType::PSKKeyExchangeModes)?;
        match *ext {
            ClientExtension::PresharedKeyModes(ref psk_modes) => Some(psk_modes),
            _ => None,
        }
    }

    pub(crate) fn psk_mode_offered(&self, mode: PSKKeyExchangeMode) -> bool {
        self.psk_modes()
            .map(|modes| modes.contains(&mode))
            .unwrap_or(false)
    }

    pub(crate) fn set_psk_binder(&mut self, binder: impl Into<Vec<u8>>) {
        let last_extension = self.extensions.last_mut();
        if let Some(ClientExtension::PresharedKey(ref mut offer)) = last_extension {
            offer.binders[0] = PresharedKeyBinder::from(binder.into());
        }
    }

    // #[cfg(feature = "tls12")]
    // pub(crate) fn ems_support_offered(&self) -> bool {
    //     self.find_extension(ExtensionType::ExtendedMasterSecret)
    //         .is_some()
    // }

    pub(crate) fn early_data_extension_offered(&self) -> bool {
        self.find_extension(ExtensionType::EarlyData)
            .is_some()
    }

    pub(crate) fn certificate_compression_extension(
        &self,
    ) -> Option<&[CertificateCompressionAlgorithm]> {
        let ext = self.find_extension(ExtensionType::CompressCertificate)?;
        match *ext {
            ClientExtension::CertificateCompressionAlgorithms(ref algs) => Some(algs),
            _ => None,
        }
    }

    pub(crate) fn has_certificate_compression_extension_with_duplicates(&self) -> bool {
        if let Some(algs) = self.certificate_compression_extension() {
            has_duplicates::<_, _, u16>(algs.iter().cloned())
        } else {
            false
        }
    }
}


/// The method of encoding to use for a handshake message.
///
/// In some cases a handshake message may be encoded differently depending on the purpose
/// the encoded message is being used for. For example, a [ServerHelloPayload] may be encoded
/// with the last 8 bytes of the random zeroed out when being encoded for ECH confirmation.
pub(crate) enum Encoding {
    /// Standard RFC 8446 encoding.
    Standard,
    /// Encoding for ECH confirmation.
    EchConfirmation,
    /// Encoding for ECH inner client hello.
    EchInnerHello { to_compress: Vec<ExtensionType> },
}


