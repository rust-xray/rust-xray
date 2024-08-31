
enum_builder! {
    /// The `ExtensionType` TLS protocol enum.  Values in this enum are taken
    /// from the various RFCs covering TLS, and are listed by IANA.
    /// The `Unknown` item is used when processing unrecognised ordinals.
    @U16
    pub enum ExtensionType {
        ServerName => 0x0000,
        MaxFragmentLength => 0x0001,
        ClientCertificateUrl => 0x0002,
        TrustedCAKeys => 0x0003,
        TruncatedHMAC => 0x0004,
        StatusRequest => 0x0005,
        UserMapping => 0x0006,
        ClientAuthz => 0x0007,
        ServerAuthz => 0x0008,
        CertificateType => 0x0009,
        EllipticCurves => 0x000a,
        ECPointFormats => 0x000b,
        SRP => 0x000c,
        SignatureAlgorithms => 0x000d,
        UseSRTP => 0x000e,
        Heartbeat => 0x000f,
        ALProtocolNegotiation => 0x0010,
        SCT => 0x0012,
        Padding => 0x0015,
        ExtendedMasterSecret => 0x0017,
        CompressCertificate => 0x001b,
        SessionTicket => 0x0023,
        PreSharedKey => 0x0029,
        EarlyData => 0x002a,
        SupportedVersions => 0x002b,
        Cookie => 0x002c,
        PSKKeyExchangeModes => 0x002d,
        TicketEarlyDataInfo => 0x002e,
        CertificateAuthorities => 0x002f,
        OIDFilters => 0x0030,
        PostHandshakeAuth => 0x0031,
        SignatureAlgorithmsCert => 0x0032,
        KeyShare => 0x0033,
        TransportParameters => 0x0039,
        NextProtocolNegotiation => 0x3374,
        ChannelId => 0x754f,
        RenegotiationInfo => 0xff01,
        TransportParametersDraft => 0xffa5,
        EncryptedClientHello => 0xfe0d, // https://datatracker.ietf.org/doc/html/draft-ietf-tls-esni-18#section-11.1
        EncryptedClientHelloOuterExtensions => 0xfd00, // https://datatracker.ietf.org/doc/html/draft-ietf-tls-esni-18#section-5.1
    }
}

enum_builder! {
    /// The `AlertDescription` TLS protocol enum.  Values in this enum are taken
    /// from the various RFCs covering TLS, and are listed by IANA.
    /// The `Unknown` item is used when processing unrecognised ordinals.
    @U8
    pub enum AlertDescription {
        CloseNotify => 0x00,
        UnexpectedMessage => 0x0a,
        BadRecordMac => 0x14,
        DecryptionFailed => 0x15,
        RecordOverflow => 0x16,
        DecompressionFailure => 0x1e,
        HandshakeFailure => 0x28,
        NoCertificate => 0x29,
        BadCertificate => 0x2a,
        UnsupportedCertificate => 0x2b,
        CertificateRevoked => 0x2c,
        CertificateExpired => 0x2d,
        CertificateUnknown => 0x2e,
        IllegalParameter => 0x2f,
        UnknownCA => 0x30,
        AccessDenied => 0x31,
        DecodeError => 0x32,
        DecryptError => 0x33,
        ExportRestriction => 0x3c,
        ProtocolVersion => 0x46,
        InsufficientSecurity => 0x47,
        InternalError => 0x50,
        InappropriateFallback => 0x56,
        UserCanceled => 0x5a,
        NoRenegotiation => 0x64,
        MissingExtension => 0x6d,
        UnsupportedExtension => 0x6e,
        CertificateUnobtainable => 0x6f,
        UnrecognisedName => 0x70,
        BadCertificateStatusResponse => 0x71,
        BadCertificateHashValue => 0x72,
        UnknownPSKIdentity => 0x73,
        CertificateRequired => 0x74,
        NoApplicationProtocol => 0x78,
        EncryptedClientHelloRequired => 0x79, // https://datatracker.ietf.org/doc/html/draft-ietf-tls-esni-18#section-11.2
    }
}

enum_builder! {
    /// The `HandshakeType` TLS protocol enum.  Values in this enum are taken
    /// from the various RFCs covering TLS, and are listed by IANA.
    /// The `Unknown` item is used when processing unrecognised ordinals.
    @U8
    pub enum HandshakeType {
        HelloRequest => 0x00,
        ClientHello => 0x01,
        ServerHello => 0x02,
        HelloVerifyRequest => 0x03,
        NewSessionTicket => 0x04,
        EndOfEarlyData => 0x05,
        HelloRetryRequest => 0x06,
        EncryptedExtensions => 0x08,
        Certificate => 0x0b,
        ServerKeyExchange => 0x0c,
        CertificateRequest => 0x0d,
        ServerHelloDone => 0x0e,
        CertificateVerify => 0x0f,
        ClientKeyExchange => 0x10,
        Finished => 0x14,
        CertificateURL => 0x15,
        CertificateStatus => 0x16,
        KeyUpdate => 0x18,
        CompressedCertificate => 0x19,
        MessageHash => 0xfe,
    }
}

enum_builder! {
    /// The `ContentType` TLS protocol enum.  Values in this enum are taken
    /// from the various RFCs covering TLS, and are listed by IANA.
    /// The `Unknown` item is used when processing unrecognised ordinals.
    @U8
    pub enum ContentType {
        ChangeCipherSpec => 0x14,
        Alert => 0x15,
        Handshake => 0x16,
        ApplicationData => 0x17,
        Heartbeat => 0x18,
    }
}

#[derive(Clone, Debug)]
pub enum ClientExtension {
    EcPointFormats(Vec<u8>),
    NamedGroups(Vec<u8>),
    SignatureAlgorithms(Vec<u8>),
    ServerName(Vec<ServerName>),
    SessionTicket(Vec<u8>),
    Protocols(Vec<u16>),
    SupportedVersions(Vec<u16>),
    KeyShare(Vec<u8>),
    PresharedKeyModes(Vec<u8>),
    PresharedKey(Vec<u8>),
    Cookie(Vec<u8>),
    ExtendedMasterSecretRequest,
    CertificateStatusRequest(Vec<u8>),
    TransportParameters(Vec<u8>),
    TransportParametersDraft(Vec<u8>),
    EarlyData,
    CertificateCompressionAlgorithms(Vec<u8>),
    EncryptedClientHello(Vec<u8>),
    EncryptedClientHelloOuterExtensions(Vec<u8>),
    Unknown(UnknownExtension),
}

#[derive(Clone, Debug, PartialEq)]
pub struct UnknownExtension {
    pub typ: ExtensionType,
    pub payload: Vec<u8>,
}

#[derive(Clone, Debug, PartialEq)]
pub struct ServerName {
    typ: u8,
    name: String,
}

impl ServerName {
    pub fn new(typ: u8, str: String) -> ServerName {
        ServerName {
            typ: typ,
            name: str,
        }
    }

    pub fn name(&self) -> String {
        self.name.clone()
    }
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

