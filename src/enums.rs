#![allow(non_camel_case_types)]
#![allow(missing_docs)]
use crate::codec::{Codec, Reader};
use crate::structs::KeyExchangeAlgorithm;

enum_builder! {
    /// The `HashAlgorithm` TLS protocol enum.  Values in this enum are taken
    /// from the various RFCs covering TLS, and are listed by IANA.
    /// The `Unknown` item is used when processing unrecognised ordinals.
    @U8
    pub enum HashAlgorithm {
        NONE => 0x00,
        MD5 => 0x01,
        SHA1 => 0x02,
        SHA224 => 0x03,
        SHA256 => 0x04,
        SHA384 => 0x05,
        SHA512 => 0x06,
    }
}

enum_builder! {
    /// The `ClientCertificateType` TLS protocol enum.  Values in this enum are taken
    /// from the various RFCs covering TLS, and are listed by IANA.
    /// The `Unknown` item is used when processing unrecognised ordinals.
    @U8
    pub(crate) enum ClientCertificateType {
        RSASign => 0x01,
        DSSSign => 0x02,
        RSAFixedDH => 0x03,
        DSSFixedDH => 0x04,
        RSAEphemeralDH => 0x05,
        DSSEphemeralDH => 0x06,
        FortezzaDMS => 0x14,
        ECDSASign => 0x40,
        RSAFixedECDH => 0x41,
        ECDSAFixedECDH => 0x42,
    }
}

enum_builder! {
    /// The `Compression` TLS protocol enum.  Values in this enum are taken
    /// from the various RFCs covering TLS, and are listed by IANA.
    /// The `Unknown` item is used when processing unrecognised ordinals.
    @U8
    pub enum Compression {
        Null => 0x00,
        Deflate => 0x01,
        LSZ => 0x40,
    }
}

enum_builder! {
    /// The `AlertLevel` TLS protocol enum.  Values in this enum are taken
    /// from the various RFCs covering TLS, and are listed by IANA.
    /// The `Unknown` item is used when processing unrecognised ordinals.
    @U8
    pub enum AlertLevel {
        Warning => 0x01,
        Fatal => 0x02,
    }
}

enum_builder! {
    /// The `HeartbeatMessageType` TLS protocol enum.  Values in this enum are taken
    /// from the various RFCs covering TLS, and are listed by IANA.
    /// The `Unknown` item is used when processing unrecognised ordinals.
    @U8
    pub(crate) enum HeartbeatMessageType {
        Request => 0x01,
        Response => 0x02,
    }
}

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

impl ExtensionType {
    /// Returns true if the extension type can be compressed in an "inner" client hello for ECH.
    ///
    /// This function should only return true for extension types where the inner hello and outer
    /// hello extensions values will always be identical. Extensions that may be identical
    /// sometimes (e.g. server name, cert compression methods), but not always, SHOULD NOT be
    /// compressed.
    ///
    /// See [draft-ietf-esni-18 §5](https://datatracker.ietf.org/doc/html/draft-ietf-tls-esni-18#section-5)
    /// and [draft-ietf-esni-18 §10.5](https://datatracker.ietf.org/doc/html/draft-ietf-tls-esni-18#section-10.5)
    /// for more information.
    pub(crate) fn ech_compress(&self) -> bool {
        // We match which extensions we will compress with BoringSSL and Go's stdlib.
        matches!(
            self,
            Self::StatusRequest
                | Self::EllipticCurves
                | Self::SignatureAlgorithms
                | Self::SignatureAlgorithmsCert
                | Self::ALProtocolNegotiation
                | Self::SupportedVersions
                | Self::Cookie
                | Self::KeyShare
                | Self::PSKKeyExchangeModes
        )
    }
}

enum_builder! {
    /// The `ServerNameType` TLS protocol enum.  Values in this enum are taken
    /// from the various RFCs covering TLS, and are listed by IANA.
    /// The `Unknown` item is used when processing unrecognised ordinals.
    @U8
    pub(crate) enum ServerNameType {
        HostName => 0x00,
    }
}

enum_builder! {
    /// The `NamedCurve` TLS protocol enum.  Values in this enum are taken
    /// from the various RFCs covering TLS, and are listed by IANA.
    /// The `Unknown` item is used when processing unrecognised ordinals.
    ///
    /// This enum is used for recognizing elliptic curve parameters advertised
    /// by a peer during a TLS handshake. It is **not** a list of curves that
    /// Rustls supports. See [`crate::crypto::ring::kx_group`] for the list of supported
    /// elliptic curve groups.
    @U16
    pub(crate) enum NamedCurve {
        sect163k1 => 0x0001,
        sect163r1 => 0x0002,
        sect163r2 => 0x0003,
        sect193r1 => 0x0004,
        sect193r2 => 0x0005,
        sect233k1 => 0x0006,
        sect233r1 => 0x0007,
        sect239k1 => 0x0008,
        sect283k1 => 0x0009,
        sect283r1 => 0x000a,
        sect409k1 => 0x000b,
        sect409r1 => 0x000c,
        sect571k1 => 0x000d,
        sect571r1 => 0x000e,
        secp160k1 => 0x000f,
        secp160r1 => 0x0010,
        secp160r2 => 0x0011,
        secp192k1 => 0x0012,
        secp192r1 => 0x0013,
        secp224k1 => 0x0014,
        secp224r1 => 0x0015,
        secp256k1 => 0x0016,
        secp256r1 => 0x0017,
        secp384r1 => 0x0018,
        secp521r1 => 0x0019,
        brainpoolp256r1 => 0x001a,
        brainpoolp384r1 => 0x001b,
        brainpoolp512r1 => 0x001c,
        X25519 => 0x001d,
        X448 => 0x001e,
        arbitrary_explicit_prime_curves => 0xff01,
        arbitrary_explicit_char2_curves => 0xff02,
    }
}

enum_builder! {
    /// The `NamedGroup` TLS protocol enum.  Values in this enum are taken
    /// from the various RFCs covering TLS, and are listed by IANA.
    /// The `Unknown` item is used when processing unrecognised ordinals.
    @U16
    pub enum NamedGroup {
        secp256r1 => 0x0017,
        secp384r1 => 0x0018,
        secp521r1 => 0x0019,
        X25519 => 0x001d,
        X448 => 0x001e,
        FFDHE2048 => 0x0100,
        FFDHE3072 => 0x0101,
        FFDHE4096 => 0x0102,
        FFDHE6144 => 0x0103,
        FFDHE8192 => 0x0104,
    }
}

impl NamedGroup {
    /// Return the key exchange algorithm associated with this `NamedGroup`
    pub fn key_exchange_algorithm(self) -> KeyExchangeAlgorithm {
        match u16::from(self) {
            x if (0x100..0x200).contains(&x) => KeyExchangeAlgorithm::DHE,
            _ => KeyExchangeAlgorithm::ECDHE,
        }
    }
}

enum_builder! {
    /// The `ECPointFormat` TLS protocol enum.  Values in this enum are taken
    /// from the various RFCs covering TLS, and are listed by IANA.
    /// The `Unknown` item is used when processing unrecognised ordinals.
    @U8
    pub enum ECPointFormat {
        Uncompressed => 0x00,
        ANSIX962CompressedPrime => 0x01,
        ANSIX962CompressedChar2 => 0x02,
    }
}

impl ECPointFormat {
    pub(crate) const SUPPORTED: [Self; 1] = [Self::Uncompressed];
}

enum_builder! {
    /// The `HeartbeatMode` TLS protocol enum.  Values in this enum are taken
    /// from the various RFCs covering TLS, and are listed by IANA.
    /// The `Unknown` item is used when processing unrecognised ordinals.
    @U8
    pub(crate) enum HeartbeatMode {
        PeerAllowedToSend => 0x01,
        PeerNotAllowedToSend => 0x02,
    }
}

enum_builder! {
    /// The `ECCurveType` TLS protocol enum.  Values in this enum are taken
    /// from the various RFCs covering TLS, and are listed by IANA.
    /// The `Unknown` item is used when processing unrecognised ordinals.
    @U8
    pub(crate) enum ECCurveType {
        ExplicitPrime => 0x01,
        ExplicitChar2 => 0x02,
        NamedCurve => 0x03,
    }
}

enum_builder! {
    /// The `PSKKeyExchangeMode` TLS protocol enum.  Values in this enum are taken
    /// from the various RFCs covering TLS, and are listed by IANA.
    /// The `Unknown` item is used when processing unrecognised ordinals.
    @U8
    pub enum PSKKeyExchangeMode {
        PSK_KE => 0x00,
        PSK_DHE_KE => 0x01,
    }
}

enum_builder! {
    /// The `KeyUpdateRequest` TLS protocol enum.  Values in this enum are taken
    /// from the various RFCs covering TLS, and are listed by IANA.
    /// The `Unknown` item is used when processing unrecognised ordinals.
    @U8
    pub enum KeyUpdateRequest {
        UpdateNotRequested => 0x00,
        UpdateRequested => 0x01,
    }
}

enum_builder! {
    /// The `CertificateStatusType` TLS protocol enum.  Values in this enum are taken
    /// from the various RFCs covering TLS, and are listed by IANA.
    /// The `Unknown` item is used when processing unrecognised ordinals.
    @U8
    pub enum CertificateStatusType {
        OCSP => 0x01,
    }
}

enum_builder! {
    /// The Key Encapsulation Mechanism (`Kem`) type for HPKE operations.
    /// Listed by IANA, as specified in [RFC 9180 Section 7.1]
    ///
    /// [RFC 9180 Section 7.1]: <https://datatracker.ietf.org/doc/html/rfc9180#kemid-values>
    @U16
    pub enum HpkeKem {
        DHKEM_P256_HKDF_SHA256 => 0x0010,
        DHKEM_P384_HKDF_SHA384 => 0x0011,
        DHKEM_P521_HKDF_SHA512 => 0x0012,
        DHKEM_X25519_HKDF_SHA256 => 0x0020,
        DHKEM_X448_HKDF_SHA512 => 0x0021,
    }
}

enum_builder! {
    /// The Key Derivation Function (`Kdf`) type for HPKE operations.
    /// Listed by IANA, as specified in [RFC 9180 Section 7.2]
    ///
    /// [RFC 9180 Section 7.2]: <https://datatracker.ietf.org/doc/html/rfc9180#name-key-derivation-functions-kd>
    @U16
    pub enum HpkeKdf {
        HKDF_SHA256 => 0x0001,
        HKDF_SHA384 => 0x0002,
        HKDF_SHA512 => 0x0003,
    }
}

impl Default for HpkeKdf {
    // TODO(XXX): revisit the default configuration. This is just what Cloudflare ships right now.
    fn default() -> Self {
        Self::HKDF_SHA256
    }
}

enum_builder! {
    /// The Authenticated Encryption with Associated Data (`Aead`) type for HPKE operations.
    /// Listed by IANA, as specified in [RFC 9180 Section 7.3]
    ///
    /// [RFC 9180 Section 7.3]: <https://datatracker.ietf.org/doc/html/rfc9180#name-authenticated-encryption-wi>
    @U16
    pub enum HpkeAead {
        AES_128_GCM => 0x0001,
        AES_256_GCM => 0x0002,
        CHACHA20_POLY_1305 => 0x0003,
        EXPORT_ONLY => 0xFFFF,
    }
}

impl HpkeAead {
    /// Returns the length of the tag for the AEAD algorithm, or none if the AEAD is EXPORT_ONLY.
    pub(crate) fn tag_len(&self) -> Option<usize> {
        match self {
            // See RFC 9180 Section 7.3, column `Nt`, the length in bytes of the authentication tag
            // for the algorithm.
            // https://www.rfc-editor.org/rfc/rfc9180.html#section-7.3
            Self::AES_128_GCM | Self::AES_256_GCM | Self::CHACHA20_POLY_1305 => Some(16),
            _ => None,
        }
    }
}

impl Default for HpkeAead {
    // TODO(XXX): revisit the default configuration. This is just what Cloudflare ships right now.
    fn default() -> Self {
        Self::AES_128_GCM
    }
}

enum_builder! {
    /// The Encrypted Client Hello protocol version (`EchVersion`).
    ///
    /// Specified in [draft-ietf-tls-esni Section 4].
    /// TODO(XXX): Update reference once RFC is published.
    ///
    /// [draft-ietf-tls-esni Section 4]: <https://www.ietf.org/archive/id/draft-ietf-tls-esni-17.html#section-4>
    @U16
    pub enum EchVersion {
        V18 => 0xfe0d,
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

enum_builder! {
    /// The `ProtocolVersion` TLS protocol enum.  Values in this enum are taken
    /// from the various RFCs covering TLS, and are listed by IANA.
    /// The `Unknown` item is used when processing unrecognised ordinals.
    @U16
    pub enum ProtocolVersion {
        SSLv2 => 0x0200,
        SSLv3 => 0x0300,
        TLSv1_0 => 0x0301,
        TLSv1_1 => 0x0302,
        TLSv1_2 => 0x0303,
        TLSv1_3 => 0x0304,
        DTLSv1_0 => 0xFEFF,
        DTLSv1_2 => 0xFEFD,
        DTLSv1_3 => 0xFEFC,
    }
}

enum_builder! {
    /// The `CipherSuite` TLS protocol enum.  Values in this enum are taken
    /// from the various RFCs covering TLS, and are listed by IANA.
    /// The `Unknown` item is used when processing unrecognised ordinals.
    @U16
    pub enum CipherSuite {
        TLS_NULL_WITH_NULL_NULL => 0x0000,
        TLS_RSA_WITH_NULL_MD5 => 0x0001,
        TLS_RSA_WITH_NULL_SHA => 0x0002,
        TLS_RSA_EXPORT_WITH_RC4_40_MD5 => 0x0003,
        TLS_RSA_WITH_RC4_128_MD5 => 0x0004,
        TLS_RSA_WITH_RC4_128_SHA => 0x0005,
        TLS_RSA_EXPORT_WITH_RC2_CBC_40_MD5 => 0x0006,
        TLS_RSA_WITH_IDEA_CBC_SHA => 0x0007,
        TLS_RSA_EXPORT_WITH_DES40_CBC_SHA => 0x0008,
        TLS_RSA_WITH_DES_CBC_SHA => 0x0009,
        TLS_RSA_WITH_3DES_EDE_CBC_SHA => 0x000a,
        TLS_DH_DSS_EXPORT_WITH_DES40_CBC_SHA => 0x000b,
        TLS_DH_DSS_WITH_DES_CBC_SHA => 0x000c,
        TLS_DH_DSS_WITH_3DES_EDE_CBC_SHA => 0x000d,
        TLS_DH_RSA_EXPORT_WITH_DES40_CBC_SHA => 0x000e,
        TLS_DH_RSA_WITH_DES_CBC_SHA => 0x000f,
        TLS_DH_RSA_WITH_3DES_EDE_CBC_SHA => 0x0010,
        TLS_DHE_DSS_EXPORT_WITH_DES40_CBC_SHA => 0x0011,
        TLS_DHE_DSS_WITH_DES_CBC_SHA => 0x0012,
        TLS_DHE_DSS_WITH_3DES_EDE_CBC_SHA => 0x0013,
        TLS_DHE_RSA_EXPORT_WITH_DES40_CBC_SHA => 0x0014,
        TLS_DHE_RSA_WITH_DES_CBC_SHA => 0x0015,
        TLS_DHE_RSA_WITH_3DES_EDE_CBC_SHA => 0x0016,
        TLS_DH_anon_EXPORT_WITH_RC4_40_MD5 => 0x0017,
        TLS_DH_anon_WITH_RC4_128_MD5 => 0x0018,
        TLS_DH_anon_EXPORT_WITH_DES40_CBC_SHA => 0x0019,
        TLS_DH_anon_WITH_DES_CBC_SHA => 0x001a,
        TLS_DH_anon_WITH_3DES_EDE_CBC_SHA => 0x001b,
        SSL_FORTEZZA_KEA_WITH_NULL_SHA => 0x001c,
        SSL_FORTEZZA_KEA_WITH_FORTEZZA_CBC_SHA => 0x001d,
        TLS_KRB5_WITH_DES_CBC_SHA_or_SSL_FORTEZZA_KEA_WITH_RC4_128_SHA => 0x001e,
        TLS_KRB5_WITH_3DES_EDE_CBC_SHA => 0x001f,
        TLS_KRB5_WITH_RC4_128_SHA => 0x0020,
        TLS_KRB5_WITH_IDEA_CBC_SHA => 0x0021,
        TLS_KRB5_WITH_DES_CBC_MD5 => 0x0022,
        TLS_KRB5_WITH_3DES_EDE_CBC_MD5 => 0x0023,
        TLS_KRB5_WITH_RC4_128_MD5 => 0x0024,
        TLS_KRB5_WITH_IDEA_CBC_MD5 => 0x0025,
        TLS_KRB5_EXPORT_WITH_DES_CBC_40_SHA => 0x0026,
        TLS_KRB5_EXPORT_WITH_RC2_CBC_40_SHA => 0x0027,
        TLS_KRB5_EXPORT_WITH_RC4_40_SHA => 0x0028,
        TLS_KRB5_EXPORT_WITH_DES_CBC_40_MD5 => 0x0029,
        TLS_KRB5_EXPORT_WITH_RC2_CBC_40_MD5 => 0x002a,
        TLS_KRB5_EXPORT_WITH_RC4_40_MD5 => 0x002b,
        TLS_PSK_WITH_NULL_SHA => 0x002c,
        TLS_DHE_PSK_WITH_NULL_SHA => 0x002d,
        TLS_RSA_PSK_WITH_NULL_SHA => 0x002e,
        TLS_RSA_WITH_AES_128_CBC_SHA => 0x002f,
        TLS_DH_DSS_WITH_AES_128_CBC_SHA => 0x0030,
        TLS_DH_RSA_WITH_AES_128_CBC_SHA => 0x0031,
        TLS_DHE_DSS_WITH_AES_128_CBC_SHA => 0x0032,
        TLS_DHE_RSA_WITH_AES_128_CBC_SHA => 0x0033,
        TLS_DH_anon_WITH_AES_128_CBC_SHA => 0x0034,
        TLS_RSA_WITH_AES_256_CBC_SHA => 0x0035,
        TLS_DH_DSS_WITH_AES_256_CBC_SHA => 0x0036,
        TLS_DH_RSA_WITH_AES_256_CBC_SHA => 0x0037,
        TLS_DHE_DSS_WITH_AES_256_CBC_SHA => 0x0038,
        TLS_DHE_RSA_WITH_AES_256_CBC_SHA => 0x0039,
        TLS_DH_anon_WITH_AES_256_CBC_SHA => 0x003a,
        TLS_RSA_WITH_NULL_SHA256 => 0x003b,
        TLS_RSA_WITH_AES_128_CBC_SHA256 => 0x003c,
        TLS_RSA_WITH_AES_256_CBC_SHA256 => 0x003d,
        TLS_DH_DSS_WITH_AES_128_CBC_SHA256 => 0x003e,
        TLS_DH_RSA_WITH_AES_128_CBC_SHA256 => 0x003f,
        TLS_DHE_DSS_WITH_AES_128_CBC_SHA256 => 0x0040,
        TLS_RSA_WITH_CAMELLIA_128_CBC_SHA => 0x0041,
        TLS_DH_DSS_WITH_CAMELLIA_128_CBC_SHA => 0x0042,
        TLS_DH_RSA_WITH_CAMELLIA_128_CBC_SHA => 0x0043,
        TLS_DHE_DSS_WITH_CAMELLIA_128_CBC_SHA => 0x0044,
        TLS_DHE_RSA_WITH_CAMELLIA_128_CBC_SHA => 0x0045,
        TLS_DH_anon_WITH_CAMELLIA_128_CBC_SHA => 0x0046,
        TLS_ECDH_ECDSA_WITH_NULL_SHA_draft => 0x0047,
        TLS_ECDH_ECDSA_WITH_RC4_128_SHA_draft => 0x0048,
        TLS_ECDH_ECDSA_WITH_DES_CBC_SHA_draft => 0x0049,
        TLS_ECDH_ECDSA_WITH_3DES_EDE_CBC_SHA_draft => 0x004a,
        TLS_ECDH_ECDSA_WITH_AES_128_CBC_SHA_draft => 0x004b,
        TLS_ECDH_ECDSA_WITH_AES_256_CBC_SHA_draft => 0x004c,
        TLS_ECDH_ECNRA_WITH_DES_CBC_SHA_draft => 0x004d,
        TLS_ECDH_ECNRA_WITH_3DES_EDE_CBC_SHA_draft => 0x004e,
        TLS_ECMQV_ECDSA_NULL_SHA_draft => 0x004f,
        TLS_ECMQV_ECDSA_WITH_RC4_128_SHA_draft => 0x0050,
        TLS_ECMQV_ECDSA_WITH_DES_CBC_SHA_draft => 0x0051,
        TLS_ECMQV_ECDSA_WITH_3DES_EDE_CBC_SHA_draft => 0x0052,
        TLS_ECMQV_ECNRA_NULL_SHA_draft => 0x0053,
        TLS_ECMQV_ECNRA_WITH_RC4_128_SHA_draft => 0x0054,
        TLS_ECMQV_ECNRA_WITH_DES_CBC_SHA_draft => 0x0055,
        TLS_ECMQV_ECNRA_WITH_3DES_EDE_CBC_SHA_draft => 0x0056,
        TLS_ECDH_anon_NULL_WITH_SHA_draft => 0x0057,
        TLS_ECDH_anon_WITH_RC4_128_SHA_draft => 0x0058,
        TLS_ECDH_anon_WITH_DES_CBC_SHA_draft => 0x0059,
        TLS_ECDH_anon_WITH_3DES_EDE_CBC_SHA_draft => 0x005a,
        TLS_ECDH_anon_EXPORT_WITH_DES40_CBC_SHA_draft => 0x005b,
        TLS_ECDH_anon_EXPORT_WITH_RC4_40_SHA_draft => 0x005c,
        TLS_RSA_EXPORT1024_WITH_RC4_56_MD5 => 0x0060,
        TLS_RSA_EXPORT1024_WITH_RC2_CBC_56_MD5 => 0x0061,
        TLS_RSA_EXPORT1024_WITH_DES_CBC_SHA => 0x0062,
        TLS_DHE_DSS_EXPORT1024_WITH_DES_CBC_SHA => 0x0063,
        TLS_RSA_EXPORT1024_WITH_RC4_56_SHA => 0x0064,
        TLS_DHE_DSS_EXPORT1024_WITH_RC4_56_SHA => 0x0065,
        TLS_DHE_DSS_WITH_RC4_128_SHA => 0x0066,
        TLS_DHE_RSA_WITH_AES_128_CBC_SHA256 => 0x0067,
        TLS_DH_DSS_WITH_AES_256_CBC_SHA256 => 0x0068,
        TLS_DH_RSA_WITH_AES_256_CBC_SHA256 => 0x0069,
        TLS_DHE_DSS_WITH_AES_256_CBC_SHA256 => 0x006a,
        TLS_DHE_RSA_WITH_AES_256_CBC_SHA256 => 0x006b,
        TLS_DH_anon_WITH_AES_128_CBC_SHA256 => 0x006c,
        TLS_DH_anon_WITH_AES_256_CBC_SHA256 => 0x006d,
        TLS_DHE_DSS_WITH_3DES_EDE_CBC_RMD => 0x0072,
        TLS_DHE_DSS_WITH_AES_128_CBC_RMD => 0x0073,
        TLS_DHE_DSS_WITH_AES_256_CBC_RMD => 0x0074,
        TLS_DHE_RSA_WITH_3DES_EDE_CBC_RMD => 0x0077,
        TLS_DHE_RSA_WITH_AES_128_CBC_RMD => 0x0078,
        TLS_DHE_RSA_WITH_AES_256_CBC_RMD => 0x0079,
        TLS_RSA_WITH_3DES_EDE_CBC_RMD => 0x007c,
        TLS_RSA_WITH_AES_128_CBC_RMD => 0x007d,
        TLS_RSA_WITH_AES_256_CBC_RMD => 0x007e,
        TLS_GOSTR341094_WITH_28147_CNT_IMIT => 0x0080,
        TLS_GOSTR341001_WITH_28147_CNT_IMIT => 0x0081,
        TLS_GOSTR341094_WITH_NULL_GOSTR3411 => 0x0082,
        TLS_GOSTR341001_WITH_NULL_GOSTR3411 => 0x0083,
        TLS_RSA_WITH_CAMELLIA_256_CBC_SHA => 0x0084,
        TLS_DH_DSS_WITH_CAMELLIA_256_CBC_SHA => 0x0085,
        TLS_DH_RSA_WITH_CAMELLIA_256_CBC_SHA => 0x0086,
        TLS_DHE_DSS_WITH_CAMELLIA_256_CBC_SHA => 0x0087,
        TLS_DHE_RSA_WITH_CAMELLIA_256_CBC_SHA => 0x0088,
        TLS_DH_anon_WITH_CAMELLIA_256_CBC_SHA => 0x0089,
        TLS_PSK_WITH_RC4_128_SHA => 0x008a,
        TLS_PSK_WITH_3DES_EDE_CBC_SHA => 0x008b,
        TLS_PSK_WITH_AES_128_CBC_SHA => 0x008c,
        TLS_PSK_WITH_AES_256_CBC_SHA => 0x008d,
        TLS_DHE_PSK_WITH_RC4_128_SHA => 0x008e,
        TLS_DHE_PSK_WITH_3DES_EDE_CBC_SHA => 0x008f,
        TLS_DHE_PSK_WITH_AES_128_CBC_SHA => 0x0090,
        TLS_DHE_PSK_WITH_AES_256_CBC_SHA => 0x0091,
        TLS_RSA_PSK_WITH_RC4_128_SHA => 0x0092,
        TLS_RSA_PSK_WITH_3DES_EDE_CBC_SHA => 0x0093,
        TLS_RSA_PSK_WITH_AES_128_CBC_SHA => 0x0094,
        TLS_RSA_PSK_WITH_AES_256_CBC_SHA => 0x0095,
        TLS_RSA_WITH_SEED_CBC_SHA => 0x0096,
        TLS_DH_DSS_WITH_SEED_CBC_SHA => 0x0097,
        TLS_DH_RSA_WITH_SEED_CBC_SHA => 0x0098,
        TLS_DHE_DSS_WITH_SEED_CBC_SHA => 0x0099,
        TLS_DHE_RSA_WITH_SEED_CBC_SHA => 0x009a,
        TLS_DH_anon_WITH_SEED_CBC_SHA => 0x009b,
        TLS_RSA_WITH_AES_128_GCM_SHA256 => 0x009c,
        TLS_RSA_WITH_AES_256_GCM_SHA384 => 0x009d,
        TLS_DHE_RSA_WITH_AES_128_GCM_SHA256 => 0x009e,
        TLS_DHE_RSA_WITH_AES_256_GCM_SHA384 => 0x009f,
        TLS_DH_RSA_WITH_AES_128_GCM_SHA256 => 0x00a0,
        TLS_DH_RSA_WITH_AES_256_GCM_SHA384 => 0x00a1,
        TLS_DHE_DSS_WITH_AES_128_GCM_SHA256 => 0x00a2,
        TLS_DHE_DSS_WITH_AES_256_GCM_SHA384 => 0x00a3,
        TLS_DH_DSS_WITH_AES_128_GCM_SHA256 => 0x00a4,
        TLS_DH_DSS_WITH_AES_256_GCM_SHA384 => 0x00a5,
        TLS_DH_anon_WITH_AES_128_GCM_SHA256 => 0x00a6,
        TLS_DH_anon_WITH_AES_256_GCM_SHA384 => 0x00a7,
        TLS_PSK_WITH_AES_128_GCM_SHA256 => 0x00a8,
        TLS_PSK_WITH_AES_256_GCM_SHA384 => 0x00a9,
        TLS_DHE_PSK_WITH_AES_128_GCM_SHA256 => 0x00aa,
        TLS_DHE_PSK_WITH_AES_256_GCM_SHA384 => 0x00ab,
        TLS_RSA_PSK_WITH_AES_128_GCM_SHA256 => 0x00ac,
        TLS_RSA_PSK_WITH_AES_256_GCM_SHA384 => 0x00ad,
        TLS_PSK_WITH_AES_128_CBC_SHA256 => 0x00ae,
        TLS_PSK_WITH_AES_256_CBC_SHA384 => 0x00af,
        TLS_PSK_WITH_NULL_SHA256 => 0x00b0,
        TLS_PSK_WITH_NULL_SHA384 => 0x00b1,
        TLS_DHE_PSK_WITH_AES_128_CBC_SHA256 => 0x00b2,
        TLS_DHE_PSK_WITH_AES_256_CBC_SHA384 => 0x00b3,
        TLS_DHE_PSK_WITH_NULL_SHA256 => 0x00b4,
        TLS_DHE_PSK_WITH_NULL_SHA384 => 0x00b5,
        TLS_RSA_PSK_WITH_AES_128_CBC_SHA256 => 0x00b6,
        TLS_RSA_PSK_WITH_AES_256_CBC_SHA384 => 0x00b7,
        TLS_RSA_PSK_WITH_NULL_SHA256 => 0x00b8,
        TLS_RSA_PSK_WITH_NULL_SHA384 => 0x00b9,
        TLS_RSA_WITH_CAMELLIA_128_CBC_SHA256 => 0x00ba,
        TLS_DH_DSS_WITH_CAMELLIA_128_CBC_SHA256 => 0x00bb,
        TLS_DH_RSA_WITH_CAMELLIA_128_CBC_SHA256 => 0x00bc,
        TLS_DHE_DSS_WITH_CAMELLIA_128_CBC_SHA256 => 0x00bd,
        TLS_DHE_RSA_WITH_CAMELLIA_128_CBC_SHA256 => 0x00be,
        TLS_DH_anon_WITH_CAMELLIA_128_CBC_SHA256 => 0x00bf,
        TLS_RSA_WITH_CAMELLIA_256_CBC_SHA256 => 0x00c0,
        TLS_DH_DSS_WITH_CAMELLIA_256_CBC_SHA256 => 0x00c1,
        TLS_DH_RSA_WITH_CAMELLIA_256_CBC_SHA256 => 0x00c2,
        TLS_DHE_DSS_WITH_CAMELLIA_256_CBC_SHA256 => 0x00c3,
        TLS_DHE_RSA_WITH_CAMELLIA_256_CBC_SHA256 => 0x00c4,
        TLS_DH_anon_WITH_CAMELLIA_256_CBC_SHA256 => 0x00c5,
        TLS_EMPTY_RENEGOTIATION_INFO_SCSV => 0x00ff,
        TLS13_AES_128_GCM_SHA256 => 0x1301,
        TLS13_AES_256_GCM_SHA384 => 0x1302,
        TLS13_CHACHA20_POLY1305_SHA256 => 0x1303,
        TLS13_AES_128_CCM_SHA256 => 0x1304,
        TLS13_AES_128_CCM_8_SHA256 => 0x1305,
        TLS_ECDH_ECDSA_WITH_NULL_SHA => 0xc001,
        TLS_ECDH_ECDSA_WITH_RC4_128_SHA => 0xc002,
        TLS_ECDH_ECDSA_WITH_3DES_EDE_CBC_SHA => 0xc003,
        TLS_ECDH_ECDSA_WITH_AES_128_CBC_SHA => 0xc004,
        TLS_ECDH_ECDSA_WITH_AES_256_CBC_SHA => 0xc005,
        TLS_ECDHE_ECDSA_WITH_NULL_SHA => 0xc006,
        TLS_ECDHE_ECDSA_WITH_RC4_128_SHA => 0xc007,
        TLS_ECDHE_ECDSA_WITH_3DES_EDE_CBC_SHA => 0xc008,
        TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA => 0xc009,
        TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA => 0xc00a,
        TLS_ECDH_RSA_WITH_NULL_SHA => 0xc00b,
        TLS_ECDH_RSA_WITH_RC4_128_SHA => 0xc00c,
        TLS_ECDH_RSA_WITH_3DES_EDE_CBC_SHA => 0xc00d,
        TLS_ECDH_RSA_WITH_AES_128_CBC_SHA => 0xc00e,
        TLS_ECDH_RSA_WITH_AES_256_CBC_SHA => 0xc00f,
        TLS_ECDHE_RSA_WITH_NULL_SHA => 0xc010,
        TLS_ECDHE_RSA_WITH_RC4_128_SHA => 0xc011,
        TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA => 0xc012,
        TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA => 0xc013,
        TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA => 0xc014,
        TLS_ECDH_anon_WITH_NULL_SHA => 0xc015,
        TLS_ECDH_anon_WITH_RC4_128_SHA => 0xc016,
        TLS_ECDH_anon_WITH_3DES_EDE_CBC_SHA => 0xc017,
        TLS_ECDH_anon_WITH_AES_128_CBC_SHA => 0xc018,
        TLS_ECDH_anon_WITH_AES_256_CBC_SHA => 0xc019,
        TLS_SRP_SHA_WITH_3DES_EDE_CBC_SHA => 0xc01a,
        TLS_SRP_SHA_RSA_WITH_3DES_EDE_CBC_SHA => 0xc01b,
        TLS_SRP_SHA_DSS_WITH_3DES_EDE_CBC_SHA => 0xc01c,
        TLS_SRP_SHA_WITH_AES_128_CBC_SHA => 0xc01d,
        TLS_SRP_SHA_RSA_WITH_AES_128_CBC_SHA => 0xc01e,
        TLS_SRP_SHA_DSS_WITH_AES_128_CBC_SHA => 0xc01f,
        TLS_SRP_SHA_WITH_AES_256_CBC_SHA => 0xc020,
        TLS_SRP_SHA_RSA_WITH_AES_256_CBC_SHA => 0xc021,
        TLS_SRP_SHA_DSS_WITH_AES_256_CBC_SHA => 0xc022,
        TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256 => 0xc023,
        TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA384 => 0xc024,
        TLS_ECDH_ECDSA_WITH_AES_128_CBC_SHA256 => 0xc025,
        TLS_ECDH_ECDSA_WITH_AES_256_CBC_SHA384 => 0xc026,
        TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256 => 0xc027,
        TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384 => 0xc028,
        TLS_ECDH_RSA_WITH_AES_128_CBC_SHA256 => 0xc029,
        TLS_ECDH_RSA_WITH_AES_256_CBC_SHA384 => 0xc02a,
        TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256 => 0xc02b,
        TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384 => 0xc02c,
        TLS_ECDH_ECDSA_WITH_AES_128_GCM_SHA256 => 0xc02d,
        TLS_ECDH_ECDSA_WITH_AES_256_GCM_SHA384 => 0xc02e,
        TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256 => 0xc02f,
        TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384 => 0xc030,
        TLS_ECDH_RSA_WITH_AES_128_GCM_SHA256 => 0xc031,
        TLS_ECDH_RSA_WITH_AES_256_GCM_SHA384 => 0xc032,
        TLS_ECDHE_PSK_WITH_RC4_128_SHA => 0xc033,
        TLS_ECDHE_PSK_WITH_3DES_EDE_CBC_SHA => 0xc034,
        TLS_ECDHE_PSK_WITH_AES_128_CBC_SHA => 0xc035,
        TLS_ECDHE_PSK_WITH_AES_256_CBC_SHA => 0xc036,
        TLS_ECDHE_PSK_WITH_AES_128_CBC_SHA256 => 0xc037,
        TLS_ECDHE_PSK_WITH_AES_256_CBC_SHA384 => 0xc038,
        TLS_ECDHE_PSK_WITH_NULL_SHA => 0xc039,
        TLS_ECDHE_PSK_WITH_NULL_SHA256 => 0xc03a,
        TLS_ECDHE_PSK_WITH_NULL_SHA384 => 0xc03b,
        TLS_RSA_WITH_ARIA_128_CBC_SHA256 => 0xc03c,
        TLS_RSA_WITH_ARIA_256_CBC_SHA384 => 0xc03d,
        TLS_DH_DSS_WITH_ARIA_128_CBC_SHA256 => 0xc03e,
        TLS_DH_DSS_WITH_ARIA_256_CBC_SHA384 => 0xc03f,
        TLS_DH_RSA_WITH_ARIA_128_CBC_SHA256 => 0xc040,
        TLS_DH_RSA_WITH_ARIA_256_CBC_SHA384 => 0xc041,
        TLS_DHE_DSS_WITH_ARIA_128_CBC_SHA256 => 0xc042,
        TLS_DHE_DSS_WITH_ARIA_256_CBC_SHA384 => 0xc043,
        TLS_DHE_RSA_WITH_ARIA_128_CBC_SHA256 => 0xc044,
        TLS_DHE_RSA_WITH_ARIA_256_CBC_SHA384 => 0xc045,
        TLS_DH_anon_WITH_ARIA_128_CBC_SHA256 => 0xc046,
        TLS_DH_anon_WITH_ARIA_256_CBC_SHA384 => 0xc047,
        TLS_ECDHE_ECDSA_WITH_ARIA_128_CBC_SHA256 => 0xc048,
        TLS_ECDHE_ECDSA_WITH_ARIA_256_CBC_SHA384 => 0xc049,
        TLS_ECDH_ECDSA_WITH_ARIA_128_CBC_SHA256 => 0xc04a,
        TLS_ECDH_ECDSA_WITH_ARIA_256_CBC_SHA384 => 0xc04b,
        TLS_ECDHE_RSA_WITH_ARIA_128_CBC_SHA256 => 0xc04c,
        TLS_ECDHE_RSA_WITH_ARIA_256_CBC_SHA384 => 0xc04d,
        TLS_ECDH_RSA_WITH_ARIA_128_CBC_SHA256 => 0xc04e,
        TLS_ECDH_RSA_WITH_ARIA_256_CBC_SHA384 => 0xc04f,
        TLS_RSA_WITH_ARIA_128_GCM_SHA256 => 0xc050,
        TLS_RSA_WITH_ARIA_256_GCM_SHA384 => 0xc051,
        TLS_DHE_RSA_WITH_ARIA_128_GCM_SHA256 => 0xc052,
        TLS_DHE_RSA_WITH_ARIA_256_GCM_SHA384 => 0xc053,
        TLS_DH_RSA_WITH_ARIA_128_GCM_SHA256 => 0xc054,
        TLS_DH_RSA_WITH_ARIA_256_GCM_SHA384 => 0xc055,
        TLS_DHE_DSS_WITH_ARIA_128_GCM_SHA256 => 0xc056,
        TLS_DHE_DSS_WITH_ARIA_256_GCM_SHA384 => 0xc057,
        TLS_DH_DSS_WITH_ARIA_128_GCM_SHA256 => 0xc058,
        TLS_DH_DSS_WITH_ARIA_256_GCM_SHA384 => 0xc059,
        TLS_DH_anon_WITH_ARIA_128_GCM_SHA256 => 0xc05a,
        TLS_DH_anon_WITH_ARIA_256_GCM_SHA384 => 0xc05b,
        TLS_ECDHE_ECDSA_WITH_ARIA_128_GCM_SHA256 => 0xc05c,
        TLS_ECDHE_ECDSA_WITH_ARIA_256_GCM_SHA384 => 0xc05d,
        TLS_ECDH_ECDSA_WITH_ARIA_128_GCM_SHA256 => 0xc05e,
        TLS_ECDH_ECDSA_WITH_ARIA_256_GCM_SHA384 => 0xc05f,
        TLS_ECDHE_RSA_WITH_ARIA_128_GCM_SHA256 => 0xc060,
        TLS_ECDHE_RSA_WITH_ARIA_256_GCM_SHA384 => 0xc061,
        TLS_ECDH_RSA_WITH_ARIA_128_GCM_SHA256 => 0xc062,
        TLS_ECDH_RSA_WITH_ARIA_256_GCM_SHA384 => 0xc063,
        TLS_PSK_WITH_ARIA_128_CBC_SHA256 => 0xc064,
        TLS_PSK_WITH_ARIA_256_CBC_SHA384 => 0xc065,
        TLS_DHE_PSK_WITH_ARIA_128_CBC_SHA256 => 0xc066,
        TLS_DHE_PSK_WITH_ARIA_256_CBC_SHA384 => 0xc067,
        TLS_RSA_PSK_WITH_ARIA_128_CBC_SHA256 => 0xc068,
        TLS_RSA_PSK_WITH_ARIA_256_CBC_SHA384 => 0xc069,
        TLS_PSK_WITH_ARIA_128_GCM_SHA256 => 0xc06a,
        TLS_PSK_WITH_ARIA_256_GCM_SHA384 => 0xc06b,
        TLS_DHE_PSK_WITH_ARIA_128_GCM_SHA256 => 0xc06c,
        TLS_DHE_PSK_WITH_ARIA_256_GCM_SHA384 => 0xc06d,
        TLS_RSA_PSK_WITH_ARIA_128_GCM_SHA256 => 0xc06e,
        TLS_RSA_PSK_WITH_ARIA_256_GCM_SHA384 => 0xc06f,
        TLS_ECDHE_PSK_WITH_ARIA_128_CBC_SHA256 => 0xc070,
        TLS_ECDHE_PSK_WITH_ARIA_256_CBC_SHA384 => 0xc071,
        TLS_ECDHE_ECDSA_WITH_CAMELLIA_128_CBC_SHA256 => 0xc072,
        TLS_ECDHE_ECDSA_WITH_CAMELLIA_256_CBC_SHA384 => 0xc073,
        TLS_ECDH_ECDSA_WITH_CAMELLIA_128_CBC_SHA256 => 0xc074,
        TLS_ECDH_ECDSA_WITH_CAMELLIA_256_CBC_SHA384 => 0xc075,
        TLS_ECDHE_RSA_WITH_CAMELLIA_128_CBC_SHA256 => 0xc076,
        TLS_ECDHE_RSA_WITH_CAMELLIA_256_CBC_SHA384 => 0xc077,
        TLS_ECDH_RSA_WITH_CAMELLIA_128_CBC_SHA256 => 0xc078,
        TLS_ECDH_RSA_WITH_CAMELLIA_256_CBC_SHA384 => 0xc079,
        TLS_RSA_WITH_CAMELLIA_128_GCM_SHA256 => 0xc07a,
        TLS_RSA_WITH_CAMELLIA_256_GCM_SHA384 => 0xc07b,
        TLS_DHE_RSA_WITH_CAMELLIA_128_GCM_SHA256 => 0xc07c,
        TLS_DHE_RSA_WITH_CAMELLIA_256_GCM_SHA384 => 0xc07d,
        TLS_DH_RSA_WITH_CAMELLIA_128_GCM_SHA256 => 0xc07e,
        TLS_DH_RSA_WITH_CAMELLIA_256_GCM_SHA384 => 0xc07f,
        TLS_DHE_DSS_WITH_CAMELLIA_128_GCM_SHA256 => 0xc080,
        TLS_DHE_DSS_WITH_CAMELLIA_256_GCM_SHA384 => 0xc081,
        TLS_DH_DSS_WITH_CAMELLIA_128_GCM_SHA256 => 0xc082,
        TLS_DH_DSS_WITH_CAMELLIA_256_GCM_SHA384 => 0xc083,
        TLS_DH_anon_WITH_CAMELLIA_128_GCM_SHA256 => 0xc084,
        TLS_DH_anon_WITH_CAMELLIA_256_GCM_SHA384 => 0xc085,
        TLS_ECDHE_ECDSA_WITH_CAMELLIA_128_GCM_SHA256 => 0xc086,
        TLS_ECDHE_ECDSA_WITH_CAMELLIA_256_GCM_SHA384 => 0xc087,
        TLS_ECDH_ECDSA_WITH_CAMELLIA_128_GCM_SHA256 => 0xc088,
        TLS_ECDH_ECDSA_WITH_CAMELLIA_256_GCM_SHA384 => 0xc089,
        TLS_ECDHE_RSA_WITH_CAMELLIA_128_GCM_SHA256 => 0xc08a,
        TLS_ECDHE_RSA_WITH_CAMELLIA_256_GCM_SHA384 => 0xc08b,
        TLS_ECDH_RSA_WITH_CAMELLIA_128_GCM_SHA256 => 0xc08c,
        TLS_ECDH_RSA_WITH_CAMELLIA_256_GCM_SHA384 => 0xc08d,
        TLS_PSK_WITH_CAMELLIA_128_GCM_SHA256 => 0xc08e,
        TLS_PSK_WITH_CAMELLIA_256_GCM_SHA384 => 0xc08f,
        TLS_DHE_PSK_WITH_CAMELLIA_128_GCM_SHA256 => 0xc090,
        TLS_DHE_PSK_WITH_CAMELLIA_256_GCM_SHA384 => 0xc091,
        TLS_RSA_PSK_WITH_CAMELLIA_128_GCM_SHA256 => 0xc092,
        TLS_RSA_PSK_WITH_CAMELLIA_256_GCM_SHA384 => 0xc093,
        TLS_PSK_WITH_CAMELLIA_128_CBC_SHA256 => 0xc094,
        TLS_PSK_WITH_CAMELLIA_256_CBC_SHA384 => 0xc095,
        TLS_DHE_PSK_WITH_CAMELLIA_128_CBC_SHA256 => 0xc096,
        TLS_DHE_PSK_WITH_CAMELLIA_256_CBC_SHA384 => 0xc097,
        TLS_RSA_PSK_WITH_CAMELLIA_128_CBC_SHA256 => 0xc098,
        TLS_RSA_PSK_WITH_CAMELLIA_256_CBC_SHA384 => 0xc099,
        TLS_ECDHE_PSK_WITH_CAMELLIA_128_CBC_SHA256 => 0xc09a,
        TLS_ECDHE_PSK_WITH_CAMELLIA_256_CBC_SHA384 => 0xc09b,
        TLS_RSA_WITH_AES_128_CCM => 0xc09c,
        TLS_RSA_WITH_AES_256_CCM => 0xc09d,
        TLS_DHE_RSA_WITH_AES_128_CCM => 0xc09e,
        TLS_DHE_RSA_WITH_AES_256_CCM => 0xc09f,
        TLS_RSA_WITH_AES_128_CCM_8 => 0xc0a0,
        TLS_RSA_WITH_AES_256_CCM_8 => 0xc0a1,
        TLS_DHE_RSA_WITH_AES_128_CCM_8 => 0xc0a2,
        TLS_DHE_RSA_WITH_AES_256_CCM_8 => 0xc0a3,
        TLS_PSK_WITH_AES_128_CCM => 0xc0a4,
        TLS_PSK_WITH_AES_256_CCM => 0xc0a5,
        TLS_DHE_PSK_WITH_AES_128_CCM => 0xc0a6,
        TLS_DHE_PSK_WITH_AES_256_CCM => 0xc0a7,
        TLS_PSK_WITH_AES_128_CCM_8 => 0xc0a8,
        TLS_PSK_WITH_AES_256_CCM_8 => 0xc0a9,
        TLS_PSK_DHE_WITH_AES_128_CCM_8 => 0xc0aa,
        TLS_PSK_DHE_WITH_AES_256_CCM_8 => 0xc0ab,
        TLS_ECDHE_ECDSA_WITH_AES_128_CCM => 0xc0ac,
        TLS_ECDHE_ECDSA_WITH_AES_256_CCM => 0xc0ad,
        TLS_ECDHE_ECDSA_WITH_AES_128_CCM_8 => 0xc0ae,
        TLS_ECDHE_ECDSA_WITH_AES_256_CCM_8 => 0xc0af,
        TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256 => 0xcca8,
        TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256 => 0xcca9,
        TLS_DHE_RSA_WITH_CHACHA20_POLY1305_SHA256 => 0xccaa,
        TLS_PSK_WITH_CHACHA20_POLY1305_SHA256 => 0xccab,
        TLS_ECDHE_PSK_WITH_CHACHA20_POLY1305_SHA256 => 0xccac,
        TLS_DHE_PSK_WITH_CHACHA20_POLY1305_SHA256 => 0xccad,
        TLS_RSA_PSK_WITH_CHACHA20_POLY1305_SHA256 => 0xccae,
        SSL_RSA_FIPS_WITH_DES_CBC_SHA => 0xfefe,
        SSL_RSA_FIPS_WITH_3DES_EDE_CBC_SHA => 0xfeff,
    }
}

enum_builder! {
    /// The `SignatureScheme` TLS protocol enum.  Values in this enum are taken
    /// from the various RFCs covering TLS, and are listed by IANA.
    /// The `Unknown` item is used when processing unrecognised ordinals.
    @U16
    pub enum SignatureScheme {
        RSA_PKCS1_SHA1 => 0x0201,
        ECDSA_SHA1_Legacy => 0x0203,
        RSA_PKCS1_SHA256 => 0x0401,
        ECDSA_NISTP256_SHA256 => 0x0403,
        RSA_PKCS1_SHA384 => 0x0501,
        ECDSA_NISTP384_SHA384 => 0x0503,
        RSA_PKCS1_SHA512 => 0x0601,
        ECDSA_NISTP521_SHA512 => 0x0603,
        RSA_PSS_SHA256 => 0x0804,
        RSA_PSS_SHA384 => 0x0805,
        RSA_PSS_SHA512 => 0x0806,
        ED25519 => 0x0807,
        ED448 => 0x0808,
    }
}

impl SignatureScheme {
    pub(crate) fn algorithm(&self) -> SignatureAlgorithm {
        match *self {
            Self::RSA_PKCS1_SHA1
            | Self::RSA_PKCS1_SHA256
            | Self::RSA_PKCS1_SHA384
            | Self::RSA_PKCS1_SHA512
            | Self::RSA_PSS_SHA256
            | Self::RSA_PSS_SHA384
            | Self::RSA_PSS_SHA512 => SignatureAlgorithm::RSA,
            Self::ECDSA_SHA1_Legacy
            | Self::ECDSA_NISTP256_SHA256
            | Self::ECDSA_NISTP384_SHA384
            | Self::ECDSA_NISTP521_SHA512 => SignatureAlgorithm::ECDSA,
            Self::ED25519 => SignatureAlgorithm::ED25519,
            Self::ED448 => SignatureAlgorithm::ED448,
            _ => SignatureAlgorithm::Unknown(0),
        }
    }

    /// Whether a particular `SignatureScheme` is allowed for TLS protocol signatures
    /// in TLS1.3.
    ///
    /// This prevents (eg) RSA_PKCS1_SHA256 being offered or accepted, even if our
    /// verifier supports it for other protocol versions.
    ///
    /// See RFC8446 s4.2.3.
    pub(crate) fn supported_in_tls13(&self) -> bool {
        matches!(
            *self,
            Self::ECDSA_NISTP521_SHA512
                | Self::ECDSA_NISTP384_SHA384
                | Self::ECDSA_NISTP256_SHA256
                | Self::RSA_PSS_SHA512
                | Self::RSA_PSS_SHA384
                | Self::RSA_PSS_SHA256
                | Self::ED25519
        )
    }
}

enum_builder! {
    /// The `SignatureAlgorithm` TLS protocol enum.  Values in this enum are taken
    /// from the various RFCs covering TLS, and are listed by IANA.
    /// The `Unknown` item is used when processing unrecognised ordinals.
    @U8
    pub enum SignatureAlgorithm {
        Anonymous => 0x00,
        RSA => 0x01,
        DSA => 0x02,
        ECDSA => 0x03,
        ED25519 => 0x07,
        ED448 => 0x08,
    }
}

enum_builder! {
    /// The "TLS Certificate Compression Algorithm IDs" TLS protocol enum.
    /// Values in this enum are taken from [RFC8879].
    ///
    /// [RFC8879]: https://www.rfc-editor.org/rfc/rfc8879.html#section-7.3
    @U16
    pub enum CertificateCompressionAlgorithm {
        Zlib => 1,
        Brotli => 2,
        Zstd => 3,
    }
}

enum_builder! {
    /// The type of Encrypted Client Hello (`EchClientHelloType`).
    ///
    /// Specified in [draft-ietf-tls-esni Section 5].
    ///
    /// [draft-ietf-tls-esni Section 5]: <https://www.ietf.org/archive/id/draft-ietf-tls-esni-18.html#section-5>
    @U8
    pub enum EchClientHelloType {
        ClientHelloOuter => 0,
        ClientHelloInner => 1
    }
}

