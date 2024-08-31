use crate::enums::{AlertDescription, HandshakeType, KeyExchangeAlgorithm};

/// rustls reports protocol errors using this type.
#[non_exhaustive]
#[derive(Debug, PartialEq, Clone)]
pub enum Error {
    /// We received a TLS message that isn't valid right now.
    /// `expect_types` lists the message types we can expect right now.
    /// `got_type` is the type we found.  This error is typically
    /// caused by a buggy TLS stack (the peer or this one), a broken
    /// network, or an attack.
    InappropriateMessage,

    /// We received a TLS handshake message that isn't valid right now.
    /// `expect_types` lists the handshake message types we can expect
    /// right now.  `got_type` is the type we found.
    InappropriateHandshakeMessage {
        /// Which handshake type we expected
        expect_types: Vec<HandshakeType>,
        /// What handshake type we received
        got_type: HandshakeType,
    },

    /// An error occurred while handling Encrypted Client Hello (ECH).
    InvalidEncryptedClientHello,

    /// The peer sent us a TLS message with invalid contents.
    InvalidMessage(InvalidMessage),

    /// The peer didn't give us any certificates.
    NoCertificatesPresented,

    /// The certificate verifier doesn't support the given type of name.
    UnsupportedNameType,

    /// We couldn't decrypt a message.  This is invariably fatal.
    DecryptError,

    /// We couldn't encrypt a message because it was larger than the allowed message size.
    /// This should never happen if the application is using valid record sizes.
    EncryptError,

    /// The peer doesn't support a protocol version/feature we require.
    /// The parameter gives a hint as to what version/feature it is.
    PeerIncompatible,

    /// The peer deviated from the standard TLS protocol.
    /// The parameter gives a hint where.
    PeerMisbehaved,

    /// We received a fatal alert.  This means the peer is unhappy.
    AlertReceived(AlertDescription),

    /// We saw an invalid certificate.
    ///
    /// The contained error is from the certificate validation trait
    /// implementation.
    InvalidCertificate,

    /// A provided certificate revocation list (CRL) was invalid.
    InvalidCertRevocationList,

    /// A catch-all error for unlikely errors.
    General(String),

    /// We failed to figure out what time it currently is.
    FailedToGetCurrentTime,

    /// We failed to acquire random bytes from the system.
    FailedToGetRandomBytes,

    /// This function doesn't work until the TLS handshake
    /// is complete.
    HandshakeNotComplete,

    /// The peer sent an oversized record/fragment.
    PeerSentOversizedRecord,

    /// An incoming connection did not support any known application protocol.
    NoApplicationProtocol,

    /// The `max_fragment_size` value supplied in configuration was too small,
    /// or too large.
    BadMaxFragmentSize,

    /// Specific failure cases from [`keys_match`].
    ///
    /// [`keys_match`]: crate::crypto::signer::CertifiedKey::keys_match
    InconsistentKeys,

    /// Any other error.
    ///
    /// This variant should only be used when the error is not better described by a more
    /// specific variant. For example, if a custom crypto provider returns a
    /// provider specific error.
    ///
    /// Enums holding this variant will never compare equal to each other.
    Other,
}

/// A corrupt TLS message payload that resulted in an error.
#[non_exhaustive]
#[derive(Debug, Clone, Copy, PartialEq)]

pub enum InvalidMessage {
    /// A certificate payload exceeded rustls's 64KB limit
    CertificatePayloadTooLarge,
    /// An advertised message was larger then expected.
    HandshakePayloadTooLarge,
    /// The peer sent us a syntactically incorrect ChangeCipherSpec payload.
    InvalidCcs,
    /// An unknown content type was encountered during message decoding.
    InvalidContentType,
    /// A peer sent an invalid certificate status type
    InvalidCertificateStatusType,
    /// Context was incorrectly attached to a certificate request during a handshake.
    InvalidCertRequest,
    /// A peer's DH params could not be decoded
    InvalidDhParams,
    /// A message was zero-length when its record kind forbids it.
    InvalidEmptyPayload,
    /// A peer sent an unexpected key update request.
    InvalidKeyUpdate,
    /// A peer's server name could not be decoded
    InvalidServerName,
    /// A TLS message payload was larger then allowed by the specification.
    MessageTooLarge,
    /// Message is shorter than the expected length
    MessageTooShort,
    /// Missing data for the named handshake payload value
    MissingData(&'static str),
    /// A peer did not advertise its supported key exchange groups.
    MissingKeyExchange,
    /// A peer sent an empty list of signature schemes
    NoSignatureSchemes,
    /// Trailing data found for the named handshake payload value
    TrailingData(&'static str),
    /// A peer sent an unexpected message type.
    UnexpectedMessage(&'static str),
    /// An unknown TLS protocol was encountered during message decoding.
    UnknownProtocolVersion,
    /// A peer sent a non-null compression method.
    UnsupportedCompression,
    /// A peer sent an unknown elliptic curve type.
    UnsupportedCurveType,
    /// A peer sent an unsupported key exchange algorithm.
    UnsupportedKeyExchangeAlgorithm(KeyExchangeAlgorithm),
}

impl From<InvalidMessage> for Error {
    #[inline]
    fn from(e: InvalidMessage) -> Self {
        Self::InvalidMessage(e)
    }
}
