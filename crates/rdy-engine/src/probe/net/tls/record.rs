//! The trust stores and the recording verifier. Private to the TLS facade (ADR 0009 decision 5, ADR 0014
//! decision 3).
//!
//! [`Recording`] accepts every chain, so a handshake against a server whose issuer the machine does not
//! trust still completes and the chain can be read. It never reaches a caller: [`Probe::tls_chain`]
//! builds it, drives one handshake that sends no application data, and returns the chain and the two
//! verdicts, never the stream. Nothing here is `pub`, and no other module builds a `ClientConfig`
//! with it.
//!
//! Inside `verify_server_cert` it runs two real `WebPkiServerVerifier`s, one on the OS roots and one on
//! the bundled Mozilla roots, and keeps each verdict. Signature checks go to the provider as they would
//! for any verifier. There is no revocation check.

use std::sync::{Arc, Mutex, PoisonError};

use rustls::client::WebPkiServerVerifier;
use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::crypto::{CryptoProvider, WebPkiSupportedAlgorithms};
use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
use rustls::{CertificateError, DigitallySignedStruct, Error, RootCertStore, SignatureScheme};

use super::{TrustFailure, TrustVerdict};

/// A set of trust anchors and the verifier built on it. A set with no anchor cannot verify anything
/// (`webpki` refuses to build one), so `verifier` is `None` and the verdict is [`TrustVerdict::Unavailable`].
#[derive(Debug)]
pub(crate) struct Trust {
    pub(super) verifier: Option<Arc<WebPkiServerVerifier>>,
    /// The number of anchors in the set.
    roots: usize,
}

impl Trust {
    /// A set with no anchors: every verdict is `Unavailable`. It stands for an OS with no source and for
    /// a store that could not be read.
    pub(crate) fn unavailable() -> Self {
        Self {
            verifier: None,
            roots: 0,
        }
    }

    /// The OS roots, as DER. A certificate that does not parse is left out; the count is of those used.
    pub(crate) fn from_der(certs: &[Vec<u8>], provider: &Arc<CryptoProvider>) -> Self {
        let mut store = RootCertStore::empty();
        let _ = store.add_parsable_certificates(
            certs.iter().map(|der| CertificateDer::from(der.as_slice())),
        );
        Self::from_store(store, provider)
    }

    /// The Mozilla roots that `webpki-roots` bundles.
    pub(crate) fn bundled(provider: &Arc<CryptoProvider>) -> Self {
        let store = RootCertStore {
            roots: webpki_roots::TLS_SERVER_ROOTS.to_vec(),
        };
        Self::from_store(store, provider)
    }

    fn from_store(store: RootCertStore, provider: &Arc<CryptoProvider>) -> Self {
        let roots = store.len();
        let verifier = if roots == 0 {
            None
        } else {
            WebPkiServerVerifier::builder_with_provider(Arc::new(store), Arc::clone(provider))
                .build()
                .ok()
        };
        Self { verifier, roots }
    }

    /// The number of trust anchors.
    pub(crate) fn roots(&self) -> usize {
        self.roots
    }

    fn judge(
        &self,
        end_entity: &CertificateDer<'_>,
        intermediates: &[CertificateDer<'_>],
        name: &ServerName<'_>,
        now: UnixTime,
    ) -> TrustVerdict {
        let Some(verifier) = &self.verifier else {
            return TrustVerdict::Unavailable;
        };
        match verifier.verify_server_cert(end_entity, intermediates, name, &[], now) {
            Ok(_) => TrustVerdict::Valid,
            Err(error) => TrustVerdict::Rejected(failure_of(&error)),
        }
    }
}

/// The class of a verifier error. Everything that is not one of the named classes is `Policy`: rustls
/// and `webpki` refuse some certificates that older appliances still issue (no SAN, SHA-1).
pub(super) fn failure_of(error: &Error) -> TrustFailure {
    match error {
        Error::InvalidCertificate(inner) => match inner {
            CertificateError::UnknownIssuer => TrustFailure::UnknownIssuer,
            CertificateError::Expired | CertificateError::ExpiredContext { .. } => {
                TrustFailure::Expired
            }
            CertificateError::NotValidYet | CertificateError::NotValidYetContext { .. } => {
                TrustFailure::NotYetValid
            }
            CertificateError::NotValidForName | CertificateError::NotValidForNameContext { .. } => {
                TrustFailure::NameMismatch
            }
            CertificateError::BadSignature => TrustFailure::BadSignature,
            _ => TrustFailure::Policy,
        },
        _ => TrustFailure::Policy,
    }
}

/// What one handshake showed: the chain as the server sent it, and the two verdicts.
#[derive(Debug, Clone)]
pub(crate) struct Seen {
    /// The DER of each certificate, the server's own first.
    pub(crate) chain: Vec<Vec<u8>>,
    pub(crate) system: TrustVerdict,
    pub(crate) bundled: TrustVerdict,
}

/// The verifier that records the chain and accepts it. See the module docs.
#[derive(Debug)]
pub(crate) struct Recording {
    system: Arc<Trust>,
    bundled: Arc<Trust>,
    algorithms: WebPkiSupportedAlgorithms,
    seen: Mutex<Option<Seen>>,
}

impl Recording {
    pub(crate) fn new(
        system: Arc<Trust>,
        bundled: Arc<Trust>,
        algorithms: WebPkiSupportedAlgorithms,
    ) -> Self {
        Self {
            system,
            bundled,
            algorithms,
            seen: Mutex::new(None),
        }
    }

    /// What the handshake showed, once. `None` if the server never presented a certificate.
    pub(crate) fn take(&self) -> Option<Seen> {
        self.seen
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .take()
    }
}

impl ServerCertVerifier for Recording {
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        intermediates: &[CertificateDer<'_>],
        server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        now: UnixTime,
    ) -> Result<ServerCertVerified, Error> {
        let seen = Seen {
            chain: std::iter::once(end_entity)
                .chain(intermediates)
                .map(|der| der.as_ref().to_vec())
                .collect(),
            system: self
                .system
                .judge(end_entity, intermediates, server_name, now),
            bundled: self
                .bundled
                .judge(end_entity, intermediates, server_name, now),
        };
        *self.seen.lock().unwrap_or_else(PoisonError::into_inner) = Some(seen);
        Ok(ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, Error> {
        rustls::crypto::verify_tls12_signature(message, cert, dss, &self.algorithms)
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, Error> {
        rustls::crypto::verify_tls13_signature(message, cert, dss, &self.algorithms)
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.algorithms.supported_schemes()
    }
}
