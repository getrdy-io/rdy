//! The trust stores and the recording verifier. Private to the TLS facade (ADR 0009 decision 5, ADR 0014
//! decision 3).
//!
//! [`Recording`] accepts every chain, so a handshake against a server whose issuer the machine does not
//! trust still completes and the chain can be read. It never reaches a caller: [`Probe::tls_chain`]
//! builds it, drives one handshake that sends no application data, and returns the chain and the two
//! verdicts, never the stream. Nothing here is more visible than `pub(super)`, [`recording_client`] is
//! the only place that builds a `ClientConfig` with it, and it is also the only place that calls
//! `rustls`'s `dangerous()` builder: clippy bans that method everywhere else (`clippy.toml`).
//!
//! Inside `verify_server_cert` it runs two real `WebPkiServerVerifier`s, one on the OS roots and one on
//! the bundled Mozilla roots, and keeps each verdict. Signature checks go to the provider as they would
//! for any verifier. There is no revocation check.

use std::sync::{Arc, Mutex, PoisonError};

use rustls::ClientConfig;
use rustls::client::Resumption;

use rustls::client::WebPkiServerVerifier;
use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::crypto::{CryptoProvider, WebPkiSupportedAlgorithms};
use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
use rustls::{CertificateError, DigitallySignedStruct, Error, RootCertStore, SignatureScheme};

use super::{ALPN_PROTOCOLS, NoRoots, TrustFailure, TrustVerdict};
use crate::probe::{StoreSource, SystemRoots};

/// A set of trust anchors and the verifier built on it. A set with no anchor cannot verify anything
/// (`webpki` refuses to build one), so `verifier` is `None` and the verdict is [`TrustVerdict::Unavailable`].
#[derive(Debug)]
pub(super) struct Trust {
    pub(super) verifier: Option<Arc<WebPkiServerVerifier>>,
    /// Why there is no verifier, when there is none.
    missing: NoRoots,
    /// The number of anchors in the set.
    roots: usize,
    /// Where the OS roots were read from. Empty for the bundled set and for a store that was not read.
    sources: Vec<StoreSource>,
    /// The SHA-256 of the DER of each anchor of an OS store, in store order. Empty for the bundled set.
    hashes: Vec<[u8; 32]>,
}

impl Trust {
    /// A set with no anchors: every verdict is `Unavailable`, for this reason. `Empty` stands for an OS
    /// with no source, `Unreadable` for a store that could not be read.
    pub(super) fn unavailable(missing: NoRoots) -> Self {
        Self {
            verifier: None,
            missing,
            roots: 0,
            sources: Vec::new(),
            hashes: Vec::new(),
        }
    }

    /// The OS roots, as DER. A certificate that does not parse is left out; the count and the hashes are
    /// of those used.
    pub(super) fn from_der(found: &SystemRoots, provider: &Arc<CryptoProvider>) -> Self {
        let mut store = RootCertStore::empty();
        let mut hashes = Vec::with_capacity(found.certs.len());
        for der in &found.certs {
            if store.add(CertificateDer::from(der.as_slice())).is_ok() {
                hashes.push(sha256(der));
            }
        }
        let mut trust = Self::from_store(store, provider);
        trust.sources.clone_from(&found.sources);
        trust.hashes = hashes;
        trust
    }

    /// The Mozilla roots that `webpki-roots` bundles.
    pub(super) fn bundled(provider: &Arc<CryptoProvider>) -> Self {
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
        Self {
            verifier,
            // A store that parsed into nothing is an empty store.
            missing: NoRoots::Empty,
            roots,
            sources: Vec::new(),
            hashes: Vec::new(),
        }
    }

    /// The number of trust anchors.
    pub(super) fn roots(&self) -> usize {
        self.roots
    }

    /// Why there is no verifier, for a set that has none.
    pub(super) fn missing(&self) -> NoRoots {
        self.missing
    }

    /// Where the roots were read from.
    pub(super) fn sources(&self) -> &[StoreSource] {
        &self.sources
    }

    /// The SHA-256 of each root.
    pub(super) fn hashes(&self) -> &[[u8; 32]] {
        &self.hashes
    }

    fn judge(
        &self,
        end_entity: &CertificateDer<'_>,
        intermediates: &[CertificateDer<'_>],
        name: &ServerName<'_>,
        now: UnixTime,
    ) -> TrustVerdict {
        let Some(verifier) = &self.verifier else {
            return TrustVerdict::Unavailable(self.missing);
        };
        match verifier.verify_server_cert(end_entity, intermediates, name, &[], now) {
            Ok(_) => TrustVerdict::Valid,
            Err(error) => TrustVerdict::Rejected(failure_of(&error)),
        }
    }
}

/// The SHA-256 of `der`.
pub(super) fn sha256(der: &[u8]) -> [u8; 32] {
    let digest = ring::digest::digest(&ring::digest::SHA256, der);
    let mut out = [0_u8; 32];
    out.copy_from_slice(digest.as_ref());
    out
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
pub(super) struct Seen {
    /// The DER of each certificate, the server's own first.
    pub(super) chain: Vec<Vec<u8>>,
    pub(super) system: TrustVerdict,
    pub(super) bundled: TrustVerdict,
}

/// The verifier that records the chain and accepts it. See the module docs.
#[derive(Debug)]
pub(super) struct Recording {
    system: Arc<Trust>,
    bundled: Arc<Trust>,
    algorithms: WebPkiSupportedAlgorithms,
    seen: Mutex<Option<Seen>>,
}

impl Recording {
    fn new(system: Arc<Trust>, bundled: Arc<Trust>, algorithms: WebPkiSupportedAlgorithms) -> Self {
        Self {
            system,
            bundled,
            algorithms,
            seen: Mutex::new(None),
        }
    }

    /// What the handshake showed, once. `None` if the server never presented a certificate.
    pub(super) fn take(&self) -> Option<Seen> {
        self.seen
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .take()
    }
}

/// The client configuration of a recording handshake and the recorder that holds what it saw: the
/// recording verifier, TLS 1.2 and 1.3 on ring, the ALPN offer, SNI on, and no session to resume.
///
/// This is the one place that builds a `ClientConfig` around [`Recording`].
pub(super) fn recording_client(
    system: Arc<Trust>,
    bundled: Arc<Trust>,
    provider: Arc<CryptoProvider>,
) -> Result<(ClientConfig, Arc<Recording>), Error> {
    let recorder = Arc::new(Recording::new(
        system,
        bundled,
        provider.signature_verification_algorithms,
    ));
    let builder =
        ClientConfig::builder_with_provider(provider).with_safe_default_protocol_versions()?;
    // The one call of `dangerous()` in the workspace. The verifier it takes accepts every chain, so
    // it is built here and the stream it protects never leaves `tls_chain`.
    #[expect(
        clippy::disallowed_methods,
        reason = "the recording verifier is the point of this module; see the module docs"
    )]
    let builder = builder.dangerous();
    let mut config = builder
        .with_custom_certificate_verifier(Arc::clone(&recorder) as Arc<dyn ServerCertVerifier>)
        .with_no_client_auth();
    config.alpn_protocols = ALPN_PROTOCOLS
        .iter()
        .map(|protocol| protocol.as_bytes().to_vec())
        .collect();
    config.enable_sni = true;
    config.resumption = Resumption::disabled();
    Ok((config, recorder))
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
