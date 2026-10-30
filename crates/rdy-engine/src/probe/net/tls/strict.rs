//! The strict client configuration of the HTTP probe (M1-093, ADR 0014 decision 3).
//!
//! An HTTP call must not send a request to a server whose certificate the roots do not accept, so
//! this configuration verifies with a real `WebPkiServerVerifier` on the roots of the call: the OS
//! store for `trust: system`, the bundled Mozilla list for `trust: bundled`, and nothing else. It has no
//! custom verifier and no `dangerous()` call. A chain that does not validate fails the handshake with
//! the rustls error the caller types, and no application byte is sent. The recording verifier of
//! `record.rs` is the only one that accepts an untrusted chain, and it is never offered here.
//!
//! The ALPN offer is `http/1.1` alone: the probe speaks nothing else, and a server that would choose
//! `h2` from the recording handshake's offer must not be given the chance. There is no revocation
//! check. Sessions are not resumed, so every call shows its own handshake.

use std::sync::Arc;

use rustls::ClientConfig;
use rustls::client::Resumption;
use rustls::crypto::CryptoProvider;

use super::NoRoots;
use super::record::Trust;

/// The only protocol the strict handshake offers.
pub(super) const ALPN: &[u8] = b"http/1.1";

/// Why no strict configuration could be built.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum StrictError {
    /// The set of roots is empty or unavailable, so there is nothing to verify against.
    NoRoots(NoRoots),
    /// rustls refused the protocol versions or the provider. A broken build, not a test result.
    Config,
}

/// The client configuration that verifies with `trust` and speaks HTTP/1.1.
pub(super) fn strict_client(
    trust: &Trust,
    provider: Arc<CryptoProvider>,
) -> Result<ClientConfig, StrictError> {
    let verifier = trust
        .verifier
        .clone()
        .ok_or_else(|| StrictError::NoRoots(trust.missing()))?;
    let mut config = ClientConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()
        .map_err(|_| StrictError::Config)?
        .with_webpki_verifier(verifier)
        .with_no_client_auth();
    config.alpn_protocols = vec![ALPN.to_vec()];
    config.enable_sni = true;
    config.resumption = Resumption::disabled();
    Ok(config)
}
