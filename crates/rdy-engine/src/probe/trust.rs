//! The words for why a certificate chain or a trust store did not work out (M1-092, M1-093).
//!
//! These small enums sit outside the `net` module because [`NetFailure`](super::NetFailure) names them
//! and `NetFailure` is built in every configuration of the crate. `probe::net` re-exports them under
//! the names `TrustFailure` and `NoRoots`, where the TLS facade documents them.

/// Why a chain did not validate against a set of roots.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum TrustFailure {
    /// No root in the set signed the chain: the issuer's CA is not installed here.
    UnknownIssuer,
    /// A certificate in the chain has expired. Report it as clock or expiry, not as interception.
    Expired,
    /// A certificate in the chain is not valid yet. Report it as clock or expiry too.
    NotYetValid,
    /// The leaf is not valid for the name asked for.
    NameMismatch,
    /// A certificate's signature did not verify.
    BadSignature,
    /// rustls policy refused the chain for another reason: no subject alternative name, a SHA-1
    /// signature, a key usage that does not fit, a malformed certificate.
    Policy,
}

impl TrustFailure {
    /// `true` for the two failures that point at a wrong clock or an old certificate and not at the
    /// issuer: `Expired` and `NotYetValid`.
    #[must_use]
    pub fn is_clock_or_expiry(self) -> bool {
        matches!(self, Self::Expired | Self::NotYetValid)
    }

    /// A fixed phrase for the failure, for messages and the action log.
    #[must_use]
    pub fn phrase(self) -> &'static str {
        match self {
            Self::UnknownIssuer => "its issuer is not trusted by this machine",
            Self::Expired => "the certificate has expired",
            Self::NotYetValid => "the certificate is not valid yet",
            Self::NameMismatch => "the certificate is not valid for this name",
            Self::BadSignature => "a signature in the chain did not verify",
            Self::Policy => "the certificate was refused by the TLS rules",
        }
    }

    /// What to do about the failure, as a sentence for a `Fix:` hint.
    pub(crate) fn fix(self) -> &'static str {
        match self {
            Self::UnknownIssuer => {
                "either a proxy or firewall re-signs TLS (run net.tls_intercept to see who signs it) or this machine lacks the issuing CA; install the CA in the OS trust store, or ask the vendor whether the spec may use trust: bundled"
            }
            Self::Expired | Self::NotYetValid => {
                "check this machine's clock first, then the certificate's dates with the server's owner"
            }
            Self::NameMismatch => {
                "use a host name that the server's certificate lists, or ask its owner to add the name"
            }
            Self::BadSignature | Self::Policy => {
                "the server's certificate chain is damaged or too old for current TLS rules; ask its owner to reissue it"
            }
        }
    }
}

/// Why there are no OS roots to judge a chain against.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum NoRoots {
    /// The OS has no trust store rdy can see, or the store holds no certificate. A check reports "no OS
    /// trust store found".
    Empty,
    /// The OS has a store but it could not be read: a file the operator named with `SSL_CERT_FILE` or
    /// `SSL_CERT_DIR` was missing or refused, or the OS gave an error. A check reports "the OS trust store
    /// could not be read" and not "no store found".
    Unreadable,
    /// `SSL_CERT_FILE` or `SSL_CERT_DIR` is set and rdy may not read what it names on this OS (Windows,
    /// in this version). A check reports that and says to unset the variable.
    Overridden,
}

impl NoRoots {
    /// A fixed phrase, for messages and the action log.
    #[must_use]
    pub fn phrase(self) -> &'static str {
        match self {
            Self::Empty => "no OS trust store found",
            Self::Unreadable => "the OS trust store could not be read",
            Self::Overridden => {
                "SSL_CERT_FILE or SSL_CERT_DIR is set and rdy does not read it on this OS"
            }
        }
    }

    /// What to do about it, as a sentence for a `Fix:` hint.
    pub(crate) fn fix(self) -> &'static str {
        match self {
            Self::Empty => {
                "install the ca-certificates package (or this OS's equivalent), or ask the vendor whether the spec may use trust: bundled"
            }
            Self::Unreadable => {
                "check that SSL_CERT_FILE and SSL_CERT_DIR, if set, name files this user can read, and that the OS trust store is intact"
            }
            Self::Overridden => "unset SSL_CERT_FILE and SSL_CERT_DIR and run again",
        }
    }
}
