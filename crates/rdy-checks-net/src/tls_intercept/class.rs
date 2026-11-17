//! The classes of `net.tls_intercept` and the words for each (03 section 3, "net.tls_intercept").
//!
//! The recording handshake of the probe facade yields two verdicts for one chain: one against the
//! bundled public roots and one against this machine's OS store. [`Class::of_verdicts`] turns the pair
//! into one class. It is a pure function, so every pair has a table test and no socket is needed.
//!
//! A class is a short stable id, safe to put in a report. The `Fix:` text holds only the spec's own
//! host text, never a name or a value read from the peer's certificate.

use rdy_engine::check::{Level, Os};
use rdy_engine::probe::NoRoots;
use rdy_engine::probe::net::{TrustFailure, TrustVerdict};

/// What one host's chain turned out to be.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum Class {
    /// The bundled public roots validate the chain: nothing re-signs it.
    Public,
    /// Only this machine's store validates it: an internal CA, or an inspecting proxy whose CA was
    /// installed here. The Windows and macOS stores hold roots Mozilla does not, so this is not stated
    /// as an inspection proxy.
    MachineOnly,
    /// No root validates it: the issuer's CA is not installed, and product clients will fail.
    UnknownCa,
    /// A certificate is expired or not yet valid. Never reported as interception.
    ClockOrExpiry,
    /// The certificate does not name the host.
    NameMismatch,
    /// The chain was refused for a reason that is not the issuer: a bad signature, a SHA-1 signature, a
    /// key usage that does not fit.
    Untrusted,
    /// The chain does not validate publicly and this machine has no store to judge it against.
    NoTrustStore,
}

impl Class {
    /// Every class, for the tests that audit all the words.
    #[cfg(test)]
    pub(super) const ALL: [Class; 7] = [
        Self::Public,
        Self::MachineOnly,
        Self::UnknownCa,
        Self::ClockOrExpiry,
        Self::NameMismatch,
        Self::Untrusted,
        Self::NoTrustStore,
    ];

    /// The class of a chain from its two verdicts.
    ///
    /// The order of the rules is the point. A chain the public roots validate is public, whatever this
    /// machine's store says. Then one that only the OS store validates. Of the rest, a clock failure
    /// comes first, because a wrong clock or an old certificate must never be read as interception;
    /// then a wrong name, then a missing store, then an unknown issuer.
    pub(super) fn of_verdicts(bundled: TrustVerdict, system: TrustVerdict) -> Self {
        if bundled == TrustVerdict::Valid {
            return Self::Public;
        }
        if system == TrustVerdict::Valid {
            return Self::MachineOnly;
        }
        let failed = |wanted: fn(TrustFailure) -> bool| {
            [bundled, system]
                .into_iter()
                .any(|v| matches!(v, TrustVerdict::Rejected(f) if wanted(f)))
        };
        if failed(TrustFailure::is_clock_or_expiry) {
            Self::ClockOrExpiry
        } else if failed(|f| f == TrustFailure::NameMismatch) {
            Self::NameMismatch
        } else if matches!(system, TrustVerdict::Unavailable(_))
            && bundled == TrustVerdict::Rejected(TrustFailure::UnknownIssuer)
        {
            Self::NoTrustStore
        } else if failed(|f| f == TrustFailure::UnknownIssuer) {
            Self::UnknownCa
        } else {
            Self::Untrusted
        }
    }

    /// The id written to the report.
    pub(super) fn id(self) -> &'static str {
        match self {
            Self::Public => "public",
            Self::MachineOnly => "machine_only",
            Self::UnknownCa => "unknown_ca",
            Self::ClockOrExpiry => "clock_or_expiry",
            Self::NameMismatch => "tls_name_mismatch",
            Self::Untrusted => "tls_untrusted",
            Self::NoTrustStore => "no_trust_store",
        }
    }

    /// How bad the class is. `forbid_interception` turns a machine-only chain from a warning into a
    /// block, for vendors whose product pins certificates or uses mutual TLS.
    pub(super) fn level(self, forbid_interception: bool) -> Level {
        match self {
            Self::Public => Level::Pass,
            Self::MachineOnly if forbid_interception => Level::Fail,
            Self::MachineOnly => Level::Warn,
            _ => Level::Fail,
        }
    }

    /// One phrase for the message line, after the host.
    pub(super) fn phrase(self, why: Option<NoRoots>) -> &'static str {
        match self {
            Self::Public => "chain validates against the public roots",
            Self::MachineOnly => "chain is trusted by this machine only",
            Self::UnknownCa => "issuer's CA is not installed on this machine",
            Self::ClockOrExpiry => "certificate is expired or not valid yet",
            Self::NameMismatch => "certificate is not valid for this name",
            Self::Untrusted => "chain was rejected by rustls policy or has a bad signature",
            Self::NoTrustStore => why.map_or("no OS trust store found", NoRoots::phrase),
        }
    }

    /// The `Fix:` text for `host` on `os`, or `None` for a chain that needs none. Every command in it
    /// is on the fix-text allow-list (a test audits all of them).
    pub(super) fn fix(
        self,
        os: Os,
        host: &str,
        port: u16,
        forbid_interception: bool,
        why: Option<NoRoots>,
    ) -> Option<String> {
        let install = match os {
            Os::Windows => {
                "import that CA into the Trusted Root Certification Authorities store with `certlm.msc`"
            }
            Os::Macos => {
                "install that CA with `security add-trusted-cert -d -r trustRoot -k /Library/Keychains/System.keychain ca.crt`"
            }
            _ => {
                "install that CA (Debian and Ubuntu: `update-ca-certificates`; RHEL: `update-ca-trust`)"
            }
        };
        Some(match self {
            Self::Public => return None,
            Self::MachineOnly => {
                let pinned = if forbid_interception {
                    " The spec forbids interception, so the product cannot cross a proxy that re-signs TLS."
                } else {
                    ""
                };
                format!(
                    "{host} is presented with a chain that public roots do not vouch for but this machine's store trusts. An internal CA or a TLS-inspecting proxy is the usual cause. Ask the network team to bypass inspection for {host}.{pinned} Container images and Java do not read the host store, so a product in one fails unless that CA is added there too."
                )
            }
            Self::UnknownCa => format!(
                "{host} is presented with a chain from a CA this machine does not trust, so the product's clients will fail. A TLS-inspecting proxy is the usual cause. Ask the network team to bypass inspection for {host}, or {install}."
            ),
            Self::ClockOrExpiry => {
                let clock = match os {
                    Os::Windows => "`w32tm /query /status`",
                    Os::Macos => "`sntp time.apple.com`",
                    _ => "`timedatectl`",
                };
                format!(
                    "The certificate of {host} is expired or not valid yet. This is not interception. Check this machine's clock with {clock} and see host.time_sync. If the clock is right, the server's owner must renew the certificate."
                )
            }
            Self::NameMismatch => format!(
                "The certificate of {host} is not valid for that name. Check the name in the spec, or ask the server's owner for a certificate that names it."
            ),
            Self::Untrusted => {
                // An address host sends no SNI, so no -servername; a name is bare, with no brackets.
                let name = host.trim_matches(['[', ']']);
                let sni = if name.parse::<std::net::IpAddr>().is_ok() {
                    String::new()
                } else {
                    format!(" -servername {name}")
                };
                format!(
                    "The certificate chain of {host} was rejected by rustls policy or has a bad signature, not a problem with its issuer: an old hash, a missing subject alternative name or a key that does not fit. Run `openssl s_client -connect {host}:{port}{sni}` to see the chain and ask the server's owner to reissue it."
                )
            }
            Self::NoTrustStore => match why {
                Some(NoRoots::Overridden) => format!(
                    "SSL_CERT_FILE or SSL_CERT_DIR is set and rdy does not read it on this OS, so {host} cannot be judged against the OS store. Unset SSL_CERT_FILE and SSL_CERT_DIR and run again."
                ),
                Some(NoRoots::Unreadable) => format!(
                    "The OS trust store could not be read, so {host} cannot be judged against it. Check that SSL_CERT_FILE and SSL_CERT_DIR, if set, name files this user can read, and that the OS store is intact."
                ),
                _ => {
                    let store = match os {
                        Os::Linux => {
                            "Install it with `apt-get install ca-certificates` or `dnf install ca-certificates`."
                        }
                        _ => "Check that the OS certificate store is intact.",
                    };
                    format!(
                        "This machine has no CA store rdy can read, so {host} cannot be judged against it. {store}"
                    )
                }
            },
        })
    }
}
