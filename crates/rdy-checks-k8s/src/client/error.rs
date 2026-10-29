//! Errors of the kube client layer.
//!
//! One rule shapes every variant: **no text from a kube error and no byte of a credential plugin's
//! output goes into an error value.** kube's own errors can hold them. `AuthExecRun` formats the
//! plugin's whole stdout and stderr with `{:?}`, and a parse error can quote the kubeconfig line that
//! holds a token. So this module maps each kube error to a variant with fixed words, a status code, an
//! exit code or an `io::ErrorKind`, and drops the kube error itself. The variants hold no kube value,
//! so `Debug` and `Display` of a [`KubeError`] are safe to log (ADR 0010 decision 7, ADR 0031).

use std::error::Error as _;
use std::io;

use kube::client::AuthError;
use kube::config::KubeconfigError;

use super::text::escape_capped;

/// The longest piece of server or network text kept in an error, in characters.
const CAUSE_CAP: usize = 240;

/// Why the kube client could not be built or did not get an answer.
///
/// Every variant has a [`KubeError::hint`]. The `Display` text is one short sentence.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum KubeError {
    /// No kubeconfig file and no in-cluster config.
    #[error("no kubeconfig found")]
    NoKubeconfig,

    /// A kubeconfig file could not be read.
    #[error("cannot read the kubeconfig {path}: {reason}")]
    KubeconfigUnreadable {
        /// The path, escaped for a terminal.
        path: String,
        /// A fixed phrase.
        reason: &'static str,
    },

    /// A kubeconfig file is not a valid kubeconfig, or two files cannot be merged.
    #[error("the kubeconfig {path} is not valid: {reason}")]
    KubeconfigInvalid {
        /// The path, escaped for a terminal. Empty when the error is about a merge of several files.
        path: String,
        /// A fixed phrase. It never quotes the file.
        reason: &'static str,
    },

    /// The kubeconfig has no `current-context` and `--kube-context` was not given.
    #[error("the kubeconfig has no current context")]
    NoCurrentContext {
        /// Context names in the kubeconfig, escaped, at most 10.
        available: Vec<String>,
    },

    /// The context asked for is not in the kubeconfig (or `--kube-context` was given in a pod).
    #[error("the context {name} is not in the kubeconfig")]
    ContextNotFound {
        /// The name, escaped.
        name: String,
        /// Context names in the kubeconfig, escaped, at most 10.
        available: Vec<String>,
    },

    /// The selected context, cluster or user is missing a part the client needs.
    #[error("the kubeconfig is incomplete: {what}")]
    IncompleteKubeconfig {
        /// A fixed phrase.
        what: &'static str,
    },

    /// The user entry uses a legacy `auth-provider`.
    #[error("the kubeconfig user uses the {name} auth-provider, which rdy does not run")]
    AuthProviderUnsupported {
        /// The provider name, escaped.
        name: String,
    },

    /// The cluster entry has a `proxy-url`.
    #[error("the kubeconfig sets a proxy-url for the cluster, which this rdy does not use yet")]
    ProxyUnsupported,

    /// The TLS setup failed (a bad certificate, key or CA bundle).
    #[error("cannot set up TLS for the cluster: {what}")]
    Tls {
        /// A fixed phrase.
        what: &'static str,
    },

    /// The credential plugin did not start.
    #[error("the credential plugin {plugin} did not start: {reason}")]
    PluginNotStarted {
        /// The plugin's file name, escaped. Never its arguments.
        plugin: String,
        /// A fixed phrase from the `io::ErrorKind`.
        reason: &'static str,
    },

    /// The credential plugin ran and failed. Its output is not kept.
    #[error("the credential plugin {plugin} failed{}", exit_suffix(*.exit_code))]
    PluginFailed {
        /// The plugin's file name, escaped. Never its arguments.
        plugin: String,
        /// The exit code, when the plugin exited with one.
        exit_code: Option<i32>,
    },

    /// The credential plugin ran but gave no credentials rdy could read. Its output is not kept.
    #[error("the credential plugin {plugin} gave no usable credentials")]
    PluginOutputInvalid {
        /// The plugin's file name, escaped. Never its arguments.
        plugin: String,
    },

    /// The credentials could not be loaded for another reason (a token file, a bad header value).
    #[error("cannot load the credentials: {what}")]
    CredentialsUnavailable {
        /// A fixed phrase.
        what: &'static str,
    },

    /// The API server answered 401.
    #[error("the cluster at {server} did not accept the credentials (401)")]
    Unauthorized {
        /// The server URL without user info, escaped.
        server: String,
    },

    /// The API server answered 403.
    #[error("the cluster at {server} refused the request (403)")]
    Forbidden {
        /// The server URL without user info, escaped.
        server: String,
    },

    /// The API server answered with another error status.
    #[error("the cluster at {server} answered with status {code}")]
    Api {
        /// The server URL without user info, escaped.
        server: String,
        /// The HTTP status code.
        code: u16,
        /// The reason from the server's `Status` body, escaped and cut. Empty when it had none.
        reason: String,
    },

    /// The connect or the read timed out.
    #[error("no answer from {server} in time")]
    Timeout {
        /// The server URL without user info, escaped.
        server: String,
    },

    /// The connection or the TLS handshake failed.
    #[error("cannot reach {server}: {cause}")]
    Unreachable {
        /// The server URL without user info, escaped.
        server: String,
        /// The network error chain (io, hyper, rustls), escaped and cut. It never comes from a
        /// credential plugin.
        cause: String,
    },

    /// The runtime shut down while the client was being built.
    #[error("the run was cancelled while the cluster client was being built")]
    Cancelled,

    /// Something else went wrong. The text is fixed.
    #[error("the cluster client failed: {what}")]
    Internal {
        /// A fixed phrase.
        what: &'static str,
    },
}

fn exit_suffix(code: Option<i32>) -> String {
    code.map_or_else(String::new, |c| format!(" with exit code {c}"))
}

impl KubeError {
    /// What to do about it. Short sentences, no em dashes (the fix hint of every user-facing error).
    #[must_use]
    pub fn hint(&self) -> String {
        match self {
            Self::NoKubeconfig => "Pass --kubeconfig <file> or set KUBECONFIG.".to_owned(),
            Self::KubeconfigUnreadable { .. } => {
                "Check that the file exists, is a regular file under 8 MiB, and that you can read it."
                    .to_owned()
            }
            Self::KubeconfigInvalid { .. } => {
                "Fix the file, or point --kubeconfig or KUBECONFIG at a kubeconfig that kubectl accepts."
                    .to_owned()
            }
            Self::NoCurrentContext { available } => context_hint("Pass --kube-context <name>", available),
            Self::ContextNotFound { available, .. } => {
                if available.is_empty() {
                    "A kubeconfig is not in use, so there are no contexts to choose from. Leave out --kube-context."
                        .to_owned()
                } else {
                    context_hint("Pass one of the names that exist with --kube-context <name>", available)
                }
            }
            Self::IncompleteKubeconfig { .. } => {
                "Check the context, cluster and user entries in the kubeconfig with kubectl config view."
                    .to_owned()
            }
            Self::AuthProviderUnsupported { .. } => {
                "Switch the user to an exec credential plugin, as kubectl 1.26 and later require."
                    .to_owned()
            }
            Self::ProxyUnsupported => {
                "Remove proxy-url from the kubeconfig cluster entry for this run, or tell the vendor."
                    .to_owned()
            }
            Self::Tls { .. } => {
                "Check certificate-authority, client-certificate and client-key in the kubeconfig."
                    .to_owned()
            }
            Self::PluginNotStarted { .. } => {
                "Install the plugin and put it on PATH, then run again. Check the command in the kubeconfig user."
                    .to_owned()
            }
            Self::PluginFailed { .. } | Self::PluginOutputInvalid { .. } => {
                "Run the same plugin command yourself to see why it fails. Log in again if it needs a login, then run rdy again."
                    .to_owned()
            }
            Self::CredentialsUnavailable { .. } => {
                "Check the user entry in the kubeconfig, then run again.".to_owned()
            }
            Self::Unauthorized { .. } => {
                "The credentials are expired or not accepted. Log in again, then run again.".to_owned()
            }
            Self::Forbidden { .. } => {
                "The identity may not read the server version. Ask the cluster admin for a read-only role."
                    .to_owned()
            }
            Self::Api { .. } => {
                "Check that the server address in the kubeconfig is the API server.".to_owned()
            }
            Self::Timeout { .. } | Self::Unreachable { .. } => {
                "Check the server address in your kubeconfig and that you are on the right network or VPN, then run rdy again."
                    .to_owned()
            }
            Self::Cancelled => "Run the command again.".to_owned(),
            Self::Internal { .. } => "Run the command again, and tell the vendor if it repeats.".to_owned(),
        }
    }

    /// The short text for the `capabilities` entry of the report when the cluster need is not met.
    ///
    /// `no kubeconfig found` for a missing config (07 appendix B), the `Display` text otherwise.
    #[must_use]
    pub fn detail(&self) -> String {
        self.to_string()
    }
}

fn context_hint(lead: &str, available: &[String]) -> String {
    if available.is_empty() {
        format!("{lead}.")
    } else {
        format!("{lead}. Contexts: {}.", available.join(", "))
    }
}

/// Maps a kubeconfig error to a variant with fixed words. The kube text is dropped: a parse error can
/// quote the file.
pub(crate) fn from_kubeconfig_error(error: &KubeconfigError, path: &str) -> KubeError {
    match error {
        KubeconfigError::Parse(_) => KubeError::KubeconfigInvalid {
            path: path.to_owned(),
            reason: "it is not a YAML kubeconfig",
        },
        KubeconfigError::KindMismatch | KubeconfigError::ApiVersionMismatch => {
            KubeError::KubeconfigInvalid {
                path: String::new(),
                reason: "the files in KUBECONFIG cannot be merged (different kind or apiVersion)",
            }
        }
        KubeconfigError::ReadConfig(source, _) => KubeError::KubeconfigUnreadable {
            path: path.to_owned(),
            reason: io_reason(source.kind()),
        },
        KubeconfigError::CurrentContextNotSet => KubeError::NoCurrentContext {
            available: Vec::new(),
        },
        KubeconfigError::LoadContext(_) => KubeError::IncompleteKubeconfig {
            what: "the context is not defined",
        },
        KubeconfigError::LoadClusterOfContext(_) => KubeError::IncompleteKubeconfig {
            what: "the context names a cluster that the kubeconfig does not define",
        },
        KubeconfigError::MissingClusterUrl => KubeError::IncompleteKubeconfig {
            what: "the cluster has no server URL",
        },
        KubeconfigError::ParseClusterUrl(_) => KubeError::IncompleteKubeconfig {
            what: "the server URL is not valid",
        },
        KubeconfigError::ParseProxyUrl(_) => KubeError::IncompleteKubeconfig {
            what: "a proxy URL (proxy-url in the kubeconfig, or HTTPS_PROXY) is not valid",
        },
        KubeconfigError::LoadCertificateAuthority(_) | KubeconfigError::ParseCertificates(_) => {
            KubeError::IncompleteKubeconfig {
                what: "the certificate authority cannot be read",
            }
        }
        KubeconfigError::LoadClientCertificate(_) => KubeError::IncompleteKubeconfig {
            what: "the client certificate cannot be read",
        },
        KubeconfigError::LoadClientKey(_) => KubeError::IncompleteKubeconfig {
            what: "the client key cannot be read",
        },
        _ => KubeError::IncompleteKubeconfig {
            what: "the kubeconfig cannot be used",
        },
    }
}

/// A fixed phrase for an `io::ErrorKind`.
pub(crate) fn io_reason(kind: io::ErrorKind) -> &'static str {
    match kind {
        io::ErrorKind::NotFound => "no such file",
        io::ErrorKind::PermissionDenied => "permission denied",
        io::ErrorKind::TimedOut => "timed out",
        io::ErrorKind::InvalidData => "it is not valid text",
        _ => "it cannot be read",
    }
}

/// Maps a kube error from building the client or from a request.
///
/// `server` is the display form of the server URL (already escaped). `plugin` is the exec plugin's file
/// name from the kubeconfig, when there is one.
pub(crate) fn from_kube_error(
    error: &kube::Error,
    server: &str,
    plugin: Option<&str>,
) -> KubeError {
    // An auth error can sit anywhere in the chain (the request path boxes it). Look for it first, so
    // nothing from a plugin is ever read from a `Display` text.
    if let Some(auth) = find_auth(error) {
        return from_auth_error(auth, plugin);
    }
    match error {
        kube::Error::Api(status) => match status.code {
            401 => KubeError::Unauthorized {
                server: server.to_owned(),
            },
            403 => KubeError::Forbidden {
                server: server.to_owned(),
            },
            code => KubeError::Api {
                server: server.to_owned(),
                code,
                reason: escape_capped(&status.reason, CAUSE_CAP),
            },
        },
        kube::Error::ProxyProtocolDisabled { .. }
        | kube::Error::ProxyProtocolUnsupported { .. } => KubeError::ProxyUnsupported,
        kube::Error::RustlsTls(tls) => KubeError::Tls {
            what: match tls {
                kube::client::RustlsTlsError::InvalidIdentityPem(_) => {
                    "the client certificate or key is not valid PEM"
                }
                kube::client::RustlsTlsError::MissingPrivateKey => {
                    "the client key is missing or not PKCS8 or RSA"
                }
                kube::client::RustlsTlsError::MissingCertificate => {
                    "the client certificate is missing"
                }
                kube::client::RustlsTlsError::InvalidPrivateKey(_)
                | kube::client::RustlsTlsError::UnknownPrivateKeyFormat => {
                    "the client key is not usable"
                }
                kube::client::RustlsTlsError::AddRootCertificate(_) => {
                    "a certificate authority is not usable"
                }
                kube::client::RustlsTlsError::NoValidNativeRootCA(_) => {
                    "the system has no usable root certificates"
                }
                kube::client::RustlsTlsError::InvalidServerName(_) => {
                    "the tls-server-name is not valid"
                }
            },
        },
        kube::Error::TlsRequired => KubeError::Tls {
            what: "no TLS stack is built in",
        },
        kube::Error::InferKubeconfig(inner) => from_kubeconfig_error(inner, ""),
        kube::Error::HyperError(_) | kube::Error::Service(_) | kube::Error::HttpError(_) => {
            network_error(error, server)
        }
        kube::Error::SerdeError(_) | kube::Error::FromUtf8(_) => KubeError::Api {
            server: server.to_owned(),
            code: 200,
            reason: "the answer is not a Kubernetes version document".to_owned(),
        },
        _ => KubeError::Internal {
            what: "the request failed",
        },
    }
}

fn network_error(error: &kube::Error, server: &str) -> KubeError {
    let mut leaf = error.to_string();
    let mut timed_out = false;
    let mut current: Option<&(dyn std::error::Error + 'static)> = error.source();
    while let Some(err) = current {
        if let Some(io_error) = err.downcast_ref::<io::Error>()
            && io_error.kind() == io::ErrorKind::TimedOut
        {
            timed_out = true;
        }
        // The outer layers repeat their source in their own text, so the last one is the shortest
        // statement of the cause.
        leaf = err.to_string();
        current = err.source();
    }
    if timed_out {
        return KubeError::Timeout {
            server: server.to_owned(),
        };
    }
    KubeError::Unreachable {
        server: server.to_owned(),
        cause: escape_capped(&leaf, CAUSE_CAP),
    }
}

/// Looks for an auth error in `error` and its sources.
fn find_auth(error: &kube::Error) -> Option<&AuthError> {
    if let kube::Error::Auth(auth) = error {
        return Some(auth);
    }
    let mut current: Option<&(dyn std::error::Error + 'static)> = error.source();
    while let Some(err) = current {
        if let Some(auth) = err.downcast_ref::<AuthError>() {
            return Some(auth);
        }
        if let Some(inner) = err.downcast_ref::<kube::Error>()
            && let kube::Error::Auth(auth) = inner
        {
            return Some(auth);
        }
        current = err.source();
    }
    None
}

fn from_auth_error(error: &AuthError, plugin: Option<&str>) -> KubeError {
    let plugin = plugin.map_or_else(|| "(unnamed)".to_owned(), str::to_owned);
    match error {
        AuthError::AuthExecRun { status, .. } => KubeError::PluginFailed {
            plugin,
            exit_code: status.code(),
        },
        AuthError::AuthExecStart(source) => KubeError::PluginNotStarted {
            plugin,
            reason: match source.kind() {
                io::ErrorKind::NotFound => "no such command",
                io::ErrorKind::PermissionDenied => "permission denied",
                _ => "it could not be started",
            },
        },
        AuthError::AuthExecParse(_)
        | AuthError::ExecPluginFailed
        | AuthError::MalformedTokenExpirationDate(_) => KubeError::PluginOutputInvalid { plugin },
        AuthError::MissingCommand => KubeError::IncompleteKubeconfig {
            what: "the exec credential plugin has no command",
        },
        AuthError::ExecMissingClusterInfo => KubeError::IncompleteKubeconfig {
            what: "the exec credential plugin needs cluster info that is missing",
        },
        AuthError::ReadTokenFile(source, _) => KubeError::CredentialsUnavailable {
            what: match source.kind() {
                io::ErrorKind::NotFound => "the token file does not exist",
                io::ErrorKind::PermissionDenied => "the token file is not readable",
                _ => "the token file cannot be read",
            },
        },
        AuthError::InvalidBasicAuth(_) | AuthError::InvalidBearerToken(_) => {
            KubeError::CredentialsUnavailable {
                what: "the token or password is not valid in an HTTP header",
            }
        }
        // `AuthExec` holds text that can include a command line, and `ParseTokenKey` quotes input.
        // Neither is read.
        _ => KubeError::CredentialsUnavailable {
            what: "the credentials cannot be loaded",
        },
    }
}
