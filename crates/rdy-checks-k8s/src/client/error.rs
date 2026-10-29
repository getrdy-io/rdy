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

    /// A kubeconfig file, or a file it names (a CA, a client certificate or key, a token file), could
    /// not be read.
    #[error("cannot read {path}: {reason}")]
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
    #[error(
        "the kubeconfig sets the proxy-url {proxy} for the cluster, which this rdy does not use yet"
    )]
    ProxyUnsupported {
        /// The proxy as scheme, host and port. Never user info, path or query. Escaped.
        proxy: String,
    },

    /// rdy runs in a pod, and the service account files or variables are not usable.
    #[error("the pod's service account cannot be used: {what}")]
    InClusterUnusable {
        /// A fixed phrase.
        what: &'static str,
    },

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

    /// The API server answered 200, but not with a Kubernetes version document.
    #[error("the answer from {server} is not a Kubernetes version document")]
    BadAnswer {
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
        /// `HTTPS_PROXY` or `https_proxy` is set in the environment. rdy does not use it for the
        /// cluster, and the hint says so.
        proxy_env_set: bool,
    },

    /// The connection or the TLS handshake failed.
    #[error("cannot reach {server}: {cause}")]
    Unreachable {
        /// The server URL without user info, escaped.
        server: String,
        /// One of a fixed set of phrases for the kind of failure. It is chosen from the error kind and
        /// never copies text from the error chain, so it cannot hold anything a plugin printed.
        cause: &'static str,
        /// `HTTPS_PROXY` or `https_proxy` is set in the environment. rdy does not use it for the
        /// cluster, and the hint says so.
        proxy_env_set: bool,
        /// The kubeconfig (or the pod) names a certificate authority. Without one rdy trusts only its
        /// bundled public roots, and the hint for an unknown issuer says so.
        ca_set: bool,
    },

    /// The runtime shut down while the config was being read or the client was being built.
    #[error("the run was cancelled while the cluster client was being set up")]
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
            Self::NoKubeconfig => with_distro_files("Pass --kubeconfig <file> or set KUBECONFIG."),
            Self::KubeconfigUnreadable { reason, .. } => {
                let base = "Check that the file exists, is a regular file under 8 MiB (1 MiB for a certificate, key or token file), and that you can read it.";
                if *reason == "permission denied" {
                    with_distro_files(base)
                } else {
                    base.to_owned()
                }
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
            Self::AuthProviderUnsupported { name } => auth_provider_hint(name),
            Self::ProxyUnsupported { .. } => {
                "rdy does not use a proxy for the cluster yet. Do not edit your working kubeconfig. Run rdy from a host that reaches the API server directly, or pass a copy of the kubeconfig without proxy-url with --kubeconfig."
                    .to_owned()
            }
            Self::InClusterUnusable { .. } => {
                "Mount the service account token (automountServiceAccountToken: true) or pass --kubeconfig <file>."
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
                "Every logged-in identity may read /version, so a gateway or proxy in front of the API server probably refused the request, or a cluster admin removed the system:public-info-viewer binding. Ask the cluster admin."
                    .to_owned()
            }
            Self::Api { .. } | Self::BadAnswer { .. } => {
                "Check that the server address in the kubeconfig is the API server.".to_owned()
            }
            Self::Timeout { proxy_env_set, .. } => {
                with_proxy_note(NETWORK_HINT, *proxy_env_set)
            }
            Self::Unreachable {
                cause,
                proxy_env_set,
                ca_set,
                ..
            } => {
                let base = if !cause.contains("UnknownIssuer") {
                    NETWORK_HINT
                } else if *ca_set {
                    "The certificate authority in the kubeconfig does not match this server, or a proxy re-signs TLS (run net.tls_intercept)."
                } else {
                    "The kubeconfig names no certificate authority, so rdy trusts only its bundled public roots, not this machine's store (kubectl uses it). Pass a copy with certificate-authority set with --kubeconfig."
                };
                with_proxy_note(base, *proxy_env_set)
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

const NETWORK_HINT: &str = "Check the server address in your kubeconfig and that you are on the right network or VPN, then run rdy again.";

fn with_proxy_note(base: &str, proxy_env_set: bool) -> String {
    if proxy_env_set {
        format!("{base} {PROXY_ENV_NOTE}")
    } else {
        base.to_owned()
    }
}

/// Adds the distribution kubeconfig paths on Linux, where those distributions run.
fn with_distro_files(base: &str) -> String {
    if cfg!(target_os = "linux") {
        format!("{base} {DISTRO_FILES}")
    } else {
        base.to_owned()
    }
}

/// Where the common distributions keep a kubeconfig that only root can read.
const DISTRO_FILES: &str = "k3s keeps one at /etc/rancher/k3s/k3s.yaml, RKE2 at /etc/rancher/rke2/rke2.yaml and kubeadm at /etc/kubernetes/admin.conf. They are root-only: copy one to ~/.kube/config and chmod 600 it.";

/// Said when the environment names a proxy that kubectl would use and rdy does not.
const PROXY_ENV_NOTE: &str = "HTTPS_PROXY is set; rdy does not use it for the cluster yet.";

/// The hint for a legacy `auth-provider`, by provider. The name is already escaped.
fn auth_provider_hint(name: &str) -> String {
    match name {
        "gcp" => "Install gke-gcloud-auth-plugin and run gcloud container clusters get-credentials again. It writes an exec credential plugin entry that rdy can run.".to_owned(),
        "azure" => "Run kubelogin convert-kubeconfig -l azurecli to switch the user to an exec credential plugin that rdy can run.".to_owned(),
        "oidc" => "rdy does not run the oidc auth-provider yet. Switch the user to an exec credential plugin for your identity provider, or tell the vendor.".to_owned(),
        _ => "rdy does not run auth-provider entries. Switch the user to an exec credential plugin, or tell the vendor.".to_owned(),
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
            what: "a proxy URL is not valid",
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
    proxy_env_set: bool,
    ca_set: bool,
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
        kube::Error::ProxyProtocolDisabled { proxy_url, .. }
        | kube::Error::ProxyProtocolUnsupported { proxy_url, .. } => KubeError::ProxyUnsupported {
            proxy: proxy_display(&proxy_url.to_string()),
        },
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
            network_error(error, server, proxy_env_set, ca_set)
        }
        kube::Error::SerdeError(_) | kube::Error::FromUtf8(_) => KubeError::BadAnswer {
            server: server.to_owned(),
        },
        _ => KubeError::Internal {
            what: "the request failed",
        },
    }
}

fn network_error(
    error: &kube::Error,
    server: &str,
    proxy_env_set: bool,
    ca_set: bool,
) -> KubeError {
    // Everything read from the chain below is only looked at. None of it is copied into the result, so a
    // plugin cannot get text into the error through a network failure.
    let mut timed_out = false;
    let mut kind = None;
    let mut seen = error.to_string().to_ascii_lowercase();
    let mut current: Option<&(dyn std::error::Error + 'static)> = error.source();
    while let Some(err) = current {
        if let Some(io_error) = err.downcast_ref::<io::Error>() {
            if io_error.kind() == io::ErrorKind::TimedOut {
                timed_out = true;
            }
            if kind.is_none() && io_error.kind() != io::ErrorKind::Other {
                kind = Some(io_error.kind());
            }
        }
        seen.push(' ');
        seen.push_str(&err.to_string().to_ascii_lowercase());
        current = err.source();
    }
    if timed_out {
        return KubeError::Timeout {
            server: server.to_owned(),
            proxy_env_set,
        };
    }
    KubeError::Unreachable {
        server: server.to_owned(),
        cause: cause_words(&seen, kind),
        proxy_env_set,
        ca_set,
    }
}

/// A fixed phrase for a network failure, from what the error chain says (lowercase) and its io kind.
pub(crate) fn cause_words(seen: &str, kind: Option<io::ErrorKind>) -> &'static str {
    let has = |word: &str| seen.contains(word);
    // rustls 0.23 words these in its Display text ("certificate not valid for name ..."); older text
    // and the Debug names are matched too.
    if has("unknownissuer") {
        "the server certificate is signed by an authority that is not trusted (UnknownIssuer)"
    } else if has("notvalidforname") || has("not valid for name") {
        "the server certificate is not valid for this address (NotValidForName)"
    } else if has("notvalidyet") || has("not valid yet") {
        "the server certificate is not valid yet (NotValidYet)"
    } else if has("expired") {
        "the server certificate has expired (Expired)"
    } else if has("revoked") {
        "the server certificate was revoked (Revoked)"
    } else if has("invalid peer certificate") || has("badsignature") {
        "the server certificate was rejected"
    } else if has("handshake") || has("alert") || has("corrupt message") || has("tls") {
        "the TLS handshake failed"
    } else if has("dns") || has("lookup") || has("resolve") {
        "the server name did not resolve"
    } else {
        match kind {
            Some(io::ErrorKind::ConnectionRefused) => "the connection was refused",
            Some(
                io::ErrorKind::ConnectionReset
                | io::ErrorKind::ConnectionAborted
                | io::ErrorKind::BrokenPipe
                | io::ErrorKind::UnexpectedEof,
            ) => "the connection was closed",
            Some(io::ErrorKind::HostUnreachable) => "there is no route to the host",
            Some(io::ErrorKind::NetworkUnreachable) => "the network is unreachable",
            Some(io::ErrorKind::PermissionDenied) => "the connection was not permitted",
            _ => "the connection failed",
        }
    }
}

/// A proxy URL as scheme, host and port: no user info, path or query. Escaped.
pub(crate) fn proxy_display(raw: &str) -> String {
    let Some((scheme, rest)) = raw.split_once("://") else {
        return "(not a valid URL)".to_owned();
    };
    let authority = rest.split(['/', '?', '#']).next().unwrap_or("");
    let host_port = authority.rsplit('@').next().unwrap_or("");
    escape_capped(&format!("{scheme}://{host_port}"), CAUSE_CAP)
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
