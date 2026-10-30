//! The kube client layer: find the kubeconfig, build the client, say which cluster it is about to touch.
//!
//! This is the only module of the crate that may name a kube client or config type (02 Appendix A, the
//! lint wall). It is also where the kubeconfig is read. The probe facade denies reads under `.kube`
//! for every check and for the run itself (ADR 0014), so the kubeconfig does not go through a
//! `Probe`. kube reads it here, once, from a path the operator chose: `--kubeconfig`, `KUBECONFIG` or
//! the default `~/.kube/config` (ADR 0031). The probe hook that wraps this module (M1-107) writes the
//! `read` entries of [`Loaded::files`] and the `exec` entry of the credential plugin to the action log.
//!
//! The steps are separate on purpose:
//!
//! 1. [`load`] reads files and builds a [`Loaded`]. It opens no socket and runs no plugin. It runs on the
//!    blocking pool, so the scheduler's timer around the probe can bound it (M1-107).
//! 2. [`Loaded::connect`] calls the `announce` closure with the [`ClusterLine`] (context, server and
//!    user), and only then builds the client (which may run a credential plugin) and sends the first
//!    request, `GET /version`. The order is in one function, so no caller can send before announcing.
//! 3. [`Connected`] holds the client and the server version.
//!
//! What this module does not do, on purpose:
//!
//! - It never calls `Config::infer` or `Client::try_default`. `infer` applies `KUBE_RS_DEBUG_*`
//!   variables that can swap the server URL or impersonate a user, and rdy must not honour them.
//! - It never reads a credential plugin's output into an error, a log line or a report ([`KubeError`]).
//! - It refuses `auth-provider` entries (legacy `gcp`, `oidc` and `azure` providers can run a command
//!   that the report would not name).
//! - It never lets kube read `HTTPS_PROXY`. kube would read it inside `Config::try_from` and fail on a
//!   malformed value, so a fixed placeholder takes the `proxy_url` slot of the chosen cluster before the
//!   build and the slot is cleared after it. rdy then picks the proxy itself, the way `kubectl` does
//!   (the cluster's `proxy-url`, else `HTTPS_PROXY` unless `NO_PROXY` covers the API host), and reports
//!   which rule applied ([`ProxyUse`], ADR 0037). Only an `http://` proxy is used.
//! - It never lets a credential plugin talk to the terminal unless stdin and stderr are both terminals
//!   (client-go's `IfAvailable` rule). Without a terminal the plugin runs with `interactiveMode: Never`,
//!   so its stderr is captured, not inherited (ADR 0031 decision 8).
//! - It strips the rdy variables (`RDY_*`) from a plugin's environment. Cloud credentials stay, because
//!   the plugins need them.
//! - It reads no namespace: `default_namespace` of the kubeconfig and of the service account is not used.
//!   A check that needs a namespace gets it from its spec parameter.
//! - It sends nothing that the read-only guard (M1-103, [`guard`]) refuses. The raw kube client is private
//!   to this module. `connect` sends `GET /version` through the guard, and [`Connected::read_only`] gives
//!   a check a [`ReadOnlyClient`] bound to its own probe, so every request writes one `kube` entry to the
//!   action log under that check's id.
//!
//! Timeouts: the connect, read and write timeouts of the client are the check timeout, at most
//! [`MAX_TIMEOUT`]. kube's retries are off. A credential plugin that waits for a login is not bounded
//! here: the scheduler's timer around the probe is (M1-107), and the build runs on the blocking pool so
//! it never holds a worker.

#![allow(clippy::disallowed_types, clippy::disallowed_methods)]

use std::ffi::OsString;
use std::fmt;
use std::fs;
use std::io::IsTerminal;
use std::path::{Path, PathBuf};
use std::time::Duration;

use kube::Config;
use kube::client::ClientBuilder;
use kube::config::{AuthInfo, Cluster, ExecInteractiveMode, Kubeconfig};
use rdy_engine::check::{CheckError, MAX_TIMEOUT};
use rdy_engine::probe::Probe;
use secrecy::ExposeSecret;

mod b64;
mod credential;
mod error;
pub mod guard;
#[cfg(test)]
pub(crate) mod mock;
mod proxy;
mod text;

#[cfg(test)]
mod facts_tests;
#[cfg(test)]
pub(crate) mod testkit;
#[cfg(test)]
mod tests;

pub use credential::Credential;
pub use error::KubeError;
pub(crate) use error::from_kube_error;
use error::{from_kubeconfig_error, io_reason, proxy_display};
pub use guard::{GuardError, ReadOnlyClient, guarded_service};
pub use proxy::{ProxyRule, ProxyUse};
use text::escape;

/// The largest kubeconfig rdy reads. A real one is a few kilobytes.
const MAX_KUBECONFIG_BYTES: u64 = 8 * 1024 * 1024;

/// The largest CA bundle, certificate, key or token file rdy lets kube read.
const MAX_FILE_BYTES: u64 = 1024 * 1024;

/// A valid proxy URL that is never used. kube reads `HTTPS_PROXY` only when the cluster has no
/// `proxy_url`, so this takes the slot, and the slot is cleared once kube has built the config.
const PROXY_PLACEHOLDER: &str = "http://proxy.invalid:3128";

/// Variables that are never handed to a credential plugin. The `RDY_*` variables that are set in the
/// process are added at load time (an ExternalId variable, for example). Cloud credentials are not
/// dropped: `aws eks get-token` and its kind need them.
const PLUGIN_DROP_ENV: [&str; 2] = ["RDY_TOKEN", "RDY_KEY_PASSWORD"];

/// The service account files of a pod, in the order kube reads them.
const SERVICE_ACCOUNT_FILES: [(&str, &str); 3] = [
    (
        "/var/run/secrets/kubernetes.io/serviceaccount/token",
        "the service account token is missing or not a regular file under 1 MiB",
    ),
    (
        "/var/run/secrets/kubernetes.io/serviceaccount/ca.crt",
        "the service account CA bundle is missing or not a regular file under 1 MiB",
    ),
    (
        "/var/run/secrets/kubernetes.io/serviceaccount/namespace",
        "the service account namespace file is missing or not a regular file under 1 MiB",
    ),
];

/// The most context names listed in a hint.
const MAX_LISTED_CONTEXTS: usize = 10;

/// What the caller chose: the flags and the check timeout.
#[derive(Debug, Clone)]
#[non_exhaustive]
pub struct KubeOptions {
    /// `--kubeconfig`. When set, this file is the only source: a missing file is an error.
    pub kubeconfig: Option<PathBuf>,
    /// `--kube-context`.
    pub context: Option<String>,
    /// The check timeout. It becomes the connect, read and write timeout, capped at [`MAX_TIMEOUT`].
    pub timeout: Duration,
}

impl KubeOptions {
    /// Options with no flags and this timeout.
    #[must_use]
    pub fn new(timeout: Duration) -> Self {
        Self {
            kubeconfig: None,
            context: None,
            timeout,
        }
    }

    /// Sets `--kubeconfig`.
    #[must_use]
    pub fn kubeconfig(mut self, path: impl Into<PathBuf>) -> Self {
        self.kubeconfig = Some(path.into());
        self
    }

    /// Sets `--kube-context`.
    #[must_use]
    pub fn context(mut self, name: impl Into<String>) -> Self {
        self.context = Some(name.into());
        self
    }
}

/// True for a `RDY_*` variable name. Windows variable names are case-insensitive, so `rdy_token` counts
/// there. `case_insensitive` is a parameter so every platform tests both rules. It compares bytes, so a
/// name with a multi-byte character near the start cannot panic.
fn is_rdy_var(name: &str, case_insensitive: bool) -> bool {
    let prefix = name.as_bytes().get(..4);
    if case_insensitive {
        prefix.is_some_and(|p| p.eq_ignore_ascii_case(b"RDY_"))
    } else {
        prefix == Some(b"RDY_".as_slice())
    }
}

/// The parts of the process environment this module looks at, gathered once.
///
/// Tests build one by hand, so they never change the process environment. `Debug` hides the proxy URL,
/// which can hold a password.
#[derive(Clone, Default)]
#[non_exhaustive]
pub struct Env {
    /// The value of `KUBECONFIG`, a list of paths separated by the OS list separator.
    pub kubeconfig: Option<OsString>,
    /// The home directory, for `~/.kube/config`.
    pub home: Option<PathBuf>,
    /// Whether to try the in-cluster config (a service account in a pod) when no kubeconfig is found.
    /// [`Env::from_process`] sets it only when `KUBERNETES_SERVICE_HOST` is set.
    pub in_cluster: bool,
    /// Whether stdin is a terminal. A credential plugin may be interactive only when this and
    /// `stderr_is_terminal` are both true.
    pub stdin_is_terminal: bool,
    /// Whether stderr is a terminal.
    pub stderr_is_terminal: bool,
    /// The value of `HTTPS_PROXY`, else `https_proxy`, when it is not empty. It is the proxy for an
    /// `https` API server unless `no_proxy` covers the host (ADR 0037). It can hold a password: never
    /// print it.
    pub https_proxy: Option<String>,
    /// The name of the variable `https_proxy` was read from, for reports.
    pub https_proxy_name: &'static str,
    /// The value of `NO_PROXY`, else `no_proxy`, when it is not empty.
    pub no_proxy: Option<String>,
    /// The names of the `RDY_*` variables set in the process. They are removed from a plugin's
    /// environment.
    pub rdy_vars: Vec<String>,
    /// The time at load, in Unix seconds. The time left on a token or certificate is counted from it.
    pub now_unix: i64,
}

impl fmt::Debug for Env {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Env")
            .field("kubeconfig", &self.kubeconfig)
            .field("home", &self.home)
            .field("in_cluster", &self.in_cluster)
            .field("stdin_is_terminal", &self.stdin_is_terminal)
            .field("stderr_is_terminal", &self.stderr_is_terminal)
            .field("https_proxy", &self.https_proxy.as_ref().map(|_| "(set)"))
            .field("no_proxy", &self.no_proxy)
            .field("rdy_vars", &self.rdy_vars)
            .field("now_unix", &self.now_unix)
            .finish()
    }
}

impl Env {
    /// Reads `KUBECONFIG`, the home directory, the terminal state, the proxy variables and the `RDY_*`
    /// names from the process. The in-cluster config is allowed when `KUBERNETES_SERVICE_HOST` is set.
    #[must_use]
    pub fn from_process() -> Self {
        let set = |name: &str| std::env::var_os(name).is_some_and(|value| !value.is_empty());
        let text = |name: &str| std::env::var(name).ok().filter(|value| !value.is_empty());
        // Go reads the upper case name first, and so does kubectl. On Windows the two are one variable.
        let (https_proxy, https_proxy_name) = match (text("HTTPS_PROXY"), text("https_proxy")) {
            (Some(value), _) => (Some(value), "HTTPS_PROXY"),
            (None, Some(value)) => (Some(value), "https_proxy"),
            (None, None) => (None, ""),
        };
        Self {
            kubeconfig: std::env::var_os("KUBECONFIG"),
            home: std::env::home_dir(),
            in_cluster: set("KUBERNETES_SERVICE_HOST"),
            stdin_is_terminal: std::io::stdin().is_terminal(),
            stderr_is_terminal: std::io::stderr().is_terminal(),
            https_proxy,
            https_proxy_name,
            no_proxy: text("NO_PROXY").or_else(|| text("no_proxy")),
            rdy_vars: std::env::vars_os()
                .filter_map(|(name, _)| name.into_string().ok())
                .filter(|name| is_rdy_var(name, cfg!(windows)))
                .collect(),
            now_unix: unix_now(),
        }
    }

    /// An environment with nothing set, and no in-cluster fallback.
    #[must_use]
    pub fn empty() -> Self {
        Self::default()
    }

    /// Sets `KUBECONFIG`.
    #[must_use]
    pub fn with_kubeconfig_var(mut self, value: impl Into<OsString>) -> Self {
        self.kubeconfig = Some(value.into());
        self
    }

    /// Sets the home directory.
    #[must_use]
    pub fn with_home(mut self, home: impl Into<PathBuf>) -> Self {
        self.home = Some(home.into());
        self
    }

    /// Allows the in-cluster fallback.
    #[must_use]
    pub fn with_in_cluster(mut self) -> Self {
        self.in_cluster = true;
        self
    }

    /// Says that stdin and stderr are both terminals, so an interactive plugin may prompt.
    #[must_use]
    pub fn with_terminal(mut self) -> Self {
        self.stdin_is_terminal = true;
        self.stderr_is_terminal = true;
        self
    }

    /// Sets `HTTPS_PROXY`.
    #[must_use]
    pub fn with_https_proxy(mut self, value: impl Into<String>) -> Self {
        self.https_proxy = Some(value.into());
        self.https_proxy_name = "HTTPS_PROXY";
        self
    }

    /// Sets `NO_PROXY`.
    #[must_use]
    pub fn with_no_proxy(mut self, value: impl Into<String>) -> Self {
        self.no_proxy = Some(value.into());
        self
    }

    /// Pins the time at load, in Unix seconds.
    #[must_use]
    pub fn with_now(mut self, now_unix: i64) -> Self {
        self.now_unix = now_unix;
        self
    }

    /// Adds the name of a `RDY_*` variable that a plugin must not see.
    #[must_use]
    pub fn with_rdy_var(mut self, name: impl Into<String>) -> Self {
        self.rdy_vars.push(name.into());
        self
    }
}

/// Where the config came from. The report says which.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum Source {
    /// The file given with `--kubeconfig`.
    Flag(PathBuf),
    /// The files listed in `KUBECONFIG`.
    Env(Vec<PathBuf>),
    /// `~/.kube/config`.
    Default(PathBuf),
    /// The service account of the pod rdy runs in.
    InCluster,
}

impl Source {
    /// A short label for the report: `--kubeconfig`, `KUBECONFIG`, `~/.kube/config` or `in-cluster`.
    #[must_use]
    pub fn label(&self) -> &'static str {
        match self {
            Self::Flag(_) => "--kubeconfig",
            Self::Env(_) => "KUBECONFIG",
            Self::Default(_) => "~/.kube/config",
            Self::InCluster => "in-cluster",
        }
    }
}

/// Which cluster rdy is about to touch (07 section 2.1, the `cluster` header line).
///
/// Every text is escaped for a terminal, and the server has no user info, query or fragment.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ClusterLine {
    context: String,
    server: String,
    user: Option<String>,
    plugin: Option<String>,
    tls_verification_off: bool,
}

impl ClusterLine {
    /// The context name, or `in-cluster`.
    #[must_use]
    pub fn context(&self) -> &str {
        &self.context
    }

    /// The server URL without user info. A path prefix (Rancher) is kept.
    #[must_use]
    pub fn server(&self) -> &str {
        &self.server
    }

    /// The user name from the kubeconfig. This is the entry name, not the identity the API server
    /// sees: that comes from a `SelfSubjectReview` after the first request (M1-103, M1-109). `None`
    /// for the in-cluster config.
    #[must_use]
    pub fn user(&self) -> Option<&str> {
        self.user.as_deref()
    }

    /// The file name of the exec credential plugin, never its arguments.
    #[must_use]
    pub fn plugin(&self) -> Option<&str> {
        self.plugin.as_deref()
    }

    /// True when the kubeconfig sets `insecure-skip-tls-verify: true`.
    #[must_use]
    pub fn tls_verification_off(&self) -> bool {
        self.tls_verification_off
    }
}

impl fmt::Display for ClusterLine {
    /// `<context>, <server>, user <name>, credential plugin: <name>, TLS verification is OFF`. The
    /// last three parts appear only when they apply.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}, {}", self.context, self.server)?;
        if let Some(user) = &self.user {
            write!(f, ", user {user}")?;
        }
        if let Some(plugin) = &self.plugin {
            write!(f, ", credential plugin: {plugin}")?;
        }
        if self.tls_verification_off {
            f.write_str(", TLS verification is OFF")?;
        }
        Ok(())
    }
}

/// The credential plugin of the chosen user, as the action log needs it (02, "The action log").
///
/// The texts are escaped for a terminal. The arguments can hold a secret, so they must go through the
/// redactor before they are written anywhere. `Debug` shows the command and the number of arguments only.
#[derive(Clone, PartialEq, Eq)]
pub struct PluginExec {
    command: String,
    args: Vec<String>,
}

impl PluginExec {
    /// The command as the kubeconfig names it. It is an absolute path when the kubeconfig gave a path.
    /// A bare name is looked up on `PATH` by the operating system when the plugin starts.
    #[must_use]
    pub fn command(&self) -> &str {
        &self.command
    }

    /// The arguments. Redact them before logging.
    #[must_use]
    pub fn args(&self) -> &[String] {
        &self.args
    }
}

impl fmt::Debug for PluginExec {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("PluginExec")
            .field("command", &self.command)
            .field("args", &format_args!("[{} hidden]", self.args.len()))
            .finish()
    }
}

/// What the config says about the connection, known before any request: `k8s.access` reports it, and
/// still can when the connection then fails.
///
/// It holds no secret. The credentials are kinds and times (see [`Credential`]), the proxy is shown as
/// scheme, host and port, and the cluster line is escaped.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConnectionFacts {
    source: Source,
    line: ClusterLine,
    credentials: Vec<Credential>,
    proxy: ProxyUse,
    ca_set: bool,
}

impl ConnectionFacts {
    /// Where the config came from.
    #[must_use]
    pub fn source(&self) -> &Source {
        &self.source
    }

    /// The cluster rdy is about to touch.
    #[must_use]
    pub fn line(&self) -> &ClusterLine {
        &self.line
    }

    /// What the kubeconfig user sends: tokens, a client certificate, a password, a plugin or the pod's
    /// service account. Empty means the kubeconfig carries no credentials, so the server sees
    /// `system:anonymous`.
    #[must_use]
    pub fn credentials(&self) -> &[Credential] {
        &self.credentials
    }

    /// The route to the API server and the rule that chose it.
    #[must_use]
    pub fn proxy(&self) -> &ProxyUse {
        &self.proxy
    }

    /// Whether the kubeconfig (or the pod) names a certificate authority. Without one rdy trusts only
    /// its bundled public roots.
    #[must_use]
    pub fn ca_set(&self) -> bool {
        self.ca_set
    }
}

/// A config that is read and checked, with no socket opened and no plugin run.
pub struct Loaded {
    facts: ConnectionFacts,
    files: Vec<PathBuf>,
    config: Config,
    plugin_exec: Option<PluginExec>,
    secrets: Vec<String>,
}

impl fmt::Debug for Loaded {
    // The kube `Config` holds tokens and plugin settings, so it is never printed.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Loaded")
            .field("source", &self.facts.source)
            .field("line", &self.facts.line)
            .finish_non_exhaustive()
    }
}

impl Loaded {
    /// Where the config came from.
    #[must_use]
    pub fn source(&self) -> &Source {
        &self.facts.source
    }

    /// What the config says about the connection. A copy: keep it, because `connect` takes `self`, and
    /// `k8s.access` reports it even when `connect` fails.
    #[must_use]
    pub fn facts(&self) -> ConnectionFacts {
        self.facts.clone()
    }

    /// The route to the API server and the rule that chose it (ADR 0037).
    #[must_use]
    pub fn proxy(&self) -> &ProxyUse {
        &self.facts.proxy
    }

    /// Every file that was read to build this config, in order: the kubeconfig files, then the
    /// certificate authority, client certificate, client key and token file the chosen cluster and user
    /// name (only the ones kube reads: inline data wins over a path). For the in-cluster config it is the
    /// service account token, CA bundle and namespace file. Each one was checked to be a regular file
    /// within its size cap. The probe hook logs each as a `read` entry with no check id.
    #[must_use]
    pub fn files(&self) -> &[PathBuf] {
        &self.files
    }

    /// The cluster rdy is about to touch.
    #[must_use]
    pub fn line(&self) -> &ClusterLine {
        &self.facts.line
    }

    /// The credential plugin kube will run, for the `exec` entry of the action log. `None` when the
    /// user has no exec plugin.
    #[must_use]
    pub fn plugin_exec(&self) -> Option<&PluginExec> {
        self.plugin_exec.as_ref()
    }

    /// The secret values of this config: the inline token, password and client key, and the contents of
    /// a token file or client key file. The caller adds them to the run-scoped known-secret set
    /// (02, "The action log"; ADR 0015 decision 3) before anything is printed or written. A token a
    /// credential plugin hands out is not here: it exists only after `connect` runs the plugin.
    ///
    /// Never print or log the result.
    #[must_use]
    pub fn known_secrets(&self) -> Vec<String> {
        self.secrets.clone()
    }

    /// Announces the cluster, builds the client and asks the server for its version.
    ///
    /// `announce` runs first, before any plugin starts and before any socket opens. The caller prints
    /// the [`ClusterLine`] from it. Then the client is built on the blocking pool (the build can run a
    /// credential plugin, which blocks), and `GET /version` is the first request. It goes through the
    /// read-only guard and writes a `kube` entry to the log of `probe`, which is the run-level probe
    /// (`check: null`). The need `kube_context` is met when this returns `Ok` (ADR 0010 decision 5).
    /// Needs a running tokio runtime.
    ///
    /// # Errors
    ///
    /// A [`KubeError`]. It never holds plugin output or credentials.
    pub async fn connect(
        self,
        probe: &Probe,
        announce: impl FnOnce(&ClusterLine),
    ) -> Result<Connected, KubeError> {
        announce(&self.facts.line);
        let Self {
            facts,
            files,
            config,
            ..
        } = self;
        let server = facts.line.server.clone();
        let plugin = facts.line.plugin.clone();
        let (proxied, ca_set) = (facts.proxy.is_proxied(), facts.ca_set);
        let built =
            rdy_engine::blocking::blocking(move || Ok::<_, CheckError>(build_client(config))).await;
        let client = match built {
            Ok(Ok(client)) => client,
            Ok(Err(error)) => {
                return Err(from_kube_error(
                    &error,
                    &server,
                    plugin.as_deref(),
                    proxied,
                    ca_set,
                ));
            }
            Err(_) => return Err(KubeError::Cancelled),
        };
        // The clock around the first request. The plugin ran in the build above, so its time is not in
        // this number, which is the round trip to `/version` and nothing else.
        let started = std::time::Instant::now();
        let info = ReadOnlyClient::new(&client, probe)
            .version()
            .await
            .map_err(|error| {
                from_kube_error(&error, &server, plugin.as_deref(), proxied, ca_set)
            })?;
        let latency = started.elapsed();
        Ok(Connected {
            facts,
            files,
            version: ServerVersion::from_info(info),
            latency,
            client,
        })
    }
}

/// A client that has answered `GET /version`.
pub struct Connected {
    facts: ConnectionFacts,
    files: Vec<PathBuf>,
    version: ServerVersion,
    latency: Duration,
    // The unguarded client. It is private, and the only way to send with it is through the guard
    // (`Connected::read_only`), which wraps it in a service that refuses before it sends.
    client: kube::Client,
}

impl fmt::Debug for Connected {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Connected")
            .field("source", &self.facts.source)
            .field("line", &self.facts.line)
            .field("version", &self.version)
            .finish_non_exhaustive()
    }
}

impl Connected {
    /// Where the config came from.
    #[must_use]
    pub fn source(&self) -> &Source {
        &self.facts.source
    }

    /// What the config said about the connection.
    #[must_use]
    pub fn facts(&self) -> &ConnectionFacts {
        &self.facts
    }

    /// The kubeconfig files that were read.
    #[must_use]
    pub fn files(&self) -> &[PathBuf] {
        &self.files
    }

    /// The cluster that answered.
    #[must_use]
    pub fn line(&self) -> &ClusterLine {
        &self.facts.line
    }

    /// What `GET /version` said.
    #[must_use]
    pub fn server_version(&self) -> &ServerVersion {
        &self.version
    }

    /// How long `GET /version` took from send to a parsed answer. A credential plugin's time is not in
    /// it: the plugin runs when the client is built.
    #[must_use]
    pub fn version_latency(&self) -> Duration {
        self.latency
    }

    /// The read-only client for one check. `probe` is the check's own probe
    /// (`CheckContext::probe`): every request the client sends writes one `kube` entry to the action
    /// log under that check's id, and a request made after the check ended is refused. The guard
    /// refuses everything that is not an allowed read before it is sent (INV-14).
    ///
    /// Cheap: it shares the connection and the credentials with this value and starts one worker task,
    /// so call it from a tokio runtime.
    #[must_use]
    pub fn read_only(&self, probe: &Probe) -> ReadOnlyClient {
        ReadOnlyClient::new(&self.client, probe)
    }
}

/// The answer of `GET /version`. The texts come from the server and are not escaped: escape them
/// before they reach a terminal. `k8s.version` (M1-106) parses `git_version`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ServerVersion {
    /// For example `v1.29.4-eks-abc123`.
    pub git_version: String,
    /// The major version as text, for example `1`.
    pub major: String,
    /// The minor version as text. Some distributions add a `+`, for example `29+`.
    pub minor: String,
    /// For example `linux/amd64`.
    pub platform: String,
}

impl ServerVersion {
    /// The four texts of a `GET /version` answer.
    fn from_info(info: k8s_openapi::apimachinery::pkg::version::Info) -> Self {
        Self {
            git_version: info.git_version,
            major: info.major,
            minor: info.minor,
            platform: info.platform,
        }
    }
}

/// Finds and reads the config. Reads files, opens no socket, runs no plugin.
///
/// The file reads run on the blocking pool, so a caller's timer can bound this call (a slow disk or a
/// network mount cannot hold a worker).
///
/// Order (03 section 4): `--kubeconfig`, then `KUBECONFIG`, then `~/.kube/config`, then the in-cluster
/// config. A `--kubeconfig` file that is missing is an error and does not fall through. Files listed in
/// `KUBECONFIG` that do not exist are skipped, as `kubectl` does, and the rest are merged with the first
/// file winning. Every file kube will read (the kubeconfigs, and the CA, certificate, key and token files
/// they name) must be a regular file within its size cap.
///
/// # Errors
///
/// [`KubeError::NoKubeconfig`] when no source exists, and other [`KubeError`] variants when a source
/// exists and cannot be used. The text never quotes the kubeconfig.
pub async fn load(options: &KubeOptions, env: &Env) -> Result<Loaded, KubeError> {
    let (options, env) = (options.clone(), env.clone());
    match rdy_engine::blocking::blocking(move || Ok::<_, CheckError>(load_sync(&options, &env)))
        .await
    {
        Ok(result) => result,
        Err(_) => Err(KubeError::Cancelled),
    }
}

/// [`load`] on the calling thread.
fn load_sync(options: &KubeOptions, env: &Env) -> Result<Loaded, KubeError> {
    match read_files(options, env)? {
        Some((source, files, kubeconfig)) => {
            from_kubeconfig(options, env, source, files, kubeconfig)
        }
        None => in_cluster(options, env),
    }
}

/// A kubeconfig and where it came from.
type Found = (Source, Vec<PathBuf>, Kubeconfig);

/// Checks that `path` is a regular file of at most `max` bytes. A FIFO or a device would block the read
/// for ever, and a huge file is not a kubeconfig or a certificate. `too_big` is the phrase for the size.
fn check_regular(
    path: &Path,
    max: u64,
    too_big: &'static str,
    metadata: &fs::Metadata,
) -> Result<(), KubeError> {
    if !metadata.is_file() {
        return Err(KubeError::KubeconfigUnreadable {
            path: escape(&path.display().to_string()),
            reason: "it is not a regular file",
        });
    }
    if metadata.len() > max {
        return Err(KubeError::KubeconfigUnreadable {
            path: escape(&path.display().to_string()),
            reason: too_big,
        });
    }
    Ok(())
}

/// [`check_regular`] for a file that kube reads on its own (a CA, a certificate, a key, a token).
fn check_referenced(path: &Path) -> Result<(), KubeError> {
    let metadata = fs::metadata(path).map_err(|error| KubeError::KubeconfigUnreadable {
        path: escape(&path.display().to_string()),
        reason: io_reason(error.kind()),
    })?;
    check_regular(path, MAX_FILE_BYTES, "it is larger than 1 MiB", &metadata)
}

fn read_files(options: &KubeOptions, env: &Env) -> Result<Option<Found>, KubeError> {
    let (source, paths, required) = if let Some(path) = &options.kubeconfig {
        (Source::Flag(path.clone()), vec![path.clone()], true)
    } else if let Some(paths) = env_paths(env) {
        (Source::Env(paths.clone()), paths, false)
    } else if let Some(home) = &env.home {
        let path = home.join(".kube").join("config");
        (Source::Default(path.clone()), vec![path], false)
    } else {
        return Ok(None);
    };

    let mut files = Vec::new();
    let mut merged: Option<Kubeconfig> = None;
    for path in paths {
        let shown = escape(&path.display().to_string());
        let metadata = match fs::metadata(&path) {
            Ok(metadata) => metadata,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound && !required => continue,
            Err(error) => {
                return Err(KubeError::KubeconfigUnreadable {
                    path: shown,
                    reason: io_reason(error.kind()),
                });
            }
        };
        check_regular(
            &path,
            MAX_KUBECONFIG_BYTES,
            "it is larger than 8 MiB",
            &metadata,
        )?;
        let one =
            Kubeconfig::read_from(&path).map_err(|error| from_kubeconfig_error(&error, &shown))?;
        merged = Some(match merged {
            None => one,
            Some(previous) => previous
                .merge(one)
                .map_err(|error| from_kubeconfig_error(&error, &shown))?,
        });
        files.push(path);
    }
    Ok(merged.map(|kubeconfig| (source, files, kubeconfig)))
}

/// The non-empty paths of `KUBECONFIG`, or `None` when it is unset or has none.
fn env_paths(env: &Env) -> Option<Vec<PathBuf>> {
    let value = env.kubeconfig.as_ref()?;
    let paths: Vec<PathBuf> = std::env::split_paths(value)
        .filter(|path| !path.as_os_str().is_empty())
        .collect();
    (!paths.is_empty()).then_some(paths)
}

/// The files kube will read for this cluster and user, as it reads them: inline data wins over a path,
/// and an inline token or a username with a password wins over a token file. Paths are absolute (kube
/// resolves them against the kubeconfig's directory when it reads the kubeconfig).
fn referenced_files(cluster: &Cluster, auth: Option<&AuthInfo>) -> Vec<PathBuf> {
    let path = |value: &Option<String>| {
        value
            .as_deref()
            .filter(|path| !path.is_empty())
            .map(PathBuf::from)
    };
    let mut files = Vec::new();
    if cluster.certificate_authority_data.is_none() {
        files.extend(path(&cluster.certificate_authority));
    }
    if let Some(auth) = auth {
        if auth.client_certificate_data.is_none() {
            files.extend(path(&auth.client_certificate));
        }
        if auth.client_key_data.is_none() {
            files.extend(path(&auth.client_key));
        }
        let basic = auth.username.is_some() && auth.password.is_some();
        if auth.token.is_none() && !basic {
            files.extend(path(&auth.token_file));
        }
    }
    files
}

fn from_kubeconfig(
    options: &KubeOptions,
    env: &Env,
    source: Source,
    mut files: Vec<PathBuf>,
    mut kubeconfig: Kubeconfig,
) -> Result<Loaded, KubeError> {
    let available: Vec<String> = kubeconfig
        .contexts
        .iter()
        .take(MAX_LISTED_CONTEXTS)
        .map(|named| escape(&named.name))
        .collect();

    let context_name = options
        .context
        .clone()
        .or_else(|| {
            kubeconfig
                .current_context
                .clone()
                .filter(|current| !current.is_empty())
        })
        .ok_or_else(|| KubeError::NoCurrentContext {
            available: available.clone(),
        })?;
    let context = kubeconfig
        .contexts
        .iter()
        .find(|named| named.name == context_name)
        .and_then(|named| named.context.clone())
        .ok_or_else(|| KubeError::ContextNotFound {
            name: escape(&context_name),
            available: available.clone(),
        })?;

    let cluster = kubeconfig
        .clusters
        .iter()
        .find(|named| named.name == context.cluster)
        .and_then(|named| named.cluster.as_ref())
        .ok_or(KubeError::IncompleteKubeconfig {
            what: "the context names a cluster that the kubeconfig does not define",
        })?;
    // The cluster's own proxy. It is judged after the config is built, with the environment (ADR 0037).
    let kubeconfig_proxy = cluster.proxy_url.clone().filter(|proxy| !proxy.is_empty());

    let user_name = context.user.clone().filter(|user| !user.is_empty());
    let auth = user_name
        .as_deref()
        .and_then(|user| {
            kubeconfig
                .auth_infos
                .iter()
                .find(|named| named.name == user)
        })
        .and_then(|named| named.auth_info.as_ref());
    if let Some(provider) = auth.and_then(|auth| auth.auth_provider.as_ref()) {
        return Err(KubeError::AuthProviderUnsupported {
            name: escape(&provider.name),
        });
    }

    // Everything kube reads on its own is checked first: a FIFO would hang the build and a device such
    // as /dev/zero would fill memory. The files are listed for the action log.
    let mut secrets = inline_secrets(auth);
    let mut token_text = auth
        .and_then(|auth| auth.token.as_ref())
        .map(|t| t.expose_secret().to_owned());
    let mut certificate_text = auth
        .and_then(|auth| auth.client_certificate_data.as_deref())
        .and_then(b64::decode)
        .and_then(|bytes| String::from_utf8(bytes).ok());
    for path in referenced_files(cluster, auth) {
        check_referenced(&path)?;
        if auth.is_some_and(|auth| {
            auth.client_key.as_deref() == path.to_str()
                || auth.token_file.as_deref() == path.to_str()
        }) {
            let text = read_secret_file(&path);
            if auth.is_some_and(|auth| auth.token_file.as_deref() == path.to_str()) {
                token_text = token_text.or_else(|| text.clone());
            }
            secrets.extend(text);
        }
        if auth.is_some_and(|auth| auth.client_certificate.as_deref() == path.to_str()) {
            certificate_text = certificate_text.or_else(|| fs::read_to_string(&path).ok());
        }
        files.push(path);
    }

    // `Config::try_from(Kubeconfig)` reads the current context, so the choice is written there. It also
    // reads HTTPS_PROXY unless the cluster has a `proxy_url`, and fails on a malformed value. A fixed
    // placeholder takes the slot, and the slot is cleared below, so kube never looks at the environment.
    // The proxy is chosen after the build, from the kubeconfig and the environment, by `proxy::resolve`.
    kubeconfig.current_context = Some(context_name.clone());
    if let Some(chosen) = kubeconfig
        .clusters
        .iter_mut()
        .find(|named| named.name == context.cluster)
        .and_then(|named| named.cluster.as_mut())
    {
        chosen.proxy_url = Some(PROXY_PLACEHOLDER.to_owned());
    }
    let credentials = credentials_of(
        auth,
        token_text.as_deref(),
        certificate_text.as_deref(),
        env.now_unix,
    );
    let mut config =
        Config::try_from(kubeconfig).map_err(|error| from_kubeconfig_error(&error, ""))?;
    let resolved = proxy::resolve(kubeconfig_proxy.as_deref(), env, &config.cluster_url)?;
    secrets.extend(resolved.secrets);
    config.proxy_url = resolved.uri;
    harden_plugin(&mut config, env);

    let line = ClusterLine {
        context: escape(&context_name),
        server: server_of(&config),
        user: user_name.as_deref().map(escape),
        plugin: plugin_of(&config),
        tls_verification_off: config.accept_invalid_certs,
    };
    let plugin_exec = plugin_exec_of(&config);
    let ca_set = config.root_cert.is_some();
    // No namespace is used (ADR 0031 decision 12), so the one from the context is not kept.
    config.default_namespace = String::new();
    limit(&mut config, options.timeout);
    Ok(Loaded {
        facts: ConnectionFacts {
            source,
            line,
            credentials,
            proxy: resolved.used,
            ca_set,
        },
        files,
        config,
        plugin_exec,
        secrets,
    })
}

/// What the user entry sends to the server. `token` and `certificate` are the texts already read (inline
/// or from the file the entry names); only their end dates are kept.
fn credentials_of(
    auth: Option<&AuthInfo>,
    token: Option<&str>,
    certificate: Option<&str>,
    now: i64,
) -> Vec<Credential> {
    let Some(auth) = auth else {
        return Vec::new();
    };
    let mut credentials = Vec::new();
    if let Some(token) = token {
        credentials.push(Credential::Token {
            expires_in: credential::token_expires_in(token, now),
        });
    } else if auth.username.is_some() && auth.password.is_some() {
        credentials.push(Credential::Password);
    }
    let has_key = auth.client_key_data.is_some() || auth.client_key.is_some();
    if has_key && (auth.client_certificate_data.is_some() || auth.client_certificate.is_some()) {
        credentials.push(Credential::ClientCertificate {
            expires_in: certificate.and_then(|pem| credential::certificate_expires_in(pem, now)),
        });
    }
    if let Some(binary) = auth
        .exec
        .as_ref()
        .and_then(|exec| exec.command.as_deref())
        .and_then(plugin_file)
    {
        credentials.push(Credential::Plugin { binary });
    }
    credentials
}

/// The plugin's terminal use and environment, set from the process state (ADR 0031 decisions 8 and 10).
///
/// kube treats `interactiveMode` unset or `IfAvailable` as interactive even with no terminal: it
/// inherits stderr, which would bring plugin text past the redactor, and a login prompt would wait for
/// nobody. client-go only prompts when a terminal is there. So unless stdin and stderr are both
/// terminals the mode becomes `Never` (also for `Always`, which could not prompt anyway).
fn harden_plugin(config: &mut Config, env: &Env) {
    let Some(exec) = config.auth_info.exec.as_mut() else {
        return;
    };
    if !(env.stdin_is_terminal && env.stderr_is_terminal) {
        exec.interactive_mode = Some(ExecInteractiveMode::Never);
    }
    let mut drop = exec.drop_env.take().unwrap_or_default();
    for name in PLUGIN_DROP_ENV
        .iter()
        .map(|name| (*name).to_owned())
        .chain(env.rdy_vars.iter().cloned())
    {
        if !drop.contains(&name) {
            drop.push(name);
        }
    }
    exec.drop_env = Some(drop);
}

/// The inline secret values of a user entry.
fn inline_secrets(auth: Option<&AuthInfo>) -> Vec<String> {
    let Some(auth) = auth else {
        return Vec::new();
    };
    let mut secrets: Vec<String> = [&auth.token, &auth.password, &auth.client_key_data]
        .into_iter()
        .flatten()
        .map(|secret| secret.expose_secret().trim().to_owned())
        .filter(|value| !value.is_empty())
        .collect();
    // `client-key-data` is the base64 of a PEM key. The key shows up in output as PEM lines, not as
    // base64, so the decoded text is a known secret too. The set adds a multi-line value line by line.
    if let Some(data) = &auth.client_key_data
        && let Some(decoded) = b64::decode(data.expose_secret())
        && let Ok(pem) = String::from_utf8(decoded)
        && !pem.trim().is_empty()
    {
        secrets.push(pem.trim().to_owned());
    }
    // The `env` entries of an exec plugin go into the plugin's environment. The ones whose name looks
    // like a secret are known secrets too (a value under the redactor's minimum, such as a profile
    // name, is not: it would match common words).
    for entry in auth
        .exec
        .iter()
        .filter_map(|exec| exec.env.as_ref())
        .flatten()
    {
        if let (Some(name), Some(value)) = (entry.get("name"), entry.get("value")) {
            // The redactor's own key-name rule, plus `KEY` (it treats `KEY` alone as a plain word).
            let secret_name = rdy_engine::redact::is_secret_name(name)
                || name.to_ascii_uppercase().contains("KEY");
            if secret_name && value.trim().len() >= rdy_engine::redact::KNOWN_SECRET_MIN_LEN {
                secrets.push(value.clone());
            }
        }
    }
    secrets
}

/// The trimmed contents of a secret file that was already checked to be small and regular.
fn read_secret_file(path: &Path) -> Option<String> {
    let text = fs::read_to_string(path).ok()?;
    let text = text.trim();
    (!text.is_empty()).then(|| text.to_owned())
}

fn in_cluster(options: &KubeOptions, env: &Env) -> Result<Loaded, KubeError> {
    if !env.in_cluster {
        return Err(KubeError::NoKubeconfig);
    }
    if let Some(context) = &options.context {
        // A pod has no named contexts. Reaching some other cluster than the one asked for would be worse.
        return Err(KubeError::ContextNotFound {
            name: escape(context),
            available: Vec::new(),
        });
    }
    // kube reads these three files with no size or type check, so they are checked first.
    let mut files = Vec::new();
    for (path, problem) in SERVICE_ACCOUNT_FILES {
        let path = PathBuf::from(path);
        let usable = fs::metadata(&path)
            .is_ok_and(|metadata| metadata.is_file() && metadata.len() <= MAX_FILE_BYTES);
        if !usable {
            return Err(KubeError::InClusterUnusable { what: problem });
        }
        files.push(path);
    }
    let mut config = match Config::incluster_env() {
        Ok(config) => config,
        // The variable is gone since the check of `Env`. Same as not being in a pod.
        Err(kube::config::InClusterError::ReadEnvironmentVariable(_)) => {
            return Err(KubeError::NoKubeconfig);
        }
        Err(
            kube::config::InClusterError::ParseClusterPort(_)
            | kube::config::InClusterError::ParseClusterUrl(_),
        ) => {
            return Err(KubeError::InClusterUnusable {
                what: "KUBERNETES_SERVICE_HOST or KUBERNETES_SERVICE_PORT is not a valid address",
            });
        }
        Err(kube::config::InClusterError::ParseCertificates(_)) => {
            return Err(KubeError::InClusterUnusable {
                what: "the service account CA bundle is not valid PEM",
            });
        }
        Err(_) => {
            return Err(KubeError::InClusterUnusable {
                what: "a service account file cannot be read",
            });
        }
    };
    // A pod has no kubeconfig, so only the environment can name a proxy (ADR 0037).
    let resolved = proxy::resolve(None, env, &config.cluster_url)?;
    config.proxy_url = resolved.uri;
    let line = ClusterLine {
        context: "in-cluster".to_owned(),
        server: server_of(&config),
        user: None,
        plugin: None,
        tls_verification_off: config.accept_invalid_certs,
    };
    let mut secrets: Vec<String> = files
        .first()
        .and_then(|token| read_secret_file(token))
        .into_iter()
        .collect();
    secrets.extend(resolved.secrets);
    config.default_namespace = String::new();
    limit(&mut config, options.timeout);
    Ok(Loaded {
        facts: ConnectionFacts {
            source: Source::InCluster,
            line,
            credentials: vec![Credential::ServiceAccount],
            proxy: resolved.used,
            ca_set: true,
        },
        files,
        config,
        plugin_exec: None,
        secrets,
    })
}

/// Builds the kube client from a checked config. The one place a client is made.
///
/// The client is not guarded: the guard needs a probe, and a probe belongs to a check. It stays inside
/// [`Connected`], and [`ReadOnlyClient`] is the only way to send with it.
fn build_client(config: Config) -> Result<kube::Client, kube::Error> {
    Ok(ClientBuilder::try_from(config)?.build())
}

/// The wall clock in Unix seconds. A clock before 1970 reads as 0, which makes every token look valid.
fn unix_now() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .ok()
        .and_then(|elapsed| i64::try_from(elapsed.as_secs()).ok())
        .unwrap_or(0)
}

/// Sets the timeouts from the check timeout and turns kube's retries off.
fn limit(config: &mut Config, timeout: Duration) {
    let timeout = timeout.min(MAX_TIMEOUT);
    config.connect_timeout = Some(timeout);
    config.read_timeout = Some(timeout);
    config.write_timeout = Some(timeout);
    // A retry is a second request the action log and the guard would have to explain.
    config.default_retry = false;
}

/// The server URL for display: scheme, host, port and path. No user info, query or fragment.
fn server_of(config: &Config) -> String {
    let url = &config.cluster_url;
    let scheme = url.scheme_str().unwrap_or("https");
    let host = url.host().unwrap_or("");
    let port = url
        .port_u16()
        .map(|port| format!(":{port}"))
        .unwrap_or_default();
    let path = url.path().trim_end_matches('/');
    escape(&format!("{scheme}://{host}{port}{path}"))
}

/// The file name of the exec plugin's command, never its arguments.
fn plugin_of(config: &Config) -> Option<String> {
    plugin_file(config.auth_info.exec.as_ref()?.command.as_deref()?)
}

/// The file name of a plugin command, escaped.
fn plugin_file(command: &str) -> Option<String> {
    let file = Path::new(command).file_name().map_or_else(
        || command.to_owned(),
        |name| name.to_string_lossy().into_owned(),
    );
    Some(escape(&file))
}

/// The exec plugin's command and arguments for the action log.
fn plugin_exec_of(config: &Config) -> Option<PluginExec> {
    let exec = config.auth_info.exec.as_ref()?;
    Some(PluginExec {
        command: escape(exec.command.as_deref()?),
        args: exec
            .args
            .as_deref()
            .unwrap_or_default()
            .iter()
            .map(|arg| escape(arg))
            .collect(),
    })
}
