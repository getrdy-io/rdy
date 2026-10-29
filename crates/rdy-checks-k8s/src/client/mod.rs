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
//! 1. [`load`] reads files and builds a [`Loaded`]. It opens no socket and runs no plugin.
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
//!   that the report would not name) and a cluster `proxy-url` (proxy support is M1-109).
//! - It ignores `HTTPS_PROXY` for the cluster. kube would read it silently and, with no proxy feature,
//!   fail with an error that hides the cause.
//! - It sends nothing but `GET /version`. The read-only guard layer (M1-103) goes in
//!   `build_client`, and then `connect` returns the guarded type.
//!
//! Timeouts: the connect, read and write timeouts of the client are the check timeout, at most
//! [`MAX_TIMEOUT`]. kube's retries are off. A credential plugin that waits for a login is not bounded
//! here: the scheduler's timer around the probe is (M1-107), and the build runs on the blocking pool so
//! it never holds a worker.

#![allow(clippy::disallowed_types, clippy::disallowed_methods)]

use std::ffi::OsString;
use std::fmt;
use std::fs;
use std::path::{Path, PathBuf};
use std::time::Duration;

use kube::Config;
use kube::client::ClientBuilder;
use kube::config::Kubeconfig;
use rdy_engine::check::{CheckError, MAX_TIMEOUT};

mod error;
mod text;

#[cfg(test)]
mod tests;

pub use error::KubeError;
use error::{from_kube_error, from_kubeconfig_error, io_reason};
use text::escape;

/// The largest kubeconfig rdy reads. A real one is a few kilobytes.
const MAX_KUBECONFIG_BYTES: u64 = 8 * 1024 * 1024;

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

/// The parts of the process environment this module looks at, gathered once.
///
/// Tests build one by hand, so they never change the process environment.
#[derive(Debug, Clone, Default)]
#[non_exhaustive]
pub struct Env {
    /// The value of `KUBECONFIG`, a list of paths separated by the OS list separator.
    pub kubeconfig: Option<OsString>,
    /// The home directory, for `~/.kube/config`.
    pub home: Option<PathBuf>,
    /// Whether to try the in-cluster config (a service account in a pod) when no kubeconfig is found.
    pub in_cluster: bool,
}

impl Env {
    /// Reads `KUBECONFIG` and the home directory from the process, and allows the in-cluster config.
    #[must_use]
    pub fn from_process() -> Self {
        Self {
            kubeconfig: std::env::var_os("KUBECONFIG"),
            home: std::env::home_dir(),
            in_cluster: true,
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

/// A config that is read and checked, with no socket opened and no plugin run.
pub struct Loaded {
    source: Source,
    files: Vec<PathBuf>,
    line: ClusterLine,
    config: Config,
}

impl fmt::Debug for Loaded {
    // The kube `Config` holds tokens and plugin settings, so it is never printed.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Loaded")
            .field("source", &self.source)
            .field("line", &self.line)
            .finish_non_exhaustive()
    }
}

impl Loaded {
    /// Where the config came from.
    #[must_use]
    pub fn source(&self) -> &Source {
        &self.source
    }

    /// The kubeconfig files that were read, in order. Empty for the in-cluster config. The probe hook
    /// logs each as a `read` entry with no check id.
    #[must_use]
    pub fn files(&self) -> &[PathBuf] {
        &self.files
    }

    /// The cluster rdy is about to touch.
    #[must_use]
    pub fn line(&self) -> &ClusterLine {
        &self.line
    }

    /// Announces the cluster, builds the client and asks the server for its version.
    ///
    /// `announce` runs first, before any plugin starts and before any socket opens. The caller prints
    /// the [`ClusterLine`] from it. Then the client is built on the blocking pool (the build can run a
    /// credential plugin, which blocks), and `GET /version` is the first request. The need
    /// `kube_context` is met when this returns `Ok` (ADR 0010 decision 5).
    ///
    /// # Errors
    ///
    /// A [`KubeError`]. It never holds plugin output or credentials.
    pub async fn connect(
        self,
        announce: impl FnOnce(&ClusterLine),
    ) -> Result<Connected, KubeError> {
        announce(&self.line);
        let Self {
            source,
            files,
            line,
            config,
        } = self;
        let server = line.server.clone();
        let plugin = line.plugin.clone();
        let built =
            rdy_engine::blocking::blocking(move || Ok::<_, CheckError>(build_client(config))).await;
        let client = match built {
            Ok(Ok(client)) => client,
            Ok(Err(error)) => return Err(from_kube_error(&error, &server, plugin.as_deref())),
            Err(_) => return Err(KubeError::Cancelled),
        };
        let info = client
            .apiserver_version()
            .await
            .map_err(|error| from_kube_error(&error, &server, plugin.as_deref()))?;
        Ok(Connected {
            source,
            files,
            line,
            version: ServerVersion {
                git_version: info.git_version,
                major: info.major,
                minor: info.minor,
                platform: info.platform,
            },
            client,
        })
    }
}

/// A client that has answered `GET /version`.
pub struct Connected {
    source: Source,
    files: Vec<PathBuf>,
    line: ClusterLine,
    version: ServerVersion,
    // M1-103 replaces this field with the guarded client (`ReadOnlyClient`) and the unguarded one stops
    // being reachable. Until then nothing outside this module can send a request with it.
    #[expect(dead_code, reason = "M1-103 wraps this client in the read-only guard")]
    client: kube::Client,
}

impl fmt::Debug for Connected {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Connected")
            .field("source", &self.source)
            .field("line", &self.line)
            .field("version", &self.version)
            .finish_non_exhaustive()
    }
}

impl Connected {
    /// Where the config came from.
    #[must_use]
    pub fn source(&self) -> &Source {
        &self.source
    }

    /// The kubeconfig files that were read.
    #[must_use]
    pub fn files(&self) -> &[PathBuf] {
        &self.files
    }

    /// The cluster that answered.
    #[must_use]
    pub fn line(&self) -> &ClusterLine {
        &self.line
    }

    /// What `GET /version` said.
    #[must_use]
    pub fn server_version(&self) -> &ServerVersion {
        &self.version
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

/// Builds the kube client from a checked config. The one place a client is made.
fn build_client(config: Config) -> Result<kube::Client, kube::Error> {
    // M1-103 adds `.with_layer(&guard)` here, so the guard sits in front of every request.
    Ok(ClientBuilder::try_from(config)?.build())
}

/// Finds and reads the config. Reads files, opens no socket, runs no plugin.
///
/// Order (03 section 4): `--kubeconfig`, then `KUBECONFIG`, then `~/.kube/config`, then the in-cluster
/// config. A `--kubeconfig` file that is missing is an error and does not fall through. Files listed in
/// `KUBECONFIG` that do not exist are skipped, as `kubectl` does, and the rest are merged with the first
/// file winning.
///
/// # Errors
///
/// [`KubeError::NoKubeconfig`] when no source exists, and other [`KubeError`] variants when a source
/// exists and cannot be used. The text never quotes the kubeconfig.
pub fn load(options: &KubeOptions, env: &Env) -> Result<Loaded, KubeError> {
    match read_files(options, env)? {
        Some((source, files, kubeconfig)) => from_kubeconfig(options, source, files, kubeconfig),
        None => in_cluster(options, env),
    }
}

/// A kubeconfig and where it came from.
type Found = (Source, Vec<PathBuf>, Kubeconfig);

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
        // A FIFO or a device would block the read for ever, and a huge file is not a kubeconfig.
        if !metadata.is_file() {
            return Err(KubeError::KubeconfigUnreadable {
                path: shown,
                reason: "it is not a regular file",
            });
        }
        if metadata.len() > MAX_KUBECONFIG_BYTES {
            return Err(KubeError::KubeconfigUnreadable {
                path: shown,
                reason: "it is larger than 8 MiB",
            });
        }
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

fn from_kubeconfig(
    options: &KubeOptions,
    source: Source,
    files: Vec<PathBuf>,
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
    if cluster
        .proxy_url
        .as_deref()
        .is_some_and(|proxy| !proxy.is_empty())
    {
        return Err(KubeError::ProxyUnsupported);
    }

    let user_name = context.user.clone().filter(|user| !user.is_empty());
    if let Some(provider) = user_name
        .as_deref()
        .and_then(|user| {
            kubeconfig
                .auth_infos
                .iter()
                .find(|named| named.name == user)
        })
        .and_then(|named| named.auth_info.as_ref())
        .and_then(|auth| auth.auth_provider.as_ref())
    {
        return Err(KubeError::AuthProviderUnsupported {
            name: escape(&provider.name),
        });
    }

    // `Config::try_from(Kubeconfig)` reads the current context, so the choice is written there.
    kubeconfig.current_context = Some(context_name.clone());
    let mut config =
        Config::try_from(kubeconfig).map_err(|error| from_kubeconfig_error(&error, ""))?;
    // kube also reads HTTPS_PROXY here. This build has no proxy feature, so an env proxy would only
    // make the build fail with a hidden cause. The cluster is contacted directly (M1-109 owns proxies).
    config.proxy_url = None;

    let line = ClusterLine {
        context: escape(&context_name),
        server: server_of(&config),
        user: user_name.as_deref().map(escape),
        plugin: plugin_of(&config),
        tls_verification_off: config.accept_invalid_certs,
    };
    limit(&mut config, options.timeout);
    Ok(Loaded {
        source,
        files,
        line,
        config,
    })
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
    let mut config = Config::incluster_env().map_err(|_| KubeError::NoKubeconfig)?;
    config.proxy_url = None;
    let line = ClusterLine {
        context: "in-cluster".to_owned(),
        server: server_of(&config),
        user: None,
        plugin: None,
        tls_verification_off: config.accept_invalid_certs,
    };
    limit(&mut config, options.timeout);
    Ok(Loaded {
        source: Source::InCluster,
        files: Vec::new(),
        line,
        config,
    })
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
    let command = config.auth_info.exec.as_ref()?.command.as_deref()?;
    let file = Path::new(command).file_name().map_or_else(
        || command.to_owned(),
        |name| name.to_string_lossy().into_owned(),
    );
    Some(escape(&file))
}
