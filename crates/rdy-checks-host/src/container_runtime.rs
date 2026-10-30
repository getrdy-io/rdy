//! `host.container_runtime`: which container runtime is present, its version, cgroup driver, storage
//! driver and `d_type` support, daemon proxy settings, and whether it agrees with the kubelet.
//!
//! Linux only. Every source is read through the probe:
//!
//! - **Docker and Podman** are asked over their unix sockets with `Probe::unix_get`: `GET /version`
//!   and `GET /info`, nothing else. The facade sends only `GET`, only to those paths, only to the
//!   sockets listed in [`INFO`]. The `/info` body can carry a proxy URL with a password, so the check
//!   parses the **redacted** text (`Probe::unix_text`) and keeps nothing from the raw bytes.
//! - **containerd and CRI-O** speak gRPC, so the check stats the socket and runs `containerd --version`
//!   or `crio --version` from the command table. containerd's cgroup driver and snapshotter come from
//!   `/etc/containerd/config.toml`, read by config version (see [`containerd`]).
//! - `/etc/docker/daemon.json` fills in what the Docker API could not say (a user outside the `docker`
//!   group, a daemon that is down). The kubelet's `cgroupDriver` comes from
//!   `/var/lib/kubelet/config.yaml`. Proxy settings come from the `Environment=` lines of the systemd
//!   drop-ins of `docker` and `containerd`.
//!
//! Every file is read as redacted text (`Probe::file_text`), so a registry password in a config file
//! cannot reach a note or the evidence.
//!
//! The spec lists runtimes of which any one will do. The check judges each allowed runtime that is
//! present and takes the best one. Docker and Podman are present when their socket is. containerd and
//! CRI-O are present when their socket is or their program runs. rdy asks only the runtimes the spec
//! names, or all four when it names none.
//!
//! Not read in M1: the CRI-O and Podman configuration, rootless `daemon.json`, the kubelet's
//! `--cgroup-driver` flag, and containerd files named in `imports`. Each leaves the value unknown, and an
//! unknown value is a warning, never a pass. The Windows named pipe is M2-052.

use std::path::Path;

use rdy_engine::check::{
    BoxFuture, Check, CheckContext, CheckError, CheckInfo, CheckMeta, CheckOutcome, CommandSpec,
    Need, Os, PeerClass,
};
use rdy_engine::exec::policy::PolicyError;
use rdy_engine::exec::table;
use rdy_engine::probe::ProbeError;
use rdy_spec::check::{CgroupDriver, ContainerRuntime, HostContainerRuntime};
use rdy_spec::scalar::Version;

use crate::family::{OS, ROOT};
use crate::reads::Read;
use crate::text::{short, soft};

mod containerd;
mod engine;
mod files;
mod judge;

#[cfg(test)]
mod tests;
#[cfg(test)]
mod unit_tests;

use judge::{Api, Seen};

/// What the check says on an OS it has no data source for.
const NO_SOURCE: &str =
    "this check reads Linux runtime sockets and files and has no data source on this OS yet";

const SOCK_DOCKER: &str = "/var/run/docker.sock";
const SOCK_CONTAINERD: &str = "/run/containerd/containerd.sock";
const SOCK_PODMAN: &str = "/run/podman/podman.sock";
const SOCK_CRIO: &str = "/var/run/crio/crio.sock";
const DAEMON_JSON: &str = "/etc/docker/daemon.json";
const CONTAINERD_CONFIG: &str = "/etc/containerd/config.toml";
pub(crate) const KUBELET_CONFIG: &str = "/var/lib/kubelet/config.yaml";
const DOCKER_DROPINS: &str = "/etc/systemd/system/docker.service.d";
const CONTAINERD_DROPINS: &str = "/etc/systemd/system/containerd.service.d";

/// The most drop-in files read per service.
const MAX_DROPINS: usize = 16;
/// The longest evidence string kept.
const MAX_TEXT: usize = 200;

/// The static facts about `host.container_runtime` (03 section 2).
pub(crate) static INFO: CheckInfo = CheckInfo {
    id: "host.container_runtime",
    family: "host",
    summary: "Docker, containerd, Podman, CRI-O",
    meta: CheckMeta {
        title: "Container runtime",
        remediation: "Install a container runtime the vendor supports, and make its socket readable by adding the user to the `docker` group or by running as root. The runtime and the kubelet must use the same cgroup driver. For containerd, set `SystemdCgroup = true` in `/etc/containerd/config.toml`, then run `systemctl restart containerd`.",
    },
    needs: &[],
    wants: ROOT,
    default_timeout: Some(std::time::Duration::from_secs(5)),
    os: OS,
    reads: &[
        SOCK_DOCKER,
        SOCK_CONTAINERD,
        SOCK_PODMAN,
        SOCK_CRIO,
        "/run/user",
        DAEMON_JSON,
        CONTAINERD_CONFIG,
        KUBELET_CONFIG,
        DOCKER_DROPINS,
        CONTAINERD_DROPINS,
    ],
    statfs: &[],
    env: &["XDG_RUNTIME_DIR"],
    commands: &[
        CommandSpec {
            program: "containerd",
            extra_dirs: &[],
            max_stdout: 16 * 1024,
            env: &[],
        },
        CommandSpec {
            program: "crio",
            extra_dirs: &[],
            max_stdout: 16 * 1024,
            env: &[],
        },
    ],
    peers: &[
        PeerClass::UnixSocket(SOCK_DOCKER),
        PeerClass::UnixSocket(SOCK_PODMAN),
        PeerClass::UnixSocket("/run/user/{uid}/docker.sock"),
        PeerClass::UnixSocket("/run/user/{uid}/podman/podman.sock"),
    ],
};

/// What the kubelet's config says.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub(crate) struct Kubelet {
    /// The config file exists.
    pub present: bool,
    pub driver: Option<CgroupDriver>,
    /// Why the file could not be read, when it exists.
    pub unreadable: Option<String>,
}

/// `host.container_runtime`.
///
/// Built from the spec's `runtime`, `min_version`, `cgroup_driver` and `storage_driver`. With none of
/// them it blocks when no runtime is found and otherwise reports what it finds.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct ContainerRuntimeCheck {
    runtimes: Option<Vec<ContainerRuntime>>,
    min_version: Option<Version>,
    cgroup_driver: Option<CgroupDriver>,
    storage_driver: Option<String>,
}

impl ContainerRuntimeCheck {
    /// A check for the parameters of a `host.container_runtime` spec entry.
    #[must_use]
    pub fn from_params(params: &HostContainerRuntime) -> Self {
        Self {
            runtimes: params
                .runtime
                .as_ref()
                .map(|list| list.iter().copied().collect()),
            min_version: params.min_version.clone(),
            cgroup_driver: params.cgroup_driver,
            storage_driver: params
                .storage_driver
                .as_ref()
                .map(|s| s.as_str().to_owned()),
        }
    }

    fn asks(&self, kind: ContainerRuntime) -> bool {
        self.runtimes.as_ref().is_none_or(|l| l.contains(&kind))
    }

    async fn inspect(&self, ctx: &CheckContext) -> CheckOutcome {
        if ctx.os() != Os::Linux {
            return Err(CheckError::Unsupported(NO_SOURCE));
        }
        let kubelet = kubelet(ctx).await?;
        let user_dir = user_runtime_dir(ctx)?;
        let mut seen = Vec::new();
        if self.asks(ContainerRuntime::Docker) {
            seen.push(engine(ctx, ContainerRuntime::Docker, SOCK_DOCKER, false).await?);
            if let Some(dir) = &user_dir {
                let socket = format!("{dir}/docker.sock");
                seen.push(engine(ctx, ContainerRuntime::Docker, &socket, true).await?);
            }
        }
        if self.asks(ContainerRuntime::Containerd) {
            seen.push(containerd(ctx).await?);
        }
        if self.asks(ContainerRuntime::Podman) {
            seen.push(engine(ctx, ContainerRuntime::Podman, SOCK_PODMAN, false).await?);
            if let Some(dir) = &user_dir {
                let socket = format!("{dir}/podman/podman.sock");
                seen.push(engine(ctx, ContainerRuntime::Podman, &socket, true).await?);
            }
        }
        if self.asks(ContainerRuntime::Crio) {
            seen.push(crio(ctx).await?);
        }
        Ok(judge::judge(self, &seen, &kubelet, ctx.has(&Need::Root)))
    }
}

impl Check for ContainerRuntimeCheck {
    fn info(&self) -> &'static CheckInfo {
        &INFO
    }

    fn run<'a>(&'a self, ctx: &'a CheckContext) -> BoxFuture<'a, CheckOutcome> {
        Box::pin(self.inspect(ctx))
    }
}

/// Text from the machine, cut to a length that fits evidence, with controls turned into spaces.
pub(crate) fn clip(text: &str) -> String {
    text.chars()
        .take(MAX_TEXT)
        .map(|c| if c.is_control() { ' ' } else { c })
        .collect()
}

/// The rootless socket directory: `XDG_RUNTIME_DIR` when it is `/run/user/<digits>`, which is the only
/// shape the facade accepts for a `{uid}` socket.
fn user_runtime_dir(ctx: &CheckContext) -> Result<Option<String>, CheckError> {
    let value = ctx
        .probe()
        .env("XDG_RUNTIME_DIR")
        .map_err(CheckError::Probe)?;
    Ok(value.filter(|dir| {
        dir.strip_prefix("/run/user/").is_some_and(|id| {
            !id.is_empty() && id.len() <= 10 && id.bytes().all(|b| b.is_ascii_digit())
        })
    }))
}

/// A file as redacted text. Nothing from the raw bytes is kept.
async fn read_redacted(ctx: &CheckContext, path: &str) -> Result<Read, CheckError> {
    let probe = ctx.probe();
    match probe.read(Path::new(path)).await {
        Ok(file) => {
            let text = probe.file_text(&file).map_err(CheckError::Probe)?;
            Ok(Read::Text((*text).clone()))
        }
        Err(error) => match soft(error)? {
            ProbeError::NotFound => Ok(Read::Absent),
            other => Ok(Read::Unreadable(short(&other))),
        },
    }
}

async fn kubelet(ctx: &CheckContext) -> Result<Kubelet, CheckError> {
    Ok(match read_redacted(ctx, KUBELET_CONFIG).await? {
        Read::Absent => Kubelet::default(),
        Read::Text(text) => Kubelet {
            present: true,
            driver: files::kubelet_driver(&text),
            unreadable: None,
        },
        Read::Unreadable(why) => Kubelet {
            present: true,
            driver: None,
            unreadable: Some(why),
        },
    })
}

/// How a failed socket call reads. A refusal by the facade is a fault of the check, except on a
/// rootless socket, where the `{uid}` rule may name another user.
fn api_failure(error: ProbeError, rootless: bool) -> Result<Api, CheckError> {
    match error {
        ProbeError::PermissionDenied => Ok(Api::Denied),
        ProbeError::NotFound => Ok(Api::NotListening),
        ProbeError::Timeout => Ok(Api::Odd("it did not answer in time".to_owned())),
        ProbeError::Io(message) if message.to_ascii_lowercase().contains("refused") => {
            Ok(Api::NotListening)
        }
        ProbeError::Denied { .. } if rootless => Ok(Api::Odd(
            "the socket belongs to another user than the one running rdy".to_owned(),
        )),
        other => Ok(Api::Odd(short(&soft(other)?))),
    }
}

/// Asks one `GET` of a Docker or Podman socket. `Ok(None)` when the reply is not 200 with text.
async fn get(
    ctx: &CheckContext,
    socket: &str,
    path: &str,
    rootless: bool,
) -> Result<Result<String, Api>, CheckError> {
    let probe = ctx.probe();
    match probe.unix_get(Path::new(socket), path).await {
        Err(error) => Ok(Err(api_failure(error, rootless)?)),
        Ok(reply) if reply.status != 200 => Ok(Err(Api::Odd(format!(
            "{path} answered with status {}",
            reply.status
        )))),
        Ok(reply) => {
            // Only the redacted text is used from here on.
            let text = probe.unix_text(&reply).map_err(CheckError::Probe)?;
            Ok(Ok((*text).clone()))
        }
    }
}

/// A Docker or Podman socket: stat it, then `GET /version` and `GET /info`.
async fn engine(
    ctx: &CheckContext,
    kind: ContainerRuntime,
    socket: &str,
    rootless: bool,
) -> Result<Seen, CheckError> {
    let mut seen = Seen::new(kind, rootless, socket);
    match ctx.probe().stat(Path::new(socket)).await {
        Ok(Some(_)) => seen.socket_present = true,
        Ok(None) | Err(ProbeError::NotFound) => return Ok(seen),
        Err(error) => {
            seen.socket_present = true;
            seen.api = api_failure(error, rootless)?;
            return fall_back(ctx, seen).await;
        }
    }
    let source = if kind == ContainerRuntime::Podman {
        "podman info"
    } else {
        "docker info"
    };
    let version = match get(ctx, socket, "/version", rootless).await? {
        Err(api) => {
            seen.api = api;
            return fall_back(ctx, seen).await;
        }
        Ok(text) => engine::parse_version(&text),
    };
    let Some(version) = version else {
        seen.api = Api::Odd("the /version reply is not the Engine API".to_owned());
        return fall_back(ctx, seen).await;
    };
    if version.product == engine::Product::Podman && seen.kind == ContainerRuntime::Docker {
        seen.kind = ContainerRuntime::Podman;
        seen.notes
            .push("the Docker socket is served by Podman".to_owned());
    }
    seen.version = version.version;
    let info = match get(ctx, socket, "/info", rootless).await? {
        Err(api) => {
            seen.api = api;
            return fall_back(ctx, seen).await;
        }
        Ok(text) => engine::parse_info(&text),
    };
    let Some(info) = info else {
        seen.api = Api::Odd("the /info reply is not the Engine API".to_owned());
        return fall_back(ctx, seen).await;
    };
    seen.api = Api::Read;
    if info.server_version.is_some() {
        seen.version = info.server_version;
    }
    seen.cgroup = info.cgroup_driver.map(|d| (d, source));
    seen.storage = info.storage_driver.map(|s| (s, source));
    seen.d_type = info.d_type;
    seen.rootless_mode = info.rootless;
    let proxy = files::Proxy {
        http: info.http_proxy,
        https: info.https_proxy,
        no_proxy: info.no_proxy,
    };
    if !proxy.is_empty() {
        seen.proxy = Some((proxy, source));
    }
    Ok(seen)
}

/// When the API could not be read, `daemon.json` gives the configured cgroup driver, storage driver
/// and proxy of a system Docker, and the drop-ins give a proxy. These are what is configured, not what
/// the running daemon uses, and a note says so.
async fn fall_back(ctx: &CheckContext, mut seen: Seen) -> Result<Seen, CheckError> {
    if seen.kind != ContainerRuntime::Docker || seen.rootless {
        return Ok(seen);
    }
    match read_redacted(ctx, DAEMON_JSON).await? {
        Read::Absent => {}
        Read::Unreadable(why) => seen
            .notes
            .push(format!("{DAEMON_JSON} could not be read ({why})")),
        Read::Text(text) => match files::parse_daemon_json(&text) {
            Ok(daemon) => {
                seen.cgroup = daemon.cgroup_driver.map(|d| (d, DAEMON_JSON));
                seen.storage = daemon.storage_driver.map(|s| (s, DAEMON_JSON));
                if !daemon.proxy.is_empty() {
                    seen.proxy = Some((daemon.proxy, DAEMON_JSON));
                }
                seen.notes.push(format!(
                    "values come from {DAEMON_JSON}, not from the running daemon"
                ));
            }
            Err(why) => seen.notes.push(format!("{DAEMON_JSON}: {why}")),
        },
    }
    dropin_proxy(ctx, &mut seen, DOCKER_DROPINS).await?;
    Ok(seen)
}

/// The proxy of the last drop-in (in file name order) that sets one, when none is known yet.
async fn dropin_proxy(
    ctx: &CheckContext,
    seen: &mut Seen,
    dir: &'static str,
) -> Result<(), CheckError> {
    if seen.proxy.is_some() {
        return Ok(());
    }
    let entries = match ctx.probe().read_dir(Path::new(dir)).await {
        Ok(entries) => entries,
        Err(error) => {
            soft(error)?;
            return Ok(());
        }
    };
    let mut names: Vec<String> = entries
        .iter()
        .filter(|e| !e.is_dir)
        .map(|e| e.name.clone())
        .filter(|n| n.ends_with(".conf") && !n.contains('/'))
        .collect();
    names.sort_unstable();
    names.truncate(MAX_DROPINS);
    let mut found = files::Proxy::default();
    for name in names {
        if let Read::Text(text) = read_redacted(ctx, &format!("{dir}/{name}")).await? {
            let one = files::parse_dropin(&text);
            found.http = one.http.or(found.http);
            found.https = one.https.or(found.https);
            found.no_proxy = one.no_proxy.or(found.no_proxy);
        }
    }
    if !found.is_empty() {
        seen.proxy = Some((found, "a systemd drop-in"));
    }
    Ok(())
}

/// What running a `--version` command gave.
enum Ran {
    Text(String),
    Absent,
    Odd(String),
}

async fn version_text(ctx: &CheckContext, program: &str) -> Result<Ran, CheckError> {
    let failed = || CheckError::Failed {
        message: format!("{program} is not in rdy's command table"),
        hint: "Tell the vendor which rdy version this is.".to_owned(),
    };
    let entry = table::entry(program).ok_or_else(failed)?;
    let cmd = entry
        .cmd_for(ctx.os(), "version", &[])
        .map_err(|e| CheckError::Probe(ProbeError::Table(e)))?;
    let out = match ctx.probe().exec(cmd).await {
        Ok(out) => out,
        Err(error) => {
            if matches!(error, ProbeError::Policy(PolicyError::NotFound { .. })) {
                return Ok(Ran::Absent);
            }
            return match soft(error)? {
                ProbeError::NotFound => Ok(Ran::Absent),
                other => Ok(Ran::Odd(short(&other))),
            };
        }
    };
    if out.exit != Some(0) {
        return Ok(Ran::Odd("it exited with an error".to_owned()));
    }
    let text = ctx.probe().stdout_text(&out).map_err(CheckError::Probe)?;
    Ok(Ran::Text((*text).clone()))
}

/// stat of a gRPC socket: present, and whether the user may look.
async fn grpc_socket(ctx: &CheckContext, seen: &mut Seen) -> Result<(), CheckError> {
    match ctx.probe().stat(Path::new(&seen.socket)).await {
        Ok(Some(_)) => seen.socket_present = true,
        Ok(None) | Err(ProbeError::NotFound) => {}
        Err(error) => {
            seen.socket_present = true;
            seen.api = api_failure(error, false)?;
        }
    }
    Ok(())
}

async fn containerd(ctx: &CheckContext) -> Result<Seen, CheckError> {
    let mut seen = Seen::new(ContainerRuntime::Containerd, false, SOCK_CONTAINERD);
    grpc_socket(ctx, &mut seen).await?;
    match version_text(ctx, "containerd").await? {
        Ran::Text(text) => {
            seen.installed = true;
            seen.version = files::containerd_version(&text);
        }
        Ran::Absent => {}
        Ran::Odd(why) => seen
            .notes
            .push(format!("containerd --version failed ({why})")),
    }
    if !seen.present() {
        return Ok(seen);
    }
    let major = seen
        .version
        .as_deref()
        .and_then(files::leading_number)
        .and_then(|n| n.split('.').next())
        .and_then(|m| m.parse::<u32>().ok());
    let config = match read_redacted(ctx, CONTAINERD_CONFIG).await? {
        Read::Absent => containerd::built_in(major),
        Read::Unreadable(why) => {
            seen.notes
                .push(format!("{CONTAINERD_CONFIG} could not be read ({why})"));
            let mut unknown = containerd::built_in(major);
            unknown.cgroup = None;
            unknown.snapshotter = None;
            unknown
        }
        Read::Text(text) => match containerd::parse(&text) {
            Ok(config) => config,
            Err(why) => {
                seen.notes.push(format!("{CONTAINERD_CONFIG}: {why}"));
                let mut unknown = containerd::built_in(major);
                unknown.from_file = true;
                unknown.cgroup = None;
                unknown.snapshotter = None;
                unknown
            }
        },
    };
    let source = if config.from_file {
        CONTAINERD_CONFIG
    } else {
        "containerd's built-in default (no config file)"
    };
    seen.cgroup = config.cgroup.map(|d| (d, source));
    seen.storage = config.snapshotter.clone().map(|s| (s, source));
    seen.notes.extend(config.notes.iter().cloned());
    seen.config = Some(config);
    dropin_proxy(ctx, &mut seen, CONTAINERD_DROPINS).await?;
    Ok(seen)
}

async fn crio(ctx: &CheckContext) -> Result<Seen, CheckError> {
    let mut seen = Seen::new(ContainerRuntime::Crio, false, SOCK_CRIO);
    grpc_socket(ctx, &mut seen).await?;
    match version_text(ctx, "crio").await? {
        Ran::Text(text) => {
            seen.installed = true;
            seen.version = files::crio_version(&text);
        }
        Ran::Absent => {}
        Ran::Odd(why) => seen.notes.push(format!("crio --version failed ({why})")),
    }
    if seen.present() {
        seen.blind = true;
        seen.notes.push(
            "the CRI-O configuration is not read, so its cgroup and storage drivers are unknown"
                .to_owned(),
        );
    }
    Ok(seen)
}
