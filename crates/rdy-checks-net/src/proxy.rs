//! `net.proxy`: the proxy settings the product would really see (03 section 3, M1-098).
//!
//! It answers four questions:
//!
//! 1. **What is set, and where?** The process environment (`HTTPS_PROXY`, `https_proxy`, `HTTP_PROXY`,
//!    `http_proxy`, `ALL_PROXY`, `NO_PROXY`, `no_proxy`, `auto_proxy`) and, on Linux, the systemd drop-ins
//!    of `docker`, `containerd` and `kubelet` (`/etc/systemd/system/<unit>.service.d/*.conf`) and the
//!    `proxies` of `/etc/docker/daemon.json`. Two spellings of one variable that differ are reported.
//! 2. **Do the daemons have it too?** A shell with a proxy and a daemon with none is the classic failed
//!    pull. It warns, with the drop-in text to create, and blocks when the spec sets `daemons_need_proxy`.
//! 3. **Does `NO_PROXY` cover what the vendor needs direct?** The spec's `required_no_proxy` is matched
//!    with the facade matcher (`rdy_engine::probe::NoProxy`), for the shell and for each daemon.
//! 4. **Can this machine reach the proxy?** One TCP connection to the run's proxy through
//!    `Probe::proxy_reach`, closed at once. It sends no byte, so no credential leaves. A proxy that
//!    cannot be reached blocks.
//!
//! **PAC and WPAD are detected, never fetched or evaluated** (ADR 0009, 02 "no PAC fetch in M1"). A
//! PAC address in `auto_proxy`, or a proxy variable whose value is a PAC URL, warns. The check declares
//! no spec host, so the facade has no route to fetch one.
//!
//! **Never printed.** A proxy is shown as `http://host:port`, never with its user name or password
//! (`rdy_engine::probe::ProxyUrl` has no accessor for either). Raw values are classified at once and
//! dropped. The planted-secret tests cover the environment, a drop-in, `daemon.json` and the action log.
//! `~/.docker/config.json` is not read: the facade refuses it on purpose (its `auths` hold registry
//! credentials), and the `proxies` it may hold apply to containers and not to the daemon.
//!
//! **Sources not built.** macOS (`scutil --proxy`) and Windows (the registry and WinHTTP) arrive with
//! M2-010. There the check reads the environment only, and every result is `partial`. `EnvironmentFile=`
//! targets, `/etc/environment`, package manager configs and `/etc/profile.d` are not read, and a note says
//! so when a drop-in names an environment file.
//!
//! **Privilege.** None. Every file is world readable. **Time.** The reads are bounded (at most 16 drop-ins
//! per unit) and the proxy connection gets what is left of the 5 s timeout. Under `--no-network` the
//! proxy is not contacted and the result is `partial`.

use std::collections::HashMap;
use std::path::Path;
use std::time::Duration;

use rdy_engine::check::{
    BoxFuture, Check, CheckContext, CheckError, CheckInfo, CheckMeta, CheckOutcome, Need, Os,
    OsSupport, PeerClass, Support,
};
use rdy_engine::probe::net::TcpReport;
use rdy_engine::probe::{
    AttemptOutcome, NO_PROXY_ENV, NetFailure, NoProxy, PROXY_ENV, ProbeError, env_conflicts,
};
use rdy_spec::check::NetProxy;

use crate::text::{short, soft};

mod judge;
mod parse;
#[cfg(test)]
mod tests;

use judge::{Daemon, Facts, Reach, Rules, judge};
use parse::{Assign, Kind, Setting, classify, daemon_json_proxies, pac_url, parse_dropin};

/// The units whose environment is read.
const UNITS: [&str; 3] = ["docker", "containerd", "kubelet"];

/// The most drop-ins read for one unit.
const MAX_DROPINS: usize = 16;

/// The variables whose value is a proxy.
const OTHER_PROXY_ENV: [&str; 2] = ["ALL_PROXY", "all_proxy"];

/// The variables that name a PAC script.
const PAC_ENV: [&str; 2] = ["auto_proxy", "AUTO_PROXY"];

const DAEMON_JSON: &str = "/etc/docker/daemon.json";

/// What the check says on an OS it has only the environment for.
const PARTIAL_OS: &str = "only the process environment is read here: the macOS proxy settings (scutil) and the Windows ones (registry, WinHTTP) are not read by this version, and daemons are not compared";

/// The time kept for writing the result when the proxy connection runs long.
const RESERVE: Duration = Duration::from_millis(500);

/// Unit files, drop-in directories and `daemon.json`, as the manifest declares them. A unit file is only
/// inspected (`stat`), never read.
const READS: &[&str] = &[
    "/etc/systemd/system/docker.service",
    "/usr/lib/systemd/system/docker.service",
    "/lib/systemd/system/docker.service",
    "/etc/systemd/system/docker.service.d",
    "/etc/systemd/system/containerd.service",
    "/usr/lib/systemd/system/containerd.service",
    "/lib/systemd/system/containerd.service",
    "/etc/systemd/system/containerd.service.d",
    "/etc/systemd/system/kubelet.service",
    "/usr/lib/systemd/system/kubelet.service",
    "/lib/systemd/system/kubelet.service",
    "/etc/systemd/system/kubelet.service.d",
    DAEMON_JSON,
];

/// Every variable the check reads, by name. None is secret by name, and a value is parsed and dropped.
const ENV: &[&str] = &[
    "HTTPS_PROXY",
    "https_proxy",
    "HTTP_PROXY",
    "http_proxy",
    "ALL_PROXY",
    "all_proxy",
    "NO_PROXY",
    "no_proxy",
    "auto_proxy",
    "AUTO_PROXY",
];

/// The static facts about `net.proxy` (03 section 3).
pub(crate) static INFO: CheckInfo = CheckInfo {
    id: "net.proxy",
    family: "net",
    summary: "Proxy settings of the shell and the daemons, NO_PROXY coverage, PAC, reachability",
    meta: CheckMeta {
        title: "Proxy",
        remediation: "Set the proxy the same way for the shell and for Docker, containerd and the kubelet. For a daemon, create a systemd drop-in such as `/etc/systemd/system/docker.service.d/http-proxy.conf` with `[Service]` and `Environment=\"HTTPS_PROXY=http://proxy.acme.example:3128\"`, then run `systemctl daemon-reload && systemctl restart docker`. List cluster-internal names and networks in NO_PROXY. rdy cannot evaluate a PAC script: use an explicit http:// proxy address. If the proxy is not reachable, ask the network team to allow its port from this machine.",
    },
    needs: &[],
    wants: &[],
    default_timeout: Some(Duration::from_secs(5)),
    os: OsSupport {
        linux: Support::Full,
        macos: Support::Partial(PARTIAL_OS),
        windows: Support::Partial(PARTIAL_OS),
    },
    reads: READS,
    statfs: &[],
    env: ENV,
    commands: &[],
    peers: &[PeerClass::Proxy],
};

/// `net.proxy`, built from its spec entry.
#[derive(Debug, Clone)]
pub struct ProxyCheck {
    rules: Rules,
}

impl ProxyCheck {
    /// The check for these spec parameters.
    #[must_use]
    pub fn from_params(params: &NetProxy) -> Self {
        Self {
            rules: Rules {
                required_no_proxy: params
                    .required_no_proxy
                    .iter()
                    .flat_map(|list| list.iter())
                    .map(|entry| entry.as_str().to_owned())
                    .collect(),
                daemons_need_proxy: params.daemons_need_proxy,
            },
        }
    }

    /// The static facts, for a family that lists its checks.
    #[must_use]
    pub fn info() -> &'static CheckInfo {
        &INFO
    }

    async fn inspect(&self, ctx: &CheckContext) -> CheckOutcome {
        let mut notes = Vec::new();
        let mut unread = Vec::new();
        let (vars, no_proxy, values) = read_environment(ctx)?;
        let conflicts = env_conflicts(|name| values.get(name).cloned());
        let daemons = if ctx.os() == Os::Linux {
            let mut found = Vec::new();
            for unit in UNITS {
                found.push(read_daemon(ctx, unit, &mut notes, &mut unread).await?);
            }
            found
        } else {
            Vec::new()
        };
        let reach = reach(ctx).await?;
        let facts = Facts {
            os: ctx.os(),
            vars,
            no_proxy,
            conflicts,
            daemons,
            missing_network: matches!(reach, Reach::NotTried(_)),
            reach,
            notes,
            unread,
        };
        Ok(judge(&facts, &self.rules))
    }
}

impl Check for ProxyCheck {
    fn info(&self) -> &'static CheckInfo {
        &INFO
    }

    fn run<'a>(&'a self, ctx: &'a CheckContext) -> BoxFuture<'a, CheckOutcome> {
        Box::pin(self.inspect(ctx))
    }
}

/// The classified proxy variables, the `NO_PROXY` list, and the trimmed non-blank values by name (kept
/// only for the comparison of two spellings, and dropped with the function that asked for them).
type Environment = (
    Vec<(&'static str, Setting)>,
    Option<(&'static str, NoProxy)>,
    HashMap<&'static str, String>,
);

/// Reads the environment through the probe. A raw value goes into `values` for the comparison of two
/// spellings and is never shown.
fn read_environment(ctx: &CheckContext) -> Result<Environment, CheckError> {
    let mut values: HashMap<&'static str, String> = HashMap::new();
    for name in ENV {
        // Windows names are not case sensitive, so the lower-case spelling would read the same value twice.
        if ctx.os() == Os::Windows && name.chars().any(|c| c.is_ascii_lowercase()) {
            continue;
        }
        if let Some(value) = ctx.probe().env(name)? {
            let value = value.trim().to_owned();
            if !value.is_empty() {
                values.insert(*name, value);
            }
        }
    }
    let mut vars = Vec::new();
    for name in PROXY_ENV.iter().chain(&OTHER_PROXY_ENV) {
        if let Some(value) = values.get(name) {
            vars.push((*name, classify(value)));
        }
    }
    for name in &PAC_ENV {
        if let Some(value) = values.get(name) {
            let url = pac_url(value)
                .or_else(|| rdy_engine::redact::evidence_url(value))
                .unwrap_or_else(|| "(an address rdy cannot show)".to_owned());
            vars.push((*name, Setting::Pac(url)));
        }
    }
    let no_proxy = NO_PROXY_ENV
        .iter()
        .find_map(|name| values.get(name).map(|value| (*name, NoProxy::parse(value))));
    Ok((vars, no_proxy, values))
}

/// The settings of one unit: its systemd drop-ins and, for Docker, `daemon.json`.
async fn read_daemon(
    ctx: &CheckContext,
    unit: &'static str,
    notes: &mut Vec<String>,
    unread: &mut Vec<String>,
) -> Result<Daemon, CheckError> {
    let mut daemon = Daemon {
        unit,
        ..Daemon::default()
    };
    for dir in [
        "/etc/systemd/system",
        "/usr/lib/systemd/system",
        "/lib/systemd/system",
    ] {
        let path = format!("{dir}/{unit}.service");
        match ctx.probe().stat(Path::new(&path)).await {
            Ok(Some(_)) => daemon.present = true,
            Ok(None) => {}
            Err(error) => {
                soft(error)?;
            }
        }
    }
    let dir = format!("/etc/systemd/system/{unit}.service.d");
    let entries = match ctx.probe().read_dir(Path::new(&dir)).await {
        Ok(entries) => entries,
        Err(error) => {
            let text = short(&error);
            if !matches!(soft(error)?, ProbeError::NotFound) {
                unread.push(format!("{dir} could not be listed: {text}"));
                daemon.unread = true;
            }
            return daemon_json(ctx, daemon, notes, unread).await;
        }
    };
    daemon.present = true;
    let mut names: Vec<String> = entries
        .into_iter()
        .filter(|entry| !entry.is_dir)
        .map(|entry| entry.name)
        .filter(|name| name.ends_with(".conf") && !name.contains(['/', '\\', '\0']))
        .collect();
    // systemd reads drop-ins in file name order, and a later one overrides an earlier one.
    names.sort_unstable();
    if names.len() > MAX_DROPINS {
        names.truncate(MAX_DROPINS);
        notes.push(format!(
            "Only the first {MAX_DROPINS} drop-ins of {unit} were read."
        ));
    }
    for name in names {
        let path = format!("{dir}/{name}");
        match ctx.probe().read(Path::new(&path)).await {
            Ok(file) => {
                let text = String::from_utf8_lossy(&file.bytes).into_owned();
                apply(&mut daemon, parse_dropin(&text), &path);
            }
            Err(error) => {
                let text = short(&error);
                if !matches!(soft(error)?, ProbeError::NotFound) {
                    unread.push(format!("{path} could not be read: {text}"));
                    daemon.unread = true;
                }
            }
        }
    }
    daemon_json(ctx, daemon, notes, unread).await
}

/// Docker's `daemon.json`, applied after the drop-ins and outside any reset of them: the daemon gives the
/// file precedence over its environment. Nothing of the file but `proxies` is read.
async fn daemon_json(
    ctx: &CheckContext,
    mut daemon: Daemon,
    notes: &mut Vec<String>,
    unread: &mut Vec<String>,
) -> Result<Daemon, CheckError> {
    if daemon.unit == "docker" {
        let path = DAEMON_JSON;
        match ctx.probe().read(Path::new(path)).await {
            Ok(file) => {
                daemon.present = true;
                let text = String::from_utf8_lossy(&file.bytes).into_owned();
                match daemon_json_proxies(&text) {
                    Ok(assigns) => apply(&mut daemon, assigns, path),
                    Err(why) => notes.push(format!("{path} was not read: {why}.")),
                }
            }
            Err(error) => {
                let text = short(&error);
                if !matches!(soft(error)?, ProbeError::NotFound) {
                    unread.push(format!("{path} could not be read: {text}"));
                    daemon.unread = true;
                }
            }
        }
    }
    Ok(daemon)
}

/// Applies the assignments of one file to a daemon. Raw values are classified at once and dropped.
fn apply(daemon: &mut Daemon, assigns: Vec<Assign>, path: &str) {
    let mut touched = false;
    for assign in assigns {
        touched = true;
        match assign {
            Assign::Var(Kind::Http, raw) => daemon.http = Some(classify(&raw)),
            Assign::Var(Kind::Https, raw) => daemon.https = Some(classify(&raw)),
            Assign::Var(Kind::No, raw) => daemon.no_proxy = Some(NoProxy::parse(&raw)),
            Assign::Reset => {
                daemon.http = None;
                daemon.https = None;
                daemon.no_proxy = None;
            }
            Assign::File(file) => {
                if !daemon.env_files.contains(&file) {
                    daemon.env_files.push(file);
                }
                touched = false;
            }
        }
    }
    if touched {
        daemon.sources.push(path.to_owned());
    }
}

/// Opens one TCP connection to the run's proxy, when the run has one and the network is allowed.
async fn reach(ctx: &CheckContext) -> Result<Reach, CheckError> {
    let Some(origin) = ctx.probe().proxy_origin() else {
        return Ok(Reach::NoProxy);
    };
    if !ctx.has(&Need::Network) {
        return Ok(Reach::NotTried("--no-network is set"));
    }
    let budget = ctx.remaining().saturating_sub(RESERVE);
    let failed = |class, why| Reach::Failed {
        origin: origin.clone(),
        class,
        why,
    };
    let Some(result) = ctx.within(budget, ctx.probe().proxy_reach()).await else {
        return Ok(failed("timeout", "no answer in time"));
    };
    Ok(match result {
        Ok(report) if report.connected => Reach::Connected {
            origin: origin.clone(),
            ms: connect_ms(&report),
        },
        Ok(report) => {
            let (class, why) = class_of(&report);
            failed(class, why)
        }
        Err(ProbeError::Net(NetFailure::Dns { .. })) => {
            failed("dns", "its name does not resolve on this machine")
        }
        Err(error) if error.is_no_network() => Reach::NotTried("--no-network is set"),
        Err(ProbeError::Denied { rule, .. })
            if rule == rdy_engine::probe::net::RULE_PROXY_ADDRESS =>
        {
            failed(
                "refused_by_policy",
                "its address is in a range rdy refuses (link-local or metadata)",
            )
        }
        Err(ProbeError::Timeout) => failed("timeout", "no answer in time"),
        Err(error) => match soft(error)? {
            ProbeError::Net(_) | ProbeError::ConnectionRefused => {
                failed("failed", "the connection could not be opened")
            }
            other => return Err(CheckError::Probe(other)),
        },
    })
}

/// When the winning address had connected, in milliseconds from the start of the call.
fn connect_ms(report: &TcpReport) -> u64 {
    report
        .attempts
        .iter()
        .find(|a| a.outcome == AttemptOutcome::Connected)
        .map_or(0, |a| {
            u64::try_from((a.started + a.elapsed).as_millis()).unwrap_or(u64::MAX)
        })
}

/// The class and phrase of a connection that did not open, from its attempts: all silent is a
/// black hole, else the last attempt decides.
fn class_of(report: &TcpReport) -> (&'static str, &'static str) {
    let silent = !report.attempts.is_empty()
        && report
            .attempts
            .iter()
            .all(|a| a.outcome == AttemptOutcome::TimedOut);
    let outcome = if silent {
        AttemptOutcome::TimedOut
    } else {
        report
            .attempts
            .last()
            .map_or(AttemptOutcome::Failed, |a| a.outcome)
    };
    match outcome {
        AttemptOutcome::Refused => ("refused", "connection refused"),
        AttemptOutcome::TimedOut => ("blackhole", "no reply within 3 s"),
        AttemptOutcome::Unreachable => ("unreachable", "no route to the host"),
        AttemptOutcome::Reset => ("reset", "the connection was reset"),
        _ => ("failed", "the connection could not be opened"),
    }
}
