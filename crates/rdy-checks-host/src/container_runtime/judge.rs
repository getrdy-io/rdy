//! The judgement of `host.container_runtime`: a pure function of what was found.
//!
//! Each runtime that is present and that the spec allows gets a list of issues. The spec lists runtimes
//! of which any one will do, so the result takes the best runtime: it passes when one allowed runtime
//! has no issue, and the others' issues become notes. With no allowed runtime present the check fails.

use rdy_engine::check::{Finding, Level, Need, Partial};
use rdy_engine::text::escape_untrusted;
use rdy_engine::units::version_at_least;
use rdy_spec::check::{CgroupDriver, ContainerRuntime};
use rdy_spec::scalar::Version;
use serde_json::{Value, json};

use super::containerd;
use super::files::{Proxy, leading_number};
use super::{ContainerRuntimeCheck, KUBELET_CONFIG, Kubelet};

/// How the API (or the socket) of one runtime answered.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) enum Api {
    /// rdy did not ask: containerd and CRI-O speak gRPC only.
    NotAsked,
    /// `/version` and `/info` were read.
    Read,
    /// The user may not open the socket.
    Denied,
    /// The socket exists and nothing answers.
    NotListening,
    /// It answered with something rdy could not use. The text says what.
    Odd(String),
}

/// A runtime rdy looked for, and everything it learned about it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct Seen {
    pub kind: ContainerRuntime,
    /// The socket of the user rdy runs as, not the system one.
    pub rootless: bool,
    pub socket: String,
    pub socket_present: bool,
    /// The program ran and printed a version.
    pub installed: bool,
    pub api: Api,
    pub version: Option<String>,
    pub cgroup: Option<(CgroupDriver, &'static str)>,
    pub storage: Option<(String, &'static str)>,
    pub d_type: Option<bool>,
    pub rootless_mode: Option<bool>,
    pub proxy: Option<(Proxy, &'static str)>,
    /// The containerd config, for the fix text.
    pub config: Option<containerd::Config>,
    pub notes: Vec<String>,
    /// rdy does not read this runtime's configuration (CRI-O), so an unknown driver is not a warning
    /// against the kubelet alone.
    pub blind: bool,
}

impl Seen {
    pub(super) fn new(kind: ContainerRuntime, rootless: bool, socket: &str) -> Self {
        Self {
            kind,
            rootless,
            socket: socket.to_owned(),
            socket_present: false,
            installed: false,
            api: Api::NotAsked,
            version: None,
            cgroup: None,
            storage: None,
            d_type: None,
            rootless_mode: None,
            proxy: None,
            config: None,
            notes: Vec::new(),
            blind: false,
        }
    }

    pub(super) fn present(&self) -> bool {
        self.socket_present || self.installed
    }

    fn name(&self) -> String {
        let base = word(self.kind);
        if self.rootless {
            format!("{base} (rootless)")
        } else {
            base.to_owned()
        }
    }

    /// The name with the version, `containerd 1.7.13`.
    fn named(&self) -> String {
        match &self.version {
            Some(v) => format!("{} {}", self.name(), escape_untrusted(v)),
            None => self.name(),
        }
    }

    /// Whether the daemon is known to be up: the API answered, or a gRPC socket is there.
    fn up(&self) -> bool {
        match self.api {
            Api::Read => true,
            Api::NotAsked => self.socket_present,
            _ => false,
        }
    }

    fn unit(&self) -> &'static str {
        match self.kind {
            ContainerRuntime::Docker => "docker",
            ContainerRuntime::Containerd => "containerd",
            ContainerRuntime::Podman => "podman.socket",
            ContainerRuntime::Crio => "crio",
            _ => "docker",
        }
    }
}

/// The spec word and the name used in sentences.
pub(super) fn word(kind: ContainerRuntime) -> &'static str {
    match kind {
        ContainerRuntime::Docker => "docker",
        ContainerRuntime::Containerd => "containerd",
        ContainerRuntime::Podman => "podman",
        ContainerRuntime::Crio => "CRI-O",
        _ => "a runtime",
    }
}

pub(super) fn driver_text(driver: CgroupDriver) -> &'static str {
    match driver {
        CgroupDriver::Systemd => "systemd",
        _ => "cgroupfs",
    }
}

#[derive(Debug, Clone)]
struct Issue {
    level: Level,
    text: String,
    fix: Option<String>,
}

impl Issue {
    fn new(level: Level, text: String, fix: impl Into<Option<String>>) -> Self {
        Self {
            level,
            text,
            fix: fix.into(),
        }
    }
}

fn severity(level: Level) -> u8 {
    match level {
        Level::Pass => 0,
        Level::Warn => 1,
        _ => 2,
    }
}

fn worst(issues: &[Issue]) -> Level {
    issues
        .iter()
        .map(|i| i.level)
        .max_by_key(|l| severity(*l))
        .unwrap_or(Level::Pass)
}

/// Whether two storage driver names mean the same thing. containerd calls overlay `overlayfs`.
pub(super) fn same_storage(have: &str, want: &str) -> bool {
    let overlay = |s: &str| matches!(s.to_ascii_lowercase().as_str(), "overlay2" | "overlayfs");
    have.eq_ignore_ascii_case(want) || (overlay(have) && overlay(want))
}

fn parsed(text: &str) -> Option<Version> {
    leading_number(text).and_then(|n| Version::parse(n).ok())
}

/// The fix that makes `seen` use `target`, or `None` when it already does.
fn runtime_cgroup_fix(seen: &Seen, target: CgroupDriver) -> String {
    let to = driver_text(target);
    match seen.kind {
        ContainerRuntime::Containerd => containerd_fix(seen, target),
        ContainerRuntime::Docker => format!(
            "Set `\"exec-opts\": [\"native.cgroupdriver={to}\"]` in /etc/docker/daemon.json, then run `systemctl restart docker`."
        ),
        ContainerRuntime::Podman => format!(
            "Set `cgroup_manager = \"{to}\"` under [engine] in /etc/containers/containers.conf."
        ),
        ContainerRuntime::Crio => format!(
            "Set `cgroup_manager = \"{to}\"` in a file under /etc/crio/crio.conf.d/, then run `systemctl restart crio`."
        ),
        _ => format!("Set the {to} cgroup driver in the runtime's configuration."),
    }
}

fn containerd_fix(seen: &Seen, target: CgroupDriver) -> String {
    let value = matches!(target, CgroupDriver::Systemd);
    let fallback = containerd::built_in(None);
    let config = seen.config.as_ref().unwrap_or(&fallback);
    let table = containerd::table_name(config.version);
    let name = &config.runtime_name;
    let place = format!("[plugins.\"{table}\".containerd.runtimes.{name}.options]");
    let mut text = String::new();
    if !config.from_file {
        text.push_str(
            "Run `containerd config default | sudo tee /etc/containerd/config.toml` to write the default file. ",
        );
    }
    if let Some(other) = config.misplaced {
        text.push_str(&format!(
            "SystemdCgroup is set under plugins.\"{other}\", which a version {} file does not read. Move it to {place}. ",
            config.version
        ));
    } else {
        text.push_str(&format!(
            "Set `SystemdCgroup = {value}` under `{place}` in /etc/containerd/config.toml. "
        ));
    }
    text.push_str("Then run `systemctl restart containerd`.");
    text
}

/// How to read a setting rdy could not, by runtime.
fn read_fix(seen: &Seen, what: &str) -> String {
    match seen.kind {
        ContainerRuntime::Docker => format!(
            "Read the {what} from the output of docker info and check it matches the spec and the kubelet."
        ),
        ContainerRuntime::Containerd => format!(
            "Check the {what} in /etc/containerd/config.toml and in the files it imports (fix the file first if it is not valid TOML), and check it matches the spec and the kubelet."
        ),
        ContainerRuntime::Crio => format!(
            "Check the {what} in /etc/crio/crio.conf and /etc/crio/crio.conf.d/, and check it matches the spec and the kubelet."
        ),
        _ => format!(
            "Check the {what} in /etc/containers/containers.conf and /etc/containers/storage.conf, and check it matches the spec and the kubelet."
        ),
    }
}

fn kubelet_fix(target: CgroupDriver) -> String {
    format!(
        "Set `cgroupDriver: {}` in {KUBELET_CONFIG}, then run `systemctl restart kubelet`.",
        driver_text(target)
    )
}

fn start_fix(seen: &Seen) -> String {
    format!("Run `systemctl enable --now {}`.", seen.unit())
}

fn issues(check: &ContainerRuntimeCheck, seen: &Seen, kubelet: &Kubelet) -> Vec<Issue> {
    let name = seen.named();
    let mut out = Vec::new();

    // State first: the other judgements need a daemon that answered.
    match &seen.api {
        Api::Read | Api::NotAsked if seen.socket_present => {}
        Api::NotAsked => out.push(Issue::new(
            Level::Warn,
            format!("{name} is installed but its socket {} is missing, so it is not running.", seen.socket),
            start_fix(seen),
        )),
        Api::Denied => out.push(Issue::new(
            Level::Warn,
            format!("{name} is present, but this user may not open its socket {}, so rdy could not read its settings.", seen.socket),
            if seen.kind == ContainerRuntime::Docker {
                "Add the user to the docker group with `usermod -aG docker USER` and log in again, or run rdy as root."
            } else {
                "Run rdy as root, or as a user who may open the socket."
            }
            .to_owned(),
        )),
        Api::NotListening => out.push(Issue::new(
            Level::Warn,
            format!("{name} has a socket at {} but nothing answers on it.", seen.socket),
            format!("Run `systemctl restart {}` and check `systemctl status {}`.", seen.unit(), seen.unit()),
        )),
        Api::Odd(why) => out.push(Issue::new(
            Level::Warn,
            format!("{name} answered on {} with something rdy could not read ({}).", seen.socket, escape_untrusted(why)),
            format!("Check the daemon with `systemctl status {}`.", seen.unit()),
        )),
        Api::Read => {}
    }
    let state_issue = !out.is_empty();

    if let (Some(min), Some([only])) = (&check.min_version, check.runtimes.as_deref())
        && *only == seen.kind
        && !state_issue
    {
        match seen.version.as_deref().and_then(parsed) {
            Some(have) if !version_at_least(&have, min) => out.push(Issue::new(
                Level::Fail,
                format!("{name} is older than the {} the spec needs.", min.as_str()),
                format!(
                    "Upgrade {} to {} or later with your package manager, then run `systemctl restart {}`.",
                    word(seen.kind),
                    min.as_str(),
                    seen.unit()
                ),
            )),
            Some(_) => {}
            None => out.push(Issue::new(
                Level::Warn,
                format!("rdy could not read the version of {}, so the minimum {} is not verified.", seen.name(), min.as_str()),
                format!("Run the runtime's own version command and check it is {} or later.", min.as_str()),
            )),
        }
    }

    out.extend(cgroup_issues(check, seen, kubelet, state_issue));
    out.extend(storage_issues(check, seen, state_issue));

    if seen.d_type == Some(false) {
        out.push(Issue::new(
            Level::Fail,
            format!(
                "{name} keeps its images on a file system without d_type support, which overlay storage needs."
            ),
            "Move `data-root` in /etc/docker/daemon.json (default /var/lib/docker) to an ext4 volume, or to an XFS volume made with ftype=1, then run `systemctl restart docker`. The output of docker info must show Supports d_type true.".to_owned(),
        ));
    }
    out
}

fn cgroup_issues(
    check: &ContainerRuntimeCheck,
    seen: &Seen,
    kubelet: &Kubelet,
    state_issue: bool,
) -> Vec<Issue> {
    let name = seen.named();
    let target = check.cgroup_driver.unwrap_or(CgroupDriver::Systemd);
    let Some((have, _)) = seen.cgroup else {
        // Only a spec that asks for a driver makes an unknown one a warning. Against the kubelet alone
        // it is a note on the runtime (CRI-O's configuration is not read), so a healthy node is not
        // flagged for what rdy cannot see.
        let asks = check.cgroup_driver.is_some() || (kubelet.driver.is_some() && !seen.blind);
        if asks && !state_issue {
            return vec![Issue::new(
                Level::Warn,
                format!(
                    "rdy could not read the cgroup driver of {}, so it is not verified.",
                    seen.name()
                ),
                read_fix(seen, "cgroup driver"),
            )];
        }
        return Vec::new();
    };
    let mut out = Vec::new();
    let mut steps = Vec::new();
    if let Some(want) = check.cgroup_driver
        && have != want
    {
        out.push((
            Level::Fail,
            format!(
                "{name} uses the {} cgroup driver, the spec needs {}.",
                driver_text(have),
                driver_text(want)
            ),
        ));
    }
    if let Some(k) = kubelet.driver
        && have != k
    {
        out.push((
            Level::Fail,
            format!(
                "{name} uses the {} cgroup driver but the kubelet uses {}.",
                driver_text(have),
                driver_text(k)
            ),
        ));
    }
    if out.is_empty() {
        return Vec::new();
    }
    if have != target {
        steps.push(runtime_cgroup_fix(seen, target));
    }
    if kubelet.driver.is_some_and(|k| k != target) {
        steps.push(kubelet_fix(target));
    }
    let fix = steps.join(" ");
    let mut issues: Vec<Issue> = out
        .into_iter()
        .map(|(level, text)| Issue::new(level, text, None))
        .collect();
    if let Some(first) = issues.first_mut() {
        first.fix = Some(fix);
    }
    issues
}

fn storage_issues(check: &ContainerRuntimeCheck, seen: &Seen, state_issue: bool) -> Vec<Issue> {
    let Some(want) = check.storage_driver.as_deref() else {
        return Vec::new();
    };
    match &seen.storage {
        Some((have, _)) if same_storage(have, want) => Vec::new(),
        Some((have, _)) => {
            let fix = match seen.kind {
                ContainerRuntime::Containerd => format!(
                    "Set `snapshotter = \"overlayfs\"` in the CRI table of /etc/containerd/config.toml (the {} table for a version {} file), then run `systemctl restart containerd`. Existing images are not moved.",
                    seen.config
                        .as_ref()
                        .map_or("io.containerd.grpc.v1.cri", |c| containerd::table_name(
                            c.version
                        )),
                    seen.config.as_ref().map_or(2, |c| c.version)
                ),
                _ => format!(
                    "Set `\"storage-driver\": \"{}\"` in /etc/docker/daemon.json, then run `systemctl restart docker`. Existing images are not moved.",
                    escape_untrusted(want)
                ),
            };
            vec![Issue::new(
                Level::Fail,
                format!(
                    "{} uses the {} storage driver, the spec needs {}.",
                    seen.named(),
                    escape_untrusted(have),
                    escape_untrusted(want)
                ),
                fix,
            )]
        }
        None if !state_issue => vec![Issue::new(
            Level::Warn,
            format!(
                "rdy could not read the storage driver of {}, so {} is not verified.",
                seen.name(),
                escape_untrusted(want)
            ),
            read_fix(seen, "storage driver"),
        )],
        None => Vec::new(),
    }
}

/// One sentence about a runtime that passed.
fn summary(seen: &Seen) -> String {
    let mut parts = Vec::new();
    if let Some((driver, _)) = seen.cgroup {
        parts.push(format!("cgroup driver {}", driver_text(driver)));
    }
    if let Some((storage, _)) = &seen.storage {
        parts.push(format!("storage driver {}", escape_untrusted(storage)));
    }
    let state = if seen.up() {
        "is running"
    } else {
        "is present"
    };
    if parts.is_empty() {
        format!("{} {state}.", seen.named())
    } else {
        format!("{} {state} ({}).", seen.named(), parts.join(", "))
    }
}

fn list_text(words: &[&str]) -> String {
    match words {
        [] => String::new(),
        [one] => (*one).to_owned(),
        [init @ .., last] => format!("{} or {last}", init.join(", ")),
    }
}

fn proxy_json(proxy: &(Proxy, &'static str)) -> Value {
    json!({
        "source": proxy.1,
        "http": proxy.0.http,
        "https": proxy.0.https,
        "no_proxy": proxy.0.no_proxy,
    })
}

fn observed(seen: &[Seen], kubelet: &Kubelet) -> Value {
    let runtimes: Vec<Value> = seen
        .iter()
        .filter(|s| s.present())
        .map(|s| {
            json!({
                "runtime": word(s.kind),
                "rootless_socket": s.rootless,
                "socket": s.socket,
                "socket_present": s.socket_present,
                "installed": s.installed,
                "api": match &s.api {
                    Api::NotAsked => "not asked",
                    Api::Read => "read",
                    Api::Denied => "permission denied",
                    Api::NotListening => "not listening",
                    Api::Odd(_) => "unreadable reply",
                },
                "version": s.version,
                "cgroup_driver": s.cgroup.map(|(d, _)| driver_text(d)),
                "cgroup_driver_source": s.cgroup.map(|(_, src)| src),
                "storage_driver": s.storage.as_ref().map(|(d, _)| d),
                "storage_driver_source": s.storage.as_ref().map(|(_, src)| *src),
                "d_type": s.d_type,
                "rootless": s.rootless_mode,
                "proxy": s.proxy.as_ref().map(proxy_json),
                "config_version": s.config.as_ref().filter(|c| c.from_file).map(|c| c.version),
            })
        })
        .collect();
    json!({
        "runtimes": runtimes,
        "kubelet": {
            "config_present": kubelet.present,
            "cgroup_driver": kubelet.driver.map(driver_text),
        },
    })
}

fn expected(check: &ContainerRuntimeCheck) -> Value {
    json!({
        "runtime": check
            .runtimes
            .as_ref()
            .map(|list| list.iter().map(|r| word(*r)).collect::<Vec<_>>()),
        "min_version": check.min_version.as_ref().map(Version::as_str),
        "cgroup_driver": check.cgroup_driver.map(driver_text),
        "storage_driver": check.storage_driver,
    })
}

/// Joins the issue sentences, at most three, then counts the rest.
fn sentences(issues: &[Issue]) -> String {
    let mut text: Vec<String> = issues.iter().take(3).map(|i| i.text.clone()).collect();
    if issues.len() > 3 {
        text.push(format!(
            "{} more problems are in the notes.",
            issues.len() - 3
        ));
    }
    text.join(" ")
}

/// Unique fixes in order, joined.
fn fixes(issues: &[Issue]) -> Option<String> {
    let mut seen: Vec<&str> = Vec::new();
    for fix in issues.iter().filter_map(|i| i.fix.as_deref()) {
        if !seen.contains(&fix) {
            seen.push(fix);
        }
    }
    (!seen.is_empty()).then(|| seen.join(" "))
}

/// The result for what was found.
pub(super) fn judge(
    check: &ContainerRuntimeCheck,
    seen: &[Seen],
    kubelet: &Kubelet,
    root: bool,
) -> Finding {
    let found: Vec<&Seen> = seen.iter().filter(|s| s.present()).collect();
    let allowed: Vec<&Seen> = found
        .iter()
        .copied()
        .filter(|s| check.runtimes.as_ref().is_none_or(|l| l.contains(&s.kind)))
        .collect();

    let mut notes: Vec<String> = Vec::new();
    for s in &found {
        for note in &s.notes {
            notes.push(format!("{}: {}", s.name(), escape_untrusted(note)));
        }
        if let Some((proxy, source)) = &s.proxy
            && !proxy.is_empty()
        {
            notes.push(format!(
                "{} has a proxy set in {source}. Image pulls go through it, so check that it can reach the registry and that no_proxy lists the cluster addresses.",
                s.name()
            ));
        }
    }
    if let Some(why) = &kubelet.unreadable {
        notes.push(format!(
            "The kubelet config {KUBELET_CONFIG} could not be read ({}), so the runtime's cgroup driver was not compared with the kubelet's.",
            escape_untrusted(why)
        ));
    }

    let mut finding = if allowed.is_empty() {
        none_allowed(check, &found)
    } else {
        let results: Vec<(&Seen, Vec<Issue>)> = allowed
            .iter()
            .map(|s| (*s, issues(check, s, kubelet)))
            .collect();
        // The first runtime with the least severe worst issue. `min_by_key` keeps the first of equals.
        let best = results
            .iter()
            .enumerate()
            .min_by_key(|(_, (_, list))| severity(worst(list)))
            .map_or(0, |(i, _)| i);
        for (i, (s, list)) in results.iter().enumerate() {
            if i != best && !list.is_empty() {
                notes.push(format!("{}: {}", s.name(), sentences(list)));
            }
        }
        let (chosen, list) = &results[best];
        let level = worst(list);
        if level == Level::Pass {
            Finding::pass(summary(chosen))
        } else {
            let mut f = Finding::new(level, sentences(list));
            if let Some(fix) = fixes(list) {
                f = f.with_fix(fix);
            }
            f
        }
    };

    finding = finding
        .with_observed(observed(seen, kubelet))
        .with_expected(expected(check));
    for note in notes {
        finding = finding.with_note(note);
    }

    let denied = allowed.iter().any(|s| s.api == Api::Denied);
    if !root && (denied || kubelet.unreadable.is_some()) {
        let engine_api = allowed.iter().any(|s| {
            s.api == Api::Denied
                && matches!(s.kind, ContainerRuntime::Docker | ContainerRuntime::Podman)
        });
        let note = if engine_api {
            "Runtime present, API not readable; add the user to the docker group or run as root."
        } else if denied {
            "Runtime present, socket not readable; run as root."
        } else {
            "The kubelet config could not be read; run as root to compare cgroup drivers."
        };
        finding = finding.with_partial(Partial::new(vec![Need::Root], note));
    }
    finding
}

/// The result when no allowed runtime is present.
fn none_allowed(check: &ContainerRuntimeCheck, found: &[&Seen]) -> Finding {
    let wanted: Vec<&str> = check
        .runtimes
        .as_ref()
        .map(|l| l.iter().map(|r| word(*r)).collect())
        .unwrap_or_default();
    let other: Vec<&str> = found.iter().map(|s| word(s.kind)).collect();
    let message = match (wanted.is_empty(), other.is_empty()) {
        (_, true) if wanted.is_empty() => "No container runtime was found. rdy looked for the Docker, containerd, Podman and CRI-O sockets.".to_owned(),
        (_, true) => format!(
            "No allowed container runtime was found. The spec needs {}.",
            list_text(&wanted)
        ),
        _ => format!(
            "The spec needs {}, but only {} was found.",
            list_text(&wanted),
            list_text(&other)
        ),
    };
    let pick = check
        .runtimes
        .as_ref()
        .and_then(|l| l.first().copied())
        .unwrap_or(ContainerRuntime::Containerd);
    let unit = Seen::new(pick, false, "").unit();
    let fix = if wanted.is_empty() {
        "Install a container runtime the vendor supports with your package manager, then start it. For containerd, run `systemctl enable --now containerd`.".to_owned()
    } else {
        format!(
            "Install {} with your package manager, then run `systemctl enable --now {unit}`.",
            list_text(&wanted)
        )
    };
    Finding::fail(message).with_fix(fix)
}
