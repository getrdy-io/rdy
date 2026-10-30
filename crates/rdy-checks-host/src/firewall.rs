//! `host.firewall`: is a host firewall active, and does it let the product's inbound ports through.
//!
//! Linux only. M1 reads firewalld (zone listing and service files) and ufw (config and rule tuples).
//! Rules written straight into nftables or iptables are not read yet (M2-050), and the result says so.
//!
//! The judgement is a pure function of text. Each source is read through the probe, parsed by a small
//! module (`firewalld`, `service`, `ufw`, `route`), and the verdicts for every requested port are
//! assembled into one finding. Closed is only reported when the text proves it. Anything the listing
//! cannot settle (a rich rule that touches the port, a service file that is missing, rules that need
//! root) is "unknown" and gives a warning.

use std::path::Path;
use std::time::Duration;

use rdy_engine::check::{
    BoxFuture, Check, CheckContext, CheckError, CheckInfo, CheckMeta, CheckOutcome, CommandSpec,
    Finding, Level, Need, Os, Partial,
};
use rdy_engine::exec::policy::PolicyError;
use rdy_engine::exec::table::{self, ExitClass, Param};
use rdy_engine::probe::ProbeError;
use serde_json::{Map, Value, json};

use crate::family::{OS, ROOT};
use crate::text::{short, soft};

mod firewalld;
mod ports;
mod route;
mod service;
mod ufw;

#[cfg(test)]
mod tests;
#[cfg(test)]
mod unit_tests;

/// What the check says on an OS it has no data source for.
const NO_SOURCE: &str =
    "this check reads Linux firewall files and has no data source on this OS yet";

/// firewalld creates this directory when its daemon starts.
const RUN_FIREWALLD: &str = "/run/firewalld";
const UFW_CONF: &str = "/etc/ufw/ufw.conf";
const UFW_DEFAULTS: &str = "/etc/default/ufw";
const UFW_RULES: &str = "/etc/ufw/user.rules";
/// Direct rules (raw iptables or nftables rules handed to firewalld) that survive a reload.
const DIRECT_XML: &str = "/etc/firewalld/direct.xml";
/// The tags in `direct.xml` that add a rule: a firewalld-form `<rule>` and a raw iptables `<passthrough>`.
const DIRECT_TAGS: &[&str] = &["rule", "passthrough"];
const ROUTE_V4: &str = "/proc/net/route";
const ROUTE_V6: &str = "/proc/net/ipv6_route";

/// The most ports a run checks. The spec parameter allows no more.
const MAX_PORTS: usize = 256;
/// The most ports listed in one sentence before the rest are counted.
const LIST_PORTS: usize = 8;

/// The static facts about `host.firewall` (03 section 2).
pub(crate) static INFO: CheckInfo = CheckInfo {
    id: "host.firewall",
    family: "host",
    summary: "Host firewall active, inbound ports allowed",
    meta: CheckMeta {
        title: "Host firewall",
        remediation: "Open the product's inbound ports in the host firewall. On firewalld, run `firewall-cmd --permanent --add-port=6443/tcp && firewall-cmd --reload`, with your port and the zone of the default-route interface. On ufw, run `ufw allow 6443/tcp`. If rdy could not read the rules, run it as root or check the rules by hand.",
    },
    needs: &[],
    wants: ROOT,
    default_timeout: Some(Duration::from_secs(5)),
    os: OS,
    reads: &[
        RUN_FIREWALLD,
        "/etc/firewalld/services",
        "/usr/lib/firewalld/services",
        DIRECT_XML,
        UFW_CONF,
        UFW_DEFAULTS,
        UFW_RULES,
        ROUTE_V4,
        ROUTE_V6,
    ],
    statfs: &[],
    env: &[],
    commands: &[CommandSpec {
        program: "firewall-cmd",
        extra_dirs: &[],
        max_stdout: 1024 * 1024,
        env: &[],
    }],
    peers: &[],
};

/// What a firewall does with inbound TCP on one port.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum Verdict {
    /// Let through. The text says by which rule.
    Open(String),
    /// Refused, and the text proves it.
    Closed(String),
    /// The text cannot settle it. The reason says why.
    Unknown(String),
}

impl Verdict {
    fn word(&self) -> &'static str {
        match self {
            Self::Open(_) => "open",
            Self::Closed(_) => "closed",
            Self::Unknown(_) => "unknown",
        }
    }

    fn detail(&self) -> &str {
        match self {
            Self::Open(t) | Self::Closed(t) | Self::Unknown(t) => t,
        }
    }
}

/// What one firewall manager said about every requested port.
#[derive(Debug, Clone, PartialEq, Eq)]
struct Inspection {
    manager: &'static str,
    zone: Option<String>,
    interface: Option<String>,
    verdicts: Vec<(u16, Verdict)>,
    notes: Vec<String>,
    /// The needs whose absence kept rdy from reading the rules.
    missing: Vec<Need>,
}

impl Inspection {
    fn new(manager: &'static str) -> Self {
        Self {
            manager,
            zone: None,
            interface: None,
            verdicts: Vec::new(),
            notes: Vec::new(),
            missing: Vec::new(),
        }
    }

    /// Every port is unknown for the same reason.
    fn cannot(manager: &'static str, ports: &[u16], why: &str, missing: Vec<Need>) -> Self {
        let mut this = Self::new(manager);
        this.verdicts = ports
            .iter()
            .map(|p| (*p, Verdict::Unknown(why.to_owned())))
            .collect();
        this.missing = missing;
        this
    }

    fn with_note(mut self, note: &str) -> Self {
        self.notes.push(note.to_owned());
        self
    }

    fn ports_with(&self, wanted: fn(&Verdict) -> bool) -> Vec<u16> {
        self.verdicts
            .iter()
            .filter(|(_, v)| wanted(v))
            .map(|(p, _)| *p)
            .collect()
    }
}

/// `host.firewall`.
///
/// Built from the ports the spec wants open (`open_inbound`, TCP). With none, it reports which manager
/// is active and passes.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Firewall {
    ports: Vec<u16>,
}

impl Firewall {
    /// A check for these inbound TCP ports. Duplicates and port 0 are dropped, and at most 256 are kept.
    #[must_use]
    pub fn new(open_inbound: impl IntoIterator<Item = u16>) -> Self {
        let mut ports: Vec<u16> = open_inbound.into_iter().filter(|p| *p != 0).collect();
        ports.sort_unstable();
        ports.dedup();
        ports.truncate(MAX_PORTS);
        Self { ports }
    }

    /// The ports this check looks at, sorted.
    #[must_use]
    pub fn ports(&self) -> &[u16] {
        &self.ports
    }

    async fn inspect(&self, ctx: &CheckContext) -> CheckOutcome {
        if ctx.os() != Os::Linux {
            return Err(CheckError::Unsupported(NO_SOURCE));
        }
        let root = ctx.has(&Need::Root);
        let mut found = Vec::new();
        found.extend(self.firewalld(ctx, root).await?);
        found.extend(self.ufw(ctx, root).await?);
        Ok(assemble(&self.ports, &found))
    }

    /// firewalld, or `None` when it is not running.
    async fn firewalld(
        &self,
        ctx: &CheckContext,
        root: bool,
    ) -> Result<Option<Inspection>, CheckError> {
        let probe = ctx.probe();
        match probe.stat(Path::new(RUN_FIREWALLD)).await {
            Ok(Some(_)) => {}
            Ok(None) | Err(ProbeError::NotFound) => return Ok(None),
            // Cannot tell from the directory: ask the daemon.
            Err(error) => {
                soft(error)?;
            }
        }
        match firewall_cmd(ctx, "state", &[]).await? {
            Ran::Exit(ExitClass::Ok, _) => {}
            Ran::Exit(ExitClass::NotRunning, _) => return Ok(None),
            Ran::Exit(..) => {
                return Ok(Some(
                    self.cannot("firewall-cmd --state gave an answer rdy does not know"),
                ));
            }
            Ran::Absent => {
                let mut found = Inspection::cannot(
                    "firewalld",
                    &self.ports,
                    "firewalld is running but the firewall-cmd program was not found",
                    vec![Need::Command("firewall-cmd")],
                );
                found.notes.push("firewalld is running".to_owned());
                return Ok(Some(found));
            }
            Ran::Odd(why) => {
                return Ok(Some(
                    self.cannot(&format!("firewall-cmd --state failed: {why}")),
                ));
            }
        }
        if self.ports.is_empty() {
            return Ok(Some(
                Inspection::new("firewalld")
                    .with_note("firewalld is running; the spec names no ports"),
            ));
        }
        if !root {
            return Ok(Some(
                Inspection::cannot(
                    "firewalld",
                    &self.ports,
                    "firewalld is running and its rules need root to read",
                    vec![Need::Root],
                )
                .with_note("firewalld is running"),
            ));
        }
        let found = Inspection::new("firewalld").with_note(
            "firewalld policies, direct rules added only at runtime and rules written outside firewalld are not read",
        );
        Ok(Some(self.firewalld_rules(ctx, found).await?))
    }

    fn cannot(&self, why: &str) -> Inspection {
        Inspection::cannot("firewalld", &self.ports, why, Vec::new())
    }

    /// The zone of the default-route interface, its listing, and a verdict per port.
    async fn firewalld_rules(
        &self,
        ctx: &CheckContext,
        mut found: Inspection,
    ) -> Result<Inspection, CheckError> {
        let probe = ctx.probe();
        let zones = match firewall_cmd(ctx, "active-zones", &[]).await? {
            Ran::Exit(ExitClass::Ok, out) => {
                firewalld::parse_active_zones(&String::from_utf8_lossy(&out))
            }
            Ran::Odd(why) => {
                return Ok(self.cannot(&format!("firewall-cmd --get-active-zones failed: {why}")));
            }
            _ => return Ok(self.cannot("firewall-cmd --get-active-zones gave no zones")),
        };
        let iface = default_interface(ctx).await?;
        let zone = match pick_zone(&zones.zones, iface.as_deref()) {
            Ok(picked) => picked,
            Err(why) => return Ok(self.cannot(&why)),
        };
        found.interface.clone_from(&iface);
        if let Some(note) = &zone.note {
            found.notes.push(note.clone());
        }
        let name = zone.zone.name.clone();
        found.zone = Some(name.clone());
        if Param::Zone.validate(&name).is_err() {
            return Ok(
                self.cannot("the zone name has characters rdy does not pass to firewall-cmd")
            );
        }
        let listing = match firewall_cmd(ctx, "list-all", &[&name]).await? {
            Ran::Exit(ExitClass::Ok, out) => String::from_utf8_lossy(&out).into_owned(),
            Ran::Odd(why) => {
                return Ok(self.cannot(&format!("firewall-cmd --list-all failed: {why}")));
            }
            _ => return Ok(self.cannot("firewall-cmd --list-all gave no listing")),
        };
        let Some(parsed) = firewalld::parse_zone(&listing) else {
            return Ok(self.cannot("the zone listing was not in the form rdy reads"));
        };
        let services = service::load(probe, firewalld::service_names(&parsed))
            .await
            .map_err(CheckError::Probe)?;
        found.verdicts = self
            .ports
            .iter()
            .map(|p| (*p, firewalld::judge(&parsed, &services, *p)))
            .collect();
        if let Some(why) = self.direct_rules(ctx).await? {
            for (_, verdict) in &mut found.verdicts {
                *verdict = Verdict::Unknown(why.clone());
            }
        }
        demote_closed(&mut found, &zones, &name);
        if !parsed.rich_rules.is_empty() {
            found.notes.push(format!(
                "zone {name} has {} rich rule(s)",
                parsed.rich_rules.len()
            ));
        }
        Ok(found)
    }

    /// Why direct rules make every answer unknown: `/etc/firewalld/direct.xml` holds a rule or a passthrough, or could
    /// not be read to the end. `None` when it is absent or holds no rule.
    async fn direct_rules(&self, ctx: &CheckContext) -> Result<Option<String>, CheckError> {
        Ok(match read_text(ctx, DIRECT_XML).await? {
            Read::Absent => None,
            Read::Text(xml) => match service::has_tag(&xml, DIRECT_TAGS) {
                Ok(true) => Some(format!(
                    "{DIRECT_XML} holds direct rules, which rdy does not evaluate"
                )),
                Ok(false) => None,
                Err(why) => Some(format!("{DIRECT_XML} {why}")),
            },
            Read::Unreadable(why) => Some(format!("{DIRECT_XML} could not be read ({why})")),
        })
    }

    /// ufw, or `None` when it is not enabled.
    async fn ufw(&self, ctx: &CheckContext, root: bool) -> Result<Option<Inspection>, CheckError> {
        let enabled = match read_text(ctx, UFW_CONF).await? {
            Read::Text(conf) => ufw::enabled(&conf),
            Read::Absent => return Ok(None),
            Read::Unreadable(why) => {
                return Ok(Some(Inspection::cannot(
                    "ufw",
                    &self.ports,
                    &format!("/etc/ufw/ufw.conf could not be read ({why})"),
                    Vec::new(),
                )));
            }
        };
        if enabled != Some(true) {
            return Ok(None);
        }
        let note = "ufw is enabled; before.rules, after.rules and user6.rules are not read";
        if self.ports.is_empty() {
            return Ok(Some(Inspection::new("ufw").with_note(note)));
        }
        if !root {
            return Ok(Some(
                Inspection::cannot(
                    "ufw",
                    &self.ports,
                    "ufw is enabled and its rules need root to read",
                    vec![Need::Root],
                )
                .with_note("ufw is enabled"),
            ));
        }
        let policy = match read_text(ctx, UFW_DEFAULTS).await? {
            Read::Text(text) => ufw::default_input(&text),
            Read::Absent | Read::Unreadable(_) => ufw::Policy::Unknown,
        };
        let rules = match read_text(ctx, UFW_RULES).await? {
            Read::Text(text) => ufw::parse_user_rules(&text),
            Read::Absent => Vec::new(),
            Read::Unreadable(why) => {
                return Ok(Some(
                    ufw_rules_unreadable(&self.ports, &why).with_note(note),
                ));
            }
        };
        let iface = default_interface(ctx).await?;
        let mut found = Inspection::new("ufw").with_note(note);
        found.interface.clone_from(&iface);
        found.verdicts = self
            .ports
            .iter()
            .map(|p| (*p, ufw::judge(&rules, policy, iface.as_deref(), *p)))
            .collect();
        Ok(Some(found))
    }
}

impl Check for Firewall {
    fn info(&self) -> &'static CheckInfo {
        &INFO
    }

    fn run<'a>(&'a self, ctx: &'a CheckContext) -> BoxFuture<'a, CheckOutcome> {
        Box::pin(self.inspect(ctx))
    }
}

/// What reading a text file gave.
enum Read {
    Text(String),
    Absent,
    Unreadable(String),
}

async fn read_text(ctx: &CheckContext, path: &str) -> Result<Read, CheckError> {
    match ctx.probe().read(Path::new(path)).await {
        Ok(file) => Ok(Read::Text(
            String::from_utf8_lossy(&file.bytes).into_owned(),
        )),
        Err(error) => match soft(error)? {
            ProbeError::NotFound => Ok(Read::Absent),
            other => Ok(Read::Unreadable(short(&other))),
        },
    }
}

/// The interface of the default route. `None` when the tables are missing or have no default.
async fn default_interface(ctx: &CheckContext) -> Result<Option<String>, CheckError> {
    let v4 = read_text(ctx, ROUTE_V4).await?;
    let v6 = read_text(ctx, ROUTE_V6).await?;
    let text = |read: &Read| match read {
        Read::Text(t) => Some(t.clone()),
        Read::Absent | Read::Unreadable(_) => None,
    };
    Ok(route::default_interface(
        text(&v4).as_deref(),
        text(&v6).as_deref(),
    ))
}

/// What running `firewall-cmd` gave.
enum Ran {
    /// It ran and exited with a code the table gives a meaning.
    Exit(ExitClass, Vec<u8>),
    /// It ran and the result is not usable. The text says why.
    Odd(String),
    /// The program does not exist on this machine.
    Absent,
}

async fn firewall_cmd(ctx: &CheckContext, form: &str, params: &[&str]) -> Result<Ran, CheckError> {
    let failed = || CheckError::Failed {
        message: "firewall-cmd is not in rdy's command table".to_owned(),
        hint: "Tell the vendor which rdy version this is.".to_owned(),
    };
    let entry = table::entry("firewall-cmd").ok_or_else(failed)?;
    let cmd = entry
        .cmd_for(ctx.os(), form, params)
        .map_err(|e| CheckError::Probe(ProbeError::Table(e)))?;
    let out = match ctx.probe().exec(cmd).await {
        Ok(out) => out,
        Err(error) => {
            // The live runner reports a program that is not on the search path as a policy
            // `NotFound`, not as a probe `NotFound`. Both mean the program is not installed.
            if matches!(error, ProbeError::Policy(PolicyError::NotFound { .. })) {
                return Ok(Ran::Absent);
            }
            return match soft(error)? {
                ProbeError::NotFound => Ok(Ran::Absent),
                other => Ok(Ran::Odd(short(&other))),
            };
        }
    };
    let Some(code) = out.exit else {
        return Ok(Ran::Odd("it was ended by a signal".to_owned()));
    };
    match entry.form(form).and_then(|f| f.classify(code)) {
        Some(class) => Ok(Ran::Exit(class, out.stdout)),
        None => Ok(Ran::Odd(format!("it exited with code {code}"))),
    }
}

/// Every port is unknown because `user.rules` could not be read. This runs only as root, so the answer
/// does not ask for root again: a security module or a user namespace is the more likely cause.
fn ufw_rules_unreadable(ports: &[u16], why: &str) -> Inspection {
    Inspection::cannot(
        "ufw",
        ports,
        &format!("{UFW_RULES} could not be read as root ({why})"),
        Vec::new(),
    )
}

/// A zone with sources takes the traffic from those addresses before the zone of the interface does.
/// When another active zone has sources (or the zone list was cut), a "closed" answer for the picked
/// zone is not proven, so it becomes "unknown" with a note.
fn demote_closed(found: &mut Inspection, zones: &firewalld::ActiveZones, picked: &str) {
    let others = zones.source_bound_besides(picked);
    if others.is_empty() && !zones.truncated {
        return;
    }
    let why = if others.is_empty() {
        "the list of active zones is longer than rdy reads, so a zone with sources may be missing"
            .to_owned()
    } else {
        let shown: Vec<&str> = others.iter().copied().take(3).collect();
        format!(
            "active zone {} is bound to source addresses and takes traffic from them before zone {picked}",
            shown.join(", ")
        )
    };
    let mut changed = false;
    for (_, verdict) in &mut found.verdicts {
        if matches!(verdict, Verdict::Closed(_)) {
            *verdict = Verdict::Unknown(why.clone());
            changed = true;
        }
    }
    if changed {
        found.notes.push(why);
    }
}

/// A zone picked from `--get-active-zones`, and a note when the pick was a guess.
struct Picked<'a> {
    zone: &'a firewalld::ActiveZone,
    note: Option<String>,
}

/// The zone that holds the default-route interface. With no match, the only active zone is used and the
/// note says so; with several zones the answer is an error text for an "unknown" verdict.
fn pick_zone<'a>(
    zones: &'a [firewalld::ActiveZone],
    iface: Option<&str>,
) -> Result<Picked<'a>, String> {
    if let Some(iface) = iface
        && let Some(zone) = zones
            .iter()
            .find(|z| z.interfaces.iter().any(|i| i == iface))
    {
        return Ok(Picked { zone, note: None });
    }
    let names = || {
        zones
            .iter()
            .map(|z| z.name.as_str())
            .collect::<Vec<_>>()
            .join(", ")
    };
    match (zones, iface) {
        ([], _) => Err("firewalld reports no active zone".to_owned()),
        ([only], _) => Ok(Picked {
            zone: only,
            note: Some(format!(
                "the default-route interface is not in a zone listing, so the only active zone ({}) was used",
                only.name
            )),
        }),
        (_, Some(iface)) => Err(format!(
            "the default-route interface {iface} is in none of the active zones ({})",
            names()
        )),
        (_, None) => Err(format!(
            "there is no default route, so rdy cannot tell which of the active zones ({}) carries traffic",
            names()
        )),
    }
}

/// `6443/tcp` or `6443/tcp, 10250/tcp and 3 more`.
fn list(ports: &[u16]) -> String {
    let shown: Vec<String> = ports
        .iter()
        .take(LIST_PORTS)
        .map(|p| format!("{p}/tcp"))
        .collect();
    let mut text = match shown.as_slice() {
        [] => String::new(),
        [one] => one.clone(),
        [init @ .., last] => format!("{} and {last}", init.join(", ")),
    };
    if ports.len() > LIST_PORTS {
        text.push_str(&format!(" and {} more", ports.len() - LIST_PORTS));
    }
    text
}

/// The `--add-port` arguments for the fix, at most [`LIST_PORTS`] of them.
fn add_ports(ports: &[u16]) -> String {
    ports
        .iter()
        .take(LIST_PORTS)
        .map(|p| format!("--add-port={p}/tcp"))
        .collect::<Vec<_>>()
        .join(" ")
}

/// One finding from what every manager said.
fn assemble(requested: &[u16], found: &[Inspection]) -> Finding {
    let mut closed_text = Vec::new();
    let mut unknown_text = Vec::new();
    let mut open_text = Vec::new();
    let mut fixes = Vec::new();
    let mut missing: Vec<Need> = Vec::new();

    for one in found {
        let closed = one.ports_with(|v| matches!(v, Verdict::Closed(_)));
        let unknown = one.ports_with(|v| matches!(v, Verdict::Unknown(_)));
        let open = one.ports_with(|v| matches!(v, Verdict::Open(_)));
        let place = match &one.zone {
            Some(zone) => format!("{} zone {zone}", one.manager),
            None => one.manager.to_owned(),
        };
        if !closed.is_empty() {
            closed_text.push(match &one.zone {
                Some(zone) => format!("{} blocks {} in zone {zone}.", one.manager, list(&closed)),
                None => format!("{} blocks {}.", one.manager, list(&closed)),
            });
            fixes.push(match (one.manager, &one.zone) {
                ("firewalld", Some(zone)) => format!(
                    "Run `firewall-cmd --permanent --zone={zone} {} && firewall-cmd --reload`.",
                    add_ports(&closed)
                ),
                _ => format!(
                    "Run `{}`.",
                    closed
                        .iter()
                        .take(LIST_PORTS)
                        .map(|p| format!("ufw allow {p}/tcp"))
                        .collect::<Vec<_>>()
                        .join(" && ")
                ),
            });
        }
        if !unknown.is_empty() {
            let reasons: Vec<&str> = one
                .verdicts
                .iter()
                .filter_map(|(_, v)| match v {
                    Verdict::Unknown(why) => Some(why.as_str()),
                    _ => None,
                })
                .collect();
            let first = reasons.first().copied().unwrap_or_default();
            let same = reasons.iter().all(|r| *r == first);
            unknown_text.push(if same {
                format!("Cannot confirm {} in {place}: {first}.", list(&unknown))
            } else {
                format!(
                    "Cannot confirm {} in {place}: {first}, and other reasons in the evidence.",
                    list(&unknown)
                )
            });
            fixes.push(unknown_fix(one, &unknown));
        }
        if !open.is_empty() {
            open_text.push(format!("{place} allows {} inbound.", list(&open)));
        }
        for need in &one.missing {
            if !missing.contains(need) {
                missing.push(need.clone());
            }
        }
    }

    let level = if !closed_text.is_empty() {
        Level::Fail
    } else if !unknown_text.is_empty() {
        Level::Warn
    } else {
        Level::Pass
    };
    let mut message: Vec<String> = Vec::new();
    message.extend(closed_text);
    message.extend(unknown_text);
    if level == Level::Pass {
        if found.is_empty() {
            message.push("No host firewall manager is active (firewalld is not running and ufw is not enabled).".to_owned());
        } else if open_text.is_empty() {
            let names: Vec<&str> = found.iter().map(|f| f.manager).collect();
            message.push(format!(
                "{} is active. The spec names no inbound ports to check.",
                names.join(" and ")
            ));
        } else {
            message.extend(open_text);
        }
    }

    let mut finding = Finding::new(level, message.join(" "))
        .with_observed(observed(found))
        .with_expected(json!({ "open_inbound": requested }));
    if found.is_empty() {
        finding = finding.with_note(
            "Rules written directly into nftables or iptables are not read in this build.",
        );
    }
    for one in found {
        for note in &one.notes {
            finding = finding.with_note(note.clone());
        }
    }
    if level != Level::Pass {
        finding = finding.with_fix(fixes.join(" "));
    }
    if !missing.is_empty() {
        finding = finding.with_partial(Partial::new(
            missing,
            "The firewall rules were not inspected.",
        ));
    }
    finding
}

/// The fix for ports that could not be confirmed.
fn unknown_fix(one: &Inspection, ports: &[u16]) -> String {
    if one.missing.contains(&Need::Root) {
        return format!(
            "Run rdy as root so it can read the {} rules, or check by hand that {} is open.",
            one.manager,
            list(ports)
        );
    }
    match (one.manager, &one.zone) {
        ("firewalld", Some(zone)) => format!(
            "Run `firewall-cmd --list-all --zone={zone}` and check that {} is accepted from the nodes that need it. If it is not, run `firewall-cmd --permanent --zone={zone} {} && firewall-cmd --reload`.",
            list(ports),
            add_ports(ports)
        ),
        ("firewalld", None) => format!(
            "Run `firewall-cmd --list-all` and check that {} is open in the zone of the default-route interface.",
            list(ports)
        ),
        _ => format!(
            "Run `ufw status verbose` as root and check that {} is allowed.",
            list(ports)
        ),
    }
}

/// The evidence object: one entry per manager with a verdict per port.
fn observed(found: &[Inspection]) -> Value {
    let managers: Vec<Value> = found
        .iter()
        .map(|one| {
            let mut ports = Map::new();
            for (port, verdict) in &one.verdicts {
                ports.insert(
                    port.to_string(),
                    json!({ "verdict": verdict.word(), "detail": verdict.detail() }),
                );
            }
            json!({
                "manager": one.manager,
                "zone": one.zone,
                "interface": one.interface,
                "ports": ports,
            })
        })
        .collect();
    json!({ "active": managers })
}
