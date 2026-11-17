//! From the sockets found to one finding: who holds which required port, what that means, and what to do.
//!
//! Nothing here touches the machine. The facts are plain data, so the judgement is tested without a probe.

use rdy_engine::check::{Finding, Level, Need, Partial};
use rdy_spec::check::Bind;
use serde_json::{Value, json};

use super::net::{Scope, Socket};
use super::owner::{Gap, Owner};
use super::range::{self, Span};
use crate::agents::comm_matches;
use rdy_engine::text::escape_untrusted;

/// The most ports named in one sentence before the rest are counted.
const LIST: usize = 8;
/// The most holders shown for one port. Others are counted.
const HOLDERS: usize = 8;

/// The file the fix writes. `sysctl --system` reads the files of `/etc/sysctl.d` in name order, and
/// distributions ship `99-sysctl.conf` (a link to `/etc/sysctl.conf`), so the name must sort after it.
const SYSCTL_FILE: &str = "/etc/sysctl.d/99-zz-reserved-ports.conf";

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub(super) enum Proto {
    Tcp,
    Udp,
}

impl Proto {
    fn word(self) -> &'static str {
        match self {
            Self::Tcp => "tcp",
            Self::Udp => "udp",
        }
    }

    /// The `ss` flags for a listing of this protocol: listening, numeric, with processes.
    fn ss(self) -> &'static str {
        match self {
            Self::Tcp => "-ltnp",
            Self::Udp => "-lunp",
        }
    }
}

/// A socket on a required port, and what is known of its owner.
#[derive(Debug, Clone)]
pub(super) struct Held {
    pub socket: Socket,
    pub owner: Option<Owner>,
    pub gap: Option<Gap>,
}

/// A required port and what was found on it.
#[derive(Debug, Clone)]
pub(super) struct PortState {
    pub proto: Proto,
    pub port: u16,
    pub bind: Bind,
    pub held: Vec<Held>,
    /// Why the tables could not prove the port free, when they could not.
    pub unverified: Option<String>,
    /// The kernel may hand the port to an outgoing connection.
    pub ephemeral: bool,
}

impl PortState {
    fn label(&self) -> String {
        format!("{}/{}", self.port, self.proto.word())
    }
}

/// Everything the finding is built from.
#[derive(Debug)]
pub(super) struct Facts<'a> {
    pub ports: Vec<PortState>,
    pub allow: &'a [String],
    pub root: bool,
    pub range: Option<Span>,
    pub reserved: Vec<Span>,
    /// The whole value of `ip_local_reserved_ports` was read. When it was not, the fix tells the user to
    /// append to the current value instead of giving a complete line.
    pub reserved_known: bool,
    pub netns: Option<String>,
    /// The file or variable that shows rdy is in a container.
    pub container: Option<String>,
    pub notes: Vec<String>,
    /// Processes whose fd directory was listed.
    pub walked: usize,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
enum Sev {
    Allowed,
    Warn,
    Fail,
}

/// Whether `comm` is a process the spec's `allow_owner` names.
fn allowed(allow: &[String], comm: &str) -> bool {
    allow.iter().any(|name| comm_matches(comm, name))
}

/// How bad one holder is for a product that binds as `bind`.
///
/// A listener on loopback only, while the product binds every address, is a warning (03): Linux refuses
/// the wildcard bind while any address holds the port, but the holder may be meant to move.
fn severity(held: &Held, bind: Bind, allow: &[String]) -> Sev {
    let loopback_only = bind == Bind::Public && held.socket.scope() == Scope::Loopback;
    let name = held.owner.as_ref().and_then(|o| o.name.as_deref());
    match name {
        Some(name) if allowed(allow, name) => Sev::Allowed,
        _ if loopback_only => Sev::Warn,
        // The owner is unknown, or has no readable name, and the spec allows some owners: it may be one.
        _ if held.owner.is_none() || name.is_none() => {
            if allow.is_empty() {
                Sev::Fail
            } else {
                Sev::Warn
            }
        }
        _ => Sev::Fail,
    }
}

/// Whether the socket conflicts with a product that binds as `bind`.
pub(super) fn conflicts(socket: &Socket, bind: Bind) -> bool {
    match bind {
        Bind::Loopback => matches!(socket.scope(), Scope::Unspecified | Scope::Loopback),
        _ => true,
    }
}

/// A process name from the machine, always in a code span. Control and invisible characters are
/// escaped, and a backtick is written `\x60`, so a name cannot close the span.
fn name(text: &str) -> String {
    let shown = escape_untrusted(text)
        .replace('\u{FFFD}', "\\u{fffd}")
        .replace('`', "\\x60");
    format!("`{shown}`")
}

fn who(owner: &Owner) -> String {
    match &owner.name {
        Some(text) => format!("{} (pid {})", name(text), owner.pid),
        None => format!("pid {}", owner.pid),
    }
}

/// The holder of a port that the spec allows, with its unit. The name is set by the process itself, so
/// the unit is what lets a reader see that it is the product's own service.
fn who_allowed(owner: &Owner) -> String {
    match (&owner.name, &owner.unit) {
        (Some(text), Some(unit)) => format!("{} (pid {}, unit `{unit}`)", name(text), owner.pid),
        _ => who(owner),
    }
}

fn gap_text(gap: Option<Gap>, root: bool) -> &'static str {
    match gap {
        Some(Gap::OtherUser) => "it belongs to another user and rdy is not root",
        Some(Gap::Unreadable) if root => "some process directories could not be read, even as root",
        Some(Gap::Unreadable) => "some process directories could not be read without root",
        Some(Gap::Cut) => "the search of /proc stopped early because of its time or size limit",
        Some(Gap::NotFound) => {
            "no process that rdy can see holds it, so it may belong to another PID namespace"
        }
        None => "the socket has no inode in the table",
    }
}

/// `a`, `a and b`, `a, b and c`, `a, b, c and 3 more`.
fn list(items: &[String]) -> String {
    let shown = &items[..items.len().min(LIST)];
    let mut text = match shown {
        [] => String::new(),
        [one] => one.clone(),
        [init @ .., last] => format!("{} and {last}", init.join(", ")),
    };
    if items.len() > LIST {
        text.push_str(&format!(" and {} more", items.len() - LIST));
    }
    text
}

fn push_once(into: &mut Vec<String>, text: String) {
    if !into.contains(&text) {
        into.push(text);
    }
}

/// The finding for these facts.
pub(super) fn assemble(facts: &Facts<'_>, expected: Value) -> Finding {
    let mut fail: Vec<String> = Vec::new();
    let mut warn: Vec<String> = Vec::new();
    let mut fixes: Vec<String> = Vec::new();
    let mut notes: Vec<String> = facts.notes.clone();
    let mut worst = Sev::Allowed;
    let mut allowed_ports: Vec<String> = Vec::new();
    let mut dual_stack = false;
    let mut unknown_owner = false;
    let mut needs_root = false;
    let mut unverified: Vec<String> = Vec::new();
    let mut unverified_why: Vec<String> = Vec::new();

    for port in &facts.ports {
        for held in &port.held {
            dual_stack |= held.socket.v6_table && held.socket.scope() == Scope::Unspecified;
            let sev = severity(held, port.bind, facts.allow);
            worst = worst.max(sev);
            if held.owner.is_none() {
                unknown_owner = true;
                needs_root |=
                    !facts.root && matches!(held.gap, Some(Gap::OtherUser | Gap::Unreadable));
            }
            let label = port.label();
            match (sev, &held.owner) {
                (Sev::Allowed, owner) => {
                    let by = owner.as_ref().map_or_else(String::new, who_allowed);
                    push_once(&mut allowed_ports, format!("{label} by {by}"));
                }
                (sev, owner) => {
                    let target = if sev == Sev::Fail {
                        &mut fail
                    } else {
                        &mut warn
                    };
                    push_once(
                        target,
                        held_sentence(port, held, owner.as_ref(), sev, facts),
                    );
                    push_once(&mut fixes, held_fix(port, held, owner.as_ref(), facts.root));
                }
            }
        }
        if let Some(why) = &port.unverified
            && port.held.is_empty()
        {
            push_once(&mut unverified, port.label());
            push_once(&mut unverified_why, why.clone());
        }
    }

    // Ports inside the ephemeral range that the kernel does not hold back.
    let exposed: Vec<&PortState> = facts.ports.iter().filter(|p| p.ephemeral).collect();
    if let (Some((low, high)), false) = (facts.range, exposed.is_empty()) {
        let labels: Vec<String> = exposed.iter().map(|p| p.label()).collect();
        warn.push(format!(
            "{} {} inside the ephemeral port range {low}-{high}, so an outgoing connection can take {}.",
            list(&labels),
            if labels.len() == 1 { "is" } else { "are" },
            if labels.len() == 1 { "it" } else { "them" },
        ));
        let mut numbers: Vec<u16> = exposed.iter().map(|p| p.port).collect();
        numbers.sort_unstable();
        numbers.dedup();
        let what = if numbers.len() == 1 {
            "the port"
        } else {
            "the ports"
        };
        let check = "Confirm with `sysctl net.ipv4.ip_local_reserved_ports`.";
        if facts.reserved_known {
            fixes.push(format!(
                "Reserve {what} for the product: `echo 'net.ipv4.ip_local_reserved_ports = {}' | sudo tee {SYSCTL_FILE} && sudo sysctl --system`. The value keeps the ports that are reserved now. If `/etc/sysctl.conf` sets this value, edit that line instead. {check}",
                range::merged_value(&facts.reserved, &numbers),
            ));
        } else {
            let added: Vec<String> = numbers.iter().map(u16::to_string).collect();
            fixes.push(format!(
                "Reserve {what} for the product. rdy could not read the ports that are reserved now, so read them with `sysctl -n net.ipv4.ip_local_reserved_ports`, append {} to that value, and write `net.ipv4.ip_local_reserved_ports = <that value>,{}` to {SYSCTL_FILE} (just `{}` if the value is empty). Then run `sudo sysctl --system`. If `/etc/sysctl.conf` sets this value, edit that line instead. {check}",
                added.join(","),
                added.join(","),
                added.join(","),
            ));
        }
    }

    if !unverified.is_empty() {
        warn.push(format!(
            "rdy could not confirm that {} {} free: {}.",
            list(&unverified),
            if unverified.len() == 1 { "is" } else { "are" },
            unverified_why.join("; "),
        ));
        fixes.push(
            "Check by hand as root: `ss -ltn` for TCP ports and `ss -lun` for UDP ports."
                .to_owned(),
        );
    }

    if let Some(marker) = &facts.container {
        warn.push(format!(
            "rdy is running in a container ({marker}), so it sees the sockets of the container's network namespace, not the node's."
        ));
        fixes.push(
            "Run rdy on the node itself, or give the container the node's view: `--network host --pid host` for Docker, `hostNetwork: true` and `hostPID: true` for a pod.".to_owned(),
        );
    }

    let level = if worst == Sev::Fail {
        Level::Fail
    } else if !warn.is_empty() || worst == Sev::Warn {
        Level::Warn
    } else {
        Level::Pass
    };

    let mut sentences: Vec<String> = Vec::new();
    sentences.extend(fail);
    sentences.extend(warn);
    if level == Level::Pass {
        sentences.push(pass_sentence(facts, &allowed_ports));
    }
    let mut finding = Finding::new(level, sentences.join(" "))
        .with_observed(observed(facts))
        .with_expected(expected);

    if dual_stack {
        notes.push(
            "A listener on [::] is counted as holding the IPv4 port too. rdy cannot see whether the socket is IPv6 only.".to_owned(),
        );
    }
    if !allowed_ports.is_empty() {
        notes.push(format!(
            "Held by a process the spec allows: {}. rdy matches the process name, which any local process can set, so the name alone does not show that the product's own service holds the port.",
            list(&allowed_ports)
        ));
    }
    for note in notes {
        finding = finding.with_note(note);
    }
    if level != Level::Pass {
        finding = finding.with_fix(fixes.join(" "));
    }
    if unknown_owner || !unverified.is_empty() {
        let mut reasons: Vec<&str> = Vec::new();
        if unknown_owner {
            reasons.push("rdy could not identify the process that holds a port");
        }
        if !unverified.is_empty() {
            reasons.push("a socket table could not be read in full");
        }
        let missing = if needs_root {
            vec![Need::Root]
        } else {
            Vec::new()
        };
        finding =
            finding.with_partial(Partial::new(missing, format!("{}.", reasons.join(" and "))));
    }
    finding
}

fn pass_sentence(facts: &Facts<'_>, allowed_ports: &[String]) -> String {
    if facts.ports.is_empty() {
        return "The spec names no ports to check.".to_owned();
    }
    let labels: Vec<String> = facts.ports.iter().map(PortState::label).collect();
    if allowed_ports.is_empty() {
        format!(
            "{} {} free.",
            list(&labels),
            if labels.len() == 1 { "is" } else { "are" }
        )
    } else {
        format!(
            "{} {} free or held by a process the spec allows.",
            list(&labels),
            if labels.len() == 1 { "is" } else { "are" }
        )
    }
}

fn held_sentence(
    port: &PortState,
    held: &Held,
    owner: Option<&Owner>,
    sev: Sev,
    facts: &Facts<'_>,
) -> String {
    let label = port.label();
    let address = held.socket.shown();
    let loopback_only = port.bind == Bind::Public && held.socket.scope() == Scope::Loopback;
    match owner {
        Some(owner) if loopback_only => format!(
            "Port {label} is held on {address} by {}. The product binds every address, so its bind will probably fail.",
            who(owner)
        ),
        Some(owner) => format!("Port {label} is held by {}.", who(owner)),
        None => {
            let mut text = format!(
                "Port {label} is in use on {address}. rdy could not identify the holder: {}.",
                gap_text(held.gap, facts.root)
            );
            if sev == Sev::Warn && !facts.allow.is_empty() && !loopback_only {
                text.push_str(" The spec allows some owners, so it may be one of them.");
            }
            text
        }
    }
}

fn held_fix(port: &PortState, held: &Held, owner: Option<&Owner>, root: bool) -> String {
    let label = port.label();
    match owner {
        Some(owner) => {
            let stop = match &owner.unit {
                Some(unit) => format!("Stop it with `systemctl stop {unit}`"),
                None => "Stop it".to_owned(),
            };
            format!(
                "Port {label} is held by {}. {stop}, or change the product's port setting.",
                who(owner)
            )
        }
        None => {
            let ss = format!("ss {} 'sport = :{}'", port.proto.ss(), port.port);
            let ask = if !root && matches!(held.gap, Some(Gap::OtherUser | Gap::Unreadable)) {
                "Run rdy as root to see the holder, or run"
            } else {
                "To see the holder, run"
            };
            format!("{ask} `{ss}` as root.")
        }
    }
}

/// The evidence object.
fn observed(facts: &Facts<'_>) -> Value {
    let ports = |proto: Proto| -> Vec<Value> {
        facts
            .ports
            .iter()
            .filter(|p| p.proto == proto)
            .map(|p| port_value(p, facts))
            .collect()
    };
    json!({
        "tcp": ports(Proto::Tcp),
        "udp": ports(Proto::Udp),
        "netns": facts.netns,
        "container": facts.container,
        "ephemeral_range": facts.range.map(|(low, high)| json!([low, high])),
        "reserved_ports": range::merged_value(&facts.reserved, &[]),
        "processes_walked": facts.walked,
    })
}

fn port_value(port: &PortState, facts: &Facts<'_>) -> Value {
    let state = if !port.held.is_empty() {
        "in_use"
    } else if port.unverified.is_some() {
        "unverified"
    } else {
        "free"
    };
    let holders: Vec<Value> = port
        .held
        .iter()
        .take(HOLDERS)
        .map(|held| {
            let owner = held
                .owner
                .as_ref()
                .map(|o| json!({ "pid": o.pid, "name": o.name, "unit": o.unit }));
            json!({
                "address": held.socket.shown(),
                "family": if held.socket.v6_table { "ipv6" } else { "ipv4" },
                "owner": owner,
                "owner_unknown": held.owner.is_none().then(|| gap_text(held.gap, facts.root)),
                "allowed": severity(held, port.bind, facts.allow) == Sev::Allowed,
            })
        })
        .collect();
    json!({
        "port": port.port,
        "bind": match port.bind { Bind::Loopback => "loopback", _ => "public" },
        "state": state,
        "holders": holders,
        "holders_not_shown": port.held.len().saturating_sub(HOLDERS),
        "ephemeral": port.ephemeral,
        "unverified": port.unverified,
    })
}
