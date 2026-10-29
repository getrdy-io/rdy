//! ufw: `/etc/ufw/ufw.conf`, `/etc/default/ufw` and the rule tuples in `/etc/ufw/user.rules`.
//!
//! `ufw` writes a comment line above the iptables lines of every rule it adds, like
//! `### tuple ### allow tcp 6443 0.0.0.0/0 any 0.0.0.0/0 in`. The comment is the rule in the form the
//! user typed it, and the lines are in the order the kernel checks them, so the tuples are enough to
//! judge a port. Rules in `before.rules` and `after.rules` are not read.

use super::Verdict;
use super::ports::PortRange;

/// The most tuples read.
const MAX_TUPLES: usize = 4096;
/// The most lines read from any ufw file.
const MAX_LINES: usize = 20_000;

/// `ENABLED=yes` or `ENABLED=no` in `ufw.conf`. The last assignment wins. `None` when there is none.
pub(super) fn enabled(conf: &str) -> Option<bool> {
    let mut out = None;
    for line in conf.lines().take(MAX_LINES) {
        let Some((key, value)) = line.trim().split_once('=') else {
            continue;
        };
        if key.trim() == "ENABLED" {
            out = match value
                .trim()
                .trim_matches(['"', '\''])
                .to_ascii_lowercase()
                .as_str()
            {
                "yes" => Some(true),
                "no" => Some(false),
                _ => out,
            };
        }
    }
    out
}

/// What ufw does with inbound traffic that no rule matches.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum Policy {
    Accept,
    Drop,
    Reject,
    Unknown,
}

impl Policy {
    fn word(self) -> &'static str {
        match self {
            Self::Accept => "ACCEPT",
            Self::Drop => "DROP",
            Self::Reject => "REJECT",
            Self::Unknown => "unknown",
        }
    }
}

/// `DEFAULT_INPUT_POLICY="DROP"` in `/etc/default/ufw`.
pub(super) fn default_input(file: &str) -> Policy {
    let mut out = Policy::Unknown;
    for line in file.lines().take(MAX_LINES) {
        let Some((key, value)) = line.trim().split_once('=') else {
            continue;
        };
        if key.trim() == "DEFAULT_INPUT_POLICY" {
            out = match value
                .trim()
                .trim_matches(['"', '\''])
                .to_ascii_uppercase()
                .as_str()
            {
                "ACCEPT" => Policy::Accept,
                "DROP" => Policy::Drop,
                "REJECT" => Policy::Reject,
                _ => Policy::Unknown,
            };
        }
    }
    out
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Action {
    Allow,
    Deny,
}

/// A TCP or any-protocol inbound rule, as far as the port question goes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct Tuple {
    action: Action,
    /// The destination ports. A rule for any port holds the range of every port.
    ports: Vec<PortRange>,
    /// The rule is for every source and every destination address, on every interface.
    everywhere: bool,
    /// The rule is bound to this interface (`in_eth0`).
    interface: Option<String>,
}

/// One place in `user.rules`, in file order.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) enum Entry {
    /// An inbound rule for TCP or any protocol.
    Rule(Tuple),
    /// A tuple line, or the rest of the file, that rdy could not read. What it holds is not known, so
    /// no verdict can be given past this point.
    Unread(&'static str),
}

/// What reading one tuple gave.
enum Parsed {
    Rule(Tuple),
    /// A rule that is not about inbound TCP: UDP, outbound, forwarded or routed.
    Elsewhere,
    /// A tuple that does not have the form rdy reads.
    Unread,
}

/// Reads the `### tuple ###` lines of `user.rules`, in order. Rules for UDP, for outbound, forwarded or
/// routed traffic are left out. A tuple that does not parse, and a file longer than the limits, become
/// [`Entry::Unread`].
pub(super) fn parse_user_rules(text: &str) -> Vec<Entry> {
    let mut out = Vec::new();
    let mut lines = text.lines();
    for line in lines.by_ref().take(MAX_LINES) {
        let Some(rest) = line.trim().strip_prefix("### tuple ###") else {
            continue;
        };
        if out.len() >= MAX_TUPLES {
            out.push(Entry::Unread("the file has more rules than rdy reads"));
            return out;
        }
        match parse_tuple(rest) {
            Parsed::Rule(tuple) => out.push(Entry::Rule(tuple)),
            Parsed::Elsewhere => {}
            Parsed::Unread => out.push(Entry::Unread("a rule line is not in the form rdy reads")),
        }
    }
    if lines.next().is_some() {
        out.push(Entry::Unread("the file is longer than rdy reads"));
    }
    out
}

/// `allow tcp 6443 0.0.0.0/0 any 0.0.0.0/0 in`, with an optional profile name and `-` before the
/// direction (`... OpenSSH - in`), an optional `_<interface>` after `in`, an optional `_log` or
/// `_log-all` after the action (`allow_log`), and an optional `comment=<hex>` at the end (ufw writes
/// one for `ufw allow 6443/tcp comment 'k8s'`).
fn parse_tuple(rest: &str) -> Parsed {
    let mut f: Vec<&str> = rest.split_whitespace().collect();
    if f.last().is_some_and(|w| w.starts_with("comment=")) {
        f.pop();
    }
    if f.len() < 7 {
        return Parsed::Unread;
    }
    let (action, proto, dport, dst, sport, src) = (f[0], f[1], f[2], f[3], f[4], f[5]);
    let direction = f[f.len() - 1];
    if action.starts_with("route:") {
        return Parsed::Elsewhere;
    }
    let action = action
        .strip_suffix("_log-all")
        .or_else(|| action.strip_suffix("_log"))
        .unwrap_or(action);
    let action = match action {
        "allow" | "limit" => Action::Allow,
        "deny" | "reject" => Action::Deny,
        _ => return Parsed::Unread,
    };
    if direction.starts_with("out") || direction.starts_with("fwd") {
        return Parsed::Elsewhere;
    }
    let interface = match direction.strip_prefix("in") {
        Some("") => None,
        Some(tail) => match tail.strip_prefix('_') {
            Some(name) => Some(name.to_owned()),
            None => return Parsed::Unread,
        },
        None => return Parsed::Unread,
    };
    if !matches!(proto, "tcp" | "any") {
        return if matches!(proto, "udp" | "ipv6" | "esp" | "ah" | "igmp") {
            Parsed::Elsewhere
        } else {
            Parsed::Unread
        };
    }
    let ports = if dport == "any" {
        vec![PortRange::all()]
    } else {
        let parsed = dport
            .split(',')
            .map(|p| PortRange::parse(p, ':'))
            .collect::<Option<Vec<_>>>();
        match parsed {
            Some(ports) => ports,
            None => return Parsed::Unread,
        }
    };
    let any_addr = |a: &str| a == "0.0.0.0/0" || a == "::/0";
    let everywhere = any_addr(dst) && any_addr(src) && sport == "any";
    Parsed::Rule(Tuple {
        action,
        ports,
        everywhere,
        interface,
    })
}

/// Judges inbound TCP `port`. `iface` is the interface of the default route, when known.
///
/// The entries are walked in file order, which is the order the kernel checks them. An unrestricted allow
/// or deny decides. A line rdy could not read ends the walk with "unknown", because it might have
/// decided. An allow bound to another interface or limited to some addresses cannot be judged without
/// the client addresses and the arrival interface, so if nothing unrestricted decides first, the answer
/// is "unknown". A deny bound to another interface does not touch this one.
pub(super) fn judge(rules: &[Entry], policy: Policy, iface: Option<&str>, port: u16) -> Verdict {
    let mut limited = false;
    for entry in rules {
        let rule = match entry {
            Entry::Rule(rule) => rule,
            Entry::Unread(why) => return Verdict::Unknown((*why).to_owned()),
        };
        if !rule.ports.iter().any(|p| p.covers(port)) {
            continue;
        }
        let bound = match (&rule.interface, iface) {
            (None, _) => true,
            (Some(a), Some(b)) => a == b,
            // A rule for an interface, and no known default route: it might be the one.
            (Some(_), None) => {
                limited = true;
                false
            }
        };
        if !bound {
            // An allow for another interface may be the one the traffic arrives on.
            limited |= rule.action == Action::Allow;
            continue;
        }
        if !rule.everywhere {
            limited = true;
            continue;
        }
        return match rule.action {
            Action::Allow => Verdict::Open(format!("rule: allow {port}/tcp")),
            Action::Deny => Verdict::Closed(format!("rule: deny or reject {port}/tcp")),
        };
    }
    if limited {
        return Verdict::Unknown(
            "a rule limits it to some addresses or interfaces, which rdy cannot judge".to_owned(),
        );
    }
    match policy {
        Policy::Accept => Verdict::Open("default input policy ACCEPT".to_owned()),
        Policy::Drop | Policy::Reject => Verdict::Closed(format!(
            "no rule allows it and the default input policy is {}",
            policy.word()
        )),
        Policy::Unknown => Verdict::Unknown(
            "no rule matches and /etc/default/ufw does not give the default input policy"
                .to_owned(),
        ),
    }
}
