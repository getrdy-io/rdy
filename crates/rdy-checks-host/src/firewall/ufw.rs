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

/// Reads the `### tuple ###` lines of `user.rules`. Rules for UDP, for outbound or forwarded traffic and
/// lines that do not parse are left out.
pub(super) fn parse_user_rules(text: &str) -> Vec<Tuple> {
    let mut out = Vec::new();
    for line in text.lines().take(MAX_LINES) {
        let Some(rest) = line.trim().strip_prefix("### tuple ###") else {
            continue;
        };
        if out.len() >= MAX_TUPLES {
            break;
        }
        if let Some(tuple) = parse_tuple(rest) {
            out.push(tuple);
        }
    }
    out
}

/// `allow tcp 6443 0.0.0.0/0 any 0.0.0.0/0 in`, with an optional profile name and `-` before the
/// direction (`... OpenSSH - in`) and an optional `_<interface>` after `in`.
fn parse_tuple(rest: &str) -> Option<Tuple> {
    let f: Vec<&str> = rest.split_whitespace().collect();
    let (action, proto, dport, dst, sport, src) = (
        f.first()?,
        f.get(1)?,
        f.get(2)?,
        f.get(3)?,
        f.get(4)?,
        f.get(5)?,
    );
    let direction = f.last()?;
    let interface = match direction.strip_prefix("in") {
        Some("") => None,
        Some(tail) => Some(tail.strip_prefix('_')?.to_owned()),
        None => return None,
    };
    let action = match *action {
        "allow" | "limit" => Action::Allow,
        "deny" | "reject" => Action::Deny,
        _ => return None,
    };
    if !matches!(*proto, "tcp" | "any") {
        return None;
    }
    let ports = if *dport == "any" {
        vec![PortRange::all()]
    } else {
        dport
            .split(',')
            .map(|p| PortRange::parse(p, ':'))
            .collect::<Option<Vec<_>>>()?
    };
    let any_addr = |a: &str| a == "0.0.0.0/0" || a == "::/0";
    let everywhere = any_addr(dst) && any_addr(src) && *sport == "any";
    Some(Tuple {
        action,
        ports,
        everywhere,
        interface,
    })
}

/// Judges inbound TCP `port`. `iface` is the interface of the default route, when known.
///
/// The tuples are walked in file order, which is the order the kernel checks them. An unrestricted allow
/// or deny decides. A rule bound to another interface is skipped. A rule limited to some addresses cannot
/// be judged without the client addresses, so if nothing unrestricted decides first, the answer is
/// "unknown".
pub(super) fn judge(rules: &[Tuple], policy: Policy, iface: Option<&str>, port: u16) -> Verdict {
    let mut limited = false;
    for rule in rules
        .iter()
        .filter(|r| r.ports.iter().any(|p| p.covers(port)))
    {
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
