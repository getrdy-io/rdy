//! `host.ports`: are the product's required TCP and UDP ports free, and if not, who holds them.
//!
//! Linux only in M1. The sockets come from `/proc/net/tcp`, `tcp6`, `udp` and `udp6` (`net`). Only a
//! listening TCP socket holds a port, and every UDP row with a local port does. The holder is found
//! lazily (`owner`): the check walks `/proc/<pid>/fd` only when a required port is taken, and stops at
//! the first match. The name is `/proc/<pid>/comm`, never `cmdline` (ADR 0036). The ephemeral range and
//! the reserved ports (`range`) say whether the kernel may hand a free port to an outgoing connection.
//! There is no `bind()` probe: a check that opens a socket on the customer's machine is not read-only.
//!
//! **Privilege.** `/proc/net` is world readable, so the held ports are found without root. The owner of a
//! socket that belongs to another user is not: without root the port is still reported in use, the owner
//! is unknown, and the result is `partial` with `Root` missing.
//!
//! **Network namespace.** `/proc/net` lists the sockets of the namespace rdy runs in. The evidence carries
//! the namespace (`read_link /proc/self/ns/net`), and a container marker makes the check warn that the
//! view is the container's.

use std::collections::BTreeMap;
use std::path::Path;
use std::time::Duration;

use rdy_engine::check::{
    BoxFuture, Check, CheckContext, CheckError, CheckInfo, CheckMeta, CheckOutcome, FD_WALK, Need,
    Os, Want,
};
use rdy_engine::probe::ProbeError;
use rdy_spec::check::{Bind, HostPorts};
use serde_json::json;

use crate::family::OS;
use crate::reads::{Read, read_text};
use crate::text::{short, soft};

mod net;
mod owner;
mod range;
mod report;

#[cfg(test)]
mod built_tests;
#[cfg(test)]
mod tests;
#[cfg(test)]
mod unit_tests;

use report::{Facts, Held, PortState, Proto};

/// What the check says on an OS it has no data source for.
const NO_SOURCE: &str =
    "this check reads Linux socket tables and has no data source on this OS yet";

pub(crate) const PROC: &str = "/proc";
pub(crate) const SELF_STATUS: &str = "/proc/self/status";
const NETNS: &str = "/proc/self/ns/net";
const TCP4: &str = "/proc/net/tcp";
const TCP6: &str = "/proc/net/tcp6";
const UDP4: &str = "/proc/net/udp";
const UDP6: &str = "/proc/net/udp6";
const PORT_RANGE: &str = "/proc/sys/net/ipv4/ip_local_port_range";
const RESERVED: &str = "/proc/sys/net/ipv4/ip_local_reserved_ports";
/// Files a container runtime leaves in the container.
const CONTAINER_MARKERS: [&str; 2] = ["/.dockerenv", "/run/.containerenv"];
const KUBE_HOST: &str = "KUBERNETES_SERVICE_HOST";

/// Root only adds evidence. `/proc/net` is readable by everyone, so a port that no listener holds is
/// proven free without root, and a held port is found. Without root the owner of a socket that belongs to
/// another user is unknown, which `partial` says, but the level does not change (02 "Verdict").
const WANTS: &[Want] = &[Want {
    need: Need::Root,
    evidence_only: true,
}];

/// The static facts about `host.ports` (03 section 2).
///
/// `/proc` covers the socket tables, the sysctl files, the process list and `comm` and `cgroup` of one
/// process. The read policy allows only a short list of files under a process directory, so declaring
/// the prefix does not open `cmdline` or `environ`. [`FD_WALK`] is the one declaration that opens
/// `/proc/<pid>/fd`, and only `host.ports` may make it (ADR 0040).
pub(crate) static INFO: CheckInfo = CheckInfo {
    id: "host.ports",
    family: "host",
    summary: "Required ports free",
    meta: CheckMeta {
        title: "Free ports",
        remediation: "Stop the process that holds the port, or change the product's port setting. If the port is in the ephemeral range, reserve it with `net.ipv4.ip_local_reserved_ports` in a file under `/etc/sysctl.d/` as root, then run `sysctl --system`.",
    },
    needs: &[],
    wants: WANTS,
    default_timeout: Some(Duration::from_secs(5)),
    os: OS,
    reads: &[PROC, FD_WALK, CONTAINER_MARKERS[0], CONTAINER_MARKERS[1]],
    statfs: &[],
    env: &[KUBE_HOST],
    commands: &[],
    peers: &[],
};

/// `host.ports`.
///
/// Built from the spec's `free` (TCP, each with how the product binds it), `udp_free` and
/// `allow_owner`.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Ports {
    tcp: Vec<(u16, Bind)>,
    udp: Vec<u16>,
    allow: Vec<String>,
}

impl Ports {
    /// The check for these spec parameters. A TCP port listed twice keeps the stricter bind (`public`).
    #[must_use]
    pub fn from_params(params: &HostPorts) -> Self {
        let mut tcp: BTreeMap<u16, Bind> = BTreeMap::new();
        for rule in params.free.iter().flatten() {
            let entry = tcp.entry(rule.port.get()).or_insert(rule.bind);
            if rule.bind == Bind::Public {
                *entry = Bind::Public;
            }
        }
        let mut udp: Vec<u16> = params
            .udp_free
            .iter()
            .flatten()
            .map(|port| port.get())
            .collect();
        udp.sort_unstable();
        udp.dedup();
        let allow = params
            .allow_owner
            .iter()
            .flatten()
            .map(|name| name.as_str().to_owned())
            .collect();
        Self {
            tcp: tcp.into_iter().collect(),
            udp,
            allow,
        }
    }

    /// The required TCP ports, sorted.
    #[must_use]
    pub fn tcp_ports(&self) -> Vec<u16> {
        self.tcp.iter().map(|(port, _)| *port).collect()
    }

    /// The required UDP ports, sorted.
    #[must_use]
    pub fn udp_ports(&self) -> &[u16] {
        &self.udp
    }

    async fn inspect(&self, ctx: &CheckContext) -> CheckOutcome {
        if ctx.os() != Os::Linux {
            return Err(CheckError::Unsupported(NO_SOURCE));
        }
        let root = ctx.has(&Need::Root);
        let mut notes: Vec<String> = Vec::new();

        let tcp = self.sockets(ctx, Proto::Tcp, &mut notes).await?;
        let udp = self.sockets(ctx, Proto::Udp, &mut notes).await?;
        let (range, reserved, reserved_known) = if self.tcp.is_empty() && self.udp.is_empty() {
            (None, Vec::new(), true)
        } else {
            ephemeral(ctx, &mut notes).await?
        };

        let mut ports: Vec<PortState> = Vec::new();
        for (port, bind) in &self.tcp {
            ports.push(port_state(Proto::Tcp, *port, *bind, &tcp, range, &reserved));
        }
        for port in &self.udp {
            ports.push(port_state(
                Proto::Udp,
                *port,
                Bind::Public,
                &udp,
                range,
                &reserved,
            ));
        }

        // Look for owners only when a required port is taken.
        let wanted: BTreeMap<u64, u32> = ports
            .iter()
            .flat_map(|p| &p.held)
            .filter(|held| held.socket.inode != 0)
            .map(|held| (held.socket.inode, held.socket.uid))
            .collect();
        let mut walked = 0;
        if !wanted.is_empty() {
            let found = owner::find(ctx, root, &wanted).await?;
            walked = found.walked;
            for held in ports.iter_mut().flat_map(|p| &mut p.held) {
                held.owner = found.owners.get(&held.socket.inode).cloned();
                if held.owner.is_none() {
                    held.gap = found.gaps.get(&held.socket.inode).copied();
                }
            }
        }

        let netns = netns(ctx).await?;
        let container = container(ctx).await?;
        let facts = Facts {
            ports,
            allow: &self.allow,
            root,
            range,
            reserved,
            reserved_known,
            netns,
            container,
            notes,
            walked,
        };
        Ok(report::assemble(&facts, self.expected()))
    }

    fn expected(&self) -> serde_json::Value {
        let free: Vec<_> = self
            .tcp
            .iter()
            .map(|(port, bind)| {
                json!({
                    "port": port,
                    "bind": match bind { Bind::Loopback => "loopback", _ => "public" },
                })
            })
            .collect();
        json!({ "free": free, "udp_free": self.udp, "allow_owner": self.allow })
    }

    /// The sockets of one protocol, or nothing when the spec names no port of it.
    async fn sockets(
        &self,
        ctx: &CheckContext,
        proto: Proto,
        notes: &mut Vec<String>,
    ) -> Result<Seen, CheckError> {
        let wanted = match proto {
            Proto::Tcp => !self.tcp.is_empty(),
            Proto::Udp => !self.udp.is_empty(),
        };
        if !wanted {
            return Ok(Seen::default());
        }
        let files = match proto {
            Proto::Tcp => [(TCP4, false), (TCP6, true)],
            Proto::Udp => [(UDP4, false), (UDP6, true)],
        };
        let mut seen = Seen::default();
        for (path, v6) in files {
            match ctx.probe().read(Path::new(path)).await {
                Ok(file) => {
                    let cut = file.truncated();
                    let table = net::parse(&String::from_utf8_lossy(&file.bytes), v6, cut);
                    // The kernel lists the listening TCP sockets first, so a cut that falls among the
                    // others loses no listener. A UDP table has no such order.
                    let lost = cut
                        && (proto == Proto::Udp
                            || table.last_state.is_none_or(|state| state == net::LISTEN));
                    if lost {
                        seen.why_not(format!("{path} is longer than the 1 MiB rdy reads"));
                    }
                    if table.skipped > 0 {
                        notes.push(format!(
                            "{} rows of {path} could not be read and were left out.",
                            table.skipped
                        ));
                    }
                    seen.sockets.extend(table.sockets);
                }
                Err(error) => match soft(error)? {
                    ProbeError::NotFound if v6 => notes.push(format!(
                        "{path} is absent, so IPv6 is off or hidden on this machine."
                    )),
                    ProbeError::NotFound => seen.why_not(format!("{path} is absent")),
                    other => seen.why_not(format!("{path} could not be read ({})", short(&other))),
                },
            }
        }
        Ok(seen)
    }
}

impl Check for Ports {
    fn info(&self) -> &'static CheckInfo {
        &INFO
    }

    fn run<'a>(&'a self, ctx: &'a CheckContext) -> BoxFuture<'a, CheckOutcome> {
        Box::pin(self.inspect(ctx))
    }
}

/// The sockets read for one protocol and why they may not be all of them.
#[derive(Debug, Default)]
struct Seen {
    sockets: Vec<net::Socket>,
    unverified: Option<String>,
}

impl Seen {
    fn why_not(&mut self, why: String) {
        match &mut self.unverified {
            Some(text) => {
                text.push_str("; ");
                text.push_str(&why);
            }
            None => self.unverified = Some(why),
        }
    }
}

/// What the tables say about one required port.
fn port_state(
    proto: Proto,
    port: u16,
    bind: Bind,
    seen: &Seen,
    range: Option<range::Span>,
    reserved: &[range::Span],
) -> PortState {
    let mut held: Vec<Held> = Vec::new();
    for socket in &seen.sockets {
        let holds = match proto {
            Proto::Tcp => socket.state == net::LISTEN,
            Proto::Udp => true,
        };
        if holds
            && socket.port == port
            && report::conflicts(socket, bind)
            && !held.iter().any(|h| h.socket == *socket)
        {
            held.push(Held {
                socket: socket.clone(),
                owner: None,
                gap: None,
            });
        }
    }
    PortState {
        proto,
        port,
        bind,
        held,
        unverified: seen.unverified.clone(),
        ephemeral: range.is_some_and(|range| range::exposed(range, reserved, port)),
    }
}

/// The ephemeral range and the reserved ports. A file that cannot be read is a note, and the overlap is
/// then not judged.
async fn ephemeral(
    ctx: &CheckContext,
    notes: &mut Vec<String>,
) -> Result<(Option<range::Span>, Vec<range::Span>, bool), CheckError> {
    let span = match read_text(ctx, PORT_RANGE).await? {
        Read::Text(text) => {
            let span = range::parse_range(&text);
            if span.is_none() {
                notes.push(format!(
                    "{PORT_RANGE} is not two numbers, so the ephemeral range was not checked."
                ));
            }
            span
        }
        Read::Absent => None,
        Read::Unreadable(why) => {
            notes.push(format!(
                "{PORT_RANGE} could not be read ({why}), so the ephemeral range was not checked."
            ));
            None
        }
    };
    let (reserved, known) = match read_text(ctx, RESERVED).await? {
        Read::Text(text) => {
            let (spans, complete) = range::parse_reserved(&text);
            if !complete {
                notes.push(format!(
                    "{RESERVED} lists more items than rdy reads, so a reserved port may be missed."
                ));
            }
            (spans, complete)
        }
        Read::Absent => (Vec::new(), true),
        Read::Unreadable(why) => {
            notes.push(format!(
                "{RESERVED} could not be read ({why}), so reserved ports may be missed."
            ));
            (Vec::new(), false)
        }
    };
    Ok((span, reserved, known))
}

/// The network namespace of rdy, as `net:[4026531840]`.
async fn netns(ctx: &CheckContext) -> Result<Option<String>, CheckError> {
    match ctx.probe().read_link(Path::new(NETNS)).await {
        Ok(link) => Ok(namespace(&link.bytes)),
        Err(error) => {
            soft(error)?;
            Ok(None)
        }
    }
}

/// `net:[4026531840]`, rebuilt from the digits so nothing else can ride along.
pub(crate) fn namespace(target: &[u8]) -> Option<String> {
    let digits = target.strip_prefix(b"net:[")?.strip_suffix(b"]")?;
    let ok = !digits.is_empty() && digits.len() <= 20 && digits.iter().all(u8::is_ascii_digit);
    ok.then(|| format!("net:[{}]", String::from_utf8_lossy(digits)))
}

/// The marker that shows rdy runs in a container, if there is one.
async fn container(ctx: &CheckContext) -> Result<Option<String>, CheckError> {
    for marker in CONTAINER_MARKERS {
        match ctx.probe().stat(Path::new(marker)).await {
            Ok(Some(_)) => return Ok(Some(format!("{marker} exists"))),
            Ok(None) => {}
            Err(error) => {
                soft(error)?;
            }
        }
    }
    Ok(match ctx.probe().env(KUBE_HOST) {
        Ok(Some(value)) if !value.is_empty() => Some(format!("{KUBE_HOST} is set")),
        _ => None,
    })
}
