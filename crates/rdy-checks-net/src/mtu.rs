//! `net.mtu`: the MTU of the default route interface, and the room it leaves for an overlay network.
//!
//! Linux only in M1. It reads `/sys/class/net/<if>/{mtu,operstate,type}` and the default route from
//! `/proc/net/route` and `/proc/net/ipv6_route` through the probe. macOS and Windows are `NotYet`: the
//! `sysinfo` source is M2-010, so on those systems the check ends as "not yet on this OS". It does not
//! measure path MTU (`net.pmtu` is reserved).
//!
//! The judgement is a pure function in `judge`, and the route tables are parsed in `route`. Neither
//! touches the machine.
//!
//! **No privilege needed.** Every file is world readable. One interface that cannot be read becomes a
//! note, and the default route interface that cannot be read becomes a warning that says it was not
//! checked. Container plumbing (`veth*`, `cali*`, `lxc*`) is counted and not read, and at most
//! [`READ_MAX`] other interfaces are read, so a busy Kubernetes node costs a bounded number of reads.

use std::time::Duration;

use rdy_engine::check::{
    BoxFuture, Check, CheckContext, CheckError, CheckInfo, CheckMeta, CheckOutcome, Os, OsSupport,
    Support,
};
use rdy_engine::probe::{Probe, ProbeError};
use rdy_spec::check::{NetMtu, Underlay};
use std::path::Path;

use crate::text::{short, soft};

mod judge;
mod route;

#[cfg(test)]
mod tests;

use judge::{Chosen, Facts, Family, Iface, Rules, judge, kind_of};

const SYS_NET: &str = "/sys/class/net";
const ROUTE_V4: &str = "/proc/net/route";
const ROUTE_V6: &str = "/proc/net/ipv6_route";

/// The most interfaces whose files are read. The rest are counted.
const READ_MAX: usize = 64;

/// Interface name prefixes of container plumbing: one per pod, never the path off the node. They are
/// counted and not read.
const PLUMBING: [&str; 3] = ["veth", "cali", "lxc"];

/// The largest MTU that is believed. The loopback MTU is 65536.
const MTU_MAX: u32 = 1_000_000;

/// What the check says on an OS it has no data source for.
const NO_SOURCE: &str = "this check reads /sys/class/net and has no data source on this OS yet";

/// Linux is `Full`. The `sysinfo` source for macOS and Windows arrives with M2-010 (MF-02).
const OS: OsSupport = OsSupport {
    linux: Support::Full,
    macos: Support::NotYet,
    windows: Support::NotYet,
};

/// The static facts about `net.mtu` (03 section 3).
///
/// `/sys/class/net/<if>` is a link into `/sys/devices`. The check declares only `/sys/class/net`. The
/// read policy admits the resolved path of such a link when it ends with `net/<if>/<file>` under
/// `/sys/devices/`, and no other path there (SEC-28-1), so a disk serial, a `vpd` page, `wwid` or a DMI
/// asset tag under `/sys/devices` stays unreadable. Files in the class directory, such as the MAC
/// `address`, are readable by the prefix, but this check reads only `mtu`, `operstate` and `type`.
pub(crate) static INFO: CheckInfo = CheckInfo {
    id: "net.mtu",
    family: "net",
    summary: "Interface MTU and overlay headroom",
    meta: CheckMeta {
        title: "Network MTU",
        remediation: "Set the MTU of the default interface to match the network, and the CNI MTU to the interface MTU less the overlay header (on IPv4, 50 for VXLAN and Geneve, 60 for WireGuard, 20 for IPIP). Set it in your network configuration (netplan, NetworkManager or the ifcfg files) so it survives a reboot. If the network is above 1500, allow ICMP \"fragmentation needed\" through every firewall on the path.",
    },
    needs: &[],
    wants: &[],
    default_timeout: Some(Duration::from_secs(3)),
    os: OS,
    reads: &[SYS_NET, ROUTE_V4, ROUTE_V6],
    statfs: &[],
    env: &[],
    commands: &[],
    peers: &[],
};

/// `net.mtu`.
///
/// Built from the spec entry's `min_mtu`, `overlay` and `underlay` ([`MtuCheck::from_params`]).
#[derive(Debug, Clone, Copy)]
pub struct MtuCheck {
    rules: Rules,
}

impl MtuCheck {
    /// The check for these spec parameters.
    #[must_use]
    pub fn from_params(params: &NetMtu) -> Self {
        Self {
            rules: Rules {
                min_mtu: params.min_mtu.map(|mtu| u32::from(mtu.get())),
                overlay: params.overlay,
                underlay: params.underlay,
            },
        }
    }

    async fn inspect(&self, ctx: &CheckContext) -> CheckOutcome {
        if ctx.os() != Os::Linux {
            return Err(CheckError::Unsupported(NO_SOURCE));
        }
        let probe = ctx.probe();
        let mut notes = Vec::new();
        let default = default_route(probe, self.rules.underlay, &mut notes).await?;
        let mut facts = interfaces(probe, default.as_ref(), &mut notes).await?;
        facts.default = default;
        facts.notes = notes;
        Ok(judge(facts, &self.rules))
    }
}

impl Check for MtuCheck {
    fn info(&self) -> &'static CheckInfo {
        &INFO
    }

    fn run<'a>(&'a self, ctx: &'a CheckContext) -> BoxFuture<'a, CheckOutcome> {
        Box::pin(self.inspect(ctx))
    }
}

/// A name from a directory listing that can be one path component.
fn is_component(name: &str) -> bool {
    !name.is_empty() && name != "." && name != ".." && !name.contains(['/', '\\', '\0'])
}

/// A text file of sysfs, trimmed, or `None` with a note when it cannot be read.
async fn sysfs_text(
    probe: &Probe,
    iface: &str,
    file: &str,
    notes: &mut Vec<String>,
) -> Result<Option<String>, CheckError> {
    let path = format!("{SYS_NET}/{iface}/{file}");
    match probe.read(Path::new(&path)).await {
        Ok(bytes) => Ok(Some(
            String::from_utf8_lossy(&bytes.bytes).trim().to_owned(),
        )),
        Err(error) => {
            let error = soft(error)?;
            if !matches!(error, ProbeError::NotFound) {
                notes.push(format!(
                    "The {file} of {} could not be read: {}.",
                    crate::text::code(iface),
                    short(&error)
                ));
            }
            Ok(None)
        }
    }
}

/// Lists the interfaces and reads the three files of each. The default route interface is always read,
/// first, whatever its name and however many interfaces there are.
async fn interfaces(
    probe: &Probe,
    default: Option<&Chosen>,
    notes: &mut Vec<String>,
) -> Result<Facts, CheckError> {
    let entries = match probe.read_dir(Path::new(SYS_NET)).await {
        Ok(entries) => entries,
        Err(error) => {
            return Err(match soft(error)? {
                ProbeError::NotFound => CheckError::Failed {
                    message: format!("{SYS_NET} does not exist on this machine"),
                    hint: "Check that /sys is mounted. A container started without it, or a chroot, has no /sys. Check that the user who runs rdy may read /sys/class/net.".to_owned(),
                },
                other => CheckError::Failed {
                    message: format!("{SYS_NET} could not be listed: {}", short(&other)),
                    hint: "Check that /sys is mounted and readable by this user.".to_owned(),
                },
            });
        }
    };
    let mut names: Vec<String> = entries
        .into_iter()
        .map(|entry| entry.name)
        .filter(|name| is_component(name) && name != "lo")
        .collect();
    names.sort();
    names.dedup();

    let mut facts = Facts::default();
    let mut to_read = Vec::new();
    for name in names {
        if default.is_some_and(|chosen| chosen.iface == name) {
            to_read.insert(0, name);
        } else if PLUMBING.iter().any(|prefix| name.starts_with(prefix)) {
            facts.container_ifaces += 1;
        } else {
            to_read.push(name);
        }
    }
    facts.unread_ifaces = to_read.len().saturating_sub(READ_MAX);
    to_read.truncate(READ_MAX);
    for name in to_read {
        let mtu = match sysfs_text(probe, &name, "mtu", notes).await? {
            Some(text) => {
                let mtu = text
                    .parse::<u32>()
                    .ok()
                    .filter(|mtu| (1..=MTU_MAX).contains(mtu));
                if mtu.is_none() {
                    notes.push(format!(
                        "The mtu file of {} did not hold a usable number.",
                        crate::text::code(&name)
                    ));
                }
                mtu
            }
            None => None,
        };
        let state = sysfs_text(probe, &name, "operstate", notes)
            .await?
            .unwrap_or_else(|| "unknown".to_owned());
        let arphrd = sysfs_text(probe, &name, "type", notes)
            .await?
            .and_then(|text| text.parse::<u32>().ok());
        let kind = kind_of(arphrd, &name);
        facts.ifaces.push(Iface {
            name,
            mtu,
            state,
            kind,
        });
    }
    facts.ifaces.sort_by(|a, b| a.name.cmp(&b.name));
    Ok(facts)
}

/// The default route of the underlay's IP version, else of the other one.
async fn default_route(
    probe: &Probe,
    underlay: Underlay,
    notes: &mut Vec<String>,
) -> Result<Option<Chosen>, CheckError> {
    let v4 = table(probe, ROUTE_V4, notes)
        .await?
        .and_then(|text| route::default_v4(&text))
        .map(|route| Chosen {
            iface: route.iface,
            family: Family::V4,
        });
    let v6 = table(probe, ROUTE_V6, notes)
        .await?
        .and_then(|text| route::default_v6(&text))
        .map(|route| Chosen {
            iface: route.iface,
            family: Family::V6,
        });
    let (first, second) = if underlay == Underlay::Ipv6 {
        (v6, v4)
    } else {
        (v4, v6)
    };
    if let (Some(first), Some(second)) = (&first, &second)
        && first.iface != second.iface
    {
        notes.push(format!(
            "The IPv4 and IPv6 default routes use different interfaces. rdy judged {}.",
            crate::text::code(&first.iface)
        ));
    }
    Ok(first.or(second))
}

/// A route table as text. A missing file is no routes. An unreadable one adds a note.
async fn table(
    probe: &Probe,
    path: &str,
    notes: &mut Vec<String>,
) -> Result<Option<String>, CheckError> {
    match probe.read(Path::new(path)).await {
        Ok(bytes) => Ok(Some(String::from_utf8_lossy(&bytes.bytes).into_owned())),
        Err(error) => {
            let error = soft(error)?;
            if !matches!(error, ProbeError::NotFound) {
                notes.push(format!("{path} could not be read: {}.", short(&error)));
            }
            Ok(None)
        }
    }
}
