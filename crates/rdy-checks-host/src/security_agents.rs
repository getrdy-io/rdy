//! `host.security_agents`: is a process from a known security-software product running.
//!
//! Linux only in M1. The check lists `/proc`, reads `/proc/<pid>/comm` for each process and compares the
//! names with the catalog (`data/agents.toml`, see [`crate::agents`]). It says "a process with this name
//! is running". It does not say the product is installed, and it never shows a user or a command line.
//!
//! The read policy refuses `/proc/<pid>/cmdline`, so the check cannot use argv[0] to recover a name the
//! kernel cut to 15 bytes. It matches the cut name instead (ADR 0036). Directories, unit files, kernel
//! modules, Windows and macOS are M2 (M2-050, M2-007, M2-009).
//!
//! Absence is weak evidence when rdy cannot see every process: not root with a hidden `/proc`
//! (`hidepid`), a process directory that cannot be read, or a list cut short. In those cases the result
//! says "not detected (limited view)", names the missing privilege, and stays a warning if the spec
//! forbids any agent.

use std::collections::{BTreeMap, BTreeSet};
use std::path::Path;
use std::time::Duration;

use rdy_engine::check::{
    BoxFuture, Check, CheckContext, CheckError, CheckInfo, CheckMeta, CheckOutcome, Finding, Level,
    Need, Os, Partial,
};
use rdy_engine::probe::ProbeError;
use serde_json::json;

use crate::agents::{self, Agent, Catalog};
use crate::family::{OS, ROOT};
use crate::text::soft;

#[cfg(test)]
mod tests;

/// What the check says on an OS it has no data source for.
const NO_SOURCE: &str =
    "this check reads Linux process names and has no data source on this OS yet";

const PROC: &str = "/proc";
const MOUNTINFO: &str = "/proc/self/mountinfo";

/// The most processes one run reads. A busy host has a few thousand. More than this is cut and said so.
pub(crate) const MAX_PIDS: usize = 16_384;
/// The check stops reading when less than this is left of its time.
const STOP_BEFORE: Duration = Duration::from_millis(250);
/// The most process names shown for one product.
const SHOW_NAMES: usize = 8;

/// The static facts about `host.security_agents` (03 section 2).
///
/// `/proc` is the one read prefix. The read policy allows only `comm`, `stat`, `status`, `cgroup` and a
/// few more under a process directory, so declaring the prefix does not open `cmdline` or `environ`.
pub(crate) static INFO: CheckInfo = CheckInfo {
    id: "host.security_agents",
    family: "host",
    summary: "Security software processes that inspect file and process activity",
    meta: CheckMeta {
        title: "Security software",
        remediation: "Security software often inspects file opens and process launches. If the install is slow or fails, ask the security team to review exclusions for the product's paths, then run rdy again.",
    },
    needs: &[],
    wants: ROOT,
    default_timeout: Some(Duration::from_secs(5)),
    os: OS,
    reads: &[PROC],
    statfs: &[],
    env: &[],
    commands: &[],
    peers: &[],
};

/// `host.security_agents`.
///
/// Built from the spec's `forbid` and `allow` agent ids. With neither, any detected product is a
/// warning.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct SecurityAgents {
    forbid: BTreeSet<String>,
    allow: BTreeSet<String>,
}

impl SecurityAgents {
    /// A check for these agent ids. A detected product in `forbid` fails the check, and one in `allow`
    /// is fine. An id in both is forbidden.
    #[must_use]
    pub fn new(
        forbid: impl IntoIterator<Item = String>,
        allow: impl IntoIterator<Item = String>,
    ) -> Self {
        Self {
            forbid: forbid.into_iter().collect(),
            allow: allow.into_iter().collect(),
        }
    }

    /// The forbidden agent ids, sorted.
    #[must_use]
    pub fn forbid(&self) -> Vec<&str> {
        self.forbid.iter().map(String::as_str).collect()
    }

    /// The allowed agent ids, sorted.
    #[must_use]
    pub fn allow(&self) -> Vec<&str> {
        self.allow.iter().map(String::as_str).collect()
    }

    async fn inspect(&self, ctx: &CheckContext, max_pids: usize) -> CheckOutcome {
        if ctx.os() != Os::Linux {
            return Err(CheckError::Unsupported(NO_SOURCE));
        }
        let catalog = agents::catalog().map_err(|error| CheckError::Failed {
            message: error.to_string(),
            hint: rdy_engine::plan::NEWER_RDY.to_owned(),
        })?;
        let root = ctx.has(&Need::Root);
        let scan = Scan::run(ctx, root, max_pids).await?;
        Ok(self.judge(catalog, &scan))
    }

    /// One finding from what the scan saw.
    fn judge(&self, catalog: &Catalog, scan: &Scan) -> Finding {
        let hits: Vec<Hit<'_>> = catalog
            .agents()
            .iter()
            .filter_map(|agent| {
                let seen: Vec<&str> = scan
                    .comms
                    .keys()
                    .map(String::as_str)
                    .filter(|comm| agent.matches_comm(comm))
                    .collect();
                (!seen.is_empty()).then_some(Hit { agent, seen })
            })
            .collect();
        let forbidden = |hit: &&Hit<'_>| self.forbid.contains(&hit.agent.id);
        let allowed = |hit: &&Hit<'_>| !forbidden(hit) && self.allow.contains(&hit.agent.id);
        let blocked: Vec<&Hit<'_>> = hits.iter().filter(forbidden).collect();
        let permitted: Vec<&Hit<'_>> = hits.iter().filter(allowed).collect();
        let flagged: Vec<&Hit<'_>> = hits
            .iter()
            .filter(|hit| !forbidden(hit) && !allowed(hit))
            .collect();
        let unknown_forbid: Vec<&str> = self
            .forbid
            .iter()
            .map(String::as_str)
            .filter(|id| catalog.get(id).is_none())
            .collect();
        let unknown_allow: Vec<&str> = self
            .allow
            .iter()
            .map(String::as_str)
            .filter(|id| catalog.get(id).is_none())
            .collect();
        let cannot_confirm = scan.incomplete() && !self.forbid.is_empty() && blocked.is_empty();

        let level = if !blocked.is_empty() {
            Level::Fail
        } else if !flagged.is_empty() || !unknown_forbid.is_empty() || cannot_confirm {
            Level::Warn
        } else {
            Level::Pass
        };

        let mut parts: Vec<String> = Vec::new();
        if !blocked.is_empty() {
            parts.push(format!("The spec forbids {}.", names(&blocked)));
        }
        if !flagged.is_empty() {
            parts.push(format!("Detected {}.", names(&flagged)));
        }
        if !permitted.is_empty() {
            parts.push(format!("The spec allows {}.", names(&permitted)));
        }
        if !unknown_forbid.is_empty() {
            parts.push(format!(
                "The spec forbids {}, which this rdy does not know, so it cannot check for {}.",
                unknown_forbid.join(", "),
                if unknown_forbid.len() == 1 {
                    "it"
                } else {
                    "them"
                }
            ));
        }
        if hits.is_empty() {
            parts.push(if scan.incomplete() {
                format!(
                    "No known security software process was detected among the {} processes rdy could read (limited view).",
                    scan.read
                )
            } else {
                format!(
                    "No known security software process was found among {} processes.",
                    scan.read
                )
            });
        }
        if cannot_confirm {
            parts.push("Cannot confirm that the forbidden software is absent.".to_owned());
        }

        let mut finding = Finding::new(level, parts.join(" "))
            .with_observed(self.observed(&hits, scan))
            .with_expected(json!({
                "forbid": self.forbid(),
                "allow": self.allow(),
            }));
        if !hits.is_empty() {
            finding = finding.with_note(
                "A match means a process with this name is running. It does not show that the product is installed.",
            );
        } else {
            finding = finding.with_note(
                "rdy sees the processes of the machine it runs on. In a container, host processes are not visible.",
            );
        }
        if !unknown_allow.is_empty() {
            finding = finding.with_note(format!(
                "The spec allows {}, which this rdy does not know. It has no effect.",
                unknown_allow.join(", ")
            ));
        }
        if let Some(partial) = scan.partial() {
            finding = finding.with_partial(partial);
        }
        if level != Level::Pass {
            finding = finding.with_fix(fix(&blocked, &flagged, &unknown_forbid, scan));
        }
        finding
    }

    fn observed(&self, hits: &[Hit<'_>], scan: &Scan) -> serde_json::Value {
        let detected: Vec<serde_json::Value> = hits
            .iter()
            .map(|hit| {
                json!({
                    "id": hit.agent.id,
                    "display_name": hit.agent.display_name,
                    "category": hit.agent.category.word(),
                    "processes": hit.seen.iter().take(SHOW_NAMES).collect::<Vec<_>>(),
                    "count": hit.seen.iter().map(|comm| scan.comms.get(*comm).copied().unwrap_or(0)).sum::<u32>(),
                })
            })
            .collect();
        json!({
            "detected": detected,
            "processes_read": scan.read,
            "processes_unreadable": scan.unreadable,
            "limited_view": scan.incomplete(),
            "list_cut": scan.cut,
        })
    }
}

impl Check for SecurityAgents {
    fn info(&self) -> &'static CheckInfo {
        &INFO
    }

    fn run<'a>(&'a self, ctx: &'a CheckContext) -> BoxFuture<'a, CheckOutcome> {
        Box::pin(self.inspect(ctx, MAX_PIDS))
    }
}

/// A catalog entry and the process names it matched.
struct Hit<'a> {
    agent: &'a Agent,
    seen: Vec<&'a str>,
}

/// `A (EDR)`, `A (EDR) and B (antivirus)`, `A (EDR), B (antivirus) and C (backup)`.
fn names(hits: &[&Hit<'_>]) -> String {
    let each: Vec<String> = hits
        .iter()
        .map(|hit| {
            format!(
                "{} ({})",
                hit.agent.display_name,
                hit.agent.category.label()
            )
        })
        .collect();
    match each.as_slice() {
        [] => String::new(),
        [one] => one.clone(),
        [init @ .., last] => format!("{} and {last}", init.join(", ")),
    }
}

/// The fixed neutral advice. The words never claim that a product breaks anything.
fn fix(blocked: &[&Hit<'_>], flagged: &[&Hit<'_>], unknown_forbid: &[&str], scan: &Scan) -> String {
    let mut sentences: Vec<String> = Vec::new();
    if !blocked.is_empty() {
        sentences.push(format!(
            "The vendor's requirements do not allow {} on this host. Use a host without it, or ask the vendor which security software it supports, then run rdy again.",
            names(blocked)
        ));
    }
    if !flagged.is_empty() {
        sentences.push(format!(
            "Software in this category often inspects file opens and process launches. If the install is slow or fails, ask the security team to review exclusions for the product's paths, then run rdy again. Detected: {}.",
            names(flagged)
        ));
    }
    let docs: Vec<String> = blocked
        .iter()
        .chain(flagged.iter())
        .filter_map(|hit| {
            hit.agent
                .exclusion_docs_url
                .as_ref()
                .map(|url| format!("{}: {url}", hit.agent.display_name))
        })
        .collect();
    if !docs.is_empty() {
        sentences.push(format!(
            "The vendor's own page on exclusions: {}.",
            docs.join(", ")
        ));
    }
    if !unknown_forbid.is_empty() {
        sentences.push(
            "Update rdy, or fix the id in the spec. Run rdy spec lint to see the known ids."
                .to_owned(),
        );
    }
    // `limited` (not root) cannot be true with `gap` (root), so it comes first. `gap` and `cut` can both
    // be true, and each has its own fix, so both are said.
    if scan.limited {
        sentences.push("Run rdy as root so it can see every process.".to_owned());
    }
    if scan.gap {
        sentences.push(
            "Some processes could not be read even as root. Check for a security module that limits /proc reads (for example SELinux or AppArmor denials in the audit log), then run rdy again."
                .to_owned(),
        );
    }
    if scan.cut {
        sentences.push(
            "The host has more processes than rdy reads in one run, so some were not looked at."
                .to_owned(),
        );
    }
    sentences.join(" ")
}

/// What reading `/proc` gave.
#[derive(Debug, Default)]
struct Scan {
    /// Each distinct process name and how many processes have it.
    comms: BTreeMap<String, u32>,
    /// Processes whose name was read.
    read: usize,
    /// Processes that were listed and could not be read (not counting ones that ended meanwhile).
    unreadable: usize,
    /// Not root, and the machine hides other users' processes.
    limited: bool,
    /// The list was longer than the cap, or time ran short.
    cut: bool,
    /// Root, and some names still could not be read (denied by a security module, or a read timed out).
    gap: bool,
}

impl Scan {
    /// Whether absence proves little: a hidden or cut process list.
    fn incomplete(&self) -> bool {
        self.limited || self.cut || self.gap
    }

    fn partial(&self) -> Option<Partial> {
        if self.limited {
            Some(Partial::new(
                vec![Need::Root],
                "Other users' processes may be hidden from rdy, so absence is not proven.",
            ))
        } else {
            // `gap` and `cut` can both be true: say both.
            let reason = match (self.gap, self.cut) {
                (true, true) => {
                    "Some process names could not be read even as root and the process list was cut short, so absence is not proven."
                }
                (true, false) => {
                    "Some process names could not be read even as root, so absence is not proven."
                }
                (false, true) => "The process list was cut short, so absence is not proven.",
                (false, false) => return None,
            };
            Some(Partial::new(Vec::new(), reason))
        }
    }

    async fn run(ctx: &CheckContext, root: bool, max_pids: usize) -> Result<Self, CheckError> {
        let probe = ctx.probe();
        let entries = probe
            .read_dir(Path::new(PROC))
            .await
            .map_err(CheckError::Probe)?;
        let mut pids: Vec<(u64, String)> = entries
            .into_iter()
            .filter(|entry| entry.is_dir)
            .filter_map(|entry| {
                let number = entry.name.parse::<u64>().ok()?;
                entry
                    .name
                    .bytes()
                    .all(|b| b.is_ascii_digit())
                    .then_some((number, entry.name))
            })
            .collect();
        pids.sort_unstable();
        let mut scan = Self::default();
        if pids.len() > max_pids {
            pids.truncate(max_pids);
            scan.cut = true;
        }
        for (_, pid) in &pids {
            if ctx.remaining() < STOP_BEFORE {
                scan.cut = true;
                break;
            }
            let path = format!("{PROC}/{pid}/comm");
            match probe.read(Path::new(&path)).await {
                Ok(file) => {
                    if let Some(comm) = comm_of(&file.bytes) {
                        scan.read += 1;
                        *scan.comms.entry(comm).or_insert(0) += 1;
                    }
                }
                Err(error) => match soft(error)? {
                    // The process ended between the listing and the read.
                    ProbeError::NotFound => {}
                    _ => scan.unreadable += 1,
                },
            }
        }
        if root {
            // Root sees every process, so a name that cannot be read is a gap in the view, not a reason to
            // pass: a forbidden agent could sit in it.
            scan.gap = scan.unreadable > 0;
        } else {
            scan.limited = scan.unreadable > 0 || hides_processes(ctx).await?;
        }
        Ok(scan)
    }
}

/// The process name in the bytes of `/proc/<pid>/comm`: the text up to the first newline. `None` when it
/// is empty.
pub(crate) fn comm_of(bytes: &[u8]) -> Option<String> {
    let line = bytes.split(|b| *b == b'\n').next().unwrap_or_default();
    let text = String::from_utf8_lossy(line);
    let text = text.trim_matches('\0');
    (!text.is_empty()).then(|| text.chars().take(64).collect())
}

/// Whether `/proc` is mounted with `hidepid`, which hides other users' processes from a non-root run.
///
/// Only the options of the mount at `/proc` count. A mountinfo that cannot be read or has no such line
/// says no: the per-process read errors are the second signal.
async fn hides_processes(ctx: &CheckContext) -> Result<bool, CheckError> {
    match ctx.probe().read(Path::new(MOUNTINFO)).await {
        Ok(file) => Ok(proc_mount_hides(&String::from_utf8_lossy(&file.bytes))),
        Err(error) => {
            soft(error)?;
            Ok(false)
        }
    }
}

/// Parses mountinfo text (`man 5 proc`): `.. mount-point options .. - fstype source super-options`.
pub(crate) fn proc_mount_hides(mountinfo: &str) -> bool {
    mountinfo.lines().any(|line| {
        let Some((left, right)) = line.split_once(" - ") else {
            return false;
        };
        let left: Vec<&str> = left.split(' ').collect();
        let right: Vec<&str> = right.split(' ').collect();
        let at_proc = left.get(4) == Some(&"/proc");
        let is_proc = right.first() == Some(&"proc");
        at_proc
            && is_proc
            && left
                .get(5)
                .into_iter()
                .chain(right.get(2))
                .flat_map(|options| options.split(','))
                .any(hidepid_hides)
    })
}

/// `hidepid=1`, `2`, `4`, `noaccess`, `invisible` and `ptraceable` hide or lock other users' processes.
/// `0` and `off` do not.
fn hidepid_hides(option: &str) -> bool {
    option
        .strip_prefix("hidepid=")
        .is_some_and(|mode| !matches!(mode, "0" | "off" | ""))
}
