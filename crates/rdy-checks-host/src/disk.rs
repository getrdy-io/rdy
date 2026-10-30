//! `host.disk`: free space, free inodes and mount flags for the file system that holds one path.
//!
//! Linux only in M1. The numbers come from `statvfs` through the probe (`NativeCall::Statvfs`), which
//! the manifest allows for any path with `statfs: ["/"]` and which cannot read a file. The file system
//! type and the `nodev` flag come from `/proc/self/mountinfo`, the one file the check reads.
//!
//! A path that does not exist yet is measured through its nearest existing parent: the check retries
//! `Statvfs` one level up for as long as the answer is `NotFound`. The mount line is the one whose
//! device (field 3) equals the device `Statvfs` reported, and among those the longest whole-component
//! mount point above the path. When no line fits, the type is unknown, and a check that needs the type
//! says "not verified", never a pass.
//!
//! A hung network mount blocks `statvfs`. The live backend runs it on the blocking pool, so the check's
//! timeout (5s) ends the wait and the result is `Timeout`.
//!
//! The judgement ([`judge`]) is a pure function of numbers and text, so tests drive it without a probe.

use std::path::{Path, PathBuf};
use std::time::Duration;

use rdy_engine::check::{
    BoxFuture, Check, CheckContext, CheckError, CheckInfo, CheckMeta, CheckOutcome, Finding, Level,
    Need, Os, Partial,
};
use rdy_engine::probe::{NativeCall, NativeValue, ProbeError, StatvfsInfo};
use rdy_engine::units::format_bytes;
use rdy_spec::Quantity;
use rdy_spec::check::{HostDisk, MountOption};
use serde_json::{Value, json};

use crate::family::OS;
use crate::firewall::{short, soft};

mod mountinfo;
#[cfg(test)]
mod tests;
#[cfg(test)]
mod unit_tests;

use mountinfo::{Lookup, Mount};

/// What the check says on an OS it has no data source for.
const NO_SOURCE: &str = "this check reads Linux mount tables and has no data source on this OS yet";

/// The one file the check reads.
const MOUNTINFO: &str = "/proc/self/mountinfo";

/// Free inodes needed when the spec says nothing (03).
const DEFAULT_MIN_INODES: u64 = 100_000;

/// The most `Statvfs` calls for one path. Each missing level is one call, and a path has at most 1024
/// characters, so this is more than any real install path needs.
const MAX_WALK: usize = 64;

const GIB: u64 = 1 << 30;

/// The static facts about `host.disk` (03 section 2).
pub(crate) static INFO: CheckInfo = CheckInfo {
    id: "host.disk",
    family: "host",
    summary: "Free space, inodes, mount flags per path",
    meta: CheckMeta {
        title: "Disk space and mount flags",
        remediation: "Free up space on the volume that holds the install path, grow the volume, or point the install at a larger disk. On Linux, run `df -h` on the install path to see what is free. If the path is on a `noexec` mount, remount it with `exec` and remove `noexec` from `/etc/fstab`, or move the install path.",
    },
    needs: &[],
    wants: &[],
    default_timeout: Some(Duration::from_secs(5)),
    os: OS,
    reads: &[MOUNTINFO],
    statfs: &["/"],
    env: &[],
    commands: &[],
    peers: &[],
};

/// What the spec asks of the path.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Rules {
    /// Less free than this fails.
    pub min: u64,
    /// Less free than this warns.
    pub recommended: u64,
    /// Fewer free inodes than this fails.
    pub min_inodes: u64,
    /// Mount options that must not be set.
    pub forbid: Vec<MountOption>,
    /// File system types that fail, as the spec wrote them.
    pub forbid_fstypes: Vec<String>,
}

/// `host.disk` for one path.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Disk {
    path: String,
    rules: Rules,
}

impl Disk {
    /// A check for the path and thresholds of one spec entry. Without `recommended`, the warn level is
    /// `min` plus 20%. Without `min_inodes`, the fail level is 100000 free inodes.
    #[must_use]
    pub fn new(params: &HostDisk) -> Self {
        let min = params.min.bytes();
        let recommended = params
            .recommended
            .map_or_else(|| min.saturating_add(min / 5), Quantity::bytes);
        Self {
            path: params.path.as_str().to_owned(),
            rules: Rules {
                min,
                recommended: recommended.max(min),
                min_inodes: params.min_inodes.unwrap_or(DEFAULT_MIN_INODES),
                forbid: params
                    .forbid_options
                    .iter()
                    .flat_map(|list| list.iter().copied())
                    .collect(),
                forbid_fstypes: params
                    .forbid_fstypes
                    .iter()
                    .flat_map(|list| list.iter().map(|t| t.as_str().to_owned()))
                    .collect(),
            },
        }
    }

    /// The path this check measures, as the spec wrote it.
    #[must_use]
    pub fn path(&self) -> &str {
        &self.path
    }

    async fn inspect(&self, ctx: &CheckContext) -> CheckOutcome {
        if ctx.os() != Os::Linux {
            return Err(CheckError::Unsupported(NO_SOURCE));
        }
        let parts = if self.path.starts_with('/') {
            mountinfo::components(&self.path)
        } else {
            None
        };
        let Some(parts) = parts else {
            return Ok(self.stop(
                "the path is not an absolute Linux path without `..`",
                "Write the install path from `/` without `..`, or scope this entry to the OS it is for with `os:`.",
                Vec::new(),
            ));
        };
        let reached = match self.reach(ctx, &parts).await? {
            Reach::Got(reached) => reached,
            Reach::Stop(finding) => return Ok(*finding),
        };
        let kept = &parts[..reached.depth];
        let lookup = lookup_mount(ctx, reached.stat.dev, kept).await?;
        let facts = Facts {
            requested: &self.path,
            measured: join(kept),
            stat: reached.stat,
            mount: lookup,
            root: ctx.has(&Need::Root),
        };
        Ok(judge(&self.rules, &facts))
    }

    /// `Statvfs` for the path, then for each parent while the answer is `NotFound`.
    async fn reach(&self, ctx: &CheckContext, parts: &[&str]) -> Result<Reach, CheckError> {
        self.reach_with(ctx, parts, MAX_WALK).await
    }

    /// [`Disk::reach`] with a limit on the calls, so a test can reach the limit.
    async fn reach_with(
        &self,
        ctx: &CheckContext,
        parts: &[&str],
        limit: usize,
    ) -> Result<Reach, CheckError> {
        let mut depth = parts.len();
        for _ in 0..limit {
            let path = PathBuf::from(join(&parts[..depth]));
            match ctx.probe().native(NativeCall::Statvfs { path }).await {
                Ok(NativeValue::Statvfs(stat)) => return Ok(Reach::Got(Reached { stat, depth })),
                Ok(_) => {
                    return Err(CheckError::Failed {
                        message: "the OS answered a statvfs call with another kind of answer"
                            .to_owned(),
                        hint: "Tell the vendor which rdy version this is.".to_owned(),
                    });
                }
                Err(ProbeError::NotFound) if depth > 0 => depth -= 1,
                Err(ProbeError::NotFound) => {
                    return Ok(Reach::Stop(Box::new(self.stop(
                        "no part of the path exists",
                        "Check that the path is on this machine, or run rdy where the install will run.",
                        Vec::new(),
                    ))));
                }
                Err(ProbeError::PermissionDenied) => {
                    let missing = if ctx.has(&Need::Root) {
                        Vec::new()
                    } else {
                        vec![Need::Root]
                    };
                    return Ok(Reach::Stop(Box::new(self.stop(
                        "cannot open the directory, permission denied",
                        "Run rdy as a user who can enter every directory on the path, or as root.",
                        missing,
                    ))));
                }
                Err(ProbeError::Denied { .. }) => {
                    return Ok(Reach::Stop(Box::new(self.stop(
                        "rdy does not read this path",
                        "Pick an install path outside the system directories rdy keeps off limits.",
                        Vec::new(),
                    ))));
                }
                Err(ProbeError::Unsupported(_)) => return Err(CheckError::Unsupported(NO_SOURCE)),
                Err(ProbeError::Io(text)) => {
                    let why = short(&ProbeError::Io(text));
                    return Ok(Reach::Stop(Box::new(self.stop(
                        &format!("the file system call failed ({why})"),
                        "Check the path, then run rdy again.",
                        Vec::new(),
                    ))));
                }
                Err(other) => return Err(CheckError::Probe(other)),
            }
        }
        Ok(Reach::Stop(Box::new(self.stop(
            "the path has too many missing levels to walk up",
            "Create the install directory, or point the spec at a path that exists.",
            Vec::new(),
        ))))
    }

    /// A warning that the path could not be measured. It never blocks.
    fn stop(&self, why: &str, fix: &str, missing: Vec<Need>) -> Finding {
        let note = format!("Not verified: {why}.");
        Finding::new(
            Level::Warn,
            format!("Cannot measure `{}`: {why}.", self.path),
        )
        .with_observed(json!({ "path": self.path }))
        .with_expected(expected(&self.rules))
        .with_fix(fix)
        .with_partial(Partial::new(missing, note))
    }
}

impl Check for Disk {
    fn info(&self) -> &'static CheckInfo {
        &INFO
    }

    fn run<'a>(&'a self, ctx: &'a CheckContext) -> BoxFuture<'a, CheckOutcome> {
        Box::pin(self.inspect(ctx))
    }
}

struct Reached {
    stat: StatvfsInfo,
    /// How many components of the requested path were kept: all of them when the path exists.
    depth: usize,
}

enum Reach {
    Got(Reached),
    Stop(Box<Finding>),
}

/// `/a/b` from its components. No components is `/`.
fn join(parts: &[&str]) -> String {
    if parts.is_empty() {
        "/".to_owned()
    } else {
        format!("/{}", parts.join("/"))
    }
}

/// What is known about the mount that holds the measured path.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum MountState {
    Found(Mount),
    /// Not known, and why.
    Unknown(String),
}

/// Reads the mount table and finds the line for `dev`.
async fn lookup_mount(
    ctx: &CheckContext,
    dev: Option<(u32, u32)>,
    kept: &[&str],
) -> Result<MountState, CheckError> {
    let Some(dev) = dev else {
        return Ok(MountState::Unknown(
            "the OS gave no device number".to_owned(),
        ));
    };
    let file = match ctx.probe().read(Path::new(MOUNTINFO)).await {
        Ok(file) => file,
        Err(error) => {
            return Ok(MountState::Unknown(match soft(error)? {
                ProbeError::NotFound => format!("{MOUNTINFO} is not there"),
                other => format!("{MOUNTINFO} could not be read ({})", short(&other)),
            }));
        }
    };
    let parsed = mountinfo::parse(&String::from_utf8_lossy(&file.bytes));
    let cut = if file.truncated_tail {
        ", and the file was cut at 1 MiB"
    } else {
        ""
    };
    let (major, minor) = dev;
    Ok(match mountinfo::find(&parsed.mounts, dev, kept) {
        Lookup::Found(mount) => MountState::Found(mount.clone()),
        Lookup::NoDevice => MountState::Unknown(format!(
            "no line in {MOUNTINFO} has device {major}:{minor}{cut}"
        )),
        Lookup::Ambiguous => MountState::Unknown(format!(
            "several mounts in {MOUNTINFO} share device {major}:{minor} and none is above the path{cut}"
        )),
    })
}

/// Everything the judgement needs.
pub(crate) struct Facts<'a> {
    /// The path as the spec wrote it.
    pub requested: &'a str,
    /// The existing path that was measured: the requested path, or its nearest parent.
    pub measured: String,
    pub stat: StatvfsInfo,
    pub mount: MountState,
    /// Whether rdy runs as root.
    pub root: bool,
}

/// A word that is safe to put in a command the customer copies: plain characters as they are, other
/// text in single quotes, and nothing at all for text that no quoting makes safe (a quote, a backtick
/// or a control character).
fn word(text: &str) -> Option<String> {
    if text.is_empty()
        || text
            .chars()
            .any(|c| c.is_control() || c == '`' || c == '\'')
    {
        return None;
    }
    let plain = text
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || "/._-+@%:,=".contains(c));
    Some(if plain {
        text.to_owned()
    } else {
        format!("'{text}'")
    })
}

fn option_name(option: MountOption) -> Option<&'static str> {
    match option {
        MountOption::Noexec => Some("noexec"),
        MountOption::Nosuid => Some("nosuid"),
        MountOption::Nodev => Some("nodev"),
        MountOption::Ro => Some("ro"),
        _ => None,
    }
}

/// The remount option that clears `option`.
fn clearing(option: &str) -> &'static str {
    match option {
        "noexec" => "exec",
        "nosuid" => "suid",
        "nodev" => "dev",
        _ => "rw",
    }
}

fn expected(rules: &Rules) -> Value {
    json!({
        "min": rules.min,
        "recommended": rules.recommended,
        "min_inodes": rules.min_inodes,
        "forbid_options": rules.forbid.iter().filter_map(|o| option_name(*o)).collect::<Vec<_>>(),
        "forbid_fstypes": rules.forbid_fstypes,
    })
}

/// The finding for a measured path.
pub(crate) fn judge(rules: &Rules, facts: &Facts<'_>) -> Finding {
    let stat = &facts.stat;
    let requested = facts.requested;
    let mount = match &facts.mount {
        MountState::Found(mount) => Some(mount),
        MountState::Unknown(_) => None,
    };
    let place = mount.map_or_else(
        || "its file system".to_owned(),
        |m| format!("`{}` ({})", m.point, m.fstype),
    );
    let check_word = word(&facts.measured);

    let mut fails: Vec<String> = Vec::new();
    let mut lows: Vec<String> = Vec::new();
    let mut unverified: Vec<String> = Vec::new();
    let mut fixes: Vec<String> = Vec::new();
    let mut notes: Vec<String> = Vec::new();

    // Free space.
    let frag = stat.fragment_size;
    let free = stat.blocks_available.saturating_mul(frag);
    let total = stat.blocks.saturating_mul(frag);
    if frag == 0 {
        unverified.push(
            "the file system reported a block size of 0, so free space is unknown".to_owned(),
        );
    } else if free < rules.recommended {
        let sentence = if free < rules.min {
            format!(
                "`{requested}` has {} free on {place}, {} needed.",
                format_bytes(free),
                format_bytes(rules.min)
            )
        } else {
            format!(
                "`{requested}` has {} free on {place}. {} is recommended and {} is the least.",
                format_bytes(free),
                format_bytes(rules.recommended),
                format_bytes(rules.min)
            )
        };
        if free < rules.min {
            fails.push(sentence);
        } else {
            lows.push(sentence);
        }
        fixes.push(space_fix(
            check_word.as_deref(),
            mount,
            rules.recommended.saturating_sub(free),
        ));
    }

    // Inodes.
    if stat.files == 0 {
        notes.push("This file system keeps no inode count, so inodes were not checked.".to_owned());
    } else if stat.files_free < rules.min_inodes {
        fails.push(format!(
            "`{requested}` has {} free inodes on {place}, {} needed.",
            stat.files_free, rules.min_inodes
        ));
        fixes.push(match &check_word {
            Some(p) => format!(
                "Run `df -i {p}` to see inode use. Delete many small files or move the install to a file system with more inodes."
            ),
            None => "Run `df -i` on the install path to see inode use. Delete many small files or move the install to a file system with more inodes.".to_owned(),
        });
    }

    // Mount flags the spec forbids.
    for &option in &rules.forbid {
        let Some(name) = option_name(option) else {
            unverified.push("this rdy does not know a mount option the spec forbids".to_owned());
            continue;
        };
        let state = match name {
            "noexec" => stat.no_exec,
            "nosuid" => Some(stat.no_suid),
            "ro" => Some(stat.read_only),
            _ => mount.map(|m| m.has_option("nodev")),
        };
        match state {
            Some(true) => {
                fails.push(format!(
                    "`{requested}` is on {place}, which is mounted {name}. The spec does not allow that."
                ));
                fixes.push(remount_fix(name, mount));
            }
            Some(false) => {}
            None => unverified.push(format!("could not tell whether the file system is {name}")),
        }
    }
    if stat.read_only && !rules.forbid.contains(&MountOption::Ro) {
        lows.push(format!(
            "`{requested}` is on {place}, which is mounted read-only. The install cannot write there."
        ));
        fixes.push(remount_fix("ro", mount));
    }

    // File system type.
    match &facts.mount {
        MountState::Found(m) => {
            let banned = rules
                .forbid_fstypes
                .iter()
                .find(|listed| mountinfo::type_matches(listed, &m.fstype));
            if let Some(listed) = banned {
                fails.push(format!(
                    "`{requested}` is on {place}, a file system type the spec does not allow ({listed})."
                ));
                fixes.push(format!(
                    "Put the install on a local disk such as ext4 or xfs, or ask the vendor whether {} is supported.",
                    m.fstype
                ));
            } else if mountinfo::is_network(&m.fstype) {
                notes.push(format!(
                    "`{}` is a network file system ({}). Free space and speed depend on the server.",
                    m.point, m.fstype
                ));
            }
        }
        MountState::Unknown(why) => {
            if rules.forbid_fstypes.is_empty() {
                notes.push(format!("The file system type is unknown: {why}."));
            } else {
                unverified.push(format!("could not tell the file system type ({why})"));
            }
        }
    }

    if !unverified.is_empty() {
        fixes.push(match &check_word {
            Some(p) => format!(
                "Check by hand: `df -hT {p}` shows the type and free space, and `mount` lists the flags."
            ),
            None => "Check by hand: `df -hT` on the install path shows the type and free space, and `mount` lists the flags.".to_owned(),
        });
    }
    if facts.root {
        notes.push("rdy runs as root. Free space is what other users can use. Blocks reserved for root are not counted.".to_owned());
    }
    if facts.measured != join(&mountinfo::components(requested).unwrap_or_default()) {
        notes.push(format!(
            "`{requested}` does not exist yet. rdy measured `{}`, the nearest parent that exists.",
            facts.measured
        ));
    }

    let level = if !fails.is_empty() {
        Level::Fail
    } else if !unverified.is_empty() || !lows.is_empty() {
        Level::Warn
    } else {
        Level::Pass
    };
    let mut sentences: Vec<String> = fails;
    sentences.extend(unverified.iter().map(|u| format!("Not verified: {u}.")));
    sentences.extend(lows);
    if level == Level::Pass {
        sentences.push(format!(
            "`{requested}` has {} free on {place}. {} is needed.",
            format_bytes(free),
            format_bytes(rules.min)
        ));
    }

    let mut finding = Finding::new(level, sentences.join(" "))
        .with_observed(observed(facts, free, total))
        .with_expected(expected(rules));
    for note in notes {
        finding = finding.with_note(note);
    }
    if level != Level::Pass {
        finding = finding.with_fix(fixes.join(" "));
    }
    if !unverified.is_empty() {
        finding = finding.with_partial(Partial::new(
            Vec::new(),
            format!("Not verified: {}.", unverified.join("; ")),
        ));
    }
    finding
}

/// The advice for too little free space.
fn space_fix(path: Option<&str>, mount: Option<&Mount>, shortfall: u64) -> String {
    let look = match path {
        Some(p) => format!("Run `df -h {p}` to see the volume."),
        None => "Run `df -h` on the install path to see the volume.".to_owned(),
    };
    let lvm = mount
        .filter(|m| m.source.starts_with("/dev/mapper/"))
        .and_then(|m| word(&m.source));
    match lvm {
        Some(source) => {
            let gib = shortfall.div_ceil(GIB).max(1);
            format!(
                "{look} Grow it with `lvextend -r -L +{gib}G {source}`, or point the install at a larger disk."
            )
        }
        None => format!("{look} Grow the volume, or point the install at a larger disk."),
    }
}

/// The advice for a forbidden or read-only mount.
fn remount_fix(option: &str, mount: Option<&Mount>) -> String {
    let clear = clearing(option);
    match mount.and_then(|m| word(&m.point)) {
        Some(point) if option == "ro" => format!(
            "Find out why the volume is read-only (`journalctl -k` shows disk errors). If it is safe, run `mount -o remount,{clear} {point}`. Otherwise move the install path."
        ),
        Some(point) => format!(
            "Run `mount -o remount,{clear} {point}` and remove {option} from /etc/fstab so it stays, or move the install path."
        ),
        None if option == "ro" => {
            "Find out why the volume is read-only, or move the install path.".to_owned()
        }
        None => format!(
            "Remount the volume without {option} and remove {option} from /etc/fstab, or move the install path."
        ),
    }
}

/// The evidence object.
fn observed(facts: &Facts<'_>, free: u64, total: u64) -> Value {
    let stat = &facts.stat;
    let cap = Quantity::MAX_BYTES;
    let (mount, fstype, network, nodev) = match &facts.mount {
        MountState::Found(m) => (
            json!(m.point),
            json!(m.fstype),
            json!(mountinfo::is_network(&m.fstype)),
            json!(m.has_option("nodev")),
        ),
        MountState::Unknown(_) => (Value::Null, Value::Null, Value::Null, Value::Null),
    };
    let inodes = stat.files != 0;
    json!({
        "path": facts.requested,
        "measured_path": facts.measured,
        "mount": mount,
        "device": stat.dev.map(|(major, minor)| format!("{major}:{minor}")),
        "fstype": fstype,
        "network": network,
        "free_bytes": free.min(cap),
        "total_bytes": total.min(cap),
        "free_inodes": inodes.then_some(stat.files_free),
        "total_inodes": inodes.then_some(stat.files),
        "read_only": stat.read_only,
        "noexec": stat.no_exec,
        "nosuid": stat.no_suid,
        "nodev": nodev,
    })
}
