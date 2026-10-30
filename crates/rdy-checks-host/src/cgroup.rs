//! The cgroup helper: the memory and CPU limits that apply to rdy, and the controllers it can see.
//!
//! Serves `host.memory` (M1-069), `host.cpu` (M1-071) and `host.cgroups` (M1-151). Linux only. On
//! another OS [`Cgroups::discover`] returns `None` without reading anything.
//!
//! **How it finds the limits.** `/proc/self/cgroup` says which cgroup rdy is in, one line per
//! hierarchy. `/proc/self/mountinfo` says where each hierarchy is mounted, and which part of it the
//! mount shows (a container may see only its own subtree). The helper joins the two, then reads the
//! limit file of the cgroup and of every parent up to the top of the mount. The effective limit is the
//! smallest finite value on that chain, because a parent limit binds its children. Each answer says at
//! which cgroup the smallest value was found.
//!
//! **What counts as no limit.** The v2 word `max`, and for the v1 memory controller any value at or
//! above `0x7FFFFFFFFFFF0000`. The kernel writes `9223372036854771712` there with 4 KiB pages and
//! `9223372036854710272` with 64 KiB pages. For v1 CPU, a quota of `-1`.
//!
//! **What it does not hide.** A level whose file is missing is skipped: the controller is not on there
//! (the v2 root never has `memory.max`). A level whose file cannot be read or understood is counted in
//! [`Chain::unreadable`], and the check says the answer may be incomplete. [`Chain::hidden_above`] says
//! the mount shows only a subtree, so a parent limit above it could not be seen.
//!
//! **Hybrid layouts.** With a v2 mount and v1 mounts, the helper uses v2 for a controller when v2
//! answered at some level, and the v1 hierarchy otherwise. An unreadable v2 level does not hide a v1
//! limit; it is reported only when v1 has nothing either.
//!
//! **Which mounts count.** Only mounts at `/sys/fs/cgroup` or under it, because the probe may read
//! nothing else. Of those, the mount that shows the most of the hierarchy wins.
//!
//! **Reads.** The probe only allows what the calling check declares in `CheckInfo::reads`. Every check
//! that calls this helper lists [`READS`].
//!
//! Not read yet: the v1 mem+swap limit (`memory.memsw.limit_in_bytes`), so [`Memory::swap`] is empty on
//! a v1 host; CPU sets and `memory.high`.

use std::collections::BTreeSet;
use std::path::Path;

use rdy_engine::check::Os;
use rdy_engine::probe::{Probe, ProbeError};

mod parse;

#[cfg(test)]
mod tests;
#[cfg(test)]
mod unit_tests;

pub use parse::CpuQuota;
use parse::{ProcLine, components, parse_proc_cgroup};

/// The paths the helper reads. A check that uses it lists these in `CheckInfo::reads`.
pub const READS: [&str; 3] = [
    "/proc/self/cgroup",
    "/proc/self/mountinfo",
    "/sys/fs/cgroup",
];

/// The deepest cgroup path the helper follows. The kernel allows more. A path deeper than this counts
/// as not visible.
const MAX_DEPTH: usize = 64;

/// Why the cgroup files could not be used.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum CgroupError {
    /// A file is not in the form the kernel documents.
    #[error(
        "{file} is not in the expected form: {reason}. Fix: none needed on your side, report the result without cgroup limits and file a bug if this repeats"
    )]
    Malformed {
        /// The file.
        file: &'static str,
        /// What was wrong. It never holds file content.
        reason: String,
    },
    /// The probe refused the read or failed.
    #[error(transparent)]
    Probe(#[from] ProbeError),
}

/// How the machine mounts cgroups.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum Layout {
    /// Only v1 hierarchies are mounted.
    V1,
    /// A v2 hierarchy and v1 hierarchies are mounted. Controllers live in v1.
    Hybrid,
    /// Only the v2 hierarchy is mounted.
    V2,
    /// No cgroup file system is mounted where rdy can see it.
    Unmounted,
}

/// Which hierarchy an answer came from.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum Hierarchy {
    /// The unified v2 hierarchy.
    V2,
    /// A v1 controller hierarchy.
    V1,
}

/// A limit and the cgroup it was found at.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Bound<T> {
    /// The limit.
    pub value: T,
    /// The cgroup that sets it, as a path in its hierarchy: `/` for the top, `/system.slice/acme.service`.
    /// Raw: redact it before it is shown.
    pub at: String,
}

/// What reading one limit file along the parent chain gave.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Chain<T> {
    /// The smallest finite limit on the chain, nearest the process when two are equal. `None` means
    /// no level set a limit.
    pub min: Option<Bound<T>>,
    /// The levels whose file was read and understood. `0` means the controller answered nowhere: it is
    /// not on, or the file does not exist on this kernel.
    pub levels_read: usize,
    /// The levels whose file exists and could not be read or understood.
    pub unreadable: usize,
    /// `true` when the mount shows only a subtree of the hierarchy, so limits above it were not seen.
    pub hidden_above: bool,
}

impl<T> Chain<T> {
    fn new(hidden_above: bool) -> Self {
        Self {
            min: None,
            levels_read: 0,
            unreadable: 0,
            hidden_above,
        }
    }

    /// `true` when at least one level answered.
    #[must_use]
    pub fn is_present(&self) -> bool {
        self.levels_read > 0
    }

    /// `true` when every level that has the file was read. Without that, "no limit" may be wrong.
    #[must_use]
    pub fn is_complete(&self) -> bool {
        self.unreadable == 0
    }

    fn add(&mut self, at: &str, seen: Seen<T>, less: impl Fn(&T, &T) -> bool) {
        match seen {
            Seen::Absent => {}
            Seen::Unreadable => self.unreadable += 1,
            Seen::Value(value) => {
                self.levels_read += 1;
                if let Some(value) = value
                    && self.min.as_ref().is_none_or(|m| less(&value, &m.value))
                {
                    self.min = Some(Bound {
                        value,
                        at: at.to_owned(),
                    });
                }
            }
        }
    }
}

/// The memory limits that apply to rdy.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Memory {
    /// Where the answer came from. `None` when no hierarchy has a memory controller on.
    pub hierarchy: Option<Hierarchy>,
    /// The memory limit in bytes (`memory.max`, v1 `memory.limit_in_bytes`).
    pub limit: Chain<u64>,
    /// The swap limit in bytes (`memory.swap.max`). Empty for v1.
    pub swap: Chain<u64>,
}

/// The CPU quota that applies to rdy.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Cpu {
    /// Where the answer came from. `None` when no hierarchy has a CPU controller on.
    pub hierarchy: Option<Hierarchy>,
    /// The quota (`cpu.max`, v1 `cpu.cfs_quota_us` over `cpu.cfs_period_us`).
    pub quota: Chain<CpuQuota>,
}

/// The controller lists of the v2 hierarchy. A list is `None` when its file is missing or unreadable.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct V2Controllers {
    /// `cgroup.controllers` at the top of the mount: what the kernel offers in this hierarchy.
    pub top_available: Option<BTreeSet<String>>,
    /// `cgroup.subtree_control` at the top: what is turned on for its children.
    pub top_enabled: Option<BTreeSet<String>>,
    /// `cgroup.controllers` of rdy's own cgroup: what its parent delegated to it.
    pub own_available: Option<BTreeSet<String>>,
    /// `cgroup.subtree_control` of rdy's own cgroup: what it turned on for its children.
    pub own_enabled: Option<BTreeSet<String>>,
}

/// The controllers rdy can see.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Controllers {
    /// How cgroups are mounted.
    pub layout: Layout,
    /// The v2 lists, when a v2 hierarchy is mounted and rdy is in it.
    pub v2: Option<V2Controllers>,
    /// The controllers of the v1 hierarchies mounted where rdy can see them (`memory`, `cpu`,
    /// `cpuacct`, `pids`). A named hierarchy such as `name=systemd` is not a controller and is left out.
    pub v1: BTreeSet<String>,
}

/// Where rdy sits in one hierarchy.
#[derive(Debug, Clone, PartialEq, Eq)]
struct Placement {
    /// The mount point, without a trailing slash.
    point: String,
    /// How many leading components of the cgroup path the mount root takes.
    skip: usize,
    /// The components of the cgroup path.
    comps: Vec<String>,
    /// The mount root is not `/`.
    hidden_above: bool,
}

/// One cgroup on the chain.
struct Level {
    /// The cgroup path in its hierarchy.
    at: String,
    /// The directory that holds its files.
    dir: String,
}

impl Placement {
    /// The cgroups from rdy's own up to the top of the mount.
    fn levels(&self) -> Vec<Level> {
        (self.skip..=self.comps.len())
            .rev()
            .map(|end| Level {
                at: format!("/{}", self.comps[..end].join("/")),
                dir: if end == self.skip {
                    self.point.clone()
                } else {
                    format!("{}/{}", self.point, self.comps[self.skip..end].join("/"))
                },
            })
            .collect()
    }
}

/// One v1 hierarchy line of `/proc/self/cgroup` and where it is mounted.
#[derive(Debug, Clone, PartialEq, Eq)]
struct V1Hierarchy {
    controllers: Vec<String>,
    placement: Option<Placement>,
}

/// The cgroups rdy is in and where they are mounted. Build it with [`Cgroups::discover`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Cgroups {
    layout: Layout,
    v2: Option<Placement>,
    v1: Vec<V1Hierarchy>,
}

/// What one level gave.
enum Seen<T> {
    Absent,
    Unreadable,
    Value(Option<T>),
}

/// What reading one file gave.
enum Raw {
    Absent,
    Unreadable,
    Text(String),
}

impl Cgroups {
    /// Reads `/proc/self/cgroup` and `/proc/self/mountinfo`. `None` when this is not Linux or the
    /// kernel has no `/proc/self/cgroup`. A cgroup that no visible mount shows is left out of the
    /// answers, and [`Cgroups::layout`] says what is mounted.
    ///
    /// Only the first 1 MiB of `mountinfo` is read, as for every file. The cgroup mounts come first on
    /// a normal boot.
    ///
    /// # Errors
    ///
    /// [`CgroupError::Malformed`] when `/proc/self/cgroup` is not in the documented form;
    /// [`CgroupError::Probe`] when the probe refuses or fails (a denied path, a timeout).
    pub async fn discover(probe: &Probe) -> Result<Option<Self>, CgroupError> {
        if probe.os() != Os::Linux {
            return Ok(None);
        }
        let Some(proc_cgroup) = read_text(probe, READS[0]).await? else {
            return Ok(None);
        };
        let lines = parse_proc_cgroup(&proc_cgroup).map_err(|reason| CgroupError::Malformed {
            file: "/proc/self/cgroup",
            reason,
        })?;
        let mounts = read_mountinfo(probe).await?;
        let (has_v2, has_v1) = (mounts.iter().any(|m| m.v2), mounts.iter().any(|m| !m.v2));
        let layout = match (has_v2, has_v1) {
            (true, true) => Layout::Hybrid,
            (true, false) => Layout::V2,
            (false, true) => Layout::V1,
            (false, false) => Layout::Unmounted,
        };
        let place = |line: &ProcLine, wanted: &dyn Fn(&parse::Mount) -> bool| {
            let comps = components(&line.path)?;
            if comps.len() > MAX_DEPTH {
                return None;
            }
            // Only mounts the probe may read count: a private mount elsewhere would make every read
            // Denied. Of those, the one that shows the most of the hierarchy (the shortest root) wins.
            mounts
                .iter()
                .filter(|m| wanted(m) && under_reads(&m.point))
                .filter_map(|mount| {
                    let root = components(&mount.root)?;
                    comps.starts_with(&root).then(|| Placement {
                        point: mount.point.trim_end_matches('/').to_owned(),
                        skip: root.len(),
                        comps: comps.iter().map(|c| (*c).to_owned()).collect(),
                        hidden_above: !root.is_empty(),
                    })
                })
                .min_by_key(|place| place.skip)
        };
        let v2 = lines
            .iter()
            .find(|line| line.controllers.is_empty())
            .and_then(|line| place(line, &|m| m.v2));
        let v1 = lines
            .iter()
            .filter(|line| !line.controllers.is_empty())
            .map(|line| V1Hierarchy {
                controllers: line.controllers.clone(),
                placement: place(line, &|m| {
                    !m.v2 && line.controllers.iter().all(|c| m.super_opts.contains(c))
                }),
            })
            .collect();
        Ok(Some(Self { layout, v2, v1 }))
    }

    /// How cgroups are mounted.
    #[must_use]
    pub fn layout(&self) -> Layout {
        self.layout
    }

    /// The v1 hierarchy that has `controller` and a mount rdy can see.
    fn v1_for(&self, controller: &str) -> Option<&Placement> {
        self.v1
            .iter()
            .find(|h| h.controllers.iter().any(|c| c == controller))
            .and_then(|h| h.placement.as_ref())
    }

    /// The memory limit and the swap limit along the parent chain.
    ///
    /// # Errors
    ///
    /// [`CgroupError::Probe`] when the probe refuses or fails. A file that is missing, unreadable or
    /// not understood is counted in the answer instead.
    pub async fn memory(&self, probe: &Probe) -> Result<Memory, CgroupError> {
        // v2 wins only when it answered. A hierarchy that answered nowhere has no controller files, and
        // an unreadable level in it must not hide the v1 limit. Its unreadable count is kept only when
        // v1 has nothing either.
        let mut fallback = None;
        if let Some(place) = &self.v2 {
            let limit = walk(probe, place, "memory.max", parse::parse_bytes, u64_less).await?;
            let swap = walk(
                probe,
                place,
                "memory.swap.max",
                parse::parse_bytes,
                u64_less,
            )
            .await?;
            let memory = Memory {
                hierarchy: Some(Hierarchy::V2),
                limit,
                swap,
            };
            if memory.limit.is_present() || memory.swap.is_present() {
                return Ok(memory);
            }
            if !memory.limit.is_complete() || !memory.swap.is_complete() {
                fallback = Some(memory);
            }
        }
        if let Some(place) = self.v1_for("memory") {
            let limit = walk(
                probe,
                place,
                "memory.limit_in_bytes",
                parse::parse_bytes,
                u64_less,
            )
            .await?;
            if limit.is_present() || !limit.is_complete() {
                return Ok(Memory {
                    hierarchy: Some(Hierarchy::V1),
                    limit,
                    swap: Chain::new(place.hidden_above),
                });
            }
        }
        if let Some(memory) = fallback {
            return Ok(memory);
        }
        let hidden = self.v2.as_ref().is_some_and(|p| p.hidden_above);
        Ok(Memory {
            hierarchy: None,
            limit: Chain::new(hidden),
            swap: Chain::new(hidden),
        })
    }

    /// The CPU quota along the parent chain.
    ///
    /// # Errors
    ///
    /// The same as [`Cgroups::memory`].
    pub async fn cpu(&self, probe: &Probe) -> Result<Cpu, CgroupError> {
        let mut fallback = None;
        if let Some(place) = &self.v2 {
            let quota = walk(probe, place, "cpu.max", parse::parse_cpu_max, quota_less).await?;
            let cpu = Cpu {
                hierarchy: Some(Hierarchy::V2),
                quota,
            };
            if cpu.quota.is_present() {
                return Ok(cpu);
            }
            if !cpu.quota.is_complete() {
                fallback = Some(cpu);
            }
        }
        if let Some(place) = self.v1_for("cpu") {
            let quota = walk_cfs(probe, place).await?;
            if quota.is_present() || !quota.is_complete() {
                return Ok(Cpu {
                    hierarchy: Some(Hierarchy::V1),
                    quota,
                });
            }
        }
        if let Some(cpu) = fallback {
            return Ok(cpu);
        }
        Ok(Cpu {
            hierarchy: None,
            quota: Chain::new(self.v2.as_ref().is_some_and(|p| p.hidden_above)),
        })
    }

    /// The controllers rdy can see.
    ///
    /// # Errors
    ///
    /// [`CgroupError::Probe`] when the probe refuses or fails.
    pub async fn controllers(&self, probe: &Probe) -> Result<Controllers, CgroupError> {
        let v2 = match &self.v2 {
            None => None,
            Some(place) => {
                let own = place
                    .levels()
                    .into_iter()
                    .next()
                    .map_or_else(|| place.point.clone(), |level| level.dir);
                Some(V2Controllers {
                    top_available: read_set(probe, &place.point, "cgroup.controllers").await?,
                    top_enabled: read_set(probe, &place.point, "cgroup.subtree_control").await?,
                    own_available: read_set(probe, &own, "cgroup.controllers").await?,
                    own_enabled: read_set(probe, &own, "cgroup.subtree_control").await?,
                })
            }
        };
        let v1 = self
            .v1
            .iter()
            .filter(|h| h.placement.is_some())
            .flat_map(|h| h.controllers.iter())
            .filter(|c| !c.starts_with("name="))
            .cloned()
            .collect();
        Ok(Controllers {
            layout: self.layout,
            v2,
            v1,
        })
    }
}

fn u64_less(a: &u64, b: &u64) -> bool {
    a < b
}

fn quota_less(a: &CpuQuota, b: &CpuQuota) -> bool {
    a.less_than(b)
}

/// Reads `name` in the directory `dir`.
async fn read_file(probe: &Probe, dir: &str, name: &str) -> Result<Raw, CgroupError> {
    let path = format!("{dir}/{name}");
    match probe.read(Path::new(&path)).await {
        Ok(file) => Ok(Raw::Text(String::from_utf8_lossy(&file.bytes).into_owned())),
        Err(ProbeError::NotFound) => Ok(Raw::Absent),
        Err(ProbeError::PermissionDenied | ProbeError::Io(_)) => Ok(Raw::Unreadable),
        Err(other) => Err(other.into()),
    }
}

/// `true` when a mount point is `/sys/fs/cgroup` or under it, the only place the probe may read.
fn under_reads(point: &str) -> bool {
    let point = point.trim_end_matches('/');
    point == READS[2]
        || point
            .strip_prefix(READS[2])
            .is_some_and(|rest| rest.starts_with('/'))
}

/// The cgroup mounts in `/proc/self/mountinfo`. When the read was cut, the last line may be cut too and
/// is dropped.
async fn read_mountinfo(probe: &Probe) -> Result<Vec<parse::Mount>, CgroupError> {
    match probe.read(Path::new(READS[1])).await {
        Ok(file) => {
            let text = String::from_utf8_lossy(&file.bytes);
            Ok(parse::parse_mountinfo(whole_lines(&text, file.truncated())))
        }
        Err(ProbeError::NotFound) => Ok(Vec::new()),
        Err(other) => Err(other.into()),
    }
}

/// `text` without its last line when `cut` says the read ended early.
fn whole_lines(text: &str, cut: bool) -> &str {
    if cut {
        text.rfind('\n').map_or("", |end| &text[..=end])
    } else {
        text
    }
}

/// A file under `/proc/self`. `None` when it does not exist.
async fn read_text(probe: &Probe, path: &str) -> Result<Option<String>, CgroupError> {
    match probe.read(Path::new(path)).await {
        Ok(file) => Ok(Some(String::from_utf8_lossy(&file.bytes).into_owned())),
        Err(ProbeError::NotFound) => Ok(None),
        Err(other) => Err(other.into()),
    }
}

async fn read_set(
    probe: &Probe,
    dir: &str,
    name: &str,
) -> Result<Option<BTreeSet<String>>, CgroupError> {
    Ok(match read_file(probe, dir, name).await? {
        Raw::Text(text) => Some(parse::parse_word_list(&text).into_iter().collect()),
        Raw::Absent | Raw::Unreadable => None,
    })
}

/// Reads one limit file on every level of the chain.
async fn walk<T>(
    probe: &Probe,
    place: &Placement,
    file: &str,
    parse: fn(&str) -> Result<Option<T>, String>,
    less: fn(&T, &T) -> bool,
) -> Result<Chain<T>, CgroupError> {
    let mut chain = Chain::new(place.hidden_above);
    for level in place.levels() {
        let seen = match read_file(probe, &level.dir, file).await? {
            Raw::Absent => Seen::Absent,
            Raw::Unreadable => Seen::Unreadable,
            Raw::Text(text) => parse(&text).map_or(Seen::Unreadable, Seen::Value),
        };
        chain.add(&level.at, seen, less);
    }
    Ok(chain)
}

/// The v1 form of the CPU quota: two files per level.
async fn walk_cfs(probe: &Probe, place: &Placement) -> Result<Chain<CpuQuota>, CgroupError> {
    let mut chain = Chain::new(place.hidden_above);
    for level in place.levels() {
        let quota = read_file(probe, &level.dir, "cpu.cfs_quota_us").await?;
        let seen = match quota {
            Raw::Absent => Seen::Absent,
            Raw::Unreadable => Seen::Unreadable,
            Raw::Text(quota) => match read_file(probe, &level.dir, "cpu.cfs_period_us").await? {
                Raw::Text(period) => {
                    parse::parse_cfs(&quota, &period).map_or(Seen::Unreadable, Seen::Value)
                }
                Raw::Absent | Raw::Unreadable => Seen::Unreadable,
            },
        };
        chain.add(&level.at, seen, quota_less);
    }
    Ok(chain)
}
