//! The judgement of `host.memory`: a pure function from facts and rules to one finding.
//!
//! Nothing here reads the machine. The thresholds are the ones in 03, "host.memory":
//!
//! - the total (the smaller of the host's `MemTotal` and the cgroup limit) below `min` by more than
//!   the nominal band is a fail, inside the band it is a pass with a note (or a warn with
//!   `tolerance_result: warn`);
//! - available memory below `min_available` is a warn;
//! - swap on when the spec forbids it is a fail.

use rdy_engine::check::{Finding, Level};
use rdy_engine::units::{Band, SizeFit, format_bytes};
use rdy_spec::Quantity;
use rdy_spec::check::SwapPolicy;
use serde_json::json;

use super::meminfo::Available;

const MIB: u64 = 1 << 20;
const GIB: u64 = 1 << 30;

/// The longest cgroup path shown in a sentence.
const SHOWN_PATH: usize = 160;

/// What the spec asks for.
#[derive(Debug, Clone, Copy)]
pub(super) struct Rules {
    pub min: Quantity,
    /// Bytes. The spec default is half of `min`.
    pub min_available: u64,
    pub swap: SwapPolicy,
    pub band: Band,
    /// What a total inside the band counts as: `Pass`, or `Warn`.
    pub in_band: Level,
}

/// A limit and the cgroup that sets it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct Limit {
    pub bytes: u64,
    /// The cgroup path in its hierarchy. Raw: the engine redacts the finding.
    pub at: String,
}

/// What the cgroup helper found.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub(super) struct Cgroup {
    /// `v1` or `v2`, when a memory controller answered.
    pub hierarchy: Option<&'static str>,
    pub limit: Option<Limit>,
    pub swap_limit: Option<Limit>,
}

/// What the machine said.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct Facts {
    pub host_total: u64,
    pub available: Option<Available>,
    /// `None` when the kernel does not report swap, which is the same as no swap.
    pub swap_total: Option<u64>,
    pub swap_free: Option<u64>,
    pub cgroup: Cgroup,
    /// Things the reads could not settle, for the report.
    pub notes: Vec<String>,
}

fn rank(level: Level) -> u8 {
    match level {
        Level::Pass => 0,
        Level::Warn => 1,
        Level::Fail => 2,
    }
}

/// A cgroup path for a sentence: control characters replaced, long paths cut.
fn shown(at: &str) -> String {
    let clean: String = at
        .chars()
        .map(|c| if c.is_control() { '?' } else { c })
        .collect();
    if clean.chars().count() > SHOWN_PATH {
        let cut: String = clean.chars().take(SHOWN_PATH).collect();
        format!("{cut}...")
    } else {
        clean
    }
}

/// The size for `MemoryMax=`: whole GiB when it is, otherwise MiB rounded up.
fn systemd_size(bytes: u64) -> String {
    if bytes.is_multiple_of(GIB) {
        format!("{}G", bytes / GIB)
    } else {
        format!("{}M", bytes.div_ceil(MIB))
    }
}

/// A systemd unit name safe to put in a command: the last path part, with a unit suffix.
fn unit_of(at: &str) -> Option<&str> {
    let last = at.rsplit('/').next()?;
    let suffix_ok = [".service", ".slice", ".scope"]
        .iter()
        .any(|s| last.ends_with(s));
    let chars_ok = last
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || matches!(c, '_' | '.' | '@' | ':' | '-'));
    (suffix_ok && chars_ok && last.len() <= 128 && !last.starts_with('-')).then_some(last)
}

/// How to raise the limit set at `at`, as one sentence.
fn raise(at: &str, need: u64) -> String {
    let last = at.rsplit('/').next().unwrap_or_default();
    if at.contains("kubepods") {
        return "Raise the memory limit of the pod in its Kubernetes spec.".to_owned();
    }
    let container = [
        "docker-",
        "cri-containerd-",
        "crio-",
        "libpod-",
        "containerd-",
    ]
    .iter()
    .any(|p| last.starts_with(p))
        || at.starts_with("/docker/");
    if container {
        return "Raise the memory limit of the container (--memory for docker and podman) and start it again.".to_owned();
    }
    match unit_of(at) {
        Some(unit) => format!(
            "Raise it with `systemctl set-property {unit} MemoryMax={}`.",
            systemd_size(need)
        ),
        None => "Raise that limit, or run rdy outside the cgroup.".to_owned(),
    }
}

/// The finding for these facts under these rules.
pub(super) fn judge(rules: &Rules, facts: &Facts) -> Finding {
    let min = rules.min;
    let host = facts.host_total;
    // A limit above the host's memory does not bind.
    let limit = facts.cgroup.limit.as_ref().filter(|l| l.bytes < host);
    let effective = limit.map_or(host, |l| l.bytes);

    let fit = rules.band.assess(effective, min);
    let total_level = fit.level(rules.in_band);
    let mut level = total_level;
    let mut message = Vec::new();
    let mut fixes = Vec::new();
    let mut notes = facts.notes.clone();

    // The total.
    let mut total = fit.note().unwrap_or_else(|| {
        format!(
            "{} found, {} needed",
            format_bytes(effective),
            format_bytes(min.bytes())
        )
    });
    if let Some(l) = limit {
        total.push_str(&format!(
            ", limited by cgroup {}, host has {}",
            shown(&l.at),
            format_bytes(host)
        ));
    }
    message.push(total);
    if matches!(fit, SizeFit::InBand { .. }) {
        notes.push(
            "Machines sold with a nominal size show a little less than that size, so the spec allows a small shortfall (tolerance_percent)."
                .to_owned(),
        );
    }
    if total_level != Level::Pass {
        fixes.push(match limit {
            Some(l) => format!(
                "The memory limit of cgroup {} is {}, {} needed (the host has {}). {}",
                shown(&l.at),
                format_bytes(l.bytes),
                format_bytes(min.bytes()),
                format_bytes(host),
                raise(&l.at, min.bytes())
            ),
            None => format!(
                "{} RAM, {} needed. Add RAM or pick a larger node class. A nominal 32 GiB machine shows about 31 GiB, so ask for a size class, not an exact number.",
                format_bytes(effective),
                format_bytes(min.bytes())
            ),
        });
    }

    // Available memory, capped by the cgroup limit.
    let mut available_seen = None;
    if let Some(a) = facts.available {
        let bytes = limit.map_or(a.bytes, |l| a.bytes.min(l.bytes));
        available_seen = Some(bytes);
        if a.estimated {
            notes.push(
                "This kernel has no MemAvailable line, so available memory is estimated as MemFree + Buffers + Cached."
                    .to_owned(),
            );
        }
        if bytes < rules.min_available {
            level = if rank(level) < rank(Level::Warn) {
                Level::Warn
            } else {
                level
            };
            let about = if a.estimated { "about " } else { "" };
            message.push(format!(
                "only {about}{} available, {} wanted, the box is busy",
                format_bytes(bytes),
                format_bytes(rules.min_available)
            ));
            fixes.push(format!(
                "Only {about}{} of RAM is available. Stop other workloads on this machine or pick a larger node class, then run rdy again.",
                format_bytes(bytes)
            ));
        }
        if limit.is_some() {
            notes.push(
                "Available memory is the host's figure capped at the cgroup limit. Use inside the cgroup is not measured."
                    .to_owned(),
            );
        }
    } else {
        notes.push("Available memory could not be read from /proc/meminfo.".to_owned());
    }

    // Swap.
    let swap_total = facts.swap_total.unwrap_or(0);
    let swap_used = swap_total.saturating_sub(facts.swap_free.unwrap_or(swap_total));
    if facts.swap_total.is_none() {
        notes.push(
            "This kernel does not report swap in /proc/meminfo, so swap is counted as off."
                .to_owned(),
        );
    }
    if rules.swap == SwapPolicy::Forbid && swap_total > 0 {
        level = Level::Fail;
        message.push(format!(
            "swap is on ({}), the spec says it must be off",
            format_bytes(swap_total)
        ));
        fixes.push(format!(
            "Swap is on ({}). Run `swapoff -a` and comment out the swap lines in `/etc/fstab`.",
            format_bytes(swap_total)
        ));
        if let Some(s) = &facts.cgroup.swap_limit {
            notes.push(format!(
                "The cgroup swap limit is {} at {}. Swap is judged for the whole machine.",
                format_bytes(s.bytes),
                shown(&s.at)
            ));
        }
    }

    let mut finding = Finding::new(level, message.join("; "))
        .with_observed(json!({
            "total_bytes": host,
            "available_bytes": facts.available.map(|a| a.bytes),
            "available_estimated": facts.available.is_some_and(|a| a.estimated),
            "available_effective_bytes": available_seen,
            "swap_total_bytes": swap_total,
            "swap_used_bytes": swap_used,
            "cgroup_limit_bytes": facts.cgroup.limit.as_ref().map(|l| l.bytes),
            "cgroup_limit_at": facts.cgroup.limit.as_ref().map(|l| shown(&l.at)),
            "cgroup_swap_limit_bytes": facts.cgroup.swap_limit.as_ref().map(|l| l.bytes),
            "cgroup_hierarchy": facts.cgroup.hierarchy,
            "effective_bytes": effective,
        }))
        .with_expected(json!({
            "min_bytes": min.bytes(),
            "min_available_bytes": rules.min_available,
            "band_bytes": rules.band.width(min),
            "swap": match rules.swap {
                SwapPolicy::Forbid => "forbid",
                _ => "any",
            },
        }));
    if level != Level::Pass {
        finding = finding.with_fix(fixes.join(" "));
    }
    for note in notes {
        finding = finding.with_note(note);
    }
    finding
}
