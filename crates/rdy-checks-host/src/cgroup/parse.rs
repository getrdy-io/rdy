//! Pure parsers for the cgroup helper. Text in, values out, no I/O.

/// The value the v1 memory controller shows for "no limit" is `LONG_MAX` rounded down to a page:
/// `9223372036854771712` with 4 KiB pages, `9223372036854710272` with 64 KiB pages. Anything at or
/// above this floor is no limit.
const UNLIMITED_FLOOR: u64 = 0x7FFF_FFFF_FFFF_0000;

/// One line of `/proc/self/cgroup`: `hierarchy-id:controller-list:path`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct ProcLine {
    /// The controllers of this hierarchy. Empty for the v2 line. `name=systemd` is kept as written.
    pub controllers: Vec<String>,
    /// The cgroup path, without a ` (deleted)` suffix.
    pub path: String,
}

/// Parses `/proc/self/cgroup`. The error names the first line that is not in the form.
pub(super) fn parse_proc_cgroup(text: &str) -> Result<Vec<ProcLine>, String> {
    let mut lines = Vec::new();
    for (index, line) in text.lines().enumerate() {
        if line.trim().is_empty() {
            continue;
        }
        let number = index + 1;
        // The path may hold a colon, so only the first two split.
        let mut parts = line.splitn(3, ':');
        let (Some(id), Some(controllers), Some(path)) = (parts.next(), parts.next(), parts.next())
        else {
            return Err(format!("line {number} has no `id:controllers:path` form"));
        };
        if id.is_empty() || !id.bytes().all(|b| b.is_ascii_digit()) {
            return Err(format!("line {number} has no hierarchy id"));
        }
        if !path.starts_with('/') {
            return Err(format!("line {number} has a path that is not absolute"));
        }
        let path = path.strip_suffix(" (deleted)").unwrap_or(path);
        lines.push(ProcLine {
            controllers: controllers
                .split(',')
                .filter(|c| !c.is_empty())
                .map(str::to_owned)
                .collect(),
            path: path.to_owned(),
        });
    }
    Ok(lines)
}

/// A cgroup mount from `/proc/self/mountinfo`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct Mount {
    /// The part of the hierarchy this mount shows, `/` for all of it.
    pub root: String,
    /// Where it is mounted.
    pub point: String,
    /// `true` for `cgroup2`, `false` for the v1 `cgroup`.
    pub v2: bool,
    /// The super options. For v1 they name the controllers (`rw,cpu,cpuacct`, `rw,name=systemd`).
    pub super_opts: Vec<String>,
}

/// The cgroup mounts in `/proc/self/mountinfo`, in file order. Lines of other file systems and lines
/// that are not in the form are left out: only a cgroup mount matters here.
pub(super) fn parse_mountinfo(text: &str) -> Vec<Mount> {
    text.lines().filter_map(mount_line).collect()
}

fn mount_line(line: &str) -> Option<Mount> {
    // `id parent major:minor root point options [optional fields] - fstype source super-options`
    let fields: Vec<&str> = line.split(' ').collect();
    let dash = fields.iter().position(|f| *f == "-")?;
    if dash < 6 {
        return None;
    }
    let v2 = match *fields.get(dash + 1)? {
        "cgroup2" => true,
        "cgroup" => false,
        _ => return None,
    };
    let super_opts = fields.get(dash + 3).copied().unwrap_or_default();
    Some(Mount {
        root: unescape(fields[3]),
        point: unescape(fields[4]),
        v2,
        super_opts: super_opts
            .split(',')
            .filter(|o| !o.is_empty())
            .map(str::to_owned)
            .collect(),
    })
}

/// Undoes the octal escapes the kernel writes in mountinfo paths: `\040` is a space, `\011` a tab,
/// `\012` a newline and `\134` a backslash.
pub(super) fn unescape(text: &str) -> String {
    let bytes = text.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut at = 0;
    while at < bytes.len() {
        if bytes[at] == b'\\'
            && let Some(digits) = bytes.get(at + 1..at + 4)
            && digits.iter().all(|d| (b'0'..=b'7').contains(d))
        {
            let value = digits
                .iter()
                .fold(0u32, |acc, d| acc * 8 + u32::from(d - b'0'));
            if let Ok(byte) = u8::try_from(value) {
                out.push(byte);
                at += 4;
                continue;
            }
        }
        out.push(bytes[at]);
        at += 1;
    }
    String::from_utf8_lossy(&out).into_owned()
}

/// The components of a cgroup or mount path. `None` when a component is `.` or `..`: a cgroup outside
/// the namespace shows as `/..`, and rdy does not walk there.
pub(super) fn components(path: &str) -> Option<Vec<&str>> {
    let parts: Vec<&str> = path.split('/').filter(|p| !p.is_empty()).collect();
    if parts.iter().any(|p| *p == "." || *p == "..") {
        None
    } else {
        Some(parts)
    }
}

/// A byte limit from `memory.max`, `memory.swap.max` or `memory.limit_in_bytes`. `None` is no limit:
/// the v2 word `max`, or the v1 value that stands for it.
pub(super) fn parse_bytes(text: &str) -> Result<Option<u64>, String> {
    let word = text.trim();
    if word == "max" {
        return Ok(None);
    }
    let value: u64 = word
        .parse()
        .map_err(|_| "a byte limit is a number or `max`".to_owned())?;
    Ok((value < UNLIMITED_FLOOR).then_some(value))
}

/// A CPU quota: microseconds of CPU time per period.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CpuQuota {
    /// Microseconds of CPU time the group may use in one period.
    pub quota_us: u64,
    /// The period in microseconds.
    pub period_us: u64,
}

impl CpuQuota {
    /// The quota as a number of CPUs: `200000/100000` is `2.0`.
    #[must_use]
    pub fn cores(&self) -> f64 {
        // Both are microsecond counts far below 2^53, so the conversion is exact.
        self.quota_us as f64 / self.period_us as f64
    }

    /// Whether this quota allows less CPU than `other`.
    pub(super) fn less_than(&self, other: &Self) -> bool {
        u128::from(self.quota_us) * u128::from(other.period_us)
            < u128::from(other.quota_us) * u128::from(self.period_us)
    }
}

/// `cpu.max` of a v2 cgroup: `max 100000` or `200000 100000`. `None` is no limit.
pub(super) fn parse_cpu_max(text: &str) -> Result<Option<CpuQuota>, String> {
    let mut words = text.split_whitespace();
    let quota = words.next().ok_or("`cpu.max` is empty")?;
    let period = words.next().map(parse_period).transpose()?;
    if words.next().is_some() {
        return Err("`cpu.max` has more than two fields".to_owned());
    }
    if quota == "max" {
        return Ok(None);
    }
    // The kernel always prints both fields. A missing period gets the kernel default.
    Ok(Some(CpuQuota {
        quota_us: parse_quota(quota)?,
        period_us: period.unwrap_or(100_000),
    }))
}

/// A v1 CPU quota from `cpu.cfs_quota_us` (`-1` is no limit) and `cpu.cfs_period_us`.
pub(super) fn parse_cfs(quota: &str, period: &str) -> Result<Option<CpuQuota>, String> {
    let period_us = parse_period(period.trim())?;
    let quota = quota.trim();
    if quota == "-1" {
        return Ok(None);
    }
    Ok(Some(CpuQuota {
        quota_us: parse_quota(quota)?,
        period_us,
    }))
}

fn parse_quota(word: &str) -> Result<u64, String> {
    match word.parse::<u64>() {
        Ok(value) if value > 0 => Ok(value),
        _ => Err("a CPU quota is a positive number, `max` or (v1) -1".to_owned()),
    }
}

fn parse_period(word: &str) -> Result<u64, String> {
    match word.parse::<u64>() {
        Ok(value) if value > 0 => Ok(value),
        _ => Err("a CPU period is a positive number".to_owned()),
    }
}

/// The words of `cgroup.controllers` or `cgroup.subtree_control`.
pub(super) fn parse_word_list(text: &str) -> Vec<String> {
    text.split_whitespace().map(str::to_owned).collect()
}
