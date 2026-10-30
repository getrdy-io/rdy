//! Pure parsers for `host.cpu`. Text in, values out, no I/O.
//!
//! The kernel files are read by the check through the probe. These functions only turn their text into
//! numbers and sets. They never keep a line of the file: the model string, serial numbers and the other
//! fields of `/proc/cpuinfo` are dropped here, so they cannot reach a finding.

use std::collections::BTreeSet;

/// The largest CPU number rdy accepts in a CPU list. Linux builds stop at 8192 CPUs, so anything above
/// this is a malformed file, not a big machine.
const MAX_CPU: u32 = 1 << 20;

/// The most comma-separated items rdy reads in one CPU list.
const MAX_ITEMS: usize = 4096;

/// A set of CPU numbers in the kernel list form: `0-3,8,10-11`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct CpuList {
    /// Sorted, non-overlapping inclusive ranges.
    ranges: Vec<(u32, u32)>,
}

impl CpuList {
    /// Parses `0-3,8`. `None` when the text is empty or not in the form.
    pub(super) fn parse(text: &str) -> Option<Self> {
        let text = text.trim();
        if text.is_empty() {
            return None;
        }
        let mut ranges = Vec::new();
        for (index, item) in text.split(',').enumerate() {
            if index >= MAX_ITEMS {
                return None;
            }
            let item = item.trim();
            let (low, high) = match item.split_once('-') {
                Some((low, high)) => (number(low)?, number(high)?),
                None => {
                    let one = number(item)?;
                    (one, one)
                }
            };
            if low > high {
                return None;
            }
            ranges.push((low, high));
        }
        ranges.sort_unstable();
        let mut merged: Vec<(u32, u32)> = Vec::with_capacity(ranges.len());
        for (low, high) in ranges {
            match merged.last_mut() {
                Some(last) if low <= last.1.saturating_add(1) => last.1 = last.1.max(high),
                _ => merged.push((low, high)),
            }
        }
        Some(Self { ranges: merged })
    }

    /// A list of `count` CPUs numbered from 0, for a machine that only says how many.
    pub(super) fn first(count: u32) -> Option<Self> {
        let last = count.checked_sub(1)?;
        (last <= MAX_CPU).then(|| Self {
            ranges: vec![(0, last)],
        })
    }

    /// How many CPUs the list holds.
    pub(super) fn count(&self) -> u64 {
        self.ranges
            .iter()
            .map(|(low, high)| u64::from(high - low) + 1)
            .sum()
    }

    /// How many CPUs are in both lists.
    pub(super) fn common(&self, other: &Self) -> u64 {
        let mut total = 0u64;
        for (a_low, a_high) in &self.ranges {
            for (b_low, b_high) in &other.ranges {
                let low = (*a_low).max(*b_low);
                let high = (*a_high).min(*b_high);
                if low <= high {
                    total += u64::from(high - low) + 1;
                }
            }
        }
        total
    }
}

fn number(text: &str) -> Option<u32> {
    let text = text.trim();
    if text.is_empty() || !text.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    text.parse::<u32>().ok().filter(|n| *n <= MAX_CPU)
}

/// The `Cpus_allowed_list` line of `/proc/self/status`: the CPUs the scheduler lets rdy run on.
pub(super) fn allowed_list(status: &str) -> Option<CpuList> {
    status
        .lines()
        .find_map(|line| line.strip_prefix("Cpus_allowed_list:"))
        .and_then(CpuList::parse)
}

/// What `/proc/cpuinfo` says that the check needs. Nothing else is kept.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub(super) struct CpuInfo {
    /// How many processor blocks the file holds.
    pub processors: u32,
    /// The feature names every processor has: the `flags` line on x86, `Features` on Arm. `None` when
    /// no processor block has such a line.
    pub flags: Option<BTreeSet<String>>,
    /// Distinct `(physical id, core id)` pairs, when the file has them. Arm kernels do not print them.
    pub physical_cores: Option<u32>,
}

/// Parses `/proc/cpuinfo`. When `cut` is true the read ended early and the last block may be cut, so
/// it is dropped.
pub(super) fn parse_cpuinfo(text: &str, cut: bool) -> CpuInfo {
    let mut info = CpuInfo::default();
    let mut cores: BTreeSet<(String, String)> = BTreeSet::new();
    let mut have_cores = false;
    let blocks: Vec<&str> = text.split("\n\n").collect();
    let kept = if cut {
        blocks.len().saturating_sub(1)
    } else {
        blocks.len()
    };
    for block in blocks.into_iter().take(kept) {
        let mut is_processor = false;
        let mut flags: Option<BTreeSet<String>> = None;
        let (mut physical, mut core) = (None, None);
        for line in block.lines() {
            let Some((key, value)) = line.split_once(':') else {
                continue;
            };
            let value = value.trim();
            match key.trim() {
                "processor" => is_processor = true,
                "flags" | "Features" | "features" if flags.is_none() => {
                    flags = Some(value.split_whitespace().map(str::to_lowercase).collect());
                }
                "physical id" => physical = Some(value.to_owned()),
                "core id" => core = Some(value.to_owned()),
                _ => {}
            }
        }
        if !is_processor {
            continue;
        }
        info.processors = info.processors.saturating_add(1);
        if let Some(flags) = flags {
            match &mut info.flags {
                Some(common) => common.retain(|flag| flags.contains(flag)),
                None => info.flags = Some(flags),
            }
        }
        if let (Some(physical), Some(core)) = (physical, core) {
            have_cores = true;
            cores.insert((physical, core));
        }
    }
    if have_cores && !cut {
        info.physical_cores = u32::try_from(cores.len()).ok();
    }
    info
}

/// A feature name as the check compares it: lower case, with `-` as `_`.
pub(super) fn normalize(name: &str) -> String {
    name.trim().to_lowercase().replace('-', "_")
}

/// Names that mean the same feature in `/proc/cpuinfo` and in a vendor's documentation. The kernel
/// shows LZCNT as `abm` and SSE3 as `pni`; Arm calls NEON `asimd`.
const ALIASES: &[(&str, &str)] = &[("lzcnt", "abm"), ("sse3", "pni"), ("neon", "asimd")];

/// The feature names of each x86-64 micro-architecture level, as `/proc/cpuinfo` spells them. Each
/// level also needs all the levels below it.
const LEVELS: [&[&str]; 4] = [
    // v1 is the baseline of every x86_64 CPU.
    &[
        "cmov", "cx8", "fpu", "fxsr", "mmx", "syscall", "sse", "sse2",
    ],
    &[
        "cx16", "lahf_lm", "popcnt", "pni", "sse4_1", "sse4_2", "ssse3",
    ],
    &[
        "avx", "avx2", "bmi1", "bmi2", "f16c", "fma", "abm", "movbe", "xsave",
    ],
    &["avx512f", "avx512bw", "avx512cd", "avx512dq", "avx512vl"],
];

/// The level a name asks for: `x86-64-v2` is 2. `None` for any other name.
pub(super) fn level_of(name: &str) -> Option<usize> {
    match normalize(name).as_str() {
        "x86_64_v1" => Some(1),
        "x86_64_v2" => Some(2),
        "x86_64_v3" => Some(3),
        "x86_64_v4" => Some(4),
        _ => None,
    }
}

/// The highest x86-64 level the feature set meets, 0 when it does not meet v1.
pub(super) fn x86_level(flags: &BTreeSet<String>) -> usize {
    LEVELS
        .iter()
        .take_while(|level| level.iter().all(|f| flags.contains(*f)))
        .count()
}

/// The features of levels 1 to `level` that the set lacks.
pub(super) fn level_gaps(flags: &BTreeSet<String>, level: usize) -> Vec<&'static str> {
    LEVELS
        .iter()
        .take(level)
        .flat_map(|names| names.iter().copied())
        .filter(|name| !flags.contains(*name))
        .collect()
}

/// Whether a feature name is present in the set, by its own name or by an alias.
pub(super) fn has_feature(flags: &BTreeSet<String>, name: &str) -> bool {
    let name = normalize(name);
    if flags.contains(&name) {
        return true;
    }
    ALIASES.iter().any(|(a, b)| {
        let other = if name == *a {
            b
        } else if name == *b {
            a
        } else {
            return false;
        };
        flags.contains(*other)
    })
}

/// A CPU architecture as the spec names it: `x86_64` or `aarch64`. `amd64` and `arm64` are folded.
/// Any other machine type is returned lower-cased as it is.
pub(super) fn normalize_arch(machine: &str) -> String {
    let machine = machine.trim().to_lowercase();
    match machine.as_str() {
        "amd64" | "x86_64" | "x86-64" => "x86_64".to_owned(),
        "arm64" | "aarch64" | "aarch64_be" => "aarch64".to_owned(),
        _ => machine,
    }
}

/// Whether DMI product text or a hypervisor type says the machine is a virtual machine. Used where
/// the CPU has no `hypervisor` flag (Arm).
pub(super) fn looks_virtual(product: &str) -> bool {
    let product = product.to_lowercase();
    [
        "virtual",
        "kvm",
        "qemu",
        "vmware",
        "xen",
        "hvm domu",
        "bochs",
        "openstack",
        "google compute engine",
        "amazon ec2",
        "bhyve",
        "parallels",
    ]
    .iter()
    .any(|marker| product.contains(marker))
}
