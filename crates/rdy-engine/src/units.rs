//! Helpers that every check family shares: dotted version compare, byte sizes, the nominal band and
//! the severity cap (03, "Shared helpers"; 02, "Crate layout").
//!
//! They are pure functions with no I/O and no feature gate, so `rdy-checks-host`, `rdy-checks-k8s` and
//! `rdy-checks-gpu` use them without depending on each other. Parsing stays in `rdy-spec`:
//! [`Quantity`] reads `32Gi` and [`Version`] reads `535.104.05`. This module compares and formats.

use std::cmp::Ordering;

use rdy_spec::result::{Severity, Status};
use rdy_spec::{Quantity, Version};

use crate::check::Level;

#[cfg(test)]
mod tests;

const KIB: u64 = 1 << 10;
const MIB: u64 = 1 << 20;
const GIB: u64 = 1 << 30;
const TIB: u64 = 1 << 40;
const PIB: u64 = 1 << 50;

/// Compares two dotted versions part by part as numbers, never as semver.
///
/// The shorter one is padded with zeros, so `1.28` equals `1.28.0` and `535.54.03` is less than
/// `535.104.05`. A leading `v` and leading zeros do not matter.
///
/// `k8s.version` does not use this for a server version. It compares over the parts both sides have, so a
/// bound written `1.31` accepts every 1.31 patch, and it treats a bound with a patch against a server with
/// an unknown patch as unverified, where this function would count the missing patch as zero.
#[must_use]
pub fn compare_versions(a: &Version, b: &Version) -> Ordering {
    let (a, b) = (a.components(), b.components());
    (0..a.len().max(b.len()))
        .map(|i| {
            let left = a.get(i).copied().unwrap_or(0);
            let right = b.get(i).copied().unwrap_or(0);
            left.cmp(&right)
        })
        .find(|order| order.is_ne())
        .unwrap_or(Ordering::Equal)
}

/// `true` when `have` is at least `min`, by [`compare_versions`].
#[must_use]
pub fn version_at_least(have: &Version, min: &Version) -> bool {
    compare_versions(have, min).is_ge()
}

/// Turns a level into a status under the spec's severity: the severity cap.
///
/// `Pass` is `pass` and `Warn` is `warn`. `Fail` is `block` for a required check and `warn` for a
/// `severity: warn` check. An unknown severity counts as required. The outcome mapping uses this
/// function, so there is one rule.
#[must_use]
pub fn cap_level(level: Level, severity: &Severity) -> Status {
    match (level, severity) {
        (Level::Pass, _) => Status::Pass,
        (Level::Warn, _) | (Level::Fail, Severity::Warn) => Status::Warn,
        (Level::Fail, _) => Status::Block,
    }
}

/// Writes a byte count for a message: `31.3 GiB`, `512 MiB`, `100 bytes`.
///
/// It uses binary units and at most one decimal place, and drops a `.0`.
#[must_use]
pub fn format_bytes(bytes: u64) -> String {
    for (name, size) in [
        ("PiB", PIB),
        ("TiB", TIB),
        ("GiB", GIB),
        ("MiB", MIB),
        ("KiB", KIB),
    ] {
        if bytes >= size {
            // Tenths of the unit, rounded to nearest. u128 keeps the multiply exact.
            let tenths = (u128::from(bytes) * 10 + u128::from(size) / 2) / u128::from(size);
            let (whole, tenth) = (tenths / 10, tenths % 10);
            return if tenth == 0 {
                format!("{whole} {name}")
            } else {
                format!("{whole}.{tenth} {name}")
            };
        }
    }
    format!("{bytes} bytes")
}

/// Why a [`Band`] has the width it has for one requirement.
#[derive(Debug, Clone, Copy, PartialEq)]
#[non_exhaustive]
pub enum BandBasis {
    /// The percent of `min`.
    Percent(f64),
    /// The floor in bytes, because the percent came to less.
    Floor(u64),
}

/// How far below `min` a size may be and still count as met.
///
/// People write nominal sizes. A "32 GB" VM shows about 31.3 GiB in `MemTotal`. The band is a percent
/// of `min`, with a floor in bytes. A percent of 0 turns the band off, floor included. The spec's
/// `tolerance_percent` sets the percent (0 to 20, bounded by the spec parser).
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct Band {
    percent: f64,
    floor: u64,
}

fn clean_percent(percent: f64) -> f64 {
    if percent.is_nan() {
        0.0
    } else {
        percent.clamp(0.0, 100.0)
    }
}

impl Band {
    /// The default for RAM: 5 percent, at least 256 MiB.
    pub const MEMORY: Self = Self {
        percent: 5.0,
        floor: 256 * MIB,
    };

    /// The default for GPU memory: 8 percent, no floor.
    pub const VRAM: Self = Self {
        percent: 8.0,
        floor: 0,
    };

    /// A band of `percent` of `min` and at least `floor`.
    ///
    /// A `percent` outside 0 to 100, or not a number, is clamped. 0 turns the band off.
    #[must_use]
    pub fn new(percent: f64, floor: Quantity) -> Self {
        Self {
            percent: clean_percent(percent),
            floor: floor.bytes(),
        }
    }

    /// The same floor with another percent, for a spec `tolerance_percent`.
    #[must_use]
    pub fn with_percent(self, percent: f64) -> Self {
        Self {
            percent: clean_percent(percent),
            floor: self.floor,
        }
    }

    /// No band at all.
    #[must_use]
    pub fn off() -> Self {
        Self {
            percent: 0.0,
            floor: 0,
        }
    }

    /// The band width in bytes for a requirement of `min`. It is never more than half of `min`.
    #[must_use]
    pub fn width(&self, min: Quantity) -> u64 {
        self.sized(min).0
    }

    fn sized(&self, min: Quantity) -> (u64, BandBasis) {
        if self.percent <= 0.0 {
            return (0, BandBasis::Percent(0.0));
        }
        // Hundredths of a percent, so 6.25 percent is exact. u128 keeps the multiply exact.
        let hundredths = u128::from((self.percent * 100.0).round() as u64);
        let by_percent = u64::try_from(u128::from(min.bytes()) * hundredths / 10_000).unwrap_or(0);
        // A band never reaches half of `min`, so a floor wider than a small `min` cannot make zero
        // or a tiny value pass.
        let cap = min.bytes() / 2;
        if self.floor > by_percent {
            (self.floor.min(cap), BandBasis::Floor(self.floor.min(cap)))
        } else {
            (by_percent.min(cap), BandBasis::Percent(self.percent))
        }
    }

    /// Sets `have` bytes against `min`.
    ///
    /// A value at or above `min` is [`SizeFit::Meets`]. A value below `min` by no more than the band is
    /// [`SizeFit::InBand`]. Anything lower is [`SizeFit::Below`].
    #[must_use]
    pub fn assess(&self, have: u64, min: Quantity) -> SizeFit {
        let need = min.bytes();
        if have >= need {
            return SizeFit::Meets;
        }
        let (width, basis) = self.sized(min);
        if need - have <= width {
            SizeFit::InBand { have, need, basis }
        } else {
            SizeFit::Below { have, need }
        }
    }
}

/// The result of [`Band::assess`].
#[derive(Debug, Clone, Copy, PartialEq)]
#[non_exhaustive]
pub enum SizeFit {
    /// At or above `min`.
    Meets,
    /// Below `min`, inside the band.
    InBand {
        /// What was found, in bytes.
        have: u64,
        /// What was needed, in bytes.
        need: u64,
        /// Why the band is as wide as it is.
        basis: BandBasis,
    },
    /// Below `min` and outside the band.
    Below {
        /// What was found, in bytes.
        have: u64,
        /// What was needed, in bytes.
        need: u64,
    },
}

impl SizeFit {
    /// The level, given what an in-band value counts as: [`Level::Pass`] by default, or
    /// [`Level::Warn`] for `tolerance_result: warn`.
    #[must_use]
    pub fn level(&self, in_band: Level) -> Level {
        match self {
            Self::Meets => Level::Pass,
            Self::InBand { .. } => in_band,
            Self::Below { .. } => Level::Fail,
        }
    }

    /// The note for an in-band value, such as `31.3 GiB found, 32 GiB needed, inside the 5% tolerance`.
    /// `None` for the other two.
    #[must_use]
    pub fn note(&self) -> Option<String> {
        let Self::InBand { have, need, basis } = self else {
            return None;
        };
        let how = match basis {
            BandBasis::Percent(percent) => format!("{percent}%"),
            BandBasis::Floor(bytes) => format_bytes(*bytes),
        };
        Some(format!(
            "{} found, {} needed, inside the {how} tolerance",
            format_bytes(*have),
            format_bytes(*need),
        ))
    }
}
