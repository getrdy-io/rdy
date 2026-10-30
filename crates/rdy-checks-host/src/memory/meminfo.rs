//! The parser of `/proc/meminfo`. Pure: text in, numbers out, no panic on any input.

/// What `/proc/meminfo` says that `host.memory` uses, in bytes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) struct MemInfo {
    /// `MemTotal`. Never zero.
    pub total: u64,
    /// `MemAvailable`, or the estimate when the kernel has no such line.
    pub available: Option<Available>,
    /// `SwapTotal`. `None` when the kernel does not report swap.
    pub swap_total: Option<u64>,
    /// `SwapFree`.
    pub swap_free: Option<u64>,
}

/// Memory a new program can get without swapping.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) struct Available {
    pub bytes: u64,
    /// `true` when it is `MemFree + Buffers + Cached` because there is no `MemAvailable` line
    /// (kernels before 3.14).
    pub estimated: bool,
}

/// The first value of `key` in kilobytes, as bytes. A line without the `kB` unit, or whose number does
/// not fit, is not a value. The kernel does not repeat a key, and the first one wins.
fn value(text: &str, key: &str) -> Option<u64> {
    text.lines().find_map(|line| {
        let (name, rest) = line.split_once(':')?;
        if name.trim() != key {
            return None;
        }
        let mut words = rest.split_whitespace();
        let number: u64 = words.next()?.parse().ok()?;
        if !words.next()?.eq_ignore_ascii_case("kB") || words.next().is_some() {
            return None;
        }
        number.checked_mul(1024)
    })
}

/// Reads the text of `/proc/meminfo`.
///
/// # Errors
///
/// A short reason, without file content, when there is no usable `MemTotal` line.
pub(super) fn parse(text: &str) -> Result<MemInfo, &'static str> {
    let total = match value(text, "MemTotal") {
        None => return Err("there is no MemTotal line in kB"),
        Some(0) => return Err("MemTotal is 0"),
        Some(total) => total,
    };
    let available = match value(text, "MemAvailable") {
        Some(bytes) => Some(Available {
            bytes,
            estimated: false,
        }),
        None => value(text, "MemFree").map(|free| Available {
            bytes: free
                .saturating_add(value(text, "Buffers").unwrap_or(0))
                .saturating_add(value(text, "Cached").unwrap_or(0)),
            estimated: true,
        }),
    }
    // Free memory cannot exceed the total; a bad line must not make the box look bigger.
    .map(|a| Available {
        bytes: a.bytes.min(total),
        ..a
    });
    Ok(MemInfo {
        total,
        available,
        swap_total: value(text, "SwapTotal"),
        swap_free: value(text, "SwapFree"),
    })
}
