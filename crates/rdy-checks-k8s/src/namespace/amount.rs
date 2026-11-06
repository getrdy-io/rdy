//! Kubernetes quantities, read for comparison.
//!
//! A quota or a limit range holds amounts such as `8`, `500m`, `64Gi`, `1e3` or `2G`. The check compares
//! the amount the product needs with what a quota has left, so it needs the number, not the text. The
//! grammar is the one of the API (`resource.Quantity`): an optional `+`, a number with at most one dot, and
//! one suffix, which is a binary one (`Ki` to `Ei`), a decimal one (`n`, `u`, `m`, nothing, `k`, `M`, `G`,
//! `T`, `P`, `E`) or a decimal exponent (`e3`, `E-2`).
//!
//! An [`Amount`] counts nano-units in an `i128`. Text from the server is untrusted, so the reader is
//! bounded (at most 48 characters, at most 36 digits) and never panics: what it cannot read is `None`, and
//! an amount too large for 38 digits saturates, which keeps it larger than any real one.

/// The longest amount text the reader accepts, in characters.
const MAX_CHARS: usize = 48;

/// The most digits of the number.
const MAX_DIGITS: usize = 36;

/// Nano-units in one unit.
const NANO: i128 = 1_000_000_000;

/// A quantity in nano-units.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub(super) struct Amount(i128);

impl Amount {
    /// A size in bytes, from the spec's strict size grammar.
    pub(super) fn from_bytes(bytes: u64) -> Self {
        Self(i128::from(bytes).saturating_mul(NANO))
    }

    /// Reads a quantity. `None` for text that is not one, a negative amount and text over the bounds.
    pub(super) fn parse(text: &str) -> Option<Self> {
        if text.is_empty() || text.len() > MAX_CHARS || !text.is_ascii() {
            return None;
        }
        let text = text.strip_prefix('+').unwrap_or(text);
        let end = text
            .find(|c: char| !(c.is_ascii_digit() || c == '.'))
            .unwrap_or(text.len());
        let (number, suffix) = text.split_at(end);
        let (whole, fraction) = number.split_once('.').unwrap_or((number, ""));
        if whole.is_empty() && fraction.is_empty() {
            return None;
        }
        if fraction.contains('.') {
            return None;
        }
        let digits: String = whole.chars().chain(fraction.chars()).collect();
        let digits = digits.trim_start_matches('0');
        if digits.len() > MAX_DIGITS {
            return None;
        }
        let mantissa: u128 = if digits.is_empty() {
            0
        } else {
            digits.parse().ok()?
        };
        let (binary, exp10) = suffix_scale(suffix)?;
        let fraction_len = i32::try_from(fraction.len()).ok()?;
        let exp10 = exp10.checked_add(9)?.checked_sub(fraction_len)?;
        Some(Self(scale(mantissa, binary, exp10)))
    }

    /// The amount in nano-units.
    pub(super) fn nano(self) -> i128 {
        self.0
    }

    /// Zero when the amount is below it.
    pub(super) fn at_least_zero(self) -> Self {
        Self(self.0.max(0))
    }

    /// `self` minus `other`. Saturates, so a hostile pair cannot overflow.
    pub(super) fn minus(self, other: Self) -> Self {
        Self(self.0.saturating_sub(other.0))
    }
}

/// The binary factor (a power of two) and the decimal exponent of a suffix.
fn suffix_scale(suffix: &str) -> Option<(u32, i32)> {
    let scale = match suffix {
        "" => (0, 0),
        "n" => (0, -9),
        "u" => (0, -6),
        "m" => (0, -3),
        "k" => (0, 3),
        "M" => (0, 6),
        "G" => (0, 9),
        "T" => (0, 12),
        "P" => (0, 15),
        "E" => (0, 18),
        "Ki" => (10, 0),
        "Mi" => (20, 0),
        "Gi" => (30, 0),
        "Ti" => (40, 0),
        "Pi" => (50, 0),
        "Ei" => (60, 0),
        _ => {
            let exponent = suffix.strip_prefix(['e', 'E'])?;
            let (sign, digits) = match exponent.strip_prefix('-') {
                Some(rest) => (-1, rest),
                None => (1, exponent.strip_prefix('+').unwrap_or(exponent)),
            };
            if digits.is_empty() || digits.len() > 3 || !digits.bytes().all(|b| b.is_ascii_digit())
            {
                return None;
            }
            (0, sign * digits.parse::<i32>().ok()?)
        }
    };
    Some(scale)
}

/// `mantissa * 2^binary * 10^exp10`, rounded up to a whole number, saturating at `i128::MAX`.
fn scale(mantissa: u128, binary: u32, exp10: i32) -> i128 {
    if mantissa == 0 {
        return 0;
    }
    let Some(mut value) = mantissa.checked_mul(1u128 << binary) else {
        return i128::MAX;
    };
    if exp10 >= 0 {
        for _ in 0..exp10 {
            match value.checked_mul(10) {
                Some(next) => value = next,
                None => return i128::MAX,
            }
        }
    } else {
        // More than 40 divisions by ten leave less than one nano-unit, which rounds up to one.
        let steps = exp10.unsigned_abs().min(40);
        let mut rest = false;
        for _ in 0..steps {
            rest |= value % 10 != 0;
            value /= 10;
        }
        if exp10.unsigned_abs() > steps {
            rest |= value != 0;
            value = 0;
        }
        if rest {
            value += 1;
        }
    }
    i128::try_from(value).unwrap_or(i128::MAX)
}

/// An amount as a person reads it. `bytes` is true for memory, storage and huge pages.
///
/// The result is built from the number only, never from server text.
pub(super) fn show(amount: Amount, bytes: bool) -> String {
    let nano = amount.nano();
    if nano <= 0 {
        return "0".to_owned();
    }
    if nano % NANO == 0 {
        let whole = nano / NANO;
        if bytes {
            for (unit, size) in [
                ("Ei", 1i128 << 60),
                ("Pi", 1 << 50),
                ("Ti", 1 << 40),
                ("Gi", 1 << 30),
                ("Mi", 1 << 20),
                ("Ki", 1 << 10),
            ] {
                if whole >= size && whole % size == 0 {
                    return format!("{}{unit}", whole / size);
                }
            }
        }
        return whole.to_string();
    }
    if nano % 1_000_000 == 0 {
        return format!("{}m", nano / 1_000_000);
    }
    format!("{nano}n")
}
