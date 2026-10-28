//! [`Duration`]: a span of time.

use std::fmt;
use std::str::FromStr;

use serde::de::{self, Visitor};
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use thiserror::Error;

use super::{ScalarError, de_error, split_digits};

/// Units in milliseconds, largest first.
const UNITS: [(&str, u64); 5] = [
    ("d", 86_400_000),
    ("h", 3_600_000),
    ("m", 60_000),
    ("s", 1_000),
    ("ms", 1),
];

/// The most digits a duration may have, as in the JSON schema.
const MAX_DIGITS: usize = 9;

/// What is wrong with a refused duration.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
#[non_exhaustive]
pub enum DurationProblem {
    /// There is nothing to read.
    #[error("it is empty")]
    Empty,
    /// There is a space, tab or newline in it.
    #[error("it has a space in it")]
    Whitespace,
    /// It does not start with a whole number.
    #[error("it does not start with a whole number")]
    NotWholeNumber,
    /// There is a number and no unit.
    #[error("it has no unit")]
    MissingUnit,
    /// The unit is not `ms`, `s`, `m`, `h` or `d`.
    #[error("the unit is not ms, s, m, h or d")]
    UnknownUnit,
    /// Two parts were joined, as in `1m30s`.
    #[error("it has more than one part")]
    Compound,
    /// The number is zero or starts with a zero.
    #[error("the number is zero or starts with a zero")]
    LeadingZero,
    /// The number has more than 9 digits.
    #[error("the number has more than 9 digits")]
    TooLarge,
}

impl DurationProblem {
    /// The fix line for this problem. Never empty.
    #[must_use]
    pub fn hint(self) -> &'static str {
        match self {
            Self::Empty => "write a duration such as '10s'.",
            Self::Whitespace => "remove the space. Write '10s', not '10 s'.",
            Self::NotWholeNumber => {
                "write a whole number and a unit, such as '10s'. For 1.5 seconds write '1500ms'."
            }
            Self::MissingUnit => "add a unit: ms, s, m, h or d, such as '10s'.",
            Self::UnknownUnit => "use ms, s, m, h or d, in lowercase, such as '10s', '5m' or '7d'.",
            Self::Compound => "write one unit only. For 1m30s write '90s'.",
            Self::LeadingZero => "write a number from 1 up, without a leading zero, such as '10s'.",
            Self::TooLarge => {
                "use at most 9 digits. A larger unit needs fewer digits, such as '999999d'."
            }
        }
    }
}

/// A span of time, written as a whole number and one unit: `500ms`, `10s`, `5m`, `2h`, `7d`.
///
/// The number is 1 to 999999999. There are no compound forms, no fractions, no spaces, and the units
/// are lowercase. Zero is refused, because a zero timeout or window is always a mistake. A field that
/// needs a narrower range, such as a check `timeout` of 1s to 60s, checks that on top.
///
/// The value is kept in milliseconds, and so is the comparison: `60s` equals `1m`. The text as written
/// is kept too, and `Display` and the serde writer give it back exactly, so a report shows `60s` and not
/// `1m`. The printed form always parses back to an equal value.
#[derive(Debug, Clone)]
pub struct Duration {
    millis: u64,
    source: String,
}

impl PartialEq for Duration {
    fn eq(&self, other: &Self) -> bool {
        self.millis == other.millis
    }
}

impl Eq for Duration {}

impl PartialOrd for Duration {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for Duration {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        self.millis.cmp(&other.millis)
    }
}

impl std::hash::Hash for Duration {
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        self.millis.hash(state);
    }
}

impl Duration {
    /// Reads a duration such as `10s`.
    ///
    /// # Errors
    ///
    /// Returns [`ScalarError::InvalidDuration`] when `text` does not fit the grammar.
    pub fn parse(text: &str) -> Result<Self, ScalarError> {
        Self::check(text).map_err(|p| ScalarError::duration(text, p))
    }

    /// The text as the author wrote it, such as `60s`.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.source
    }

    /// The length in milliseconds.
    #[must_use]
    pub fn as_millis(&self) -> u64 {
        self.millis
    }

    /// The length as a standard library duration.
    #[must_use]
    pub fn to_std(&self) -> std::time::Duration {
        std::time::Duration::from_millis(self.millis)
    }

    fn check(text: &str) -> Result<Self, DurationProblem> {
        if text.is_empty() {
            return Err(DurationProblem::Empty);
        }
        if text.chars().any(char::is_whitespace) {
            return Err(DurationProblem::Whitespace);
        }
        let (digits, suffix) = split_digits(text);
        if digits.is_empty() || suffix.starts_with('.') {
            return Err(DurationProblem::NotWholeNumber);
        }
        if suffix.is_empty() {
            return Err(DurationProblem::MissingUnit);
        }
        let Some((_, unit)) = UNITS.iter().find(|(name, _)| *name == suffix) else {
            let compound = UNITS.iter().any(|(name, _)| {
                suffix
                    .strip_prefix(name)
                    .is_some_and(|rest| rest.starts_with(|c: char| c.is_ascii_digit()))
            });
            return Err(if compound {
                DurationProblem::Compound
            } else {
                DurationProblem::UnknownUnit
            });
        };
        if digits.starts_with('0') {
            return Err(DurationProblem::LeadingZero);
        }
        if digits.len() > MAX_DIGITS {
            return Err(DurationProblem::TooLarge);
        }
        let number: u64 = digits.parse().map_err(|_| DurationProblem::TooLarge)?;
        // 999999999 days is 8.64e16 ms, far below u64::MAX, so this cannot overflow.
        Ok(Self {
            millis: number * unit,
            source: text.to_owned(),
        })
    }
}

impl FromStr for Duration {
    type Err = ScalarError;

    fn from_str(s: &str) -> Result<Self, ScalarError> {
        Self::parse(s)
    }
}

impl fmt::Display for Duration {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.source)
    }
}

impl Serialize for Duration {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.collect_str(self)
    }
}

impl<'de> Deserialize<'de> for Duration {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        struct Reader;

        impl Visitor<'_> for Reader {
            type Value = Duration;

            fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str("a duration such as 10s")
            }

            fn visit_u64<E: de::Error>(self, v: u64) -> Result<Duration, E> {
                Err(de_error(&ScalarError::duration(
                    &v.to_string(),
                    DurationProblem::MissingUnit,
                )))
            }

            fn visit_i64<E: de::Error>(self, v: i64) -> Result<Duration, E> {
                let problem = if v < 0 {
                    DurationProblem::NotWholeNumber
                } else {
                    DurationProblem::MissingUnit
                };
                Err(de_error(&ScalarError::duration(&v.to_string(), problem)))
            }

            fn visit_f64<E: de::Error>(self, v: f64) -> Result<Duration, E> {
                Err(de_error(&ScalarError::duration(
                    &v.to_string(),
                    DurationProblem::NotWholeNumber,
                )))
            }

            fn visit_str<E: de::Error>(self, v: &str) -> Result<Duration, E> {
                Duration::parse(v).map_err(|e| de_error(&e))
            }
        }

        deserializer.deserialize_any(Reader)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn millis(s: &str) -> u64 {
        Duration::parse(s).unwrap().as_millis()
    }

    fn problem(s: &str) -> DurationProblem {
        match Duration::parse(s).unwrap_err() {
            ScalarError::InvalidDuration { problem, .. } => problem,
            other => panic!("wrong variant {other:?}"),
        }
    }

    #[test]
    fn accepts_the_grammar() {
        assert_eq!(millis("500ms"), 500);
        assert_eq!(millis("10s"), 10_000);
        assert_eq!(millis("5m"), 300_000);
        assert_eq!(millis("2h"), 7_200_000);
        assert_eq!(millis("7d"), 604_800_000);
        assert_eq!(millis("999999999d"), 999_999_999 * 86_400_000);
        assert_eq!(Duration::parse("10s").unwrap().to_std().as_secs(), 10);
    }

    #[test]
    fn display_keeps_the_text_and_equality_uses_the_value() {
        for s in ["60s", "1m", "1500ms", "48h", "2d", "90s"] {
            let d = Duration::parse(s).unwrap();
            assert_eq!(d.to_string(), s);
            assert_eq!(d.as_str(), s);
        }
        let a = Duration::parse("60s").unwrap();
        let b = Duration::parse("1m").unwrap();
        assert_eq!(a, b);
        assert!(Duration::parse("59s").unwrap() < b);
        assert_eq!(serde_json::to_string(&a).unwrap(), "\"60s\"");
    }

    #[test]
    fn refuses_near_misses() {
        assert_eq!(problem(""), DurationProblem::Empty);
        for s in ["10 s", " 10s", "10s ", "1 0s"] {
            assert_eq!(problem(s), DurationProblem::Whitespace, "{s:?}");
        }
        for s in ["s", "-5s", "1.5s", ".5s", "+1s"] {
            assert_eq!(problem(s), DurationProblem::NotWholeNumber, "{s:?}");
        }
        assert_eq!(problem("10"), DurationProblem::MissingUnit);
        for s in [
            "10S", "10M", "10H", "10D", "10MS", "10sec", "10min", "10w", "10us", "10y",
        ] {
            assert_eq!(problem(s), DurationProblem::UnknownUnit, "{s:?}");
        }
        for s in ["1m30s", "1h30m", "1d12h", "1s500ms"] {
            assert_eq!(problem(s), DurationProblem::Compound, "{s:?}");
        }
        for s in ["0s", "00s", "05s", "0ms"] {
            assert_eq!(problem(s), DurationProblem::LeadingZero, "{s:?}");
        }
        for s in ["1000000000s", "99999999999999999999999d"] {
            assert_eq!(problem(s), DurationProblem::TooLarge, "{s:?}");
        }
    }

    #[test]
    fn serde_errors_carry_the_fix_line() {
        let e = serde_json::from_str::<Duration>("\"10 s\"").unwrap_err();
        assert!(e.to_string().contains(". fix: "), "{e}");
    }

    #[test]
    fn serde_reads_strings_only_and_writes_strings() {
        let d: Duration = serde_json::from_str("\"7d\"").unwrap();
        assert_eq!(serde_json::to_string(&d).unwrap(), "\"7d\"");
        for bad in ["10", "-1", "1.5", "\"10\"", "\"10 s\"", "null", "true"] {
            assert!(serde_json::from_str::<Duration>(bad).is_err(), "{bad}");
        }
    }
}
