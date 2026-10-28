//! [`Quantity`]: a size in bytes.

use std::fmt;
use std::str::FromStr;

use serde::de::{self, Visitor};
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use thiserror::Error;

use super::{ScalarError, de_error, split_digits};

/// Binary units, largest first.
const UNITS: [(&str, u64); 5] = [
    ("Pi", 1 << 50),
    ("Ti", 1 << 40),
    ("Gi", 1 << 30),
    ("Mi", 1 << 20),
    ("Ki", 1 << 10),
];

/// The most digits a size may have, as in the JSON schema.
const MAX_DIGITS: usize = 15;

/// Decimal suffixes people reach for. Each is refused with a pointer to the binary unit.
const DECIMAL_UNITS: [&str; 10] = ["K", "KB", "M", "MB", "G", "GB", "T", "TB", "P", "PB"];

/// What is wrong with a refused size.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
#[non_exhaustive]
pub enum QuantityProblem {
    /// There is nothing to read.
    #[error("it is empty")]
    Empty,
    /// There is a space, tab or newline in it.
    #[error("it has a space in it")]
    Whitespace,
    /// It does not start with a whole number.
    #[error("it does not start with a whole number")]
    NotWholeNumber,
    /// The unit is a decimal one such as `G` or `GB`.
    #[error("the unit is decimal, and sizes use binary units")]
    DecimalUnit,
    /// The unit is not one of `Ki`, `Mi`, `Gi`, `Ti` or `Pi`.
    #[error("the unit is not Ki, Mi, Gi, Ti or Pi")]
    UnknownUnit,
    /// The size is more than 2^53 - 1 bytes, or has more than 15 digits.
    #[error("it is too large")]
    TooLarge,
}

impl QuantityProblem {
    /// The fix line for this problem. Never empty.
    #[must_use]
    pub fn hint(self) -> &'static str {
        match self {
            Self::Empty => "write a size such as '32Gi' or '1048576'.",
            Self::Whitespace => "remove the space. Write '32Gi', not '32 Gi'.",
            Self::NotWholeNumber => {
                "write a whole number and an optional unit, such as '32Gi'. For 1.5 GiB write '1536Mi'."
            }
            Self::DecimalUnit => "write 32Gi, not 32G. Units are Ki, Mi, Gi, Ti and Pi.",
            Self::UnknownUnit => {
                "use Ki, Mi, Gi, Ti or Pi, with that exact capitalization, such as '32Gi'."
            }
            Self::TooLarge => {
                "use at most 15 digits, and at most 9007199254740991 bytes (just under 8Pi)."
            }
        }
    }
}

/// A size in bytes, written as a whole number with an optional binary unit: `1048576`, `200Mi`, `32Gi`.
///
/// The units are `Ki` (2^10), `Mi`, `Gi`, `Ti` and `Pi` (2^50), with this exact capitalization. Decimal
/// units such as `G` and `GB` are refused, because `32G` could mean either 32 GB or 32 GiB. A size is
/// at most 2^53 - 1 bytes, so it is exact in JSON and in any language.
///
/// `Display` writes the largest unit that divides the size exactly, so `1024Ki` prints as `1Mi`. The
/// reader accepts a bare integer or a string. The writer always writes a string.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Quantity(u64);

impl Quantity {
    /// The largest size, 2^53 - 1 bytes.
    pub const MAX_BYTES: u64 = (1 << 53) - 1;

    /// Reads a size such as `32Gi`.
    ///
    /// # Errors
    ///
    /// Returns [`ScalarError::InvalidQuantity`] when `text` does not fit the grammar.
    pub fn parse(text: &str) -> Result<Self, ScalarError> {
        Self::check(text).map_err(|p| ScalarError::quantity(text, p))
    }

    /// The size in bytes.
    #[must_use]
    pub fn bytes(self) -> u64 {
        self.0
    }

    fn check(text: &str) -> Result<Self, QuantityProblem> {
        if text.is_empty() {
            return Err(QuantityProblem::Empty);
        }
        if text.chars().any(char::is_whitespace) {
            return Err(QuantityProblem::Whitespace);
        }
        let (digits, suffix) = split_digits(text);
        if digits.is_empty() || suffix.starts_with('.') {
            return Err(QuantityProblem::NotWholeNumber);
        }
        let multiplier = if suffix.is_empty() {
            1
        } else if let Some((_, size)) = UNITS.iter().find(|(name, _)| *name == suffix) {
            *size
        } else if DECIMAL_UNITS.contains(&suffix.to_ascii_uppercase().as_str()) {
            return Err(QuantityProblem::DecimalUnit);
        } else {
            return Err(QuantityProblem::UnknownUnit);
        };
        if digits.len() > MAX_DIGITS {
            return Err(QuantityProblem::TooLarge);
        }
        let number: u64 = digits.parse().map_err(|_| QuantityProblem::TooLarge)?;
        match number.checked_mul(multiplier) {
            Some(bytes) if bytes <= Self::MAX_BYTES => Ok(Self(bytes)),
            _ => Err(QuantityProblem::TooLarge),
        }
    }

    /// A bare YAML or JSON integer. It follows the same 15-digit rule as text.
    fn from_integer(n: u64) -> Result<Self, ScalarError> {
        let text = n.to_string();
        Self::check(&text).map_err(|p| ScalarError::quantity(&text, p))
    }
}

impl FromStr for Quantity {
    type Err = ScalarError;

    fn from_str(s: &str) -> Result<Self, ScalarError> {
        Self::parse(s)
    }
}

impl fmt::Display for Quantity {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if self.0 != 0 {
            for (name, size) in UNITS {
                if self.0.is_multiple_of(size) {
                    return write!(f, "{}{name}", self.0 / size);
                }
            }
        }
        write!(f, "{}", self.0)
    }
}

impl Serialize for Quantity {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.collect_str(self)
    }
}

impl<'de> Deserialize<'de> for Quantity {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        struct Reader;

        impl Visitor<'_> for Reader {
            type Value = Quantity;

            fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str("a size such as 32Gi or 1048576")
            }

            fn visit_u64<E: de::Error>(self, v: u64) -> Result<Quantity, E> {
                Quantity::from_integer(v).map_err(|e| de_error(&e))
            }

            fn visit_i64<E: de::Error>(self, v: i64) -> Result<Quantity, E> {
                match u64::try_from(v) {
                    Ok(n) => self.visit_u64(n),
                    Err(_) => Err(de_error(&ScalarError::quantity(
                        &v.to_string(),
                        QuantityProblem::NotWholeNumber,
                    ))),
                }
            }

            fn visit_f64<E: de::Error>(self, v: f64) -> Result<Quantity, E> {
                Err(de_error(&ScalarError::quantity(
                    &v.to_string(),
                    QuantityProblem::NotWholeNumber,
                )))
            }

            fn visit_str<E: de::Error>(self, v: &str) -> Result<Quantity, E> {
                Quantity::parse(v).map_err(|e| de_error(&e))
            }
        }

        deserializer.deserialize_any(Reader)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn bytes(s: &str) -> u64 {
        Quantity::parse(s).unwrap().bytes()
    }

    fn problem(s: &str) -> QuantityProblem {
        match Quantity::parse(s).unwrap_err() {
            ScalarError::InvalidQuantity { problem, .. } => problem,
            other => panic!("wrong variant {other:?}"),
        }
    }

    #[test]
    fn accepts_the_grammar() {
        assert_eq!(bytes("0"), 0);
        assert_eq!(bytes("1048576"), 1 << 20);
        assert_eq!(bytes("1Ki"), 1024);
        assert_eq!(bytes("200Mi"), 200 << 20);
        assert_eq!(bytes("32Gi"), 32 << 30);
        assert_eq!(bytes("2Ti"), 2 << 40);
        assert_eq!(bytes("7Pi"), 7 << 50);
        assert_eq!(bytes("0Gi"), 0);
        assert_eq!(bytes("007Ki"), 7 * 1024);
    }

    #[test]
    fn display_uses_the_largest_exact_unit() {
        assert_eq!(Quantity::parse("1024Ki").unwrap().to_string(), "1Mi");
        assert_eq!(Quantity::parse("32768Mi").unwrap().to_string(), "32Gi");
        assert_eq!(Quantity::parse("1000").unwrap().to_string(), "1000");
        assert_eq!(Quantity::parse("0Ki").unwrap().to_string(), "0");
    }

    #[test]
    fn refuses_near_misses() {
        assert_eq!(problem(""), QuantityProblem::Empty);
        for s in ["32 Gi", " 32Gi", "32Gi ", "32\tGi", "3 2"] {
            assert_eq!(problem(s), QuantityProblem::Whitespace, "{s:?}");
        }
        for s in [
            "32G", "32GB", "32gb", "32M", "32MB", "32K", "32KB", "32T", "32P",
        ] {
            assert_eq!(problem(s), QuantityProblem::DecimalUnit, "{s:?}");
        }
        for s in [
            "32gi", "32GI", "32mi", "32ki", "32Ei", "32B", "32b", "32Gix", "1e3", "0x10",
        ] {
            assert_eq!(problem(s), QuantityProblem::UnknownUnit, "{s:?}");
        }
        for s in ["Gi", "-1", "+1", "-1Gi", "1.5Gi", ".5", "1.5", "\u{661}"] {
            assert_eq!(problem(s), QuantityProblem::NotWholeNumber, "{s:?}");
        }
    }

    #[test]
    fn refuses_overflow() {
        assert_eq!(problem("8Pi"), QuantityProblem::TooLarge);
        assert_eq!(problem("9007199254740992"), QuantityProblem::TooLarge);
        assert_eq!(problem("1000000000000000"), QuantityProblem::TooLarge);
        assert_eq!(problem("18446744073709551616"), QuantityProblem::TooLarge);
        assert_eq!(problem("999999999999999Pi"), QuantityProblem::TooLarge);
        assert_eq!(
            problem("99999999999999999999999Gi"),
            QuantityProblem::TooLarge
        );
        assert_eq!(bytes("999999999999999"), 999_999_999_999_999);
        assert_eq!(bytes("7Pi"), 7 << 50);
        assert_eq!(bytes("8191Ti"), 8191 << 40);
    }

    #[test]
    fn serde_errors_carry_the_fix_line() {
        let e = serde_json::from_str::<Quantity>("\"32G\"").unwrap_err();
        assert!(e.to_string().contains(". fix: "), "{e}");
    }

    #[test]
    fn serde_reads_integers_and_strings_and_writes_strings() {
        let q: Quantity = serde_json::from_str("1048576").unwrap();
        assert_eq!(q.bytes(), 1 << 20);
        let q: Quantity = serde_json::from_str("\"32Gi\"").unwrap();
        assert_eq!(serde_json::to_string(&q).unwrap(), "\"32Gi\"");
        for bad in [
            "-1",
            "1.5",
            "\"32G\"",
            "1000000000000000",
            "true",
            "null",
            "[]",
        ] {
            assert!(serde_json::from_str::<Quantity>(bad).is_err(), "{bad}");
        }
    }
}
