//! [`Version`]: a dotted numeric version.

#[cfg(feature = "schema")]
use std::borrow::Cow;
use std::fmt;
use std::str::FromStr;

#[cfg(feature = "schema")]
use schemars::{JsonSchema, Schema, SchemaGenerator, json_schema};
use serde::de::{self, Visitor};
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use thiserror::Error;

use super::{ScalarError, de_error};

/// The most parts a version may have.
const MAX_PARTS: usize = 4;

/// The most digits one part may have, as in the JSON schema.
const MAX_DIGITS: usize = 9;

/// The largest value of one part.
const MAX_PART: u64 = 999_999_999;

/// What is wrong with a refused version.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
#[non_exhaustive]
pub enum VersionProblem {
    /// There is nothing to read.
    #[error("it is empty")]
    Empty,
    /// There is a space, tab or newline in it.
    #[error("it has a space in it")]
    Whitespace,
    /// It is not whole numbers joined by dots.
    #[error("it is not whole numbers joined by dots")]
    BadShape,
    /// It has more than four parts.
    #[error("it has more than four parts")]
    TooManyParts,
    /// A part has more than 9 digits.
    #[error("a part has more than 9 digits")]
    TooLarge,
    /// It was written as a plain decimal number, and YAML has already lost the text.
    #[error("it was written as a decimal number, and the trailing zeros are lost")]
    UnquotedDecimal,
}

impl VersionProblem {
    /// The fix line for this problem. Never empty.
    #[must_use]
    pub fn hint(self) -> &'static str {
        match self {
            Self::Empty => "write a version in quotes, such as \"1.28\".",
            Self::Whitespace => "remove the space. Write \"1.28\", not \"1. 28\".",
            Self::BadShape => {
                "write whole numbers joined by dots, in quotes, such as \"1.28\" or \"5.10.0\"."
            }
            Self::TooManyParts => "use at most four parts, such as \"1.2.3.4\".",
            Self::TooLarge => "use at most 9 digits in each part.",
            Self::UnquotedDecimal => {
                "quote it, such as \"1.30\". YAML reads an unquoted 1.30 as the number 1.3 and the zero is lost."
            }
        }
    }
}

/// A dotted version such as `1.28`, `5.10.0` or `14`: one to four whole numbers joined by dots.
///
/// Write it as a quoted string. A bare integer such as `14` is also accepted, because YAML keeps its
/// text. An unquoted `1.30` is refused: YAML reads it as the number 1.3, so the real version is lost.
/// A leading `v` is allowed (`v1.29.4`). Leading zeros in a part are allowed too.
///
/// The text as written is kept, and `Display` and the serde writer give it back exactly, so a report
/// shows `1.05` and `v1.29.4` as the author wrote them. Equality and hashing use the parsed parts, so
/// `1.05` equals `1.5` and `v1.29` equals `1.29`.
///
/// Versions are compared part by part as numbers, never as semver, so `1.9 < 1.10`. This type holds
/// the parts and does not order them. `1.28` and `1.28.0` are different values here. To compare, use
/// `rdy_engine::units::compare_versions`, which pads the shorter one with zeros.
#[derive(Debug, Clone)]
pub struct Version {
    parts: [u32; MAX_PARTS],
    len: u8,
    source: String,
}

impl PartialEq for Version {
    fn eq(&self, other: &Self) -> bool {
        self.components() == other.components()
    }
}

impl Eq for Version {}

impl std::hash::Hash for Version {
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        self.components().hash(state);
    }
}

impl Version {
    /// Reads a version such as `1.28`.
    ///
    /// # Errors
    ///
    /// Returns [`ScalarError::InvalidVersion`] when `text` does not fit the grammar.
    pub fn parse(text: &str) -> Result<Self, ScalarError> {
        Self::check(text).map_err(|p| ScalarError::version(text, p))
    }

    /// The text as the author wrote it, such as `1.05`.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.source
    }

    /// The numeric parts, from the most significant. One to four of them.
    #[must_use]
    pub fn components(&self) -> &[u32] {
        &self.parts[..usize::from(self.len)]
    }

    fn check(text: &str) -> Result<Self, VersionProblem> {
        if text.is_empty() {
            return Err(VersionProblem::Empty);
        }
        if text.chars().any(char::is_whitespace) {
            return Err(VersionProblem::Whitespace);
        }
        let body = text.strip_prefix('v').unwrap_or(text);
        let mut parts = [0_u32; MAX_PARTS];
        let mut len = 0_usize;
        for piece in body.split('.') {
            if piece.is_empty() || !piece.bytes().all(|b| b.is_ascii_digit()) {
                return Err(VersionProblem::BadShape);
            }
            if piece.len() > MAX_DIGITS {
                return Err(VersionProblem::TooLarge);
            }
            if len == MAX_PARTS {
                return Err(VersionProblem::TooManyParts);
            }
            parts[len] = piece.parse().map_err(|_| VersionProblem::TooLarge)?;
            len += 1;
        }
        // `len` is at most 4 here, so it fits in a u8.
        Ok(Self {
            parts,
            len: u8::try_from(len).unwrap_or(0),
            source: text.to_owned(),
        })
    }

    /// A bare YAML or JSON integer.
    fn from_integer(n: u64) -> Result<Self, ScalarError> {
        if n > MAX_PART {
            return Err(ScalarError::version(
                &n.to_string(),
                VersionProblem::TooLarge,
            ));
        }
        Self::parse(&n.to_string())
    }
}

impl FromStr for Version {
    type Err = ScalarError;

    fn from_str(s: &str) -> Result<Self, ScalarError> {
        Self::parse(s)
    }
}

impl fmt::Display for Version {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.source)
    }
}

#[cfg(feature = "schema")]
impl JsonSchema for Version {
    fn schema_name() -> Cow<'static, str> {
        "Version".into()
    }

    fn json_schema(_: &mut SchemaGenerator) -> Schema {
        json_schema!({
            "description": "A dotted version such as 1.28 or 5.10, as a quoted string. A bare integer (14) is accepted. An unquoted decimal (1.30) is rejected because YAML reads it as the number 1.3.",
            "oneOf": [
                {"type": "string", "pattern": "^v?[0-9]{1,9}(\\.[0-9]{1,9}){0,3}$"},
                {"type": "integer", "minimum": 0}
            ]
        })
    }
}

impl Serialize for Version {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.collect_str(self)
    }
}

impl<'de> Deserialize<'de> for Version {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        struct Reader;

        impl Visitor<'_> for Reader {
            type Value = Version;

            fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str("a quoted version such as \"1.28\", or a whole number such as 14")
            }

            fn visit_u64<E: de::Error>(self, v: u64) -> Result<Version, E> {
                Version::from_integer(v).map_err(|e| de_error(&e))
            }

            fn visit_i64<E: de::Error>(self, v: i64) -> Result<Version, E> {
                match u64::try_from(v) {
                    Ok(n) => self.visit_u64(n),
                    Err(_) => Err(de_error(&ScalarError::version(
                        &v.to_string(),
                        VersionProblem::BadShape,
                    ))),
                }
            }

            fn visit_f64<E: de::Error>(self, v: f64) -> Result<Version, E> {
                Err(de_error(&ScalarError::version(
                    &v.to_string(),
                    VersionProblem::UnquotedDecimal,
                )))
            }

            fn visit_str<E: de::Error>(self, v: &str) -> Result<Version, E> {
                Version::parse(v).map_err(|e| de_error(&e))
            }
        }

        deserializer.deserialize_any(Reader)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn parts(s: &str) -> Vec<u32> {
        Version::parse(s).unwrap().components().to_vec()
    }

    fn problem(s: &str) -> VersionProblem {
        match Version::parse(s).unwrap_err() {
            ScalarError::InvalidVersion { problem, .. } => problem,
            other => panic!("wrong variant {other:?}"),
        }
    }

    #[test]
    fn accepts_the_grammar() {
        assert_eq!(parts("14"), [14]);
        assert_eq!(parts("1.30"), [1, 30]);
        assert_eq!(parts("5.10.0"), [5, 10, 0]);
        assert_eq!(parts("1.2.3.4"), [1, 2, 3, 4]);
        assert_eq!(parts("v1.29.4"), [1, 29, 4]);
        assert_eq!(parts("0"), [0]);
        assert_eq!(parts("999999999"), [999_999_999]);
        assert_eq!(parts("01.05"), [1, 5]);
    }

    #[test]
    fn display_keeps_the_text_and_equality_uses_the_parts() {
        for s in ["1.30", "12.4", "v1.29.4", "01.05", "1.05"] {
            let v = Version::parse(s).unwrap();
            assert_eq!(v.to_string(), s);
            assert_eq!(v.as_str(), s);
            assert_eq!(serde_json::to_string(&v).unwrap(), format!("\"{s}\""));
        }
        assert_eq!(
            Version::parse("1.05").unwrap(),
            Version::parse("1.5").unwrap()
        );
        assert_eq!(
            Version::parse("v1.29").unwrap(),
            Version::parse("1.29").unwrap()
        );
        assert_eq!(
            Version::parse("1.28").unwrap(),
            Version::parse("1.28").unwrap()
        );
        assert_ne!(
            Version::parse("1.28").unwrap(),
            Version::parse("1.28.0").unwrap()
        );
    }

    #[test]
    fn refuses_near_misses() {
        assert_eq!(problem(""), VersionProblem::Empty);
        for s in ["1. 28", " 1.28", "1.28 ", "1 .28"] {
            assert_eq!(problem(s), VersionProblem::Whitespace, "{s:?}");
        }
        for s in [
            "v", "V1.2", "vv1", "1.", ".1", "1..2", "1.x", "a", "-1", "+1", "1.2-rc1", "1.2+b",
            ">=4.2", "1,2", "1.2.3.4.", "\u{661}",
        ] {
            assert_eq!(problem(s), VersionProblem::BadShape, "{s:?}");
        }
        assert_eq!(problem("1.2.3.4.5"), VersionProblem::TooManyParts);
        assert_eq!(problem("1000000000"), VersionProblem::TooLarge);
        assert_eq!(problem("1.99999999999999999999"), VersionProblem::TooLarge);
    }

    #[test]
    fn serde_errors_carry_the_fix_line() {
        let e = serde_json::from_str::<Version>("1.30").unwrap_err();
        assert!(e.to_string().contains(". fix: "), "{e}");
    }

    #[test]
    fn serde_reads_strings_and_integers_and_refuses_decimals() {
        let v: Version = serde_json::from_str("\"1.30\"").unwrap();
        assert_eq!(v.components(), [1, 30]);
        assert_eq!(serde_json::to_string(&v).unwrap(), "\"1.30\"");
        let v: Version = serde_json::from_str("14").unwrap();
        assert_eq!(v.components(), [14]);
        let e = serde_json::from_str::<Version>("1.30").unwrap_err();
        assert!(e.to_string().contains("decimal"), "{e}");
        for bad in ["-1", "1000000000", "true", "null", "[]", "\"1.\"", "1e3"] {
            assert!(serde_json::from_str::<Version>(bad).is_err(), "{bad}");
        }
    }
}
