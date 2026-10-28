//! The typed scalars of the spec: [`Quantity`], [`Duration`], [`Version`] and [`Target`].
//!
//! The grammars are in docs/plan/01-spec-format.md section 2.6 and match the `$defs` of the JSON schema.
//! Each type parses with `FromStr` or `parse`, prints with `Display`, and reads and writes as a string
//! with `serde`. `Display` prints the canonical form, and parsing it again gives an equal value.
//!
//! Every refusal is a [`ScalarError`]. It echoes the refused text escaped and cut to 64 characters, and
//! it has a fix line from [`ScalarError::hint`].

mod duration;
mod quantity;
mod target;
mod version;

use thiserror::Error;

pub use duration::{Duration, DurationProblem};
pub use quantity::{Quantity, QuantityProblem};
pub use target::{Host, Target, TargetProblem};
pub(crate) use target::{is_plain_host_name, redact_for_echo};
pub use version::{Version, VersionProblem};

use crate::error::echo_safe;

/// Why a scalar value was refused.
///
/// Every variant has a fix line from [`ScalarError::hint`], which is never empty. The enum is
/// `#[non_exhaustive]`, so adding a scalar is not a breaking change.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
#[non_exhaustive]
pub enum ScalarError {
    /// A byte size such as `32Gi` was malformed.
    #[error("'{value}' is not a valid size: {problem}")]
    InvalidQuantity {
        /// The text that was refused.
        ///
        /// Already cut to 64 characters and escaped, so it is safe to print.
        value: String,
        /// What is wrong with it.
        problem: QuantityProblem,
    },
    /// A time span such as `10s` was malformed.
    #[error("'{value}' is not a valid duration: {problem}")]
    InvalidDuration {
        /// The text that was refused.
        ///
        /// Already cut to 64 characters and escaped, so it is safe to print.
        value: String,
        /// What is wrong with it.
        problem: DurationProblem,
    },
    /// A dotted version such as `1.28` was malformed.
    #[error("'{value}' is not a valid version: {problem}")]
    InvalidVersion {
        /// The text that was refused.
        ///
        /// Already cut to 64 characters and escaped, so it is safe to print.
        value: String,
        /// What is wrong with it.
        problem: VersionProblem,
    },
    /// An endpoint such as `registry.acme.example:443` was malformed.
    #[error("'{value}' is not a valid target: {problem}")]
    InvalidTarget {
        /// The text that was refused.
        ///
        /// Already cut to 64 characters and escaped, so it is safe to print.
        value: String,
        /// What is wrong with it.
        problem: TargetProblem,
    },
}

impl ScalarError {
    pub(crate) fn quantity(value: &str, problem: QuantityProblem) -> Self {
        Self::InvalidQuantity {
            value: echo_safe(value),
            problem,
        }
    }

    pub(crate) fn duration(value: &str, problem: DurationProblem) -> Self {
        Self::InvalidDuration {
            value: echo_safe(value),
            problem,
        }
    }

    pub(crate) fn version(value: &str, problem: VersionProblem) -> Self {
        Self::InvalidVersion {
            value: echo_safe(value),
            problem,
        }
    }

    pub(crate) fn target(value: &str, problem: TargetProblem) -> Self {
        Self::InvalidTarget {
            value: echo_safe(value),
            problem,
        }
    }

    /// The fix line for this error. Never empty.
    #[must_use]
    pub fn hint(&self) -> &'static str {
        match self {
            Self::InvalidQuantity { problem, .. } => problem.hint(),
            Self::InvalidDuration { problem, .. } => problem.hint(),
            Self::InvalidVersion { problem, .. } => problem.hint(),
            Self::InvalidTarget { problem, .. } => problem.hint(),
        }
    }
}

/// A serde error that carries the fix line, so the hint survives a trip through a deserializer.
///
/// The text is `<message>. fix: <hint>`.
pub(crate) fn de_error<E: serde::de::Error>(e: &ScalarError) -> E {
    E::custom(format_args!("{e}. fix: {}", e.hint()))
}

/// The digits at the start of `s`, and what follows them.
fn split_digits(s: &str) -> (&str, &str) {
    let end = s.find(|c: char| !c.is_ascii_digit()).unwrap_or(s.len());
    s.split_at(end)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_error_has_a_hint_and_a_message() {
        let samples = [
            Quantity::parse("32G").unwrap_err(),
            Duration::parse("10 s").unwrap_err(),
            Version::parse("1..2").unwrap_err(),
            Target::parse("host:99999").unwrap_err(),
        ];
        for e in samples {
            assert!(!e.hint().is_empty(), "{e:?}");
            assert!(!e.to_string().is_empty(), "{e:?}");
        }
    }

    #[test]
    fn refused_values_are_escaped_and_capped() {
        let ansi = "\u{1b}[2J\u{1b}]0;pwned\u{7}evil";
        let long = "9".repeat(10 * 1024);
        let mut errors = Vec::new();
        for text in [ansi, long.as_str()] {
            errors.push(Quantity::parse(text).unwrap_err());
            errors.push(Duration::parse(text).unwrap_err());
            errors.push(Version::parse(text).unwrap_err());
            errors.push(Target::parse(text).unwrap_err());
        }
        for e in errors {
            let text = e.to_string();
            assert!(!text.chars().any(char::is_control), "{text:?}");
            assert!(text.len() < 250, "{} bytes", text.len());
        }
        let e = Target::parse(ansi).unwrap_err();
        assert!(e.to_string().contains("\\u{1b}[2J"), "{e}");
    }
}
