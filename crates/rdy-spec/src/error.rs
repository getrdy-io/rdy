//! The error type of `rdy-spec`.

use thiserror::Error;

/// The most characters of a refused value that an error keeps.
const MAX_ECHO_CHARS: usize = 64;

/// Makes a refused value safe to print: at most 64 characters, then escaped.
///
/// A spec is untrusted, and its text reaches the terminal inside error messages. `escape_debug` turns
/// ANSI escapes, other control characters and invisible format characters into visible `\u{..}` text.
/// A cut value ends in `...`.
pub(crate) fn echo_safe(value: &str) -> String {
    let mut out: String = value
        .chars()
        .take(MAX_ECHO_CHARS)
        .flat_map(char::escape_debug)
        .collect();
    if value.chars().nth(MAX_ECHO_CHARS).is_some() {
        out.push_str("...");
    }
    out
}

/// Why a spec value or a whole spec was refused.
///
/// Every variant has a `fix:` line from [`SpecError::hint`], which is never empty. Later tickets add the
/// parse, limit and signature variants. The enum is `#[non_exhaustive]` so that is not a breaking change.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
#[non_exhaustive]
pub enum SpecError {
    /// `metadata.product` is not a valid product name.
    #[error("'{value}' is not a valid product name")]
    InvalidProduct {
        /// The text that was refused.
        ///
        /// Already cut to 64 characters and escaped, so it is safe to print.
        value: String,
    },
    /// A check `id` is not of the form `family.name`.
    #[error("'{value}' is not a valid check id")]
    InvalidCheckId {
        /// The text that was refused.
        ///
        /// Already cut to 64 characters and escaped, so it is safe to print.
        value: String,
    },
    /// A check `name` is not a valid label.
    #[error("'{value}' is not a valid check name")]
    InvalidCheckName {
        /// The text that was refused.
        ///
        /// Already cut to 64 characters and escaped, so it is safe to print.
        value: String,
    },
    /// [`crate::load`] cannot return a spec yet, because signature checking and parsing are not wired in.
    #[error("loading a spec is not available in this build")]
    LoadNotWired,
}

impl SpecError {
    /// The fix line for this error. Never empty.
    #[must_use]
    pub fn hint(&self) -> &'static str {
        match self {
            Self::InvalidProduct { .. } => {
                "use lowercase letters, digits and hyphens, such as 'acme-platform'."
            }
            Self::InvalidCheckId { .. } => {
                "write the id in lowercase as family.name, such as 'host.memory'."
            }
            Self::InvalidCheckName { .. } => {
                "use lowercase letters, digits, hyphens and underscores, such as 'data'."
            }
            Self::LoadNotWired => {
                "this is a bug in rdy. Please report it at https://github.com/getrdy-io/rdy/issues and include the output of rdy version."
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::SpecError;

    #[test]
    fn every_variant_has_a_hint_and_a_message() {
        let all = [
            SpecError::InvalidProduct { value: "A".into() },
            SpecError::InvalidCheckId { value: "A".into() },
            SpecError::InvalidCheckName { value: "A".into() },
            SpecError::LoadNotWired,
        ];
        for e in all {
            assert!(!e.hint().is_empty(), "{e:?} has no hint");
            assert!(!e.to_string().is_empty(), "{e:?} has no message");
        }
    }

    #[test]
    fn refused_values_are_escaped_and_capped() {
        let ansi = "\u{1b}[2J\u{1b}]0;pwned\u{7}evil";
        let long = "a".repeat(10 * 1024);
        let cases = [
            crate::spec::ProductSlug::new(ansi).unwrap_err(),
            crate::spec::CheckId::new(ansi).unwrap_err(),
            crate::spec::CheckName::new(ansi).unwrap_err(),
            crate::spec::ProductSlug::new(long.clone()).unwrap_err(),
            crate::spec::CheckId::new(long.clone()).unwrap_err(),
            crate::spec::CheckName::new(long).unwrap_err(),
        ];
        for e in cases {
            let text = e.to_string();
            assert!(!text.chars().any(char::is_control), "{text:?}");
            assert!(text.len() < 200, "{} bytes", text.len());
        }
        let e = crate::spec::ProductSlug::new(ansi).unwrap_err();
        assert!(e.to_string().contains("\\u{1b}[2J"), "{e}");
        let SpecError::InvalidProduct { value } =
            crate::spec::ProductSlug::new("A".repeat(10_240)).unwrap_err()
        else {
            panic!("wrong variant");
        };
        assert_eq!(value, format!("{}...", "A".repeat(64)));
    }

    #[test]
    fn product_message_matches_the_design_wording() {
        let e = SpecError::InvalidProduct {
            value: "Acme Platform".into(),
        };
        assert_eq!(e.to_string(), "'Acme Platform' is not a valid product name");
    }
}
