//! The error type of `rdy-spec`.

use thiserror::Error;

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
        value: String,
    },
    /// A check `id` is not of the form `family.name`.
    #[error("'{value}' is not a valid check id")]
    InvalidCheckId {
        /// The text that was refused.
        value: String,
    },
    /// A check `name` is not a valid label.
    #[error("'{value}' is not a valid check name")]
    InvalidCheckName {
        /// The text that was refused.
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
    fn product_message_matches_the_design_wording() {
        let e = SpecError::InvalidProduct {
            value: "Acme Platform".into(),
        };
        assert_eq!(e.to_string(), "'Acme Platform' is not a valid product name");
    }
}
