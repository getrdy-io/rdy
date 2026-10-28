//! The error type of `rdy-spec`.

use std::fmt;

use thiserror::Error;

use crate::sig::SignatureError;

/// The most characters of a refused value that an error keeps.
const MAX_ECHO_CHARS: usize = 64;

/// Makes a refused value safe to print: at most `max_chars` characters, then escaped.
///
/// Not part of the stable API; used by rdy-engine to escape echoed spec text.
///
/// A spec is untrusted, and its text reaches the terminal inside error messages. `escape_debug` turns
/// ANSI escapes, other control characters and invisible format characters into visible `\u{..}` text.
/// A cut value ends in `...`.
#[doc(hidden)]
#[must_use]
pub fn echo_capped(value: &str, max_chars: usize) -> String {
    let mut out: String = value
        .chars()
        .take(max_chars)
        .flat_map(char::escape_debug)
        .collect();
    if value.chars().nth(max_chars).is_some() {
        out.push_str("...");
    }
    out
}

/// Makes a reason from the YAML reader safe to print: at most `max_chars` characters, with control and
/// invisible characters escaped. Unlike [`echo_capped`] it leaves backslashes and quotes alone, because
/// the reader has already escaped the text it quotes and a second pass would double every backslash.
pub(crate) fn echo_reason(value: &str, max_chars: usize) -> String {
    let mut out = String::new();
    for c in value.chars().take(max_chars) {
        if matches!(c, '\\' | '\'' | '"') {
            out.push(c);
        } else {
            out.extend(c.escape_debug());
        }
    }
    if value.chars().nth(max_chars).is_some() {
        out.push_str("...");
    }
    out
}

/// Makes a refused value safe to print: at most 64 characters, then escaped. See [`echo_capped`].
pub(crate) fn echo_safe(value: &str) -> String {
    echo_capped(value, MAX_ECHO_CHARS)
}

/// A place in a spec file, as an editor shows it.
///
/// Both numbers start at 1. The column counts characters, not bytes, and a tab counts as one.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub struct Location {
    /// The line, starting at 1.
    pub line: u32,
    /// The column, starting at 1.
    pub column: u32,
}

impl Location {
    /// A location. Both numbers start at 1.
    #[must_use]
    pub fn new(line: u32, column: u32) -> Self {
        Self { line, column }
    }
}

impl fmt::Display for Location {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}:{}", self.line, self.column)
    }
}

/// Why a spec value or a whole spec was refused.
///
/// Every variant has a `fix:` line from [`SpecError::hint`], which is never empty. Errors that point at a
/// place in the file come wrapped in [`SpecError::Located`]: use [`SpecError::location`] for the place and
/// [`SpecError::kind`] for the error itself. The enum is
/// `#[non_exhaustive]` so that is not a breaking change.
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
    /// `metadata.serial` is larger than 2^53 - 1.
    #[error("serial {value} is too large")]
    InvalidSerial {
        /// The number that was refused.
        value: u64,
    },
    /// The signature is missing, in the wrong form, from a key nobody pinned for this product, for another
    /// product, or does not match the file. Nothing was parsed.
    #[error(transparent)]
    Signature(#[from] SignatureError),
    /// An error that points at a place in the file. The parser wraps every error it can place this way.
    ///
    /// `Display` shows only the inner message, so a caller can print `file:line:column: message`.
    #[error("{error}")]
    Located {
        /// Where in the file the problem is.
        at: Location,
        /// What the problem is.
        error: Box<SpecError>,
    },
    /// The file is larger than the limit. Nothing was parsed.
    #[error("the spec is {size} bytes. The limit is {limit} bytes")]
    TooLarge {
        /// The size of the file in bytes.
        size: usize,
        /// The largest size rdy reads, in bytes.
        limit: usize,
    },
    /// The file is not UTF-8 text. The error is located at the first bad byte.
    #[error("the file is not valid UTF-8 text")]
    NotUtf8,
    /// The text is not valid YAML, or the file has no YAML document.
    #[error("{reason}")]
    Syntax {
        /// What the YAML reader said, already cut and escaped so it is safe to print.
        reason: String,
    },
    /// The nesting of lists and maps is deeper than the limit.
    #[error("the nesting is deeper than {limit} levels")]
    TooDeep {
        /// The deepest nesting rdy reads.
        limit: usize,
    },
    /// The file holds more than one YAML document.
    #[error("the file has more than one YAML document")]
    MultipleDocuments,
    /// The file has a `%YAML` or `%TAG` directive, or another directive.
    #[error("YAML directives (lines that start with '%') are not allowed in a spec")]
    Directive,
    /// A node carries an explicit tag such as `!!binary` or `!custom`.
    #[error("the tag '{tag}' is not allowed in a spec")]
    Tag {
        /// The tag as written, already cut and escaped so it is safe to print.
        tag: String,
    },
    /// A node defines an anchor (`&name`).
    #[error("anchors ('&name') are not allowed in a spec")]
    Anchor,
    /// A node is an alias (`*name`).
    #[error("aliases ('*name') are not allowed in a spec")]
    Alias,
    /// A map uses the merge key `<<`.
    #[error("merge keys ('<<') are not allowed in a spec")]
    MergeKey,
    /// A key appears twice in the same map, at any depth.
    #[error("the key '{key}' appears twice in the same map")]
    DuplicateKey {
        /// The key, already cut and escaped so it is safe to print.
        key: String,
    },
    /// A number that is not finite: `.nan`, `.inf`, `-.inf` or a decimal that overflows.
    #[error("'{text}' is not allowed in a spec")]
    NonFiniteNumber {
        /// The text as written, already cut and escaped so it is safe to print.
        text: String,
    },
    /// An unquoted decimal such as `12.10`. YAML reads it as the number 12.1 and loses the trailing zero.
    #[error("{}", unquoted_decimal_message(.key.as_deref(), .text))]
    UnquotedDecimal {
        /// The key the number belongs to, if there is one, already cut and escaped.
        key: Option<String>,
        /// The text as written, already cut and escaped so it is safe to print.
        text: String,
    },
    /// `apiVersion` is missing, is not text, or names something that is not an `rdy/v` version.
    #[error("{}", bad_api_version_message(.found.as_deref()))]
    BadApiVersion {
        /// What the file said, already cut and escaped. `None` when the key is missing or not text.
        found: Option<String>,
    },
    /// `apiVersion` names a later version, such as `rdy/v2`.
    #[error("this spec is for {found}. This rdy reads rdy/v1 only")]
    UnsupportedApiVersion {
        /// The version as written, already cut and escaped so it is safe to print.
        found: String,
    },
    /// A key that the spec format does not have, at the top level or in `metadata` or `bundle`.
    #[error("unknown key '{key}'")]
    UnknownKey {
        /// The key, already cut and escaped so it is safe to print.
        key: String,
    },
    /// A required key is missing.
    #[error("missing the key '{field}'")]
    MissingField {
        /// The key, already cut and escaped so it is safe to print.
        field: String,
    },
    /// A value has the wrong shape for its place, for example text where a list belongs.
    #[error("{reason}")]
    InvalidValue {
        /// What is wrong, already cut and escaped so it is safe to print.
        reason: String,
    },
    /// A check entry has no `id`.
    #[error("check {number} has no id")]
    MissingCheckId {
        /// The place of the entry in `checks`, counting from 1.
        number: usize,
    },
    /// Two check entries have the same key, which is `id`, or `id/name` when there is a name.
    #[error("{}", duplicate_check_message(.id, .name.as_deref()))]
    DuplicateCheck {
        /// The id of both entries, already cut and escaped so it is safe to print.
        id: String,
        /// The name of both entries, if they have one.
        name: Option<String>,
    },
}

/// Keys that hold versions in the `rdy/v1` spec. A number under one of these has a version meaning, so
/// the message says versions must be text. Under any other key the message only asks for quotes.
const VERSION_KEYS: [&str; 5] = ["min", "max", "openshift_min", "version", "versions"];

fn unquoted_decimal_message(key: Option<&str>, text: &str) -> String {
    match key {
        Some(key) if VERSION_KEYS.contains(&key) => {
            format!("{key} is written as the number {text}, but versions must be text")
        }
        Some(key) => format!("{key} is written as the number {text}. Quote it to keep it as typed"),
        None => format!("{text} is written as a number. Quote it to keep it as typed"),
    }
}

fn duplicate_check_message(id: &str, name: Option<&str>) -> String {
    match name {
        Some(name) => format!("two checks are named {id} ({name})"),
        None => format!("two checks are named {id}"),
    }
}

fn bad_api_version_message(found: Option<&str>) -> String {
    match found {
        Some(found) => format!("apiVersion must be rdy/v1, not '{found}'"),
        None => "apiVersion must be rdy/v1".to_owned(),
    }
}

impl SpecError {
    /// Where in the file the problem is, when the parser could tell.
    #[must_use]
    pub fn location(&self) -> Option<Location> {
        match self {
            Self::Located { at, .. } => Some(*at),
            _ => None,
        }
    }

    /// The error without its location wrapper.
    #[must_use]
    pub fn kind(&self) -> &SpecError {
        match self {
            Self::Located { error, .. } => error.kind(),
            other => other,
        }
    }

    /// Wraps this error with the place it was found.
    pub(crate) fn at(self, at: Location) -> Self {
        Self::Located {
            at,
            error: Box::new(self),
        }
    }

    /// The fix line with the real values filled in, where the error knows them. Otherwise the same text
    /// as [`SpecError::hint`].
    #[must_use]
    pub fn fix(&self) -> String {
        match self {
            Self::Signature(error) => error.fix(),
            Self::Located { error, .. } => error.fix(),
            other => other.hint().to_owned(),
        }
    }

    /// The fix line for this error. Never empty.
    #[must_use]
    pub fn hint(&self) -> &'static str {
        match self {
            Self::Located { error, .. } => error.hint(),
            Self::TooLarge { .. } => {
                "remove checks or long text from the spec. A spec file can be at most 1 MiB."
            }
            Self::NotUtf8 => "save the file as UTF-8 text.",
            Self::Syntax { .. } => {
                "fix the YAML at the marked line. An editor with YAML support shows the problem."
            }
            Self::TooDeep { .. } => "flatten the nesting. A spec can nest 64 levels at most.",
            Self::MultipleDocuments => {
                "keep one document per file. Remove the extra '---' line and what follows it."
            }
            Self::Directive => "remove the line that starts with '%'. A spec needs no directives.",
            Self::Tag { .. } | Self::NonFiniteNumber { .. } => {
                "write a plain number, string or list."
            }
            Self::Anchor | Self::Alias => {
                "write the value out in full. A spec does not use anchors or aliases."
            }
            Self::MergeKey => "write the keys out in full. A spec does not use '<<'.",
            Self::DuplicateKey { .. } => {
                "remove one of the two keys. A key can appear once in a map."
            }
            Self::UnquotedDecimal { .. } => {
                "write it with quotes, such as min: \"1.30\", so the text stays as typed."
            }
            Self::BadApiVersion { .. } => "add 'apiVersion: rdy/v1' as the first line.",
            Self::UnsupportedApiVersion { .. } => "install the latest rdy.",
            Self::UnknownKey { .. } => {
                "check the spelling. If it is right, this spec needs a newer rdy. Install the latest and run again."
            }
            Self::MissingField { .. } => "add the key. The spec reference lists the required keys.",
            Self::InvalidValue { .. } => {
                "change the value to the form the spec reference shows for this key."
            }
            Self::MissingCheckId { .. } => "add an id such as 'id: host.memory'.",
            Self::DuplicateCheck { .. } => {
                "give each one a name, for example 'name: data'. The name is only a label."
            }
            Self::InvalidProduct { .. } => {
                "use lowercase letters, digits and hyphens, such as 'acme-platform'."
            }
            Self::InvalidCheckId { .. } => {
                "write the id in lowercase as family.name, such as 'host.memory'."
            }
            Self::InvalidCheckName { .. } => {
                "use lowercase letters, digits, hyphens and underscores, such as 'data'."
            }
            Self::InvalidSerial { .. } => "use a revision number up to 9007199254740991.",
            Self::Signature(error) => error.hint(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{Location, SpecError};
    use crate::sig::SignatureError;

    /// The match has no wildcard, so a new variant fails to compile until it is listed here and in
    /// `samples`.
    fn assert_has_hint_and_message(e: &SpecError) {
        match e {
            SpecError::InvalidProduct { .. }
            | SpecError::InvalidCheckId { .. }
            | SpecError::InvalidCheckName { .. }
            | SpecError::InvalidSerial { .. }
            | SpecError::Signature(_)
            | SpecError::Located { .. }
            | SpecError::TooLarge { .. }
            | SpecError::NotUtf8
            | SpecError::Syntax { .. }
            | SpecError::TooDeep { .. }
            | SpecError::MultipleDocuments
            | SpecError::Directive
            | SpecError::Tag { .. }
            | SpecError::Anchor
            | SpecError::Alias
            | SpecError::MergeKey
            | SpecError::DuplicateKey { .. }
            | SpecError::NonFiniteNumber { .. }
            | SpecError::UnquotedDecimal { .. }
            | SpecError::BadApiVersion { .. }
            | SpecError::UnsupportedApiVersion { .. }
            | SpecError::UnknownKey { .. }
            | SpecError::MissingField { .. }
            | SpecError::MissingCheckId { .. }
            | SpecError::DuplicateCheck { .. }
            | SpecError::InvalidValue { .. } => {
                assert!(!e.hint().is_empty(), "{e:?} has no hint");
                assert!(!e.to_string().is_empty(), "{e:?} has no message");
            }
        }
    }

    #[test]
    fn every_variant_has_a_hint_and_a_message() {
        let samples = [
            SpecError::InvalidProduct { value: "A".into() },
            SpecError::InvalidCheckId { value: "A".into() },
            SpecError::InvalidCheckName { value: "A".into() },
            SpecError::InvalidSerial { value: u64::MAX },
            SpecError::Signature(SignatureError::Missing),
            SpecError::Anchor.at(Location::new(3, 5)),
            SpecError::TooLarge { size: 2, limit: 1 },
            SpecError::NotUtf8,
            SpecError::Syntax { reason: "x".into() },
            SpecError::TooDeep { limit: 64 },
            SpecError::MultipleDocuments,
            SpecError::Directive,
            SpecError::Tag { tag: "!x".into() },
            SpecError::Anchor,
            SpecError::Alias,
            SpecError::MergeKey,
            SpecError::DuplicateKey { key: "k".into() },
            SpecError::NonFiniteNumber {
                text: ".nan".into(),
            },
            SpecError::UnquotedDecimal {
                key: Some("min".into()),
                text: "1.30".into(),
            },
            SpecError::UnquotedDecimal {
                key: None,
                text: "1.30".into(),
            },
            SpecError::BadApiVersion { found: None },
            SpecError::BadApiVersion {
                found: Some("x".into()),
            },
            SpecError::UnsupportedApiVersion {
                found: "rdy/v2".into(),
            },
            SpecError::UnknownKey { key: "k".into() },
            SpecError::MissingField { field: "k".into() },
            SpecError::InvalidValue { reason: "r".into() },
            SpecError::MissingCheckId { number: 3 },
            SpecError::DuplicateCheck {
                id: "host.disk".into(),
                name: None,
            },
            SpecError::DuplicateCheck {
                id: "host.disk".into(),
                name: Some("data".into()),
            },
        ];
        for e in &samples {
            assert_has_hint_and_message(e);
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
    fn a_located_error_keeps_its_message_hint_and_place() {
        let inner = SpecError::DuplicateKey { key: "min".into() };
        let located = inner.clone().at(Location::new(8, 5));
        assert_eq!(located.location(), Some(Location::new(8, 5)));
        assert_eq!(located.kind(), &inner);
        assert_eq!(located.to_string(), inner.to_string());
        assert_eq!(located.hint(), inner.hint());
        assert_eq!(inner.location(), None);
        assert_eq!(inner.kind(), &inner);
        assert_eq!(Location::new(8, 5).to_string(), "8:5");
        // Wrapping twice still finds the innermost error.
        let twice = located.at(Location::new(1, 1));
        assert_eq!(twice.kind(), &inner);
    }

    #[test]
    fn messages_match_the_design_wording() {
        let msg = |e: SpecError| e.to_string();
        assert_eq!(
            msg(SpecError::NonFiniteNumber {
                text: ".nan".into()
            }),
            "'.nan' is not allowed in a spec"
        );
        assert_eq!(
            msg(SpecError::UnknownKey {
                key: "metdata".into()
            }),
            "unknown key 'metdata'"
        );
        assert_eq!(
            msg(SpecError::UnsupportedApiVersion {
                found: "rdy/v2".into()
            }),
            "this spec is for rdy/v2. This rdy reads rdy/v1 only"
        );
        assert_eq!(
            msg(SpecError::BadApiVersion { found: None }),
            "apiVersion must be rdy/v1"
        );
        assert_eq!(
            msg(SpecError::UnquotedDecimal {
                key: Some("min".into()),
                text: "1.30".into()
            }),
            "min is written as the number 1.30, but versions must be text"
        );
        assert_eq!(
            msg(SpecError::UnquotedDecimal {
                key: Some("port".into()),
                text: "0080".into()
            }),
            "port is written as the number 0080. Quote it to keep it as typed"
        );
        assert_eq!(
            msg(SpecError::UnquotedDecimal {
                key: None,
                text: "1e3".into()
            }),
            "1e3 is written as a number. Quote it to keep it as typed"
        );
        assert_eq!(
            msg(SpecError::MissingCheckId { number: 3 }),
            "check 3 has no id"
        );
        assert_eq!(
            msg(SpecError::DuplicateCheck {
                id: "host.disk".into(),
                name: None
            }),
            "two checks are named host.disk"
        );
        assert_eq!(
            msg(SpecError::DuplicateCheck {
                id: "host.disk".into(),
                name: Some("data".into())
            }),
            "two checks are named host.disk (data)"
        );
        assert_eq!(
            SpecError::BadApiVersion { found: None }.hint(),
            "add 'apiVersion: rdy/v1' as the first line."
        );
    }

    #[test]
    fn product_message_matches_the_design_wording() {
        let e = SpecError::InvalidProduct {
            value: "Acme Platform".into(),
        };
        assert_eq!(e.to_string(), "'Acme Platform' is not a valid product name");
    }
}
