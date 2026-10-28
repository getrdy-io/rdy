//! Compiling the regular expressions of a spec (01 section 2.6, "Regex").
//!
//! A pattern is Rust `regex` syntax, 1 to 256 characters, matched in linear time. Lint and sign compile
//! every pattern with a size limit, so a pattern that is too big, or wrong, is found by the vendor and
//! not by the customer. [`crate::check::RegexText`] checks the length only. This module does the rest.
//!
//! A `bundle.redact_patterns` regex has one more rule (01 section 2.8): it must not match the empty
//! string, because a pattern that matches nothing everywhere would replace nothing and would
//! cost the redactor a match at every byte.

use regex::{Error, Regex, RegexBuilder};

use crate::error::echo_reason;

/// The most memory a compiled pattern may use, 1 MiB. A pattern of 256 characters that needs more, such
/// as `\w{1000}`, is refused. The regex crate's own default is ten times as much.
const COMPILED_SIZE_LIMIT: usize = 1024 * 1024;

/// The most characters of a compile error that a message keeps.
const MAX_REASON_CHARS: usize = 160;

/// Texts used to look for a pattern that matches the empty string. `""` finds `a*` and `^`. The others
/// find an empty match at a boundary, such as `\b` or `(?m)$`, which `""` alone does not.
const EMPTY_PROBES: [&str; 6] = ["", "a", " ", "a b", "line\nline", "A_1.-"];

/// Compiles `pattern` with the size limit, or says why not. The reason is safe to print.
pub(crate) fn compile(pattern: &str) -> Result<Regex, String> {
    RegexBuilder::new(pattern)
        .size_limit(COMPILED_SIZE_LIMIT)
        .build()
        .map_err(|e| reason(&e))
}

/// Compiles a redact pattern and refuses one that matches the empty string. The reason is safe to print.
pub(crate) fn check_redact_pattern(pattern: &str) -> Result<(), String> {
    let regex = compile(pattern)?;
    if EMPTY_PROBES
        .iter()
        .any(|probe| regex.find_iter(probe).any(|m| m.is_empty()))
    {
        return Err("the pattern matches the empty string".to_owned());
    }
    Ok(())
}

/// The one-line reason for a compile error. The regex crate's parse error is several lines that repeat
/// the pattern. The last line, which starts with `error: `, is the reason.
fn reason(error: &Error) -> String {
    let text = match error {
        Error::Syntax(message) => message
            .lines()
            .rev()
            .find_map(|line| line.strip_prefix("error: "))
            .unwrap_or("the pattern is not valid")
            .to_owned(),
        Error::CompiledTooBig(_) => "the compiled pattern is too large".to_owned(),
        _ => "the pattern does not compile".to_owned(),
    };
    echo_reason(&text, MAX_REASON_CHARS)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_good_pattern_compiles() {
        assert!(compile("ACME-[A-Z0-9]{20}").is_ok());
        assert!(check_redact_pattern("ACME-[A-Z0-9]{20}").is_ok());
    }

    #[test]
    fn a_bad_pattern_gives_a_one_line_reason() {
        for (pattern, want) in [
            ("(abc", "unclosed group"),
            ("a)", "unopened group"),
            ("[z-a]", "invalid character class range"),
            ("\\w{1000}", "too large"),
        ] {
            let Err(why) = compile(pattern) else {
                panic!("{pattern} compiled");
            };
            assert!(why.contains(want), "{pattern}: {why}");
            assert!(!why.contains('\n'), "{pattern}: {why}");
        }
    }

    #[test]
    fn a_pattern_that_can_match_nothing_is_refused_for_redaction() {
        for pattern in ["a*", "^", "$", "x?", "(?m)^$", "\\b", "(a|)"] {
            let Err(why) = check_redact_pattern(pattern) else {
                panic!("{pattern:?} was accepted");
            };
            assert!(why.contains("empty string"), "{pattern:?}: {why}");
        }
        for pattern in ["a+", "\\d{3}-\\d{4}", "\\bkey\\b", "(?i)secret"] {
            assert!(check_redact_pattern(pattern).is_ok(), "{pattern}");
        }
    }

    #[test]
    fn the_reason_is_escaped() {
        let Err(why) = compile("\u{1b}[") else {
            panic!("compiled");
        };
        assert!(!why.chars().any(char::is_control), "{why:?}");
    }
}
