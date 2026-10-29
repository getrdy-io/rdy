//! Compiling the regular expressions of a spec (01 section 2.6, "Regex").
//!
//! A pattern is Rust `regex` syntax, 1 to 256 characters, matched in linear time. Lint and sign compile
//! every pattern with a size limit, so a pattern that is too big, or wrong, is found by the vendor and
//! not by the customer. [`crate::check::RegexText`] checks the length only. This module does the rest.
//!
//! A `bundle.redact_patterns` regex has one more rule (01 section 2.8): it must not match the empty
//! string, because a pattern that matches the empty string matches at every byte and replaces nothing.

use regex::{Error, Regex, RegexBuilder};

use crate::error::echo_reason;

/// The most memory a compiled pattern may use, 1 MiB, for the program and for the lazy DFA cache. A
/// pattern of 256 characters that needs more, such as `\w{1000}`, is refused. The regex crate's own
/// default is ten times as much for the program.
const COMPILED_SIZE_LIMIT: usize = 1024 * 1024;

/// The most characters of a compile error that a message keeps.
const MAX_REASON_CHARS: usize = 160;

/// Compiles `pattern` with the size limits, or says why not. The reason is safe to print.
///
/// This is the one place that builds a regex from the text of a spec, so lint, sign and the checks that
/// run the pattern all apply the same limits to the same text.
#[doc(hidden)]
pub fn compile(pattern: &str) -> Result<Regex, String> {
    RegexBuilder::new(pattern)
        .size_limit(COMPILED_SIZE_LIMIT)
        .dfa_size_limit(COMPILED_SIZE_LIMIT)
        .build()
        .map_err(|e| reason(&e))
}

/// Compiles a redact pattern and refuses one that can match the empty string. The reason is safe to
/// print.
///
/// The rule is read from the parsed pattern: the shortest text it can match has length 0. That holds for
/// `a*`, `^`, `\b` and `(?-u:\B)\b` alike, with no list of sample texts to dodge.
pub(crate) fn check_redact_pattern(pattern: &str) -> Result<(), String> {
    compile(pattern)?;
    // `compile` accepted the text, so this parse cannot fail. If it somehow does, refuse.
    let hir = regex_syntax::ParserBuilder::new()
        .build()
        .parse(pattern)
        .map_err(|_| "the pattern does not parse".to_owned())?;
    if hir.properties().minimum_len() == Some(0) {
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
        // Patterns that match the empty string only at a boundary, which no short sample finds.
        for pattern in [
            "(?-u:\\B)\\b",
            "(?:a|\\b)",
            "\\B",
            "(?m:^)",
            "(?:x{0})",
            "(?:abc){0,3}",
            "\\b{start}",
        ] {
            let Err(why) = check_redact_pattern(pattern) else {
                panic!("{pattern:?} was accepted");
            };
            assert!(why.contains("empty string"), "{pattern:?}: {why}");
        }
        for pattern in [
            "a+",
            "\\d{3}-\\d{4}",
            "\\bkey\\b",
            "(?i)secret",
            "(?:ab){2,}",
        ] {
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
