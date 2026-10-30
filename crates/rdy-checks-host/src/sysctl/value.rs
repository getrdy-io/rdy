//! Comparing a value from the machine with what the spec wants.
//!
//! The kernel prints a multi-field value with tabs (`4096\t131072\t6291456`) and a vendor writes it with
//! spaces, so both sides are put in one form first: every run of white space becomes one space
//! (`ValueRule` in `rdy-spec` says so). Whole numbers are compared as numbers, in 128 bits, because a
//! live value such as `kernel.shmmax` is a `u64` and a spec number is an `i64`.

use rdy_spec::check::{Compare, ValueRule};

/// What comparing a value with a rule gave.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum Judged {
    /// The value meets the rule.
    Met,
    /// The value does not meet the rule.
    Unmet,
    /// The rule asks for a number and the value is not one, so the rule cannot be judged.
    NotNumber,
}

/// White space runs (spaces, tabs, line ends) replaced by one space, with none at either end.
pub(super) fn normalise(text: &str) -> String {
    text.split_whitespace().collect::<Vec<_>>().join(" ")
}

/// A whole number as the kernel prints it, with an optional minus sign. 30 digits at most.
pub(super) fn whole(text: &str) -> Option<i128> {
    let digits = text.strip_prefix('-').unwrap_or(text);
    if digits.is_empty() || digits.len() > 30 || !digits.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    text.parse().ok()
}

/// Whether `have`, text from the machine, meets `rule`.
pub(super) fn judge(rule: &ValueRule, have: &str) -> Judged {
    let have = normalise(have);
    match rule.compare {
        Compare::Equal => {
            let want = normalise(&rule.value);
            let same = have == want
                || matches!((whole(&have), whole(&want)), (Some(a), Some(b)) if a == b);
            if same { Judged::Met } else { Judged::Unmet }
        }
        Compare::AtLeast | Compare::AtMost => match (whole(&have), rule.integer()) {
            (Some(have), Some(want)) => judge_number(rule.compare, i128::from(want), have),
            _ => Judged::NotNumber,
        },
        _ => Judged::NotNumber,
    }
}

/// Whether the whole number `have` meets a rule of kind `compare` with the bound `want`.
pub(super) fn judge_number(compare: Compare, want: i128, have: i128) -> Judged {
    let met = match compare {
        Compare::AtLeast => have >= want,
        Compare::AtMost => have <= want,
        Compare::Equal => have == want,
        _ => return Judged::NotNumber,
    };
    if met { Judged::Met } else { Judged::Unmet }
}

/// The rule as a spec writes it: `1`, `bbr`, `>=262144`.
pub(super) fn rule_text(rule: &ValueRule) -> String {
    let value = normalise(&rule.value);
    match rule.compare {
        Compare::AtLeast => format!(">={value}"),
        Compare::AtMost => format!("<={value}"),
        _ => value,
    }
}

/// The rule in words, for a sentence: `262144`, `at least 262144`, `at most 1024`.
pub(super) fn need_words(rule: &ValueRule) -> String {
    let value = normalise(&rule.value);
    match rule.compare {
        Compare::AtLeast => format!("at least {value}"),
        Compare::AtMost => format!("at most {value}"),
        _ => value,
    }
}

/// Whether `value` may sit inside single quotes in a command that a customer copies. Only plain
/// characters pass, so a value from a spec can never end the quote and add a command.
pub(super) fn is_quotable(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 128
        && value.chars().all(|c| {
            c.is_ascii_alphanumeric() || matches!(c, ' ' | '.' | '_' | '-' | ':' | ',' | '+')
        })
}

/// At most `max` characters of `text`, with `...` where it was cut.
pub(super) fn clip(text: &str, max: usize) -> String {
    if text.chars().count() <= max {
        text.to_owned()
    } else {
        let head: String = text.chars().take(max).collect();
        format!("{head}...")
    }
}
