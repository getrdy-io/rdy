//! Tests for the engine. The rule-specific cases live next to the rules.

use std::ops::Range;

use super::rules::is_single_placeholder;
use super::*;

fn redactor() -> Redactor {
    Redactor::new(TagKey::fixed([7; 32]))
}

/// A rule with a fixed name and priority, for engine tests that need exact spans.
fn rule_for(name: &'static str, priority: u8, find: fn(&str, &mut Vec<Range<usize>>)) -> Rule {
    Rule {
        name,
        priority,
        find,
    }
}

/// Pushes fixed byte ranges, whatever the text is.
fn ranges(_text: &str, out: &mut Vec<Range<usize>>, ranges: &[(usize, usize)]) {
    out.extend(ranges.iter().map(|&(s, e)| s..e));
}

/// The tag in the first placeholder of `text`.
fn first_tag(text: &str) -> &str {
    let start = text.find("[REDACTED:").map(|i| i + "[REDACTED:".len());
    let rest = &text[start.expect("a placeholder")..];
    let colon = rest.find(':').expect("a tag separator");
    &rest[colon + 1..colon + 9]
}

#[test]
fn overlapping_spans_give_one_placeholder_and_no_leftover_bytes() {
    // Two rules find overlapping ranges of the same secret. The lower priority rule sticks out on
    // the left, the higher priority rule sticks out on the right.
    let text = "pre AAAAbbbbCCCC post";
    let low = rule_for("low", 10, |t, o| ranges(t, o, &[(4, 12)]));
    let high = rule_for("high", 20, |t, o| ranges(t, o, &[(8, 16)]));
    let mut counts = RuleCounts::default();
    let out = redactor().run(&[low, high], text, &mut counts);
    assert!(out.starts_with("pre [REDACTED:high:"), "{}", *out);
    assert!(out.ends_with("] post"), "{}", *out);
    assert_eq!(out.matches("[REDACTED:").count(), 1);
    for secret_byte_run in ["AAAA", "bbbb", "CCCC", "AAA", "bbb", "CCC", "AA", "CC"] {
        assert!(
            !out.contains(secret_byte_run),
            "{secret_byte_run} survived in {}",
            *out
        );
    }
    assert_eq!(counts.get("high"), 1);
    assert_eq!(counts.get("low"), 0);
    assert_eq!(counts.total(), 1);
}

#[test]
fn the_tag_of_a_merged_span_covers_the_whole_union() {
    let text = "..abcdefgh..";
    let a = rule_for("a", 1, |t, o| ranges(t, o, &[(2, 7)]));
    let b = rule_for("b", 1, |t, o| ranges(t, o, &[(5, 10)]));
    let out = redactor().run(&[a, b], text, &mut RuleCounts::default());
    let whole = redactor().placeholder("a", b"abcdefgh");
    assert_eq!(&*out, &format!("..{whole}.."));
}

#[test]
fn every_pair_of_spans_in_a_short_text_leaves_no_byte_behind() {
    // Exhaustive: every pair of non-empty ranges over a 10 byte text. The expected output is the text
    // with the union of the covered bytes removed, in one placeholder per connected group.
    let text = "0123456789";
    let r = redactor();
    for s1 in 0..10 {
        for e1 in s1 + 1..=10 {
            for s2 in 0..10 {
                for e2 in s2 + 1..=10 {
                    let covered: Vec<bool> = (0..10)
                        .map(|i| (s1..e1).contains(&i) || (s2..e2).contains(&i))
                        .collect();
                    // Two rules with different priorities, one range each.
                    let (x, y) = ((s1, e1), (s2, e2));
                    let spans = vec![
                        Span {
                            start: x.0,
                            end: x.1,
                            rule: "one",
                            priority: 1,
                        },
                        Span {
                            start: y.0,
                            end: y.1,
                            rule: "two",
                            priority: 2,
                        },
                    ];
                    let merged = merge(spans);
                    let out = r.write(text, &merged).expect("valid spans");
                    // Uncovered digits survive in order, covered digits are gone.
                    let kept: String = text
                        .char_indices()
                        .filter(|(i, _)| !covered[*i])
                        .map(|(_, c)| c)
                        .collect();
                    let mut stripped = out.clone();
                    while let Some(at) = stripped.find("[REDACTED:") {
                        let end = stripped[at..].find(']').expect("closing bracket") + at + 1;
                        stripped.replace_range(at..end, "");
                    }
                    assert_eq!(stripped, kept, "ranges {x:?} {y:?} gave {out}");
                    // Groups of covered bytes that touch or overlap are one placeholder.
                    let groups = covered
                        .iter()
                        .enumerate()
                        .filter(|(i, c)| **c && (*i == 0 || !covered[i - 1]))
                        .count();
                    assert_eq!(out.matches("[REDACTED:").count(), groups, "{x:?} {y:?}");
                }
            }
        }
    }
}

#[test]
fn equal_secrets_share_a_tag_inside_one_redactor() {
    let r = redactor();
    let out = r.redact_str("password=Zq9xK7mW2\ntoken: Zq9xK7mW2\nsecret=Other1234");
    let tags: Vec<&str> = out
        .match_indices("[REDACTED:secret_by_key:")
        .map(|(i, m)| &out[i + m.len()..i + m.len() + 8])
        .collect();
    assert_eq!(tags.len(), 3, "{}", *out);
    assert_eq!(tags[0], tags[1]);
    assert_ne!(tags[0], tags[2]);
}

#[test]
fn tags_differ_between_keys() {
    let one = Redactor::new(TagKey::fixed([1; 32])).redact_str("password=hunter2");
    let two = Redactor::new(TagKey::fixed([2; 32])).redact_str("password=hunter2");
    assert_ne!(first_tag(&one), first_tag(&two));
    let again = Redactor::new(TagKey::fixed([1; 32])).redact_str("password=hunter2");
    assert_eq!(one, again);
}

#[test]
fn a_forged_placeholder_prefix_does_not_hide_a_secret() {
    let out = redactor().redact_str("password=[REDACTED:x:00000000]hunter2");
    assert!(!out.contains("hunter2"), "{}", *out);
    assert!(
        out.starts_with("password=[REDACTED:secret_by_key:"),
        "{}",
        *out
    );
    assert_eq!(out.matches("[REDACTED:").count(), 1);
}

#[test]
fn an_exact_placeholder_value_is_left_as_it_is() {
    let r = redactor();
    let once = r.redact_str("password=hunter2");
    let twice = r.redact_str(&once);
    assert_eq!(once, twice);
}

#[test]
fn quotes_and_delimiters_are_kept() {
    let out = redactor().redact_str(r#"{"password": "hunter2", "user": "ada"}"#);
    assert!(
        out.starts_with(r#"{"password": "[REDACTED:secret_by_key:"#),
        "{}",
        *out
    );
    assert!(out.ends_with(r#"]", "user": "ada"}"#), "{}", *out);
}

#[test]
fn text_without_a_secret_is_returned_unchanged() {
    let text = "passed: 12\nsecretName: acme-tls\nimage: ${REGISTRY}/app:1.2\nüñí\n";
    let mut counts = RuleCounts::default();
    let out = redactor().redact_str_counted(text, &mut counts);
    assert_eq!(&*out, text);
    assert_eq!(counts.total(), 0);
}

#[test]
fn no_byte_of_a_matched_secret_survives() {
    // A secret of unusual characters, in every form the rule reads. No three character window of it may
    // appear in the output. A three character window cannot come from a placeholder, whose characters
    // are lowercase letters, digits, brackets, colon, underscore and dot.
    let secret = "Zq9!xK7#mW2$";
    let windows: Vec<&str> = (0..=secret.len() - 3).map(|i| &secret[i..i + 3]).collect();
    let forms = [
        format!("password={secret}"),
        format!("password: {secret}"),
        format!("password=\"{secret}\""),
        format!("password='{secret}'"),
        format!("{{\"password\":\"{secret}\"}}"),
        format!("{{\\\"password\\\":\\\"{secret}\\\"}}"),
        format!("--db-password={secret} --next"),
        format!("password=\"{secret}"),
        format!("x password={secret}\nmore"),
        format!("PASSWORD={secret}\r\nmore"),
        // Review round: values with spaces, glued quotes, references that carry a literal, block scalars.
        format!("password: correct {secret} staple"),
        format!("token: Bearer {secret}"),
        format!("password=x\u{a0}{secret}"),
        format!("password=\"\"{secret}"),
        format!("password=\"a\"{secret} tail"),
        format!("password=${{PG_PW:-{secret}}}"),
        format!("password=$(echo {secret})"),
        format!("password={{{{ .pw | default \"{secret}\" }}}}"),
        format!("password=${{A}}{secret}"),
        format!("Authorization: Basic {secret}"),
        format!("authProfile: {secret}"),
        format!("token: |\n  {secret}\n  more {secret}\nnext: 1"),
        format!("- token: >-\n    {secret}\n"),
        // Second review round.
        format!("password:\n  {secret}\nnext: 1"),
        format!("secret:   \r\n    {secret}\r\nnext: 1"),
        format!("token: | # note\n  {secret}"),
        format!("token: !!binary |\n  {secret}"),
        format!("token: &anchor |-\n  {secret}"),
        format!("\"token\": |\n {secret}\n"),
        format!("token: |\n\t{secret}\nnext: 1"),
        format!(r#"{{\\\"password\\\":\\\"{secret}\\\"}}"#),
        format!("password={{{{{secret}}}}}"),
        format!("password={{{{ {secret} }}}}"),
        format!("password=/run/secrets/../{secret}"),
        // Third review round.
        format!("password: # note\n  {secret}"),
        format!("token: !!binary\n  {secret}"),
        format!("password: &a\n  {secret}"),
        format!("token: !!binary |\n  {secret}"),
        format!("passwords:\n- {secret}"),
        format!("db password:\n  {secret}"),
        format!("x/token: |\n {secret}"),
        format!("password:\r  {secret}"),
        format!("    password:\n\t{secret}"),
        format!("password=!{secret}"),
        format!("password=#{secret}"),
        format!(r#"password=\"pa\\\",{secret}\" x"#),
        // Fourth review round: values that run over several lines.
        format!("password: correct {secret}\n  battery staple"),
        format!("password: \"hunter\n  {secret}\""),
        format!("password: {{\n  a: {secret}\n}}"),
        format!("password: [\n  {secret}\n]"),
        format!("password: null\n  {secret}"),
        format!("password:\n# old\n  {secret}"),
        format!("{{\"password\":\n\"{secret}\"}}"),
        format!("k:\n  y: 1\u{85}password:\n {secret}"),
        format!("k:\n  y: 1\u{2028}password:\n {secret}"),
        format!("k:\n  y: 1\u{2029}password:\n {secret}"),
        format!("token: |\n  # {secret}"),
        // Fifth review round: values that continue at the same column.
        format!("password: [a,\n{secret}]"),
        format!("password: {{\nv: {secret}}}"),
        format!("password: \"a\n{secret}\""),
        format!("{{\n\"password\": [\n\"{secret}\"\n]\n}}"),
        format!("TOKEN=\"a\n{secret}\""),
        format!("TOKEN='a\n{secret}'"),
        format!("password: [[a], {{b: [\n{secret}]}}]\nnext: 1"),
        format!("password: \"a\\\"\n{secret}\"\nnext: 1"),
        format!("password: 'it''s\n{secret}'\nnext: 1"),
        format!("password: [a,\n{secret}\nnext: 1"),
        format!("password: \"a\nb\"{secret} x\nnext: 1"),
        format!("password: [a,\nb]\n  {secret}\nnext: 1"),
    ];
    let r = redactor();
    for form in &forms {
        let out = r.redact_str(form);
        for w in &windows {
            assert!(!out.contains(w), "{w} survived in {} from {form}", *out);
        }
        assert!(out.contains("[REDACTED:secret_by_key:"), "{form}");
    }
}

#[test]
fn a_rule_that_reports_a_bad_range_makes_the_engine_drop_the_whole_string() {
    let text = "keep é this";
    // Past the end.
    let past = rule_for("past", 1, |t, o| ranges(t, o, &[(2, 99)]));
    // Inside the two-byte character, which starts at byte 5.
    let mid = rule_for("mid", 1, |t, o| ranges(t, o, &[(5, 6)]));
    // Start after end.
    let inverted = rule_for("inverted", 1, |t, o| ranges(t, o, &[(7, 3)]));
    for bad in [past, mid, inverted] {
        let mut counts = RuleCounts::default();
        let out = redactor().run(&[bad], text, &mut counts);
        assert!(out.starts_with("[REDACTED:redactor_error:"), "{}", *out);
        assert!(!out.contains("keep"), "{}", *out);
        assert_eq!(counts.get("redactor_error"), 1);
    }
}

#[test]
fn counts_are_per_call() {
    let r = redactor();
    let mut a = RuleCounts::default();
    let _ = r.redact_str_counted("password=one\ntoken=two", &mut a);
    let _ = r.redact_str("password=three");
    let mut b = RuleCounts::default();
    let _ = r.redact_str_counted("password=four", &mut b);
    assert_eq!(a.get("secret_by_key"), 2);
    assert_eq!(b.get("secret_by_key"), 1);
    assert_eq!(a.iter().collect::<Vec<_>>(), [("secret_by_key", 2)]);
}

#[test]
fn placeholder_grammar_is_checked_exactly() {
    assert!(is_single_placeholder("[REDACTED:secret_by_key:1a2b3c4d]"));
    assert!(is_single_placeholder("[REDACTED:custom.my_rule:00000000]"));
    for bad in [
        "[REDACTED:x:00000000]x",
        "x[REDACTED:x:00000000]",
        "[REDACTED:x:0000000G]",
        "[REDACTED:x:000000000]",
        "[REDACTED::00000000]",
        "[REDACTED:X:00000000]",
        "[REDACTED:x:00000000][REDACTED:x:00000000]",
        "",
    ] {
        assert!(!is_single_placeholder(bad), "{bad}");
    }
}

#[test]
fn the_error_has_a_fix_hint() {
    let msg = RedactError::NoRandomness.to_string();
    assert!(msg.contains("Fix:"), "{msg}");
}
