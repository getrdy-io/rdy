//! Tests for cut buffers: the edge drop, the key guards and the known-secret edges.

use super::*;
use crate::redact::TagKey;

fn redactor() -> Redactor {
    Redactor::new(TagKey::fixed([5; 32]))
}

fn red(bytes: &str, cut: Cut) -> String {
    redactor().redact_buffer(bytes.as_bytes(), cut).to_string()
}

const TAIL: Cut = Cut::new(false, true);
const HEAD: Cut = Cut::new(true, false);

#[test]
fn an_uncut_buffer_is_redacted_like_a_string() {
    let r = redactor();
    let text = "name: x\npassword: hunter2hunter2\nlast line no newline";
    assert_eq!(
        *r.redact_buffer(text.as_bytes(), Cut::NONE),
        *r.redact_str(text)
    );
}

#[test]
fn a_cut_tail_loses_the_partial_last_line_and_gets_the_marker() {
    assert_eq!(
        red("alpha\nbeta\ngam", TAIL),
        "alpha\nbeta\n[truncated]",
        "the line after the last newline is gone"
    );
}

#[test]
fn a_tail_that_ends_on_a_newline_has_no_partial_line() {
    assert_eq!(red("alpha\nbeta\n", TAIL), "alpha\nbeta\n[truncated]");
}

#[test]
fn a_cut_head_loses_the_partial_first_line_and_gets_the_marker() {
    assert_eq!(red("lpha\nbeta\ngamma", HEAD), "[truncated]\nbeta\ngamma");
}

#[test]
fn both_edges_cut_drop_both_partial_lines() {
    assert_eq!(
        red("lpha\nbeta\ngam", Cut::new(true, true)),
        "[truncated]\nbeta\n[truncated]"
    );
}

#[test]
fn with_no_newline_a_window_of_4_kib_goes_from_the_cut_edge_and_the_boundary_moves_to_a_separator()
{
    // Words of 9 bytes and a space: the boundary moves to the space nearest the window edge.
    let text = "aaaaaaaaa ".repeat(1000);
    let tail = red(&text, TAIL);
    let kept = tail.strip_suffix(" [truncated]").expect("marker");
    assert!(kept.ends_with(' ') || kept.ends_with("aaaaaaaaa"), "{kept}");
    assert!(
        text.len() - kept.len() >= WINDOW && text.len() - kept.len() < WINDOW + 20,
        "{}",
        kept.len()
    );
    let head = red(&text, HEAD);
    let kept = head.strip_prefix("[truncated]\n").expect("marker");
    assert!(kept.starts_with("aaaaaaaaa"), "{kept}");
    assert!(
        text.len() - kept.len() >= WINDOW && text.len() - kept.len() < WINDOW + 20,
        "{}",
        kept.len()
    );
}

#[test]
fn with_no_separator_near_the_window_edge_the_whole_buffer_goes() {
    let text = "a".repeat(10_000);
    assert_eq!(red(&text, TAIL), "[truncated]");
    assert_eq!(red(&text, HEAD), "[truncated]\n");
    // A separator exists, but further than a window away from the edge: still dropped whole.
    let far = format!("{}{}", "b ", "a".repeat(10_000));
    assert_eq!(red(&far, TAIL), "[truncated]");
    let far = format!("{} b", "a".repeat(10_000));
    assert_eq!(red(&far, HEAD), "[truncated]\n");
}

#[test]
fn a_short_buffer_with_no_newline_is_dropped_whole() {
    assert_eq!(red("AKIAXXXXXXXXXXXXXXXX", TAIL), "[truncated]");
    assert_eq!(red("AKIAXXXXXXXXXXXXXXXX", HEAD), "[truncated]\n");
}

#[test]
fn the_window_never_splits_a_character() {
    // 3-byte characters, so the window edge falls inside one for most lengths.
    let text = "€".repeat(3000);
    for len in 4090..4100 {
        let part: String = text.chars().take(len).collect();
        let _ = red(&part, TAIL);
        let _ = red(&part, HEAD);
    }
}

#[test]
fn invalid_utf8_becomes_a_replacement_character() {
    let out = redactor().redact_buffer(b"ok \xff\xfe bytes\nnext", TAIL);
    assert_eq!(*out, "ok \u{fffd}\u{fffd} bytes\n[truncated]");
}

#[test]
fn an_unterminated_private_key_goes_to_the_end_of_a_cut_tail() {
    let text = "before\n-----BEGIN RSA PRIVATE KEY-----\nMIIEowIBAAKCAQEA1111\nMIIEowIBAAKCAQEA2222\nMIIEowIB";
    let out = red(text, TAIL);
    assert!(
        out.starts_with("before\n[REDACTED:pem_private_key:"),
        "{out}"
    );
    assert!(out.ends_with("] [truncated]"), "{out}");
    assert!(!out.contains("MIIE") && !out.contains("BEGIN"), "{out}");
}

#[test]
fn a_private_key_with_its_end_is_not_the_guard_s_business() {
    let text = "-----BEGIN PRIVATE KEY-----\nAAAA\n-----END PRIVATE KEY-----\nrest\n";
    let out = red(text, TAIL);
    assert!(!out.contains("pem_private_key"), "{out}");
    // A public certificate with no end is not a key.
    let out = red("-----BEGIN CERTIFICATE-----\nMIIC\nMIID\nMII", TAIL);
    assert!(!out.contains("pem_private_key"), "{out}");
}

#[test]
fn a_private_key_whose_start_was_cut_goes_from_the_start_through_its_end_line() {
    let text = "xx cut line\nMIIEowIBAAKCAQEA1111\nMIIEowIBAAKCAQEA2222\n-----END PRIVATE KEY-----\nafter\n";
    let out = red(text, HEAD);
    assert!(
        out.starts_with("[truncated]\n[REDACTED:pem_private_key:"),
        "{out}"
    );
    assert!(out.ends_with("]\nafter\n"), "{out}");
    assert!(!out.contains("MIIE"), "{out}");
}

#[test]
fn a_complete_block_after_a_begin_in_a_cut_head_is_left_to_the_pem_rule() {
    let text = "cut\n-----BEGIN PRIVATE KEY-----\nAAAA\n-----END PRIVATE KEY-----\n";
    assert!(!red(text, HEAD).contains("pem_private_key"));
}

#[test]
fn known_secrets_are_removed_exactly_and_cut_prefixes_at_the_tail_edge() {
    let r = redactor();
    assert!(r.add_known_secret("tok-0123456789abcdef"));
    // Whole, in a complete line: exact match.
    let out = r.redact_buffer(b"x tok-0123456789abcdef y\nnext\n", TAIL);
    assert!(!out.contains("0123456789"), "{}", *out);
    assert!(out.contains("[REDACTED:known_secret:"), "{}", *out);
    // The kept text of a tail-cut buffer ends on a newline, so a prefix can only survive at the very
    // end of the kept text when the line drop did not apply. Prove the edge match on its own.
    let mut spans = Vec::new();
    r.known
        .edge_spans("v tok-0123456789", false, true, &mut spans);
    assert_eq!((spans[0].start, spans[0].end), (2, 16));
}

#[test]
fn counts_include_the_guard_and_the_known_secrets() {
    let r = redactor();
    assert!(r.add_known_secret("tok-0123456789abcdef"));
    let mut counts = RuleCounts::default();
    let _ = r.redact_buffer_counted(
        b"tok-0123456789abcdef\n-----BEGIN PRIVATE KEY-----\nAAAAAAAAAA\nBBBB",
        TAIL,
        &mut counts,
    );
    assert_eq!(counts.get("known_secret"), 1);
    assert_eq!(counts.get("pem_private_key"), 1);
}

#[test]
fn the_output_of_a_cut_buffer_is_stable_under_a_second_pass() {
    let r = redactor();
    assert!(r.add_known_secret("tok-0123456789abcdef"));
    let once = r.redact_buffer(
        b"a\ntok-0123456789abcdef\npassword=hunter2hunter2\n-----BEGIN PRIVATE KEY-----\nAAAA\nBB",
        TAIL,
    );
    let twice = r.redact_str(&once);
    assert_eq!(*once, *twice);
}
