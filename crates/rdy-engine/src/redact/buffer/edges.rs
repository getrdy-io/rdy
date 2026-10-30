//! Tests for the window edge of a cut buffer with no newline, known secrets that cross a boundary, the
//! END label match and the bare key body of a buffer cut at both ends.

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

/// A buffer of `total` bytes of `xx ` filler with `canary` written at `at`, a space on each side.
fn place(total: usize, at: usize, canary: &str) -> String {
    let mut bytes: Vec<u8> = (0..total)
        .map(|i| if i % 3 == 2 { b' ' } else { b'x' })
        .collect();
    bytes[at - 1] = b' ';
    bytes[at..at + canary.len()].copy_from_slice(canary.as_bytes());
    bytes[at + canary.len()] = b' ';
    String::from_utf8(bytes).expect("ascii")
}

fn windows(secret: &str, width: usize) -> Vec<String> {
    secret
        .as_bytes()
        .windows(width)
        .map(|w| String::from_utf8_lossy(w).into_owned())
        .collect()
}

const TOTAL: usize = 10_000;
/// Where the tail boundary falls before it moves, and where the head boundary falls.
const TAIL_EDGE: usize = TOTAL - WINDOW;
const HEAD_EDGE: usize = WINDOW;

fn assert_gone(what: &str, k: usize, out: &str, secret: &str, width: usize) {
    for needle in windows(secret, width) {
        assert!(
            !out.contains(&needle),
            "{what} at {k}: {needle} survived in {out:.80}"
        );
    }
}

#[test]
fn a_url_with_userinfo_across_either_window_edge_is_dropped_whole_at_offsets_1_to_64() {
    let userinfo = "svcuser:Pw7canaryZq9";
    let url = format!("https://{userinfo}@proxy.example.test:3128/");
    for k in 1..=64 {
        // The tail edge falls k bytes into the URL, or the URL ends before it.
        let out = red(&place(TOTAL, TAIL_EDGE - k, &url), TAIL);
        if k < url.len() {
            assert_gone("tail", k, &out, userinfo, 8);
        }
        // The head edge falls k bytes after the URL starts, or the URL ends before it.
        let out = red(&place(TOTAL, HEAD_EDGE - k, &url), HEAD);
        assert_gone("head", k, &out, userinfo, 8);
    }
}

#[test]
fn a_known_8_byte_and_6_byte_password_across_either_window_edge_never_leave_a_fragment() {
    for secret in ["Qz7!kLm2", "Zq9k2m"] {
        let r = redactor();
        assert!(r.add_known_secret(secret));
        for k in 1..=64 {
            let tail = r.redact_buffer(place(TOTAL, TAIL_EDGE - k, secret).as_bytes(), TAIL);
            assert_gone("tail", k, &tail, secret, 3);
            let head = r.redact_buffer(place(TOTAL, HEAD_EDGE - k, secret).as_bytes(), HEAD);
            assert_gone("head", k, &head, secret, 3);
        }
    }
}

#[test]
fn a_known_secret_that_holds_a_separator_is_dropped_from_its_own_start_or_end() {
    // The boundary would move to a space inside the secret and keep `ab` or `gh` on one side of it.
    let secret = "ab cd;ef gh";
    let r = redactor();
    assert!(r.add_known_secret(secret));
    for k in 1..secret.len() {
        let tail = r.redact_buffer(place(TOTAL, TAIL_EDGE - k, secret).as_bytes(), TAIL);
        assert!(!tail.contains("ab") && !tail.contains("cd"), "tail at {k}");
        let head = r.redact_buffer(place(TOTAL, HEAD_EDGE - k, secret).as_bytes(), HEAD);
        assert!(!head.contains("gh") && !head.contains("ef"), "head at {k}");
    }
}

#[test]
fn every_kind_of_separator_moves_the_boundary() {
    for sep in ['\0', '\t', ',', ';', '&', '"', '\''] {
        let word = "w".repeat(30);
        let text = format!("{}{sep}{word}{sep}{}", "a ".repeat(2500), "z ".repeat(2000));
        let out = red(&text, TAIL);
        assert!(out.ends_with("[truncated]"), "{sep:?}");
        assert!(text.len() - out.len() < 4200, "{sep:?}");
        assert!(!out.contains('w'), "{sep:?}");
    }
}

#[test]
fn a_known_secret_inside_a_placeholder_is_left_alone_so_a_second_pass_changes_nothing() {
    let r = redactor();
    assert!(r.add_known_secret("REDACTED"));
    assert!(r.add_known_secret("known_secret"));
    let once = r.redact_buffer(b"a REDACTED b known_secret c\nnext\n", TAIL);
    assert_eq!(
        once.matches("[REDACTED:known_secret:").count(),
        2,
        "{}",
        *once
    );
    assert_eq!(*r.redact_str(&once), *once);
}

#[test]
fn the_end_line_of_a_key_must_carry_the_label_of_its_begin_line() {
    // A different label does not close the key.
    let text = "ok\n-----BEGIN RSA PRIVATE KEY-----\nAAAA\n-----END PRIVATE KEY-----\nBBBB\nCC";
    let out = red(text, TAIL);
    assert!(out.contains("[REDACTED:pem_private_key:"), "{out}");
    assert!(!out.contains("BBBB"), "{out}");
    // The same label does: the PEM rule takes the block and the text after it stays.
    let text = "ok\n-----BEGIN RSA PRIVATE KEY-----\nAAAA\n-----END RSA PRIVATE KEY-----\nkeep\nCC";
    let out = red(text, TAIL);
    assert!(out.contains("]\nkeep\n"), "{out}");
    assert!(!out.contains("AAAA") && !out.contains("BEGIN"), "{out}");
    // At a cut head, a BEGIN of another label does not make the END matched.
    let text = "cut\n-----BEGIN EC PRIVATE KEY-----\nAAAA\n-----END RSA PRIVATE KEY-----\nrest\n";
    let out = red(text, HEAD);
    assert!(out.contains("[REDACTED:pem_private_key:"), "{out}");
    assert!(!out.contains("BEGIN EC"), "{out}");
}

#[test]
fn with_both_ends_cut_a_bare_key_body_goes() {
    let line = |c: char| format!("{}\n", c.to_string().repeat(64));
    let body: String = ['A', 'B', 'C'].into_iter().map(line).collect();
    let text = format!("a partial line\n{body}some trailing partial");
    let out = red(&text, Cut::new(true, true));
    assert!(
        !out.contains("AAAA") && !out.contains("BBBB") && !out.contains("CCCC"),
        "{out}"
    );
    assert!(out.contains("[REDACTED:pem_private_key:"), "{out}");
    // A buffer cut at one end alone does not run this guard.
    assert!(red(&format!("x\n{body}y\n"), HEAD).contains("AAAA"));
    assert!(red(&format!("x\n{body}y\n"), TAIL).contains("AAAA"));
}

#[test]
fn with_both_ends_cut_a_single_full_key_body_line_goes() {
    let one = format!("x\n{}\ny\n", "A".repeat(64));
    let out = red(&one, Cut::new(true, true));
    assert!(!out.contains("AAAA"), "{out}");
    assert!(out.contains("[REDACTED:pem_private_key:"), "{out}");
    // A line shorter than a key body line stays.
    let short = format!("x\n{}\ny\n", "A".repeat(39));
    assert!(red(&short, Cut::new(true, true)).contains("AAAA"));
}

#[test]
fn a_quoted_value_with_separators_across_either_window_edge_is_dropped_whole() {
    // The key rule matches the whole quoted value on the full text. The boundary must not land on the
    // space or `;` inside it and keep half.
    let value = "ab cd;ef gh,ij";
    let text = format!("password: \"{value}\"");
    for k in 1..text.len() {
        let out = red(&place(TOTAL, TAIL_EDGE - k, &text), TAIL);
        for part in ["ab", "cd", "ef", "gh", "ij"] {
            assert!(
                !out.contains(&format!("\"{part}")),
                "tail at {k}: {out:.60}"
            );
            assert!(
                !out.contains(&format!(" {part}\"")),
                "tail at {k}: {out:.60}"
            );
        }
        assert!(!out.contains("cd;ef"), "tail at {k}");
        let out = red(&place(TOTAL, HEAD_EDGE - k, &text), HEAD);
        assert!(
            !out.contains("ef gh") && !out.contains("gh,ij") && !out.contains("ij\""),
            "head at {k}"
        );
    }
}

/// URL userinfo may hold `;`, `&`, `,`, `'` and a space (RFC 3986 lets a password carry them). A
/// boundary at one of them would keep `svc:pa` and drop `ss@h`. The URL userinfo rule finds the whole
/// userinfo on the full text, and the boundary moves to its start or end.
#[test]
fn a_url_password_with_a_separator_across_either_window_edge_is_dropped_whole() {
    let url = "https://svc:pa;ss@h.example.test/";
    for k in 1..url.len() {
        let out = red(&place(TOTAL, TAIL_EDGE - k, url), TAIL);
        assert!(
            !out.contains("svc:pa") && !out.contains("pa;"),
            "tail at {k}: {out:.60}"
        );
        let out = red(&place(TOTAL, HEAD_EDGE - k, url), HEAD);
        assert!(!out.contains("ss@h"), "head at {k}: {out:.60}");
    }
}
