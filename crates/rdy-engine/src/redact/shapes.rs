//! The rules that find a secret by its shape: private keys, AWS access key ids, rdy share tokens and
//! JWTs (04 Appendix B). None of them needs a key name next to the secret.
//!
//! Every rule reports byte ranges of the original text, like all rules. A shape cannot match inside a
//! placeholder (`[REDACTED:<rule>:<8 hex>]` has lower case letters, an underscore and hex only), so a
//! second pass finds nothing new.

use std::ops::Range;
use std::sync::LazyLock;

use regex::Regex;

/// The rule name of a private key block. The cut-buffer guard in `buffer` uses the same name.
pub(crate) const PEM_PRIVATE_KEY: &str = "pem_private_key";

const BEGIN: &str = "-----BEGIN ";
const DASHES: &str = "-----";

/// The most bytes read for the label of an armor line. A real label is a few words, so a longer one is
/// not read further. This keeps the work linear on text with many `-----BEGIN ` markers and no newline.
pub(super) const LABEL_WINDOW: usize = 128;

/// The text of an armor line from `rest` (the text after `-----BEGIN ` or `-----END `): up to the end of
/// the line, and never more than [`LABEL_WINDOW`] bytes.
pub(super) fn armor_line(rest: &str) -> &str {
    let window = rest
        .get(..rest.floor_char_boundary(LABEL_WINDOW))
        .unwrap_or(rest);
    window.split(['\n', '\r']).next().unwrap_or_default()
}

/// `(AKIA|ASIA|ABIA|ACCA)` and 16 characters of base32. There is no check on the character in front of
/// it, because a key id behind a JSON escape (`\nAKIA...`) has a letter in front of it.
static AWS_ACCESS_KEY_ID: LazyLock<Result<Regex, regex::Error>> =
    LazyLock::new(|| Regex::new(r"(?:AKIA|ASIA|ABIA|ACCA)[A-Z2-7]{16}"));

/// `rdy_st_` and 20 or more letters and digits. The token has no length cap, so a long one goes whole.
static RDY_SHARE_TOKEN: LazyLock<Result<Regex, regex::Error>> =
    LazyLock::new(|| Regex::new(r"rdy_st_[A-Za-z0-9]{20,}"));

/// Three base64url parts, the first of which starts `eyJ` (`{"`). The signature may be empty (`alg: none`).
static JWT: LazyLock<Result<Regex, regex::Error>> =
    LazyLock::new(|| Regex::new(r"eyJ[A-Za-z0-9_-]{2,}\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]*"));

/// Pushes every match of `pattern`. A pattern that failed to compile (a bug a unit test catches) removes
/// the whole text.
fn find_all(
    pattern: &LazyLock<Result<Regex, regex::Error>>,
    text: &str,
    out: &mut Vec<Range<usize>>,
) {
    match pattern.as_ref() {
        Ok(re) => out.extend(re.find_iter(text).map(|m| m.range())),
        Err(_) => out.push(0..text.len()),
    }
}

/// `AKIA...`, `ASIA...`, `ABIA...` and `ACCA...` followed by 16 characters.
pub(super) fn find_aws_access_key_id(text: &str, out: &mut Vec<Range<usize>>) {
    find_all(&AWS_ACCESS_KEY_ID, text, out);
}

/// `rdy_st_` tokens.
pub(super) fn find_rdy_share_token(text: &str, out: &mut Vec<Range<usize>>) {
    find_all(&RDY_SHARE_TOKEN, text, out);
}

/// JSON Web Tokens, such as a service account token in an error text.
pub(super) fn find_jwt(text: &str, out: &mut Vec<Range<usize>>) {
    find_all(&JWT, text, out);
}

/// A private key block: from `-----BEGIN <label>-----` through `-----END <label>-----`, where the label
/// holds `PRIVATE KEY` (`RSA PRIVATE KEY`, `ENCRYPTED PRIVATE KEY`, `OPENSSH PRIVATE KEY`, `PGP PRIVATE KEY
/// BLOCK`). Everything between is part of the block: the body, headers such as `Proc-Type: 4,ENCRYPTED`,
/// blank lines, a comment marker at the start of each line, and literal `\n` escapes. Nothing is decoded.
///
/// A block with no matching END line, or an END of another label, goes through the end of the text. A
/// certificate or a public key is not a private key and stays.
pub(super) fn find_pem_private_key(text: &str, out: &mut Vec<Range<usize>>) {
    let mut from = 0;
    while let Some(found) = text.get(from..).and_then(|t| t.find(BEGIN)) {
        let start = from + found;
        let label_start = start + BEGIN.len();
        let rest = text.get(label_start..).unwrap_or_default();
        // The label ends at the closing dashes, or at the end of the line (or of the window) when there
        // are none.
        let line = armor_line(rest);
        let label = line.split(DASHES).next().unwrap_or_default();
        if !label.contains("PRIVATE KEY") {
            from = label_start;
            continue;
        }
        let body_start = label_start + label.len();
        let end_line = format!("-----END {label}-----");
        match text.get(body_start..).and_then(|t| t.find(&end_line)) {
            Some(at) => {
                let end = body_start + at + end_line.len();
                out.push(start..end);
                from = end;
            }
            None => {
                out.push(start..text.len());
                return;
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn found(rule: fn(&str, &mut Vec<Range<usize>>), text: &str) -> Vec<&str> {
        let mut out = Vec::new();
        rule(text, &mut out);
        out.into_iter().map(|r| &text[r]).collect()
    }

    #[test]
    fn the_patterns_compile() {
        assert!(AWS_ACCESS_KEY_ID.is_ok());
        assert!(RDY_SHARE_TOKEN.is_ok());
        assert!(JWT.is_ok());
    }

    #[test]
    fn an_aws_key_id_is_found_in_any_text_and_behind_an_escape() {
        let id = "AKIAIOSFODNN7EXAMPLE";
        for prefix in ["AKIA", "ASIA", "ABIA", "ACCA"] {
            let key = format!("{prefix}IOSFODNN7EXAMPLE");
            let text = format!("id={key} and {key}.");
            assert_eq!(found(find_aws_access_key_id, &text), [key.as_str(); 2]);
        }
        assert_eq!(
            found(find_aws_access_key_id, &format!("line1\\n{id}")),
            [id]
        );
        // Lower case, a digit outside 2 to 7, and a short tail are not key ids.
        for text in [
            "akiaiosfodnn7example",
            "AKIAIOSFODNN1EXAMPLE",
            "AKIAIOSFODNN7EXAMPL",
            "AKID1234567890123456",
        ] {
            assert!(found(find_aws_access_key_id, text).is_empty(), "{text}");
        }
    }

    #[test]
    fn a_share_token_needs_twenty_characters() {
        let token = format!("rdy_st_{}", "a1B2".repeat(5));
        assert_eq!(
            found(find_rdy_share_token, &format!("share {token}.")),
            [token.as_str()]
        );
        assert!(found(find_rdy_share_token, "rdy_st_abc").is_empty());
        let long = format!("rdy_st_{}", "x".repeat(40_000));
        assert_eq!(found(find_rdy_share_token, &long), [long.as_str()]);
    }

    #[test]
    fn a_jwt_is_three_parts_and_may_have_no_signature() {
        let header = ["eyJh", "bGciOiJIUzI1NiJ9"].concat();
        let payload = ["eyJz", "dWIiOiJzeW50aGV0aWMifQ"].concat();
        let jwt = format!("{header}.{payload}.c2lnbmF0dXJl");
        assert_eq!(
            found(find_jwt, &format!("token \"{jwt}\" rejected")),
            [jwt.as_str()]
        );
        let unsigned = format!("{header}.{payload}.");
        assert_eq!(found(find_jwt, &unsigned), [unsigned.as_str()]);
        assert!(found(find_jwt, &format!("{header}.{payload}")).is_empty());
        assert!(found(find_jwt, "eyJ.a.b").is_empty());
        assert!(found(find_jwt, "version 1.2.3").is_empty());
    }

    const KEY: &str = "-----BEGIN PRIVATE KEY-----\nQUJDREVGR0hJSktM\n-----END PRIVATE KEY-----";

    #[test]
    fn a_private_key_block_is_found_whole_for_every_label() {
        for label in [
            "PRIVATE KEY",
            "RSA PRIVATE KEY",
            "EC PRIVATE KEY",
            "ENCRYPTED PRIVATE KEY",
            "OPENSSH PRIVATE KEY",
            "PGP PRIVATE KEY BLOCK",
        ] {
            let block = format!("-----BEGIN {label}-----\nQUJDREVGR0hJSktM\n-----END {label}-----");
            let text = format!("before\n{block}\nafter");
            assert_eq!(
                found(find_pem_private_key, &text),
                [block.as_str()],
                "{label}"
            );
        }
    }

    #[test]
    fn headers_blank_lines_comment_markers_and_escapes_are_inside_the_block() {
        let header = "-----BEGIN RSA PRIVATE KEY-----\\nProc-Type: 4,ENCRYPTED\\n\\nQUJD\\n-----END RSA PRIVATE KEY-----";
        assert_eq!(
            found(find_pem_private_key, &format!("{{\"k\":\"{header}\"}}")),
            [header]
        );
        let commented = "-----BEGIN PRIVATE KEY-----\n#   QUJDREVG\n# \n#   R0hJSktM\n# -----END PRIVATE KEY-----";
        let text = format!("# {commented}\n# next");
        let got = found(find_pem_private_key, &text);
        assert_eq!(got.len(), 1);
        assert!(got[0].ends_with("-----END PRIVATE KEY-----"));
        assert!(!got[0].contains("next"));
    }

    #[test]
    fn a_key_with_no_end_or_another_end_goes_to_the_end_of_the_text() {
        let open = "x -----BEGIN PRIVATE KEY-----\nQUJD\nmore text";
        assert_eq!(
            found(find_pem_private_key, open),
            ["-----BEGIN PRIVATE KEY-----\nQUJD\nmore text"]
        );
        let other = "-----BEGIN RSA PRIVATE KEY-----\nQUJD\n-----END PRIVATE KEY-----\ntail";
        assert_eq!(found(find_pem_private_key, other), [other]);
        // No closing dashes on the BEGIN line.
        let bare = "-----BEGIN PRIVATE KEY\nQUJD";
        assert_eq!(found(find_pem_private_key, bare), [bare]);
    }

    #[test]
    fn two_keys_are_two_spans_and_a_certificate_is_none() {
        let text = format!("{KEY}\nmid\n{KEY}");
        assert_eq!(found(find_pem_private_key, &text), [KEY, KEY]);
        let cert = "-----BEGIN CERTIFICATE-----\nQUJD\n-----END CERTIFICATE-----";
        assert!(found(find_pem_private_key, cert).is_empty());
        let public = "-----BEGIN PUBLIC KEY-----\nQUJD\n-----END PUBLIC KEY-----";
        assert!(found(find_pem_private_key, public).is_empty());
        // A certificate after a key is not taken with it.
        let both = format!("{KEY}\n{cert}");
        assert_eq!(found(find_pem_private_key, &both), [KEY]);
    }

    #[test]
    fn many_begin_markers_with_no_newline_cost_linear_time() {
        let text = "-----BEGIN CERTIFICATE----- ".repeat(40_000);
        assert!(text.len() > 1_000_000);
        let started = std::time::Instant::now();
        assert!(found(find_pem_private_key, &text).is_empty());
        assert!(started.elapsed() < std::time::Duration::from_secs(5));
        // A label that never closes is read as far as the window and no further.
        let text = "-----BEGIN X ".repeat(80_000);
        let started = std::time::Instant::now();
        assert!(found(find_pem_private_key, &text).is_empty());
        assert!(started.elapsed() < std::time::Duration::from_secs(5));
    }

    #[test]
    fn a_label_with_no_closing_dashes_is_read_to_the_window_and_still_removed() {
        let text = format!("-----BEGIN PRIVATE KEY {}", "QUJD".repeat(1000));
        assert_eq!(found(find_pem_private_key, &text), [text.as_str()]);
    }

    #[test]
    fn many_begin_lines_cost_linear_time() {
        let text = "-----BEGIN CERTIFICATE-----\n".repeat(50_000);
        assert!(found(find_pem_private_key, &text).is_empty());
        let text = "-----BEGIN PRIVATE KEY-----\n".repeat(50_000);
        assert_eq!(found(find_pem_private_key, &text).len(), 1);
    }
}
