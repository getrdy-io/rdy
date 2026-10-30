//! Header rules: `auth_header` and `api_key_header` (04 Appendix B).
//!
//! `Authorization:` and `Proxy-Authorization:` carry any scheme (`Bearer`, `Basic`, `Negotiate`, a vendor
//! scheme), and the span is the credential after the scheme. A bare `Bearer <token>` is found anywhere.
//! `X-Api-Key` and `X-Auth-Token` carry only a value, and the span is all of it.
//!
//! The reader knows three framings and parses no escapes:
//!
//! - a quoted value, `"Authorization": "Bearer x"` or `\"Bearer x\"`, runs to the next quote of that kind;
//! - a header inside a quoted word, `-H 'Authorization: Bearer x'`, runs to the closing quote;
//! - anything else runs to the end of the line, or to a backslash (a literal `\r\n` in a log line).
//!
//! A plain word as the whole value (`authorization: true`, `null`) and a reference (`${TOKEN}`) are left
//! alone, as in the key rule.
//!
//! The key-name rule also reads these headers (`auth` is a stem), so a value it takes is the larger span
//! and the placeholder carries the name of the higher priority rule, `auth_header`.

use std::ops::Range;

use super::rules::is_exempt_value;

/// Header names, lower case. A name matches without regard to case, as headers do. `Proxy-Authorization`
/// is the `authorization` name with a `proxy-` or `proxy_` in front.
const AUTHORIZATION: &str = "authorization";
const API_KEY_NAMES: [&str; 4] = ["x-api-key", "x_api_key", "x-auth-token", "x_auth_token"];

/// Words that follow `Bearer` in prose and are not credentials.
const PROSE_WORDS: &[&str] = &[
    "authentication",
    "authenticator",
    "authorization",
    "credentials",
    "tokens",
];

/// The fewest token characters after `Bearer` that count as a credential.
const BEARER_MIN: usize = 8;

/// `Authorization:` and `Proxy-Authorization:` values, and a bare `Bearer <token>`.
pub(super) fn find_auth_header(text: &str, out: &mut Vec<Range<usize>>) {
    scan_headers(text, true, out);
    find_bearer(text, out);
}

/// `X-Api-Key` and `X-Auth-Token` values.
pub(super) fn find_api_key_header(text: &str, out: &mut Vec<Range<usize>>) {
    scan_headers(text, false, out);
}

/// A byte that can be part of a bearer token: base64, base64url, hex and the punctuation of JWTs.
fn is_token_byte(b: u8) -> bool {
    b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b'~' | b'+' | b'/' | b'=' | b'-')
}

/// `Bearer <token>` anywhere: the word on its own (not the end of another word), blanks, then at least
/// [`BEARER_MIN`] token characters. The scan is a plain byte loop, because a case-insensitive regex over
/// every byte of a large buffer costs ten times as much.
fn find_bearer(text: &str, out: &mut Vec<Range<usize>>) {
    let bytes = text.as_bytes();
    let mut i = 0;
    while let Some(found) = bytes
        .get(i..)
        .and_then(|rest| rest.iter().position(|&b| b | 0x20 == b'b'))
    {
        i += found;
        let is_word = bytes
            .get(i..i + 6)
            .is_some_and(|w| w.eq_ignore_ascii_case(b"bearer"));
        let word_start = i == 0 || !(bytes[i - 1].is_ascii_alphanumeric() || bytes[i - 1] == b'_');
        if !(is_word && word_start) {
            i += 1;
            continue;
        }
        let mut j = i + 6;
        let blanks = j;
        while bytes.get(j).is_some_and(|b| matches!(b, b' ' | b'\t')) {
            j += 1;
        }
        let token_start = j;
        if j > blanks {
            while bytes.get(j).copied().is_some_and(is_token_byte) {
                j += 1;
            }
            let token = &text[token_start..j];
            let prose = PROSE_WORDS.iter().any(|w| token.eq_ignore_ascii_case(w));
            if token.len() >= BEARER_MIN && !prose {
                out.push(token_start..j);
            }
        }
        i = j.max(i + 1);
    }
}

/// A header name found before a separator: where it starts, and whether a closing quote followed it.
struct Name {
    start: usize,
    authorization: bool,
    closed_by_quote: bool,
}

/// Looks backwards from the separator at `sep` for a header name: blanks, an optional closing quote
/// (with backslashes in front of it), then the name.
fn name_before(text: &str, sep: usize) -> Option<Name> {
    let bytes = text.as_bytes();
    let mut end = sep;
    while end > 0 && matches!(bytes[end - 1], b' ' | b'\t') {
        end -= 1;
    }
    let mut closed_by_quote = false;
    if end > 0 && matches!(bytes[end - 1], b'"' | b'\'') {
        closed_by_quote = true;
        end -= 1;
        while end > 0 && bytes[end - 1] == b'\\' {
            end -= 1;
        }
    }
    let ends_with = |name: &str| {
        end.checked_sub(name.len())
            .filter(|&start| bytes[start..end].eq_ignore_ascii_case(name.as_bytes()))
    };
    if let Some(start) = ends_with(AUTHORIZATION) {
        // `Proxy-Authorization` is one header: the prefix belongs to the name.
        let start = start
            .checked_sub(6)
            .filter(|&p| {
                bytes[p..start - 1].eq_ignore_ascii_case(b"proxy")
                    && matches!(bytes[start - 1], b'-' | b'_')
            })
            .map_or(start, |_| start - 6);
        return Some(Name {
            start,
            authorization: true,
            closed_by_quote,
        });
    }
    API_KEY_NAMES.iter().find_map(|name| {
        ends_with(name).map(|start| Name {
            start,
            authorization: false,
            closed_by_quote,
        })
    })
}

/// Reads every `name: value` and `name=value` whose name is a header of the family asked for.
fn scan_headers(text: &str, authorization: bool, out: &mut Vec<Range<usize>>) {
    let bytes = text.as_bytes();
    // A value already read is not read again, so `Authorization: Authorization: x` stays linear.
    let mut covered_until = 0;
    let mut pos = 0;
    while let Some(found) = bytes
        .get(pos..)
        .and_then(|rest| rest.iter().position(|&b| b == b':' || b == b'='))
    {
        let sep = pos + found;
        pos = sep + 1;
        let Some(name) = name_before(text, sep) else {
            continue;
        };
        if name.authorization != authorization || name.start < covered_until {
            continue;
        }
        let mut from = sep + 1;
        while bytes.get(from).is_some_and(|b| matches!(b, b' ' | b'\t')) {
            from += 1;
        }
        // A quote right before the name that the name does not close is the quote of a word that holds
        // the whole header: `-H 'Authorization: Bearer x'`.
        let word_quote = if name.closed_by_quote {
            None
        } else {
            text.get(..name.start)
                .and_then(|before| before.chars().next_back())
                .filter(|c| matches!(c, '"' | '\''))
        };
        let Some(region) = value_region(text, from, word_quote) else {
            continue;
        };
        covered_until = covered_until.max(region.end);
        let value = &text[region.clone()];
        let credential = if authorization {
            // The scheme stays: `Authorization: Basic <credential>`. One word is all credential.
            value
                .find(char::is_whitespace)
                .map_or(0, |i| i + value[i..].len() - value[i..].trim_start().len())
        } else {
            0
        };
        let span = region.start + credential..region.end;
        let credential_text = &text[span.clone()];
        if span.is_empty() || is_exempt_value(credential_text) {
            continue;
        }
        out.push(span);
    }
}

/// Where the value of a header is, after its separator.
fn value_region(text: &str, from: usize, word_quote: Option<char>) -> Option<Range<usize>> {
    let rest = text.get(from..)?;
    // The value opens with an optional run of backslashes and a quote: `"x"` or `\"x\"`.
    let slashes = rest.len() - rest.trim_start_matches('\\').len();
    let opener = rest
        .get(slashes..)
        .and_then(|r| r.chars().next())
        .filter(|c| matches!(c, '"' | '\''));
    let (start, end) = match opener {
        Some(quote) => {
            let start = from + slashes + 1;
            let body = text.get(start..)?;
            let end = body
                .find(|c| c == quote || is_line_end(c))
                .map_or(text.len(), |i| start + i);
            (start, end)
        }
        None => {
            let end = rest
                .find(|c| is_line_end(c) || c == '\\' || Some(c) == word_quote)
                .map_or(text.len(), |i| from + i);
            (from, end)
        }
    };
    let value = text.get(start..end)?;
    // Backslashes in front of a closing escaped quote are not part of the value.
    let value = value.trim_end_matches([' ', '\t', '\\']);
    let value_start = start + (text[start..end].len() - text[start..end].trim_start().len());
    let region = value_start..start + value.len();
    (region.start < region.end).then_some(region)
}

fn is_line_end(c: char) -> bool {
    matches!(c, '\n' | '\r' | '\u{85}' | '\u{2028}' | '\u{2029}')
}

#[cfg(test)]
mod tests {
    use super::*;

    fn auth(text: &str) -> Vec<&str> {
        let mut out = Vec::new();
        find_auth_header(text, &mut out);
        // A header with a bearer token is found by both readers. The engine merges equal spans.
        out.sort_by_key(|r| (r.start, r.end));
        out.dedup();
        out.into_iter().map(|r| &text[r]).collect()
    }

    fn api(text: &str) -> Vec<&str> {
        let mut out = Vec::new();
        find_api_key_header(text, &mut out);
        out.into_iter().map(|r| &text[r]).collect()
    }

    #[test]
    fn the_credential_after_any_scheme_is_the_span() {
        assert_eq!(auth("Authorization: Bearer abc123xyz"), ["abc123xyz"]);
        assert_eq!(
            auth("authorization: Basic dXNlcjpwYXNz\nHost: x"),
            ["dXNlcjpwYXNz"]
        );
        assert_eq!(
            auth("Proxy-Authorization: Basic dXNlcjpwYXNz"),
            ["dXNlcjpwYXNz"]
        );
        assert_eq!(auth("Authorization: Negotiate YIIabc=="), ["YIIabc=="]);
        assert_eq!(
            auth("Authorization: Digest username=\"a\", response=\"b\""),
            ["username=\"a\", response=\"b\""]
        );
        // One word is all credential.
        assert_eq!(auth("Authorization: abc123xyz"), ["abc123xyz"]);
        assert_eq!(auth("HTTP_AUTHORIZATION=Bearer abc123xyz"), ["abc123xyz"]);
    }

    #[test]
    fn a_header_in_a_quoted_word_stops_at_the_quote() {
        assert_eq!(
            auth("curl -H 'Authorization: Bearer abc123xyz' https://h.example.test/"),
            ["abc123xyz"]
        );
        assert_eq!(
            auth("curl -H \"Proxy-Authorization: Basic dXNlcjpwYXNz\" -v"),
            ["dXNlcjpwYXNz"]
        );
    }

    #[test]
    fn a_json_header_is_read_inside_its_quotes() {
        assert_eq!(
            auth(r#"{"Authorization": "Bearer abc123xyz", "Host": "h"}"#),
            ["abc123xyz"]
        );
        assert_eq!(
            auth(r#"{\"Authorization\":\"Bearer abc123xyz\",\"Host\":\"h\"}"#),
            ["abc123xyz"]
        );
        assert_eq!(auth(r#"{"authorization":"abc123xyz"}"#), ["abc123xyz"]);
    }

    #[test]
    fn a_literal_line_break_ends_a_bare_value() {
        assert_eq!(
            auth(r"GET / HTTP/1.1\r\nAuthorization: Bearer abc123xyz\r\nHost: h"),
            ["abc123xyz"]
        );
        assert_eq!(
            auth("Authorization: Bearer abc123xyz\r\nHost: h"),
            ["abc123xyz"]
        );
    }

    #[test]
    fn a_bare_bearer_token_is_found_anywhere() {
        assert_eq!(auth("got bearer abc123xyz from the proxy"), ["abc123xyz"]);
        assert_eq!(auth("token: Bearer eyJabc.def.ghi"), ["eyJabc.def.ghi"]);
        // Prose and short words are not credentials.
        for text in [
            "Bearer authentication failed",
            "Bearer credentials were rejected",
            "bearer tokens expire",
            "Bearer short",
            "the bearer",
        ] {
            assert!(auth(text).is_empty(), "{text}");
        }
    }

    #[test]
    fn empty_values_and_other_headers_are_left_alone() {
        for text in [
            "Authorization:",
            "authorization: \nnext: 1",
            "WWW-Authenticate: Bearer realm=\"x\"",
            "Accept: */*",
        ] {
            assert!(auth(text).is_empty(), "{text}: {:?}", auth(text));
        }
        assert!(api("X-Api-Key:").is_empty());
    }

    #[test]
    fn a_placeholder_is_not_read_again() {
        let ph = "[REDACTED:auth_header:1a2b3c4d]";
        assert!(auth(&format!("Authorization: Bearer {ph}")).is_empty());
        assert!(auth(&format!("Authorization: {ph}")).is_empty());
        assert!(auth(&format!("-H 'Proxy-Authorization: Basic {ph}'")).is_empty());
        // More than the placeholder is still taken.
        assert_eq!(
            auth(&format!("Authorization: Bearer {ph}x")),
            [format!("{ph}x")]
        );
    }

    #[test]
    fn api_key_headers_take_the_whole_value() {
        assert_eq!(api("X-Api-Key: abc123xyz"), ["abc123xyz"]);
        assert_eq!(api("x-auth-token: abc123xyz\nnext"), ["abc123xyz"]);
        assert_eq!(api("X_API_KEY=abc 123"), ["abc 123"]);
        assert_eq!(api(r#"{"X-Api-Key":"abc123xyz"}"#), ["abc123xyz"]);
        assert!(auth("X-Api-Key: abc123xyz").is_empty());
    }

    #[test]
    fn repeated_names_cost_linear_time() {
        let text = "Authorization: ".repeat(100_000);
        let _ = auth(&text);
        let text = "authorization=".repeat(100_000);
        let _ = auth(&text);
    }
}
