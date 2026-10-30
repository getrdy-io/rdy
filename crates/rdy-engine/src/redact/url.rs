//! URLs: the `url_userinfo` rule (04 Appendix B) and the evidence form of a URL (03 "Redaction in
//! evidence").
//!
//! The rule finds `scheme://user:pass@host`, `scheme://token@host` and the percent-encoded forms, and
//! removes the userinfo, so `http://[REDACTED:url_userinfo:1a2b3c4d]@proxy.acme.test:3128` keeps the host
//! a fix needs. [`evidence_url`] is what a check stores instead of a URL it was given.

use std::ops::Range;
use std::sync::LazyLock;

use regex::Regex;

use super::rules::is_single_placeholder;

/// The longest authority the rule reads, in bytes. A longer one is read up to this point, and the last
/// `@` in it ends the userinfo.
const MAX_AUTHORITY: usize = 16 * 1024;

/// A scheme and its `//`, also with JSON-escaped slashes (`http:\/\/`).
static SCHEME: LazyLock<Result<Regex, regex::Error>> =
    LazyLock::new(|| Regex::new(r"[A-Za-z][A-Za-z0-9+.\-]*:(?:\\?/){2}"));

/// Removes the userinfo of every URL in `text`.
///
/// The authority is the text after `://` up to the first `/`, `?`, `#`, quote, angle bracket, white
/// space, control character or backslash. The userinfo ends at the last `@` in it, so a password that
/// holds a raw `@` (or `;`, `&`, `,`, `'`) goes whole. A JSON-escaped `\u0040` counts as an `@`. A raw
/// `/`, `?` or `#` or a space in a password ends the authority early and leaves the rest in view: write
/// them as percent escapes, as the URL standard asks.
pub(super) fn find_url_userinfo(text: &str, out: &mut Vec<Range<usize>>) {
    // A scheme is followed by `:` and two slashes, either of which may carry a JSON backslash.
    if !text.contains(":/") && !text.contains(":\\/") {
        return;
    }
    let Ok(scheme) = SCHEME.as_ref() else {
        out.push(0..text.len());
        return;
    };
    let mut at = 0;
    while let Some(m) = scheme.find_at(text, at) {
        let (userinfo_end, scan_end) = authority(text, m.end());
        // Resume after the authority just read, so a long run of `a://a://` is read once.
        at = scan_end.max(m.end());
        let Some(end) = userinfo_end.filter(|&end| end > m.end()) else {
            continue;
        };
        let userinfo = &text[m.end()..end];
        if !is_single_placeholder(userinfo) {
            out.push(m.end()..end);
        }
    }
}

/// Reads the authority that starts at `from`. Returns where the userinfo ends (the last `@`) and where
/// the authority ends.
fn authority(text: &str, from: usize) -> (Option<usize>, usize) {
    let Some(rest) = text.get(from..) else {
        return (None, from);
    };
    let mut userinfo_end = None;
    let mut skip_until = 0;
    for (i, c) in rest.char_indices() {
        if i < skip_until {
            continue;
        }
        if i > MAX_AUTHORITY {
            return (userinfo_end, from + i);
        }
        match c {
            '@' => userinfo_end = Some(from + i),
            '\\' if rest[i..].starts_with("\\u0040") => {
                userinfo_end = Some(from + i);
                skip_until = i + "\\u0040".len();
            }
            c if c.is_whitespace()
                || c.is_control()
                || matches!(c, '/' | '?' | '#' | '"' | '<' | '>' | '`' | '\\') =>
            {
                return (userinfo_end, from + i);
            }
            _ => {}
        }
    }
    (userinfo_end, text.len())
}

/// A URL as a check stores it in evidence: `scheme://host:port/path`, with no userinfo, no query and no
/// fragment. A query carries tokens (a presigned URL), and the userinfo carries the password.
///
/// The userinfo ends at the last `@` of the whole text, because a password may hold a raw `/`, `?` or
/// `#`, and such a URL has no other safe reading. So a path with an `@` in it loses the part before the
/// `@`; write such a path without the `@` or store the host alone. The port and the path are kept as
/// written: a URL with no port gets none.
///
/// Returns `None` for text that is not a URL, and for one with a space or a control character, which
/// a URL cannot hold. A caller that gets `None` stores nothing (or a fixed word), never the original.
///
/// ```
/// use rdy_engine::redact::evidence_url;
///
/// assert_eq!(
///     evidence_url("https://svc:pw@dl.acme.test:8443/pkg/a.tgz?token=abc#top").as_deref(),
///     Some("https://dl.acme.test:8443/pkg/a.tgz"),
/// );
/// assert_eq!(evidence_url("not a url"), None);
/// ```
#[must_use]
pub fn evidence_url(url: &str) -> Option<String> {
    let url = url.trim();
    let (scheme, rest) = url.split_once("://")?;
    let mut chars = scheme.chars();
    let scheme_ok = chars.next().is_some_and(|c| c.is_ascii_alphabetic())
        && chars.all(|c| c.is_ascii_alphanumeric() || matches!(c, '+' | '.' | '-'));
    if !scheme_ok || rest.chars().any(|c| c.is_whitespace() || c.is_control()) {
        return None;
    }
    let after_userinfo = rest.rsplit_once('@').map_or(rest, |(_, after)| after);
    let without_query = after_userinfo.split(['?', '#']).next().unwrap_or_default();
    let (host_port, path) =
        without_query.split_at_checked(without_query.find('/').unwrap_or(without_query.len()))?;
    let host_ok = !host_port.is_empty()
        && host_port
            .chars()
            .all(|c| c.is_alphanumeric() || matches!(c, '.' | '-' | '_' | ':' | '[' | ']'));
    host_ok.then(|| format!("{scheme}://{host_port}{path}"))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn found(text: &str) -> Vec<&str> {
        let mut out = Vec::new();
        find_url_userinfo(text, &mut out);
        out.into_iter().map(|r| &text[r]).collect()
    }

    #[test]
    fn the_pattern_compiles() {
        assert!(SCHEME.is_ok());
    }

    #[test]
    fn the_userinfo_is_the_span_for_any_scheme() {
        for (text, want) in [
            ("http://svc:pa55@proxy.acme.test:3128", "svc:pa55"),
            (
                "postgres://app:s3cr3t@db.acme.test:5432/app?sslmode=require",
                "app:s3cr3t",
            ),
            ("https://TOKEN123@host.test/x", "TOKEN123"),
            ("ssh://git@host.test/org/repo", "git"),
            ("proxy=http://u%40x:p%3Ass@h:3128 next", "u%40x:p%3Ass"),
            ("(http://u:p@h)", "u:p"),
            ("'http://u:p@h'", "u:p"),
            ("\"url\":\"http://u:p@h/\"", "u:p"),
            (r"http:\/\/u:p@h\/x", "u:p"),
        ] {
            assert_eq!(found(text), [want], "{text}");
        }
    }

    #[test]
    fn a_password_with_separators_goes_whole() {
        assert_eq!(found("https://svc:pa;ss@h.test/"), ["svc:pa;ss"]);
        assert_eq!(found("https://svc:p&a,b'c@h.test/"), ["svc:p&a,b'c"]);
        // The last `@` ends the userinfo.
        assert_eq!(found("https://svc:p@ss@h.test/"), ["svc:p@ss"]);
        // A JSON-escaped at sign counts.
        assert_eq!(found(r"https://svc:pw\u0040h.test/"), ["svc:pw"]);
    }

    #[test]
    fn a_url_without_userinfo_is_left_alone() {
        for text in [
            "https://dl.acme.test/pkg?email=a@b.test",
            "https://registry.test/@scope/pkg",
            "https://h.test#frag@x",
            "mail a@b.test about https://h.test",
            "git@github.test:org/repo.git",
            "http://@h",
            "ftp:// x@y",
        ] {
            assert!(found(text).is_empty(), "{text}: {:?}", found(text));
        }
    }

    #[test]
    fn two_urls_in_one_line_are_two_spans() {
        assert_eq!(found("http://a:b@h1 and https://c:d@h2/x"), ["a:b", "c:d"]);
    }

    #[test]
    fn a_placeholder_userinfo_is_not_read_again() {
        let ph = "[REDACTED:url_userinfo:1a2b3c4d]";
        assert!(found(&format!("http://{ph}@proxy:3128")).is_empty());
        // More than the placeholder is taken whole.
        assert_eq!(found(&format!("http://{ph}x@proxy")), [format!("{ph}x")]);
    }

    #[test]
    fn a_long_run_of_schemes_costs_linear_time() {
        let text = "a://".repeat(100_000);
        let _ = found(&text);
        let text = "http://x@".repeat(100_000);
        assert!(!found(&text).is_empty());
        let text = format!("http://{}", "a".repeat(1_000_000));
        assert!(found(&text).is_empty());
    }

    #[test]
    fn the_evidence_form_has_scheme_host_port_and_path_only() {
        for (url, want) in [
            ("http://proxy.acme.test:3128", "http://proxy.acme.test:3128"),
            (
                "http://svc:pa55@proxy.acme.test:3128/",
                "http://proxy.acme.test:3128/",
            ),
            (
                "https://dl.acme.test/a/b.tgz?X-Amz-Signature=abc&token=t#frag",
                "https://dl.acme.test/a/b.tgz",
            ),
            ("https://tok@h.test", "https://h.test"),
            ("https://[::1]:8443/x", "https://[::1]:8443/x"),
            ("  https://h.test:1/p  ", "https://h.test:1/p"),
            // A raw slash in a password: everything up to the last `@` goes.
            ("https://u:pa/ss@h.test:9/p", "https://h.test:9/p"),
            ("https://u:pa?ss@h.test/p", "https://h.test/p"),
            ("https://h.test?x=1", "https://h.test"),
        ] {
            assert_eq!(evidence_url(url).as_deref(), Some(want), "{url}");
        }
    }

    #[test]
    fn text_that_is_not_a_url_gives_none() {
        for url in [
            "",
            "proxy.acme.test:3128",
            "://h",
            "1http://h",
            "ht tp://h",
            "https://",
            "https:///path",
            "https://h.test/a b",
            "https://h.test/a\nb",
            "https://ho\"st/",
        ] {
            assert_eq!(evidence_url(url), None, "{url:?}");
        }
    }

    #[test]
    fn an_evidence_url_holds_no_planted_secret() {
        let planted = "pa55w0rd-canary";
        let token = "tok-canary-9";
        let url = format!("https://svc:{planted}@h.test:8443/x?token={token}&a=1#{token}");
        let stored = evidence_url(&url).unwrap_or_default();
        assert!(
            !stored.contains(planted) && !stored.contains(token),
            "{stored}"
        );
    }
}
