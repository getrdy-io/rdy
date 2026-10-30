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
/// holds a raw `@` (or `;`, `&`, `,`, `'`) goes whole. A JSON-escaped `\u0040` counts as an `@`.
///
/// A raw `/`, `?` or `#` in a password ends the authority with no `@` in it. When what came before is
/// `user:x` (a name, a colon and something that is not a port), and an `@` follows before the next white
/// space, quote or backslash, the userinfo runs to the last such `@`: `postgres://app:K7x/9+Qa@db/app`.
/// A space in a password is not read: write it as a percent escape, as the URL standard asks.
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
    // No `@` sits between a scheme and this offset, so a later scheme before it needs no second look.
    let mut no_at_before = 0;
    while let Some(m) = scheme.find_at(text, at) {
        let (mut userinfo_end, scan_end) = authority(text, m.end());
        // Resume after the authority just read, so a long run of `a://a://` is read once.
        at = scan_end.max(m.end());
        if userinfo_end.is_none() && scan_end >= no_at_before {
            let (found, scanned_to) = raw_delimiter_password(text, m.end(), scan_end);
            userinfo_end = found;
            no_at_before = scanned_to;
            if let Some(end) = found {
                at = end;
            }
        }
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

/// A password with a raw `/`, `?` or `#`: the authority from `start` to `end` has no `@` and stops at one
/// of those characters. Returns where the userinfo ends (the last `@` before white space, a quote or a
/// backslash) and how far the search went.
///
/// The authority must be `user:x`, with `x` not all digits, so `host:8443/path@x` is a host and a port.
/// The scan stops at the first character that cannot be in a URL, so the work stays linear.
fn raw_delimiter_password(text: &str, start: usize, end: usize) -> (Option<usize>, usize) {
    let Some(authority) = text.get(start..end) else {
        return (None, end);
    };
    let delimiter = text.get(end..).and_then(|t| t.chars().next());
    let Some((user, password)) = authority.split_once(':') else {
        return (None, end);
    };
    let is_userinfo = matches!(delimiter, Some('/' | '?' | '#'))
        && !user.is_empty()
        && !user.starts_with('[')
        && !password.is_empty()
        && !password.bytes().all(|b| b.is_ascii_digit());
    if !is_userinfo {
        return (None, end);
    }
    let mut last_at = None;
    let mut scanned_to = text.len();
    for (i, c) in text[end..].char_indices() {
        if c.is_whitespace() || c.is_control() || matches!(c, '"' | '\'' | '`' | '<' | '>' | '\\') {
            scanned_to = end + i;
            break;
        }
        if c == '@' {
            last_at = Some(end + i);
        }
    }
    (last_at, scanned_to)
}

/// A URL as a check stores it in evidence: `scheme://host:port/path`, with no userinfo, no query and no
/// fragment. A query carries tokens (a presigned URL), and the userinfo carries the password.
///
/// The userinfo is the part of the authority before its last `@`. An `@` after the first `/`, `?` or `#`
/// has no safe reading (a password with a raw `/`, or a path, a query or an image digest that holds an
/// `@`), so such a URL gives `None`. The port and the path are kept as written: a URL with no port gets
/// none.
///
/// Returns `None` for text that is not a URL, for one with a space or a control character, which a URL
/// cannot hold, and for one with an `@` after its authority. A caller that gets `None` stores nothing (or
/// a fixed word), never the original.
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
    let (authority, tail) = rest.split_at(rest.find(['/', '?', '#']).unwrap_or(rest.len()));
    if tail.contains('@') {
        return None;
    }
    let host_port = authority
        .rsplit_once('@')
        .map_or(authority, |(_, after)| after);
    let path = tail.split(['?', '#']).next().unwrap_or_default();
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
            ("https://u:p@a@h.test/p", "https://h.test/p"),
            ("https://h.test?x=1", "https://h.test"),
        ] {
            assert_eq!(evidence_url(url).as_deref(), Some(want), "{url}");
        }
    }

    #[test]
    fn an_at_sign_after_the_authority_gives_none() {
        for url in [
            // A raw slash, question mark or hash in a password.
            "https://u:pa/ss@h.test:9/p",
            "https://u:pa?ss@h.test/p",
            "https://u:pa#ss@h.test/p",
            // A query, an image digest and a scoped package path.
            "https://dl.acme.test/pkg?email=a@b.test",
            "docker://reg.test/app@sha256:0123456789abcdef",
            "https://registry.test/@scope/pkg",
            "https://h.test/v1?k=svc@Zk3v9TokenAbc",
            "https://h.test#frag@x",
            "https://u:p@h.test/a@b",
        ] {
            assert_eq!(evidence_url(url), None, "{url:?}");
        }
    }

    #[test]
    fn a_raw_delimiter_in_a_password_goes_to_the_last_at_sign() {
        for (text, want) in [
            (
                "DATABASE_URL=postgres://app:K7x/9+Qa@db:5432/app",
                "app:K7x/9+Qa",
            ),
            ("https://u:pa?ss@h.test/p", "u:pa?ss"),
            ("https://u:pa#ss@h.test/p", "u:pa#ss"),
            ("(https://u:a/b@c@h.test/p)", "u:a/b@c"),
            ("\"u\":\"https://u:a/b@h.test/p\"", "u:a/b"),
        ] {
            assert_eq!(found(text), [want], "{text}");
        }
        // Not userinfo: a port, a name with no colon, an IPv6 host, no `@` before the space or quote.
        for text in [
            "https://h.test:8443/pkg/@scope/x",
            "https://h.test/pkg@x",
            "https://[::1]/x@y",
            "https://u:pa/ss and a@b.test",
            "'https://u:pa/ss' a@b.test",
            "https://u:/x@h",
        ] {
            assert!(found(text).is_empty(), "{text}: {:?}", found(text));
        }
    }

    #[test]
    fn many_raw_delimiter_urls_cost_linear_time() {
        let text = "a://u:x/".repeat(100_000);
        assert!(found(&text).is_empty());
        let text = "a://u:x/@".repeat(100_000);
        assert!(!found(&text).is_empty());
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
