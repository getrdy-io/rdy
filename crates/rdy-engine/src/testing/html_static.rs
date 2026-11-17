//! The static checks of ADR 0003 on an HTML report page, shared by every test that holds a golden page
//! (`report_goldens` in this crate and the env harness in `rdy`).

use std::error::Error;

use crate::report::read_report;

const OPEN: &str = "<script type=\"application/json\" id=\"rdy-result\" data-sha256=\"";

const CSP: &str = "<meta http-equiv=\"Content-Security-Policy\" content=\"default-src 'none'; \
                   style-src 'unsafe-inline'; img-src data:; base-uri 'none'; form-action 'none'\">";

fn sha256_hex(bytes: &[u8]) -> String {
    use std::fmt::Write as _;
    let digest = ring::digest::digest(&ring::digest::SHA256, bytes);
    digest.as_ref().iter().fold(String::new(), |mut out, byte| {
        let _ = write!(out, "{byte:02x}");
        out
    })
}

/// The `data-sha256` value and the text of the one result element.
fn embedded(html: &str) -> Result<(String, String), Box<dyn Error>> {
    let start = html.find(OPEN).ok_or("no result element")? + OPEN.len();
    let quote = html[start..]
        .find("\">")
        .ok_or("the attribute never ends")?;
    let hash = html[start..start + quote].to_owned();
    let text_start = start + quote + 2;
    let end = html[text_start..]
        .find("</script>")
        .ok_or("the element never ends")?;
    Ok((hash, html[text_start..text_start + end].to_owned()))
}

/// Whether `lower` (already lower-cased) has a `src` attribute: the word `src` that starts at a boundary
/// (not after a letter, digit, `-` or `_`) and is followed by `=` after any whitespace. Runs of tabs,
/// newlines, form feeds and spaces count as one space first, so `<img\n src\t=` is found.
fn has_src_attribute(lower: &str) -> bool {
    let mut text = String::with_capacity(lower.len());
    let mut space = false;
    for c in lower.chars() {
        if c.is_ascii_whitespace() {
            space = true;
        } else {
            if space {
                text.push(' ');
            }
            space = false;
            text.push(c);
        }
    }
    let text = text.replace(" =", "=");
    text.match_indices("src=").any(|(at, _)| {
        !text[..at]
            .chars()
            .next_back()
            .is_some_and(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_')
    })
}

/// The value of attribute `name` in the start tag text `tag`, if it has one.
fn attribute(tag: &str, name: &str) -> Option<String> {
    let needle = format!(" {name}=\"");
    let start = tag.find(&needle)? + needle.len();
    let end = tag[start..].find('"')?;
    Some(tag[start..start + end].to_owned())
}

/// The hrefs a page may hold besides `#id` links, written out in full. The footer links of 07 D.4 are
/// added here, exactly, when the page gets a footer. Until then the page links nowhere outside itself, and
/// a new off-file `href` fails every page check.
const OUTSIDE_HREFS: [&str; 0] = [];

/// The static checks of ADR 0003 on one HTML report page. `what` names the page in a failure. It panics on
/// a broken rule and returns an error when the page is not shaped as expected at all (no head, no data
/// block).
///
/// The page is lower-cased first, so `<LINK` and `URL(` count. The `<svg` ban below is for text from the
/// machine; ADR 0003's inline logo is not on the page yet, and when it lands this check names it.
pub fn assert_static_html(what: &str, html: &str) -> Result<(), Box<dyn Error>> {
    assert!(html.starts_with("<!DOCTYPE html>"), "{what}: no doctype");
    assert!(html.contains("<html lang=\"en\">"), "{what}: no lang=en");
    assert_eq!(html.matches(CSP).count(), 1, "{what}: the CSP is not exact");
    assert_eq!(
        html.matches("Content-Security-Policy").count(),
        1,
        "{what}: a second CSP"
    );
    let head_at = html.find("<head>").ok_or("no head")?;
    let csp_at = html.find(CSP).ok_or("no csp")?;
    let style_at = html.find("<style").ok_or("no style")?;
    let head_end = html.find("</head>").ok_or("no head end")?;
    assert!(
        head_at < csp_at && csp_at < style_at && style_at < head_end,
        "{what}: the CSP is not inside the head before the style"
    );
    let body_at = html.find("<body>").ok_or("no body")?;
    assert!(head_end < body_at, "{what}: the head ends after the body");

    let lower = html.to_ascii_lowercase();
    let (head, body) = lower.split_at(lower.find("<body>").ok_or("no body")?);
    for forbidden in [
        "<link",
        "<script",
        "@import",
        "url(",
        "srcset",
        "formaction",
        "<base",
        "<area",
        "xlink:href",
        "http://",
        "https://",
    ] {
        assert!(
            !head.contains(forbidden),
            "{what}: {forbidden:?} is in the head"
        );
    }
    for forbidden in [
        "<link",
        "srcset",
        "formaction",
        "<base",
        "<area",
        "xlink:href",
        "url(",
    ] {
        assert!(
            !body.contains(forbidden),
            "{what}: {forbidden:?} is in the body"
        );
    }
    assert!(!has_src_attribute(&lower), "{what}: a src attribute");
    // Text from the machine is escaped, so none of it opens a tag that loads or runs anything.
    for forbidden in [
        "<img",
        "<iframe",
        "<object",
        "<embed",
        "<form",
        "<svg",
        "javascript:",
        "http-equiv=\"refresh",
    ] {
        assert!(
            !lower.contains(forbidden),
            "{what}: {forbidden:?} is on the page"
        );
    }
    // Every anchor is `#id` or one of the exact outside links, which say `rel="noopener noreferrer"`.
    let mut rest = lower.as_str();
    while let Some(at) = rest.find("<a") {
        rest = &rest[at + 2..];
        match rest.chars().next() {
            Some(c) if c.is_ascii_whitespace() => {}
            Some(c) if c.is_ascii_alphanumeric() || c == '-' => continue,
            other => panic!("{what}: an anchor tag continues with {other:?}"),
        }
        let tag = format!(" {}", &rest[..rest.find('>').unwrap_or(rest.len())]);
        let tag = tag.replace(['\t', '\n', '\r', '\u{c}'], " ");
        let href = attribute(&tag, "href").ok_or("a link has no href")?;
        if !href.starts_with('#') {
            assert!(
                OUTSIDE_HREFS.contains(&href.as_str()),
                "{what}: an outside link that is not allowed: {href}"
            );
            assert_eq!(
                attribute(&tag, "rel").as_deref(),
                Some("noopener noreferrer"),
                "{what}: an outside link has no rel: {tag}"
            );
        }
    }
    // One script element, case blind, and it is the data block.
    assert_eq!(lower.matches("<script").count(), 1, "{what}: scripts");
    assert_eq!(lower.matches("</script").count(), 1, "{what}: script ends");
    assert!(html[body_at..].contains(OPEN), "{what}: no data block");
    let (hash, text) = embedded(html)?;
    assert_eq!(hash, sha256_hex(text.as_bytes()), "{what}: hash");
    assert!(
        !text.contains(['<', '>', '&', '\u{2028}', '\u{2029}']),
        "{what}: the data block is not escaped"
    );
    read_report(text.as_bytes())?;
    Ok(())
}
