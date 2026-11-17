//! The structure test of the HTML report (M1-082, 07 D.4): over the three goldens of 07 Appendix B
//! (`results-b1-ready`, `results-b2-ready-with-warnings`, `results-b3-not-ready`) heading levels never
//! skip, `lang` is set, every `h3` starts with a status word, every `th` has a `scope`, ids are unique, every
//! `href="#id"` has a target, and the only other `href` or `src` values are `data:`, the footer link and the
//! repo link.
//!
//! No HTML parser is in the dependency tree, and adding one (html5ever and its tree) is not worth it for
//! pages rdy writes itself. `tokens` below is a small tokenizer for that markup, like the stand in of
//! `html_report.rs`. It skips `<script>` and `<style>` bodies, reads quoted attributes and keeps the text
//! between tags. M1-141 adds its bdi and bidi checks on top of `tokens`, `Token`, `opens` and `text_of`,
//! with one `*_problems` function per rule and `each_golden` to run it.

use std::collections::BTreeSet;
use std::error::Error;
use std::path::PathBuf;

use rdy_engine::testing::fixtures_dir;

type TestResult<T = ()> = Result<T, Box<dyn Error>>;

/// The file stems of the three goldens (07 Appendix B.1 to B.3).
const GOLDENS: [&str; 3] = [
    "results-b1-ready",
    "results-b2-ready-with-warnings",
    "results-b3-not-ready",
];

/// The words an `h3` may start with (the check statuses, in the page's words).
const STATUS_WORDS: [&str; 7] = ["PASS", "WARN", "BLOCK", "SKIP", "TIMEOUT", "ERROR", "INFO"];

/// The start of the footer link (07 D.4): the product follows `product=`.
const FOOTER_LINK: &str = "https://getrdy.io/?ref=report&product=";

/// The repo link of the footer.
const REPO_LINK: &str = "https://github.com/getrdy-io/rdy";

/// One piece of a page.
#[derive(Debug, Clone, PartialEq, Eq)]
enum Token {
    /// `<name attr="value">`. Names are lower case. Values are kept as written.
    Open {
        name: String,
        attrs: Vec<(String, String)>,
    },
    /// `</name>`.
    Close(String),
    /// Text between tags, as written (entities are not decoded).
    Text(String),
}

fn golden_html(stem: &str) -> TestResult<String> {
    let path: PathBuf = fixtures_dir().join(format!("reports/golden/{stem}.html"));
    Ok(std::fs::read_to_string(path)?)
}

/// The tokens of `html`. Comments and the doctype are dropped, and so is the body of `script` and `style`.
fn tokens(html: &str) -> TestResult<Vec<Token>> {
    let mut out = Vec::new();
    let mut rest = html;
    while !rest.is_empty() {
        let Some(lt) = rest.find('<') else {
            out.push(Token::Text(rest.to_owned()));
            break;
        };
        if lt > 0 {
            out.push(Token::Text(rest[..lt].to_owned()));
        }
        rest = &rest[lt..];
        if let Some(after) = rest.strip_prefix("<!--") {
            let end = after.find("-->").ok_or("a comment never ends")?;
            rest = &after[end + 3..];
            continue;
        }
        let end = tag_end(rest).ok_or("a tag never ends")?;
        let inner = &rest[1..end - 1];
        rest = &rest[end..];
        if inner.starts_with('!') {
            continue;
        }
        if let Some(name) = inner.strip_prefix('/') {
            out.push(Token::Close(name.trim().to_ascii_lowercase()));
            continue;
        }
        let (name, attrs) = parse_tag(inner);
        let raw = name == "script" || name == "style";
        out.push(Token::Open {
            name: name.clone(),
            attrs,
        });
        if raw {
            let close = format!("</{name}>");
            let at = rest
                .find(&close)
                .ok_or_else(|| format!("{name} never ends"))?;
            rest = &rest[at..];
        }
    }
    Ok(out)
}

/// The length of the tag that starts `text`, counting a quoted `>` as text.
fn tag_end(text: &str) -> Option<usize> {
    let mut quote = None;
    for (at, c) in text.char_indices() {
        match (quote, c) {
            (None, '"' | '\'') => quote = Some(c),
            (Some(q), c) if c == q => quote = None,
            (None, '>') => return Some(at + 1),
            _ => {}
        }
    }
    None
}

/// The name and the attributes of the tag whose text between `<` and `>` is `inner`.
fn parse_tag(inner: &str) -> (String, Vec<(String, String)>) {
    let inner = inner.trim_end_matches('/');
    let name_end = inner
        .find(|c: char| c.is_ascii_whitespace())
        .unwrap_or(inner.len());
    let name = inner[..name_end].to_ascii_lowercase();
    let mut attrs = Vec::new();
    let mut rest = inner[name_end..].trim_start();
    while !rest.is_empty() {
        let key_end = rest
            .find(|c: char| c == '=' || c.is_ascii_whitespace())
            .unwrap_or(rest.len());
        let key = rest[..key_end].to_ascii_lowercase();
        rest = rest[key_end..].trim_start();
        let mut value = String::new();
        if let Some(after) = rest.strip_prefix('=') {
            let after = after.trim_start();
            if let Some(q) = after.chars().next().filter(|c| *c == '"' || *c == '\'') {
                let body = &after[1..];
                let close = body.find(q).unwrap_or(body.len());
                value = body[..close].to_owned();
                rest = body[(close + 1).min(body.len())..].trim_start();
            } else {
                let close = after
                    .find(|c: char| c.is_ascii_whitespace())
                    .unwrap_or(after.len());
                value = after[..close].to_owned();
                rest = after[close..].trim_start();
            }
        }
        attrs.push((key, value));
    }
    (name, attrs)
}

/// The value of attribute `name` in an open tag's attributes.
fn attr<'a>(attrs: &'a [(String, String)], name: &str) -> Option<&'a str> {
    attrs
        .iter()
        .find(|(key, _)| key == name)
        .map(|(_, value)| value.as_str())
}

/// The text of the element that opens at `tokens[open]`, tags left out, up to its matching close tag.
fn text_of(tokens: &[Token], open: usize) -> String {
    let Some(Token::Open { name, .. }) = tokens.get(open) else {
        return String::new();
    };
    let mut depth = 0usize;
    let mut text = String::new();
    for token in &tokens[open..] {
        match token {
            Token::Open { name: n, .. } if n == name => depth += 1,
            Token::Close(n) if n == name => {
                depth = depth.saturating_sub(1);
                if depth == 0 {
                    break;
                }
            }
            Token::Text(t) => text.push_str(t),
            _ => {}
        }
    }
    text
}

/// The `&#38;` and `&amp;` of an attribute value, as `&`.
fn decode_amp(value: &str) -> String {
    value.replace("&#38;", "&").replace("&amp;", "&")
}

/// Every open tag as `(index, name, attrs)`.
fn opens(tokens: &[Token]) -> impl Iterator<Item = (usize, &str, &[(String, String)])> {
    tokens.iter().enumerate().filter_map(|(i, t)| match t {
        Token::Open { name, attrs } => Some((i, name.as_str(), attrs.as_slice())),
        _ => None,
    })
}

/// The problems with heading levels: one `h1`, and no level more than one below the one before.
fn heading_problems(tokens: &[Token]) -> Vec<String> {
    let mut problems = Vec::new();
    let mut last = 0u8;
    let mut h1s = 0;
    for (_, name, _) in opens(tokens) {
        let level = match name.as_bytes() {
            [b'h', d @ b'1'..=b'6'] => d - b'0',
            _ => continue,
        };
        if level == 1 {
            h1s += 1;
        }
        if level > last + 1 {
            problems.push(format!("h{level} follows h{last}"));
        }
        last = level;
    }
    if h1s != 1 {
        problems.push(format!("{h1s} h1 elements, want 1"));
    }
    problems
}

/// The problems with `h3` status words: each `h3` must start with one inside a `status` span.
fn status_problems(tokens: &[Token]) -> Vec<String> {
    let mut problems = Vec::new();
    for (i, name, _) in opens(tokens) {
        if name != "h3" {
            continue;
        }
        let text = text_of(tokens, i);
        let first = text.split_whitespace().next().unwrap_or("");
        if !STATUS_WORDS.contains(&first) {
            problems.push(format!("h3 {text:?} has no status word"));
        }
        let in_span = matches!(
            tokens.get(i + 1),
            Some(Token::Open { name, attrs })
                if name == "span" && attr(attrs, "class") == Some("status")
        );
        if !in_span {
            problems.push(format!("h3 {text:?} does not start with a status span"));
        }
    }
    problems
}

/// The problems with tables: each has a `th`, and each `th` has `scope` `col` or `row`.
fn table_problems(tokens: &[Token]) -> Vec<String> {
    let mut problems = Vec::new();
    let mut tables = 0;
    let mut ths = 0;
    for (_, name, attrs) in opens(tokens) {
        match name {
            "table" => tables += 1,
            "th" => {
                ths += 1;
                match attr(attrs, "scope") {
                    Some("col" | "row") => {}
                    other => problems.push(format!("th with scope {other:?}")),
                }
            }
            _ => {}
        }
    }
    if tables > 0 && ths == 0 {
        problems.push("a table has no th".to_owned());
    }
    problems
}

/// The problems with ids and in-page links: no id twice, and each `href="#id"` has a target.
fn id_problems(tokens: &[Token]) -> Vec<String> {
    let mut problems = Vec::new();
    let mut ids = BTreeSet::new();
    for (_, _, attrs) in opens(tokens) {
        if let Some(id) = attr(attrs, "id")
            && !ids.insert(id)
        {
            problems.push(format!("the id {id:?} is used twice"));
        }
    }
    for (_, _, attrs) in opens(tokens) {
        if let Some(target) = attr(attrs, "href").and_then(|h| h.strip_prefix('#'))
            && !ids.contains(target)
        {
            problems.push(format!("href=\"#{target}\" has no target"));
        }
    }
    problems
}

/// The problems with `href` and `src`: only `#id`, the footer link and the repo link for `href`, and only
/// `data:` for `src`.
fn link_problems(tokens: &[Token]) -> Vec<String> {
    let mut problems = Vec::new();
    for (_, name, attrs) in opens(tokens) {
        if let Some(href) = attr(attrs, "href") {
            let href = decode_amp(href);
            let product = href.strip_prefix(FOOTER_LINK);
            let ok = href.starts_with('#')
                || href == REPO_LINK
                || product.is_some_and(|p| !p.is_empty() && !p.contains(['&', '?']));
            if !ok {
                problems.push(format!("<{name}> href {href:?} is not allowed"));
            }
        }
        if let Some(src) = attr(attrs, "src")
            && !src.starts_with("data:")
        {
            problems.push(format!("<{name}> src {src:?} is not data:"));
        }
    }
    problems
}

/// The problems with the page itself: `lang` on `html` and the four landmarks of D.4.
fn page_problems(tokens: &[Token]) -> Vec<String> {
    let mut problems = Vec::new();
    let lang = opens(tokens)
        .find(|(_, name, _)| *name == "html")
        .and_then(|(_, _, attrs)| attr(attrs, "lang"));
    if lang.is_none_or(str::is_empty) {
        problems.push("html has no lang".to_owned());
    }
    for landmark in ["header", "nav", "main", "footer"] {
        let n = opens(tokens)
            .filter(|(_, name, _)| *name == landmark)
            .count();
        if n != 1 {
            problems.push(format!("{n} {landmark} landmarks, want 1"));
        }
    }
    let nav_label = opens(tokens)
        .find(|(_, name, _)| *name == "nav")
        .and_then(|(_, _, attrs)| attr(attrs, "aria-label"));
    if nav_label != Some("Sections") {
        problems.push(format!("nav aria-label is {nav_label:?}"));
    }
    problems
}

/// Runs `check` over each golden and fails with every problem, named by golden.
fn each_golden(check: fn(&[Token]) -> Vec<String>) -> TestResult {
    let mut all = Vec::new();
    for stem in GOLDENS {
        let tokens = tokens(&golden_html(stem)?)?;
        all.extend(check(&tokens).into_iter().map(|p| format!("{stem}: {p}")));
    }
    assert_eq!(all, Vec::<String>::new());
    Ok(())
}

#[test]
fn heading_levels_never_skip() -> TestResult {
    each_golden(heading_problems)
}

#[test]
fn lang_is_set_and_the_landmarks_are_there() -> TestResult {
    each_golden(page_problems)
}

#[test]
fn every_h3_starts_with_a_status_word() -> TestResult {
    each_golden(status_problems)
}

#[test]
fn every_th_has_a_scope() -> TestResult {
    each_golden(table_problems)
}

#[test]
fn ids_are_unique_and_every_in_page_link_has_a_target() -> TestResult {
    each_golden(id_problems)
}

#[test]
fn the_only_links_are_in_page_the_footer_and_the_repo_and_the_only_src_is_data() -> TestResult {
    each_golden(link_problems)
}

/// The checks must fail on bad pages, or they prove nothing.
#[test]
fn the_checks_catch_broken_pages() -> TestResult {
    let bad = "<html><body><h1>a</h1><h3>PASS x</h3><h3><span class=\"status\">OK</span></h3>\
               <a href=\"#nowhere\">x</a><a href=\"https://evil.example/\">y</a>\
               <img src=\"https://evil.example/p.png\"><p id=\"a\"></p><p id=\"a\"></p>\
               <table><tr><th>x</th></tr></table><script>if (a < b) {}</script></body></html>";
    let t = tokens(bad)?;
    assert_eq!(heading_problems(&t), ["h3 follows h1"]);
    assert_eq!(status_problems(&t).len(), 2);
    assert_eq!(table_problems(&t), ["th with scope None"]);
    assert_eq!(id_problems(&t).len(), 2);
    assert_eq!(link_problems(&t).len(), 2);
    assert_eq!(page_problems(&t).len(), 6);
    Ok(())
}
