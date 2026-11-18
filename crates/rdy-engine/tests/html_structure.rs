//! The structure test of the HTML report (M1-082, 07 D.4): over the three goldens of 07 Appendix B
//! (`results-b1-ready`, `results-b2-ready-with-warnings`, `results-b3-not-ready`) heading levels never
//! skip, `lang` is set, every `h3` starts with a status word, every table has `th` with a `scope`, ids are
//! unique, every `href="#id"` has a target, and the only other `href` or `src` values are `data:`, the
//! footer link and the repo link.
//!
//! No HTML parser is in the dependency tree, and adding one (html5ever and its tree) is not worth it for
//! pages rdy writes itself. `tokens` below is a small tokenizer for that markup. It fails closed: a tag name
//! outside `[a-z][a-z0-9]*`, a comment, a `<!` other than the doctype, or a `script` or `style` that ends
//! early or in a different case is an error, not something to guess at. It keeps the text between tags
//! (entities decoded) and reads quoted attributes.
//!
//! M1-141 adds its bdi and bidi checks on top of `tokens`, `Token`, `opens`, `text_of` and `inside`, with
//! one `*_problems` function per rule. `problems_in` runs a rule over any rendered page and `each_golden`
//! runs it over the three goldens.
//!
//! M1-181 includes this file in the CLI's environment harness (`#[path]`) and runs the same rules over the
//! page that `rdy run` wrote. The names that harness uses are `pub(crate)`.

use std::collections::BTreeSet;
use std::error::Error;
use std::path::PathBuf;

use rdy_engine::testing::fixtures_dir;
use serde_json::Value;

type TestResult<T = ()> = Result<T, Box<dyn Error>>;

/// The file stems of the three goldens (07 Appendix B.1 to B.3). The result file of each is the stem
/// without `results-` in `tests/fixtures/results/plan-07/`.
const GOLDENS: [&str; 4] = [
    "results-b1-ready",
    "results-b2-ready-with-warnings",
    "results-b3-not-ready",
    "ready-with-warnings-nothing-verified",
];

/// The words of the status span of an `h3` (`status_word` in `report/html/view.rs`).
const STATUS_WORDS: [&str; 7] = [
    "PASS", "WARN", "BLOCK", "TIMEOUT", "ERROR", "SKIP", "NOT RUN",
];

/// The start of the footer link (07 D.4): the product follows `product=` and nothing follows the product.
const FOOTER_LINK: &str = "https://getrdy.io/?ref=report&product=";

/// The repo link of the footer.
const REPO_LINK: &str = "https://github.com/getrdy-io/rdy";

/// Elements with no end tag.
const VOID: [&str; 6] = ["meta", "link", "br", "hr", "img", "input"];

/// One piece of a page.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum Token {
    /// `<name attr="value">`. Names are lower case. Values are kept as written.
    Open {
        name: String,
        attrs: Vec<(String, String)>,
    },
    /// `</name>`.
    Close(String),
    /// Text between tags, with entities decoded.
    Text(String),
}

fn golden_html(stem: &str) -> TestResult<String> {
    let path: PathBuf = fixtures_dir().join(format!("reports/golden/{stem}.html"));
    std::fs::read_to_string(&path).map_err(|e| format!("{}: {e}", path.display()).into())
}

/// The product the result file of the golden `stem` names. A golden without the `results-` prefix is
/// built from the `not-ready-7.2.json` sample, so that file names its product.
fn golden_product(stem: &str) -> TestResult<String> {
    let path = match stem.strip_prefix("results-") {
        Some(name) => fixtures_dir().join(format!("results/plan-07/{name}.json")),
        None => fixtures_dir().join("reports/not-ready-7.2.json"),
    };
    let text = std::fs::read_to_string(&path).map_err(|e| format!("{}: {e}", path.display()))?;
    let doc: Value = serde_json::from_str(&text)?;
    Ok(doc["spec"]["product"]
        .as_str()
        .ok_or("spec.product is not text")?
        .to_owned())
}

/// A tag or attribute name: `^[a-z][a-z0-9]*$`, with `-` and `:` also allowed in attribute names.
fn valid_name(name: &str, attribute: bool) -> bool {
    let mut chars = name.chars();
    chars.next().is_some_and(|c| c.is_ascii_lowercase())
        && chars.all(|c| {
            c.is_ascii_lowercase() || c.is_ascii_digit() || (attribute && (c == '-' || c == ':'))
        })
}

/// The tokens of `html`. The body of `script` and `style` is dropped. Anything the tokenizer does not
/// expect is an error.
fn tokens(html: &str) -> Result<Vec<Token>, String> {
    let mut out = Vec::new();
    let mut rest = html;
    while !rest.is_empty() {
        let Some(lt) = rest.find('<') else {
            out.push(Token::Text(decode_entities(rest)));
            break;
        };
        if lt > 0 {
            out.push(Token::Text(decode_entities(&rest[..lt])));
        }
        rest = &rest[lt..];
        if let Some(after) = rest.strip_prefix("<!") {
            match after.strip_prefix("DOCTYPE html>") {
                Some(tail) => {
                    rest = tail;
                    continue;
                }
                None => return Err(format!("a `<!` that is not the doctype: {:?}", head(rest))),
            }
        }
        let end = tag_end(rest).ok_or("a tag never ends")?;
        let inner = &rest[1..end - 1];
        rest = &rest[end..];
        if let Some(name) = inner.strip_prefix('/') {
            if !valid_name(name, false) {
                return Err(format!("a closing tag named {name:?}"));
            }
            out.push(Token::Close(name.to_owned()));
            continue;
        }
        let (name, attrs) = parse_tag(inner)?;
        let raw = name == "script" || name == "style";
        out.push(Token::Open {
            name: name.clone(),
            attrs,
        });
        if raw {
            rest = skip_raw(rest, &name)?;
        }
    }
    Ok(out)
}

/// The first characters of `text`, for a message.
fn head(text: &str) -> String {
    text.chars().take(20).collect()
}

/// `rest` from the end tag of the raw text element `name`. A `</name` in any case that is not exactly
/// `</name>` is an error, because a browser could end the element there.
fn skip_raw<'a>(rest: &'a str, name: &str) -> Result<&'a str, String> {
    let lower = rest.to_ascii_lowercase();
    let close = format!("</{name}");
    let at = lower
        .find(&close)
        .ok_or_else(|| format!("{name} never ends"))?;
    if !rest[at..].starts_with(&format!("</{name}>")) {
        return Err(format!("{name} ends early or in a different form"));
    }
    Ok(&rest[at..])
}

/// The length of the tag that starts `text`, counting a quoted `>` as text. (The same walk as `tag_end` in
/// `html_report.rs`: every file in `tests/` is its own crate, and a shared module is not worth it for 12 lines.)
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
fn parse_tag(inner: &str) -> Result<(String, Vec<(String, String)>), String> {
    let inner = inner.trim_end_matches('/');
    let name_end = inner
        .find(|c: char| c.is_ascii_whitespace())
        .unwrap_or(inner.len());
    let name = &inner[..name_end];
    if !valid_name(name, false) {
        return Err(format!("a tag named {name:?}"));
    }
    let mut attrs = Vec::new();
    let mut rest = inner[name_end..].trim_start();
    while !rest.is_empty() {
        let key_end = rest
            .find(|c: char| c == '=' || c.is_ascii_whitespace())
            .unwrap_or(rest.len());
        let key = &rest[..key_end];
        if !valid_name(key, true) {
            return Err(format!("an attribute named {key:?} on <{name}>"));
        }
        rest = rest[key_end..].trim_start();
        let mut value = String::new();
        if let Some(after) = rest.strip_prefix('=') {
            let after = after.trim_start();
            if let Some(q) = after.chars().next().filter(|c| *c == '"' || *c == '\'') {
                let body = &after[1..];
                let close = body
                    .find(q)
                    .ok_or_else(|| format!("an attribute of <{name}> never ends"))?;
                value = body[..close].to_owned();
                rest = body[close + 1..].trim_start();
            } else {
                let close = after
                    .find(|c: char| c.is_ascii_whitespace())
                    .unwrap_or(after.len());
                value = after[..close].to_owned();
                rest = after[close..].trim_start();
            }
        }
        attrs.push((key.to_owned(), value));
    }
    Ok((name.to_owned(), attrs))
}

/// `text` with `&#38;`, `&#x26;` and the five named entities of askama's escaping decoded.
fn decode_entities(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    let mut rest = text;
    while let Some(at) = rest.find('&') {
        out.push_str(&rest[..at]);
        rest = &rest[at..];
        let decoded = rest.find(';').and_then(|semi| {
            let body = &rest[1..semi];
            let c = match body {
                "amp" => Some('&'),
                "lt" => Some('<'),
                "gt" => Some('>'),
                "quot" => Some('"'),
                "apos" => Some('\''),
                _ => body.strip_prefix('#').and_then(|n| {
                    let code = match n.strip_prefix(['x', 'X']) {
                        Some(hex) => u32::from_str_radix(hex, 16).ok(),
                        None => n.parse().ok(),
                    };
                    code.and_then(char::from_u32)
                }),
            };
            c.map(|c| (c, semi + 1))
        });
        match decoded {
            Some((c, len)) => {
                out.push(c);
                rest = &rest[len..];
            }
            None => {
                out.push('&');
                rest = &rest[1..];
            }
        }
    }
    out.push_str(rest);
    out
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

/// Whether the token at `index` sits inside an open `element` (an open-tag stack walked from the start).
fn inside(tokens: &[Token], index: usize, element: &str) -> bool {
    let mut stack: Vec<&str> = Vec::new();
    for token in &tokens[..index.min(tokens.len())] {
        match token {
            Token::Open { name, .. } if !VOID.contains(&name.as_str()) => stack.push(name),
            Token::Close(name) => {
                if let Some(at) = stack.iter().rposition(|open| open == name) {
                    stack.truncate(at);
                }
            }
            _ => {}
        }
    }
    stack.contains(&element)
}

/// Every open tag as `(index, name, attrs)`.
fn opens(tokens: &[Token]) -> impl Iterator<Item = (usize, &str, &[(String, String)])> {
    tokens.iter().enumerate().filter_map(|(i, t)| match t {
        Token::Open { name, attrs } => Some((i, name.as_str(), attrs.as_slice())),
        _ => None,
    })
}

/// The problems with heading levels: one `h1`, and no level more than one below the one before.
pub(crate) fn heading_problems(tokens: &[Token]) -> Vec<String> {
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

/// The problems with `h3` status words: each `h3` starts with a `status` span whose whole text is a status
/// word.
pub(crate) fn status_problems(tokens: &[Token]) -> Vec<String> {
    let mut problems = Vec::new();
    for (i, name, _) in opens(tokens) {
        if name != "h3" {
            continue;
        }
        let word = match tokens.get(i + 1) {
            Some(Token::Open { name, attrs })
                if name == "span" && attr(attrs, "class") == Some("status") =>
            {
                text_of(tokens, i + 1)
            }
            _ => {
                problems.push(format!(
                    "h3 {:?} does not start with a status span",
                    text_of(tokens, i)
                ));
                continue;
            }
        };
        if !STATUS_WORDS.contains(&word.as_str()) {
            problems.push(format!("h3 status {word:?} is not a status word"));
        }
    }
    problems
}

/// The problems with tables: each `table` holds at least one `th`, and each `th` has `scope` `col` or `row`.
pub(crate) fn table_problems(tokens: &[Token]) -> Vec<String> {
    let mut problems = Vec::new();
    let mut tables = 0;
    let mut open: Vec<(usize, usize)> = Vec::new();
    for token in tokens {
        match token {
            Token::Open { name, .. } if name == "table" => {
                tables += 1;
                open.push((tables, 0));
            }
            Token::Open { name, attrs } if name == "th" => match attr(attrs, "scope") {
                Some("col" | "row") => {
                    if let Some(table) = open.last_mut() {
                        table.1 += 1;
                    }
                }
                other => problems.push(format!("th with scope {other:?}")),
            },
            Token::Close(name) if name == "table" => {
                if let Some((n, 0)) = open.pop() {
                    problems.push(format!("table {n} has no th with a scope"));
                }
            }
            _ => {}
        }
    }
    problems
}

/// The problems with ids and in-page links: no id twice, and each `href="#id"` has a target.
pub(crate) fn id_problems(tokens: &[Token]) -> Vec<String> {
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

/// A product name by ADR 0003 decision 1: `^[a-z0-9][a-z0-9-]{0,62}$`.
fn valid_product(product: &str) -> bool {
    let mut chars = product.chars();
    product.len() <= 63
        && chars
            .next()
            .is_some_and(|c| c.is_ascii_lowercase() || c.is_ascii_digit())
        && chars.all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-')
}

/// The problems with `href` and `src`: only `#id`, the footer link and the repo link for `href`, and only
/// `data:` for `src`. The footer link ends with a valid product name, which is `product` when it is given.
pub(crate) fn link_problems(tokens: &[Token], product: Option<&str>) -> Vec<String> {
    let mut problems = Vec::new();
    for (_, name, attrs) in opens(tokens) {
        if let Some(href) = attr(attrs, "href") {
            let href = decode_entities(href);
            let ok = match href.strip_prefix(FOOTER_LINK) {
                _ if href.starts_with('#') || href == REPO_LINK => true,
                Some(found) => {
                    valid_product(found) && product.is_none_or(|expected| expected == found)
                }
                None => false,
            };
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
pub(crate) fn page_problems(tokens: &[Token]) -> Vec<String> {
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

/// Every rule above, run over the page `html`, each problem named by its rule. M1-141 adds its rules here,
/// so they also run on the page that `rdy run` wrote (M1-181).
pub(crate) fn all_rules(html: &str, product: Option<&str>) -> Vec<String> {
    type Rule<'a> = (&'a str, &'a dyn Fn(&[Token]) -> Vec<String>);
    let rules: [Rule; 6] = [
        ("headings", &heading_problems),
        ("status", &status_problems),
        ("tables", &table_problems),
        ("ids", &id_problems),
        ("page", &page_problems),
        ("links", &|tokens| link_problems(tokens, product)),
    ];
    let mut all = Vec::new();
    for (name, rule) in rules {
        all.extend(
            problems_in(html, rule)
                .into_iter()
                .map(|problem| format!("{name}: {problem}")),
        );
    }
    all
}

/// Runs `check` over the page `html`. A page the tokenizer refuses is one problem.
pub(crate) fn problems_in(html: &str, check: impl Fn(&[Token]) -> Vec<String>) -> Vec<String> {
    match tokens(html) {
        Ok(tokens) => check(&tokens),
        Err(e) => vec![format!("the page does not tokenize: {e}")],
    }
}

/// Runs `check` over each golden and fails with every problem, named by golden.
fn each_golden(check: fn(&[Token]) -> Vec<String>) -> TestResult {
    let mut all = Vec::new();
    for stem in GOLDENS {
        let html = golden_html(stem)?;
        all.extend(
            problems_in(&html, check)
                .into_iter()
                .map(|p| format!("{stem}: {p}")),
        );
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
fn every_table_has_th_with_a_scope() -> TestResult {
    each_golden(table_problems)
}

#[test]
fn ids_are_unique_and_every_in_page_link_has_a_target() -> TestResult {
    each_golden(id_problems)
}

#[test]
fn the_only_links_are_in_page_the_footer_and_the_repo_and_the_only_src_is_data() -> TestResult {
    each_golden(|tokens| link_problems(tokens, None))
}

#[test]
fn every_rule_together_passes_on_the_goldens() -> TestResult {
    for stem in GOLDENS {
        let found = all_rules(&golden_html(stem)?, Some(&golden_product(stem)?));
        assert_eq!(found, Vec::<String>::new(), "{stem}");
    }
    Ok(())
}

#[test]
fn the_footer_link_names_the_product_of_the_result_file() -> TestResult {
    for stem in GOLDENS {
        let product = golden_product(stem)?;
        let html = golden_html(stem)?;
        let problems = problems_in(&html, |t| link_problems(t, Some(&product)));
        assert_eq!(problems, Vec::<String>::new(), "{stem}");
        assert!(
            decode_entities(&html).contains(&format!("href=\"{FOOTER_LINK}{product}\"")),
            "{stem}: no footer link for {product}"
        );
    }
    Ok(())
}

#[test]
fn the_tokenizer_refuses_markup_it_cannot_read_safely() {
    let refused = [
        "<img/src=\"https://x\">",
        "<!-- a -->",
        "<!--> <img src=\"https://x\">",
        "<!-- a --!> <img src=\"https://x\"> -->",
        "<!x 'a>b'>",
        "<p></P>",
        "<Img src=\"https://x\">",
        "<p></SCRIPT>",
        "<script>a</SCRIPT><img src=\"https://x\"></script>",
        "<script>a</script ><img src=\"https://x\"></script>",
        "<style>a</STYLE><img src=\"https://x\"></style>",
        "<script>never ends",
        "<p onclick='x>",
        "<p 1a=\"b\">",
    ];
    for html in refused {
        assert!(tokens(html).is_err(), "{html:?} was accepted");
    }
    assert!(tokens("<!DOCTYPE html>\n<p a=\"b\">x &#38; y</p><br/>").is_ok());
}

#[test]
fn the_tokenizer_decodes_text_and_skips_raw_bodies() -> TestResult {
    let t = tokens("<p>a &#38; b &#x26; c &amp; &#8238;</p><script>if (a < b) {}</script>")?;
    assert_eq!(t[1], Token::Text("a & b & c & \u{202e}".to_owned()));
    assert_eq!(t.len(), 5);
    Ok(())
}

#[test]
fn inside_follows_the_open_elements() -> TestResult {
    let t = tokens("<p><bdi>a<br>b</bdi>c</p><bdi><b>d</b></bdi>")?;
    let at = |text: &str| t.iter().position(|x| *x == Token::Text(text.to_owned()));
    let flags: Vec<bool> = ["a", "b", "c", "d"]
        .iter()
        .map(|s| at(s).is_some_and(|i| inside(&t, i, "bdi")))
        .collect();
    assert_eq!(flags, [true, true, false, true]);
    Ok(())
}

#[test]
fn the_heading_rule_catches_a_skip_and_two_h1s() {
    let run = |html| problems_in(html, heading_problems);
    assert_eq!(run("<h1>a</h1><h3>b</h3>"), ["h3 follows h1"]);
    assert_eq!(run("<h1>a</h1><h1>b</h1>"), ["2 h1 elements, want 1"]);
}

#[test]
fn the_status_rule_catches_a_missing_or_wrong_word() {
    let run = |html| problems_in(html, status_problems);
    assert_eq!(
        run("<h3>PASS x</h3>"),
        ["h3 \"PASS x\" does not start with a status span"]
    );
    assert_eq!(
        run("<h3><span class=\"status\">OK</span></h3>"),
        ["h3 status \"OK\" is not a status word"]
    );
    assert_eq!(
        run("<h3><span class=\"status\">PASS x</span></h3>"),
        ["h3 status \"PASS x\" is not a status word"]
    );
    assert_eq!(
        run("<h3><span class=\"status\">NOT RUN</span> <bdi>a</bdi></h3>"),
        Vec::<String>::new()
    );
}

#[test]
fn the_table_rule_works_per_table() {
    let run = |html| problems_in(html, table_problems);
    assert_eq!(
        run("<table><tr><th>x</th></tr></table>"),
        ["th with scope None", "table 1 has no th with a scope"]
    );
    assert_eq!(
        run("<table><tr><th scope=\"col\">a</th></tr></table><table><tr><td>b</td></tr></table>"),
        ["table 2 has no th with a scope"]
    );
}

#[test]
fn the_id_rule_catches_a_duplicate_and_a_dead_link() {
    assert_eq!(
        problems_in(
            "<p id=\"a\"></p><p id=\"a\"></p><a href=\"#nowhere\">x</a>",
            id_problems
        ),
        [
            "the id \"a\" is used twice",
            "href=\"#nowhere\" has no target"
        ]
    );
}

#[test]
fn the_link_rule_catches_outside_links_and_a_bad_footer() {
    let run = |html: &str| problems_in(html, |t| link_problems(t, Some("acme")));
    let footer = |tail: &str| format!("<a href=\"{FOOTER_LINK}{tail}\">x</a>");
    assert_eq!(run(&footer("acme")), Vec::<String>::new());
    assert_eq!(
        run(&format!("<a href=\"{REPO_LINK}\">x</a>")),
        Vec::<String>::new()
    );
    assert_eq!(
        run("<a href=\"https://evil.example/\">y</a><img src=\"https://evil.example/p.png\">"),
        [
            "<a> href \"https://evil.example/\" is not allowed",
            "<img> src \"https://evil.example/p.png\" is not data:"
        ]
    );
    for bad in [
        "",
        "acme&#38;run=1",
        "acme#frag",
        "acme&#38;a=b&#38;c=d",
        "other",
        "Acme",
        "-acme",
    ] {
        let shown = decode_entities(&format!("{FOOTER_LINK}{bad}"));
        assert_eq!(
            run(&footer(bad)),
            [format!("<a> href {shown:?} is not allowed")],
            "{bad:?}"
        );
    }
}

#[test]
fn the_page_rule_catches_an_empty_lang_and_a_duplicate_landmark() {
    assert_eq!(
        problems_in(
            "<html lang=\"\"><header></header><header></header><nav aria-label=\"Sections\"></nav>\
             <main></main><footer></footer></html>",
            page_problems
        ),
        ["html has no lang", "2 header landmarks, want 1"]
    );
}

// ---------------------------------------------------------------------------------------------------
// M1-141: untrusted text is in `<bdi>`, and no format or zero-width character reaches the page raw.
// ---------------------------------------------------------------------------------------------------

/// A closing isolate, then a reversal (SEC-149-11): the string that closes a `<bdi>` early and flips what
/// follows. Every planted field below is a tag word followed by this.
const HOSTILE: &str = "x\u{2069}\u{202e}";

/// `HOSTILE` as the page must show it: the two controls written out, the `x` kept.
const HOSTILE_SHOWN: &str = "x\\u{2069}\\u{202e}";

/// The planted fields: the tag word that starts each value. A tag starts with a capital letter, because
/// Found and Needed labels are capitalised by the page. `hostile_page` says where each one goes.
const PLANTED: [&str; 27] = [
    "Product", "Version", "Host", "User", "Rdyver", "Message", "Fix", "Builtin", "Note", "Grant",
    "Partial", "Fkey", "Fval", "Nkey", "Nval", "Cname", "Cdetail", "Chint", "File", "Cid", "Apath",
    "Acheck", "Ahost", "Runid", "Contact", "Keyid", "Trust",
];

/// Fields on the page only in one of the pages of `hostile_page`.
const ONLY_UNSIGNED: [&str; 1] = ["File"];

/// Fields on the page only when the spec is signed: the unsigned page has no signature to show.
const ONLY_SIGNED: [&str; 2] = ["Keyid", "Trust"];

/// Planted needles that are not a tag word followed by `HOSTILE`: a fix that holds a lone U+2066 (an
/// isolate that is never closed), the capability need name, and the short fingerprint of the not-pinned
/// banner, which keeps the first eight characters and so cuts `HOSTILE` after its U+2069.
const OTHER_NEEDLES: [&str; 3] = ["Fixopen\\u{2066}rm -rf /", "Capname", "Fprintx\\u{2069}"];

/// Whether `c` is a Unicode format (Cf) character or one of the zero-width characters outside Cf. The list
/// is written out here on purpose, not taken from the engine, so the test does not agree with the engine
/// by sharing its mistake.
fn is_format_or_zero_width(c: char) -> bool {
    matches!(
        u32::from(c),
        0x00AD
            | 0x0600..=0x0605
            | 0x061C
            | 0x06DD
            | 0x070F
            | 0x0890..=0x0891
            | 0x08E2
            | 0x180E
            | 0x200B..=0x200F
            | 0x2028..=0x202E
            | 0x2060..=0x206F
            | 0xFEFF
            | 0xFFF9..=0xFFFB
            | 0x110BD
            | 0x110CD
            | 0x13430..=0x1343F
            | 0x1BCA0..=0x1BCA3
            | 0x1D173..=0x1D17A
            | 0xE0001
            | 0xE0020..=0xE007F
            // Zero-width or blank, and not Cf.
            | 0x034F
            | 0x115F..=0x1160
            | 0x17B4..=0x17B5
            | 0x3164
            | 0xFFA0
    )
}

/// The problems with raw format characters and control characters (line feed and tab excepted): none in
/// any text or attribute value. The one exception is the
/// `<title>`, which cannot hold elements, so the page wraps the product in U+2068 and U+2069 there: one of
/// each is allowed, and nothing else. The body of the embedded `<script>` data block is not a token, so it
/// is not judged here: the JSON writer keeps the report's text as it is, and no browser shows that block.
pub(crate) fn raw_format_problems(tokens: &[Token]) -> Vec<String> {
    let mut problems = Vec::new();
    let bad = |text: &str| -> Option<String> {
        text.chars()
            .find(|c| is_format_or_zero_width(*c) || (c.is_control() && *c != '\n' && *c != '\t'))
            .map(|c| format!("U+{:04X}", u32::from(c)))
    };
    for (i, token) in tokens.iter().enumerate() {
        match token {
            Token::Text(text) if inside(tokens, i, "title") => {
                let mut rest = text.clone();
                if let Some(at) = rest.find('\u{2068}') {
                    rest.remove(at);
                }
                if let Some(at) = rest.rfind('\u{2069}') {
                    rest.remove(at);
                }
                if let Some(found) = bad(&rest) {
                    problems.push(format!("raw {found} in the title"));
                }
            }
            Token::Text(text) => {
                if let Some(found) = bad(text) {
                    problems.push(format!("raw {found} in text {}", head(text)));
                }
            }
            Token::Open { name, attrs } => {
                for (key, value) in attrs {
                    if let Some(found) = bad(value) {
                        problems.push(format!("raw {found} in {name} {key}"));
                    }
                }
            }
            Token::Close(_) => {}
        }
    }
    problems
}

/// The needles for `tags`: each tag word followed by the escaped hostile text.
fn needles(tags: &[&str]) -> Vec<String> {
    tags.iter()
        .map(|tag| format!("{tag}{HOSTILE_SHOWN}"))
        .collect()
}

/// The problems with isolation: every piece of text that shows a needle sits inside a `<bdi>`, and every
/// needle was found. The `<title>` is skipped, because it cannot
/// hold a `<bdi>`; `title_problems` has its own rule.
fn bdi_problems(tokens: &[Token], needles: &[String]) -> Vec<String> {
    let mut problems = Vec::new();
    for needle in needles {
        let tag = needle;
        let mut found = 0;
        for (i, token) in tokens.iter().enumerate() {
            let Token::Text(text) = token else { continue };
            if !text.contains(needle.as_str()) || inside(tokens, i, "title") {
                continue;
            }
            found += 1;
            if !inside(tokens, i, "bdi") {
                problems.push(format!("{tag}: {} is not inside a bdi", head(text)));
            }
        }
        if found == 0 {
            problems.push(format!("{tag}: {needle:?} is not on the page"));
        }
    }
    problems
}

/// The problems with the `<title>`: it holds the escaped product between one U+2068 and one U+2069.
fn title_problems(tokens: &[Token]) -> Vec<String> {
    let want = format!("rdy report: NOT READY, \u{2068}Product{HOSTILE_SHOWN}\u{2069}");
    let titles: Vec<&str> = tokens
        .iter()
        .enumerate()
        .filter_map(|(i, t)| match t {
            Token::Text(text) if inside(tokens, i, "title") => Some(text.as_str()),
            _ => None,
        })
        .collect();
    if titles == [want.as_str()] {
        Vec::new()
    } else {
        vec![format!("the title is {titles:?}, want {want:?}")]
    }
}

/// How the signature of the hostile page is: verified with a pinned key (the vendor's name is on fixes),
/// verified with a key given for one run (the banner shows the short fingerprint), or unsigned (the banner
/// names the spec file).
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum Pinned {
    Yes,
    Flag,
    Unsigned,
}

/// The sample report with `HOSTILE` planted in every field of `PLANTED` and the other needles, rendered.
fn hostile_page(pinned: Pinned) -> TestResult<String> {
    use rdy_engine::redact::{Redactor, TagKey};
    use rdy_engine::report::render_html;
    use rdy_spec::result::Report;
    use serde_json::json;

    let path = fixtures_dir().join("reports/not-ready-7.2.json");
    let mut doc: Value = serde_json::from_str(&std::fs::read_to_string(&path)?)?;
    let plant = |tag: &str| json!(format!("{tag}{HOSTILE}"));
    doc["spec"]["product"] = plant("Product");
    doc["spec"]["version"] = plant("Version");
    doc["spec"]["file_name"] = plant("File");
    doc["host"]["hostname"] = plant("Host");
    doc["identity"]["user"] = plant("User");
    doc["producer"]["version"] = plant("Rdyver");
    doc["capabilities"][0]["detail"] = plant("Cdetail");
    doc["capabilities"][0]["hint"] = plant("Chint");
    doc["checks"][0]["observed"] = json!({ format!("Fkey{HOSTILE}"): plant("Fval") });
    doc["checks"][0]["expected"] = json!({ format!("Nkey{HOSTILE}"): plant("Nval") });
    doc["checks"][1]["message"] = plant("Message");
    doc["checks"][1]["fix"] = plant("Fix");
    doc["checks"][1]["builtin_fix"] = plant("Builtin");
    doc["checks"][1]["name"] = plant("Cname");
    doc["checks"][1]["notes"] = json!([format!("Note{HOSTILE}")]);
    doc["checks"][2]["partial"] = json!({
        "missing": [],
        "missing_grants": [format!("Grant{HOSTILE}")],
        "note": format!("Partial{HOSTILE}"),
    });
    doc["checks"][1]["id"] = plant("Cid");
    doc["checks"][2]["fix"] = json!("Fixopen\u{2066}rm -rf /");
    doc["actions"][2]["path"] = plant("Apath");
    doc["actions"][2]["check"] = plant("Acheck");
    doc["actions"][7]["host"] = plant("Ahost");
    doc["run"]["id"] = plant("Runid");
    doc["spec"]["contact"] = plant("Contact");
    doc["signature"]["key_id"] = plant("Keyid");
    doc["signature"]["trust_note"] = plant("Trust");
    doc["capabilities"][1]["need"] = json!("command");
    doc["capabilities"][1]["name"] = json!(format!("Capname{HOSTILE}"));
    if pinned == Pinned::Flag {
        doc["signature"]["trust_source"] = json!("flag");
        doc["signature"]["key_fingerprint"] = json!(format!("Fprint{HOSTILE}0123456789abcdef"));
    }
    if pinned == Pinned::Unsigned {
        doc["signature"] = json!({ "state": "unsigned" });
    }
    let report: Report = serde_json::from_value(doc)?;
    let redacted = Redactor::new(TagKey::fixed([5; 32])).redact_report(report)?;
    Ok(render_html(&redacted)?)
}

#[test]
fn hostile_text_in_every_untrusted_field_is_in_a_bdi_and_shown_as_escapes() -> TestResult {
    for pinned in [Pinned::Yes, Pinned::Flag, Pinned::Unsigned] {
        let html = hostile_page(pinned)?;
        let mut wanted = needles(
            &PLANTED
                .iter()
                .copied()
                .filter(|tag| {
                    if pinned == Pinned::Unsigned {
                        !ONLY_SIGNED.contains(tag)
                    } else {
                        !ONLY_UNSIGNED.contains(tag)
                    }
                })
                .collect::<Vec<_>>(),
        );
        wanted.extend(OTHER_NEEDLES.iter().map(|n| (*n).to_owned()));
        if pinned != Pinned::Flag {
            // The short fingerprint is in the not-pinned banner only. The details row shows it whole.
            wanted.retain(|n| !n.starts_with("Fprint"));
        }
        assert_eq!(
            problems_in(&html, |t| bdi_problems(t, &wanted)),
            Vec::<String>::new(),
            "{pinned:?}"
        );
        assert_eq!(
            problems_in(&html, raw_format_problems),
            Vec::<String>::new(),
            "{pinned:?}"
        );
        assert_eq!(
            problems_in(&html, title_problems),
            Vec::<String>::new(),
            "{pinned:?}"
        );
    }
    Ok(())
}

#[test]
fn the_banner_line_names_the_file_in_a_bdi_with_the_controls_written_out() -> TestResult {
    let html = hostile_page(Pinned::Unsigned)?;
    let t = tokens(&html)?;
    let at = t
        .iter()
        .position(|x| *x == Token::Text(format!("File{HOSTILE_SHOWN}")))
        .ok_or("the banner does not name the file")?;
    assert!(inside(&t, at, "bdi"));
    assert!(opens(&t).any(|(i, name, attrs)| {
        name == "div" && attr(attrs, "class") == Some("banner") && i < at
    }));
    Ok(())
}

#[test]
fn the_goldens_hold_no_raw_format_character() -> TestResult {
    each_golden(raw_format_problems)
}

#[test]
fn the_bdi_rule_catches_text_outside_and_text_that_is_missing() {
    let shown = format!("Host{HOSTILE_SHOWN}");
    let ok = format!("<p>on <bdi>{shown}</bdi></p>");
    let outside = format!("<p>on {shown}</p>");
    let tags = needles(&["Host"]);
    assert_eq!(
        problems_in(&ok, |t| bdi_problems(t, &tags)),
        Vec::<String>::new()
    );
    assert_eq!(problems_in(&outside, |t| bdi_problems(t, &tags)).len(), 1);
    // A bdi that closed early does not cover the text after it.
    let early = format!("<p><bdi>a</bdi>{shown}</p>");
    assert_eq!(problems_in(&early, |t| bdi_problems(t, &tags)).len(), 1);
    // A tag word that is not on the page at all is a problem, not a pass.
    assert_eq!(problems_in("<p>x</p>", |t| bdi_problems(t, &tags)).len(), 1);
}

#[test]
fn the_raw_format_rule_catches_controls_zero_width_text_and_entities() {
    for c in [
        '\u{202e}', '\u{2066}', '\u{200b}', '\u{feff}', '\u{ad}', '\u{3164}',
    ] {
        let html = format!("<p><bdi>a{c}b</bdi></p>");
        assert_eq!(problems_in(&html, raw_format_problems).len(), 1, "{c:?}");
    }
    // Controls other than line feed and tab are caught too.
    for c in ['\u{1b}', '\u{8}', '\u{7f}', '\u{85}', '\u{9b}', '\r'] {
        let html = format!("<p><bdi>a{c}b</bdi></p>");
        assert_eq!(problems_in(&html, raw_format_problems).len(), 1, "{c:?}");
    }
    assert_eq!(
        problems_in("<p>a\nb\tc</p>", raw_format_problems),
        Vec::<String>::new()
    );
    // A numeric entity decodes to the raw character, so it is caught too.
    assert_eq!(
        problems_in("<p>a&#8238;b</p>", raw_format_problems).len(),
        1
    );
    assert_eq!(
        problems_in("<p title=\"a\u{202e}\">b</p>", raw_format_problems).len(),
        1
    );
    // The title may hold its one pair of isolates, and nothing else.
    let ok = "<title>rdy report: READY, \u{2068}acme\u{2069}</title>";
    assert_eq!(problems_in(ok, raw_format_problems), Vec::<String>::new());
    let bad = "<title>rdy report: READY, \u{2068}ac\u{202e}me\u{2069}</title>";
    assert_eq!(problems_in(bad, raw_format_problems).len(), 1);
    assert_eq!(
        problems_in("<p>caf\u{e9} \u{4e2d} \u{1f600}</p>", raw_format_problems),
        Vec::<String>::new()
    );
}

/// The golden page of the hostile hostname (a line separator and a paragraph separator among other
/// things) shows them as escapes, inside the `<bdi>`.
#[test]
fn the_hostile_host_golden_shows_the_separators_as_escapes() -> TestResult {
    let html = golden_html("not-ready-hostile-host")?;
    assert_eq!(
        problems_in(&html, raw_format_problems),
        Vec::<String>::new()
    );
    let t = tokens(&html)?;
    let at = t
        .iter()
        .position(|x| matches!(x, Token::Text(text) if text.contains("\\u{2028}")))
        .ok_or("the hostname shows no escape")?;
    assert!(inside(&t, at, "bdi"));
    Ok(())
}

/// C1: a hostname that holds every character `is_format_or_zero_width` names shows each one as
/// `\u{..}` and leaves no raw one on the page.
#[test]
fn a_hostname_with_every_format_and_zero_width_character_shows_each_as_an_escape() -> TestResult {
    use rdy_engine::redact::{Redactor, TagKey};
    use rdy_engine::report::render_html;
    use rdy_spec::result::Report;

    let all: Vec<char> = (0..=0x0010_FFFFu32)
        .filter_map(char::from_u32)
        .filter(|c| is_format_or_zero_width(*c))
        .collect();
    // The list has about 180 characters, so the loop is not empty by accident.
    assert!(all.len() > 150, "{} characters", all.len());
    let path = fixtures_dir().join("reports/not-ready-7.2.json");
    let mut doc: Value = serde_json::from_str(&std::fs::read_to_string(&path)?)?;
    let hostname: String = all.iter().flat_map(|c| ['h', *c]).collect();
    doc["host"]["hostname"] = serde_json::json!(hostname);
    let report: Report = serde_json::from_value(doc)?;
    let redacted = Redactor::new(TagKey::fixed([5; 32])).redact_report(report)?;
    let html = render_html(&redacted)?;
    assert_eq!(
        problems_in(&html, raw_format_problems),
        Vec::<String>::new()
    );
    let t = tokens(&html)?;
    let shown: String = all
        .iter()
        .flat_map(|c| {
            format!("h\\u{{{:x}}}", u32::from(*c))
                .chars()
                .collect::<Vec<_>>()
        })
        .collect();
    let at = t
        .iter()
        .position(|x| *x == Token::Text(shown.clone()))
        .ok_or("the hostname does not show every character as an escape")?;
    assert!(inside(&t, at, "bdi"));
    Ok(())
}
