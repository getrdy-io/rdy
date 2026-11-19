//! Parsers for `net.proxy`: a proxy value, a systemd drop-in and `daemon.json`.
//!
//! They take text and return what they understood. They never panic on odd input, never guess, and never
//! keep a raw proxy value: a value is classified at once into a [`Setting`], which holds the proxy as
//! `http://host:port` and never its user name or password (`ProxyUrl` has no accessor for either).
//!
//! PAC and WPAD are detected, never fetched or evaluated (ADR 0009): the URL is kept as
//! `scheme://host:port/path` through `evidence_url`, with no userinfo and no query.

use rdy_engine::probe::{ProxyUrl, ProxyUrlError};
use rdy_engine::redact::evidence_url;
use serde_json::Value;

/// The most lines of one drop-in that are read.
const MAX_LINES: usize = 500;

/// The longest scheme word that is reported by name.
const MAX_SCHEME: usize = 16;

/// What one proxy value says, without the value.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) enum Setting {
    /// A plain `http://` proxy rdy can use. `credentials` is whether the URL carried a user name.
    Proxy { origin: String, credentials: bool },
    /// A proxy scheme rdy does not support in M1 (`https`, `socks5`, `socks5h`, any other).
    Unsupported(String),
    /// A PAC or WPAD address. The URL has no userinfo and no query.
    Pac(String),
    /// A value that is not a usable proxy URL, with the fixed reason.
    Bad(ProxyUrlError),
}

impl Setting {
    /// The origin of a usable proxy.
    pub(super) fn origin(&self) -> Option<&str> {
        match self {
            Self::Proxy { origin, .. } => Some(origin),
            _ => None,
        }
    }
}

/// Classifies one proxy value. `value` may hold a password and is not kept.
pub(super) fn classify(value: &str) -> Setting {
    let value = value.trim();
    if let Some(url) = pac_url(value) {
        return Setting::Pac(url);
    }
    if let Some((scheme, _)) = value.split_once("://") {
        let scheme = scheme.to_ascii_lowercase();
        if scheme != "http" {
            let plain = !scheme.is_empty()
                && scheme.len() <= MAX_SCHEME
                && scheme
                    .chars()
                    .all(|c| c.is_ascii_alphanumeric() || matches!(c, '+' | '.' | '-'));
            return if plain {
                Setting::Unsupported(scheme)
            } else {
                Setting::Bad(ProxyUrlError::Scheme)
            };
        }
    }
    match ProxyUrl::parse(value) {
        Ok(url) => Setting::Proxy {
            origin: url.origin(),
            credentials: url.has_credentials(),
        },
        Err(error) => Setting::Bad(error),
    }
}

/// The evidence form of a PAC or WPAD address, or `None` when the value is not one. A value is one when
/// its scheme starts with `pac+`, or the path of its URL ends in `.pac` or `wpad.dat`.
pub(super) fn pac_url(value: &str) -> Option<String> {
    let value = value.trim();
    let (scheme, rest) = value.split_once("://")?;
    let path = rest
        .find('/')
        .map(|at| &rest[at..])
        .unwrap_or_default()
        .split(['?', '#'])
        .next()
        .unwrap_or_default()
        .to_ascii_lowercase();
    let pac = scheme.to_ascii_lowercase().starts_with("pac+")
        || path.ends_with(".pac")
        || path.ends_with("wpad.dat");
    pac.then(|| evidence_url(value).unwrap_or_else(|| "(an address rdy cannot show)".to_owned()))
}

/// One thing a drop-in says about the environment of a unit.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) enum Assign {
    /// `HTTP_PROXY`, `HTTPS_PROXY` or `NO_PROXY` (either case) set to a value.
    Var(Kind, String),
    /// An empty `Environment=` line, which clears every earlier assignment of the unit.
    Reset,
    /// An `EnvironmentFile=` path. rdy does not read it, and says so.
    File(String),
}

/// Which of the three variables a daemon may have.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum Kind {
    Http,
    Https,
    No,
}

fn kind_of(name: &str) -> Option<Kind> {
    match name.trim().to_ascii_lowercase().as_str() {
        "http_proxy" => Some(Kind::Http),
        "https_proxy" => Some(Kind::Https),
        "no_proxy" => Some(Kind::No),
        _ => None,
    }
}

/// The assignments of one systemd drop-in, in order. Only `Environment=` and `EnvironmentFile=` lines
/// of the `[Service]` section count, as systemd reads them. The values are raw and may hold a password:
/// the caller classifies them and drops them.
pub(super) fn parse_dropin(text: &str) -> Vec<Assign> {
    let mut out = Vec::new();
    let mut in_service = false;
    for line in text.lines().take(MAX_LINES) {
        let line = line.trim();
        if line.starts_with('#') || line.starts_with(';') || line.is_empty() {
            continue;
        }
        if let Some(section) = line.strip_prefix('[') {
            in_service = section
                .trim_end_matches(']')
                .eq_ignore_ascii_case("service");
            continue;
        }
        if !in_service {
            continue;
        }
        if let Some(rest) = line.strip_prefix("Environment=") {
            let tokens = split_words(rest);
            if tokens.is_empty() {
                out.push(Assign::Reset);
            }
            for token in tokens {
                if let Some((name, value)) = token.split_once('=')
                    && let Some(kind) = kind_of(name)
                    && !value.trim().is_empty()
                {
                    out.push(Assign::Var(kind, value.trim().to_owned()));
                }
            }
        } else if let Some(rest) = line.strip_prefix("EnvironmentFile=") {
            let path = rest.trim().trim_start_matches('-').trim();
            if !path.is_empty() {
                out.push(Assign::File(path.chars().take(200).collect()));
            }
        }
    }
    out
}

/// Splits at spaces outside double or single quotes and removes the quotes that wrap a word.
fn split_words(text: &str) -> Vec<String> {
    let mut words = Vec::new();
    let mut current = String::new();
    let mut quote: Option<char> = None;
    let mut started = false;
    for c in text.chars() {
        match (quote, c) {
            (Some(q), c) if c == q => quote = None,
            (Some(_), c) => current.push(c),
            (None, '"' | '\'') => {
                quote = Some(c);
                started = true;
            }
            (None, c) if c.is_whitespace() => {
                if started || !current.is_empty() {
                    words.push(std::mem::take(&mut current));
                    started = false;
                }
            }
            (None, c) => current.push(c),
        }
    }
    if started || !current.is_empty() {
        words.push(current);
    }
    words.retain(|word| !word.is_empty());
    words
}

/// The `proxies` of a Docker `daemon.json`, as raw text. Nothing else of the file is read.
pub(super) fn daemon_json_proxies(text: &str) -> Result<Vec<Assign>, &'static str> {
    if text.trim().is_empty() {
        return Ok(Vec::new());
    }
    let root: Value = serde_json::from_str(text).map_err(|_| "it is not valid JSON")?;
    let Some(object) = root.as_object() else {
        return Err("it is not a JSON object");
    };
    let mut out = Vec::new();
    if let Some(proxies) = object.get("proxies").and_then(Value::as_object) {
        for (key, kind) in [
            ("http-proxy", Kind::Http),
            ("https-proxy", Kind::Https),
            ("no-proxy", Kind::No),
        ] {
            if let Some(value) = proxies.get(key).and_then(Value::as_str)
                && !value.trim().is_empty()
            {
                out.push(Assign::Var(kind, value.trim().to_owned()));
            }
        }
    }
    Ok(out)
}
