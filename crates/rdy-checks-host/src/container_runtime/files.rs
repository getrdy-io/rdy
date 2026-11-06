//! Small parsers for the files and command output the check reads: `daemon.json`, systemd drop-ins,
//! the kubelet config, and the `--version` lines of containerd and CRI-O.
//!
//! All of them take text and return what they understood. They never panic on odd input and never
//! guess: a value they cannot read is `None`. The callers pass redacted text.

use rdy_spec::check::CgroupDriver;
use serde_json::Value;

use super::clip;
use super::engine::driver_word;

/// A daemon's proxy settings, as redacted text.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub(super) struct Proxy {
    pub http: Option<String>,
    pub https: Option<String>,
    pub no_proxy: Option<String>,
}

impl Proxy {
    pub(super) fn is_empty(&self) -> bool {
        self.http.is_none() && self.https.is_none() && self.no_proxy.is_none()
    }
}

/// What `daemon.json` sets that the check cares about.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub(super) struct DaemonJson {
    pub cgroup_driver: Option<CgroupDriver>,
    pub storage_driver: Option<String>,
    pub proxy: Proxy,
}

fn string_at(value: &Value, key: &str) -> Option<String> {
    let text = value.get(key)?.as_str()?.trim();
    (!text.is_empty()).then(|| clip(text))
}

/// Reads `/etc/docker/daemon.json`. An empty file is an empty object, as Docker reads it.
///
/// # Errors
///
/// A short reason when the text is not a JSON object.
pub(super) fn parse_daemon_json(text: &str) -> Result<DaemonJson, String> {
    if text.trim().is_empty() {
        return Ok(DaemonJson::default());
    }
    let root: Value = serde_json::from_str(text).map_err(|e| {
        let line = e.line();
        format!("it is not valid JSON (line {line})")
    })?;
    if !root.is_object() {
        return Err("it is not a JSON object".to_owned());
    }
    // The last `native.cgroupdriver` entry wins, as in the daemon.
    let cgroup_driver = root
        .get("exec-opts")
        .and_then(Value::as_array)
        .and_then(|opts| {
            opts.iter()
                .filter_map(Value::as_str)
                .filter_map(|o| {
                    let (key, value) = o.split_once('=')?;
                    key.trim()
                        .eq_ignore_ascii_case("native.cgroupdriver")
                        .then(|| driver_word(value))
                })
                .next_back()
                .flatten()
        });
    let proxy = root
        .get("proxies")
        .map(|p| Proxy {
            http: string_at(p, "http-proxy"),
            https: string_at(p, "https-proxy"),
            no_proxy: string_at(p, "no-proxy"),
        })
        .unwrap_or_default();
    Ok(DaemonJson {
        cgroup_driver,
        storage_driver: string_at(&root, "storage-driver"),
        proxy,
    })
}

/// The proxy that the `Environment=` lines of one systemd drop-in set. A later line overrides an
/// earlier one. Only the three proxy variables are kept.
pub(super) fn parse_dropin(text: &str) -> Proxy {
    let mut proxy = Proxy::default();
    for line in text.lines().take(500) {
        let line = line.trim();
        let Some(rest) = line.strip_prefix("Environment=") else {
            continue;
        };
        for token in split_env_tokens(rest) {
            let Some((name, value)) = token.split_once('=') else {
                continue;
            };
            let value = value.trim();
            if value.is_empty() {
                continue;
            }
            match name.trim().to_ascii_lowercase().as_str() {
                "http_proxy" => proxy.http = Some(clip(value)),
                "https_proxy" => proxy.https = Some(clip(value)),
                "no_proxy" => proxy.no_proxy = Some(clip(value)),
                _ => {}
            }
        }
    }
    proxy
}

/// Splits the value of an `Environment=` line at spaces outside double or single quotes and removes
/// the quotes that wrap a word.
fn split_env_tokens(text: &str) -> Vec<String> {
    let mut words = Vec::new();
    let mut current = String::new();
    let mut quote: Option<char> = None;
    for c in text.chars() {
        match (quote, c) {
            (Some(q), c) if c == q => quote = None,
            (Some(_), c) => current.push(c),
            (None, '"' | '\'') => quote = Some(c),
            (None, c) if c.is_whitespace() => {
                if !current.is_empty() {
                    words.push(std::mem::take(&mut current));
                }
            }
            (None, c) => current.push(c),
        }
    }
    if !current.is_empty() {
        words.push(current);
    }
    words
}

/// The kubelet's `cgroupDriver` from `/var/lib/kubelet/config.yaml`: the top-level key of the first
/// document that has it. `None` when the key is missing or holds something else.
pub(super) fn kubelet_driver(text: &str) -> Option<CgroupDriver> {
    for line in text.lines().take(2000) {
        // A top-level key starts in column 0.
        let Some(rest) = line.strip_prefix("cgroupDriver:") else {
            continue;
        };
        let value = rest.split(" #").next().unwrap_or(rest);
        let value = value.trim().trim_matches(['"', '\'']);
        return driver_word(value);
    }
    None
}

/// The leading dotted number of `text`, such as `1.7.13` from `v1.7.13+unknown` or `24.0.7` from
/// `24.0.7-ce`. `None` when it does not start with a digit (after one `v`).
pub(super) fn leading_number(text: &str) -> Option<&str> {
    let text = text.trim();
    let text = text.strip_prefix('v').unwrap_or(text);
    let end = text
        .find(|c: char| !(c.is_ascii_digit() || c == '.'))
        .unwrap_or(text.len());
    let head = text[..end].trim_end_matches('.');
    head.starts_with(|c: char| c.is_ascii_digit())
        .then_some(head)
}

/// The version in `containerd --version`: `containerd github.com/containerd/containerd v1.7.13 <hash>`,
/// `containerd containerd.io 1.6.31 <hash>` or the same with `/v2` in the module path. It is the first
/// word after the program name that starts with a number.
pub(super) fn containerd_version(text: &str) -> Option<String> {
    let line = text.lines().next()?;
    line.split_whitespace()
        .skip(1)
        .find_map(|word| leading_number(word).filter(|n| n.contains('.')))
        .map(clip)
}

/// The version in `crio --version`: `crio version 1.29.1` on the first line.
pub(super) fn crio_version(text: &str) -> Option<String> {
    let line = text.lines().next()?;
    let mut words = line.split_whitespace();
    while let Some(word) = words.next() {
        if word == "version" {
            return words
                .next()
                .and_then(leading_number)
                .filter(|n| n.contains('.'))
                .map(clip);
        }
    }
    None
}
