//! Structural limits and semantic rules for a parsed spec (01 sections 2.1, 2.2, 2.5 and 2.8, threat
//! model INV-11).
//!
//! The YAML reader (`parse.rs`) refuses what a spec file must not contain. This module refuses what a
//! well-formed spec must not say:
//!
//! - 1 to [`MAX_CHECKS`] checks;
//! - at most [`MAX_HOSTS`] distinct hosts across every `net.egress` endpoint, `net.tls_intercept` host
//!   and `net.dns` name in the whole spec;
//! - at most [`MAX_ENDPOINTS`] distinct host and port pairs across every `net.egress` endpoint and
//!   `net.tls_intercept` host in the whole spec;
//! - `metadata.version` and `metadata.contact` within their lengths, at most 32 `annotations`, and
//!   `expires` in the full UTC form;
//! - the `bundle` block within its list sizes, with collectors that fit the grammar of 01 section 2.8
//!   (`journal:<duration>`, `k8s:events`, `file:<absolute path or glob>` with no `..` segment).
//!
//! The host count reads the typed parameters of the three net checks. A check that does not decode (a
//! mistyped key, a list of 65) is skipped at run time, but a spec that names 65 hosts is still refused as
//! a whole, so a vendor sees the problem in lint and sign and the limit does not depend on how a
//! neighbouring check happens to decode. Such a check is counted from its raw parameters. When a host
//! cannot be read as a [`Target`], its lowercase text counts as one host. That can only make the count
//! larger.
//!
//! Not here: compiling `redact_patterns` regexes (M1-031 and M2), expiry against a clock (see
//! [`crate::expiry`]).

use std::collections::{BTreeMap, HashSet};

use serde_json::{Map, Value};

use crate::check::CheckParams;
use crate::error::echo_safe;
use crate::expiry::parse_utc;
use crate::spec::{BundleSpec, Metadata, Spec};
use crate::{Duration, Location, SpecError, Target};

/// The most checks in a spec (01 section 2.1).
pub const MAX_CHECKS: usize = 256;

/// The most distinct hosts a spec may name across all of its checks (threat model INV-11).
pub const MAX_HOSTS: usize = 64;

/// The most distinct host and port pairs a spec may name across `net.egress` and `net.tls_intercept`.
/// Without it 256 checks of 64 endpoints each would be 16,384 pairs, enough to scan a network
/// (threat model INV-11).
pub const MAX_ENDPOINTS: usize = 256;

const DEFAULT_TLS_PORT: u16 = 443;

const MAX_VERSION_CHARS: usize = 64;
const MAX_CONTACT_CHARS: usize = 256;
const MAX_ANNOTATIONS: usize = 32;
const MAX_ANNOTATION_VALUE_CHARS: usize = 256;
const MAX_COLLECT: usize = 64;
const MAX_REDACT: usize = 64;
const MAX_REDACT_PATTERNS: usize = 32;
const MAX_REGEX_CHARS: usize = 256;
const MAX_PATH_CHARS: usize = 1024;

/// The metadata keys whose place the reader remembers, for errors about their values.
pub(crate) const PLACED_METADATA_KEYS: [&str; 4] = ["version", "contact", "expires", "annotations"];

/// How many collector places the reader keeps. One more than the limit is enough to point at the first
/// item over it.
pub(crate) const PLACED_COLLECT_ITEMS: usize = MAX_COLLECT + 1;

/// Where a few values start in the file, so an error about them can name a line and a column. The YAML
/// reader fills it while it reads, and it is bounded: four keys and 65 collectors.
#[derive(Debug, Default)]
pub(crate) struct Places {
    /// The first character of the value of a `metadata` key in [`PLACED_METADATA_KEYS`].
    pub(crate) metadata: BTreeMap<&'static str, Location>,
    /// The first character of each `bundle.collect` item, in order, up to [`PLACED_COLLECT_ITEMS`].
    pub(crate) collect: Vec<Location>,
}

impl Places {
    fn of_metadata(&self, key: &str) -> Option<Location> {
        self.metadata.get(key).copied()
    }
}

/// Puts a place on an error when there is one.
fn placed(error: SpecError, at: Option<Location>) -> SpecError {
    match at {
        Some(at) => error.at(at),
        None => error,
    }
}

fn invalid(reason: String) -> SpecError {
    SpecError::InvalidValue { reason }
}

/// Runs every rule of this module on a spec that parsed.
pub(crate) fn validate(spec: &Spec, places: &Places) -> Result<(), SpecError> {
    check_count(spec.checks.len())?;
    check_metadata(&spec.metadata, places)?;
    if let Some(bundle) = &spec.bundle {
        check_bundle(bundle, places)?;
    }
    check_hosts(spec)
}

/// 1 to [`MAX_CHECKS`] checks. Also used by the reader on its own count, before the typed read.
pub(crate) fn check_count(count: usize) -> Result<(), SpecError> {
    if count == 0 {
        return Err(SpecError::NoChecks);
    }
    if count > MAX_CHECKS {
        return Err(SpecError::TooManyChecks {
            count,
            limit: MAX_CHECKS,
        });
    }
    Ok(())
}

fn check_metadata(metadata: &Metadata, places: &Places) -> Result<(), SpecError> {
    let too_long = |key: &str, text: &str, limit: usize| {
        let found = text.chars().count();
        (found > limit).then(|| {
            placed(
                invalid(format!(
                    "metadata.{key} is {found} characters. The limit is {limit}"
                )),
                places.of_metadata(key),
            )
        })
    };
    if metadata.version.as_deref() == Some("") {
        return Err(placed(
            invalid(
                "metadata.version is empty. Write a version such as '>=4.2', or remove the key"
                    .to_owned(),
            ),
            places.of_metadata("version"),
        ));
    }
    if let Some(error) = metadata
        .version
        .as_deref()
        .and_then(|v| too_long("version", v, MAX_VERSION_CHARS))
        .or_else(|| {
            metadata
                .contact
                .as_deref()
                .and_then(|c| too_long("contact", c, MAX_CONTACT_CHARS))
        })
    {
        return Err(error);
    }
    if metadata.annotations.len() > MAX_ANNOTATIONS {
        return Err(placed(
            invalid(format!(
                "metadata.annotations has {} entries. The limit is {MAX_ANNOTATIONS}",
                metadata.annotations.len()
            )),
            places.of_metadata("annotations"),
        ));
    }
    for (key, value) in &metadata.annotations {
        let key_ok = key.chars().count() <= 63
            && key.starts_with(|c: char| c.is_ascii_lowercase() || c.is_ascii_digit())
            && key.chars().all(|c| {
                c.is_ascii_lowercase() || c.is_ascii_digit() || matches!(c, '.' | '_' | '/' | '-')
            });
        if !key_ok || value.chars().count() > MAX_ANNOTATION_VALUE_CHARS {
            return Err(placed(
                invalid(format!(
                    "the annotation '{}' is not allowed: a key is 1 to 63 characters from a-z, 0-9, . _ / and -, \
                     starting with a letter or digit, and a value is at most {MAX_ANNOTATION_VALUE_CHARS} characters",
                    echo_safe(key)
                )),
                places.of_metadata("annotations"),
            ));
        }
    }
    if let Some(expires) = &metadata.expires
        && parse_utc(expires).is_none()
    {
        return Err(placed(SpecError::BadExpires, places.of_metadata("expires")));
    }
    Ok(())
}

fn check_bundle(bundle: &BundleSpec, places: &Places) -> Result<(), SpecError> {
    let too_many = |name: &str, count: usize, limit: usize, at: Option<Location>| {
        (count > limit).then(|| {
            placed(
                invalid(format!(
                    "bundle.{name} has {count} entries. The limit is {limit}"
                )),
                at,
            )
        })
    };
    // The first collector over the limit is the one to remove. The other lists are not placed.
    let first_extra = places.collect.get(MAX_COLLECT).copied();
    if let Some(error) = too_many("collect", bundle.collect.len(), MAX_COLLECT, first_extra)
        .or_else(|| too_many("redact", bundle.redact.len(), MAX_REDACT, None))
        .or_else(|| {
            too_many(
                "redact_patterns",
                bundle.redact_patterns.len(),
                MAX_REDACT_PATTERNS,
                None,
            )
        })
    {
        return Err(error);
    }
    for (index, item) in bundle.collect.iter().enumerate() {
        if let Err(reason) = check_collector(item) {
            return Err(placed(invalid(reason), places.collect.get(index).copied()));
        }
    }
    for group in &bundle.redact {
        if !is_redact_name(group) {
            return Err(invalid(format!(
                "the redact group '{}' is not a name. {REDACT_NAME_RULE}",
                echo_safe(group)
            )));
        }
    }
    for pattern in &bundle.redact_patterns {
        if !is_redact_name(&pattern.name) {
            return Err(invalid(format!(
                "the redact pattern name '{}' is not allowed. {REDACT_NAME_RULE}",
                echo_safe(&pattern.name)
            )));
        }
        let chars = pattern.regex.chars().count();
        if chars == 0 || chars > MAX_REGEX_CHARS {
            return Err(invalid(format!(
                "the regex of redact pattern '{}' must have 1 to {MAX_REGEX_CHARS} characters",
                echo_safe(&pattern.name)
            )));
        }
    }
    Ok(())
}

const REDACT_NAME_RULE: &str =
    "A name is 1 to 32 characters from a-z, 0-9 and _, starting with a letter";

/// `^[a-z][a-z0-9_]{0,31}$`, the schema's rule for a redact group and a redact pattern name.
fn is_redact_name(name: &str) -> bool {
    name.len() <= 32
        && name.starts_with(|c: char| c.is_ascii_lowercase())
        && name
            .chars()
            .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '_')
}

/// The grammar of a `bundle.collect` item (01 section 2.8). The reason is safe to print.
fn check_collector(item: &str) -> Result<(), String> {
    if item == "k8s:events" {
        return Ok(());
    }
    if let Some(span) = item.strip_prefix("journal:") {
        return Duration::parse(span).map(drop).map_err(|_| {
            format!(
                "the collector '{}' needs a duration after journal:, such as journal:7d",
                echo_safe(item)
            )
        });
    }
    if let Some(path) = item.strip_prefix("file:") {
        return check_collector_path(path).map_err(|why| {
            format!(
                "the collector '{}' is not allowed: {why}. Write file: and then an absolute path, such as file:/etc/acme/*.yaml",
                echo_safe(item)
            )
        });
    }
    Err(format!(
        "'{}' is not a collector. Use journal:<duration>, k8s:events or file:<absolute path>",
        echo_safe(item)
    ))
}

fn check_collector_path(path: &str) -> Result<(), &'static str> {
    // The schema allows a path that starts with `/` only. A Windows path form arrives with the bundle
    // collectors of M2, in the schema and here together.
    if !path.starts_with('/') {
        return Err("the path is not absolute");
    }
    if path.chars().count() > MAX_PATH_CHARS {
        return Err("the path is too long");
    }
    // U+2028 and U+2029 are not control characters to Rust, but they break a line in a log or a page.
    if path
        .chars()
        .any(|c| c.is_control() || matches!(c, '\u{2028}' | '\u{2029}'))
    {
        return Err("the path has a control character");
    }
    // A backslash is refused until the Windows path form lands (M2), so `\..\` never passes as a name.
    if path.contains('\\') {
        return Err("the path has a backslash");
    }
    if path.split('/').any(|part| part == "..") {
        return Err("the path has a '..' part");
    }
    Ok(())
}

fn check_hosts(spec: &Spec) -> Result<(), SpecError> {
    let named = named_endpoints(spec);
    if named.hosts.len() > MAX_HOSTS {
        return Err(SpecError::TooManyHosts {
            count: named.hosts.len(),
            limit: MAX_HOSTS,
        });
    }
    if named.pairs.len() > MAX_ENDPOINTS {
        return Err(SpecError::TooManyEndpoints {
            count: named.pairs.len(),
            limit: MAX_ENDPOINTS,
        });
    }
    Ok(())
}

/// What the net checks of a spec name, collected up to one past each limit.
#[derive(Debug, Default)]
pub(crate) struct Named {
    /// Distinct lowercase hosts across `net.egress`, `net.tls_intercept` and `net.dns`. Collection stops
    /// at [`MAX_HOSTS`] plus one, because that is already a refusal.
    pub(crate) hosts: HashSet<String>,
    /// Distinct host and port pairs across `net.egress` and `net.tls_intercept`. Collection stops at
    /// [`MAX_ENDPOINTS`] plus one.
    pub(crate) pairs: HashSet<(String, u16)>,
}

impl Named {
    fn host(&mut self, host: String) {
        if self.hosts.len() <= MAX_HOSTS {
            self.hosts.insert(host);
        }
    }

    fn endpoint(&mut self, host: String, port: u16) {
        if self.hosts.len() > MAX_HOSTS {
            return;
        }
        if self.pairs.len() <= MAX_ENDPOINTS {
            self.pairs.insert((host.clone(), port));
        }
        self.host(host);
    }
}

/// Every distinct host and every distinct host and port pair that `net.egress`, `net.tls_intercept` and
/// `net.dns` entries name, anywhere in the spec. A host named by several checks, or by several endpoints
/// on different ports, counts once as a host. DNS names have no port and add no pairs.
///
/// A check that decodes is read through its typed parameters. A check of these three ids that does not
/// decode (a list of 65, a mistyped key) is skipped at run time, but it is still counted from its raw
/// parameters, so a spec cannot hide hosts in entries that fail to decode. See the module documentation.
pub(crate) fn named_endpoints(spec: &Spec) -> Named {
    let mut named = Named::default();
    for check in &spec.checks {
        match check.decode_params() {
            CheckParams::NetEgress(p) => {
                for e in &p.endpoints {
                    named.endpoint(e.target.host().to_string(), e.target.port());
                }
            }
            CheckParams::NetTlsIntercept(p) => {
                for h in p.hosts.iter().flatten() {
                    named.endpoint(h.host().to_string(), h.port().unwrap_or(DEFAULT_TLS_PORT));
                }
            }
            CheckParams::NetDns(p) => {
                for rule in &p.names {
                    named.host(host_key(rule.name.as_str()).0);
                }
            }
            CheckParams::Unsupported { id, fields, .. } => {
                let (key, inner, has_port) = match id.as_str() {
                    "net.egress" => ("endpoints", Some("target"), true),
                    "net.tls_intercept" => ("hosts", None, true),
                    "net.dns" => ("names", Some("name"), false),
                    _ => continue,
                };
                for text in listed_texts(&fields, key, inner) {
                    let (host, port) = host_key(text);
                    if has_port {
                        named.endpoint(host, port);
                    } else {
                        named.host(host);
                    }
                }
            }
            _ => {}
        }
    }
    named
}

/// The texts in the list at `key`. An item is a string, or an object whose `inner` key holds the string.
/// Anything else is not a host and is left to the check's own decoding.
fn listed_texts<'a>(
    params: &'a Map<String, Value>,
    key: &str,
    inner: Option<&'a str>,
) -> impl Iterator<Item = &'a str> {
    params
        .get(key)
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .filter_map(move |item| match item {
            Value::String(text) => Some(text.as_str()),
            Value::Object(fields) => fields.get(inner?).and_then(Value::as_str),
            _ => None,
        })
}

/// The identity of an endpoint for counting: the lowercase host and the port of a target (`host:port`,
/// `[v6]:port` or a URL), of a bare host (port 443), or the lowercase text itself and port 0 when it
/// reads as neither.
fn host_key(text: &str) -> (String, u16) {
    Target::parse(text)
        .or_else(|_| Target::parse(&format!("{text}:{DEFAULT_TLS_PORT}")))
        .map_or_else(
            |_| (text.to_ascii_lowercase(), 0),
            |t| (t.host().to_string(), t.port()),
        )
}

#[cfg(test)]
mod tests;
