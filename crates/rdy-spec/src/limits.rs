//! Structural limits and semantic rules for a parsed spec (01 sections 2.1, 2.2, 2.5 and 2.8, threat
//! model INV-11).
//!
//! The YAML reader (`parse.rs`) refuses what a spec file must not contain. This module refuses what a
//! well-formed spec must not say:
//!
//! - 1 to [`MAX_CHECKS`] checks;
//! - at most [`MAX_HOSTS`] distinct hosts across every `net.egress` endpoint, `net.tls_intercept` host
//!   and `net.dns` name in the whole spec;
//! - `metadata.version` and `metadata.contact` within their lengths, at most 32 `annotations`, and
//!   `expires` in the full UTC form;
//! - the `bundle` block within its list sizes, with collectors that fit the grammar of 01 section 2.8
//!   (`journal:<duration>`, `k8s:events`, `file:<absolute path or glob>` with no `..` segment).
//!
//! The host count reads the raw parameters of the three net checks and not their typed form. A check
//! that does not decode (a mistyped key, a list of 65) is skipped at run time, but a spec that names 65
//! hosts is still refused as a whole, so a vendor sees the problem in lint and sign and the limit does
//! not depend on how a neighbouring check happens to decode. When a host cannot be read as a
//! [`Target`], its lowercase text counts as one host. That can only make the count larger.
//!
//! Not here: compiling `redact_patterns` regexes (M1-031 and M2), expiry against a clock (see
//! [`crate::expiry`]).

use std::collections::{BTreeMap, HashSet};

use serde_json::{Map, Value};

use crate::error::echo_safe;
use crate::expiry::parse_utc;
use crate::spec::{BundleSpec, Metadata, Spec};
use crate::{Duration, Location, SpecError, Target};

/// The most checks in a spec (01 section 2.1).
pub const MAX_CHECKS: usize = 256;

/// The most distinct hosts a spec may name across all of its checks (threat model INV-11).
pub const MAX_HOSTS: usize = 64;

const MAX_VERSION_CHARS: usize = 64;
const MAX_CONTACT_CHARS: usize = 256;
const MAX_ANNOTATIONS: usize = 32;
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
    for pattern in &bundle.redact_patterns {
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
    let mut chars = path.chars();
    let absolute = match (chars.next(), chars.next(), chars.next()) {
        (Some('/'), _, _) => true,
        (Some(drive), Some(':'), Some('\\')) => drive.is_ascii_alphabetic(),
        _ => false,
    };
    if !absolute {
        return Err("the path is not absolute");
    }
    if path.chars().count() > MAX_PATH_CHARS {
        return Err("the path is too long");
    }
    if path.chars().any(char::is_control) {
        return Err("the path has a control character");
    }
    if path.split(['/', '\\']).any(|part| part == "..") {
        return Err("the path has a '..' part");
    }
    Ok(())
}

fn check_hosts(spec: &Spec) -> Result<(), SpecError> {
    let count = spec_hosts(spec).len();
    if count > MAX_HOSTS {
        return Err(SpecError::TooManyHosts {
            count,
            limit: MAX_HOSTS,
        });
    }
    Ok(())
}

/// Every distinct host that `net.egress`, `net.tls_intercept` and `net.dns` entries name, anywhere in the
/// spec. A host named by several checks, or by several endpoints on different ports, counts once.
///
/// This reads the raw parameters. See the module documentation for why.
pub(crate) fn spec_hosts(spec: &Spec) -> HashSet<String> {
    let mut hosts = HashSet::new();
    for check in &spec.checks {
        let (key, inner) = match check.id.as_str() {
            "net.egress" => ("endpoints", Some("target")),
            "net.tls_intercept" => ("hosts", None),
            "net.dns" => ("names", Some("name")),
            _ => continue,
        };
        hosts.extend(listed_texts(&check.params, key, inner).map(host_key));
    }
    hosts
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

/// The identity of a host for counting: the lowercase host of a target (`host:port`, `[v6]:port` or a
/// URL), of a bare host, or the text itself when it reads as neither.
fn host_key(text: &str) -> String {
    Target::parse(text)
        .or_else(|_| Target::parse(&format!("{text}:443")))
        .map_or_else(|_| text.to_ascii_lowercase(), |t| t.host().to_string())
}

#[cfg(test)]
mod tests;
