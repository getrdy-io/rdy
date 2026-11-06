//! The Docker and Podman Engine API replies, read from redacted JSON text.
//!
//! The caller passes text that came back through `Probe::unix_text`, so a proxy URL with a password
//! is already masked. These functions keep only a handful of named fields and cap every string.
//! Anything they do not understand is `None`, never a guess.

use rdy_spec::check::CgroupDriver;
use serde_json::Value;

use super::clip;

/// Which engine answered `GET /version`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum Product {
    Docker,
    Podman,
}

/// What `GET /version` said.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct VersionReply {
    pub product: Product,
    pub version: Option<String>,
}

/// What `GET /info` said, field by field.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub(super) struct InfoReply {
    pub server_version: Option<String>,
    pub storage_driver: Option<String>,
    pub cgroup_driver: Option<CgroupDriver>,
    /// `Supports d_type` from `DriverStatus`, when the driver reports it.
    pub d_type: Option<bool>,
    /// `name=rootless` in `SecurityOptions`, when the list is there.
    pub rootless: Option<bool>,
    pub http_proxy: Option<String>,
    pub https_proxy: Option<String>,
    pub no_proxy: Option<String>,
}

fn text_of(value: Option<&Value>) -> Option<String> {
    let text = value?.as_str()?.trim();
    (!text.is_empty()).then(|| clip(text))
}

/// The driver named by `native.cgroupdriver=...`, or a plain word.
pub(super) fn driver_word(word: &str) -> Option<CgroupDriver> {
    match word.trim().to_ascii_lowercase().as_str() {
        "systemd" => Some(CgroupDriver::Systemd),
        "cgroupfs" => Some(CgroupDriver::Cgroupfs),
        _ => None,
    }
}

/// Reads a `GET /version` body. `None` when it is not a JSON object.
pub(super) fn parse_version(text: &str) -> Option<VersionReply> {
    let root: Value = serde_json::from_str(text).ok()?;
    let object = root.as_object()?;
    let components = object.get("Components").and_then(Value::as_array);
    let named = |needle: &str| {
        components.is_some_and(|list| {
            list.iter().any(|c| {
                c.get("Name")
                    .and_then(Value::as_str)
                    .is_some_and(|n| n.to_ascii_lowercase().contains(needle))
            })
        })
    };
    let product = if named("podman") {
        Product::Podman
    } else {
        Product::Docker
    };
    // The engine component is the most exact; the top-level `Version` is the same number on Docker.
    let engine = components.and_then(|list| {
        list.iter()
            .find(|c| {
                c.get("Name").and_then(Value::as_str).is_some_and(|n| {
                    let n = n.to_ascii_lowercase();
                    n == "engine" || n.contains("podman")
                })
            })
            .and_then(|c| text_of(c.get("Version")))
    });
    let version = engine.or_else(|| text_of(object.get("Version")));
    Some(VersionReply { product, version })
}

/// Reads a `GET /info` body. `None` when it is not a JSON object.
pub(super) fn parse_info(text: &str) -> Option<InfoReply> {
    let root: Value = serde_json::from_str(text).ok()?;
    let object = root.as_object()?;
    let d_type = object
        .get("DriverStatus")
        .and_then(Value::as_array)
        .and_then(|rows| {
            rows.iter().find_map(|row| {
                let pair = row.as_array()?;
                let key = pair.first()?.as_str()?.trim();
                if !key.eq_ignore_ascii_case("supports d_type") {
                    return None;
                }
                match pair.get(1)?.as_str()?.trim().to_ascii_lowercase().as_str() {
                    "true" => Some(true),
                    "false" => Some(false),
                    _ => None,
                }
            })
        });
    let rootless = object
        .get("SecurityOptions")
        .and_then(Value::as_array)
        .map(|options| {
            options
                .iter()
                .filter_map(Value::as_str)
                .any(|o| o.split(',').any(|part| part.trim() == "name=rootless"))
        });
    Some(InfoReply {
        server_version: text_of(object.get("ServerVersion")),
        storage_driver: text_of(object.get("Driver")),
        cgroup_driver: object
            .get("CgroupDriver")
            .and_then(Value::as_str)
            .and_then(driver_word),
        d_type,
        rootless,
        http_proxy: text_of(object.get("HttpProxy")),
        https_proxy: text_of(object.get("HttpsProxy")),
        no_proxy: text_of(object.get("NoProxy")),
    })
}
