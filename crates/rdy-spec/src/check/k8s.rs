//! Parameters of the Kubernetes check ids: the six M1 ids and the five M1-late ids.
//!
//! The fields, ranges and defaults follow `$defs` in `crates/rdy-spec/schema/spec.v1.schema.json` and
//! the table in `docs/plan/01-spec-format.md` section 2.7. What each threshold means to the check is in
//! `docs/plan/03-check-catalog.md`.
//!
//! Every struct refuses a key it does not have. That includes `needs` on `k8s.storageclass`, an alias
//! that draft 1 had and 01 removed: it is `access_modes` now. Where 01 requires a key or a group of
//! keys (`can` of `k8s.rbac`, and the "one of" groups of `k8s.nodes`, `k8s.version` and `k8s.crds`), an
//! entry without them decodes to
//! [`UnsupportedReason::NoThreshold`](super::UnsupportedReason::NoThreshold). The others read bare.
//!
//! A list or an object that is empty would be a threshold that measures nothing, so it is refused
//! where it can stand for one: `apis`, `arch`, `can`, `quota_needs`, and `per_node`, `free` and
//! `limit_needs` with no resource.

use std::collections::BTreeMap;
use std::num::NonZeroU32;

use serde::{Deserialize, Deserializer};
use serde_json::{Map, Value};

use super::ParamSet;
use super::common::{Arch, BoundedList, BoundedMap, HostPort, RegexText, from_value};
use super::net::Cidr;
use crate::error::echo_safe;
use crate::scalar::{Duration, Quantity, Version};

/// Builds a deserialize error from a message.
fn bad<E: serde::de::Error>(message: impl std::fmt::Display) -> E {
    E::custom(message)
}

/// A Kubernetes object name: a DNS subdomain of 1 to 253 characters. It has dot-separated labels of 1 to
/// 63 characters from `a-z`, `0-9` and `-`, and each label starts and ends with a letter or digit.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct K8sName(String);

impl K8sName {
    /// The name as written.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl<'de> Deserialize<'de> for K8sName {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let text = String::deserialize(deserializer)?;
        if is_k8s_name(&text) {
            Ok(Self(text))
        } else {
            Err(bad(format!(
                "'{}' is not a Kubernetes name: use 1 to 253 characters from a-z, 0-9, - and ., \
                 in dot-separated parts of up to 63 characters that start and end with a letter or digit",
                echo_safe(&text)
            )))
        }
    }
}

/// The rule of [`K8sName`]. It is also the rule for the prefix of a label key.
fn is_k8s_name(text: &str) -> bool {
    let inner = |c: char| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-';
    let edge = |c: char| c.is_ascii_lowercase() || c.is_ascii_digit();
    // A DNS subdomain: dot-separated labels, each 1 to 63 characters, each starting and ending with a
    // letter or digit. So `a..b`, `a-.b` and `.a` are refused.
    (1..=253).contains(&text.chars().count())
        && text.split('.').all(|label| {
            (1..=63).contains(&label.chars().count())
                && label.chars().all(inner)
                && label.chars().next().is_some_and(edge)
                && label.chars().next_back().is_some_and(edge)
        })
}

/// The name part of a label key, or a non-empty label value: 1 to 63 characters of letters, digits, `-`,
/// `_` and `.`, starting and ending with a letter or digit.
fn is_label_part(text: &str) -> bool {
    let inner = |c: char| c.is_ascii_alphanumeric() || matches!(c, '-' | '_' | '.');
    (1..=63).contains(&text.chars().count())
        && text.chars().all(inner)
        && text
            .chars()
            .next()
            .is_some_and(|c| c.is_ascii_alphanumeric())
        && text
            .chars()
            .next_back()
            .is_some_and(|c| c.is_ascii_alphanumeric())
}

/// A Kubernetes qualified name: `name`, or `prefix/name` with a DNS-style prefix. It is the grammar of
/// label keys and taint keys, so a control or bidirectional character cannot be in one.
fn is_qualified_name(text: &str) -> bool {
    match text.split_once('/') {
        Some((prefix, name)) => is_k8s_name(prefix) && is_label_part(name),
        None => is_label_part(text),
    }
}

/// A Kubernetes label value: empty, or a label part.
fn is_label_value(text: &str) -> bool {
    text.is_empty() || is_label_part(text)
}

/// Parameters of `k8s.access`: can rdy reach the cluster with the current context.
///
/// Every key is optional. With none, the check only reports what it finds.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
#[non_exhaustive]
pub struct K8sAccess {
    /// The current kube context must match this pattern, a guard against the wrong cluster.
    pub context_pattern: Option<RegexText>,
    /// The API server URL must match this pattern.
    pub server_pattern: Option<RegexText>,
    /// A reply slower than this: the check warns. The default, 2s, is the check's.
    pub max_latency: Option<Duration>,
}

impl ParamSet for K8sAccess {
    const FIELDS: &'static [&'static str] = &["context_pattern", "server_pattern", "max_latency"];
    const REGEX_FIELDS: &'static [&'static str] = &["context_pattern", "server_pattern"];
}

/// A volume access mode.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Deserialize)]
#[non_exhaustive]
pub enum AccessMode {
    /// One node reads and writes.
    ReadWriteOnce,
    /// Many nodes read.
    ReadOnlyMany,
    /// Many nodes read and write.
    ReadWriteMany,
    /// One pod reads and writes.
    ReadWriteOncePod,
}

/// When a volume is bound.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash, Deserialize)]
#[non_exhaustive]
pub enum VolumeBinding {
    /// When a pod uses the claim.
    WaitForFirstConsumer,
    /// When the claim is made.
    Immediate,
    /// Either is fine. This is the default.
    #[default]
    #[serde(rename = "any")]
    Any,
}

/// What happens to a volume when its claim is deleted.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Deserialize)]
#[non_exhaustive]
pub enum ReclaimPolicy {
    /// The volume is kept.
    Retain,
    /// The volume is deleted.
    Delete,
}

/// Parameters of `k8s.storageclass`: a storage class the product can use.
///
/// Every key is optional. With none, the check looks for a usable default class.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
#[non_exhaustive]
pub struct K8sStorageClass {
    /// A class that must exist. The default is the cluster's default class.
    pub class: Option<K8sName>,
    /// Access modes the class must serve, 1 to 4.
    pub access_modes: Option<BoundedList<AccessMode, 4, true, 1>>,
    /// The binding mode the class must have. The default is [`VolumeBinding::Any`].
    #[serde(default)]
    pub binding: VolumeBinding,
    /// The class must allow expansion.
    pub expansion: Option<bool>,
    /// The reclaim policy the class should have. A mismatch warns.
    pub reclaim_policy: Option<ReclaimPolicy>,
}

impl ParamSet for K8sStorageClass {
    const FIELDS: &'static [&'static str] = &[
        "class",
        "access_modes",
        "binding",
        "expansion",
        "reclaim_policy",
    ];
}

/// Defines a text value of 1 to `$max` characters from a closed alphabet.
macro_rules! lower_text {
    ($(#[$meta:meta])* $name:ident, max $max:literal, $alphabet:literal, $allowed:expr) => {
        $(#[$meta])*
        #[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
        pub struct $name(String);

        impl $name {
            /// The text as written.
            #[must_use]
            pub fn as_str(&self) -> &str {
                &self.0
            }
        }

        impl<'de> Deserialize<'de> for $name {
            fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
                let text = String::deserialize(deserializer)?;
                let allowed: fn(char) -> bool = $allowed;
                if (1..=$max).contains(&text.chars().count()) && text.chars().all(allowed) {
                    Ok(Self(text))
                } else {
                    Err(bad(format!(
                        "'{}' does not fit: use 1 to {} characters from {}",
                        echo_safe(&text),
                        $max,
                        $alphabet
                    )))
                }
            }
        }
    };
}

lower_text!(
    /// An RBAC verb such as `create`, or `*`.
    RbacVerb, max 63, "a-z and *", |c| c.is_ascii_lowercase() || c == '*'
);

lower_text!(
    /// An RBAC resource such as `namespaces`, or `*`.
    RbacResource, max 253, "a-z, 0-9, - and *", |c| c.is_ascii_lowercase() || c.is_ascii_digit() || matches!(c, '-' | '*')
);

lower_text!(
    /// An RBAC subresource such as `log`.
    RbacSubresource, max 63, "a-z", |c| c.is_ascii_lowercase()
);

/// An API group such as `apps` or `rbac.authorization.k8s.io`. Empty is the core group.
#[derive(Debug, Clone, Default, PartialEq, Eq, Hash)]
pub struct ApiGroup(String);

impl ApiGroup {
    /// The group as written. Empty is the core group.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl<'de> Deserialize<'de> for ApiGroup {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let text = String::deserialize(deserializer)?;
        let fits = |c: char| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-' || c == '.';
        if text.chars().count() <= 253 && text.chars().all(fits) {
            Ok(Self(text))
        } else {
            Err(bad(format!(
                "'{}' is not an API group: use up to 253 characters from a-z, 0-9, - and .",
                echo_safe(&text)
            )))
        }
    }
}

/// One thing the install identity must be allowed to do.
///
/// In a spec it is a string like `create namespaces` or `get pods/log`, or an object. The string is
/// `verb resource[.group][/subresource]`, as in `kubectl auth can-i`. A string cannot carry a
/// namespace or a name: it uses the `namespace` of the entry, unless it names a cluster-scoped resource.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub struct RbacRule {
    /// The verb.
    pub verb: RbacVerb,
    /// The API group. Empty, which is the default, is the core group.
    pub group: ApiGroup,
    /// The resource.
    pub resource: RbacResource,
    /// The subresource, such as `log`.
    pub subresource: Option<RbacSubresource>,
    /// The namespace of the object. A string item cannot name one: it takes the `namespace` of the entry
    /// (see [`RbacRule::from_text`]), and this is `None`.
    pub namespace: Option<K8sName>,
    /// The name of the object.
    pub name: Option<K8sName>,
    /// True when the item was written as a string such as `create namespaces`. Only a string item takes
    /// the `namespace` of the entry. An object item names its own namespace or none.
    pub from_text: bool,
}

/// Splits `verb resource[.group][/subresource]` into the keys of the object form, or `None` when the
/// text has another shape. The values are checked by their own types afterwards.
fn rbac_string_to_object(text: &str) -> Option<Map<String, Value>> {
    let (verb, rest) = text.split_once(' ')?;
    if rest.starts_with('/') {
        // `get /healthz`: a non-resource URL.
        let mut map = Map::new();
        map.insert("verb".to_owned(), Value::from(verb));
        map.insert("path".to_owned(), Value::from(rest));
        return Some(map);
    }
    let (resource_group, subresource) = match rest.split_once('/') {
        Some((head, sub)) => (head, Some(sub)),
        None => (rest, None),
    };
    let (resource, group) = match resource_group.split_once('.') {
        Some((resource, group)) if !group.is_empty() => (resource, Some(group)),
        Some(_) => return None,
        None => (resource_group, None),
    };
    let mut map = Map::new();
    map.insert("verb".to_owned(), Value::from(verb));
    map.insert("resource".to_owned(), Value::from(resource));
    if let Some(group) = group {
        map.insert("group".to_owned(), Value::from(group));
    }
    if let Some(sub) = subresource {
        map.insert("subresource".to_owned(), Value::from(sub));
    }
    Some(map)
}

/// A non-resource URL such as `/healthz` or `/metrics`, or a prefix that ends in `*` such as `/logs/*`.
///
/// It starts with `/`, has 1 to 253 characters from `A-Z`, `a-z`, `0-9`, `-`, `.`, `_`, `~` and `/`,
/// may end in one `*` (the `*` is one of the 253), and has no `//` and no `..`.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct NonResourcePath(String);

impl NonResourcePath {
    /// The path as written.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl<'de> Deserialize<'de> for NonResourcePath {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let text = String::deserialize(deserializer)?;
        let body = text.strip_suffix('*').unwrap_or(&text);
        let fits = |c: char| c.is_ascii_alphanumeric() || matches!(c, '-' | '.' | '_' | '~' | '/');
        if text.starts_with('/')
            && text.chars().count() <= 253
            && body.chars().all(fits)
            && !text.contains("//")
            && !text.contains("..")
        {
            Ok(Self(text))
        } else {
            Err(bad(format!(
                "'{}' is not a non-resource path: start with /, use up to 253 characters from \
                 letters, digits, - . _ ~ and /, and end with * only for a prefix",
                echo_safe(&text)
            )))
        }
    }
}

/// A non-resource URL the install identity must be allowed to reach, such as `get /healthz`.
///
/// In a spec it is a string like `get /metrics` or an object `{verb, path}`.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub struct NonResourceRule {
    /// The verb, usually `get`.
    pub verb: RbacVerb,
    /// The URL path.
    pub path: NonResourcePath,
}

/// One thing the install identity must be allowed to do: a verb on a resource ([`RbacRule`]) or on a
/// URL that is not a resource ([`NonResourceRule`]).
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum RbacItem {
    /// A verb on a resource.
    Resource(RbacRule),
    /// A verb on a URL that is not a resource.
    NonResource(NonResourceRule),
}

impl RbacItem {
    /// The resource rule, if this item is one.
    #[must_use]
    pub fn as_resource(&self) -> Option<&RbacRule> {
        match self {
            Self::Resource(rule) => Some(rule),
            Self::NonResource(_) => None,
        }
    }
}

impl<'de> Deserialize<'de> for RbacItem {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        #[derive(Deserialize)]
        #[serde(deny_unknown_fields)]
        struct NonResource {
            verb: RbacVerb,
            path: NonResourcePath,
        }
        let value = Value::deserialize(deserializer)?;
        let non_resource = match &value {
            Value::Object(map) => map.contains_key("path"),
            Value::String(text) => text
                .split_once(' ')
                .is_some_and(|(_, rest)| rest.starts_with('/')),
            _ => false,
        };
        if !non_resource {
            return from_value(value).map(Self::Resource);
        }
        let object = match value {
            Value::String(text) => rbac_string_to_object(&text)
                .map(Value::Object)
                .ok_or_else(|| bad("a non-resource permission is written like 'get /healthz'"))?,
            other => other,
        };
        let full: NonResource = from_value(object)?;
        Ok(Self::NonResource(NonResourceRule {
            verb: full.verb,
            path: full.path,
        }))
    }
}

impl<'de> Deserialize<'de> for RbacRule {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        #[derive(Deserialize)]
        #[serde(deny_unknown_fields)]
        struct Full {
            verb: RbacVerb,
            #[serde(default)]
            group: ApiGroup,
            resource: RbacResource,
            subresource: Option<RbacSubresource>,
            namespace: Option<K8sName>,
            name: Option<K8sName>,
        }
        let mut from_text = false;
        let object = match Value::deserialize(deserializer)? {
            value @ Value::Object(_) => value,
            Value::String(text) => {
                from_text = true;
                rbac_string_to_object(&text)
                    .map(Value::Object)
                    .ok_or_else(|| {
                        bad(format!(
                            "'{}' is not a permission: write it like 'create namespaces' \
                     or 'create clusterroles.rbac.authorization.k8s.io' or 'get /healthz'",
                            echo_safe(&text)
                        ))
                    })?
            }
            other => {
                return Err(bad(format!(
                    "a permission is a string like 'create namespaces' or an object, not {}",
                    match other {
                        Value::Null => "null",
                        Value::Bool(_) => "a boolean",
                        Value::Number(_) => "a number",
                        _ => "a list",
                    }
                )));
            }
        };
        let full: Full = from_value(object)?;
        Ok(Self {
            verb: full.verb,
            group: full.group,
            resource: full.resource,
            subresource: full.subresource,
            namespace: full.namespace,
            name: full.name,
            from_text,
        })
    }
}

/// Parameters of `k8s.rbac`: what the install identity may do.
///
/// `can` is required.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
#[non_exhaustive]
pub struct K8sRbac {
    /// The permissions to test, 1 to 100. Each one is an entry in the audit log of the cluster.
    pub can: BoundedList<RbacItem, 100, false, 1>,
    /// The namespace for the string items. An object item names its own namespace. A string item that
    /// names a well-known cluster-scoped resource (`namespaces`, `nodes`, `clusterroles`) does not take
    /// it. The default is cluster scope.
    pub namespace: Option<K8sName>,
    /// The service account to test as (`as:`), `system:serviceaccount:<namespace>:<name>`, for example
    /// `system:serviceaccount:acme-system:installer`. The reviews are sent with `Impersonate-User` when the
    /// identity in the kubeconfig may impersonate it, so the check answers for the install identity before
    /// it exists as a kubeconfig. M1 takes a service account only.
    #[serde(rename = "as")]
    pub as_user: Option<ImpersonatedUser>,
}

impl ParamSet for K8sRbac {
    const FIELDS: &'static [&'static str] = &["can", "namespace", "as"];
    const THRESHOLD: &'static [&'static str] = &["can"];
}

/// The service account a `k8s.rbac` entry tests as: `system:serviceaccount:<namespace>:<name>`.
///
/// The namespace has 1 to 63 characters from `a-z`, `0-9` and `-`, the name 1 to 253 from `a-z`, `0-9`, `-`
/// and `.`, and the whole is 253 characters at most. The check applies the exact DNS-1123 rules. M1 takes
/// a service account only: the server derives its groups, and rdy sends no `Impersonate-Group`, so a plain
/// user would lose the grants it holds through groups.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct ImpersonatedUser(String);

impl ImpersonatedUser {
    /// The user as written.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl<'de> Deserialize<'de> for ImpersonatedUser {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let text = String::deserialize(deserializer)?;
        let fits = text
            .strip_prefix("system:serviceaccount:")
            .and_then(|rest| rest.split_once(':'))
            .is_some_and(|(namespace, name)| {
                (1..=63).contains(&namespace.len())
                    && namespace
                        .bytes()
                        .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
                    && (1..=253).contains(&name.len())
                    && name.bytes().all(|b| {
                        b.is_ascii_lowercase() || b.is_ascii_digit() || matches!(b, b'-' | b'.')
                    })
            });
        if fits && text.len() <= 253 {
            Ok(Self(text))
        } else {
            Err(bad(format!(
                "'{}' is not a service account: write system:serviceaccount:<namespace>:<name>. \
                 M1 takes no other user",
                echo_safe(&text)
            )))
        }
    }
}

/// A Pod Security level.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Deserialize)]
#[serde(rename_all = "lowercase")]
#[non_exhaustive]
pub enum PodSecurityLevel {
    /// No restrictions.
    Privileged,
    /// Known privilege escalations are blocked.
    Baseline,
    /// Current hardening practice is required.
    Restricted,
}

/// A pod feature that decides the lowest Pod Security level the product can run at.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Deserialize)]
#[non_exhaustive]
pub enum PodFeature {
    /// A `hostPath` volume.
    #[serde(rename = "hostPath")]
    HostPath,
    /// The host network namespace.
    #[serde(rename = "hostNetwork")]
    HostNetwork,
    /// The host process namespace.
    #[serde(rename = "hostPID")]
    HostPid,
    /// A privileged container.
    #[serde(rename = "privileged")]
    Privileged,
    /// A container that runs as root.
    #[serde(rename = "runAsRoot")]
    RunAsRoot,
}

/// Parameters of `k8s.admission`: what can reject the product's pods.
///
/// Every key is optional. `dry_run` and `probe_pod` are not keys of this version: the read-only guard
/// of ADR 0010 rejects that call.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
#[non_exhaustive]
pub struct K8sAdmission {
    /// The Pod Security level the product's pods need.
    pub pod_security: Option<PodSecurityLevel>,
    /// Pod features the product needs. The check derives the lowest level from them.
    pub uses: Option<BoundedList<PodFeature, 5, true>>,
    /// The namespace the product installs into.
    pub namespace: Option<K8sName>,
    /// The OpenShift security context constraint the product documents.
    pub scc: Option<K8sName>,
}

impl ParamSet for K8sAdmission {
    const FIELDS: &'static [&'static str] = &["pod_security", "uses", "namespace", "scc"];
}

/// An amount of CPU, kept in millicores: `4`, `0.5` or `"500m"`. At least 1m.
///
/// A number is whole or fractional cores with at most three decimals. A string is a whole number of
/// cores, or millicores with an `m`. Either form is 1m to 1000000 cores.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct CpuAmount(u64);

impl CpuAmount {
    /// The amount in millicores.
    #[must_use]
    pub fn millicores(self) -> u64 {
        self.0
    }

    /// The most cores, for the number form and the string form alike.
    const MAX_CORES: u64 = 1_000_000;
    /// The same cap in millicores.
    const MAX_MILLIS: u64 = Self::MAX_CORES * 1000;

    fn from_number(n: &serde_json::Number) -> Option<Self> {
        if let Some(cores) = n.as_u64() {
            return (1..=Self::MAX_CORES)
                .contains(&cores)
                .then(|| Self(cores * 1000));
        }
        let cores = n.as_f64().filter(|c| c.is_finite() && *c > 0.0)?;
        let millis = cores * 1000.0;
        let rounded = millis.round();
        // A fraction of a millicore is not a CPU amount. Allow for the error of the multiplication.
        if (millis - rounded).abs() > 1e-6 || rounded < 1.0 || rounded > 1e9 {
            return None;
        }
        // `rounded` is a whole number from 1 to MAX_MILLIS (1e9), so the cast is exact.
        #[allow(clippy::cast_possible_truncation, clippy::cast_sign_loss)]
        Some(Self(rounded as u64))
    }

    fn from_text(text: &str) -> Option<Self> {
        let (digits, scale) = match text.strip_suffix('m') {
            Some(digits) => (digits, 1),
            None => (text, 1000),
        };
        let shape = (1..=10).contains(&digits.len())
            && digits.bytes().all(|b| b.is_ascii_digit())
            && !digits.starts_with('0');
        if !shape {
            return None;
        }
        let millis = digits.parse::<u64>().ok()?.checked_mul(scale)?;
        (1..=Self::MAX_MILLIS)
            .contains(&millis)
            .then_some(Self(millis))
    }
}

impl<'de> Deserialize<'de> for CpuAmount {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let value = Value::deserialize(deserializer)?;
        let parsed = match &value {
            Value::Number(n) => Self::from_number(n),
            Value::String(text) => Self::from_text(text),
            _ => None,
        };
        parsed.ok_or_else(|| {
            let shown = match &value {
                Value::String(text) => echo_safe(text),
                other => echo_safe(&other.to_string()),
            };
            bad(format!(
                "'{shown}' is not a CPU amount: write cores such as 4 or 0.5, or millicores such as \"500m\""
            ))
        })
    }
}

/// Node resources for `per_node` and `free`. At least one is set.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct K8sResources {
    /// CPU.
    pub cpu: Option<CpuAmount>,
    /// Memory.
    pub memory: Option<Quantity>,
    /// Pod slots.
    pub pods: Option<NonZeroU32>,
    /// Ephemeral storage.
    pub ephemeral: Option<Quantity>,
}

impl<'de> Deserialize<'de> for K8sResources {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        #[derive(Deserialize)]
        #[serde(deny_unknown_fields)]
        struct Raw {
            cpu: Option<CpuAmount>,
            memory: Option<Quantity>,
            pods: Option<NonZeroU32>,
            ephemeral: Option<Quantity>,
        }
        let Raw {
            cpu,
            memory,
            pods,
            ephemeral,
        } = Raw::deserialize(deserializer)?;
        if cpu.is_none() && memory.is_none() && pods.is_none() && ephemeral.is_none() {
            return Err(bad(
                "no resource is set: write at least one of cpu, memory, pods or ephemeral",
            ));
        }
        Ok(Self {
            cpu,
            memory,
            pods,
            ephemeral,
        })
    }
}

/// Node labels that must match, at most 16. A key is a Kubernetes qualified name and a value is a
/// Kubernetes label value.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct LabelSelector(BTreeMap<String, String>);

impl LabelSelector {
    /// The most labels.
    pub const MAX_LABELS: usize = 16;

    /// The labels, by key.
    #[must_use]
    pub fn labels(&self) -> &BTreeMap<String, String> {
        &self.0
    }
}

impl<'de> Deserialize<'de> for LabelSelector {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let map = BTreeMap::<String, String>::deserialize(deserializer)?;
        if map.len() > Self::MAX_LABELS {
            return Err(bad(format!(
                "a selector has at most {} labels, this one has {}",
                Self::MAX_LABELS,
                map.len()
            )));
        }
        for (key, value) in &map {
            if !is_qualified_name(key) {
                return Err(bad(format!(
                    "the label key '{}' does not fit: use a name such as 'role' or \
                     'node-role.kubernetes.io/worker'",
                    echo_safe(key)
                )));
            }
            if !is_label_value(value) {
                return Err(bad(format!(
                    "the value of the label '{}' does not fit: use up to 63 letters, digits, -, _ and ., \
                     starting and ending with a letter or digit",
                    echo_safe(key)
                )));
            }
        }
        Ok(Self(map))
    }
}

/// Whether a toleration matches a value or only a key.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Deserialize)]
#[non_exhaustive]
pub enum TolerationOperator {
    /// The taint has this value.
    Equal,
    /// The taint exists, with any value.
    Exists,
}

/// Which taints a toleration covers.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Deserialize)]
#[non_exhaustive]
pub enum TaintEffect {
    /// New pods are not scheduled.
    NoSchedule,
    /// New pods are avoided if possible.
    PreferNoSchedule,
    /// Running pods are evicted.
    NoExecute,
}

/// A toleration, which lets the product's pods use tainted nodes. It has the keys of a pod's toleration,
/// except `tolerationSeconds`, and Kubernetes' own rules: without a `key` the operator must be `Exists`,
/// and with `Exists` there is no `value`. A toleration with no key and `Exists` matches every taint, the
/// control-plane taint too.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub struct Toleration {
    /// The taint key. Without it the operator is `Exists` and every taint matches.
    pub key: Option<LabelKey>,
    /// How the value is compared. Kubernetes treats a missing operator as `Equal`.
    pub operator: Option<TolerationOperator>,
    /// The taint value. Not with `Exists`.
    pub value: Option<LabelValue>,
    /// The effect to tolerate. Without it every effect matches.
    pub effect: Option<TaintEffect>,
}

impl<'de> Deserialize<'de> for Toleration {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        #[derive(Deserialize)]
        #[serde(deny_unknown_fields)]
        struct Raw {
            key: Option<LabelKey>,
            operator: Option<TolerationOperator>,
            value: Option<LabelValue>,
            effect: Option<TaintEffect>,
        }
        let Raw {
            key,
            operator,
            value,
            effect,
        } = Raw::deserialize(deserializer)?;
        let exists = operator == Some(TolerationOperator::Exists);
        if key.is_none() && !exists {
            return Err(bad(
                "a toleration without a key must have operator Exists, which matches every taint",
            ));
        }
        if exists && value.as_ref().is_some_and(|v| !v.as_str().is_empty()) {
            return Err(bad(
                "a toleration with operator Exists has no value: remove it, or use operator Equal",
            ));
        }
        Ok(Self {
            key,
            operator,
            value,
            effect,
        })
    }
}

/// A label key or a taint key: a Kubernetes qualified name, up to 317 characters. It is `name`, or
/// `prefix/name` with a lowercase DNS-style prefix.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct LabelKey(String);

impl LabelKey {
    /// The key as written.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl<'de> Deserialize<'de> for LabelKey {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let text = String::deserialize(deserializer)?;
        if is_qualified_name(&text) {
            Ok(Self(text))
        } else {
            Err(bad(format!(
                "'{}' is not a key: use a name such as 'gpu' or 'node-role.kubernetes.io/worker'",
                echo_safe(&text)
            )))
        }
    }
}

/// A taint value: a Kubernetes label value, empty or up to 63 letters, digits, `-`, `_` and `.`,
/// starting and ending with a letter or digit.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct LabelValue(String);

impl LabelValue {
    /// The value as written.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl<'de> Deserialize<'de> for LabelValue {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let text = String::deserialize(deserializer)?;
        if is_label_value(&text) {
            Ok(Self(text))
        } else {
            Err(bad(format!(
                "'{}' is not a value: use up to 63 letters, digits, -, _ and ., \
                 starting and ending with a letter or digit",
                echo_safe(&text)
            )))
        }
    }
}

/// Parameters of `k8s.nodes`: ready nodes and their size.
///
/// At least one of `min_ready`, `per_node` and `free` is required.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
#[non_exhaustive]
pub struct K8sNodes {
    /// Fewer ready nodes than this: the check fails.
    pub min_ready: Option<NonZeroU32>,
    /// Fewer zones than this: the check fails. Without zone labels it is not evaluated.
    pub min_zones: Option<NonZeroU32>,
    /// Each counted node must have at least this much allocatable. These are allocatable amounts, not
    /// the size of the instance.
    pub per_node: Option<K8sResources>,
    /// The counted nodes together must have at least this much left after the pods' requests.
    pub free: Option<K8sResources>,
    /// The architectures the counted nodes may have, 1 to 4. `amd64` is `x86_64`.
    pub arch: Option<BoundedList<Arch, 4, true, 1>>,
    /// Only nodes with these labels are counted.
    pub selector: Option<LabelSelector>,
    /// Tolerations that make tainted nodes count, at most 16.
    pub tolerations: Option<BoundedList<Toleration, 16>>,
}

impl ParamSet for K8sNodes {
    const FIELDS: &'static [&'static str] = &[
        "min_ready",
        "min_zones",
        "per_node",
        "free",
        "arch",
        "selector",
        "tolerations",
    ];
    const THRESHOLD: &'static [&'static str] = &["min_ready", "per_node", "free"];
}

/// What a server newer than `max` counts as.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash, Deserialize)]
#[serde(rename_all = "lowercase")]
#[non_exhaustive]
pub enum OverMax {
    /// It warns. This is the default.
    #[default]
    Warn,
    /// It blocks.
    Block,
}

/// A served API, written `group/version Kind` or `version Kind` for the core group.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct ApiRef {
    group: Option<String>,
    version: String,
    kind: String,
}

impl ApiRef {
    /// The longest reference in characters.
    pub const MAX_CHARS: usize = 320;

    /// The group, or `None` for the core group.
    #[must_use]
    pub fn group(&self) -> Option<&str> {
        self.group.as_deref()
    }

    /// The version, such as `v1` or `v2beta1`.
    #[must_use]
    pub fn version(&self) -> &str {
        &self.version
    }

    /// The kind, such as `Ingress`.
    #[must_use]
    pub fn kind(&self) -> &str {
        &self.kind
    }

    fn parse(text: &str) -> Option<Self> {
        if text.chars().count() > Self::MAX_CHARS {
            return None;
        }
        let (api, kind) = text.split_once(' ')?;
        let (group, version) = match api.split_once('/') {
            Some((group, version)) => (Some(group), version),
            None => (None, api),
        };
        let group_ok = group.is_none_or(|g| {
            !g.is_empty()
                && g.bytes()
                    .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'.' || b == b'-')
        });
        let version_ok = version.strip_prefix('v').is_some_and(|rest| {
            !rest.is_empty()
                && rest
                    .bytes()
                    .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit())
        });
        let kind_ok = kind.bytes().next().is_some_and(|b| b.is_ascii_uppercase())
            && kind.bytes().all(|b| b.is_ascii_alphanumeric());
        (group_ok && version_ok && kind_ok).then(|| Self {
            group: group.map(str::to_owned),
            version: version.to_owned(),
            kind: kind.to_owned(),
        })
    }
}

impl<'de> Deserialize<'de> for ApiRef {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let text = String::deserialize(deserializer)?;
        Self::parse(&text).ok_or_else(|| {
            bad(format!(
                "'{}' is not an API: write it like 'networking.k8s.io/v1 Ingress' or 'v1 Pod'",
                echo_safe(&text)
            ))
        })
    }
}

/// Parameters of `k8s.version`: the server version and the APIs it serves.
///
/// At least one of `min`, `max`, `openshift_min` and `apis` is required.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
#[non_exhaustive]
pub struct K8sVersion {
    /// An older server blocks. This is a Kubernetes version. On OpenShift, `openshift_min` replaces it when
    /// both are set.
    pub min: Option<Version>,
    /// A newer server warns, or blocks with `over_max: block`.
    pub max: Option<Version>,
    /// The lowest OpenShift version, used when the cluster is OpenShift. On an OpenShift cluster it replaces
    /// `min`: `min` is a Kubernetes version, and OpenShift 4.14 reports Kubernetes 1.27, so `min` is not
    /// applied there. `max` still applies to the Kubernetes version. On any other cluster `openshift_min` is
    /// ignored.
    pub openshift_min: Option<Version>,
    /// APIs the server must serve, 1 to 64.
    pub apis: Option<BoundedList<ApiRef, 64, false, 1>>,
    /// What a server newer than `max` counts as. The default is [`OverMax::Warn`].
    #[serde(default)]
    pub over_max: OverMax,
}

impl ParamSet for K8sVersion {
    const FIELDS: &'static [&'static str] = &["min", "max", "openshift_min", "apis", "over_max"];
    const THRESHOLD: &'static [&'static str] = &["min", "max", "openshift_min", "apis"];
}

// ---- the M1-late ids ----------------------------------------------------------------------------

lower_text!(
    /// The name of a resource in a quota, such as `requests.cpu`, `pods` or `count/jobs.batch`.
    QuotaResource, max 253, "letters, 0-9, -, _, . and /", |c| c.is_ascii_alphanumeric() || matches!(c, '-' | '_' | '.' | '/')
);

/// An amount in the Kubernetes quantity form, such as `16`, `500m`, `0.5` or `64Gi`.
///
/// The text is a number, with at most a decimal part, and one suffix of `m`, `k`, `M`, `G`, `T`, `P`,
/// `E`, `Ki`, `Mi`, `Gi`, `Ti`, `Pi` or `Ei`. It is not negative and is at most 20 characters. A bare YAML
/// number is accepted too. The text is kept as written, and the check reads it with the rules of the
/// Kubernetes API, the same ones it uses for the amounts a cluster reports.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct K8sQuantity(String);

impl K8sQuantity {
    /// The longest amount in characters.
    pub const MAX_CHARS: usize = 20;

    /// The largest bare number.
    const MAX_NUMBER: f64 = 1e15;

    /// The same limit for a whole number.
    const MAX_WHOLE: u64 = 1_000_000_000_000_000;

    /// The amount as written.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }

    fn is_valid(text: &str) -> bool {
        const SUFFIXES: [&str; 14] = [
            "", "m", "k", "M", "G", "T", "P", "E", "Ki", "Mi", "Gi", "Ti", "Pi", "Ei",
        ];
        let numeral = |b: u8| b.is_ascii_digit();
        let end = text
            .find(|c: char| !(c.is_ascii_digit() || c == '.'))
            .unwrap_or(text.len());
        let (number, suffix) = text.split_at(end);
        let number_ok = match number.split_once('.') {
            Some((whole, fraction)) => {
                whole.bytes().all(numeral) && !fraction.is_empty() && fraction.bytes().all(numeral)
            }
            None => !number.is_empty(),
        };
        text.len() <= Self::MAX_CHARS && number_ok && SUFFIXES.contains(&suffix)
    }
}

impl<'de> Deserialize<'de> for K8sQuantity {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let value = Value::deserialize(deserializer)?;
        let text = match &value {
            Value::String(text) => Some(text.clone()),
            Value::Number(n) => n
                .as_u64()
                .filter(|n| *n <= Self::MAX_WHOLE)
                .map(|n| n.to_string())
                .or_else(|| {
                    n.as_f64()
                        .filter(|f| (0.0..=Self::MAX_NUMBER).contains(f))
                        .map(|f| f.to_string())
                }),
            _ => None,
        };
        match text {
            Some(text) if Self::is_valid(&text) => Ok(Self(text)),
            _ => {
                let shown = match &value {
                    Value::String(text) => echo_safe(text),
                    other => echo_safe(&other.to_string()),
                };
                Err(bad(format!(
                    "'{shown}' is not an amount: write a number with an optional suffix, \
                     such as 16, \"500m\" or \"64Gi\""
                )))
            }
        }
    }
}

/// The `LimitRange` sizes that `k8s.namespace` checks. At least one is set.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct LimitNeeds {
    /// The memory of the largest container the product runs. A `LimitRange` maximum below it blocks.
    pub container_max_memory: Option<Quantity>,
}

impl<'de> Deserialize<'de> for LimitNeeds {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        #[derive(Deserialize)]
        #[serde(deny_unknown_fields)]
        struct Raw {
            container_max_memory: Option<Quantity>,
        }
        let Raw {
            container_max_memory,
        } = Raw::deserialize(deserializer)?;
        if container_max_memory.is_none() {
            return Err(bad("no limit is set: write container_max_memory"));
        }
        Ok(Self {
            container_max_memory,
        })
    }
}

/// Whether a quota resource counts bytes: `requests.memory`, `limits.memory`, `requests.storage`,
/// `requests.ephemeral-storage`, `hugepages-2Mi` and the per storage class form
/// `fast.storageclass.storage.k8s.io/requests.storage`. The last part of the name decides.
fn counts_bytes(resource: &str) -> bool {
    let last = resource.rsplit(['.', '/']).next().unwrap_or(resource);
    matches!(last, "memory" | "storage" | "ephemeral-storage") || last.starts_with("hugepages-")
}

/// Reads `quota_needs` and applies the strict size grammar to the resources that count bytes.
fn quota_needs<'de, D: Deserializer<'de>>(
    deserializer: D,
) -> Result<Option<BoundedMap<QuotaResource, K8sQuantity, 32, 1>>, D::Error> {
    let needs = Option::<BoundedMap<QuotaResource, K8sQuantity, 32, 1>>::deserialize(deserializer)?;
    for (resource, amount) in needs.iter().flat_map(|map| map.iter()) {
        if counts_bytes(resource.as_str()) {
            Quantity::parse(amount.as_str()).map_err(|error| {
                bad(format!(
                    "'{}' for '{}' is not a size in bytes: {}",
                    echo_safe(amount.as_str()),
                    echo_safe(resource.as_str()),
                    error.hint()
                ))
            })?;
        }
    }
    Ok(needs)
}

/// Parameters of `k8s.namespace`: the namespace, its quota and its limit range.
///
/// Every key is optional. With none, the check looks at the namespace of the family and reports what
/// it finds.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
#[non_exhaustive]
pub struct K8sNamespace {
    /// The namespace the product installs into.
    pub namespace: Option<K8sName>,
    /// What the product needs from the quota of the namespace, by quota resource, 1 to 32. A quota
    /// with less left blocks.
    ///
    /// An amount of memory, storage, ephemeral storage or huge pages is read with the strict size
    /// grammar of the rest of the spec (01 section 2.5): a whole number with an optional binary suffix
    /// (`64Gi`). `64G`, `500m` and `0.5Gi` are refused, because the decimal and binary forms differ by
    /// 7 percent and a milli-byte is a mistake. Other resources, such as `requests.cpu` (`500m`) and
    /// `pods`, keep the Kubernetes form.
    #[serde(default, deserialize_with = "quota_needs")]
    pub quota_needs: Option<BoundedMap<QuotaResource, K8sQuantity, 32, 1>>,
    /// What the product needs from the limit range of the namespace.
    pub limit_needs: Option<LimitNeeds>,
}

impl ParamSet for K8sNamespace {
    const FIELDS: &'static [&'static str] = &["namespace", "quota_needs", "limit_needs"];
}

/// The version of a custom resource, such as `v1` or `v1beta1`: a `v` and lowercase letters and digits.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct CrdVersion(String);

impl CrdVersion {
    /// The version as written.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl<'de> Deserialize<'de> for CrdVersion {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let text = String::deserialize(deserializer)?;
        let shape = text.strip_prefix('v').is_some_and(|rest| {
            (1..=62).contains(&rest.len())
                && rest
                    .bytes()
                    .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit())
        });
        if shape {
            Ok(Self(text))
        } else {
            Err(bad(format!(
                "'{}' is not an API version: write it like v1 or v1beta1",
                echo_safe(&text)
            )))
        }
    }
}

/// A custom resource definition that must be installed.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Deserialize)]
#[serde(deny_unknown_fields)]
#[non_exhaustive]
pub struct CrdRule {
    /// The name of the definition, such as `certificates.cert-manager.io`.
    pub name: K8sName,
    /// Versions the definition must serve, 1 to 16, none twice. Without it any version counts.
    pub versions: Option<BoundedList<CrdVersion, 16, true, 1>>,
}

/// An operator whose deployment must run.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Deserialize)]
#[serde(deny_unknown_fields)]
#[non_exhaustive]
pub struct OperatorRule {
    /// The namespace of the deployment.
    pub namespace: K8sName,
    /// The name of the deployment.
    pub deployment: K8sName,
    /// An older operator blocks. It is read from the image tag or the version label of the deployment.
    pub min_version: Option<Version>,
}

/// Parameters of `k8s.crds`: the custom resources and operators the product needs.
///
/// At least one of `crds` and `operators` is required.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
#[non_exhaustive]
pub struct K8sCrds {
    /// Definitions that must be installed, 1 to 64.
    pub crds: Option<BoundedList<CrdRule, 64, false, 1>>,
    /// Operators that must run, 1 to 16.
    pub operators: Option<BoundedList<OperatorRule, 16, false, 1>>,
}

impl ParamSet for K8sCrds {
    const FIELDS: &'static [&'static str] = &["crds", "operators"];
    const THRESHOLD: &'static [&'static str] = &["crds", "operators"];
}

lower_text!(
    /// The controller of an `IngressClass`, such as `k8s.io/ingress-nginx`, or `any`.
    IngressController, max 253, "letters, 0-9, -, _, . and /", |c| c.is_ascii_alphanumeric() || matches!(c, '-' | '_' | '.' | '/')
);

/// Whether the Gateway API must be installed.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Deserialize)]
#[serde(rename_all = "lowercase")]
#[non_exhaustive]
pub enum GatewayApi {
    /// Missing blocks, except where the platform has its own ingress.
    Required,
    /// Missing is fine.
    Optional,
}

/// Parameters of `k8s.ingress`: how traffic gets into the cluster.
///
/// Every key is optional. With none, the check reports the ingress classes it finds.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
#[non_exhaustive]
pub struct K8sIngress {
    /// The controller of an `IngressClass` that must exist, such as `k8s.io/ingress-nginx`, or `any`
    /// for any class. It is the `spec.controller` of the class, not its name.
    pub controller: Option<IngressController>,
    /// Whether the Gateway API must be installed.
    pub gateway_api: Option<GatewayApi>,
    /// The product needs an OpenShift `Route`. The default is false.
    #[serde(default)]
    pub route: bool,
    /// The product needs a `LoadBalancer` service, so one that stays pending warns. The default is
    /// false.
    #[serde(default)]
    pub loadbalancer: bool,
}

impl ParamSet for K8sIngress {
    const FIELDS: &'static [&'static str] = &["controller", "gateway_api", "route", "loadbalancer"];
}

/// What the cluster network must do with network policies.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Deserialize)]
#[serde(rename_all = "lowercase")]
#[non_exhaustive]
pub enum NetworkPolicyMode {
    /// The network plugin must enforce `NetworkPolicy`. One that does not blocks.
    Enforced,
}

/// Parameters of `k8s.cni`: the network plugin, network policy and address ranges.
///
/// Every key is optional. With none, the check reports the plugin and the address ranges it finds.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
#[non_exhaustive]
pub struct K8sCni {
    /// What the network plugin must do with network policies.
    pub network_policy: Option<NetworkPolicyMode>,
    /// Destinations the product's pods need to reach, `host:port`, 1 to 64, none twice. A default-deny
    /// policy in the namespace that does not allow them warns. Nothing is connected to.
    pub needs_egress: Option<BoundedList<HostPort, 64, true, 1>>,
    /// Address ranges that the pod and service networks must not overlap, 1 to 32, none twice.
    pub avoid_cidrs: Option<BoundedList<Cidr, 32, true, 1>>,
}

impl ParamSet for K8sCni {
    const FIELDS: &'static [&'static str] = &["network_policy", "needs_egress", "avoid_cidrs"];
}

/// Parameters of `k8s.dns`: the cluster DNS.
///
/// The key is optional.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
#[non_exhaustive]
pub struct K8sDns {
    /// The cluster domain. The default, `cluster.local`, is the check's.
    pub cluster_domain: Option<K8sName>,
}

impl ParamSet for K8sDns {
    const FIELDS: &'static [&'static str] = &["cluster_domain"];
}

#[cfg(test)]
mod tests;
