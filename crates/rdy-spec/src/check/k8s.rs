//! Parameters of the six M1 Kubernetes check ids.
//!
//! The fields, ranges and defaults follow `$defs` in `crates/rdy-spec/schema/spec.v1.schema.json` and
//! the table in `docs/plan/01-spec-format.md` section 2.7. What each threshold means to the check is in
//! `docs/plan/03-check-catalog.md`.
//!
//! Every struct refuses a key it does not have. That includes `needs` on `k8s.storageclass`, an alias
//! that draft 1 had and 01 removed: it is `access_modes` now. Where 01 requires a key or a group of
//! keys (`can` of `k8s.rbac`, and the "one of" groups of `k8s.nodes` and `k8s.version`), an entry
//! without them decodes to [`UnsupportedReason::NoThreshold`](super::UnsupportedReason::NoThreshold).
//! The other three read bare.
//!
//! A list or an object that is empty would be a threshold that measures nothing, so it is refused
//! where it can stand for one: `apis`, `arch`, `can`, and `per_node` and `free` with no resource.

use std::collections::BTreeMap;
use std::num::NonZeroU32;

use serde::{Deserialize, Deserializer};
use serde_json::{Map, Value};

use super::ParamSet;
use super::common::{Arch, BoundedList, RegexText, from_value};
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
        #[derive(Debug, Clone, PartialEq, Eq, Hash)]
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
/// namespace or a name: it uses the `namespace` of the entry.
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
    /// The namespace of the object. For a string item this is the `namespace` of the entry.
    pub namespace: Option<K8sName>,
    /// The name of the object.
    pub name: Option<K8sName>,
}

/// Splits `verb resource[.group][/subresource]` into the keys of the object form, or `None` when the
/// text has another shape. The values are checked by their own types afterwards.
fn rbac_string_to_object(text: &str) -> Option<Map<String, Value>> {
    let (verb, rest) = text.split_once(' ')?;
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
        let object = match Value::deserialize(deserializer)? {
            value @ Value::Object(_) => value,
            Value::String(text) => {
                rbac_string_to_object(&text)
                    .map(Value::Object)
                    .ok_or_else(|| {
                        bad(format!(
                            "'{}' is not a permission: write it like 'create namespaces' \
                     or 'create clusterroles.rbac.authorization.k8s.io'",
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
    pub can: BoundedList<RbacRule, 100, false, 1>,
    /// The namespace for the string items. The default is cluster scope.
    pub namespace: Option<K8sName>,
}

impl ParamSet for K8sRbac {
    const FIELDS: &'static [&'static str] = &["can", "namespace"];
    const THRESHOLD: &'static [&'static str] = &["can"];
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
    /// Pods a node can run.
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
    /// An older server blocks.
    pub min: Option<Version>,
    /// A newer server warns, or blocks with `over_max: block`.
    pub max: Option<Version>,
    /// The lowest OpenShift version, used when the cluster is OpenShift.
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

#[cfg(test)]
mod tests;
