//! Pod Security levels, the labels of a namespace, and the level the product needs.
//!
//! The rules here follow the Pod Security admission plugin of Kubernetes (`PolicyToEvaluate` in
//! `k8s.io/pod-security-admission/api`):
//!
//! - A label value that is not `privileged`, `baseline` or `restricted` is an error for the namespace. For
//!   `enforce` the plugin then reads `restricted` (it fails closed). For `warn` and `audit` it reads
//!   `privileged` (it fails open).
//! - A missing `enforce` label means the cluster default, which lives in the API server's admission
//!   configuration and cannot be read through the API.
//! - A missing `warn` label means the cluster default too, except that an explicit valid `enforce` label
//!   that is stricter than that default makes `warn` follow it. `audit` never follows. The check judges
//!   `enforce` first and `warn` only when the label is set, so the follow rule never changes an answer.
//!
//! The levels are ordered by strictness: `privileged`, then `baseline`, then `restricted`.

use std::collections::BTreeMap;

use rdy_spec::check::{K8sAdmission, PodFeature, PodSecurityLevel};

/// The label prefix of Pod Security admission.
const PREFIX: &str = "pod-security.kubernetes.io/";

/// A Pod Security Standard. The order is the order of strictness.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub(super) enum Standard {
    /// No restrictions.
    Privileged,
    /// Known privilege escalations are blocked: no hostPath, host namespaces or privileged containers.
    Baseline,
    /// Current hardening practice, including `runAsNonRoot`.
    Restricted,
}

impl Standard {
    /// The word the labels and the spec use.
    pub(super) fn name(self) -> &'static str {
        match self {
            Self::Privileged => "privileged",
            Self::Baseline => "baseline",
            Self::Restricted => "restricted",
        }
    }

    fn parse(value: &str) -> Option<Self> {
        match value {
            "privileged" => Some(Self::Privileged),
            "baseline" => Some(Self::Baseline),
            "restricted" => Some(Self::Restricted),
            _ => None,
        }
    }

    /// The level of the spec. A level this build does not know is left out, so the check does not judge on it.
    fn from_spec(level: PodSecurityLevel) -> Option<Self> {
        match level {
            PodSecurityLevel::Privileged => Some(Self::Privileged),
            PodSecurityLevel::Baseline => Some(Self::Baseline),
            PodSecurityLevel::Restricted => Some(Self::Restricted),
            _ => None,
        }
    }
}

/// One of the three mode labels of a namespace.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum Label {
    /// The label is not set.
    Absent,
    /// A valid level.
    Valid(Standard),
    /// A value that is not a level. The server's text is never kept.
    Invalid,
}

impl Label {
    fn of(labels: &BTreeMap<String, String>, mode: &str) -> Self {
        match labels.get(&format!("{PREFIX}{mode}")) {
            None => Self::Absent,
            Some(value) => Standard::parse(value).map_or(Self::Invalid, Self::Valid),
        }
    }

    /// The word for a report: the level, `invalid` or `none`.
    pub(super) fn word(self) -> &'static str {
        match self {
            Self::Absent => "none",
            Self::Valid(level) => level.name(),
            Self::Invalid => "invalid",
        }
    }
}

/// The Pod Security labels of a namespace.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) struct Labels {
    pub(super) enforce: Label,
    pub(super) audit: Label,
    pub(super) warn: Label,
    /// The `enforce-version` label, when it is `latest` or `v1.N`; `invalid` for any other value.
    pub(super) enforce_version: Version,
}

/// The `enforce-version` label.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum Version {
    Absent,
    Latest,
    /// `v1.N`.
    Minor(u32),
    Invalid,
}

impl Version {
    fn of(labels: &BTreeMap<String, String>) -> Self {
        let Some(value) = labels.get(&format!("{PREFIX}enforce-version")) else {
            return Self::Absent;
        };
        if value == "latest" {
            return Self::Latest;
        }
        value
            .strip_prefix("v1.")
            .filter(|minor| {
                !minor.is_empty()
                    && minor.bytes().all(|b| b.is_ascii_digit())
                    && (minor == &"0" || !minor.starts_with('0'))
            })
            .and_then(|minor| minor.parse().ok())
            .map_or(Self::Invalid, Self::Minor)
    }

    /// The word for a report, `None` when the label is not set.
    pub(super) fn word(self) -> Option<String> {
        match self {
            Self::Absent => None,
            Self::Latest => Some("latest".to_owned()),
            Self::Minor(minor) => Some(format!("v1.{minor}")),
            Self::Invalid => Some("invalid".to_owned()),
        }
    }
}

impl Labels {
    pub(super) fn from_map(labels: &BTreeMap<String, String>) -> Self {
        Self {
            enforce: Label::of(labels, "enforce"),
            audit: Label::of(labels, "audit"),
            warn: Label::of(labels, "warn"),
            enforce_version: Version::of(labels),
        }
    }
}

/// The level the product needs, and why.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct Need {
    pub(super) level: Standard,
    /// The features of the spec that need this level, in the words of a sentence.
    pub(super) because: Vec<&'static str>,
    /// The `uses` of the spec, in the spec's own words, for the report.
    pub(super) uses: Vec<&'static str>,
}

/// The lowest level a feature runs at, and the words for it.
fn feature(feature: PodFeature) -> Option<(Standard, &'static str, &'static str)> {
    match feature {
        PodFeature::HostPath => Some((Standard::Privileged, "hostPath", "hostPath volumes")),
        PodFeature::HostNetwork => Some((Standard::Privileged, "hostNetwork", "host networking")),
        PodFeature::HostPid => Some((Standard::Privileged, "hostPID", "the host PID namespace")),
        PodFeature::Privileged => {
            Some((Standard::Privileged, "privileged", "privileged containers"))
        }
        PodFeature::RunAsRoot => Some((
            Standard::Baseline,
            "runAsRoot",
            "containers that run as root",
        )),
        _ => None,
    }
}

/// The level the product needs: the most permissive of the spec's `pod_security` and the level of every
/// feature in `uses`. `None` when the spec says neither.
///
/// "Needs" runs the other way from strictness: a product that needs `privileged` cannot run in a namespace
/// that enforces `baseline`. If the spec states `baseline` and also uses hostPath, the spec contradicts
/// itself, and the answer is `privileged`, because a pass on the weaker need would be a wrong pass.
pub(super) fn need_of(params: &K8sAdmission) -> Option<Need> {
    let stated = params.pod_security.and_then(Standard::from_spec);
    let features: Vec<(Standard, &'static str, &'static str)> = params
        .uses
        .as_ref()
        .map(|uses| uses.iter().filter_map(|f| feature(*f)).collect())
        .unwrap_or_default();
    // The product needs the most permissive level of anything it states. `Privileged` sorts lowest, so
    // that is the minimum.
    let level = features
        .iter()
        .map(|(level, _, _)| *level)
        .chain(stated)
        .min()?;
    let because = features
        .iter()
        .filter(|(feature_level, _, _)| *feature_level == level)
        .map(|(_, _, words)| *words)
        .collect();
    let uses = features.iter().map(|(_, name, _)| *name).collect();
    Some(Need {
        level,
        because,
        uses,
    })
}
