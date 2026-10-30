//! What `k8s.storageclass` takes from the objects it reads, before any judgement.
//!
//! Every text that comes from the server is held as it came and shown only through [`token`], which keeps a
//! Kubernetes-looking name and replaces anything else, so a class called `` `rm -rf` `` cannot reach a
//! fix text or a terminal.

use k8s_openapi::api::core::v1::{Event, PersistentVolumeClaim};
use k8s_openapi::api::storage::v1::{CSINode, StorageClass};
use k8s_openapi::jiff::Timestamp;

/// The default-class annotation, and the legacy one.
const DEFAULT_ANNOTATIONS: [&str; 2] = [
    "storageclass.kubernetes.io/is-default-class",
    "storageclass.beta.kubernetes.io/is-default-class",
];

/// The longest server text that goes into a sentence, in characters.
const SHOWN: usize = 64;

/// A server text made safe for a sentence and for a command in a fix: letters, digits and `. _ / - :`
/// stay, anything else becomes `?`, and the result is cut at 64 characters.
pub(super) fn token(text: &str) -> String {
    let mut out: String = text
        .chars()
        .take(SHOWN)
        .map(|c| {
            if c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '/' | '-' | ':') {
                c
            } else {
                '?'
            }
        })
        .collect();
    if text.chars().count() > SHOWN {
        out.push_str("...");
    }
    out
}

/// How a read ended. A refusal for this identity and a missing object are answers.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) enum Read<T> {
    /// The object or list.
    Ok(T),
    /// 403: the identity may not read it.
    Forbidden,
    /// 404: it does not exist.
    Missing,
    /// Any other status of the server.
    Unreadable(u16),
}

/// A page of a list, and whether the server had more.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct Page<T> {
    pub(super) items: Vec<T>,
    /// A `continue` token came back: the list is longer than the page.
    pub(super) more: bool,
}

/// How a class binds volumes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum Binding {
    /// When the claim is made. This is the default.
    Immediate,
    /// When a pod uses the claim.
    WaitForFirstConsumer,
}

impl Binding {
    pub(super) fn word(self) -> &'static str {
        match self {
            Self::Immediate => "Immediate",
            Self::WaitForFirstConsumer => "WaitForFirstConsumer",
        }
    }
}

/// What happens to a volume when its claim goes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum Reclaim {
    /// The volume is deleted. This is the default.
    Delete,
    /// The volume is kept.
    Retain,
    /// The old `Recycle` policy, or a word this build does not know.
    Other,
}

impl Reclaim {
    pub(super) fn word(self) -> &'static str {
        match self {
            Self::Delete => "Delete",
            Self::Retain => "Retain",
            Self::Other => "an unknown policy",
        }
    }
}

/// One class, reduced to what the check judges.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct Class {
    pub(super) name: String,
    pub(super) provisioner: String,
    /// The default marker, either annotation, set to exactly `true` (as the API server reads it).
    pub(super) default: bool,
    pub(super) created: Option<Timestamp>,
    pub(super) binding: Binding,
    pub(super) expansion: bool,
    pub(super) reclaim: Reclaim,
}

impl Class {
    pub(super) fn from_object(object: &StorageClass) -> Option<Self> {
        let name = object.metadata.name.clone()?;
        let default = object.metadata.annotations.as_ref().is_some_and(|notes| {
            DEFAULT_ANNOTATIONS
                .iter()
                .any(|key| notes.get(*key).is_some_and(|value| value == "true"))
        });
        let binding = match object.volume_binding_mode.as_deref() {
            Some("WaitForFirstConsumer") => Binding::WaitForFirstConsumer,
            _ => Binding::Immediate,
        };
        let reclaim = match object.reclaim_policy.as_deref() {
            None | Some("Delete") => Reclaim::Delete,
            Some("Retain") => Reclaim::Retain,
            Some(_) => Reclaim::Other,
        };
        Some(Self {
            name,
            provisioner: object.provisioner.clone(),
            default,
            created: object.metadata.creation_timestamp.as_ref().map(|t| t.0),
            binding,
            expansion: object.allow_volume_expansion == Some(true),
            reclaim,
        })
    }
}

/// How many nodes registered a driver, out of the `CSINode` objects read.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) struct Registered {
    pub(super) with_driver: usize,
    pub(super) read: usize,
}

impl Registered {
    /// Counts the `CSINode` objects of `page` that list `driver`.
    pub(super) fn count(page: &Page<CSINode>, driver: &str) -> Self {
        let with_driver = page
            .items
            .iter()
            .filter(|node| node.spec.drivers.iter().any(|d| d.name == driver))
            .count();
        Self {
            with_driver,
            read: page.items.len(),
        }
    }
}

/// A claim that has waited, and what the events say about it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct Waiting {
    pub(super) name: String,
    pub(super) minutes: i64,
    /// An event with reason `ProvisioningFailed` names this claim.
    pub(super) failed: bool,
}

/// How long a claim must be `Pending` before it counts (03).
pub(super) const PENDING_AFTER_SECONDS: i64 = 5 * 60;

/// The claims of `claims` that are `Pending` for 5 minutes or more at `now` and use `class`. A claim with
/// no class name uses the default class, so it counts when `class_is_default`.
pub(super) fn pending_claims(
    claims: &[PersistentVolumeClaim],
    class: &str,
    class_is_default: bool,
    now: Timestamp,
) -> Vec<(String, i64)> {
    let mut out = Vec::new();
    for claim in claims {
        let Some(name) = claim.metadata.name.clone() else {
            continue;
        };
        let pending = claim
            .status
            .as_ref()
            .and_then(|status| status.phase.as_deref())
            == Some("Pending");
        if !pending {
            continue;
        }
        let uses = match claim
            .spec
            .as_ref()
            .and_then(|s| s.storage_class_name.as_deref())
        {
            Some(named) => named == class,
            None => class_is_default,
        };
        let Some(created) = claim.metadata.creation_timestamp.as_ref().map(|t| t.0) else {
            continue;
        };
        let age = now.as_second() - created.as_second();
        if uses && age >= PENDING_AFTER_SECONDS {
            out.push((name, age / 60));
        }
    }
    out.sort();
    out
}

/// Marks the claims that an event with reason `ProvisioningFailed` names.
pub(super) fn with_failures(claims: Vec<(String, i64)>, events: &[Event]) -> Vec<Waiting> {
    claims
        .into_iter()
        .map(|(name, minutes)| {
            let failed = events.iter().any(|event| {
                event.reason.as_deref() == Some("ProvisioningFailed")
                    && event.involved_object.kind.as_deref() == Some("PersistentVolumeClaim")
                    && event.involved_object.name.as_deref() == Some(name.as_str())
            });
            Waiting {
                name,
                minutes,
                failed,
            }
        })
        .collect()
}
