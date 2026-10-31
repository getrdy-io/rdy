//! What the check keeps of a `ResourceQuota` and a `LimitRange`.
//!
//! Everything else in the objects is dropped while reading: annotations, labels, owner references and the
//! resources the check has no need for. What stays is text from the server, so it is held as text and
//! made safe (`judge::shown`) before it reaches a sentence.

use std::collections::BTreeMap;

use k8s_openapi::api::core::v1::{LimitRange, ResourceQuota};

/// The most scope names kept for one quota.
const MAX_SCOPES: usize = 8;

/// One page of a list, and whether the server said there was more.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct Page<T> {
    pub(super) items: Vec<T>,
    /// True when the list has a next page that was not read.
    pub(super) cut: bool,
}

/// A quota, as far as the check reads it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct Quota {
    pub(super) name: String,
    /// The scopes of the quota: `spec.scopes` and the scope names of `spec.scopeSelector`. A quota with
    /// any scope applies only to the pods it selects.
    pub(super) scopes: Vec<String>,
    /// True when the quota has `scopes` or a `scopeSelector`, whatever they name.
    pub(super) scoped: bool,
    /// `spec.hard`, or `status.hard` when the spec has none.
    pub(super) hard: BTreeMap<String, String>,
    /// `status.used`, when the quota controller has filled it in.
    pub(super) used: Option<BTreeMap<String, String>>,
}

/// A quota object as the check keeps it.
pub(super) fn quota_of(quota: ResourceQuota) -> Quota {
    let name = quota
        .metadata
        .name
        .unwrap_or_else(|| "<unnamed>".to_owned());
    let mut scopes: Vec<String> = Vec::new();
    let mut scoped = false;
    let mut hard = BTreeMap::new();
    if let Some(spec) = quota.spec {
        if let Some(listed) = spec.scopes {
            scoped |= !listed.is_empty();
            scopes.extend(listed);
        }
        if let Some(selector) = spec.scope_selector {
            let expressions = selector.match_expressions.unwrap_or_default();
            scoped |= !expressions.is_empty();
            scopes.extend(expressions.into_iter().map(|e| e.scope_name));
        }
        if let Some(map) = spec.hard {
            hard = map.into_iter().map(|(k, v)| (k, v.0)).collect();
        }
    }
    let mut used = None;
    if let Some(status) = quota.status {
        if hard.is_empty()
            && let Some(map) = status.hard
        {
            hard = map.into_iter().map(|(k, v)| (k, v.0)).collect();
        }
        used = status
            .used
            .map(|map| map.into_iter().map(|(k, v)| (k, v.0)).collect());
    }
    scopes.truncate(MAX_SCOPES);
    Quota {
        name,
        scopes,
        scoped,
        hard,
        used,
    }
}

/// The memory amounts of one `LimitRange` item, as the server wrote them.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub(super) struct MemoryLimits {
    pub(super) max: Option<String>,
    pub(super) min: Option<String>,
    /// The limit given to a container that sets none.
    pub(super) default: Option<String>,
}

/// One item of a limit range: its type and its memory amounts.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct LimitItem {
    /// `Container`, `Pod`, `PersistentVolumeClaim` or whatever the server sent.
    pub(super) kind: String,
    pub(super) memory: MemoryLimits,
}

/// A limit range, as far as the check reads it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct Limits {
    pub(super) name: String,
    pub(super) items: Vec<LimitItem>,
}

/// A limit range object as the check keeps it.
pub(super) fn limits_of(range: LimitRange) -> Limits {
    let name = range
        .metadata
        .name
        .unwrap_or_else(|| "<unnamed>".to_owned());
    let items = range
        .spec
        .map(|spec| spec.limits)
        .unwrap_or_default()
        .into_iter()
        .map(|item| {
            let memory =
                |map: Option<
                    BTreeMap<String, k8s_openapi::apimachinery::pkg::api::resource::Quantity>,
                >| { map.and_then(|mut map| map.remove("memory")).map(|q| q.0) };
            LimitItem {
                kind: item.type_,
                memory: MemoryLimits {
                    max: memory(item.max),
                    min: memory(item.min),
                    default: memory(item.default),
                },
            }
        })
        .collect();
    Limits { name, items }
}
