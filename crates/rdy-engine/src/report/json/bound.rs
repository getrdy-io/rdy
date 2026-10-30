//! The schema's caps on lists and maps, applied to a copy of the report before it is written.
//!
//! The numbers are the ones of `schema/result.v1.schema.json` (M1-041, 01 section 5). The redactor
//! already cut every text and every list inside `observed` and `expected` to 200 items, so this pass
//! only meets what is left: more keys than the schema allows, values nested too deep, texts in the
//! free-form maps over 4 KiB, and lists the redactor does not look at.
//!
//! Every free-form map comes out with its keys sorted. When a map has too many keys, the first ones in
//! that order stay.

use std::collections::BTreeMap;

use rdy_spec::result::{Action, CheckResult, Report};
use serde_json::{Map, Value};

use super::JsonError;
use crate::redact::cap_text;

/// Results in a report (a spec has at most 256 checks).
const MAX_CHECKS: usize = 256;
/// Entries in the action log.
pub(super) const MAX_ACTIONS: usize = 5000;
/// Keys in `actions_dropped` and in `annotations`.
pub(super) const MAX_SMALL_MAP: usize = 32;
/// Keys in `by_rule`.
const MAX_BY_RULE: usize = 64;
/// Items in any other list.
pub(super) const MAX_ITEMS: usize = 1000;
/// Needs on one check.
const MAX_NEEDS: usize = 32;
/// Notes on one check.
const MAX_NOTES: usize = 20;
/// Keys of `observed`, of `expected`, of an action's own fields and of any object inside them.
const MAX_KEYS: usize = 64;
/// Items of a list inside `observed`, `expected` or an action.
const MAX_LIST: usize = 256;
/// Bytes of a text inside `observed`, `expected` or an action.
const MAX_TEXT: usize = 4096;
/// How many levels of list or object a value may hold: the value itself and its children, and the
/// grandchildren are scalars (the schema's `Extra`).
const MAX_DEPTH: usize = 2;
/// What a list or object nested too deep becomes.
const DEEP: &str = "[truncated]";

/// Brings `report` within the schema's caps. A result that lost something gets `truncated: true`.
pub(super) fn bound_report(report: &mut Report) -> Result<(), JsonError> {
    if report.checks.len() > MAX_CHECKS {
        // Cutting results would make the verdict and the summary disagree with the list.
        return Err(JsonError::TooManyChecks {
            found: report.checks.len(),
            max: MAX_CHECKS,
        });
    }
    report.checks.iter_mut().for_each(bound_check);
    report.actions.iter_mut().for_each(bound_action);
    report.capabilities.truncate(MAX_ITEMS);
    if let Some(proxy) = &mut report.proxy {
        proxy.no_proxy.truncate(MAX_ITEMS);
    }
    fold_counts(&mut report.actions_dropped, MAX_SMALL_MAP);
    cap_keys(&mut report.spec.annotations, MAX_SMALL_MAP);
    cap_keys(&mut report.redaction.by_rule, MAX_BY_RULE);
    Ok(())
}

/// Keeps the first `max` keys in order and drops the rest. True if any went.
pub(super) fn cap_keys<V>(map: &mut BTreeMap<String, V>, max: usize) -> bool {
    let mut cut = false;
    while map.len() > max {
        cut |= map.pop_last().is_some();
    }
    cut
}

/// Keeps the first `max` keys of a map of counters. The counters of the keys past that are added to the
/// last key kept, so no count is lost (`actions_dropped` never holds more than a handful of kinds, so
/// this is a guard).
pub(super) fn fold_counts(map: &mut BTreeMap<String, u64>, max: usize) {
    while map.len() > max.max(1) {
        let Some((_, count)) = map.pop_last() else {
            return;
        };
        if let Some(mut last) = map.last_entry() {
            let total = last.get().saturating_add(count);
            *last.get_mut() = total;
        }
    }
}

fn bound_check(check: &mut CheckResult) {
    let mut cut = false;
    cut |= truncate(&mut check.needs, MAX_NEEDS);
    cut |= truncate(&mut check.notes, MAX_NOTES);
    if let Some(fields) = &mut check.unsupported_fields {
        cut |= truncate(fields, MAX_ITEMS);
    }
    if let Some(partial) = &mut check.partial {
        cut |= truncate(&mut partial.missing, MAX_ITEMS);
        cut |= truncate(&mut partial.missing_grants, MAX_ITEMS);
    }
    for map in [&mut check.observed, &mut check.expected]
        .into_iter()
        .flatten()
    {
        cut |= bound_map(map);
    }
    if cut {
        check.truncated = true;
    }
}

/// An action's own fields follow the same bound as `observed`. The entry carries no flag of a cut: its
/// `truncated` field means that the output it names was cut.
fn bound_action(action: &mut Action) {
    bound_map(&mut action.fields);
}

fn truncate<T>(items: &mut Vec<T>, max: usize) -> bool {
    let cut = items.len() > max;
    items.truncate(max);
    cut
}

/// Sorts the keys, keeps the first [`MAX_KEYS`] and bounds every value. True if anything was cut.
pub(super) fn bound_map(map: &mut Map<String, Value>) -> bool {
    let mut cut = sort_and_cap_keys(map);
    for value in map.values_mut() {
        bound_value(value, 0, &mut cut);
    }
    cut
}

fn sort_and_cap_keys(map: &mut Map<String, Value>) -> bool {
    if !map.keys().is_sorted() {
        let mut entries: Vec<(String, Value)> = std::mem::take(map).into_iter().collect();
        entries.sort_by(|a, b| a.0.cmp(&b.0));
        map.extend(entries);
    }
    if map.len() <= MAX_KEYS {
        return false;
    }
    let keep: Vec<String> = map.keys().take(MAX_KEYS).cloned().collect();
    map.retain(|key, _| keep.contains(key));
    true
}

/// Bounds one value. `depth` counts the lists and objects above it inside the map.
pub(super) fn bound_value(value: &mut Value, depth: usize, cut: &mut bool) {
    match value {
        Value::String(text) => {
            if text.len() > MAX_TEXT {
                let (shorter, was_cut) = cap_text(std::mem::take(text), MAX_TEXT);
                *text = shorter;
                *cut |= was_cut;
            }
        }
        Value::Array(_) | Value::Object(_) if depth >= MAX_DEPTH => {
            *value = Value::String(DEEP.to_owned());
            *cut = true;
        }
        Value::Array(items) => {
            *cut |= truncate(items, MAX_LIST);
            for item in items {
                bound_value(item, depth + 1, cut);
            }
        }
        Value::Object(map) => {
            *cut |= sort_and_cap_keys(map);
            for item in map.values_mut() {
                bound_value(item, depth + 1, cut);
            }
        }
        Value::Null | Value::Bool(_) | Value::Number(_) => {}
    }
}
