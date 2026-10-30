//! Unit tests for the pieces of the JSON writer: the escapes and the bounds on one value or map.
//! The writer end to end, with a redactor, is `tests/json_writer.rs`.

use serde_json::{Value, json};

use super::bound::{bound_map, bound_value, fold_counts};
use super::escape_html;

#[test]
fn the_five_characters_are_escaped_and_nothing_else_changes() {
    let json = "{\"a\": \"<b>&\u{2028}\u{2029}é\\\\\"}";
    assert_eq!(
        escape_html(json),
        "{\"a\": \"\\u003cb\\u003e\\u0026\\u2028\\u2029é\\\\\"}"
    );
    assert_eq!(escape_html("plain"), "plain");
}

/// Bounds `map` (an object) as the writer bounds `observed`: its values are the first level.
fn bounded(map: Value) -> (Value, bool) {
    let Value::Object(mut map) = map else {
        return (map, false);
    };
    let cut = bound_map(&mut map);
    (Value::Object(map), cut)
}

#[test]
fn one_value_is_bounded_from_the_level_it_is_given() {
    let mut value = json!([[[1]]]);
    let mut cut = false;
    bound_value(&mut value, 1, &mut cut);
    assert_eq!(value, json!(["[truncated]"]));
    assert!(cut);
}

#[test]
fn a_value_of_three_levels_stays() {
    // The value, its children and its grandchildren (scalars).
    let value = json!({ "nodes": [ { "cpu": 4, "name": "n1" }, [1, 2] ], "total": 2 });
    let (out, cut) = bounded(value.clone());
    assert_eq!(out, value);
    assert!(!cut);
}

#[test]
fn a_list_or_object_at_the_fourth_level_becomes_text() {
    let (out, cut) = bounded(json!({ "a": { "b": { "c": 1 } }, "l": [[[1]]], "ok": [[1]] }));
    assert_eq!(out["a"]["b"], json!({ "c": 1 }));
    assert!(cut);
    let (out, _) = bounded(json!({ "a": { "b": { "c": { "d": 1 } } } }));
    assert_eq!(out["a"]["b"]["c"], "[truncated]");
    let (out, _) = bounded(json!({ "l": [[[1]]] }));
    assert_eq!(out["l"][0][0], "[truncated]");
    let (out, cut) = bounded(json!({ "ok": [[1]] }));
    assert_eq!(out["ok"], json!([[1]]));
    assert!(!cut);
}

#[test]
fn a_list_past_256_items_and_an_object_past_64_keys_are_cut() {
    let list: Vec<u32> = (0..300).collect();
    let (out, cut) = bounded(json!({ "list": list }));
    assert_eq!(out["list"].as_array().map(Vec::len), Some(256));
    assert!(cut);

    let object: serde_json::Map<String, Value> = (0..100)
        .rev()
        .map(|i| (format!("k{i:03}"), json!(i)))
        .collect();
    let (out, cut) = bounded(json!({ "inner": object }));
    let inner = out["inner"]
        .as_object()
        .map(|m| m.keys().cloned().collect::<Vec<_>>());
    let inner = inner.unwrap_or_default();
    assert_eq!(inner.len(), 64);
    // The first 64 in key order stay, whatever the order they came in.
    assert_eq!(inner.first().map(String::as_str), Some("k000"));
    assert_eq!(inner.last().map(String::as_str), Some("k063"));
    assert!(cut);
}

#[test]
fn a_text_over_4_kib_is_cut_with_the_marker() {
    let (out, cut) = bounded(json!({ "t": "ab cd ".repeat(2000) }));
    let text = out["t"].as_str().unwrap_or_default();
    assert!(text.len() <= 4096, "{}", text.len());
    assert!(text.ends_with(" [truncated]"));
    assert!(cut);
    let (out, cut) = bounded(json!({ "t": "x".repeat(4096) }));
    assert_eq!(out["t"].as_str().map(str::len), Some(4096));
    assert!(!cut);
}

#[test]
fn a_map_comes_out_sorted_and_with_at_most_64_keys() {
    let mut map: serde_json::Map<String, Value> = ["b", "a", "c"]
        .iter()
        .map(|k| ((*k).to_owned(), json!(1)))
        .collect();
    assert!(!bound_map(&mut map));
    assert_eq!(
        map.keys().map(String::as_str).collect::<Vec<_>>(),
        ["a", "b", "c"]
    );

    let mut big: serde_json::Map<String, Value> = (0..70)
        .rev()
        .map(|i| (format!("k{i:02}"), json!(i)))
        .collect();
    assert!(bound_map(&mut big));
    assert_eq!(big.len(), 64);
    assert!(big.contains_key("k00"));
    assert!(!big.contains_key("k64"));
}

#[test]
fn counters_past_the_cap_are_added_to_the_last_key_kept() {
    let mut map: std::collections::BTreeMap<String, u64> =
        (0..5).map(|i| (format!("k{i}"), 10)).collect();
    fold_counts(&mut map, 3);
    assert_eq!(map.len(), 3);
    assert_eq!(map.get("k2"), Some(&30));
    assert_eq!(map.values().sum::<u64>(), 50);
}
