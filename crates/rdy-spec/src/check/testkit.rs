//! Helpers for the parameter tests of the net and k8s structs.
//!
//! Each struct has one [`Case`]: a fixture that sets every field, and a rejected value for every field.
//! [`run_case_checks`] holds the tests that every struct must pass, so a new field cannot be added
//! without an accepting and a rejecting fixture.

use std::collections::BTreeSet;

use serde_json::{Value, json};

use super::common::serde_fields_of;
use super::{CheckParams, ParamSet, UnsupportedReason};
use crate::spec::CheckSpec;

/// Decodes an entry written as JSON, the way a spec file reaches `decode_params`.
pub(crate) fn decode_entry(value: &Value) -> CheckParams {
    let spec: CheckSpec =
        serde_json::from_value(value.clone()).expect("an entry with an id always reads");
    spec.decode_params()
}

/// The entry for `id` with `params` merged in.
pub(crate) fn entry(id: &str, params: &Value) -> Value {
    let mut map = params.as_object().expect("params are an object").clone();
    map.insert("id".to_owned(), json!(id));
    Value::Object(map)
}

/// Why the entry is skipped. Panics when it decodes.
pub(crate) fn why(id: &str, params: &Value) -> UnsupportedReason {
    match decode_entry(&entry(id, params)) {
        CheckParams::Unsupported { reason, .. } => reason,
        other => panic!("{id} {params}: expected Unsupported, got {other:?}"),
    }
}

/// The typed parameters of the entry. Panics when it does not decode.
pub(crate) fn typed(id: &str, params: &Value) -> CheckParams {
    match decode_entry(&entry(id, params)) {
        CheckParams::Unknown { .. } => panic!("{id} is Unknown"),
        CheckParams::Unsupported { reason, .. } => panic!("{id} {params}: {reason}"),
        other => other,
    }
}

pub(crate) fn keys(value: &Value) -> BTreeSet<String> {
    value
        .as_object()
        .expect("an object")
        .keys()
        .cloned()
        .collect()
}

pub(crate) fn names(fields: &[&str]) -> BTreeSet<String> {
    fields.iter().map(|f| (*f).to_owned()).collect()
}

/// One check id with a fixture that sets every field, and rejected values.
pub(crate) struct Case {
    pub id: &'static str,
    /// Sets every field of the struct.
    pub full: Value,
    /// A rejected value for each field, as `(field, value)`. A field may have several.
    pub bad: Vec<(&'static str, Value)>,
    pub fields: &'static [&'static str],
}

/// The checks that every struct passes.
pub(crate) fn run_case_checks(cases: &[Case]) {
    for case in cases {
        // The fixture sets every field and decodes.
        assert_eq!(keys(&case.full), names(case.fields), "{}", case.id);
        typed(case.id, &case.full);

        // Every field has a rejecting case, and each is refused with the field named.
        let covered: BTreeSet<String> = case.bad.iter().map(|(f, _)| (*f).to_owned()).collect();
        assert_eq!(
            covered,
            names(case.fields),
            "{}: a field has no bad case",
            case.id
        );
        for (field, bad) in &case.bad {
            let mut params = case.full.clone();
            params[*field] = bad.clone();
            let reason = why(case.id, &params);
            match &reason {
                UnsupportedReason::BadValue {
                    field: culprit,
                    message,
                } => {
                    assert_eq!(culprit.as_deref(), Some(*field), "{} {bad}", case.id);
                    assert!(!message.is_empty());
                }
                // A block with a key it does not have is told by the path of that key, which starts
                // with the field.
                UnsupportedReason::UnknownNestedField { path, .. } => {
                    assert!(path.starts_with(*field), "{} {bad}: {path}", case.id);
                }
                other => panic!(
                    "{} {field}={bad}: expected BadValue, got {other:?}",
                    case.id
                ),
            }
            let text = reason.to_string();
            assert!(!text.chars().any(char::is_control), "{text:?}");
            assert!(text.len() < 400, "{} chars", text.len());
        }

        // A key the check does not have is named.
        let mut params = case.full.clone();
        params["mn"] = json!("32Gi");
        assert_eq!(
            why(case.id, &params),
            UnsupportedReason::UnknownField { field: "mn".into() },
            "{}",
            case.id
        );

        // A key with no value is a bad value and not an absent key.
        for field in case.fields {
            let mut params = case.full.clone();
            params[*field] = Value::Null;
            let reason = why(case.id, &params);
            assert!(
                matches!(&reason, UnsupportedReason::BadValue { field: Some(f), .. } if f == field),
                "{} {field}: {reason:?}",
                case.id
            );
        }
    }
}

/// `FIELDS` names exactly the keys of the struct, and `THRESHOLD` and `ALSO_REQUIRED` name fields.
pub(crate) fn fields_match<P: ParamSet>() {
    let from_list: BTreeSet<String> = P::FIELDS.iter().map(|f| (*f).to_owned()).collect();
    assert_eq!(from_list.len(), P::FIELDS.len(), "FIELDS names a key twice");
    assert_eq!(serde_fields_of::<P>(), from_list);
    for key in P::THRESHOLD.iter().chain(P::ALSO_REQUIRED) {
        assert!(
            P::FIELDS.contains(key),
            "THRESHOLD or ALSO_REQUIRED names '{key}', not a field"
        );
    }
}

/// The text a spec writer sees must be short and have no control character.
pub(crate) fn assert_printable(reason: &UnsupportedReason) {
    let text = reason.to_string();
    assert!(!text.chars().any(char::is_control), "{text:?}");
    assert!(text.len() < 400, "{} chars", text.len());
}
