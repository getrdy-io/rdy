//! Unit tests of the schema generator: the fragments, the references and the byte-for-byte output.

use std::collections::BTreeSet;

use serde_json::Value;

use super::*;

fn parse(text: &str) -> Value {
    serde_json::from_str(text).expect("the generated schema is JSON")
}

/// Every `$ref` of the form `#/$defs/<Name>` inside `value`.
fn refs(value: &Value, out: &mut BTreeSet<String>) {
    match value {
        Value::Object(map) => {
            for (key, inner) in map {
                if key == "$ref"
                    && let Value::String(target) = inner
                    && let Some(name) = target.strip_prefix("#/$defs/")
                {
                    out.insert(name.to_owned());
                } else {
                    refs(inner, out);
                }
            }
        }
        Value::Array(items) => items.iter().for_each(|item| refs(item, out)),
        _ => {}
    }
}

#[test]
fn the_fragments_are_json_objects() {
    assert!(!fragment(CHECK_PARAMS).is_empty());
    assert!(!fragment(ACTION_FIELDS).is_empty());
    assert!(!fragment(COMMAND_OUTPUT).is_empty());
}

#[test]
fn the_parameter_fragment_names_exactly_the_known_check_ids() {
    let in_fragment: BTreeSet<String> = check_param_defs().into_iter().map(|(id, _)| id).collect();
    let known: BTreeSet<String> = crate::check::KNOWN_IDS
        .iter()
        .map(|id| (*id).to_owned())
        .collect();
    assert_eq!(in_fragment, known);
}

#[test]
fn every_reference_resolves() {
    for (name, text) in [
        ("spec", spec_schema_json()),
        ("result", result_schema_json()),
    ] {
        let schema = parse(&text);
        let defs = schema["$defs"].as_object().expect("$defs");
        let mut wanted = BTreeSet::new();
        refs(&schema, &mut wanted);
        for target in wanted {
            assert!(defs.contains_key(&target), "{name}: dangling $ref {target}");
        }
    }
}

#[test]
fn the_output_is_stable_and_ends_with_one_newline() {
    for text in [spec_schema_json(), result_schema_json()] {
        assert!(text.ends_with("}\n"));
        assert!(!text.contains('\r'));
    }
    assert_eq!(spec_schema_json(), spec_schema_json());
    assert_eq!(result_schema_json(), result_schema_json());
}

/// The parameter fragment is written by hand, so nothing but this test ties its field names to the
/// parameter structs. A field added to a struct and left out of the fragment (or the reverse) fails here.
#[test]
fn each_parameter_definition_lists_the_fields_of_its_struct() {
    let defs = fragment(CHECK_PARAMS)
        .remove("$defs")
        .expect("the fragment has definitions");
    for (id, def) in check_param_defs() {
        let Some(fields) = crate::check::fields_of(&id) else {
            panic!("{id} has no parameter struct");
        };
        let properties = defs[def.as_str()]["properties"]
            .as_object()
            .unwrap_or_else(|| panic!("{def} has no properties"));
        let in_schema: BTreeSet<&str> = properties.keys().map(String::as_str).collect();
        let in_struct: BTreeSet<&str> = fields.iter().copied().collect();
        assert_eq!(in_schema, in_struct, "{id}: {def} and the struct disagree");
    }
}
