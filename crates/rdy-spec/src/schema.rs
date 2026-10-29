//! The JSON schemas of the `rdy/v1` spec and result, generated from the wire types.
//!
//! The Rust types are the source of truth (docs/adr/0012). `schemars` derives a schema from each type,
//! and doc comments become descriptions. [`spec_schema_json`] and [`result_schema_json`] return the two
//! files that are committed under `crates/rdy-spec/schema/`. `cargo xtask schema` writes them, and
//! `cargo xtask schema --check` fails when a type or a doc comment changed and the files did not.
//!
//! The output is JSON Schema draft 2020-12, written with two-space indent, keys in a fixed order and a
//! final newline. It depends on nothing but the types, so two runs give the same bytes.
//!
//! # What the types do not say yet
//!
//! Three parts of the contract have no Rust type yet. Their schema comes from a JSON fragment in
//! `src/schema/`, merged into the output as it is:
//!
//! | Fragment | Holds | Goes away when |
//! | --- | --- | --- |
//! | `check_params.json` | the parameters of the 17 check ids, and the small shared definitions they use | the typed parameter structs derive `JsonSchema` |
//! | `action_fields.json` | the fields of an action that depend on its `kind` | the action log is typed |
//! | `command_output.json` | the `ErrorOutput` and `Verification` objects | the commands that print them own their types |
//!
//! A fragment is checked like the rest: its descriptions go through the same lint, and a test keeps
//! its list of check ids equal to [`crate::check::KNOWN_IDS`].

use schemars::generate::SchemaSettings;
use schemars::transform::{RecursiveTransform, Transform};
use schemars::{Schema, SchemaGenerator};
use serde_json::{Map, Value};

mod rules;
mod tidy;

pub(crate) use rules::{
    action_fields, check_result_rules, check_rules, exit_code_schema, host_rules, identity_rules,
    report_rules, signature_rules, version_rules,
};

use crate::lint::LintReport;
use crate::result::{Report, VersionInfo};
use crate::scalar::{Target, Version};
use crate::spec::Spec;

/// The `$id` of the spec schema.
const SPEC_ID: &str = "https://getrdy.io/schema/rdy/v1/spec.v1.schema.json";
/// The `$id` of the result schema.
const RESULT_ID: &str = "https://getrdy.io/schema/rdy/v1/result.v1.schema.json";

/// Description of the whole result document, which has no Rust doc comment of its own.
const RESULT_DESCRIPTION: &str = "The JSON report rdy writes and Rdy Cloud reads. Ignore fields you do not know. Accept values not listed where a description says Open. Use verdict as written. A whole document is at most 2 MiB; readers should check that before parsing.";

const CHECK_PARAMS: &str = include_str!("schema/check_params.json");
const ACTION_FIELDS: &str = include_str!("schema/action_fields.json");
const COMMAND_OUTPUT: &str = include_str!("schema/command_output.json");

/// A JSON fragment compiled into the crate.
///
/// The fragments are constants and a test parses each one, so a parse failure is a bug in this crate and
/// not an input error.
fn fragment(text: &str) -> Map<String, Value> {
    match serde_json::from_str::<Value>(text) {
        Ok(Value::Object(map)) => map,
        Ok(_) => panic!("a schema fragment is not a JSON object"),
        Err(e) => panic!("a schema fragment is not valid JSON: {e}"),
    }
}

/// The check ids of the parameter fragment, each with the name of its parameter definition.
pub(crate) fn check_param_defs() -> Vec<(String, String)> {
    let mut out = Vec::new();
    if let Some(Value::Object(ids)) = fragment(CHECK_PARAMS).get("ids") {
        for (id, def) in ids {
            if let Value::String(def) = def {
                out.push((id.clone(), def.clone()));
            }
        }
    }
    out
}

/// The properties of an action that depend on its `kind`.
pub(crate) fn action_kind_properties() -> Map<String, Value> {
    match fragment(ACTION_FIELDS).remove("properties") {
        Some(Value::Object(props)) => props,
        _ => panic!("the action fragment has no properties"),
    }
}

fn generator() -> SchemaGenerator {
    SchemaSettings::draft2020_12()
        .with(|s| s.inline_subschemas = false)
        .into_generator()
}

/// The spec schema (`spec.v1.schema.json`) as text, ready to write to disk.
///
/// The root is the spec itself, so an editor that reads the file treats it as the document schema. The
/// definitions it refers to are under `$defs`.
#[must_use]
pub fn spec_schema_json() -> String {
    let mut generator = generator();
    generator.subschema_for::<Spec>();
    // The parameter fragment refers to these two. No derived type reaches them yet.
    generator.subschema_for::<Version>();
    generator.subschema_for::<Target>();
    let mut defs = generator.take_definitions(false);

    let root = match defs.remove("Spec") {
        Some(Value::Object(spec)) => spec,
        _ => panic!("the generator did not produce the Spec definition"),
    };
    merge_defs(&mut defs, fragment(CHECK_PARAMS).remove("$defs"));

    finish(root, defs, SPEC_ID, Tidy::SPEC)
}

/// The result schema (`result.v1.schema.json`) as text, ready to write to disk.
///
/// The root points at the `Report` definition. The other objects the CLI prints with `--json`
/// (`Verification`, `ErrorOutput`, `LintReport` and `Version`) are definitions beside it. `LintReport` and
/// `Version` are derived. The other two come from `command_output.json`.
#[must_use]
pub fn result_schema_json() -> String {
    let mut generator = generator();
    generator.subschema_for::<Report>();
    generator.subschema_for::<VersionInfo>();
    generator.subschema_for::<LintReport>();
    let mut defs = generator.take_definitions(false);
    merge_defs(&mut defs, Some(Value::Object(fragment(COMMAND_OUTPUT))));

    let mut root = Map::new();
    root.insert("title".into(), "rdy/v1 run result".into());
    root.insert("description".into(), RESULT_DESCRIPTION.into());
    root.insert("$ref".into(), "#/$defs/Report".into());
    finish(root, defs, RESULT_ID, Tidy::RESULT)
}

/// Adds the definitions of a fragment. A fragment never replaces a generated definition.
fn merge_defs(defs: &mut Map<String, Value>, fragment: Option<Value>) {
    if let Some(Value::Object(extra)) = fragment {
        for (name, def) in extra {
            let clash = defs.insert(name.clone(), def).is_some();
            assert!(!clash, "the fragment redefines the generated type {name}");
        }
    }
}

/// Sorts the definitions, runs the clean-up pass and writes the text.
///
/// `$schema` and `$id` are written first, by hand, because the serializer for a schema has a fixed
/// keyword order that puts `$id` far down.
fn finish(mut root: Map<String, Value>, defs: Map<String, Value>, id: &str, tidy: Tidy) -> String {
    let mut names: Vec<&String> = defs.keys().collect();
    names.sort();
    let sorted: Map<String, Value> = names
        .into_iter()
        .filter_map(|name| defs.get(name).map(|def| (name.clone(), def.clone())))
        .collect();
    root.insert("$defs".into(), Value::Object(sorted));

    let mut schema = Schema::from(root);
    RecursiveTransform(tidy).transform(&mut schema);
    match serde_json::to_string_pretty(&schema) {
        Ok(body) => {
            let head = format!(
                "{{\n  \"$schema\": \"https://json-schema.org/draft/2020-12/schema\",\n  \"$id\": \"{id}\",\n"
            );
            let mut text = body.replacen("{\n", &head, 1);
            text.push('\n');
            text
        }
        Err(e) => panic!("a schema is not valid JSON: {e}"),
    }
}

/// The clean-up pass that runs over every subschema of a finished schema. See [`tidy`].
pub(crate) use tidy::Tidy;

#[cfg(test)]
mod tests;
