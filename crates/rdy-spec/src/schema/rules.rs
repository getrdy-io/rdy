//! The rules that a derived schema cannot say by itself.
//!
//! Each function is a `schemars` transform named by a `#[schemars(transform = ...)]` attribute on the
//! type it belongs to, or a `schema_with` function for one field. They add the cross-field rules of
//! 01 section 5 (a verdict fixes the exit code, a verified signature needs its key fields) and the
//! check-id dispatch of the spec.

use schemars::{Schema, SchemaGenerator, json_schema};
use serde_json::{Value, json};

/// Appends `rules` to the schema's `allOf`, keeping the rules already there.
fn push_all_of(schema: &mut Schema, rules: Vec<Value>) {
    let mut all_of = match schema.remove("allOf") {
        Some(Value::Array(existing)) => existing,
        _ => Vec::new(),
    };
    all_of.extend(rules);
    schema.insert("allOf".into(), Value::Array(all_of));
}

/// Adds `names` to the schema's `required` list.
///
/// A field that is an `Option` is left out of `required` by the derive, and the `required` attribute
/// would also remove `null` from its type. Several result fields must be present and may be `null`,
/// so the type's transform lists them here instead.
fn require(schema: &mut Schema, names: &[&str]) {
    let mut required = match schema.remove("required") {
        Some(Value::Array(existing)) => existing,
        _ => Vec::new(),
    };
    for name in names {
        let name = Value::String((*name).to_owned());
        if !required.contains(&name) {
            required.push(name);
        }
    }
    schema.insert("required".into(), Value::Array(required));
}

/// `if <property> is <value> then <consequence>`, the shape of every rule below.
fn when(property: &str, value: &Value, then: Value) -> Value {
    json!({
        "if": { "properties": { property: { "const": value } } },
        "then": then
    })
}

/// The spec's `Check`: each known id has its own parameters, and nothing else may appear.
///
/// A check entry is a flat map, so the parameters sit next to the common fields. The rule per id is
/// `if id is host.cpu then HostCpuParams`. An id this schema does not know is allowed, with any
/// parameters, because rdy reports that check as not run (01 section 2.4). Every key that no rule
/// and no common field names is refused by `unevaluatedProperties`.
pub(crate) fn check_rules(schema: &mut Schema) {
    let known = super::check_param_defs();
    let mut rules: Vec<Value> = known
        .iter()
        .map(|(id, def)| {
            when(
                "id",
                &json!(id),
                json!({ "$ref": format!("#/$defs/{def}") }),
            )
        })
        .collect();
    let ids: Vec<&String> = known.iter().map(|(id, _)| id).collect();
    rules.push(json!({
        "description": "Check ids this schema does not know. Their parameters are not checked here; rdy reports the check as not run.",
        "if": { "properties": { "id": { "not": { "enum": ids } } } },
        "then": { "additionalProperties": true }
    }));
    push_all_of(schema, rules);
    schema.insert("unevaluatedProperties".into(), Value::Bool(false));
}

/// `exit_code` is 0, 1 or 2. Exit 70 means there is no report to read.
pub(crate) fn exit_code_schema(_: &mut SchemaGenerator) -> Schema {
    json_schema!({ "enum": [0, 1, 2] })
}

/// The `Report` rules: the verdict fixes the exit code, an unsigned spec means the run allowed it, and a
/// `ready` verdict has no reason and nothing left over.
pub(crate) fn report_rules(schema: &mut Schema) {
    require(schema, &["verdict_reason"]);
    push_all_of(
        schema,
        vec![
            when(
                "verdict",
                &json!("ready"),
                json!({ "properties": { "exit_code": { "const": 0 } } }),
            ),
            when(
                "verdict",
                &json!("ready_with_warnings"),
                json!({ "properties": { "exit_code": { "const": 1 } } }),
            ),
            when(
                "verdict",
                &json!("not_ready"),
                json!({ "properties": { "exit_code": { "const": 2 } } }),
            ),
            json!({
                "if": { "properties": { "signature": { "properties": { "state": { "const": "unsigned" } } } } },
                "then": { "properties": { "run": { "properties": { "options": {
                    "properties": { "allow_unsigned": { "const": true } }
                } } } } }
            }),
            when(
                "verdict",
                &json!("ready"),
                json!({ "properties": {
                    "verdict_reason": { "type": "null" },
                    "summary": { "properties": {
                        "block": { "const": 0 },
                        "warn": { "const": 0 },
                        "required_not_run": { "const": 0 },
                        "optional_not_run": { "const": 0 }
                    } }
                } }),
            ),
        ],
    );
}

/// `host_id` is always written, and is `null` when the machine has no usable id.
pub(crate) fn host_rules(schema: &mut Schema) {
    require(schema, &["host_id"]);
}

/// `euid` and `user` are always written, and are `null` where the OS has no such thing.
pub(crate) fn identity_rules(schema: &mut Schema) {
    require(schema, &["euid", "user"]);
}

/// `commit` and `date` are always written, and are `null` for a build with no git information.
pub(crate) fn version_rules(schema: &mut Schema) {
    require(schema, &["commit", "date"]);
}

/// A verified signature names its key, fingerprint, product, signing time and trust source.
pub(crate) fn signature_rules(schema: &mut Schema) {
    push_all_of(
        schema,
        vec![when(
            "state",
            &json!("verified"),
            json!({
                "required": ["key_id", "key_fingerprint", "product", "signed_at", "trust_source"],
                "properties": {
                    "key_id": { "type": "string" },
                    "key_fingerprint": { "type": "string" },
                    "product": { "type": "string" },
                    "signed_at": { "type": "string" },
                    "trust_source": { "type": "string" }
                }
            }),
        )],
    );
}

/// The fields of a check result that depend on its status.
///
/// A skipped check says why, a timeout says after how long, an error says what kind, and a check
/// that did not pass says what to do. Only a pass and a not-applicable skip may go without a fix.
pub(crate) fn check_result_rules(schema: &mut Schema) {
    require(
        schema,
        &[
            "name",
            "fix",
            "fix_source",
            "observed",
            "expected",
            "partial",
        ],
    );
    bound_values(schema, &["observed", "expected"]);
    push_all_of(
        schema,
        vec![
            when(
                "status",
                &json!("skipped"),
                json!({ "required": ["skip_kind"] }),
            ),
            when(
                "status",
                &json!("timeout"),
                json!({ "required": ["timeout_after_ms"] }),
            ),
            when(
                "status",
                &json!("error"),
                json!({ "required": ["error_kind"] }),
            ),
            json!({
                "if": { "properties": { "status": { "enum": ["warn", "block", "timeout", "error"] } } },
                "then": { "properties": { "fix": { "type": "string" } } }
            }),
            json!({
                "if": {
                    "properties": {
                        "status": { "const": "skipped" },
                        "skip_kind": { "not": { "const": "not_applicable" } }
                    },
                    "required": ["skip_kind"]
                },
                "then": { "properties": { "fix": { "type": "string", "minLength": 1 } } }
            }),
            when(
                "status",
                &json!("pass"),
                json!({ "properties": { "fix_source": { "type": "null" } } }),
            ),
        ],
    );
}

/// Adds the fields of an action that depend on its `kind`.
///
/// They are optional and may appear next to the common fields. The action log ticket replaces this
/// with typed fields.
pub(crate) fn action_fields(schema: &mut Schema) {
    require(schema, &["check"]);
    let mut properties = match schema.remove("properties") {
        Some(Value::Object(existing)) => existing,
        _ => serde_json::Map::new(),
    };
    properties.extend(super::action_kind_properties());
    schema.insert("properties".into(), Value::Object(properties));
}

/// Texts, numbers and booleans, at most 4 KiB each.
fn scalar_value() -> Value {
    json!({ "type": ["string", "number", "boolean", "null"], "maxLength": 4096 })
}

/// A value of `observed` or `expected`: a scalar, or a list or object whose children are `child`.
fn value_of(child: &Value) -> Value {
    json!({
        "type": ["string", "number", "boolean", "null", "array", "object"],
        "maxLength": 4096,
        "maxItems": 256,
        "maxProperties": 64,
        "items": child,
        "additionalProperties": child
    })
}

/// Bounds what the free-form maps `observed` and `expected` may hold, so a text or a list inside one
/// cannot be larger than any other field. The maps have at most 64 keys, and a value nests at most
/// three levels: a scalar, a list or object of those, and a list or object of those.
fn bound_values(schema: &mut Schema, names: &[&str]) {
    let leaf = scalar_value();
    let middle = value_of(&leaf);
    let top = value_of(&middle);
    let Some(Value::Object(properties)) = schema.get_mut("properties") else {
        return;
    };
    for name in names {
        if let Some(Value::Object(field)) = properties.get_mut(*name) {
            field.insert("additionalProperties".into(), top.clone());
            field.insert("maxProperties".into(), json!(64));
        }
    }
}
