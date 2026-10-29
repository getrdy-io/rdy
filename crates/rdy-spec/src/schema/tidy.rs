//! The clean-up pass over a finished schema.
//!
//! `schemars` does the structure. This pass fixes what it leaves for a reader or a validator to
//! trip over. It runs on every subschema, in this order.
//!
//! 1. Descriptions become plain text: line breaks inside a paragraph turn into spaces, and the
//!    rustdoc link form ``[`Name`]`` becomes ``Name`` in backticks.
//! 2. The `format` keyword on integers is dropped (`uint64`, `int32`). They are Rust widths, not
//!    JSON Schema formats, and a validator that knows them would add checks the contract does not make.
//! 3. In the spec schema, a `null` alternative is removed. A YAML key with no value is never a valid
//!    value in a spec, though the typed reader treats it as unset.
//! 4. In the result schema, a text with no other limit gets `maxLength` 4096 (docs/plan/05, SEC-63),
//!    so a field added later is capped without anyone remembering to do it.

use schemars::Schema;
use schemars::transform::Transform;
use serde_json::{Map, Value, json};

/// The longest text in a result field that has no smaller limit of its own.
pub(crate) const MAX_TEXT: u64 = 4096;

/// Integer and float formats that name a Rust width.
const NUMBER_FORMATS: &[&str] = &[
    "int8", "int16", "int32", "int64", "int128", "uint", "uint8", "uint16", "uint32", "uint64",
    "uint128", "float", "double",
];

/// Which steps of the pass to run. Steps 1 and 2 always run.
#[derive(Debug, Clone, Copy)]
pub(crate) struct Tidy {
    forbid_null: bool,
    cap_text: bool,
}

impl Tidy {
    /// The pass for the spec schema.
    pub(crate) const SPEC: Self = Self {
        forbid_null: true,
        cap_text: false,
    };
    /// The pass for the result schema.
    pub(crate) const RESULT: Self = Self {
        forbid_null: false,
        cap_text: true,
    };
}

impl Transform for Tidy {
    fn transform(&mut self, schema: &mut Schema) {
        let Some(object) = schema.as_object_mut() else {
            return;
        };
        for key in ["description", "title"] {
            if let Some(Value::String(text)) = object.get_mut(key) {
                *text = plain_text(text);
            }
        }
        drop_number_format(object);
        if self.forbid_null {
            forbid_null(object);
        }
        if self.cap_text {
            cap_text(object);
        }
    }
}

/// Joins the lines of each paragraph and drops the rustdoc link brackets.
fn plain_text(text: &str) -> String {
    let paragraphs: Vec<String> = text
        .split("\n\n")
        .map(|paragraph| {
            paragraph
                .lines()
                .map(str::trim)
                .filter(|line| !line.is_empty())
                .collect::<Vec<_>>()
                .join(" ")
        })
        .filter(|paragraph| !paragraph.is_empty())
        .collect();
    unlink(&paragraphs.join("\n\n"))
}

/// Turns ``[`Name`]`` into ``` `Name` ```. A bracket that is not that form is left alone.
fn unlink(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    let mut rest = text;
    while let Some(start) = rest.find("[`") {
        out.push_str(&rest[..start]);
        let after = &rest[start + 1..];
        match after.find("`]") {
            Some(end) if !after[..end].contains('\n') => {
                out.push_str(&after[..end + 1]);
                rest = &after[end + 2..];
            }
            _ => {
                out.push('[');
                rest = after;
            }
        }
    }
    out.push_str(rest);
    out
}

fn drop_number_format(object: &mut Map<String, Value>) {
    let is_width = matches!(object.get("format"), Some(Value::String(f)) if NUMBER_FORMATS.contains(&f.as_str()));
    if is_width {
        object.remove("format");
    }
}

/// Removes `null` from `type: [..., "null"]` and from an `anyOf` that has a `{"type": "null"}` branch.
fn forbid_null(object: &mut Map<String, Value>) {
    if let Some(Value::Array(types)) = object.get_mut("type") {
        types.retain(|t| t != "null");
        if types.len() == 1 {
            let only = types.remove(0);
            object.insert("type".into(), only);
        }
    }
    let Some(Value::Array(branches)) = object.get_mut("anyOf") else {
        return;
    };
    let null = json!({ "type": "null" });
    branches.retain(|branch| *branch != null);
    if branches.len() == 1 {
        let only = branches.remove(0);
        object.remove("anyOf");
        if let Value::Object(fields) = only {
            for (key, value) in fields {
                object.entry(key).or_insert(value);
            }
        }
    }
}

/// Gives a plain text a `maxLength`. A text with a pattern, a format, a fixed value or a list of
/// values already has a limit of its own.
fn cap_text(object: &mut Map<String, Value>) {
    let is_text = match object.get("type") {
        Some(Value::String(t)) => t == "string",
        Some(Value::Array(types)) => types.iter().any(|t| t == "string"),
        _ => false,
    };
    let limited = ["maxLength", "pattern", "format", "enum", "const"]
        .iter()
        .any(|key| object.contains_key(*key));
    if is_text && !limited {
        object.insert("maxLength".into(), json!(MAX_TEXT));
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn plain_text_joins_lines_and_keeps_paragraphs() {
        let text = " First line\n continues here.\n\n Second paragraph.\n";
        assert_eq!(
            plain_text(text),
            "First line continues here.\n\nSecond paragraph."
        );
    }

    #[test]
    fn unlink_drops_rustdoc_brackets_only() {
        assert_eq!(unlink("see [`Foo::bar`] now"), "see `Foo::bar` now");
        assert_eq!(unlink("a [b] c and [`x`]"), "a [b] c and `x`");
        assert_eq!(unlink("open [` never closed"), "open [` never closed");
    }

    #[test]
    fn cap_text_skips_limited_texts() {
        let mut plain = json!({"type": "string"})
            .as_object()
            .cloned()
            .unwrap_or_default();
        cap_text(&mut plain);
        assert_eq!(plain.get("maxLength"), Some(&json!(4096)));

        let mut nullable = json!({"type": ["string", "null"]})
            .as_object()
            .cloned()
            .unwrap_or_default();
        cap_text(&mut nullable);
        assert_eq!(nullable.get("maxLength"), Some(&json!(4096)));

        for limited in [
            json!({"type": "string", "pattern": "^a$"}),
            json!({"type": "string", "maxLength": 10}),
            json!({"type": "string", "format": "uuid"}),
            json!({"type": "string", "const": "x"}),
        ] {
            let mut object = limited.as_object().cloned().unwrap_or_default();
            let before = object.clone();
            cap_text(&mut object);
            assert_eq!(object, before);
        }
    }

    #[test]
    fn forbid_null_folds_the_alternatives() {
        let mut typed = json!({"type": ["string", "null"], "minLength": 1})
            .as_object()
            .cloned()
            .unwrap_or_default();
        forbid_null(&mut typed);
        assert_eq!(typed.get("type"), Some(&json!("string")));

        let mut any =
            json!({"anyOf": [{"$ref": "#/$defs/A"}, {"type": "null"}], "description": "d"})
                .as_object()
                .cloned()
                .unwrap_or_default();
        forbid_null(&mut any);
        assert_eq!(
            Value::Object(any),
            json!({"$ref": "#/$defs/A", "description": "d"})
        );
    }
}
