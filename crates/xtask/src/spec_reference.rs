//! The reference pages, rendered from the committed JSON schemas (docs/plan/09-docs-site.md, section 5).
//!
//! The spec page comes from `spec.v1.schema.json` and the result page from `result.v1.schema.json`
//! (ADR 0019). Each page is the frontmatter, the banner, the hand-written intro from `docs/intro/`, and
//! the tables. The output depends only on those committed files.
//!
//! The root object and each object with fields that a property names get one table, with one row per
//! property. An array of objects gets a section for its items. A `oneOf` or `anyOf` that mixes scalars
//! and objects shows the types in its row, and each object form gets a section. An `allOf` `if`/`then`
//! variant that fixes one property to a constant gets a section for its own fields, titled by that
//! constant. The check parameters are that kind of variant: each check id has its own table, keyed by
//! `id`. Sections nest, so a section inside a check variant is one heading level deeper.
//!
//! An `if`/`then` is a variant only when its `then` names a definition with fields. An inline `then` only
//! constrains fields the object already has, such as `exit_code` for each verdict, so it gets no section.
//!
//! Each object gets one section, however many properties name it. A later property that names the same
//! object gets a row that links to the section, so every field appears once on the page (M1-085).
//!
//! A row gives the name, the type, whether the field is required, the default, the description and an
//! example. A scalar shows its JSON type, and an array shows `array of` and the type of its items. An
//! object shows `object`. A list of types, such as `string` and `null`, shows each type joined with `or`.
//! A `null` type shows `null`. A fixed set of values, from `enum`, from `oneOf` or `anyOf` of constants,
//! or from a bare `const`, shows `one of` and the values. An open set, a closed list plus open text such
//! as `OpenCode`, shows the same values and `or another value`. A nullable choice shows its inner shape
//! and `or null`. Any other `oneOf` or `anyOf` shows `choice`. A shape that none of these covers fails
//! the run and names the property path. A property with no description fails the run too, and so does a
//! variant example that does not carry the value that selects its variant.
//!
//! An example is a JSON value stored under `examples` in the schema. The page shows it as YAML, and the
//! YAML must read back as the same value. The test suite checks each example against the schema node it
//! sits under, and decodes it with the rdy-spec parser (ADR 0034).

use std::collections::HashMap;

use anyhow::{Context, Result, anyhow, bail};
use serde_json::{Map, Value};

/// The type names a type list may hold. Anything else fails the render.
const TYPE_NAMES: [&str; 7] = [
    "string", "integer", "number", "boolean", "null", "object", "array",
];

const TABLE_HEAD: &str = "| Property | Type | Required | Default | Description | Example |\n| --- | --- | --- | --- | --- | --- |\n";

/// What a page says around the generated tables.
pub struct Page<'a> {
    /// The `title` of the frontmatter.
    pub title: &'a str,
    /// The `description` of the frontmatter.
    pub description: &'a str,
    /// The hand-written prose, read from `docs/intro/`. It goes after the banner and before the tables.
    pub intro: &'a str,
    /// Definitions that are documents of their own, with the heading of each: `(name, heading)`. Each one
    /// gets an H2 section after the root, in this order.
    pub documents: &'a [(&'a str, &'a str)],
}

/// Renders the whole page from the text of a schema.
pub fn page(schema_text: &str, page: &Page<'_>) -> Result<String> {
    let schema: Value = serde_json::from_str(schema_text)
        .context("the schema is not valid JSON. Run `cargo xtask schema` to write it again.")?;
    // The root of the result schema is a `$ref` to `Report`, so follow it to the object that holds the
    // fields. The names it passes go in the chain, so a definition that holds the root fails.
    let (names, top) = resolve(&schema, &schema, "The top level", &[])?;
    let mut out = frontmatter(page.title, page.description);
    out.push_str(page.intro.trim_end());
    out.push_str("\n\n");
    if let Some(text) = text(&schema, "description").or_else(|| text(top, "description")) {
        out.push_str(text.trim_end());
        out.push_str("\n\n");
    }
    out.push_str("## Top-level fields\n\n");
    let mut shown = Shown::new();
    write_table(&schema, top, "", &names, None, 1, &mut shown, &mut out)?;
    for (name, heading) in page.documents {
        let node = schema
            .get("$defs")
            .and_then(|defs| defs.get(*name))
            .with_context(|| {
                format!(
                    "the document {name} is not in the schema. Fix the document list in crates/xtask/src/docs.rs, or the schema in rdy-spec."
                )
            })?;
        shown.insert(node as *const Value, (*heading).to_owned());
        out.push_str(&format!("\n## {heading}\n\n"));
        if let Some(text) = text(node, "description") {
            out.push_str(text.trim_end());
            out.push_str("\n\n");
        }
        write_table(&schema, node, name, &[name], None, 2, &mut shown, &mut out)?;
    }
    Ok(out)
}

/// Frontmatter first, because Starlight reads it only at the start of the file. The banner follows.
fn frontmatter(title: &str, description: &str) -> String {
    format!(
        "---\ntitle: {title}\ndescription: {description}\n---\n\n<!-- Generated by cargo xtask docs. Do not edit. -->\n\n"
    )
}

/// The objects the page has shown, by address in the schema, with the heading of the section that holds
/// each one. A property that names a shown object links to that heading instead.
type Shown = HashMap<*const Value, String>;

/// The anchor a heading gets on the site: lowercase, letters, digits, hyphens and underscores, with each
/// space a hyphen. This matches github-slugger for the ASCII headings the reference pages have. The
/// test `the_spec_page_has_unique_headings_and_links_that_resolve` checks every link against it.
fn anchor(heading: &str) -> String {
    heading
        .trim()
        .to_lowercase()
        .chars()
        .filter_map(|c| match c {
            ' ' => Some('-'),
            c if c.is_alphanumeric() || c == '-' || c == '_' => Some(c),
            _ => None,
        })
        .collect()
}

/// A table that gets its own section: an object with fields, an object form of a `oneOf` or `anyOf`,
/// or a variant of an `allOf` `if`/`then`.
struct Section<'a> {
    /// The heading text, without the `#` marks that start it.
    heading: String,
    /// The dotted name of `object`, with array and variant marks. Its properties are named under it,
    /// and errors start with it.
    path: String,
    object: &'a Value,
    /// The defs entered on the way to `object`.
    chain: Vec<&'a str>,
    /// The example whose values fill the Example column of this table.
    context: Option<&'a Value>,
}

/// What a property shows in its row, and the sections it adds.
struct Shape<'a> {
    label: String,
    /// The schema the property points at, after every `$ref` is followed. Its default, its description
    /// and its examples are the fallbacks when the property has none of its own.
    node: &'a Value,
    sections: Vec<Section<'a>>,
}

/// Writes one table for `object`, its examples, then one section for each object with fields that a
/// property names, and each variant of `object`. `path` is the dotted name of `object`, empty for the
/// root. `chain` holds the defs that `object` came from. `context` is the example that fills the
/// Example column. `level` is the heading level of this table, and its sections sit one level below.
/// `shown` holds the objects already on the page, so an object that a second property names is not
/// shown twice.
#[allow(clippy::too_many_arguments)]
fn write_table<'a>(
    root: &'a Value,
    object: &'a Value,
    path: &str,
    chain: &[&'a str],
    context: Option<&'a Value>,
    level: usize,
    shown: &mut Shown,
    out: &mut String,
) -> Result<()> {
    let required = required_names(object);
    let mut rows = String::new();
    let mut sections: Vec<Section<'a>> = Vec::new();
    let properties: Option<&'a Map<String, Value>> =
        object.get("properties").and_then(Value::as_object);
    for (name, schema) in properties.into_iter().flatten() {
        let here = join(path, name);
        let shape = shape(root, schema, &here, name, chain)?;
        let description = text(schema, "description")
            .or_else(|| text(shape.node, "description"))
            .filter(|text| !text.trim().is_empty())
            .with_context(|| {
                format!(
                    "{here} has no description. Add a doc comment or a `description` in rdy-spec, then run `cargo xtask schema` and `cargo xtask docs` again."
                )
            })?;
        let own = examples_of(schema);
        let property_examples = if own.is_empty() {
            examples_of(shape.node)
        } else {
            own
        };
        let example = context
            .and_then(|value| value.get(name))
            .or_else(|| property_examples.first().copied());
        let is_required = if required.contains(&name.as_str()) {
            "yes"
        } else {
            "no"
        };
        let default = schema.get("default").or_else(|| shape.node.get("default"));
        let mut label = shape.label;
        let links = claim(shape.sections, shown, &mut sections);
        if !links.is_empty() {
            label.push_str(", see ");
            label.push_str(&links.join(" and "));
        }
        rows.push_str(&format!(
            "| `{name}` | {} | {is_required} | {} | {} | {} |\n",
            cell(&label),
            default_cell(default),
            cell(description),
            example_cell(example, &here)?
        ));
    }
    // A variant has no row, so a repeat of one is dropped without a link.
    let _ = claim(
        variant_sections(root, object, path, chain)?,
        shown,
        &mut sections,
    );

    out.push_str(TABLE_HEAD);
    out.push_str(&rows);
    for example in examples_of(object) {
        out.push_str("\nExample:\n\n```yaml\n");
        out.push_str(&yaml_block(example, &display(path))?);
        out.push_str("```\n");
    }
    let marks = "#".repeat(level + 1);
    for section in sections {
        out.push_str(&format!("\n{marks} {}\n\n", section.heading));
        if let Some(text) = text(section.object, "description") {
            out.push_str(text.trim_end());
            out.push_str("\n\n");
        }
        write_table(
            root,
            section.object,
            &section.path,
            &section.chain,
            section.context,
            level + 1,
            shown,
            out,
        )?;
    }
    Ok(())
}

/// Takes the sections that are not on the page yet, and records them as shown. A section whose object is
/// shown already is dropped. The return value holds a Markdown link to the heading of each dropped one.
fn claim<'a>(
    offered: Vec<Section<'a>>,
    shown: &mut Shown,
    kept: &mut Vec<Section<'a>>,
) -> Vec<String> {
    let mut links = Vec::new();
    for section in offered {
        let key = section.object as *const Value;
        match shown.get(&key) {
            Some(heading) => links.push(format!("[{heading}](#{})", anchor(heading))),
            None => {
                shown.insert(key, section.heading.clone());
                kept.push(section);
            }
        }
    }
    links
}

/// Works out a property's label and the sections it adds. `here` is the dotted path, and `base` is the
/// readable name a section takes: the property name, or `name entries` for the items of an array.
/// `chain` holds the defs already entered, so a schema that holds itself fails with the path instead of
/// recursing forever.
fn shape<'a>(
    root: &'a Value,
    schema: &'a Value,
    here: &str,
    base: &str,
    chain: &[&'a str],
) -> Result<Shape<'a>> {
    let (names, node) = resolve(root, schema, here, chain)?;
    let mut inside: Vec<&'a str> = chain.to_vec();
    inside.extend(names);
    if let Some(inner) = nullable_inner(node) {
        // Shown as its inner shape with `or null`, so `object or null` gets the object's section.
        let shown = shape(root, inner, here, base, &inside)?;
        return Ok(Shape {
            label: format!("{} or null", shown.label),
            node: shown.node,
            sections: shown.sections,
        });
    }
    if let Some(values) = fixed_values(node) {
        return Ok(Shape {
            label: one_of_label(&values),
            node,
            sections: Vec::new(),
        });
    }
    if let Some(values) = open_values(root, node) {
        return Ok(Shape {
            label: format!("{}, or another value", one_of_label(&values)),
            node,
            sections: Vec::new(),
        });
    }
    if node.get("type").is_none() && (node.get("oneOf").is_some() || node.get("anyOf").is_some()) {
        if let Some(union) = union_shape(root, node, here, base, &inside)? {
            return Ok(union);
        }
        return Ok(Shape {
            label: "choice".to_owned(),
            node,
            sections: option_sections(root, node, here, base, &inside)?,
        });
    }
    if let Some(Value::Array(kinds)) = node.get("type") {
        return type_list_shape(here, node, kinds);
    }
    let Some(kind) = node.get("type").and_then(Value::as_str) else {
        bail!(
            "{here} has no single type and is not a fixed set of values. Give it a `type` in rdy-spec."
        );
    };
    match kind {
        "string" | "integer" | "number" | "boolean" | "null" => Ok(Shape {
            label: kind.to_owned(),
            node,
            sections: Vec::new(),
        }),
        "array" => {
            let Some(items) = node.get("items") else {
                bail!("{here} is an array with no `items`. Give it `items` in rdy-spec.");
            };
            let inner = shape(
                root,
                items,
                &format!("{here}[]"),
                &format!("{base} entries"),
                &inside,
            )?;
            Ok(Shape {
                label: format!("array of {}", inner.label),
                node,
                sections: inner.sections,
            })
        }
        "object" => {
            let sections = if has_fields(node) {
                vec![Section {
                    heading: base.to_owned(),
                    path: here.to_owned(),
                    object: node,
                    chain: inside.clone(),
                    context: None,
                }]
            } else {
                Vec::new()
            };
            Ok(Shape {
                label: "object".to_owned(),
                node,
                sections,
            })
        }
        other => bail!(
            "{here} has the type {other}, which the spec reference does not read yet. Add the type to `shape` in crates/xtask/src/spec_reference.rs, or change the schema in rdy-spec."
        ),
    }
}

/// A list of types, such as `string` and `null` for a nullable field. The label names each type. A list
/// that holds fields fails, because its fields would not be shown.
fn type_list_shape<'a>(here: &str, node: &'a Value, kinds: &[Value]) -> Result<Shape<'a>> {
    let mut labels: Vec<&str> = Vec::new();
    for kind in kinds {
        let name = kind
            .as_str()
            .filter(|name| TYPE_NAMES.contains(name))
            .with_context(|| {
                format!("{here} has a type list with a type that the spec reference does not read. Fix the schema in rdy-spec.")
            })?;
        labels.push(name);
    }
    if labels.is_empty() || has_fields(node) {
        bail!(
            "{here} has a list of types and fields at once. Give it one type, and move the fields into a definition, in rdy-spec."
        );
    }
    Ok(Shape {
        label: labels.join(" or "),
        node,
        sections: Vec::new(),
    })
}

/// The label of a `oneOf` or `anyOf` whose options are scalar types or objects: the types, joined with
/// `or`. Each object option gets a section, from [`option_sections`]. `None` when an option is neither,
/// such as a constraint with no type, so the caller falls back to `choice`.
fn union_shape<'a>(
    root: &'a Value,
    node: &'a Value,
    here: &str,
    base: &str,
    inside: &[&'a str],
) -> Result<Option<Shape<'a>>> {
    let Some(options) = options_of(node) else {
        return Ok(None);
    };
    let mut labels: Vec<&str> = Vec::new();
    let mut objects = 0_usize;
    for option in options {
        let (_, target) = resolve(root, option, here, inside)?;
        let label = if has_fields(target) {
            objects += 1;
            "object"
        } else {
            match target.get("type").and_then(Value::as_str) {
                Some("string") => "string",
                Some("integer") => "integer",
                Some("number") => "number",
                Some("boolean") => "boolean",
                Some("object") => "object",
                Some("null") => "null",
                _ => return Ok(None),
            }
        };
        if !labels.contains(&label) {
            labels.push(label);
        }
    }
    if labels.is_empty() {
        return Ok(None);
    }
    let sections = if objects > 0 {
        option_sections(root, node, here, base, inside)?
    } else {
        Vec::new()
    };
    Ok(Some(Shape {
        label: labels.join(" or "),
        node,
        sections,
    }))
}

/// The options of a `oneOf` or `anyOf`, in that order. `None` when the node has neither.
fn options_of(node: &Value) -> Option<&Vec<Value>> {
    ["oneOf", "anyOf"]
        .iter()
        .find_map(|key| node.get(*key).and_then(Value::as_array))
}

/// One section for each object form of a `oneOf` or `anyOf`. When the object is one of several forms,
/// the section is titled `as an object`. Otherwise it is titled by its number among the options.
fn option_sections<'a>(
    root: &'a Value,
    node: &'a Value,
    here: &str,
    base: &str,
    chain: &[&'a str],
) -> Result<Vec<Section<'a>>> {
    let mut forms: Vec<(usize, Vec<&'a str>, &'a Value)> = Vec::new();
    for key in ["oneOf", "anyOf"] {
        let Some(Value::Array(options)) = node.get(key) else {
            continue;
        };
        for (index, option) in options.iter().enumerate() {
            let (names, target) = resolve(root, option, here, chain)?;
            if has_fields(target) {
                forms.push((index + 1, names, target));
            }
        }
    }
    let total = options_of(node).map_or(0, Vec::len);
    let mixed = forms.len() == 1 && total > 1;
    let mut sections = Vec::new();
    for (number, names, target) in forms {
        let mut inside: Vec<&'a str> = chain.to_vec();
        inside.extend(names);
        let heading = if mixed {
            format!("{base}, as an object")
        } else {
            format!("{base}, option {number}")
        };
        sections.push(Section {
            heading,
            path: with_selector(here, &format!("option {number}")),
            object: target,
            chain: inside,
            context: None,
        });
    }
    Ok(sections)
}

/// One section for each `allOf` `if`/`then` that fixes one property of `object` to a constant, such
/// as `id` of a check. The `then` must hold fields. Each example of the variant must carry the constant.
fn variant_sections<'a>(
    root: &'a Value,
    object: &'a Value,
    path: &str,
    chain: &[&'a str],
) -> Result<Vec<Section<'a>>> {
    let mut sections = Vec::new();
    let Some(Value::Array(parts)) = object.get("allOf") else {
        return Ok(sections);
    };
    for part in parts {
        let (Some(condition), Some(then)) = (part.get("if"), part.get("then")) else {
            continue;
        };
        let Some(Value::Object(tests)) = condition.get("properties") else {
            continue;
        };
        if tests.len() != 1 {
            continue;
        }
        let Some((key, test)) = tests.iter().next() else {
            continue;
        };
        let Some(constant) = test.get("const") else {
            continue;
        };
        // Only a named definition is a variant. An inline `then` constrains fields the object already has.
        if then.get("$ref").is_none() {
            continue;
        }
        let (names, target) = resolve(root, then, path, chain)?;
        if !has_fields(target) {
            continue;
        }
        let shown = scalar_text(constant);
        let variant_examples = examples_of(target);
        for example in &variant_examples {
            if example.get(key) != Some(constant) {
                bail!(
                    "{} has an example whose {key} is not {shown}. A variant example must carry the value that selects it. Fix the example in rdy-spec.",
                    display(path)
                );
            }
        }
        let mut inside: Vec<&'a str> = chain.to_vec();
        inside.extend(names);
        sections.push(Section {
            heading: shown.clone(),
            path: with_selector(path, &format!("{key}={shown}")),
            object: target,
            chain: inside,
            context: variant_examples.first().copied(),
        });
    }
    Ok(sections)
}

/// The example as a YAML document. It is read back, and it must give the same value. Fails otherwise.
fn yaml_block(example: &Value, here: &str) -> Result<String> {
    let mut text = serde_saphyr::to_string(example)
        .map_err(|e| anyhow!("{here} example cannot be written as YAML: {e}"))?;
    let back: Value = serde_saphyr::from_str(&text).map_err(|e| {
        anyhow!("{here} example does not read back as YAML: {e}. Fix the example in rdy-spec.")
    })?;
    if back != *example {
        bail!("{here} example reads back as a different value. Fix the example in rdy-spec.");
    }
    if !text.ends_with('\n') {
        text.push('\n');
    }
    Ok(text)
}

/// The example as one line of YAML, for a table cell. A top-level scalar is plain YAML when YAML allows
/// it. A list or a map is written in flow style, with its strings in double quotes, which is valid YAML.
fn yaml_inline(example: &Value) -> Result<String> {
    match example {
        Value::Array(_) | Value::Object(_) => flow(example),
        _ => Ok(serde_saphyr::to_string(example)
            .map_err(|e| anyhow!("an example cannot be written as YAML: {e}"))?
            .trim_end()
            .to_owned()),
    }
}

/// A value in YAML flow style on one line. Strings are JSON strings, which are valid YAML.
fn flow(value: &Value) -> Result<String> {
    Ok(match value {
        Value::Array(items) => {
            let parts: Result<Vec<String>> = items.iter().map(flow).collect();
            format!("[{}]", parts?.join(", "))
        }
        Value::Object(map) => {
            let mut parts = Vec::new();
            for (key, inner) in map {
                parts.push(format!("{}: {}", serde_json::to_string(key)?, flow(inner)?));
            }
            format!("{{{}}}", parts.join(", "))
        }
        other => serde_json::to_string(other)?,
    })
}

fn example_cell(example: Option<&Value>, here: &str) -> Result<String> {
    match example {
        None => Ok(String::new()),
        Some(value) => {
            let inline = yaml_inline(value).with_context(|| format!("{here} example"))?;
            Ok(cell(&format!("`{inline}`")))
        }
    }
}

/// The values of a field with a fixed set of them: an `enum`, or a `oneOf` or `anyOf` of constants
/// with no `type` of its own. `None` for any other shape.
fn fixed_values(node: &Value) -> Option<Vec<&Value>> {
    if let Some(Value::Array(values)) = node.get("enum") {
        return Some(values.iter().collect());
    }
    if node.get("type").is_some() {
        return None;
    }
    // A bare `const` is a set of one value, such as the `kind` of a document.
    if let Some(constant) = node.get("const") {
        return Some(vec![constant]);
    }
    for key in ["oneOf", "anyOf"] {
        if let Some(Value::Array(options)) = node.get(key) {
            let constants: Option<Vec<&Value>> =
                options.iter().map(|option| option.get("const")).collect();
            if let Some(constants) = constants.filter(|list| !list.is_empty()) {
                return Some(constants);
            }
        }
    }
    None
}

/// The option that is not `null` in a `anyOf` or `oneOf` of exactly two options, one of them `null`. `None`
/// for any other node.
fn nullable_inner(node: &Value) -> Option<&Value> {
    if node.get("type").is_some() {
        return None;
    }
    let options = options_of(node)?;
    if options.len() != 2 {
        return None;
    }
    let is_null = |option: &Value| option.get("type").and_then(Value::as_str) == Some("null");
    match (is_null(&options[0]), is_null(&options[1])) {
        (false, true) => Some(&options[0]),
        (true, false) => Some(&options[1]),
        _ => None,
    }
}

/// The values of an open set: a `anyOf` or `oneOf` whose options are `enum` lists or constants, plus one
/// option that is open text, such as `OpenCode`. A newer producer may send other text, so the row says
/// so. `None` for any other node.
fn open_values<'a>(root: &'a Value, node: &'a Value) -> Option<Vec<&'a Value>> {
    if node.get("type").is_some() {
        return None;
    }
    let options = options_of(node)?;
    let mut values: Vec<&'a Value> = Vec::new();
    let mut open = false;
    for option in options {
        if let Some(Value::Array(list)) = option.get("enum") {
            values.extend(list.iter());
        } else if let Some(constant) = option.get("const") {
            values.push(constant);
        } else {
            let (_, target) = resolve(root, option, "", &[]).ok()?;
            let is_text = target.get("type").and_then(Value::as_str) == Some("string");
            if !is_text || fixed_values(target).is_some() {
                return None;
            }
            open = true;
        }
    }
    (open && !values.is_empty()).then_some(values)
}

fn one_of_label(values: &[&Value]) -> String {
    let shown: Vec<String> = values
        .iter()
        .map(|value| format!("`{}`", scalar_text(value)))
        .collect();
    format!("one of {}", shown.join(", "))
}

/// A value as the text a reader sees: a string as it is, anything else as JSON.
fn scalar_text(value: &Value) -> String {
    match value {
        Value::String(text) => text.clone(),
        other => other.to_string(),
    }
}

/// The examples stored under `examples` in a schema node. Empty when it has none.
fn examples_of(node: &Value) -> Vec<&Value> {
    match node.get("examples") {
        Some(Value::Array(items)) => items.iter().collect(),
        _ => Vec::new(),
    }
}

/// Follows `$ref` links, possibly several, to the schema they end at. Returns the names of the defs
/// passed, in order. A name that is in `chain`, or that the links pass twice, is a cycle and fails
/// with the path.
fn resolve<'a>(
    root: &'a Value,
    schema: &'a Value,
    here: &str,
    chain: &[&'a str],
) -> Result<(Vec<&'a str>, &'a Value)> {
    let mut node = schema;
    let mut names: Vec<&'a str> = Vec::new();
    loop {
        let Some(reference) = node.get("$ref") else {
            return Ok((names, node));
        };
        let Some(pointer) = reference.as_str() else {
            bail!("{here} has a $ref that is not text. Fix the schema that rdy-spec generates.");
        };
        let Some(name) = pointer.strip_prefix("#/$defs/") else {
            bail!(
                "{here} refers to {pointer}. The spec reference reads only `#/$defs/` names. Fix the reference in rdy-spec."
            );
        };
        if chain.contains(&name) {
            bail!(
                "{here} refers to {name}, which already encloses it. A table cannot hold a cycle. Break the cycle in rdy-spec."
            );
        }
        if names.contains(&name) {
            bail!("{here} has a $ref cycle through {name}. Break the cycle in rdy-spec.");
        }
        node = root
            .get("$defs")
            .and_then(|defs| defs.get(name))
            .with_context(|| {
                format!(
                    "{here} refers to {pointer}, which is not defined in the schema. Fix the reference in rdy-spec."
                )
            })?;
        names.push(name);
    }
}

fn has_fields(node: &Value) -> bool {
    node.get("properties")
        .and_then(Value::as_object)
        .is_some_and(|properties| !properties.is_empty())
}

fn required_names(object: &Value) -> Vec<&str> {
    object
        .get("required")
        .and_then(Value::as_array)
        .map(|names| names.iter().filter_map(Value::as_str).collect())
        .unwrap_or_default()
}

fn text<'a>(node: &'a Value, key: &str) -> Option<&'a str> {
    node.get(key).and_then(Value::as_str)
}

/// The dotted name of a property under `path`.
fn join(path: &str, name: &str) -> String {
    if path.is_empty() {
        name.to_owned()
    } else {
        format!("{path}.{name}")
    }
}

/// The name of an object in an error message. The root has no name, so it is called the top level.
fn display(path: &str) -> String {
    if path.is_empty() {
        "The top level".to_owned()
    } else {
        path.to_owned()
    }
}

/// The path of an option of the object at `path`. A path that names array items keeps its place:
/// `checks[]` becomes `checks[option 2]`.
fn with_selector(path: &str, selector: &str) -> String {
    match path.strip_suffix("[]") {
        Some(base) => format!("{base}[{selector}]"),
        None => format!("{path}[{selector}]"),
    }
}

/// One table cell: the words on one line, with each `|` escaped so it does not end the cell.
fn cell(text: &str) -> String {
    text.split_whitespace()
        .collect::<Vec<_>>()
        .join(" ")
        .replace('|', "\\|")
}

fn default_cell(value: Option<&Value>) -> String {
    match value {
        None => String::new(),
        Some(Value::String(text)) => cell(&format!("`{text}`")),
        Some(other) => cell(&format!("`{other}`")),
    }
}

#[cfg(test)]
mod tests {
    use std::collections::HashSet;

    use super::*;
    use rdy_spec::check::CheckParams;

    /// Renders a schema with no intro and no documents. The tests of one rule use this.
    fn page(schema_text: &str) -> Result<String> {
        super::page(
            schema_text,
            &Page {
                title: "Test",
                description: "Test.",
                intro: "",
                documents: &[],
            },
        )
    }

    /// The committed file at `path`, read from the repo.
    fn committed(path: &str) -> Result<String> {
        let root = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../..");
        Ok(std::fs::read_to_string(root.join(path))?)
    }

    /// The committed readiness schema, read from the repo.
    fn committed_schema() -> Result<String> {
        committed(crate::schema::SPEC_PATH)
    }

    /// The committed result schema, read from the repo.
    fn committed_result_schema() -> Result<String> {
        committed(crate::schema::RESULT_PATH)
    }

    /// The result page as `cargo xtask docs` renders it, with the intro left empty.
    fn committed_result_page() -> Result<String> {
        super::page(
            &committed_result_schema()?,
            &Page {
                title: "Result reference",
                description: "Test.",
                intro: "",
                documents: crate::docs::RESULT_DOCUMENTS,
            },
        )
    }

    /// Rows that start a table body: one per property, in every table of the page.
    fn table_rows(page: &str) -> usize {
        page.lines().filter(|line| line.starts_with("| `")).count()
    }

    /// The number of rows the page must hold: one per property of each object the page shows. An object
    /// is counted once, however many properties name it, as the render shows it once. `seen` holds the
    /// objects counted so far.
    fn expected_rows(root: &Value, object: &Value, seen: &mut Vec<*const Value>) -> Result<usize> {
        if seen.contains(&(object as *const Value)) {
            return Ok(0);
        }
        seen.push(object as *const Value);
        let mut total = 0;
        if let Some(properties) = object.get("properties").and_then(Value::as_object) {
            total += properties.len();
            for schema in properties.values() {
                let mut node = resolve(root, schema, "test", &[])?.1;
                while node.get("type").and_then(Value::as_str) == Some("array") {
                    let Some(items) = node.get("items") else {
                        break;
                    };
                    node = resolve(root, items, "test", &[])?.1;
                }
                if has_fields(node) {
                    total += expected_rows(root, node, seen)?;
                }
                if let Some(options) = options_of(node) {
                    for option in options {
                        let target = resolve(root, option, "test", &[])?.1;
                        if has_fields(target) {
                            total += expected_rows(root, target, seen)?;
                        }
                    }
                }
            }
        }
        if let Some(Value::Array(parts)) = object.get("allOf") {
            for part in parts {
                let (Some(condition), Some(then)) = (part.get("if"), part.get("then")) else {
                    continue;
                };
                let fixed = condition
                    .get("properties")
                    .and_then(Value::as_object)
                    .is_some_and(|tests| tests.len() == 1);
                if !fixed || then.get("$ref").is_none() {
                    continue;
                }
                let target = resolve(root, then, "test", &[])?.1;
                if has_fields(target) {
                    total += expected_rows(root, target, seen)?;
                }
            }
        }
        Ok(total)
    }

    /// Asserts that every heading has its own anchor, and that every link on the page points at one.
    fn assert_links_resolve(page: &str) {
        let headings: Vec<String> = page
            .lines()
            .filter(|line| line.starts_with('#'))
            .map(|line| line.trim_start_matches('#').trim().to_owned())
            .collect();
        let anchors: HashSet<String> = headings.iter().map(|h| anchor(h)).collect();
        assert_eq!(
            anchors.len(),
            headings.len(),
            "two headings share an anchor:\n{page}"
        );
        for link in page.split("](#").skip(1) {
            let target = link.split(')').next().unwrap_or_default();
            assert!(
                anchors.contains(target),
                "{target} is not a heading:\n{page}"
            );
        }
    }

    /// Asserts that rendering `schema` fails with a message that starts with `path`.
    fn fails_at(schema: &str, path: &str) {
        let err = page(schema).err().map(|e| format!("{e:#}"));
        let message = err.unwrap_or_else(|| "no error".to_owned());
        assert!(
            message.starts_with(path),
            "expected an error that starts with {path:?}, got {message:?}"
        );
    }

    /// The `examples` of every node in the schema, with the path where each one sits.
    fn all_examples(node: &Value, at: &str, out: &mut Vec<(String, Value)>) {
        match node {
            Value::Object(map) => {
                for (key, inner) in map {
                    if key == "examples" {
                        if let Value::Array(items) = inner {
                            for item in items {
                                out.push((at.to_owned(), item.clone()));
                            }
                        }
                    } else {
                        all_examples(inner, &format!("{at}/{key}"), out);
                    }
                }
            }
            Value::Array(items) => {
                for (index, inner) in items.iter().enumerate() {
                    all_examples(inner, &format!("{at}/{index}"), out);
                }
            }
            _ => {}
        }
    }

    /// The validator rdy-spec uses in its tests: draft 2020-12, with formats checked. It holds the
    /// whole schema, so a `$ref` resolves, and it checks a value as a `Check`, the node the variant
    /// examples sit under.
    fn check_validator(schema: &Value) -> Result<jsonschema::Validator> {
        let wrapper = serde_json::json!({
            "$schema": "https://json-schema.org/draft/2020-12/schema",
            "$ref": "#/$defs/Check",
            "$defs": schema["$defs"],
        });
        Ok(jsonschema::draft202012::options()
            .should_validate_formats(true)
            .build(&wrapper)?)
    }

    #[test]
    fn the_readiness_schema_has_one_table_row_per_property() -> Result<()> {
        let schema_text = committed_schema()?;
        let schema: Value = serde_json::from_str(&schema_text)?;
        let page = page(&schema_text)?;
        let expected = expected_rows(&schema, &schema, &mut Vec::new())?;
        assert_eq!(table_rows(&page), expected);
        assert_links_resolve(&page);
        // Five top-level properties, six in metadata, four in bundle, six in each checks entry and
        // two in each redact_patterns entry. The parameters of the 17 check ids come on top, as their
        // own tables under each checks entry. `k8s.nodes` has `per_node` and `free` of one definition,
        // so its four fields are shown once, under `per_node`, and `free` links to that section.
        assert_eq!(expected, 120);
        assert!(page.contains("\n## checks entries\n\n"), "{page}");
        // `bundle` is a section, so its own sections sit one level below it.
        assert!(page.contains("\n### redact_patterns entries\n\n"), "{page}");
        assert!(
            page.contains("| `checks` | array of object | yes |"),
            "{page}"
        );
        Ok(())
    }

    #[test]
    fn every_check_id_gets_its_own_titled_section_and_example() -> Result<()> {
        let page = page(&committed_schema()?)?;
        let ids = [
            "host.cpu",
            "host.memory",
            "host.disk",
            "host.ports",
            "host.lsm",
            "host.security_agents",
            "host.os",
            "net.egress",
            "net.proxy",
            "net.tls_intercept",
            "net.dns",
            "k8s.access",
            "k8s.storageclass",
            "k8s.rbac",
            "k8s.admission",
            "k8s.nodes",
            "k8s.version",
        ];
        for id in ids {
            assert!(page.contains(&format!("\n### {id}\n\n")), "{id}\n{page}");
        }
        assert_eq!(page.matches("```yaml\n").count(), 17, "{page}");
        assert!(
            page.contains("```yaml\nid: host.cpu\nmin: 4\nrecommended: 8\n```"),
            "{page}"
        );
        Ok(())
    }

    #[test]
    fn headings_are_readable_and_nest_one_level_below_their_table() -> Result<()> {
        let page = page(&committed_schema()?)?;
        for line in page.lines().filter(|line| line.starts_with('#')) {
            assert!(!line.contains('[') && !line.contains('='), "{line}");
        }
        assert!(page.contains("\n### host.ports\n\n"), "{page}");
        assert!(
            page.contains("\n#### free entries, as an object\n\n"),
            "{page}"
        );
        Ok(())
    }

    #[test]
    fn every_example_validates_under_its_node_and_decodes() -> Result<()> {
        let schema_text = committed_schema()?;
        let schema: Value = serde_json::from_str(&schema_text)?;
        let mut examples = Vec::new();
        all_examples(&schema, "", &mut examples);
        assert_eq!(examples.len(), 17, "every check id has one example");
        // Each variant's examples sit under `Check`, the object whose `allOf` names the variant.
        let validator = check_validator(&schema)?;
        for (at, example) in &examples {
            assert!(
                validator.validate(example).is_ok(),
                "{at} does not validate: {example}"
            );
            // Decode it the way rdy reads a spec: as the one check of a whole spec document.
            let document = serde_json::json!({
                "apiVersion": "rdy/v1",
                "kind": "Readiness",
                "metadata": {"product": "acme"},
                "checks": [example],
            });
            let yaml = serde_saphyr::to_string(&document)?;
            let spec = rdy_spec::parse_unverified(yaml.as_bytes())
                .map_err(|e| anyhow!("{at} example does not parse as a spec: {e:?}"))?;
            let entry = spec
                .checks
                .first()
                .context("the example document has no check")?;
            assert!(
                !matches!(
                    entry.decode_params(),
                    CheckParams::Unsupported { .. } | CheckParams::Unknown { .. }
                ),
                "{at} does not decode: {example}"
            );
        }
        Ok(())
    }

    #[test]
    fn an_example_that_does_not_validate_is_caught_by_the_check() -> Result<()> {
        // The render does not validate examples. This test does, so a bad example fails the suite.
        let schema: Value = serde_json::from_str(&committed_schema()?)?;
        let validator = check_validator(&schema)?;
        let bad = serde_json::json!({"id": "host.cpu", "min": "lots"});
        assert!(validator.validate(&bad).is_err());
        let unknown = serde_json::json!({"id": "host.cpu", "min": 4, "nope": true});
        assert!(validator.validate(&unknown).is_err());
        Ok(())
    }

    #[test]
    fn scalars_objects_arrays_and_choices_each_get_one_row() -> Result<()> {
        let schema: Value = serde_json::from_str(
            r##"{
              "description": "Root object.",
              "type": "object",
              "properties": {
                "b": {"description": "Second key first in file.\nIt wraps.", "type": "string", "default": "x"},
                "a": {"description": "A | pipe.", "$ref": "#/$defs/Port"},
                "list": {"description": "A list.", "type": "array", "items": {"type": "string"}},
                "pick": {"description": "One of two.", "$ref": "#/$defs/Kind"},
                "inner": {"$ref": "#/$defs/Inner"},
                "map": {"description": "A map.", "type": "object"}
              },
              "required": ["b", "inner"],
              "$defs": {
                "Port": {"description": "1 to 65535.", "type": "integer"},
                "Kind": {"oneOf": [{"const": "A"}]},
                "Inner": {"description": "The inner object.", "type": "object",
                  "properties": {"flag": {"description": "A flag.", "type": "boolean"}}, "required": ["flag"]}
              }
            }"##,
        )?;
        let page = page(&serde_json::to_string(&schema)?)?;
        let rows = [
            "| `b` | string | yes | `x` | Second key first in file. It wraps. |  |",
            "| `a` | integer | no |  | A \\| pipe. |  |",
            "| `list` | array of string | no |  | A list. |  |",
            "| `pick` | one of `A` | no |  | One of two. |  |",
            "| `inner` | object | yes |  | The inner object. |  |",
            "| `map` | object | no |  | A map. |  |",
        ];
        let mut at = 0;
        for row in rows {
            let found = page[at..].find(row);
            assert!(found.is_some(), "missing row {row:?} in\n{page}");
            at += found.unwrap_or(0) + row.len();
        }
        assert!(page.contains("## inner\n\nThe inner object.\n\n| Property | Type | Required | Default | Description | Example |\n| --- | --- | --- | --- | --- | --- |\n| `flag` | boolean | yes |  | A flag. |  |\n"));
        assert_eq!(table_rows(&page), 7);
        Ok(())
    }

    #[test]
    fn an_enum_lists_its_values() -> Result<()> {
        let schema = r#"{"type": "object", "properties": {"sev": {"description": "Severity.", "enum": ["block", "warn"], "default": "block"}}}"#;
        assert!(
            page(schema)?
                .contains("| `sev` | one of `block`, `warn` | no | `block` | Severity. |  |")
        );
        Ok(())
    }

    #[test]
    fn an_open_enum_lists_its_values_and_says_others_are_allowed() -> Result<()> {
        let schema = r##"{"type": "object", "properties": {"sev": {"description": "Severity.",
            "anyOf": [{"enum": ["block", "warn"]}, {"$ref": "#/$defs/Code"}]}},
            "$defs": {"Code": {"description": "A code.", "type": "string", "pattern": "^[a-z]+$"}}}"##;
        assert!(page(schema)?.contains(
            "| `sev` | one of `block`, `warn`, or another value | no |  | Severity. |  |"
        ));
        Ok(())
    }

    #[test]
    fn a_nullable_object_is_an_object_or_null_with_its_section() -> Result<()> {
        let schema = r##"{"type": "object", "properties": {"p": {"description": "Proxy.",
            "anyOf": [{"$ref": "#/$defs/Inner"}, {"type": "null"}]}},
            "$defs": {"Inner": {"description": "Inner.", "type": "object",
              "properties": {"url": {"description": "The URL.", "type": "string"}}}}}"##;
        let page = page(schema)?;
        assert!(
            page.contains("| `p` | object or null | no |  | Proxy. |  |"),
            "{page}"
        );
        assert!(page.contains("\n## p\n\n"), "{page}");
        assert_links_resolve(&page);
        Ok(())
    }

    #[test]
    fn a_union_of_scalar_types_is_labelled_with_its_types() -> Result<()> {
        let schema = r#"{"type": "object", "properties": {"v": {"description": "Version.",
            "oneOf": [{"type": "string"}, {"type": "integer"}]}}}"#;
        let page = page(schema)?;
        assert!(
            page.contains("| `v` | string or integer | no |  | Version. |  |"),
            "{page}"
        );
        assert!(!page.contains("\n## v"), "{page}");
        Ok(())
    }

    #[test]
    fn a_scalar_or_object_union_gets_an_as_an_object_section() -> Result<()> {
        let schema = r#"{"type": "object", "properties": {"pick": {"description": "Pick one.",
            "oneOf": [{"description": "A name.", "type": "string"},
                      {"title": "Long form", "type": "object", "properties": {
                         "name": {"description": "The name.", "type": "string"}}}]}}}"#;
        let page = page(schema)?;
        assert!(
            page.contains("| `pick` | string or object | no |  | Pick one. |  |"),
            "{page}"
        );
        assert!(
            page.contains("\n## pick, as an object\n\n| Property | Type | Required | Default | Description | Example |\n| --- | --- | --- | --- | --- | --- |\n| `name` | string | no |  | The name. |  |\n"),
            "{page}"
        );
        Ok(())
    }

    #[test]
    fn several_object_options_are_numbered() -> Result<()> {
        let schema = r#"{"type": "object", "properties": {"pick": {"description": "Pick one.",
            "oneOf": [{"type": "object", "properties": {"a": {"description": "A.", "type": "string"}}},
                      {"type": "object", "properties": {"b": {"description": "B.", "type": "string"}}}]}}}"#;
        let page = page(schema)?;
        assert!(
            page.contains("| `pick` | object | no |  | Pick one. |  |"),
            "{page}"
        );
        assert!(page.contains("\n## pick, option 1\n\n"), "{page}");
        assert!(page.contains("\n## pick, option 2\n\n"), "{page}");
        Ok(())
    }

    #[test]
    fn an_array_of_one_of_options_names_its_form_by_the_entries() -> Result<()> {
        let schema = r#"{"type": "object", "properties": {"xs": {"description": "Items.", "type": "array",
            "items": {"oneOf": [{"type": "string"},
                                {"type": "object", "properties": {"id": {"description": "Id.", "type": "string"}}}]}}}}"#;
        let page = page(schema)?;
        assert!(
            page.contains("| `xs` | array of string or object | no |  | Items. |  |"),
            "{page}"
        );
        assert!(page.contains("\n## xs entries, as an object\n\n"), "{page}");
        assert!(
            page.contains("| `id` | string | no |  | Id. |  |"),
            "{page}"
        );
        Ok(())
    }

    #[test]
    fn an_all_of_variant_gets_its_own_section_with_its_example() -> Result<()> {
        let schema = r##"{"type": "object", "properties": {"c": {"description": "A check.", "$ref": "#/$defs/Check"}},
            "$defs": {
              "Check": {"type": "object", "description": "One check.",
                "properties": {"id": {"description": "Which check.", "type": "string"}},
                "required": ["id"],
                "allOf": [{"if": {"properties": {"id": {"const": "x.one"}}}, "then": {"$ref": "#/$defs/OneParams"}}]},
              "OneParams": {"type": "object", "properties": {"min": {"description": "Floor.", "type": "integer"}},
                "examples": [{"id": "x.one", "min": 2}]}
            }}"##;
        let page = page(schema)?;
        assert!(
            page.contains("\n### x.one\n\n| Property | Type | Required | Default | Description | Example |\n| --- | --- | --- | --- | --- | --- |\n| `min` | integer | no |  | Floor. | `2` |\n"),
            "{page}"
        );
        assert!(page.contains("```yaml\nid: x.one\nmin: 2\n```"), "{page}");
        Ok(())
    }

    #[test]
    fn a_property_without_a_description_fails_and_names_the_path() {
        fails_at(
            r#"{"type": "object", "properties": {"x": {"type": "string"}}}"#,
            "x has no description",
        );
    }

    #[test]
    fn a_blank_description_counts_as_none() {
        fails_at(
            r#"{"type": "object", "properties": {"x": {"type": "string", "description": "  "}}}"#,
            "x has no description",
        );
    }

    #[test]
    fn a_variant_property_without_a_description_fails_and_names_the_variant_path() {
        fails_at(
            r##"{"type": "object", "properties": {"c": {"description": "A check.", "$ref": "#/$defs/Check"}},
                 "$defs": {"Check": {"type": "object", "properties": {"id": {"description": "Id.", "type": "string"}},
                   "allOf": [{"if": {"properties": {"id": {"const": "x.one"}}}, "then": {"$ref": "#/$defs/P"}}]},
                   "P": {"type": "object", "properties": {"min": {"type": "integer"}}}}}"##,
            "c[id=x.one].min has no description",
        );
    }

    #[test]
    fn a_variant_example_that_names_another_id_fails_and_names_the_path() {
        fails_at(
            r##"{"type": "object", "properties": {"c": {"description": "A check.", "$ref": "#/$defs/Check"}},
                 "$defs": {"Check": {"type": "object", "properties": {"id": {"description": "Id.", "type": "string"}},
                   "allOf": [{"if": {"properties": {"id": {"const": "x.one"}}}, "then": {"$ref": "#/$defs/P"}}]},
                   "P": {"type": "object", "properties": {"min": {"description": "Floor.", "type": "integer"}},
                     "examples": [{"id": "x.two", "min": 1}]}}}"##,
            "c has an example whose id is not x.one",
        );
    }

    #[test]
    fn an_object_example_is_written_as_yaml() -> Result<()> {
        let schema = r#"{"type": "object", "description": "Root.", "examples": [{"a": "x", "count": 2}],
            "properties": {"a": {"description": "A.", "type": "string"}, "count": {"description": "N.", "type": "integer"}}}"#;
        let page = page(schema)?;
        assert!(
            page.contains("\nExample:\n\n```yaml\na: x\ncount: 2\n```\n"),
            "{page}"
        );
        Ok(())
    }

    #[test]
    fn a_property_example_is_shown_in_the_example_column() -> Result<()> {
        let schema = r#"{"type": "object", "properties": {"v": {"description": "Version.", "type": "string",
            "examples": ["1.28"]}}}"#;
        assert!(page(schema)?.contains("| `v` | string | no |  | Version. | `\"1.28\"` |"));
        Ok(())
    }

    #[test]
    fn a_list_example_is_one_line_of_flow_yaml() -> Result<()> {
        let schema = r#"{"type": "object", "properties": {"ports": {"description": "Ports.", "type": "array",
            "items": {"type": "integer"}, "examples": [[80, 443]]}}}"#;
        assert!(
            page(schema)?.contains("| `ports` | array of integer | no |  | Ports. | `[80, 443]` |")
        );
        Ok(())
    }

    #[test]
    fn a_missing_definition_fails_and_names_the_property() {
        fails_at(
            r##"{"type": "object", "properties": {"x": {"description": "X.", "$ref": "#/$defs/Missing"}}}"##,
            "x refers to #/$defs/Missing",
        );
    }

    #[test]
    fn a_reference_outside_defs_fails_and_names_the_property() {
        fails_at(
            r##"{"type": "object", "properties": {"x": {"description": "X.", "$ref": "#/properties/y"}}}"##,
            "x refers to #/properties/y",
        );
    }

    #[test]
    fn a_property_with_no_type_or_choice_fails_and_names_the_path() {
        fails_at(
            r#"{"type": "object", "properties": {"x": {"description": "No type."}}}"#,
            "x has no single type",
        );
    }

    #[test]
    fn a_type_list_shows_each_type_in_its_row() -> Result<()> {
        let schema = r#"{"type": "object", "properties": {"x": {"description": "A name.", "type": ["string", "null"]}}}"#;
        assert!(page(schema)?.contains("| `x` | string or null | no |  | A name. |  |"));
        Ok(())
    }

    #[test]
    fn a_type_list_with_fields_fails_and_names_the_property() {
        fails_at(
            r#"{"type": "object", "properties": {"x": {"description": "X.", "type": ["object", "null"],
                "properties": {"y": {"description": "Y.", "type": "string"}}}}}"#,
            "x has a list of types and fields at once",
        );
    }

    #[test]
    fn a_type_list_with_an_unknown_type_fails_and_names_the_property() {
        fails_at(
            r#"{"type": "object", "properties": {"x": {"description": "X.", "type": ["string", "date"]}}}"#,
            "x has a type list",
        );
    }

    #[test]
    fn an_inline_then_is_a_constraint_and_gets_no_section() -> Result<()> {
        let schema = r#"{"type": "object", "properties": {"id": {"description": "Id.", "type": "string"},
            "min": {"description": "Min.", "type": "integer"}},
            "allOf": [{"if": {"properties": {"id": {"const": "x"}}}, "then": {"properties": {"min": {"const": 1}}}}]}"#;
        let page = page(schema)?;
        assert!(!page.contains("\n### x"), "{page}");
        assert_eq!(table_rows(&page), 2);
        Ok(())
    }

    #[test]
    fn an_object_named_twice_is_shown_once_and_the_second_row_links_to_it() -> Result<()> {
        let schema = r##"{"type": "object", "properties": {
              "first": {"description": "First.", "$ref": "#/$defs/Inner"},
              "second": {"description": "Second.", "$ref": "#/$defs/Inner"}},
            "$defs": {"Inner": {"description": "The inner object.", "type": "object",
              "properties": {"flag": {"description": "A flag.", "type": "boolean"}}}}}"##;
        let page = page(schema)?;
        assert!(
            page.contains("| `first` | object | no |  | First. |  |"),
            "{page}"
        );
        assert!(
            page.contains("| `second` | object, see [first](#first) | no |  | Second. |  |"),
            "{page}"
        );
        assert_eq!(page.matches("\n## first\n").count(), 1, "{page}");
        assert!(!page.contains("\n## second\n"), "{page}");
        assert_eq!(table_rows(&page), 3);
        assert_links_resolve(&page);
        Ok(())
    }

    #[test]
    fn an_unknown_type_fails_with_a_fix_hint_and_names_the_property() {
        let schema =
            r#"{"type": "object", "properties": {"x": {"description": "X.", "type": "file"}}}"#;
        fails_at(schema, "x has the type file");
        let text = page(schema)
            .err()
            .map(|e| format!("{e:#}"))
            .unwrap_or_default();
        assert!(text.contains("Add the type to `shape`"), "{text}");
    }

    #[test]
    fn an_array_with_no_items_fails_and_names_the_property() {
        fails_at(
            r#"{"type": "object", "properties": {"xs": {"description": "Xs.", "type": "array"}}}"#,
            "xs is an array with no `items`",
        );
    }

    #[test]
    fn a_definition_that_holds_itself_fails_and_names_the_path() {
        fails_at(
            r##"{"type": "object", "properties": {"a": {"description": "A.", "$ref": "#/$defs/A"}},
                 "$defs": {"A": {"type": "object", "properties": {"next": {"description": "Next.", "$ref": "#/$defs/A"}}}}}"##,
            "a.next refers to A, which already encloses it",
        );
    }

    #[test]
    fn an_array_that_holds_itself_fails_and_names_the_path() {
        fails_at(
            r##"{"type": "object", "properties": {"xs": {"description": "Xs.", "type": "array", "items": {"$ref": "#/$defs/L"}}},
                 "$defs": {"L": {"type": "array", "items": {"$ref": "#/$defs/L"}}}}"##,
            "xs[][] refers to L, which already encloses it",
        );
    }

    #[test]
    fn a_chain_of_references_that_loops_fails_and_names_the_path() {
        fails_at(
            r##"{"type": "object", "properties": {"x": {"description": "X.", "$ref": "#/$defs/B"}},
                 "$defs": {"B": {"$ref": "#/$defs/C"}, "C": {"$ref": "#/$defs/B"}}}"##,
            "x has a $ref cycle through B",
        );
    }

    #[test]
    fn a_chain_of_references_that_ends_is_followed() -> Result<()> {
        let schema = r##"{"type": "object", "properties": {"x": {"description": "X.", "$ref": "#/$defs/B"}},
                 "$defs": {"B": {"$ref": "#/$defs/C"}, "C": {"type": "integer", "description": "Deep."}}}"##;
        assert!(page(schema)?.contains("| `x` | integer | no |  | X. |  |"));
        Ok(())
    }

    #[test]
    fn a_default_that_is_not_text_is_shown_as_json() -> Result<()> {
        let schema = r#"{"type": "object", "properties": {"x": {"description": "X.", "type": "boolean", "default": false}}}"#;
        assert!(page(schema)?.contains("| `x` | boolean | no | `false` | X. |  |"));
        Ok(())
    }

    #[test]
    fn fields_keep_the_order_of_the_schema_file() -> Result<()> {
        let schema = r#"{"type": "object", "properties": {"zeta": {"description": "Z.", "type": "string"}, "alpha": {"description": "A.", "type": "string"}}}"#;
        let page = page(schema)?;
        assert!(
            page.find("`zeta`")
                .is_some_and(|z| page.find("`alpha`").is_some_and(|a| z < a))
        );
        Ok(())
    }

    #[test]
    fn the_page_is_the_same_on_every_render() -> Result<()> {
        let schema = committed_schema()?;
        assert_eq!(page(&schema)?, page(&schema)?);
        Ok(())
    }

    #[test]
    fn the_spec_page_has_unique_headings_and_links_that_resolve() -> Result<()> {
        assert_links_resolve(&page(&committed_schema()?)?);
        Ok(())
    }

    #[test]
    fn the_result_page_has_one_row_per_field_and_every_object_once() -> Result<()> {
        let schema_text = committed_result_schema()?;
        let schema: Value = serde_json::from_str(&schema_text)?;
        let page = committed_result_page()?;
        let top = resolve(&schema, &schema, "test", &[])?.1;
        let mut seen = Vec::new();
        let mut expected = expected_rows(&schema, top, &mut seen)?;
        for (name, _) in crate::docs::RESULT_DOCUMENTS {
            expected += expected_rows(&schema, &schema["$defs"][*name], &mut seen)?;
        }
        assert_eq!(table_rows(&page), expected, "{page}");
        // Every object definition with fields is on the page, so none is dropped without a word.
        if let Some(defs) = schema["$defs"].as_object() {
            for (name, def) in defs {
                if has_fields(def) {
                    assert!(
                        seen.contains(&(def as *const Value)),
                        "{name} has fields and is not on the page"
                    );
                }
            }
        }
        assert_links_resolve(&page);
        Ok(())
    }

    #[test]
    fn the_result_page_shows_the_report_then_each_document() -> Result<()> {
        let page = committed_result_page()?;
        assert!(page.contains("\n## Top-level fields\n\n"), "{page}");
        let mut at = 0;
        for (_, heading) in crate::docs::RESULT_DOCUMENTS {
            let found = page[at..].find(&format!("\n## {heading}\n\n"));
            assert!(
                found.is_some(),
                "{heading} is missing or out of order:\n{page}"
            );
            at += found.unwrap_or(0);
        }
        assert!(
            page.contains("| `kind` | string | yes |  | Always `Report`. |"),
            "{page}"
        );
        Ok(())
    }
}
