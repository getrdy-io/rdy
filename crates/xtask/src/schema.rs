//! `cargo xtask schema`: writes the JSON schema files generated from the rdy-spec types.
//!
//! The Rust types are the source of truth (ADR 0012). `rdy_spec::schema` renders the two files, this
//! command writes them under `crates/rdy-spec/schema/`, and `--check` fails when the files on disk
//! differ from a fresh render. The run also lints every description in the render. A description that
//! names an ADR, a milestone or a plan document fails, written or not, because the text reaches
//! customers through the docs site and the editors that read the schema.

use std::path::Path;

use anyhow::Result;
use serde_json::Value;

use crate::generate::{self, Generated};

/// Where the spec schema is written.
pub const SPEC_PATH: &str = "crates/rdy-spec/schema/spec.v1.schema.json";
/// Where the result schema is written.
pub const RESULT_PATH: &str = "crates/rdy-spec/schema/result.v1.schema.json";

/// The schema files this build generates.
fn outputs() -> Vec<Generated> {
    vec![
        Generated {
            path: SPEC_PATH,
            contents: rdy_spec::schema::spec_schema_json(),
        },
        Generated {
            path: RESULT_PATH,
            contents: rdy_spec::schema::result_schema_json(),
        },
    ]
}

/// Writes the schema files, or checks them when `check` is set. Returns `Ok(true)` when the run passes.
pub fn run(root: &Path, check: bool) -> Result<bool> {
    run_files(root, check, &outputs())
}

/// The same as [`run`] for any set of files, so a test can hand it a render with a bad description.
fn run_files(root: &Path, check: bool, files: &[Generated]) -> Result<bool> {
    let problems = lint_files(files)?;
    if !problems.is_empty() {
        for problem in &problems {
            eprintln!("{problem}");
        }
        eprintln!(
            "schema: {} description problem(s). Fix the doc comment or `description` attribute in rdy-spec and run `cargo xtask schema` again.",
            problems.len()
        );
        return Ok(false);
    }
    generate::run(root, check, "schema", files)
}

/// Lints every description and title in the generated files.
fn lint_files(files: &[Generated]) -> Result<Vec<String>> {
    let mut problems = Vec::new();
    for file in files {
        let schema: Value = serde_json::from_str(&file.contents)?;
        lint_value(&schema, file.path, "", &mut problems);
    }
    Ok(problems)
}

/// Walks a schema and reports each `description` or `title` text that breaks a rule.
///
/// A key named `description` inside `properties` holds a schema, not a text, so only string values
/// are checked.
fn lint_value(value: &Value, file: &str, pointer: &str, problems: &mut Vec<String>) {
    match value {
        Value::Object(map) => {
            for (key, inner) in map {
                let here = format!("{pointer}/{}", key.replace('~', "~0").replace('/', "~1"));
                match (key.as_str(), inner) {
                    ("description" | "title", Value::String(text)) => {
                        for why in text_problems(text) {
                            problems.push(format!("{file}{here}: {why}"));
                        }
                    }
                    _ => lint_value(inner, file, &here, problems),
                }
            }
        }
        Value::Array(items) => {
            for (index, inner) in items.iter().enumerate() {
                lint_value(inner, file, &format!("{pointer}/{index}"), problems);
            }
        }
        _ => {}
    }
}

/// What is wrong with one description text. Empty when it is fine.
fn text_problems(text: &str) -> Vec<String> {
    let mut why = Vec::new();
    if has_word(text, "ADR") {
        why.push("names an ADR. Say what the field does, not where it was decided".to_owned());
    }
    if let Some(name) = milestone_name(text) {
        why.push(format!(
            "names the milestone or ticket {name}. Describe the behaviour, not the plan"
        ));
    }
    if text.contains("docs/plan") || text.contains("docs/adr") {
        why.push("points to a plan document. Customers cannot read it".to_owned());
    }
    if text.contains("[`") {
        why.push("holds a rustdoc link. Write plain text".to_owned());
    }
    if has_section_reference(text) {
        why.push("refers to a section of a plan document. Say it in words".to_owned());
    }
    if text.contains("::") {
        why.push("holds a Rust path. Name the value as it is written on the wire".to_owned());
    }
    why
}

/// True for "section 5.3" and "sections 2 and 5": the word `section` followed by a digit.
fn has_section_reference(text: &str) -> bool {
    let words: Vec<&str> = text
        .split(|c: char| !c.is_alphanumeric())
        .filter(|word| !word.is_empty())
        .collect();
    words.windows(2).any(|pair| {
        matches!(
            pair[0].to_ascii_lowercase().as_str(),
            "section" | "sections"
        ) && pair[1].starts_with(|c: char| c.is_ascii_digit())
    })
}

/// True when `word` appears in `text` with no letter or digit on either side.
fn has_word(text: &str, word: &str) -> bool {
    text.match_indices(word).any(|(start, _)| {
        let before = text[..start].chars().next_back();
        let after = text[start + word.len()..].chars().next();
        !before.is_some_and(char::is_alphanumeric) && !after.is_some_and(char::is_alphanumeric)
    })
}

/// The first milestone (`M1` to `M9`) or ticket (`M1-022`) name in `text`.
fn milestone_name(text: &str) -> Option<String> {
    let bytes = text.as_bytes();
    for (start, _) in text.match_indices('M') {
        let boundary_before = start == 0 || !bytes[start - 1].is_ascii_alphanumeric();
        let digit = bytes.get(start + 1).is_some_and(u8::is_ascii_digit);
        if !(boundary_before && digit) {
            continue;
        }
        let mut end = start + 2;
        // A ticket id: M1-022.
        if bytes.get(end) == Some(&b'-') {
            let digits = bytes[end + 1..]
                .iter()
                .take_while(|b| b.is_ascii_digit())
                .count();
            if digits > 0 {
                end += 1 + digits;
            }
        }
        let after_ok = bytes.get(end).is_none_or(|b| !b.is_ascii_alphanumeric());
        if after_ok {
            return Some(text[start..end].to_owned());
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_generated_files_pass_their_own_lint() -> Result<()> {
        let problems = lint_files(&outputs())?;
        assert!(problems.is_empty(), "{problems:#?}");
        Ok(())
    }

    #[test]
    fn a_description_that_names_an_adr_fails() {
        assert!(!text_problems("Decided in ADR 0013.").is_empty());
        assert!(!text_problems("See ADR.").is_empty());
        // Words that merely contain the letters are fine.
        assert!(text_problems("A QUADRANT of data.").is_empty());
        assert!(text_problems("Readiness and addresses.").is_empty());
    }

    #[test]
    fn a_description_that_names_a_milestone_fails() {
        for bad in [
            "Arrives in M2.",
            "Added by M1-022 for the report.",
            "(M3)",
            "M4",
        ] {
            assert!(!text_problems(bad).is_empty(), "{bad}");
        }
        for fine in ["MB of memory", "the M row", "HTTPM2", "Mi and Gi suffixes"] {
            assert!(text_problems(fine).is_empty(), "{fine}");
        }
    }

    #[test]
    fn a_description_that_points_into_the_plan_fails() {
        assert!(!text_problems("See docs/plan/01-spec-format.md.").is_empty());
        assert!(!text_problems("Link [`Foo`] left in.").is_empty());
        assert!(text_problems("Plain text with `code` in it.").is_empty());
    }

    #[test]
    fn a_description_that_cites_a_plan_section_or_a_rust_path_fails() {
        assert!(!text_problems("Counts as block (01 section 5.3).").is_empty());
        assert!(!text_problems("See sections 2 and 5.").is_empty());
        assert!(!text_problems("Treated like `TrustSource::Flag`.").is_empty());
        // Ordinary uses of the word are fine.
        assert!(text_problems("Each section of the report has a title.").is_empty());
        assert!(text_problems("The intersection 5 times.").is_empty());
    }

    #[test]
    fn the_lint_finds_a_description_anywhere_in_the_schema() -> Result<()> {
        let schema: Value = serde_json::from_str(
            r#"{"$defs": {"A": {"properties": {"description": {"description": "ok"},
                "b": {"description": "Added in M2."}}}}}"#,
        )?;
        let mut problems = Vec::new();
        lint_value(&schema, "x.json", "", &mut problems);
        assert_eq!(problems.len(), 1, "{problems:?}");
        assert!(
            problems[0].starts_with("x.json/$defs/A/properties/b/description:"),
            "{problems:?}"
        );
        Ok(())
    }

    #[test]
    fn a_bad_description_stops_the_write_and_the_check() -> Result<()> {
        let dir = tempfile::tempdir()?;
        let files = vec![Generated {
            path: "x.json",
            contents: r#"{"description": "Decided in ADR 0013."}"#.to_owned(),
        }];
        assert_eq!(lint_files(&files)?.len(), 1);
        // The check fails, and so does the write, which also leaves the disk alone.
        assert!(!run_files(dir.path(), true, &files)?);
        assert!(!run_files(dir.path(), false, &files)?);
        assert!(!dir.path().join("x.json").exists());
        Ok(())
    }

    #[test]
    fn the_check_follows_the_types() -> Result<()> {
        let dir = tempfile::tempdir()?;
        assert!(run(dir.path(), false)?);
        assert!(run(dir.path(), true)?);
        // A file that no longer matches its render, as after a type or doc comment change that was
        // not regenerated, fails the check and passes again after a write.
        let spec = dir.path().join(SPEC_PATH);
        let text = std::fs::read_to_string(&spec)?;
        std::fs::write(
            &spec,
            text.replacen("Document kind.", "Kind of document.", 1),
        )?;
        assert!(!run(dir.path(), true)?);
        assert!(run(dir.path(), false)?);
        assert!(run(dir.path(), true)?);
        Ok(())
    }

    #[test]
    fn the_committed_files_are_current() -> Result<()> {
        let root = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../..");
        assert!(
            run(&root, true)?,
            "the schema files are stale. Run `cargo xtask schema` and commit the result."
        );
        Ok(())
    }
}
