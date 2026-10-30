//! `cargo xtask docs`: writes the generated Markdown pages under `docs/`.
//!
//! Only `docs/src/content/docs/` is published by Starlight. Generated pages live there too
//! (docs/plan/09-docs-site.md, sections 2 and 5).
//!
//! This build generates the spec and result reference pages. Each is rendered from a committed JSON
//! schema that `cargo xtask schema` writes, so `docs` reads those files and never the Rust types.
//!
//! The intro above the tables is hand-written, in `docs/intro/`. That folder is outside the published
//! tree. The generator adds the frontmatter, the banner and the tables, and their text comes from the
//! schema's descriptions.

use std::fs;
use std::path::Path;

use anyhow::{Context, Result};

use crate::generate::{self, Generated};
use crate::schema::{RESULT_PATH, SPEC_PATH};
use crate::spec_reference::{self, Page};

/// Where the spec reference page is written.
const SPEC_PAGE: &str = "docs/src/content/docs/reference/spec/index.md";
/// Where the result reference page is written.
const RESULT_PAGE: &str = "docs/src/content/docs/reference/result/index.md";
/// The hand-written intro of the spec reference page.
const SPEC_INTRO: &str = "docs/intro/reference-spec.md";
/// The hand-written intro of the result reference page.
const RESULT_INTRO: &str = "docs/intro/reference-result.md";

/// The objects in the result schema that are documents of their own, not the report. Each gets a section
/// after the report, in this order: its definition name and its heading.
pub(crate) const RESULT_DOCUMENTS: &[(&str, &str)] = &[
    ("Verification", "rdy verify --json"),
    ("ErrorOutput", "Error output with --json"),
    ("LintReport", "rdy spec lint --json"),
    ("Version", "rdy version --json"),
];

/// The pages this build generates. Reads the committed schemas and intros under `root`.
pub fn pages(root: &Path) -> Result<Vec<Generated>> {
    let schema_hint = "Run `cargo xtask schema` first, then `cargo xtask docs`.";
    let intro_hint = "The hand-written intro of this page lives here. Restore the file, then run `cargo xtask docs`.";
    let spec = read(root, SPEC_PATH, schema_hint)?;
    let result = read(root, RESULT_PATH, schema_hint)?;
    let spec_intro = read(root, SPEC_INTRO, intro_hint)?;
    let result_intro = read(root, RESULT_INTRO, intro_hint)?;
    Ok(vec![
        Generated {
            path: SPEC_PAGE,
            contents: spec_reference::page(
                &spec,
                &Page {
                    title: "Spec reference",
                    description: "Look up each rdy/v1 spec field, its type, whether it is required and its default.",
                    intro: &spec_intro,
                    documents: &[],
                },
            )?,
        },
        Generated {
            path: RESULT_PAGE,
            contents: spec_reference::page(
                &result,
                &Page {
                    title: "Result reference",
                    description: "Look up each field of the JSON that rdy prints, its type and what it means.",
                    intro: &result_intro,
                    documents: RESULT_DOCUMENTS,
                },
            )?,
        },
    ])
}

/// Reads a committed file under `root`. A missing file fails with `hint`, which says how to get it back.
fn read(root: &Path, rel: &str, hint: &str) -> Result<String> {
    let path = generate::safe_join(root, rel)?;
    fs::read_to_string(&path).with_context(|| format!("cannot read {}. {hint}", path.display()))
}

/// Writes the pages, or checks them when `check` is set. Returns `Ok(true)` when the run passes.
pub fn run(root: &Path, check: bool) -> Result<bool> {
    generate::run(root, check, "docs", &pages(root)?)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The repo root: two levels above this crate's manifest.
    fn repo_root() -> std::path::PathBuf {
        std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../..")
    }

    #[test]
    fn every_page_is_markdown_under_the_docs_tree_without_escapes() -> Result<()> {
        let root = repo_root();
        for page in pages(&root)? {
            assert!(page.path.starts_with("docs/"), "{}", page.path);
            assert!(page.path.ends_with(".md"), "{}", page.path);
            assert!(
                generate::safe_join(&root, page.path).is_ok(),
                "{}",
                page.path
            );
        }
        Ok(())
    }

    #[test]
    fn a_page_path_that_climbs_out_of_docs_is_refused() {
        // The generator refuses `docs/../x` (generate::safe_join), so no page can escape docs/.
        assert!(generate::safe_join(Path::new("/repo"), "docs/../x").is_err());
    }

    #[test]
    fn every_page_starts_frontmatter_and_carries_the_banner() -> Result<()> {
        for page in pages(&repo_root())? {
            assert!(page.contents.starts_with("---\n"), "{}", page.path);
            assert!(
                page.contents
                    .contains("<!-- Generated by cargo xtask docs. Do not edit. -->"),
                "{}",
                page.path
            );
        }
        Ok(())
    }

    #[test]
    fn the_committed_spec_page_matches_the_render() -> Result<()> {
        // This is the drift check in CI: the page on disk must be what the schema renders to.
        let root = repo_root();
        assert!(
            generate::check_all(&root, &pages(&root)?, "docs")?,
            "the spec reference page is stale. Run `cargo xtask docs` and commit the result."
        );
        Ok(())
    }

    #[test]
    fn render_is_deterministic() -> Result<()> {
        let root = repo_root();
        assert_eq!(pages(&root)?, pages(&root)?);
        Ok(())
    }
}
