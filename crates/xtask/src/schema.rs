//! `cargo xtask schema`: writes the JSON schema files generated from the rdy-spec types.
//!
//! This build generates no schema yet. M1-022 adds schemars and the files under
//! `crates/rdy-spec/schema/` (ADR 0012). Until then the command says so and passes, so the CI
//! gate can exist before its inputs do.

use std::path::Path;

use anyhow::Result;

use crate::generate::{self, Generated};

/// The schema files this build generates. Empty until M1-022.
fn outputs() -> Vec<Generated> {
    Vec::new()
}

/// Writes the schema files, or checks them when `check` is set. Returns `Ok(true)` when the run
/// passes.
pub fn run(root: &Path, check: bool) -> Result<bool> {
    let files = outputs();
    if files.is_empty() {
        eprintln!(
            "schema: no schema files are generated yet. M1-022 adds them from the rdy-spec types."
        );
        return Ok(true);
    }
    generate::run(root, check, "schema", &files)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn no_outputs_yet_so_check_passes() -> Result<()> {
        let dir = tempfile::tempdir()?;
        assert!(outputs().is_empty());
        assert!(run(dir.path(), true)?);
        Ok(())
    }
}
