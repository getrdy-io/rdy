//! Shared write and check logic for generated files.
//!
//! A generator returns the exact text that each file must hold. `write_all` puts that text on disk.
//! `check_all` fails when a file is missing or differs from its render. Generated files are never
//! edited by hand (docs/plan/09-docs-site.md, section 2).

use std::fs;
use std::io;
use std::path::Path;

use anyhow::{Context, Result};

/// One file that a generator owns.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Generated {
    /// Path relative to the repo root, with `/` separators.
    pub path: &'static str,
    /// The whole file. Use LF line endings.
    pub contents: String,
}

/// Writes or checks `files`, depending on `check`. Returns `Ok(true)` when the run passes.
///
/// `command` names the command that fixes a stale tree, for example `docs`. It appears in the
/// message for each stale file.
pub fn run(root: &Path, check: bool, command: &str, files: &[Generated]) -> Result<bool> {
    if check {
        check_all(root, files, command)
    } else {
        write_all(root, files)?;
        Ok(true)
    }
}

/// Writes every file under `root`, creating parent directories as needed.
pub fn write_all(root: &Path, files: &[Generated]) -> Result<()> {
    for file in files {
        let target = root.join(file.path);
        if let Some(parent) = target.parent() {
            fs::create_dir_all(parent)
                .with_context(|| format!("cannot create {}", parent.display()))?;
        }
        fs::write(&target, &file.contents)
            .with_context(|| format!("cannot write {}", target.display()))?;
        eprintln!("wrote {}", file.path);
    }
    Ok(())
}

/// Compares every file with its render. Prints one line per stale file.
///
/// Returns `Ok(false)` when a file is missing or differs. CRLF on disk counts as LF, so a checkout
/// with `core.autocrlf` still passes.
pub fn check_all(root: &Path, files: &[Generated], command: &str) -> Result<bool> {
    let mut clean = true;
    for file in files {
        match read_normalized(&root.join(file.path))? {
            None => {
                eprintln!(
                    "{}: missing. Run `cargo xtask {command}` and commit the result.",
                    file.path
                );
                clean = false;
            }
            Some(on_disk) if on_disk != file.contents => {
                eprintln!(
                    "{}: differs from the generated output. Do not edit generated files. Run `cargo xtask {command}` and commit the result.",
                    file.path
                );
                clean = false;
            }
            Some(_) => {}
        }
    }
    if clean {
        eprintln!("{command}: {} generated file(s) match.", files.len());
    }
    Ok(clean)
}

/// Reads a file as text with LF line endings. `None` means the file does not exist.
fn read_normalized(path: &Path) -> Result<Option<String>> {
    match fs::read(path) {
        Ok(bytes) => Ok(Some(String::from_utf8_lossy(&bytes).replace("\r\n", "\n"))),
        Err(err) if err.kind() == io::ErrorKind::NotFound => Ok(None),
        Err(err) => Err(err).with_context(|| format!("cannot read {}", path.display())),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn page(text: &str) -> Vec<Generated> {
        vec![Generated {
            path: "docs/page.md",
            contents: text.to_owned(),
        }]
    }

    #[test]
    fn check_passes_after_write() -> Result<()> {
        let dir = tempfile::tempdir()?;
        let files = page("one\ntwo\n");
        assert!(run(dir.path(), false, "docs", &files)?);
        assert!(run(dir.path(), true, "docs", &files)?);
        Ok(())
    }

    #[test]
    fn check_fails_on_a_hand_edit() -> Result<()> {
        let dir = tempfile::tempdir()?;
        let files = page("one\ntwo\n");
        write_all(dir.path(), &files)?;
        fs::write(dir.path().join("docs/page.md"), "one\ntwo\nthree\n")?;
        assert!(!check_all(dir.path(), &files, "docs")?);
        Ok(())
    }

    #[test]
    fn check_fails_when_the_file_is_missing() -> Result<()> {
        let dir = tempfile::tempdir()?;
        assert!(!check_all(dir.path(), &page("one\n"), "docs")?);
        Ok(())
    }

    #[test]
    fn check_treats_crlf_as_lf() -> Result<()> {
        let dir = tempfile::tempdir()?;
        let files = page("one\ntwo\n");
        write_all(dir.path(), &files)?;
        fs::write(dir.path().join("docs/page.md"), "one\r\ntwo\r\n")?;
        assert!(check_all(dir.path(), &files, "docs")?);
        Ok(())
    }

    #[test]
    fn write_creates_parent_directories() -> Result<()> {
        let dir = tempfile::tempdir()?;
        write_all(dir.path(), &page("x\n"))?;
        assert!(dir.path().join("docs/page.md").is_file());
        Ok(())
    }
}
