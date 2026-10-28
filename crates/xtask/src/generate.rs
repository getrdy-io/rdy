//! Shared write and check logic for generated files.
//!
//! A generator returns the exact text that each file must hold. `write_all` puts that text on disk.
//! `check_all` fails when a file is missing or differs from its render. Generated files are never
//! edited by hand (docs/plan/09-docs-site.md, section 2).

use std::fs;
use std::io;
use std::path::{Component, Path, PathBuf};

use anyhow::{Context, Result, bail};

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

/// Joins a generated file's relative path onto `root`.
///
/// Refuses an absolute path, a path with a `..` or `.` part, a backslash and an empty path. A
/// generator that asks for any of those has a bug, so the run fails before it touches the disk.
pub fn safe_join(root: &Path, rel: &str) -> Result<PathBuf> {
    // Each `/` segment must be a plain name. Empty, `.` and `..` segments are refused, and so are
    // a leading `/` and a Windows prefix.
    let well_formed = !rel.is_empty()
        && !rel.contains('\\')
        && rel
            .split('/')
            .all(|segment| !segment.is_empty() && segment != "." && segment != "..")
        && Path::new(rel)
            .components()
            .all(|part| matches!(part, Component::Normal(_)));
    if !well_formed {
        bail!(
            "generated path {rel:?} must be relative, stay under the repo root, and use `/` separators. Fix the generator that names it."
        );
    }
    Ok(root.join(rel))
}

/// Writes every file under `root`, creating parent directories as needed.
pub fn write_all(root: &Path, files: &[Generated]) -> Result<()> {
    for file in files {
        let target = safe_join(root, file.path)?;
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
        match read_normalized(&safe_join(root, file.path)?)? {
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
    fn safe_join_refuses_escapes_and_accepts_plain_paths() -> Result<()> {
        let root = Path::new("/repo");
        assert!(safe_join(root, "docs/x.md").is_ok());
        for bad in [
            "docs/../x",
            "../x",
            "/etc/passwd",
            "docs/./x",
            "docs\\..\\x",
            "",
            "docs//x",
        ] {
            assert!(safe_join(root, bad).is_err(), "{bad:?} must be refused");
        }
        Ok(())
    }

    #[test]
    fn write_refuses_a_parent_escape_before_touching_the_disk() -> Result<()> {
        let dir = tempfile::tempdir()?;
        let root = dir.path().join("repo");
        fs::create_dir_all(&root)?;
        let files = vec![Generated {
            path: "docs/../escaped.md",
            contents: "x\n".to_owned(),
        }];
        assert!(write_all(&root, &files).is_err());
        assert!(!dir.path().join("escaped.md").exists());
        assert!(!root.join("escaped.md").exists());
        Ok(())
    }

    #[test]
    fn check_refuses_an_escaping_path() -> Result<()> {
        let dir = tempfile::tempdir()?;
        let files = vec![Generated {
            path: "/etc/passwd",
            contents: String::new(),
        }];
        assert!(check_all(dir.path(), &files, "docs").is_err());
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
