//! Helpers the lint wall tests share: the workspace root, the check crates and a reader for clippy.toml.

#![allow(dead_code, clippy::expect_used, clippy::unwrap_used)]

use std::path::{Path, PathBuf};

/// The workspace root (this crate is `tests/lint-wall`).
pub fn root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../..")
}

/// Every directory `crates/rdy-checks-*`, sorted by name. A new check crate shows up here with no edit.
pub fn check_crates() -> Vec<PathBuf> {
    let mut dirs: Vec<PathBuf> = std::fs::read_dir(root().join("crates"))
        .expect("read crates/")
        .map(|e| e.expect("dir entry").path())
        .filter(|p| {
            p.is_dir()
                && p.file_name()
                    .and_then(|n| n.to_str())
                    .is_some_and(|n| n.starts_with("rdy-checks-"))
        })
        .collect();
    dirs.sort();
    assert!(
        dirs.len() >= 3,
        "expected at least the host, net and k8s check crates, found {dirs:?}"
    );
    dirs
}

/// The name of a crate directory.
pub fn name(dir: &Path) -> String {
    dir.file_name()
        .and_then(|n| n.to_str())
        .expect("utf-8 name")
        .to_owned()
}

/// Which table of clippy.toml an entry sits in.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Kind {
    /// `disallowed-types`
    Type,
    /// `disallowed-methods`
    Method,
    /// `disallowed-macros`
    Macro,
}

/// One entry of a clippy.toml.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Entry {
    /// The table.
    pub kind: Kind,
    /// The exact path.
    pub path: String,
    /// Whether the entry carries `allow-invalid = true`.
    pub allow_invalid: bool,
}

/// The entries of a clippy.toml. The files keep one entry per line, as `{ path = "..", .. },`, under a
/// `disallowed-types = [`, `disallowed-methods = [` or `disallowed-macros = [` line. The reader fails on a
/// `path =` it cannot place, so a different layout cannot hide an entry from the tests.
pub fn entries(file: &Path) -> Vec<Entry> {
    let text = std::fs::read_to_string(file).unwrap_or_else(|e| panic!("{}: {e}", file.display()));
    let mut kind = None;
    let mut out = Vec::new();
    for (n, line) in text.lines().enumerate() {
        let t = line.trim();
        if t.starts_with('#') {
            continue;
        }
        if let Some(k) = [
            ("disallowed-types", Kind::Type),
            ("disallowed-methods", Kind::Method),
            ("disallowed-macros", Kind::Macro),
        ]
        .iter()
        .find(|(h, _)| t.starts_with(&format!("{h} = [")))
        .map(|(_, k)| *k)
        {
            kind = Some(k);
            continue;
        }
        if t == "]" {
            kind = None;
            continue;
        }
        if t.contains("path = \"") {
            let rest = t.split_once("path = \"").expect("checked").1;
            let path = rest.split_once('"').expect("closing quote").0.to_owned();
            let kind = kind.unwrap_or_else(|| {
                panic!("{}:{}: an entry outside a table", file.display(), n + 1)
            });
            assert!(
                t.starts_with("{ path = \"") && t.ends_with("},"),
                "{}:{}: write one entry per line as `{{ path = \"..\", reason = \"..\" }},`",
                file.display(),
                n + 1
            );
            out.push(Entry {
                kind,
                path,
                allow_invalid: t.contains("allow-invalid = true"),
            });
        }
    }
    out
}
