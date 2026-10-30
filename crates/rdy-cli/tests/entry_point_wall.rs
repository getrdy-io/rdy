//! The source checks of ADR 0011 decision 4 (M1-074): the shipped code cannot name the test backend,
//! and the live backend is built in exactly one place.
//!
//! - `crates/rdy-cli/src`, outside `#[cfg(test)]` items, never names `Replay` or `testing`.
//! - `live_backend` appears outside test code in `src/entry.rs` only (INV-07). The lint wall allows the
//!   one `expect(clippy::disallowed_methods)` there and in no other file of this crate.
//! - The normal `rdy-engine` dependency does not turn on `testing`. CI's `cargo tree` step checks the
//!   built graph on every push; this is the same rule at the manifest.
//!
//! The other half of decision 4, that no Replay-only string is in a release binary, is checked on the
//! built archives before signing (06), not here.

use std::path::{Path, PathBuf};

fn src() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("src")
}

fn rust_files(dir: &Path, out: &mut Vec<PathBuf>) {
    let entries =
        std::fs::read_dir(dir).unwrap_or_else(|e| panic!("cannot read {}: {e}", dir.display()));
    for entry in entries {
        let path = entry
            .unwrap_or_else(|e| panic!("cannot list {}: {e}", dir.display()))
            .path();
        if path.is_dir() {
            rust_files(&path, out);
        } else if path.extension().is_some_and(|ext| ext == "rs") {
            out.push(path);
        }
    }
}

/// A file that is compiled only for tests: `tests.rs`, `*_tests.rs`, or anything in a `tests` folder.
fn test_only_file(path: &Path) -> bool {
    let name = path.file_name().and_then(|n| n.to_str()).unwrap_or("");
    let in_tests_dir = path
        .components()
        .any(|part| part.as_os_str() == std::ffi::OsStr::new("tests"));
    name == "tests.rs" || name.ends_with("_tests.rs") || in_tests_dir
}

/// The code of `text` that is compiled outside tests, with comments removed. A `#[cfg(test)]` item is
/// dropped: a `mod x;` line, or an inline module up to the closing brace at its own indent.
fn shipped_code(text: &str) -> Vec<String> {
    let mut kept = Vec::new();
    let mut lines = text.lines().peekable();
    while let Some(line) = lines.next() {
        let trimmed = line.trim();
        if trimmed == "#[cfg(test)]" {
            let indent = line.len() - line.trim_start().len();
            let Some(item) = lines.next() else { break };
            if item.trim_end().ends_with(';') {
                continue;
            }
            let closer = format!("{}}}", " ".repeat(indent));
            for inner in lines.by_ref() {
                if inner.trim_end() == closer {
                    break;
                }
            }
            continue;
        }
        let code = match line.find("//") {
            Some(at) => &line[..at],
            None => line,
        };
        if !code.trim().is_empty() {
            kept.push(code.to_owned());
        }
    }
    kept
}

/// Whether `word` appears in `code` as a whole identifier.
fn names(code: &str, word: &str) -> bool {
    code.split(|c: char| !(c.is_alphanumeric() || c == '_'))
        .any(|part| part == word)
}

fn shipped_files() -> Vec<(PathBuf, Vec<String>)> {
    let mut files = Vec::new();
    rust_files(&src(), &mut files);
    files.sort();
    files
        .into_iter()
        .filter(|path| !test_only_file(path))
        .map(|path| {
            let text = std::fs::read_to_string(&path)
                .unwrap_or_else(|e| panic!("cannot read {}: {e}", path.display()));
            let code = shipped_code(&text);
            (path, code)
        })
        .collect()
}

#[test]
fn shipped_code_never_names_replay_or_testing() {
    let files = shipped_files();
    assert!(files.len() > 10, "the walk found {} files", files.len());
    for (path, code) in &files {
        for line in code {
            for word in ["Replay", "testing"] {
                assert!(
                    !names(line, word),
                    "{} names `{word}` outside #[cfg(test)]: {line}",
                    path.display()
                );
            }
        }
    }
}

#[test]
fn only_the_entry_point_builds_the_live_backend() {
    let mut found = Vec::new();
    for (path, code) in shipped_files() {
        if code.iter().any(|line| names(line, "live_backend")) {
            found.push(path.file_name().map(|n| n.to_string_lossy().into_owned()));
        }
    }
    assert_eq!(found, [Some("entry.rs".to_owned())]);
}

#[test]
fn the_helper_sees_what_it_must() {
    let text = "use a::Replay;\n// Replay in a comment\nfn f() {}\n#[cfg(test)]\nmod tests {\n    use b::Replay;\n}\n#[cfg(test)]\nmod more;\nfn g() { live_backend(); } // note\n";
    let code = shipped_code(text);
    assert_eq!(
        code,
        ["use a::Replay;", "fn f() {}", "fn g() { live_backend(); } "]
    );
    assert!(names("use a::Replay;", "Replay"));
    assert!(!names("use a::ReplayLog;", "Replay"));
    assert!(!names("let testing_mode = 1;", "testing"));
}

#[test]
fn the_normal_engine_dependency_does_not_turn_on_testing() {
    let manifest =
        std::fs::read_to_string(Path::new(env!("CARGO_MANIFEST_DIR")).join("Cargo.toml"))
            .unwrap_or_else(|e| panic!("cannot read Cargo.toml: {e}"));
    let mut section = "";
    let mut seen = false;
    for line in manifest.lines() {
        let line = line.trim();
        if line.starts_with('[') {
            section = line;
            continue;
        }
        if section == "[dependencies]" && line.starts_with("rdy-engine") {
            seen = true;
            assert!(
                !line.contains("testing"),
                "the normal rdy-engine dependency turns on `testing`: {line}"
            );
        }
    }
    assert!(seen, "no rdy-engine line under [dependencies]");
}
