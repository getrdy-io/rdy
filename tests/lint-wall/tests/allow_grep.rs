//! The allow grep (M1-044, INV-07, ADR 0014 decision 7).
//!
//! `allow(clippy::disallowed_..)` is legal only in the facade's `live/` module and the k8s client module.
//! This test parses every `.rs` file of the workspace with `syn`, walks every attribute (inside `cfg_attr`
//! too, and in the tokens of a macro), and fails on one that relaxes a `disallowed_*` lint, or a group that
//! holds one, in a file that is not on the list below. Spacing, line breaks and a second attribute on a
//! line do not matter, and a comment or a string does not count. No directory is skipped, because
//! `#[path]` can reach any file. To add a place, edit the list in this file. `/tests/lint-wall/` is in
//! CODEOWNERS, so the change gets the security review.
//!
//! The check crates get no exemption for tests, except the client tests of `rdy-checks-k8s`, which start
//! mock servers and write kubeconfigs. A test of a check uses `TestRun`, not the machine.
//!
//! The grep also fails a check crate whose Cargo.toml turns the lint off with a `[lints.clippy]` table or
//! leaves the workspace lints, because that has the same effect.

#![allow(clippy::expect_used, clippy::unwrap_used)]

mod common;

use common::{check_crates, name, root};
use std::path::{Path, PathBuf};

/// Where an attribute naming a disallowed lint is legal. Paths are relative to the workspace root, with
/// `/` separators. A path that ends in `/` is a directory prefix.
const ALLOWED: &[(&str, &str)] = &[
    // The two places the rule names.
    (
        "crates/rdy-checks-k8s/src/client/",
        "the k8s client module builds the one guarded kube client (ADR 0010, ADR 0031)",
    ),
    (
        "crates/rdy-engine/src/probe/live/",
        "the facade's live backend, M1-045 (ADR 0014); the directory does not exist yet",
    ),
    // The client module's integration tests.
    (
        "crates/rdy-checks-k8s/tests/client.rs",
        "tests of the client module: a mock API server, kubeconfig files, plugin scripts",
    ),
    (
        "crates/rdy-checks-k8s/tests/tls.rs",
        "tests of the client module: a TLS server with a throwaway CA",
    ),
    (
        "crates/rdy-checks-k8s/tests/live_cluster.rs",
        "the ignored kind test of the client module (M1-108)",
    ),
    (
        "crates/rdy-checks-k8s/tests/common/mod.rs",
        "helpers of the client module tests",
    ),
    // Outside the check crates the wall is the root list (clap, the clock, the raw runners). These files
    // call those on purpose, and each says why in its own words.
    (
        "crates/rdy-engine/src/probe.rs",
        "the one call of exec::table::run, in the probe spawn (ADR 0014, ADR 0028)",
    ),
    (
        "crates/rdy-engine/src/exec/policy.rs",
        "the tests of the policy call the raw runner",
    ),
    (
        "crates/rdy-engine/src/exec/runner/tests.rs",
        "the tests of the raw runner",
    ),
    (
        "crates/rdy-engine/src/exec/table/tests.rs",
        "the tests of the table runner",
    ),
    (
        "crates/rdy-engine/tests/exit_bound.rs",
        "an integration test of the raw runner",
    ),
    (
        "crates/rdy-engine/tests/sigchld_ignored.rs",
        "an integration test of the raw runner",
    ),
    (
        "crates/rdy-engine/tests/watchdog_hang.rs",
        "an integration test of the watchdog that starts a real process with the raw runner (M1-043)",
    ),
    (
        "crates/rdy-spec/tests/semantic_limits.rs",
        "a test that pins the clock with load_at",
    ),
    (
        "crates/xtask/src/main.rs",
        "xtask is a repo tool, not the `rdy` binary: it prints clap's own usage error",
    ),
];

/// Lints that cover `disallowed_*`: the three lints, and the groups that include them. Compared with
/// whitespace removed, so `clippy :: disallowed_methods` matches.
const COVERING: &[&str] = &[
    "clippy::disallowed_",
    "clippy::all",
    "clippy::style",
    "warnings",
];

/// The attributes that relax a lint. `deny` and `forbid` tighten, so they pass.
const RELAXING: &[&str] = &["allow(", "expect(", "warn("];

fn strip(text: &str) -> String {
    text.chars().filter(|c| !c.is_whitespace()).collect()
}

fn covers(stripped: &str) -> bool {
    COVERING.iter().any(|c| stripped.contains(c))
}

/// Whether the text of one attribute (without `#[` and `]`, whitespace removed) relaxes a `disallowed_*`
/// lint: `allow(..)`, `expect(..)` or `warn(..)` naming one, or a `cfg_attr(..)` that holds one of those.
fn attribute_relaxes(stripped: &str) -> bool {
    let direct = RELAXING.iter().any(|r| stripped.starts_with(r));
    let through_cfg_attr =
        stripped.starts_with("cfg_attr(") && RELAXING.iter().any(|r| stripped.contains(r));
    (direct || through_cfg_attr) && covers(stripped)
}

/// `#[..]` and `#![..]` inside the tokens of a macro, which syn does not parse as attributes: a
/// `macro_rules!` body can hold `#[allow(clippy::disallowed_methods)]` and expand it anywhere.
fn tokens_hide_a_relaxing_attribute(tokens: proc_macro2::TokenStream) -> bool {
    use proc_macro2::{Delimiter, TokenTree};
    let trees: Vec<TokenTree> = tokens.into_iter().collect();
    for (i, tree) in trees.iter().enumerate() {
        if let TokenTree::Group(g) = tree
            && tokens_hide_a_relaxing_attribute(g.stream())
        {
            return true;
        }
        let is_hash = matches!(tree, TokenTree::Punct(p) if p.as_char() == '#');
        if !is_hash {
            continue;
        }
        let mut j = i + 1;
        if matches!(trees.get(j), Some(TokenTree::Punct(p)) if p.as_char() == '!') {
            j += 1;
        }
        if let Some(TokenTree::Group(g)) = trees.get(j)
            && g.delimiter() == Delimiter::Bracket
            && attribute_relaxes(&strip(&g.stream().to_string()))
        {
            return true;
        }
    }
    false
}

/// Walks every attribute of a parsed file, including those inside `cfg_attr`, and the tokens of every
/// macro.
struct Finder {
    found: bool,
}

impl<'ast> syn::visit::Visit<'ast> for Finder {
    fn visit_attribute(&mut self, attr: &'ast syn::Attribute) {
        let name = attr
            .path()
            .segments
            .last()
            .map(|s| s.ident.to_string())
            .unwrap_or_default();
        let tokens = match &attr.meta {
            syn::Meta::List(list) => strip(&list.tokens.to_string()),
            _ => String::new(),
        };
        if attribute_relaxes(&format!("{name}({tokens})")) {
            self.found = true;
        }
        syn::visit::visit_attribute(self, attr);
    }

    fn visit_macro(&mut self, mac: &'ast syn::Macro) {
        if tokens_hide_a_relaxing_attribute(mac.tokens.clone()) {
            self.found = true;
        }
        syn::visit::visit_macro(self, mac);
    }
}

/// Whether the source relaxes a `disallowed_*` lint anywhere. A file that does not parse is judged by its
/// text: any lint-relaxing word and any covering lint name in it counts, because a file that syn cannot
/// read is one nobody checked.
fn relaxes_a_disallowed_lint(source: &str) -> bool {
    match syn::parse_file(source) {
        Ok(file) => {
            let mut finder = Finder { found: false };
            syn::visit::Visit::visit_file(&mut finder, &file);
            finder.found
        }
        Err(_) => {
            let stripped = strip(source);
            RELAXING.iter().any(|r| stripped.contains(r)) && covers(&stripped)
        }
    }
}

/// Every `.rs` file under `dir`, in every directory. Nothing is skipped: `#[path = ".."]` can reach a file
/// in a directory named `target` or one that starts with a dot.
fn rust_files(dir: &Path, out: &mut Vec<PathBuf>) {
    for entry in std::fs::read_dir(dir).unwrap_or_else(|e| panic!("{}: {e}", dir.display())) {
        let path = entry.expect("dir entry").path();
        if path.is_dir() {
            rust_files(&path, out);
        } else if path.extension().is_some_and(|x| x == "rs") {
            out.push(path);
        }
    }
}

fn allowed(relative: &str) -> bool {
    ALLOWED
        .iter()
        .any(|(p, _)| relative == *p || (p.ends_with('/') && relative.starts_with(p)))
}

fn relative(base: &Path, file: &Path) -> String {
    file.strip_prefix(base)
        .expect("under the root")
        .to_string_lossy()
        .replace('\\', "/")
}

#[test]
fn an_allow_of_a_disallowed_lint_is_only_in_the_allowlisted_files() {
    let base = root();
    let mut files = Vec::new();
    rust_files(&base.join("crates"), &mut files);
    rust_files(&base.join("tests"), &mut files);
    assert!(files.len() > 50, "found only {} source files", files.len());
    let mut bad = Vec::new();
    for file in files {
        let rel = relative(&base, &file);
        let text = std::fs::read_to_string(&file).expect("read source");
        if relaxes_a_disallowed_lint(&text) && !allowed(&rel) {
            bad.push(rel);
        }
    }
    assert!(
        bad.is_empty(),
        "these files relax a disallowed_* lint and are not on the list in tests/lint-wall/tests/allow_grep.rs: {bad:#?}\nA check reaches the machine through its Probe. Do not allow the lint; use the facade."
    );
}

#[test]
fn every_allowlisted_file_still_exists_and_still_needs_the_allow() {
    // A stale entry is a hole nobody notices. `live/` does not exist yet.
    let base = root();
    for (path, why) in ALLOWED {
        if path.ends_with("probe/live/") {
            continue;
        }
        let full = base.join(path);
        assert!(
            full.exists(),
            "{path} is on the allowlist but missing ({why})"
        );
        let mut files = Vec::new();
        if full.is_dir() {
            rust_files(&full, &mut files);
        } else {
            files.push(full);
        }
        let used = files
            .iter()
            .any(|f| relaxes_a_disallowed_lint(&std::fs::read_to_string(f).expect("read source")));
        assert!(
            used,
            "{path} is on the allowlist but no longer relaxes a disallowed_* lint: remove it from the list ({why})"
        );
    }
}

#[test]
fn the_grep_sees_every_form_it_must() {
    for (what, source) in [
        ("plain", "#[allow(clippy::disallowed_methods)] fn f() {}"),
        (
            "inner",
            "#![allow(clippy::disallowed_types, clippy::disallowed_methods)]",
        ),
        ("expect", "#[expect(clippy::disallowed_macros)] fn f() {}"),
        (
            "an attribute after code on the same line",
            "fn f() {} #[allow(clippy::disallowed_methods)] fn g() {}",
        ),
        (
            "a space after the hash",
            "# [allow(clippy::disallowed_methods)] fn f() {}",
        ),
        (
            "spaces in the lint path",
            "#[allow(clippy :: disallowed_methods)] fn f() {}",
        ),
        (
            "a newline in the lint path",
            "#[allow(\n    clippy\n    ::\n    disallowed_methods,\n)] fn f() {}",
        ),
        (
            "inside cfg_attr",
            "#[cfg_attr(test, allow(clippy::disallowed_methods))] fn f() {}",
        ),
        (
            "inside a nested cfg_attr",
            "#[cfg_attr(unix, cfg_attr(test, allow(clippy::disallowed_methods)))] fn f() {}",
        ),
        ("the all group", "#![allow(clippy::all)]"),
        ("the style group", "#[allow(clippy::style)] fn f() {}"),
        ("warnings", "#![allow(warnings)]"),
        (
            "in a macro_rules body",
            "macro_rules! m { () => { #[allow(clippy::disallowed_methods)] fn f() {} }; }",
        ),
        (
            "in an inner attribute of a macro body",
            "macro_rules! m { () => { #![allow(clippy::disallowed_methods)] }; }",
        ),
        (
            "in a nested module",
            "mod a { mod b { #[allow(clippy::disallowed_methods)] fn f() {} } }",
        ),
        (
            "on a statement",
            "fn f() { #[allow(clippy::disallowed_methods)] let _x = 1; }",
        ),
        (
            "in a file that does not parse",
            "fn f( { #[allow(clippy::disallowed_methods)]",
        ),
    ] {
        assert!(relaxes_a_disallowed_lint(source), "the grep missed: {what}");
    }
    for (what, source) in [
        (
            "a comment",
            "// #[allow(clippy::disallowed_methods)]\nfn f() {}",
        ),
        (
            "a block comment",
            "/* #[allow(clippy::disallowed_methods)] */ fn f() {}",
        ),
        (
            "a string",
            "const S: &str = \"#[allow(clippy::disallowed_methods)]\";",
        ),
        ("an unrelated allow", "#![allow(clippy::expect_used)]"),
        ("deny", "#![deny(clippy::disallowed_methods)]"),
        ("forbid", "#![forbid(unsafe_code)]"),
        (
            "cfg_attr that does not relax",
            "#[cfg_attr(test, deny(clippy::disallowed_methods))] fn f() {}",
        ),
        ("an empty file", ""),
    ] {
        assert!(
            !relaxes_a_disallowed_lint(source),
            "the grep flagged: {what}"
        );
    }
}

#[test]
fn the_walk_reaches_every_directory() {
    // `#[path]` can name a file in a directory the walk would skip if it skipped `target` or dot dirs.
    let dir = Path::new(env!("CARGO_TARGET_TMPDIR")).join("allow-grep-walk");
    let _ = std::fs::remove_dir_all(&dir);
    for sub in [".hidden", "target", "src/deep/er"] {
        std::fs::create_dir_all(dir.join(sub)).expect("create dir");
        std::fs::write(dir.join(sub).join("x.rs"), "").expect("write");
    }
    let mut found = Vec::new();
    rust_files(&dir, &mut found);
    assert_eq!(found.len(), 3, "{found:?}");
}

#[test]
fn a_check_crate_keeps_the_workspace_lints() {
    for dir in check_crates() {
        let text = std::fs::read_to_string(dir.join("Cargo.toml")).expect("Cargo.toml");
        assert!(
            text.contains("[lints]\nworkspace = true"),
            "{}: Cargo.toml must have `[lints]` with `workspace = true`",
            name(&dir)
        );
        assert!(
            !text.contains("[lints."),
            "{}: Cargo.toml has a `[lints.*]` table; a check crate takes the workspace lints as they are",
            name(&dir)
        );
    }
}
