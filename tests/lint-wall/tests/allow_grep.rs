//! The allow grep (M1-044, INV-07, ADR 0014 decision 7).
//!
//! `allow(clippy::disallowed_..)` is legal only in the facade's `live/` module and the k8s client module.
//! This test parses every `.rs` file of the workspace with `syn`, walks every attribute (inside `cfg_attr`
//! too, and in the tokens of a macro), and fails on one that relaxes a `disallowed_*` lint, or a group that
//! holds one, in a file that is not on the list below. Spacing, line breaks, raw identifiers and a second
//! attribute on a line do not matter, a comment or a string does not count, and an attribute that a macro
//! builds from the caller's tokens (`#[allow($($t)*)]`, `#[$a(..)]`) is refused too. The walk starts at the
//! repository root and skips only `target/`, `.git/` and the local agent checkouts, because a source file
//! can reach any other with `#[path]` or `include!`; a check crate may use neither. To add a place, edit
//! the list in this file. `/tests/lint-wall/` is in CODEOWNERS, so the change gets the security review.
//!
//! The check crates get no exemption for tests, except the client tests of `rdy-checks-k8s`, which start
//! mock servers and write kubeconfigs. A test of a check uses `TestRun`, not the machine.
//!
//! The manifests are checked in `wall_intact.rs`.

#![allow(clippy::expect_used, clippy::unwrap_used)]

mod common;

use common::{check_crates, root};
use std::collections::BTreeSet;
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
        "the facade's live backend, M1-045 (ADR 0014)",
    ),
    // The client module's integration tests.
    (
        "crates/rdy-checks-k8s/tests/client.rs",
        "tests of the client module: a mock API server, kubeconfig files, plugin scripts",
    ),
    (
        "crates/rdy-checks-k8s/tests/guard.rs",
        "tests of the read-only guard on the real client stack: a mock API server and kubeconfig files",
    ),
    (
        "crates/rdy-checks-k8s/tests/rbac_example.rs",
        "reads examples/rbac/rdy-readonly.yaml to compare it with the guard's allowlist (SEC-24)",
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
        "crates/rdy-engine/src/probe/tests.rs",
        "the tests of the probe call Probe::kube_call, which only the k8s guard may call in a check crate (M1-103)",
    ),
    (
        "crates/rdy-engine/src/probe/sock/tests.rs",
        "the live socket tests build the live backend to run the real UDP and unix socket bodies (M1-144)",
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
        "crates/rdy-cli/src/entry.rs",
        "the one call site of live_backend outside the engine: the binary reads the real machine (INV-07, ADR 0011 decision 4, M1-074). `crates/rdy-cli/tests/entry_point_wall.rs` checks that no other CLI file names it",
    ),
    (
        "crates/xtask/src/main.rs",
        "xtask is a repo tool, not the `rdy` binary: it prints clap's own usage error",
    ),
];

/// Check-crate files that embed a data file the crate ships, with `include_str!` in code that is not a test
/// (03 Appendix B: data files are embedded at build time). Data only: a `.toml` file under the crate's own
/// `data/` directory, never Rust.
///
/// Each entry is `(file, literal, reason)`. The file holds exactly one include call, its only literal is
/// `literal` (no `concat!`), and `literal` is `../data/<name>.toml`, one step out of the crate's `src/` into
/// its own `data/` directory (`shipped_data_is_embedded_only_from_the_crates_own_data_directory` checks it).
/// A test module of the same crate is covered by `INCLUDE_DATA_ALLOWED`.
const INCLUDE_SHIPPED_DATA_ALLOWED: &[(&str, &str, &str)] = &[(
    "crates/rdy-checks-host/src/agents.rs",
    "../data/agents.toml",
    "embeds the security-software catalog that host.security_agents matches against (M1-146)",
)];

/// Check-crate files that embed a data file with `include_str!` or `include_bytes!`. Data only: the file
/// is text, never Rust. `include!` and `#[path]` are never allowed in a check crate.
///
/// Each entry is `(file, required_prefix, reason)`. Every include literal in the file must start with the
/// prefix, so a later `include_str!` of some other path in the same file fails the test. The file must
/// be a test module: it, or a module above it, is declared under `#[cfg(test)]`.
const INCLUDE_DATA_ALLOWED: &[(&str, &str, &str)] = &[
    (
        "crates/rdy-checks-host/src/family/tests.rs",
        "../../../../examples/specs/acme-platform.yaml",
        "embeds examples/specs/acme-platform.yaml for a test",
    ),
    (
        "crates/rdy-checks-host/src/firewall/tests.rs",
        "../../../../tests/fixtures/checks/host.firewall/",
        "embeds the synthetic cases of tests/fixtures/checks/host.firewall until the Replay loader (M1-049) reads them",
    ),
    (
        "crates/rdy-checks-host/src/firewall/unit_tests.rs",
        "../../../../tests/fixtures/checks/host.firewall/",
        "embeds recorded text from tests/fixtures/checks/host.firewall for the parser tests",
    ),
    (
        "crates/rdy-checks-k8s/src/client/guard/tests/parser.rs",
        "../../../../../../docs/plan/03-check-catalog.md",
        "embeds docs/plan/03-check-catalog.md so a test can check the check ids that ALLOWED cites",
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

/// Whitespace and the `r#` of a raw identifier removed, so `# [r#allow(clippy :: disallowed_methods)]`
/// reads like the plain form.
fn strip(text: &str) -> String {
    let squeezed: String = text.chars().filter(|c| !c.is_whitespace()).collect();
    squeezed.replace("r#", "")
}

fn covers(stripped: &str) -> bool {
    COVERING.iter().any(|c| stripped.contains(c))
}

/// Whether the text of one attribute (without `#[` and `]`, stripped) relaxes a `disallowed_*` lint:
/// `allow(..)`, `expect(..)` or `warn(..)` naming one, or a `cfg_attr(..)` that holds one of those.
fn attribute_relaxes(stripped: &str) -> bool {
    let direct = RELAXING.iter().any(|r| stripped.starts_with(r));
    let through_cfg_attr =
        stripped.starts_with("cfg_attr(") && RELAXING.iter().any(|r| stripped.contains(r));
    (direct || through_cfg_attr) && covers(stripped)
}

/// An attribute in a macro body that is built from the caller's tokens: `#[$a(..)]`, or a relaxing
/// attribute or `cfg_attr` that holds a `$`. `macro_rules! m { ($($t:tt)*) => { #[allow($($t)*)] .. } }`
/// called as `m!(clippy::disallowed_methods)` relaxes the lint with no lint name in the source of the
/// macro, so any such attribute is refused.
fn attribute_forwards_tokens(stripped: &str) -> bool {
    if stripped.starts_with('$') {
        return true;
    }
    let direct = RELAXING.iter().any(|r| stripped.starts_with(r));
    let through_cfg_attr = stripped.starts_with("cfg_attr(")
        && (RELAXING.iter().any(|r| stripped.contains(r)) || stripped.contains(",$"));
    (direct || through_cfg_attr) && stripped.contains('$')
}

/// What a source file does that the wall cares about.
#[derive(Default, Debug)]
struct Findings {
    /// An attribute relaxes a `disallowed_*` lint.
    relaxes: bool,
    /// A `#[path = ".."]` attribute: it can pull in any file.
    path_attribute: bool,
    /// `include!`: it can pull in any Rust file.
    include_code: bool,
    /// `include_str!` or `include_bytes!`.
    include_data: bool,
    /// How many `include_str!` and `include_bytes!` calls, with any delimiter: `(..)`, `[..]` or `{..}`.
    include_data_calls: usize,
}

/// The macro names that read a file at build time.
fn note_macro_name(findings: &mut Findings, name: &str) {
    match name {
        "include" => findings.include_code = true,
        "include_str" | "include_bytes" => {
            findings.include_data = true;
            findings.include_data_calls += 1;
        }
        _ => {}
    }
}

/// Looks through the tokens of a macro, which syn does not parse as attributes or macro calls: a
/// `macro_rules!` body can hold `#[allow(clippy::disallowed_methods)]`, `#[path = ".."]` and
/// `include!(..)`, and expand them anywhere.
///
/// The body of `macro_rules!` is a list of arms, `(matcher) => { transcriber };`. The `$m:meta` names that
/// make `#[$m]` safe are bound per arm: only the arm whose matcher takes `#[$m:meta]` as written may
/// forward `#[$m]`. Tokens outside an arm (the arguments of a call) are scanned with no names bound.
fn scan_tokens(findings: &mut Findings, tokens: proc_macro2::TokenStream) {
    use proc_macro2::{Spacing, TokenStream, TokenTree};
    let trees: Vec<TokenTree> = tokens.into_iter().collect();
    let mut in_an_arm = vec![false; trees.len()];
    let mut i = 0;
    while i + 3 < trees.len() {
        if let (
            TokenTree::Group(matcher),
            TokenTree::Punct(eq),
            TokenTree::Punct(gt),
            TokenTree::Group(transcriber),
        ) = (&trees[i], &trees[i + 1], &trees[i + 2], &trees[i + 3])
            && eq.as_char() == '='
            && eq.spacing() == Spacing::Joint
            && gt.as_char() == '>'
        {
            let mut bound = BTreeSet::new();
            meta_passthrough(&mut bound, matcher.stream());
            scan_with(findings, matcher.stream(), &bound);
            scan_with(findings, transcriber.stream(), &bound);
            for flag in &mut in_an_arm[i..=i + 3] {
                *flag = true;
            }
            i += 4;
        } else {
            i += 1;
        }
    }
    let rest: TokenStream = trees
        .into_iter()
        .zip(in_an_arm)
        .filter(|(_, arm)| !arm)
        .map(|(tree, _)| tree)
        .collect();
    scan_with(findings, rest, &BTreeSet::new());
}

/// The names `$m` of every `#[$m:meta]` in the tokens: the matcher of a macro that takes attributes
/// written as attributes at the call site, so the call site shows them (`$(#[$meta:meta])*` is how a
/// macro forwards doc comments). `#[$m]` in its output is then no more than those.
fn meta_passthrough(names: &mut BTreeSet<String>, tokens: proc_macro2::TokenStream) {
    use proc_macro2::{Delimiter, TokenTree};
    let trees: Vec<TokenTree> = tokens.into_iter().collect();
    for (i, tree) in trees.iter().enumerate() {
        if let TokenTree::Group(g) = tree {
            meta_passthrough(names, g.stream());
        }
        let hash = matches!(tree, TokenTree::Punct(p) if p.as_char() == '#');
        if hash
            && let Some(TokenTree::Group(g)) = trees.get(i + 1)
            && g.delimiter() == Delimiter::Bracket
        {
            let text = strip(&g.stream().to_string());
            if let Some(name) = text.strip_prefix('$').and_then(|t| t.strip_suffix(":meta")) {
                names.insert(name.to_owned());
            }
        }
    }
}

fn scan_with(
    findings: &mut Findings,
    tokens: proc_macro2::TokenStream,
    passthrough: &BTreeSet<String>,
) {
    use proc_macro2::{Delimiter, TokenTree};
    let trees: Vec<TokenTree> = tokens.into_iter().collect();
    for (i, tree) in trees.iter().enumerate() {
        match tree {
            TokenTree::Group(g) => scan_with(findings, g.stream(), passthrough),
            TokenTree::Ident(id) => {
                let bang =
                    matches!(trees.get(i + 1), Some(TokenTree::Punct(p)) if p.as_char() == '!');
                if bang {
                    note_macro_name(findings, &id.to_string().replace("r#", ""));
                }
            }
            // `$h [$a]`: the hash of an attribute is a `tt` the caller passes. Nothing in the source
            // of the macro says what the attribute is, so it is refused.
            TokenTree::Punct(p) if p.as_char() == '$' => {
                if matches!(trees.get(i + 1), Some(TokenTree::Ident(_)))
                    && let Some(TokenTree::Group(g)) = trees.get(i + 2)
                    && g.delimiter() == Delimiter::Bracket
                    && g.stream().to_string().trim_start().starts_with('$')
                {
                    findings.relaxes = true;
                }
            }
            TokenTree::Punct(p) if p.as_char() == '#' => {
                // `m!(# allow(clippy::disallowed_methods))`: the hash alone, the attribute after it,
                // for a macro that puts a `$h` in front of `[$a]`.
                if let (Some(TokenTree::Ident(name)), Some(TokenTree::Group(args))) =
                    (trees.get(i + 1), trees.get(i + 2))
                    && attribute_relaxes(&strip(&format!("{name}{args}")))
                {
                    findings.relaxes = true;
                }
                let mut j = i + 1;
                if matches!(trees.get(j), Some(TokenTree::Punct(p)) if p.as_char() == '!') {
                    j += 1;
                }
                if let Some(TokenTree::Group(g)) = trees.get(j)
                    && g.delimiter() == Delimiter::Bracket
                {
                    let text = strip(&g.stream().to_string());
                    let forwarded_meta = text
                        .strip_prefix('$')
                        .map(|name| name.strip_suffix(":meta").unwrap_or(name))
                        .is_some_and(|name| passthrough.contains(name));
                    if attribute_relaxes(&text)
                        || (attribute_forwards_tokens(&text) && !forwarded_meta)
                    {
                        findings.relaxes = true;
                    }
                    if text.starts_with("path=")
                        || text.contains("cfg_attr(") && text.contains("path=")
                    {
                        findings.path_attribute = true;
                    }
                }
            }
            TokenTree::Punct(_) | TokenTree::Literal(_) => {}
        }
    }
}

/// Walks every attribute of a parsed file, including those inside `cfg_attr`, and the tokens of every
/// macro.
struct Finder {
    findings: Findings,
}

impl<'ast> syn::visit::Visit<'ast> for Finder {
    fn visit_attribute(&mut self, attr: &'ast syn::Attribute) {
        let name = attr
            .path()
            .segments
            .last()
            .map(|s| s.ident.to_string())
            .unwrap_or_default();
        let name = name.replace("r#", "");
        let tokens = match &attr.meta {
            syn::Meta::List(list) => strip(&list.tokens.to_string()),
            _ => String::new(),
        };
        let text = strip(&format!("{name}({tokens})"));
        if attribute_relaxes(&text) {
            self.findings.relaxes = true;
        }
        if name == "path" && matches!(attr.meta, syn::Meta::NameValue(_)) {
            self.findings.path_attribute = true;
        }
        if name == "cfg_attr" && text.contains("path=") {
            self.findings.path_attribute = true;
        }
        syn::visit::visit_attribute(self, attr);
    }

    fn visit_macro(&mut self, mac: &'ast syn::Macro) {
        if let Some(last) = mac.path.segments.last() {
            note_macro_name(
                &mut self.findings,
                &last.ident.to_string().replace("r#", ""),
            );
        }
        scan_tokens(&mut self.findings, mac.tokens.clone());
        syn::visit::visit_macro(self, mac);
    }
}

/// What the source does. A file that does not parse is judged by its text: any lint-relaxing word and any
/// covering lint name in it counts, and so does any `include` or `path` word, because a file that syn
/// cannot read is one nobody checked.
fn findings_of(source: &str) -> Findings {
    match syn::parse_file(source) {
        Ok(file) => {
            let mut finder = Finder {
                findings: Findings::default(),
            };
            syn::visit::Visit::visit_file(&mut finder, &file);
            finder.findings
        }
        Err(_) => {
            let stripped = strip(source);
            Findings {
                relaxes: RELAXING.iter().any(|r| stripped.contains(r)) && covers(&stripped),
                path_attribute: stripped.contains("#[path=") || stripped.contains("path="),
                include_code: stripped.contains("include!"),
                include_data: stripped.contains("include_str!")
                    || stripped.contains("include_bytes!"),
                include_data_calls: stripped.matches("include_str!").count()
                    + stripped.matches("include_bytes!").count(),
            }
        }
    }
}

fn relaxes_a_disallowed_lint(source: &str) -> bool {
    findings_of(source).relaxes
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

/// Every `.rs` file of the repository. A source file can reach any other with `#[path]` or `include!`,
/// so the walk starts at the root and skips only the build output (`target/`), `.git/` and the local
/// agent checkouts in `.claude/worktrees/`, which are other copies of this repository and never in CI.
fn repo_rust_files(base: &Path) -> Vec<PathBuf> {
    let mut out = Vec::new();
    for entry in std::fs::read_dir(base).unwrap_or_else(|e| panic!("{}: {e}", base.display())) {
        let path = entry.expect("dir entry").path();
        let file_name = path.file_name().and_then(|n| n.to_str()).unwrap_or("");
        if path.is_dir() {
            if file_name == "target" || file_name == ".git" {
                continue;
            }
            if file_name == ".claude" {
                for inner in std::fs::read_dir(&path).expect("read .claude") {
                    let inner = inner.expect("entry").path();
                    if inner.file_name().is_some_and(|n| n == "worktrees") {
                        continue;
                    }
                    if inner.is_dir() {
                        rust_files(&inner, &mut out);
                    } else if inner.extension().is_some_and(|x| x == "rs") {
                        out.push(inner);
                    }
                }
                continue;
            }
            rust_files(&path, &mut out);
        } else if path.extension().is_some_and(|x| x == "rs") {
            out.push(path);
        }
    }
    out
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
    let files = repo_rust_files(&base);
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
fn a_check_crate_does_not_reach_other_files_by_path_or_include() {
    // `#[path]` and `include!` pull a file that is outside the crate's own module tree into it, so the
    // grep above would have to know where it is. A check crate has neither.
    let base = root();
    let mut bad = Vec::new();
    for dir in check_crates() {
        let mut files = Vec::new();
        rust_files(&dir, &mut files);
        for file in files {
            let rel = relative(&base, &file);
            let found = findings_of(&std::fs::read_to_string(&file).expect("read source"));
            if found.path_attribute || found.include_code {
                bad.push(format!("{rel}: #[path] or include!"));
            }
            if found.include_data
                && !INCLUDE_DATA_ALLOWED.iter().any(|(p, _, _)| *p == rel)
                && !INCLUDE_SHIPPED_DATA_ALLOWED
                    .iter()
                    .any(|(p, _, _)| *p == rel)
            {
                bad.push(format!("{rel}: include_str! or include_bytes!"));
            }
        }
    }
    assert!(
        bad.is_empty(),
        "a check crate may not reach other files this way (add a data include to INCLUDE_DATA_ALLOWED in tests/lint-wall/tests/allow_grep.rs with a reason): {bad:#?}"
    );
    for (path, prefix, why) in INCLUDE_DATA_ALLOWED {
        let source = std::fs::read_to_string(base.join(path)).expect("read source");
        let found = findings_of(&source);
        assert!(
            found.include_data,
            "{path} is on INCLUDE_DATA_ALLOWED but embeds nothing now ({why})"
        );
        let literals = include_literals(&source);
        assert!(
            !literals.is_empty(),
            "{path}: found include_str! but could not read its path literal ({why})"
        );
        // The text readers above see only the `(..)` form. The syn count sees every delimiter, so a call
        // written `include_bytes!["/abs/path"]` makes the counts differ and fails here.
        assert_eq!(
            found.include_data_calls,
            literals.len(),
            "{path}: an include_str! or include_bytes! call is not written with parentheses, so its path was not checked ({why})"
        );
        for literal in literals {
            assert!(
                literal.starts_with(prefix),
                "{path}: an include path `{literal}` does not start with `{prefix}`. The entry allows only that data ({why})"
            );
        }
        // Past the required prefix nothing may climb out of it: not in the first literal, not in a later
        // literal of the call, not in the joined text, and not in an argument of an `fx!` call.
        for call in include_calls(&source) {
            assert!(
                !climbs(&call, prefix),
                "{path}: an include path {call:?} climbs out of `{prefix}` with `..` ({why})"
            );
        }
        for literal in macro_literals(&source, "fx!(") {
            assert!(
                !literal.contains(".."),
                "{path}: an fx! argument `{literal}` contains `..`, which would leave the fixture directory ({why})"
            );
        }
        assert!(
            test_only(&base, path),
            "{path} embeds data but is not a #[cfg(test)] module: declare it, or the module above it, under #[cfg(test)] ({why})"
        );
    }
}

#[test]
fn shipped_data_is_embedded_only_from_the_crates_own_data_directory() {
    let base = root();
    let crates: Vec<String> = check_crates()
        .iter()
        .map(|dir| format!("{}/", relative(&base, dir)))
        .collect();
    for (path, literal, why) in INCLUDE_SHIPPED_DATA_ALLOWED {
        let source = std::fs::read_to_string(base.join(path)).expect("read source");
        let calls = include_calls(&source);
        assert_eq!(
            findings_of(&source).include_data_calls,
            1,
            "{path} must hold exactly one include_str! or include_bytes! call, in any delimiter ({why})"
        );
        assert_eq!(
            calls.len(),
            1,
            "{path} must hold exactly one include call written with parentheses ({why})"
        );
        assert_eq!(
            calls[0],
            [(*literal).to_owned()],
            "{path}: the include must be the single literal `{literal}` ({why})"
        );
        let name = literal
            .strip_prefix("../data/")
            .unwrap_or_else(|| panic!("{path}: `{literal}` is not under ../data/ ({why})"));
        assert!(
            name.ends_with(".toml")
                && !name.contains('/')
                && !name.contains('\\')
                && !name.contains(".."),
            "{path}: `{name}` must be a plain .toml file name ({why})"
        );
        // The file sits directly in the crate's src/ directory: `<crate>/src/<file>.rs`.
        let crate_dir = crates
            .iter()
            .find(|dir| path.starts_with(&format!("{dir}src/")))
            .unwrap_or_else(|| panic!("{path} is not in a check crate's src/ ({why})"));
        assert!(
            !path[crate_dir.len() + "src/".len()..].contains('/'),
            "{path} must sit directly in src/ so that `../data/` is the crate's own directory ({why})"
        );
        let target = base.join(crate_dir).join("data").join(name);
        assert!(target.is_file(), "{} is missing ({why})", target.display());
    }
}

/// The source without whole-line `//` comments.
fn without_comments(source: &str) -> String {
    source
        .lines()
        .filter(|l| !l.trim_start().starts_with("//"))
        .collect::<Vec<_>>()
        .join("\n")
}

/// Whether the literals of one include call climb out of `prefix`: past the prefix, a `..` in the first
/// literal, in any later literal, or in the text the literals make when joined.
fn climbs(call: &[String], prefix: &str) -> bool {
    let first = call.first().map_or("", String::as_str);
    let mut after: Vec<&str> = vec![first.get(prefix.len()..).unwrap_or_default()];
    after.extend(call.iter().skip(1).map(String::as_str));
    after.iter().any(|part| part.contains("..")) || after.concat().contains("..")
}

/// Reads one string literal. `body` starts just after the opening quote. Returns the text and what is
/// left after the closing quote.
fn read_literal(body: &str) -> (String, &str) {
    let mut text = String::new();
    let mut chars = body.char_indices();
    while let Some((at, c)) = chars.next() {
        match c {
            '"' => return (text, &body[at + 1..]),
            '\\' => text.extend(chars.next().map(|(_, c)| c)),
            c => text.push(c),
        }
    }
    (text, "")
}

/// Every string literal in the arguments of the macro call that starts at `args` (just after the
/// opening parenthesis), up to the matching closing one. Nested calls such as `concat!(..)` are read
/// too.
fn call_literals(args: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut depth = 1_usize;
    let mut rest = args;
    while let Some(c) = rest.chars().next() {
        match c {
            '"' => {
                let (text, after) = read_literal(&rest[1..]);
                out.push(text);
                rest = after;
                continue;
            }
            '(' => depth += 1,
            ')' => {
                depth -= 1;
                if depth == 0 {
                    break;
                }
            }
            _ => {}
        }
        rest = &rest[c.len_utf8()..];
    }
    out
}

/// Every string literal in the arguments of every call of the macro `name` (written `fx!(`).
fn macro_literals(source: &str, name: &str) -> Vec<String> {
    let code = without_comments(source);
    let mut out = Vec::new();
    let mut rest = code.as_str();
    while let Some(at) = rest.find(name) {
        rest = &rest[at + name.len()..];
        out.extend(call_literals(rest));
    }
    out
}

/// All the string literals of every `include_str!(..)` and `include_bytes!(..)` call, one list per call,
/// looking through a `concat!(`.
fn include_calls(source: &str) -> Vec<Vec<String>> {
    let code = without_comments(source);
    let mut out = Vec::new();
    for name in ["include_str!(", "include_bytes!("] {
        let mut rest = code.as_str();
        while let Some(at) = rest.find(name) {
            rest = &rest[at + name.len()..];
            out.push(call_literals(rest));
        }
    }
    out
}

/// The first string literal of every `include_str!(..)` and `include_bytes!(..)` in the source, looking
/// through a `concat!(`. A path that does not start with a literal (a macro variable, say) reads as the
/// empty string, which no prefix matches. Whole-line `//` comments are ignored.
fn include_literals(source: &str) -> Vec<String> {
    let code = without_comments(source);
    let mut out = Vec::new();
    for name in ["include_str!(", "include_bytes!("] {
        let mut rest = code.as_str();
        while let Some(at) = rest.find(name) {
            rest = &rest[at + name.len()..];
            let mut arg = rest.trim_start();
            if let Some(inner) = arg.strip_prefix("concat!(") {
                arg = inner.trim_start();
            }
            let literal = arg.strip_prefix('"').map(|body| read_literal(body).0);
            out.push(literal.unwrap_or_default());
        }
    }
    out
}

/// Whether the module in `module` is compiled only for tests: it is declared under `#[cfg(test)]` in
/// its parent file, or its parent file is itself test-only.
fn test_only(base: &Path, module: &str) -> bool {
    let file = base.join(module);
    let Some(stem) = file.file_stem().and_then(|s| s.to_str()) else {
        return false;
    };
    let Some(dir) = file.parent() else {
        return false;
    };
    let sibling = {
        let mut name = dir.as_os_str().to_owned();
        name.push(".rs");
        std::path::PathBuf::from(name)
    };
    let parents = [
        sibling,
        dir.join("mod.rs"),
        dir.join("lib.rs"),
        dir.join("main.rs"),
    ];
    let declared = format!("#[cfg(test)]mod{stem};");
    for parent in parents.iter().filter(|p| p.is_file() && **p != file) {
        let text: String = std::fs::read_to_string(parent)
            .expect("read parent source")
            .split_whitespace()
            .collect();
        if text.contains(&declared) {
            return true;
        }
        if text.contains(&format!("mod{stem};")) {
            let parent_relative = relative(base, parent);
            return test_only(base, &parent_relative);
        }
    }
    false
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
            "a raw identifier for the attribute",
            "#[r#allow(clippy::disallowed_methods)] fn f() {}",
        ),
        (
            "a raw identifier in the lint path",
            "#[allow(clippy::r#disallowed_methods)] fn f() {}",
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
            "tokens forwarded into allow",
            "macro_rules! m { ($($t:tt)*) => { #[allow($($t)*)] fn f() {} }; } m!(clippy::disallowed_methods);",
        ),
        (
            "an attribute name forwarded",
            "macro_rules! m { ($a:ident) => { #[$a(clippy::disallowed_methods)] fn f() {} }; } m!(allow);",
        ),
        (
            "a whole meta forwarded",
            "macro_rules! m { ($m:meta) => { #[$m] fn f() {} }; } m!(allow(clippy::disallowed_methods));",
        ),
        (
            "tokens forwarded into cfg_attr",
            "macro_rules! m { ($($t:tt)*) => { #[cfg_attr(test, allow($($t)*))] fn f() {} }; }",
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
        (
            "the hash passed as a tt (the body and the call)",
            "macro_rules! m { ($h:tt $a:meta) => { $h [$a] mod e { pub fn f() {} } }; } m!(# allow(clippy::disallowed_methods));",
        ),
        (
            "the hash passed as a tt (the call only)",
            "m!(# allow(clippy::disallowed_methods));",
        ),
        (
            "the hash passed as a tt (the body only)",
            "macro_rules! m { ($h:tt $a:meta) => { $h [$a] mod e {} }; }",
        ),
        (
            "a def! call that rewrites a matcher",
            "def!((#[$a:meta]) => { $h [$a] mod e {} });",
        ),
        (
            "a doc-style arm and a bare-meta arm in one macro",
            "macro_rules! m { (#[$a:meta]) => {}; ($a:meta) => { #[$a] fn f() {} }; } m!(allow(clippy::disallowed_methods));",
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
        (
            "a macro that forwards a deny",
            "macro_rules! m { ($l:ident) => { #[deny(clippy::$l)] fn f() {} }; }",
        ),
        (
            "doc attributes forwarded as written at the call site",
            "macro_rules! m { ($(#[$meta:meta])* $n:ident) => { $(#[$meta])* struct $n; }; }",
        ),
        (
            "two arms that both take the attribute as written",
            "macro_rules! m { (#[$a:meta] $n:ident) => { #[$a] struct $n; }; (#[$b:meta] #[$c:meta] $n:ident) => { #[$b] #[$c] struct $n; }; }",
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
fn the_reach_scan_sees_path_and_include() {
    for (what, source, code, data, path) in [
        ("path", "#[path = \"x.rs\"] mod a;", false, false, true),
        (
            "path to another directory",
            "#[path = \"../../../examples/x.rs\"] mod a;",
            false,
            false,
            true,
        ),
        (
            "path with spaces",
            "# [ path = \"x.rs\" ] mod a;",
            false,
            false,
            true,
        ),
        (
            "path in cfg_attr",
            "#[cfg_attr(unix, path = \"x.rs\")] mod a;",
            false,
            false,
            true,
        ),
        (
            "path in a macro body",
            "macro_rules! m { () => { #[path = \"x.rs\"] mod a; }; }",
            false,
            false,
            true,
        ),
        ("include", "include!(\"x.rs\");", true, false, false),
        (
            "include in an expression",
            "fn f() { include!(\"x.rs\"); }",
            true,
            false,
            false,
        ),
        (
            "include in a macro body",
            "macro_rules! m { () => { include!(\"x.rs\") }; }",
            true,
            false,
            false,
        ),
        (
            "include_str",
            "const A: &str = include_str!(\"x\");",
            false,
            true,
            false,
        ),
        (
            "include_bytes",
            "const A: &[u8] = include_bytes!(\"x\");",
            false,
            true,
            false,
        ),
        (
            "qualified include",
            "include_str!(\"a\"); core::include!(\"x.rs\");",
            true,
            true,
            false,
        ),
    ] {
        let f = findings_of(source);
        assert_eq!(f.include_code, code, "{what}: include!");
        assert_eq!(f.include_data, data, "{what}: include_str or include_bytes");
        assert_eq!(f.path_attribute, path, "{what}: path");
    }
    for (what, source) in [
        ("a comment", "// include!(\"x.rs\")\nfn f() {}"),
        ("a string", "const S: &str = \"include!(x) #[path = y]\";"),
        ("a plain mod", "mod a;"),
        ("an unrelated attribute", "#[derive(Debug)] struct S;"),
    ] {
        let f = findings_of(source);
        assert!(
            !f.include_code && !f.include_data && !f.path_attribute,
            "flagged: {what}"
        );
    }
}

#[test]
fn an_include_in_any_delimiter_is_counted() {
    // The text readers (`include_calls`, `include_literals`) find only the `(..)` form. The syn count must
    // see `[..]`, `{..}` and a space before the delimiter, so an include that the readers miss still fails
    // the count checks of both include lists.
    for (what, source) in [
        ("parentheses", "const A: &str = include_str!(\"x\");"),
        ("brackets", "const A: &str = include_str![\"/etc/x\"];"),
        ("braces", "const A: &[u8] = include_bytes!{\"/etc/x\"};"),
        ("a space", "const A: &str = include_str! (\"x\");"),
        ("nested", "const A: &str = concat!(include_str![\"x\"]);"),
        (
            "a macro body",
            "macro_rules! m { () => { include_str![\"x\"] }; }",
        ),
    ] {
        assert_eq!(findings_of(source).include_data_calls, 1, "{what}");
    }
    assert_eq!(
        findings_of("fn f() { include_str!(\"a\"); include_bytes![\"b\"]; }").include_data_calls,
        2
    );
    // A bracket call hides from the readers, which is what the count catches.
    let hidden = "const A: &[u8] = include_bytes![\"/abs/path\"];";
    assert!(include_calls(hidden).is_empty());
    assert!(include_literals(hidden).is_empty());
    assert_eq!(findings_of(hidden).include_data_calls, 1);
    // A file that does not parse is counted by its text.
    assert_eq!(
        findings_of("fn ( include_str![\"x\"]").include_data_calls,
        1
    );
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
fn the_repo_walk_starts_at_the_root_and_skips_only_build_output() {
    let dir = Path::new(env!("CARGO_TARGET_TMPDIR")).join("allow-grep-repo");
    let _ = std::fs::remove_dir_all(&dir);
    for sub in [
        "docs",
        "examples",
        "scripts",
        ".github",
        ".claude/agents",
        "crates/a",
        // The three that are skipped.
        "target",
        ".git",
        ".claude/worktrees/w",
    ] {
        std::fs::create_dir_all(dir.join(sub)).expect("create dir");
        std::fs::write(dir.join(sub).join("x.rs"), "").expect("write");
    }
    std::fs::write(dir.join("build.rs"), "").expect("write");
    let mut found: Vec<String> = repo_rust_files(&dir)
        .iter()
        .map(|p| relative(&dir, p))
        .collect();
    found.sort();
    assert_eq!(
        found,
        [
            ".claude/agents/x.rs",
            ".github/x.rs",
            "build.rs",
            "crates/a/x.rs",
            "docs/x.rs",
            "examples/x.rs",
            "scripts/x.rs"
        ]
    );
}

#[test]
fn the_include_reader_sees_every_literal_and_refuses_what_it_cannot_read() {
    assert_eq!(
        include_literals("const A: &str = include_str!(\"../a/b.txt\");"),
        ["../a/b.txt"]
    );
    assert_eq!(
        include_literals(
            "macro_rules! fx { () => { include_bytes!(concat!(\n \"../x/\", $c)) }; }"
        ),
        ["../x/"]
    );
    assert_eq!(include_literals("let a = include_str!($path);"), [""]);
    assert!(include_literals("// include_str!(\"../a\")\nfn f() {}").is_empty());
}

#[test]
fn the_include_reader_sees_every_literal_of_a_call_and_of_fx() {
    let source = "const A: &str = include_str!(concat!(\"../x/\", $c, \"/../../etc\", f(\"y\")));\nlet b = fx!(\"case\", \"a/../b\");";
    assert_eq!(
        include_calls(source),
        [["../x/", "/../../etc", "y"]],
        "a nested call and a later literal are read"
    );
    assert_eq!(macro_literals(source, "fx!("), ["case", "a/../b"]);
    // The macro definition is not a call.
    assert!(macro_literals("macro_rules! fx { () => {} }", "fx!(").is_empty());
    // A closing parenthesis inside a literal does not end the call.
    assert_eq!(call_literals("\"a)\", \"b\") \"c\""), ["a)", "b"]);
}

#[test]
fn a_climb_after_the_prefix_is_found_in_a_later_literal_or_in_the_joined_text() {
    let lits = |parts: &[&str]| parts.iter().map(|p| (*p).to_owned()).collect::<Vec<_>>();
    assert!(!climbs(
        &lits(&["../../f/", "case", "/", "file"]),
        "../../f/"
    ));
    assert!(climbs(&lits(&["../../f/", "../../x"]), "../../f/"));
    assert!(climbs(&lits(&["../../f/../x"]), "../../f/"));
    assert!(climbs(&lits(&["../../f/.", "."]), "../../f/"));
}
