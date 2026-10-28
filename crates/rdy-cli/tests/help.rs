//! Help output of every M1 command (07 Appendix A). The snapshots are the output of this build.
//! The words, the sections and the examples were checked against Appendix A when they were taken.
//!
//! `-h` is the compact form. `--help` is the full form with examples. A changed help text fails
//! with the path of an `.actual` file to compare. `UPDATE_GOLDENS=1` rewrites the snapshots, and
//! is refused when `CI` is set.

use std::path::PathBuf;

/// Every command with its snapshot name and its words on the command line.
const COMMANDS: &[(&str, &[&str])] = &[
    ("rdy", &[]),
    ("run", &["run"]),
    ("verify", &["verify"]),
    ("spec", &["spec"]),
    ("spec-lint", &["spec", "lint"]),
    ("spec-sign", &["spec", "sign"]),
    ("spec-keygen", &["spec", "keygen"]),
    ("trust", &["trust"]),
    ("trust-add", &["trust", "add"]),
    ("trust-list", &["trust", "list"]),
    ("trust-remove", &["trust", "remove"]),
    ("version", &["version"]),
];

/// Run `rdy` in process and return (exit code, stdout, stderr).
fn rdy(args: &[&str]) -> (u8, String, String) {
    let mut out = Vec::new();
    let mut err = Vec::new();
    let argv = std::iter::once("rdy").chain(args.iter().copied());
    let code = rdy_cli::run(argv, &mut out, &mut err);
    let text = |bytes: Vec<u8>| {
        String::from_utf8(bytes).unwrap_or_else(|e| panic!("output is not UTF-8: {e}"))
    };
    (code, text(out), text(err))
}

fn help(path: &[&str], flag: &str) -> String {
    let mut args = path.to_vec();
    args.push(flag);
    let (code, out, err) = rdy(&args);
    assert_eq!(code, 0, "rdy {args:?} did not exit 0");
    assert!(err.is_empty(), "rdy {args:?} wrote to stderr: {err:?}");
    out
}

fn snapshot_path(name: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests")
        .join("snapshots")
        .join(name)
}

/// Compare `actual` with the snapshot file `name`.
fn check_snapshot(name: &str, actual: &str) {
    let path = snapshot_path(name);
    if std::env::var_os("UPDATE_GOLDENS").is_some_and(|v| v == "1") {
        assert!(
            std::env::var_os("CI").is_none(),
            "UPDATE_GOLDENS=1 is refused when CI is set"
        );
        std::fs::write(&path, actual)
            .unwrap_or_else(|e| panic!("cannot write {}: {e}", path.display()));
        return;
    }
    let want = std::fs::read_to_string(&path).unwrap_or_else(|e| {
        panic!(
            "missing snapshot {}: {e}. Run with UPDATE_GOLDENS=1 to create it.",
            path.display()
        )
    });
    if want != actual {
        let mut actual_path = path.clone().into_os_string();
        actual_path.push(".actual");
        let actual_path = PathBuf::from(actual_path);
        std::fs::write(&actual_path, actual)
            .unwrap_or_else(|e| panic!("cannot write {}: {e}", actual_path.display()));
        panic!(
            "help text changed. Compare {} with {}",
            path.display(),
            actual_path.display()
        );
    }
}

#[test]
fn short_help_snapshots() {
    for (name, path) in COMMANDS {
        check_snapshot(&format!("{name}.short.txt"), &help(path, "-h"));
    }
}

#[test]
fn long_help_snapshots() {
    for (name, path) in COMMANDS {
        check_snapshot(&format!("{name}.long.txt"), &help(path, "--help"));
    }
}

#[test]
fn help_subcommand_matches_long_help() {
    let want = help(&["run"], "--help");
    let (code, out, _) = rdy(&["help", "run"]);
    assert_eq!(code, 0);
    assert_eq!(out, want);
    let want = help(&["spec", "lint"], "--help");
    let (_, out, _) = rdy(&["help", "spec", "lint"]);
    assert_eq!(out, want);
}

#[test]
fn compact_form_has_no_examples_and_full_form_has_them() {
    for (name, path) in COMMANDS {
        let short = help(path, "-h");
        assert!(
            !short.contains("Examples:") && !short.contains("Exit codes:"),
            "{name} -h is not compact:\n{short}"
        );
    }
    // 07 A.5 and A.9 to A.11 show no examples for the two groups and `trust list`.
    for (name, path) in COMMANDS {
        if ["spec", "trust", "trust-list"].contains(name) {
            continue;
        }
        let long = help(path, "--help");
        assert!(long.contains("Example"), "{name} --help has no examples");
    }
}

#[test]
fn run_and_verify_pages_have_no_m2_flags() {
    for path in [&["run"][..], &["verify"][..], &[][..]] {
        for flag in ["-h", "--help"] {
            let text = help(path, flag);
            assert!(
                !text.contains("--timeout"),
                "{path:?} {flag} names --timeout"
            );
            assert!(
                !text.contains("--dry-run"),
                "{path:?} {flag} names --dry-run"
            );
        }
    }
}

#[test]
fn verify_has_no_allow_unsigned() {
    for flag in ["-h", "--help"] {
        let text = help(&["verify"], flag);
        assert!(!text.contains("--allow-unsigned"));
    }
}

#[test]
fn lines_fit_in_80_columns() {
    for (name, path) in COMMANDS {
        for flag in ["-h", "--help"] {
            for line in help(path, flag).lines() {
                assert!(
                    line.chars().count() <= 80,
                    "{name} {flag}: line is over 80 columns: {line:?}"
                );
            }
        }
    }
}

#[test]
fn help_is_ascii_without_trailing_spaces() {
    for (name, path) in COMMANDS {
        for flag in ["-h", "--help"] {
            let text = help(path, flag);
            assert!(text.is_ascii(), "{name} {flag} is not ASCII");
            assert!(
                text.lines().all(|l| l == l.trim_end()),
                "{name} {flag} has trailing spaces"
            );
            assert!(!text.contains('\u{1b}'), "{name} {flag} has an escape");
        }
    }
}

#[test]
fn the_command_tree_is_the_m1_tree() {
    let root = rdy_cli::command();
    let names = |cmd: &clap::Command| {
        cmd.get_subcommands()
            .map(|c| c.get_name().to_string())
            .collect::<Vec<_>>()
    };
    assert_eq!(
        names(&root),
        ["run", "verify", "spec", "trust", "version", "help"]
    );
    let spec = root.find_subcommand("spec").map(names);
    assert_eq!(
        spec,
        Some(vec!["lint".into(), "sign".into(), "keygen".into()])
    );
    let trust = root.find_subcommand("trust").map(names);
    assert_eq!(
        trust,
        Some(vec!["add".into(), "list".into(), "remove".into()])
    );
}

#[test]
fn global_flags_work_before_and_after_the_subcommand() {
    for args in [
        &["--color", "never", "version"][..],
        &["version", "--color", "never"][..],
        &["--progress=never", "-q", "version"][..],
        &["version", "-v", "--progress", "auto"][..],
    ] {
        let (code, out, err) = rdy(args);
        assert_eq!((code, err.as_str()), (0, ""), "rdy {args:?}");
        assert!(out.starts_with("rdy "), "rdy {args:?}: {out:?}");
    }
}

#[test]
fn the_binary_name_is_rdy_whatever_argv0_is() {
    // On Windows argv[0] is `rdy.exe`. clap would print that in Usage lines.
    for name in ["rdy.exe", "C:\\tools\\rdy.exe", "./target/debug/rdy"] {
        for path in [&[][..], &["run"][..], &["spec", "lint"][..]] {
            for flag in ["-h", "--help"] {
                let mut out = Vec::new();
                let mut err = Vec::new();
                let argv = std::iter::once(name)
                    .chain(path.iter().copied())
                    .chain([flag]);
                assert_eq!(rdy_cli::run(argv, &mut out, &mut err), 0);
                let out = String::from_utf8(out).unwrap_or_default();
                assert_eq!(out, help(path, flag), "argv[0] = {name}");
                assert!(!out.contains(".exe"), "{name}: {out}");
            }
        }
        let mut out = Vec::new();
        let mut err = Vec::new();
        let code = rdy_cli::run([name, "run"], &mut out, &mut err);
        let err = String::from_utf8(err).unwrap_or_default();
        assert_eq!(code, 64);
        assert!(err.contains("fix: see 'rdy run --help'"), "{name}: {err}");
        assert!(!err.contains(".exe"), "{name}: {err}");
    }
}
