//! Exit codes of the built `rdy` binary (ADR 0008, 07 section 1 and 5).
//!
//! clap exits 2 on its own errors. In rdy 2 means NOT READY, so a usage error must exit 64.
//! Commands that later tickets implement exit 70 with a fix line.

use std::process::{Command, Output};

fn rdy(args: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_rdy"))
        .args(args)
        .env_remove("RDY_PROGRESS")
        .output()
        .unwrap_or_else(|e| panic!("the rdy binary did not start: {e}"))
}

fn text(bytes: &[u8]) -> &str {
    std::str::from_utf8(bytes).unwrap_or_else(|e| panic!("output is not UTF-8: {e}"))
}

fn code(out: &Output) -> i32 {
    out.status
        .code()
        .unwrap_or_else(|| panic!("rdy was killed by a signal: {out:?}"))
}

/// A usage error: exit 64, nothing on stdout, and the two lines on stderr.
fn assert_usage_error(args: &[&str]) -> String {
    let out = rdy(args);
    assert_eq!(code(&out), 64, "rdy {args:?}: {out:?}");
    assert!(out.stdout.is_empty(), "rdy {args:?} wrote to stdout");
    let err = text(&out.stderr).to_string();
    let lines: Vec<&str> = err.lines().collect();
    assert_eq!(lines.len(), 2, "want two lines: {err:?}");
    assert!(lines[0].starts_with("error: "), "{err:?}");
    assert!(lines[1].starts_with("fix: "), "{err:?}");
    err
}

#[test]
fn bare_rdy_prints_help_on_stdout_and_exits_0() {
    let out = rdy(&[]);
    assert_eq!(code(&out), 0);
    assert!(out.stderr.is_empty());
    let stdout = text(&out.stdout);
    assert!(
        stdout.contains("Usage: rdy [OPTIONS] <COMMAND>"),
        "{stdout}"
    );
    assert!(stdout.contains("Commands:"), "{stdout}");
}

#[test]
fn bare_spec_and_trust_print_help_on_stdout_and_exit_0() {
    for (group, usage) in [
        ("spec", "Usage: rdy spec [OPTIONS] <COMMAND>"),
        ("trust", "Usage: rdy trust [OPTIONS] <COMMAND>"),
    ] {
        let out = rdy(&[group]);
        assert_eq!(code(&out), 0, "rdy {group}");
        assert!(out.stderr.is_empty(), "rdy {group}");
        assert!(text(&out.stdout).contains(usage), "rdy {group}");
    }
}

#[test]
fn help_and_version_flags_exit_0_on_stdout() {
    for args in [&["-h"][..], &["--help"], &["run", "--help"], &["-V"]] {
        let out = rdy(args);
        assert_eq!(code(&out), 0, "rdy {args:?}");
        assert!(out.stderr.is_empty(), "rdy {args:?}");
        assert!(!out.stdout.is_empty(), "rdy {args:?}");
    }
}

#[test]
fn an_unknown_flag_exits_64_not_2() {
    for args in [
        &["--bogus"][..],
        &["run", "spec.yaml", "--bogus"],
        &["spec", "lint", "spec.yaml", "--bogus"],
        &["trust", "list", "--bogus"],
        &["version", "--bogus"],
    ] {
        assert_usage_error(args);
    }
}

#[test]
fn a_missing_argument_exits_64() {
    for args in [
        &["run"][..],
        &["verify"],
        &["spec", "lint"],
        &["spec", "sign", "spec.yaml"],
        &["spec", "keygen"],
        &["trust", "add", "acme"],
        &["trust", "remove"],
    ] {
        assert_usage_error(args);
    }
}

#[test]
fn an_unknown_command_and_a_bad_value_exit_64() {
    assert_usage_error(&["bogus"]);
    assert_usage_error(&["spec", "bogus"]);
    assert_usage_error(&["--color", "purple", "version"]);
    assert_usage_error(&["help", "bogus"]);
}

#[test]
fn quiet_with_verbose_exits_64() {
    assert_usage_error(&["-q", "-v", "version"]);
}

#[test]
fn version_flag_is_top_level_only() {
    assert_usage_error(&["run", "spec.yaml", "-V"]);
}

#[test]
fn a_usage_error_never_echoes_what_was_typed() {
    // The full no-echo suite is in no_echo.rs (M1-030). This is the floor: no value comes back.
    for args in [
        &["run", "spec.yaml", "--tokne=CANARY-7f3a"][..],
        &["run", "spec.yaml", "--pasword", "CANARY-7f3a"],
        &["run", "spec.yaml", "CANARY-7f3a"],
        &["CANARY-7f3a"],
        &["--color", "CANARY-7f3a", "version"],
        &["--CANARY_7f3a=x"],
        &["run", "spec.yaml", "--jobs=CANARY-7f3a"],
        &["run", "spec.yaml", "-qCANARY-7f3a"],
        &["help", "CANARY-7f3a"],
        &["spec", "CANARY-7f3a"],
    ] {
        let err = assert_usage_error(args);
        assert!(!err.contains("CANARY"), "rdy {args:?} echoed: {err:?}");
    }
}

#[test]
fn a_usage_error_never_names_the_trust_flags() {
    for args in [
        &["run", "spec.yaml", "--keey", "k.pub"][..],
        &["run", "spec.yaml", "--allow-unsgned"],
        &["run", "spec.yaml", "--yes"],
        &["run", "spec.yaml", "--kye"],
    ] {
        let err = assert_usage_error(args);
        assert!(
            !err.contains("--key") && !err.contains("--allow-unsigned"),
            "rdy {args:?}: {err:?}"
        );
    }
}

#[test]
fn commands_for_later_tickets_exit_70_with_a_fix_line() {
    for args in [
        &["run", "spec.yaml"][..],
        &["verify", "spec.yaml"],
        &["trust", "add", "acme", "--key", "acme.pub"],
        &["trust", "list"],
        &["trust", "remove", "acme"],
    ] {
        let out = rdy(args);
        assert_eq!(code(&out), 70, "rdy {args:?}: {out:?}");
        assert!(out.stdout.is_empty(), "rdy {args:?} wrote to stdout");
        let err = text(&out.stderr);
        assert!(
            err.starts_with("error: rdy ") && err.contains("is not yet implemented in this build"),
            "rdy {args:?}: {err:?}"
        );
        assert!(err.contains("\nfix: "), "rdy {args:?} has no fix: {err:?}");
    }
}

/// With `--json` the same failure also puts an error object on stdout (M1-021, 07 section 4.1).
#[test]
fn a_later_ticket_command_with_json_prints_the_error_object_too() {
    let out = rdy(&["run", "spec.yaml", "--json"]);
    assert_eq!(code(&out), 70);
    let err = text(&out.stderr);
    assert!(
        err.contains("is not yet implemented in this build"),
        "{err:?}"
    );
    assert!(err.contains("\nfix: "), "{err:?}");
    assert!(text(&out.stdout).contains("\"code\": \"internal\""));
}

#[test]
fn version_still_works() {
    let out = rdy(&["version"]);
    assert_eq!(code(&out), 0);
    assert!(text(&out.stdout).starts_with("rdy "));
    assert!(out.stderr.is_empty());
}

#[test]
fn a_bad_progress_variable_is_not_echoed_and_not_blamed_on_a_flag() {
    let out = Command::new(env!("CARGO_BIN_EXE_rdy"))
        .args(["version"])
        .env("RDY_PROGRESS", "CANARY-7f3a")
        .output()
        .unwrap_or_else(|e| panic!("the rdy binary did not start: {e}"));
    assert_eq!(code(&out), 64);
    let err = text(&out.stderr);
    assert!(!err.contains("CANARY"), "{err:?}");
    assert!(err.contains("RDY_PROGRESS"), "{err:?}");
    assert!(!err.contains("--progress"), "{err:?}");
}

#[test]
fn fix_lines_name_the_subcommand() {
    for (args, fix) in [
        (&["run", "spec.yaml", "--color", "purple"][..], "rdy run"),
        (&["run", "spec.yaml", "--jobs", "abc"], "rdy run"),
        (&["run", "spec.yaml", "-q", "-v"], "rdy run"),
        (
            &["spec", "sign", "s.yaml", "--color=purple"],
            "rdy spec sign",
        ),
        (&["trust", "remove"], "rdy trust remove"),
        (&["--color", "run", "version"], "rdy version"),
        (&["--bogus"], "rdy"),
    ] {
        let err = assert_usage_error(args);
        let want = format!("fix: see '{fix} --help'");
        assert!(
            err.contains(&want),
            "rdy {args:?}: want {want:?} in {err:?}"
        );
    }
}

#[test]
fn repeated_and_valueless_flags_have_their_own_words() {
    let err = assert_usage_error(&["run", "s.yaml", "--sig", "a", "--sig", "b"]);
    assert!(err.contains("can be used only once"), "{err:?}");
    let err = assert_usage_error(&["run", "s.yaml", "--sig"]);
    assert!(err.contains("missing a value for --sig"), "{err:?}");
    let err = assert_usage_error(&["run", "s.yaml", "-q", "-v"]);
    assert!(err.contains("cannot be used together"), "{err:?}");
}
