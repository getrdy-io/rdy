//! `--password` on argv is refused with exit 64 and the value is never echoed (M1-112, 07
//! section 10).

use std::process::{Command, Output};

const WANT: &str = "error: passwords on the command line show up in shell history and in ps\n\
                    fix: use --password-file, the RDY_KEY_PASSWORD variable, or the prompt\n";

fn rdy(args: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_rdy"))
        .args(args)
        .env_remove("RDY_PROGRESS")
        .env_remove("RDY_KEY_PASSWORD")
        .output()
        .unwrap_or_else(|e| panic!("the rdy binary did not start: {e}"))
}

fn stderr_of(out: &Output) -> &str {
    std::str::from_utf8(&out.stderr).unwrap_or_else(|e| panic!("stderr is not UTF-8: {e}"))
}

#[test]
fn password_on_argv_exits_64_with_the_reason_and_never_echoes_the_value() {
    for args in [
        &[
            "spec",
            "sign",
            "s.yaml",
            "--secret-key",
            "k.key",
            "--password",
            "CANARY-7f3a",
        ][..],
        &[
            "spec",
            "sign",
            "s.yaml",
            "--secret-key",
            "k.key",
            "--password=CANARY-7f3a",
        ],
        &[
            "spec",
            "sign",
            "--password",
            "CANARY-7f3a",
            "s.yaml",
            "--secret-key",
            "k.key",
        ],
        &[
            "spec",
            "keygen",
            "acme-signing",
            "--password",
            "CANARY-7f3a",
        ],
        &["spec", "keygen", "acme-signing", "--password=CANARY-7f3a"],
        &["spec", "keygen", "--password=CANARY-7f3a"],
        &["spec", "sign", "--password"],
        &["spec", "sign", "--password="],
    ] {
        let out = rdy(args);
        assert_eq!(out.status.code(), Some(64), "rdy {args:?}: {out:?}");
        assert!(out.stdout.is_empty(), "rdy {args:?} wrote to stdout");
        assert_eq!(stderr_of(&out), WANT, "rdy {args:?}");
    }
}

#[test]
fn the_refusal_wins_over_a_missing_required_argument() {
    // Without --secret-key, clap alone would say "missing required argument".
    let out = rdy(&["spec", "sign", "s.yaml", "--password", "CANARY-7f3a"]);
    assert_eq!(out.status.code(), Some(64));
    assert_eq!(stderr_of(&out), WANT);
}

#[test]
fn password_file_and_the_variable_are_not_refused() {
    // The commands run (M1-125). Run them in an empty folder so nothing lands in the source tree.
    let dir = tempfile::tempdir().unwrap_or_else(|e| panic!("tempdir: {e}"));
    let run = |args: &[&str], password: Option<&str>| {
        let mut cmd = Command::new(env!("CARGO_BIN_EXE_rdy"));
        cmd.args(args)
            .current_dir(dir.path())
            .env_remove("RDY_PROGRESS")
            .env_remove("RDY_KEY_PASSWORD");
        if let Some(password) = password {
            cmd.env("RDY_KEY_PASSWORD", password);
        }
        cmd.output()
            .unwrap_or_else(|e| panic!("the rdy binary did not start: {e}"))
    };
    // A spec that is not there: the error is about the file, never about the password flag.
    let out = run(
        &[
            "spec",
            "sign",
            "s.yaml",
            "--secret-key",
            "k.key",
            "--password-file",
            "-",
        ],
        None,
    );
    assert_eq!(out.status.code(), Some(64), "{out:?}");
    assert!(stderr_of(&out).contains("cannot read s.yaml"), "{out:?}");
    assert!(!stderr_of(&out).contains("shell history"));
    // A password file that is not there.
    let out = run(
        &[
            "spec",
            "keygen",
            "acme-signing",
            "--password-file",
            "pw.txt",
        ],
        None,
    );
    assert_eq!(out.status.code(), Some(64), "{out:?}");
    assert!(!stderr_of(&out).contains("shell history"));
    assert!(!dir.path().join("acme-signing.key").exists());
    // The variable works, and its value is never echoed.
    let out = run(&["spec", "keygen", "acme-signing"], Some("CANARY-7f3a"));
    assert_eq!(out.status.code(), Some(0), "{out:?}");
    assert!(!stderr_of(&out).contains("CANARY"));
    assert!(dir.path().join("acme-signing.key").exists());
}

#[test]
fn after_double_dash_it_is_not_a_flag() {
    let out = rdy(&[
        "spec",
        "sign",
        "s.yaml",
        "--secret-key",
        "k.key",
        "--",
        "--password",
    ]);
    assert!(!stderr_of(&out).contains("shell history"), "{out:?}");
}

#[test]
fn other_commands_keep_the_generic_unknown_flag_error() {
    // Only the commands that read a key password have the password reason.
    let out = rdy(&["run", "s.yaml", "--password", "CANARY-7f3a"]);
    assert_eq!(out.status.code(), Some(64));
    let err = stderr_of(&out);
    assert!(!err.contains("CANARY"), "{err:?}");
    assert!(!err.contains("shell history"), "{err:?}");
}

#[test]
fn help_for_the_signing_commands_does_not_offer_a_password_flag() {
    for args in [
        &["spec", "sign", "--help"][..],
        &["spec", "keygen", "--help"],
    ] {
        let out = rdy(args);
        let text = String::from_utf8_lossy(&out.stdout);
        assert!(!text.contains("--password "), "rdy {args:?}: {text}");
        assert!(text.contains("--password-file"), "rdy {args:?}");
        assert!(text.contains("RDY_KEY_PASSWORD"), "rdy {args:?}");
    }
}
