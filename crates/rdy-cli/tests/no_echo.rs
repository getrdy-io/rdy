//! The no-echo rule for usage errors (M1-030, 07 sections 1 and 9, rules 7 and 8).
//!
//! A usage error prints the name of an unknown flag, never the text after `=` or the next argument.
//! A did-you-mean never offers `--key` or `--allow-unsigned`, a hidden flag or a flag of another
//! command. The tests run the library entry point with capture buffers.

use rdy_cli::run;
use serde_json::Value;

const CANARY: &str = "CANARYsecret0123456789";

/// Run `rdy` with `args`. Returns the exit code, stdout and stderr.
fn rdy(args: &[&str]) -> (u8, String, String) {
    let mut out = Vec::new();
    let mut err = Vec::new();
    let argv = std::iter::once("rdy").chain(args.iter().copied());
    let code = run(argv, &mut out, &mut err);
    let text = |b: Vec<u8>| String::from_utf8(b).unwrap_or_else(|e| panic!("not UTF-8: {e}"));
    (code, text(out), text(err))
}

/// The two stderr lines of a usage error: (message, fix), without prefixes.
fn usage(args: &[&str]) -> (String, String) {
    let (code, stdout, stderr) = rdy(args);
    assert_eq!(code, 64, "rdy {args:?}: {stderr}");
    assert!(stdout.is_empty(), "rdy {args:?} wrote to stdout");
    let lines: Vec<&str> = stderr.lines().collect();
    assert_eq!(lines.len(), 2, "want two lines: {stderr:?}");
    let message = lines[0]
        .strip_prefix("error: ")
        .unwrap_or_else(|| panic!("{stderr:?}"));
    let fix = lines[1]
        .strip_prefix("fix: ")
        .unwrap_or_else(|| panic!("{stderr:?}"));
    (message.to_string(), fix.to_string())
}

#[test]
fn a_misspelled_token_flag_prints_its_name_and_not_the_text_after_the_equals_sign() {
    let arg = format!("--tokne={CANARY}");
    let (message, fix) = usage(&["run", "spec.yaml", &arg]);
    assert_eq!(message, "unknown flag --tokne");
    assert_eq!(fix, "see 'rdy run --help'");
}

#[test]
fn a_misspelled_password_flag_does_not_print_the_next_argument() {
    for args in [
        &["spec", "sign", "spec.yaml", "--pasword", CANARY][..],
        &["spec", "keygen", "--pasword", CANARY],
    ] {
        let (code, _, stderr) = rdy(args);
        assert_eq!(code, 64, "{args:?}");
        assert!(stderr.contains("unknown flag --pasword"), "{stderr}");
        assert!(!stderr.contains(CANARY), "{stderr}");
    }
    let arg = format!("--pasword={CANARY}");
    let (code, _, stderr) = rdy(&["spec", "sign", "spec.yaml", &arg]);
    assert_eq!(code, 64);
    assert!(!stderr.contains(CANARY), "{stderr}");
}

#[test]
fn canaries_are_absent_from_stderr_and_from_json_in_every_position() {
    let eq = format!("--tokne={CANARY}");
    let cases: Vec<Vec<&str>> = vec![
        vec!["run", "spec.yaml", &eq],
        vec!["run", &eq, "spec.yaml"],
        vec!["--tokne", CANARY, "run", "spec.yaml"],
        vec!["run", "spec.yaml", "--tokne", CANARY],
        vec!["run", "spec.yaml", CANARY],
        vec!["run", "spec.yaml", "--jobs", CANARY],
        vec!["run", "spec.yaml", "--color", CANARY],
        vec!["--color", CANARY, "version"],
        vec![CANARY],
        vec!["spec", CANARY],
        vec!["help", CANARY],
        vec!["run", "spec.yaml", "--", CANARY],
        vec!["run", "spec.yaml", "--", &eq],
        vec!["run", "spec.yaml", "-x", CANARY],
        vec!["run", "spec.yaml", "--out-dir"],
    ];
    for case in cases {
        for json in [false, true] {
            let mut args = case.clone();
            if json {
                args.push("--json");
            }
            let (code, stdout, stderr) = rdy(&args);
            assert_eq!(code, 64, "{args:?}: {stderr}");
            assert!(!stderr.contains(CANARY), "{args:?}: {stderr}");
            assert!(!stdout.contains(CANARY), "{args:?}: {stdout}");
        }
    }
}

#[test]
fn text_after_two_dashes_is_not_taken_for_a_flag() {
    // After `--` every word is a value, so its text is not echoed even if it looks like a flag.
    let (message, _) = usage(&["run", "spec.yaml", "--", "--tokne=CANARYsecret"]);
    assert!(!message.contains("tokne"), "{message}");
}

#[test]
fn a_flag_name_that_is_not_a_plain_name_is_not_echoed() {
    for name in [
        format!("--{CANARY}{CANARY}{CANARY}"),
        "--rdy_st_abc".to_string(),
        "--a\u{1b}[2J".to_string(),
        "--tok\u{202e}ne".to_string(),
        "--\u{e9}\u{e9}".to_string(),
    ] {
        let (message, fix) = usage(&["run", "spec.yaml", &name]);
        assert_eq!(message, "unknown option or argument", "{name:?}");
        assert_eq!(fix, "see 'rdy run --help'", "{name:?}");
    }
}

#[test]
fn a_short_flag_is_named_but_its_attached_text_is_not() {
    let arg = format!("-x{CANARY}");
    let (message, fix) = usage(&["run", "spec.yaml", &arg]);
    assert_eq!(message, "unknown flag -x");
    assert_eq!(fix, "see 'rdy run --help'");
}

#[test]
fn an_extra_positional_is_not_echoed() {
    let (message, fix) = usage(&["run", "spec.yaml", CANARY]);
    assert_eq!(message, "unknown option or argument");
    assert_eq!(fix, "see 'rdy run --help'");
}

#[test]
fn a_typo_of_a_visible_flag_gets_a_did_you_mean() {
    let (message, fix) = usage(&["run", "spec.yaml", "--out-dri", "reports"]);
    assert_eq!(message, "unknown flag --out-dri");
    assert_eq!(fix, "did you mean --out-dir? See 'rdy run --help'.");

    // The value after `=` is cut here too.
    let arg = format!("--out-dri={CANARY}");
    let (message, fix) = usage(&["run", "spec.yaml", &arg]);
    assert_eq!(message, "unknown flag --out-dri");
    assert_eq!(fix, "did you mean --out-dir? See 'rdy run --help'.");
}

#[test]
fn a_typo_of_a_global_flag_is_suggested_on_a_subcommand() {
    // `--verbose` is global: it is declared on the root and offered on every subcommand.
    let (message, fix) = usage(&["spec", "lint", "spec.yaml", "--verbsoe"]);
    assert_eq!(message, "unknown flag --verbsoe");
    assert_eq!(fix, "did you mean --verbose? See 'rdy spec lint --help'.");
}

#[test]
fn a_flag_typed_before_a_subcommand_is_judged_on_the_command_it_was_typed_on() {
    // `--json` is not a flag of the root, so it is not suggested for a typo placed before `spec`.
    let (message, fix) = usage(&["--jsno", "spec", "lint", "spec.yaml"]);
    assert_eq!(message, "unknown flag --jsno");
    assert_eq!(fix, "see 'rdy --help'");
}

#[test]
fn a_name_that_is_not_a_typo_of_a_real_flag_is_not_echoed() {
    // A typed name can be a secret. Only a typo of a flag rdy has is printed.
    let uuid = "--123e4567-e89b-12d3-a456-426614174000";
    let hex_key = "--9f86d081884c7d659a2feaa0c55ad015";
    for name in [
        "--hunter2",
        "--password-hunter2",
        "--pa55w0rd-hunter2",
        uuid,
        hex_key,
        "--bogus",
        "--x--key",
        "--x--allow-unsigned",
    ] {
        for json in [false, true] {
            let mut args = vec!["run", "spec.yaml", name];
            if json {
                args.push("--json");
            }
            let (code, stdout, stderr) = rdy(&args);
            assert_eq!(code, 64, "{args:?}");
            let shown = format!("{stdout}{stderr}");
            assert!(shown.contains("unknown option or argument"), "{shown}");
            assert!(!shown.contains(&name[2..]), "{name}: {shown}");
            assert!(!shown.contains("--key"), "{name}: {shown}");
            assert!(!shown.contains("--allow-unsigned"), "{name}: {shown}");
        }
    }
}

#[test]
fn a_typo_of_a_hidden_or_other_command_flag_is_named_but_not_suggested() {
    // Known names decide only whether the typed name is printed. They are never offered.
    let (message, fix) = usage(&["run", "spec.yaml", "--unencryptd"]);
    assert_eq!(message, "unknown flag --unencryptd");
    assert_eq!(fix, "see 'rdy run --help'");
    let (message, fix) = usage(&["run", "spec.yaml", "--tokne=x"]);
    assert_eq!(message, "unknown flag --tokne");
    assert_eq!(fix, "see 'rdy run --help'");
}

#[test]
fn near_misses_of_key_and_allow_unsigned_never_name_them() {
    let cases: &[&[&str]] = &[
        &["run", "spec.yaml", "--keey", "acme.pub"],
        &["run", "spec.yaml", "--kye"],
        &["run", "spec.yaml", "--ky"],
        &["run", "spec.yaml", "--ke"],
        &["run", "spec.yaml", "--keyy"],
        &["run", "spec.yaml", "--yes"],
        &["run", "spec.yaml", "--allow-unsgned"],
        &["run", "spec.yaml", "--allow-unsigend"],
        &["run", "spec.yaml", "--alow-unsigned"],
        &["run", "spec.yaml", "--allow-unsignd"],
        // One letter short: the near-miss the M1-030 review asked to pin (carried to M1-044).
        &["run", "spec.yaml", "--allow-unsigne"],
        &["verify", "spec.yaml", "--allow-unsigne"],
        &["verify", "spec.yaml", "--keey"],
        &["verify", "spec.yaml", "--allow-unsgned"],
        &["trust", "add", "acme", "--kye", "acme.pub"],
        &["spec", "sign", "spec.yaml", "--keey", "k"],
    ];
    for args in cases {
        for json in [false, true] {
            let mut args = args.to_vec();
            if json {
                args.push("--json");
            }
            let (code, stdout, stderr) = rdy(&args);
            assert_eq!(code, 64, "{args:?}");
            for text in [&stderr, &stdout] {
                assert!(!text.contains("--key"), "{args:?}: {text}");
                assert!(!text.contains("--allow-unsigned"), "{args:?}: {text}");
            }
            if json {
                let v: Value = serde_json::from_str(&stdout)
                    .unwrap_or_else(|e| panic!("{args:?}: stdout is not JSON: {e}"));
                let fix = v["error"]["fix"].as_str().unwrap_or_default();
                assert!(!fix.contains("--key"), "{args:?}: {fix}");
                assert!(!fix.contains("--allow-unsigned"), "{args:?}: {fix}");
                assert!(fix.starts_with("see 'rdy "), "{args:?}: {fix}");
            } else {
                let fix = stderr.lines().nth(1).unwrap_or_default();
                assert!(fix.starts_with("fix: see 'rdy "), "{args:?}: {fix}");
            }
        }
    }
}

#[test]
fn the_plain_fix_for_a_near_miss_is_the_help_pointer() {
    let (message, fix) = usage(&["run", "spec.yaml", "--keey", "acme-platform.pub"]);
    assert_eq!(message, "unknown flag --keey");
    assert_eq!(fix, "see 'rdy run --help'");
    let (message, fix) = usage(&["run", "spec.yaml", "--yes"]);
    assert_eq!(message, "unknown flag --yes");
    assert_eq!(fix, "see 'rdy run --help'");
}

#[test]
fn a_flag_of_another_command_is_never_suggested() {
    // `--unencrypted` belongs to `spec keygen`. A typo of it on `run` gets no suggestion.
    let (_, fix) = usage(&["run", "spec.yaml", "--unencryptd"]);
    assert_eq!(fix, "see 'rdy run --help'");
}

#[test]
fn a_hidden_flag_is_never_suggested() {
    // The password flag is refused before clap runs and is not a visible flag of any command.
    let (_, fix) = usage(&["run", "spec.yaml", "--passwrd"]);
    assert!(!fix.contains("--password"), "{fix}");
}

#[test]
fn json_carries_the_same_two_lines() {
    let (code, stdout, _) = rdy(&["run", "spec.yaml", "--out-dri", "reports", "--json"]);
    assert_eq!(code, 64);
    let v: Value = serde_json::from_str(&stdout).unwrap_or_else(|e| panic!("{e}: {stdout}"));
    assert_eq!(v["error"]["code"], "usage");
    assert_eq!(v["error"]["message"], "unknown flag --out-dri");
    assert_eq!(
        v["error"]["fix"],
        "did you mean --out-dir? See 'rdy run --help'."
    );
}
