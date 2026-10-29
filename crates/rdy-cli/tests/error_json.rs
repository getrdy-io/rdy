//! `--json` failures print an ErrorOutput with a stable code (M1-021, 07 sections 4.1 and 9).
//!
//! The binary is run for the cases it can reach today (usage errors and commands a later ticket
//! builds). The other codes are rendered through the library and checked against the same schema.

use std::path::Path;
use std::process::{Command, Output};

use jsonschema::Validator;
use rdy_cli::error::{CliError, ErrorCode, IoReason, ReportStep};
use rdy_spec::{Location, SpecError};
use serde_json::Value;

mod common;

fn rdy(args: &[&str]) -> Output {
    common::quiet(
        Command::new(env!("CARGO_BIN_EXE_rdy"))
            .args(args)
            .env_remove("RDY_PROGRESS")
            .output()
            .unwrap_or_else(|e| panic!("the rdy binary did not start: {e}")),
    )
}

fn text(bytes: &[u8]) -> &str {
    std::str::from_utf8(bytes).unwrap_or_else(|e| panic!("output is not UTF-8: {e}"))
}

fn error_output_validator() -> Validator {
    let path =
        Path::new(env!("CARGO_MANIFEST_DIR")).join("../rdy-spec/schema/result.v1.schema.json");
    let source = std::fs::read_to_string(&path)
        .unwrap_or_else(|e| panic!("cannot read {}: {e}", path.display()));
    let mut schema: Value =
        serde_json::from_str(&source).unwrap_or_else(|e| panic!("schema is not JSON: {e}"));
    schema["$ref"] = Value::String("#/$defs/ErrorOutput".into());
    jsonschema::draft202012::options()
        .should_validate_formats(true)
        .build(&schema)
        .unwrap_or_else(|e| panic!("schema does not build: {e}"))
}

fn assert_valid(v: &Validator, doc: &Value, what: &str) {
    let errors: Vec<String> = v
        .iter_errors(doc)
        .map(|e| format!("{e} at {}", e.instance_path()))
        .collect();
    assert!(
        errors.is_empty(),
        "{what} fails the schema: {errors:#?}\n{doc}"
    );
}

fn parse(bytes: &[u8]) -> Value {
    serde_json::from_str(text(bytes)).unwrap_or_else(|e| panic!("stdout is not JSON: {e}"))
}

#[test]
fn a_usage_error_with_json_prints_one_error_object_with_code_usage() {
    let v = error_output_validator();
    for args in [
        &["run", "spec.yaml", "--keey", "x", "--json"][..],
        &["--json", "--bogus"],
        &["run", "--json"],
        &["spec", "lint", "--json", "--tokne=CANARY-7f3a"],
        &["help", "nope", "--json"],
    ] {
        let out = rdy(args);
        assert_eq!(out.status.code(), Some(64), "rdy {args:?}: {out:?}");
        let doc = parse(&out.stdout);
        assert_valid(&v, &doc, &format!("rdy {args:?}"));
        assert_eq!(doc["error"]["code"], "usage", "rdy {args:?}");
        assert_eq!(doc["kind"], "Error");
        assert_eq!(doc["verdict"], Value::Null);
        assert_eq!(doc["complete"], false);
        // The same text goes to stderr, as the two lines (07 section 4.1).
        let err = text(&out.stderr);
        let want = format!(
            "error: {}\nfix: {}\n",
            doc["error"]["message"].as_str().unwrap_or_default(),
            doc["error"]["fix"].as_str().unwrap_or_default()
        );
        assert_eq!(err, want, "rdy {args:?}");
        for stream in [text(&out.stdout), err] {
            assert!(!stream.contains("CANARY"), "{stream}");
            assert!(!stream.contains("--allow-unsigned"), "{stream}");
            assert!(!stream.contains("--key"), "{stream}");
        }
    }
}

#[test]
fn a_usage_error_without_json_prints_nothing_on_stdout() {
    let out = rdy(&["run", "spec.yaml", "--keey", "x"]);
    assert_eq!(out.status.code(), Some(64));
    assert!(out.stdout.is_empty());
    assert_eq!(text(&out.stderr).lines().count(), 2);
}

#[test]
fn a_command_that_is_not_built_yet_prints_an_internal_error_object() {
    let v = error_output_validator();
    let out = rdy(&["run", "spec.yaml", "--json"]);
    assert_eq!(out.status.code(), Some(70));
    let doc = parse(&out.stdout);
    assert_valid(&v, &doc, "rdy run --json");
    assert_eq!(doc["error"]["code"], "internal");
    assert!(
        doc["error"]["message"]
            .as_str()
            .unwrap_or_default()
            .contains("not yet implemented")
    );
}

#[test]
fn help_and_version_with_json_still_exit_0_on_stdout() {
    for args in [&["--help", "--json"][..], &["-V", "--json"]] {
        let out = rdy(args);
        assert_eq!(out.status.code(), Some(0), "rdy {args:?}");
        assert!(out.stderr.is_empty(), "rdy {args:?}");
        assert!(!out.stdout.is_empty(), "rdy {args:?}");
    }
}

#[test]
fn a_password_on_argv_with_json_is_a_usage_object_that_never_echoes_it() {
    let v = error_output_validator();
    let out = rdy(&[
        "spec",
        "sign",
        "s.yaml",
        "--secret-key",
        "k.key",
        "--password=CANARY-7f3a",
        "--json",
    ]);
    assert_eq!(out.status.code(), Some(64));
    let doc = parse(&out.stdout);
    assert_valid(&v, &doc, "password refusal");
    assert_eq!(doc["error"]["code"], "usage");
    assert!(!text(&out.stdout).contains("CANARY"));
    assert!(!text(&out.stderr).contains("CANARY"));
}

/// Every code, rendered through the library, validates against the schema and keeps its exit code.
#[test]
fn every_kind_of_error_object_validates_against_the_schema() {
    let v = error_output_validator();
    let io_missing = std::io::Error::from(std::io::ErrorKind::NotFound);
    let located = SpecError::Located {
        at: Location::new(14, 11),
        error: Box::new(SpecError::UnquotedDecimal {
            key: Some("min".into()),
            text: "1.3".into(),
        }),
    };
    let errors = [
        (
            CliError::usage("unknown flag --keey", "see 'rdy run --help'"),
            64,
        ),
        (CliError::spec_unreadable("a.yaml", &io_missing), 64),
        (CliError::spec("a.yaml", located), 64),
        (
            CliError::spec("a.yaml", SpecError::BadApiVersion { found: None }),
            64,
        ),
        (
            CliError::ReportWrite {
                step: ReportStep::CreateFolder,
                path: "/usr/share/rdy-report-x".into(),
                reason: IoReason::PermissionDenied.into(),
            },
            70,
        ),
        (CliError::Interrupted, 70),
        (CliError::bug(), 70),
    ];
    let mut seen = Vec::new();
    for (error, exit) in errors {
        let rendered = error.render();
        assert_eq!(i32::from(rendered.exit_code()), exit, "{error:?}");
        let doc: Value =
            serde_json::from_str(&rendered.json()).unwrap_or_else(|e| panic!("not JSON: {e}"));
        assert_valid(&v, &doc, &format!("{error:?}"));
        assert_eq!(doc["error"]["code"], rendered.code.as_str());
        seen.push(rendered.code);
    }
    // The positions only appear for spec errors, and as numbers from 1.
    let doc: Value = serde_json::from_str(
        &CliError::spec(
            "acme-platform.yaml",
            SpecError::Located {
                at: Location::new(14, 11),
                error: Box::new(SpecError::Anchor),
            },
        )
        .render()
        .json(),
    )
    .unwrap_or_default();
    assert_eq!(doc["error"]["file"], "acme-platform.yaml");
    assert_eq!(doc["error"]["line"], 14);
    assert_eq!(doc["error"]["column"], 11);
    // The codes seen here are all in the closed list.
    for code in seen {
        assert!(ErrorCode::ALL.contains(&code));
    }
}

#[test]
fn the_schema_description_lists_exactly_the_codes_of_the_error_enum() {
    let path =
        Path::new(env!("CARGO_MANIFEST_DIR")).join("../rdy-spec/schema/result.v1.schema.json");
    let schema: Value = serde_json::from_str(
        &std::fs::read_to_string(&path).unwrap_or_else(|e| panic!("{}: {e}", path.display())),
    )
    .unwrap_or_else(|e| panic!("schema is not JSON: {e}"));
    let description =
        schema["$defs"]["ErrorOutput"]["properties"]["error"]["properties"]["code"]["description"]
            .as_str()
            .unwrap_or_default();
    for code in ErrorCode::ALL {
        assert!(
            description.contains(code.as_str()),
            "the schema does not list {code}"
        );
    }
}
