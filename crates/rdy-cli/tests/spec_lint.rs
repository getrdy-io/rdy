//! `rdy spec lint` (M1-031, 07 section C.8, 01 section 2.5).
//!
//! The tests run the library entry point with capture buffers, on the example specs and on small files
//! written to a temporary folder. `--json` output is validated against `$defs/LintReport` of the result
//! schema.

use std::path::{Path, PathBuf};

use jsonschema::Validator;
use rdy_cli::run;
use serde_json::Value;

struct Ran {
    code: u8,
    stdout: String,
    stderr: String,
}

fn rdy(args: &[&str]) -> Ran {
    let mut out = Vec::new();
    let mut err = Vec::new();
    let argv = std::iter::once("rdy").chain(args.iter().copied());
    let code = run(argv, &mut out, &mut err);
    let text = |b: Vec<u8>| String::from_utf8(b).unwrap_or_else(|e| panic!("not UTF-8: {e}"));
    Ran {
        code,
        stdout: text(out),
        stderr: text(err),
    }
}

fn root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../..")
}

fn example(name: &str) -> String {
    root()
        .join("examples/specs")
        .join(name)
        .to_string_lossy()
        .into_owned()
}

fn validator(def: &str) -> Validator {
    let path = root().join("crates/rdy-spec/schema/result.v1.schema.json");
    let source = std::fs::read_to_string(&path)
        .unwrap_or_else(|e| panic!("cannot read {}: {e}", path.display()));
    let mut schema: Value =
        serde_json::from_str(&source).unwrap_or_else(|e| panic!("schema is not JSON: {e}"));
    schema["$ref"] = Value::String(format!("#/$defs/{def}"));
    jsonschema::draft202012::options()
        .should_validate_formats(true)
        .build(&schema)
        .unwrap_or_else(|e| panic!("schema does not build: {e}"))
}

fn assert_valid(v: &Validator, doc: &Value) {
    let errors: Vec<String> = v
        .iter_errors(doc)
        .map(|e| format!("{e} at {}", e.instance_path()))
        .collect();
    assert!(errors.is_empty(), "fails the schema: {errors:#?}\n{doc}");
}

fn json(ran: &Ran) -> Value {
    serde_json::from_str(&ran.stdout).unwrap_or_else(|e| panic!("stdout is not JSON: {e}"))
}

const HEAD: &str = "apiVersion: rdy/v1\nkind: Readiness\nmetadata:\n  product: acme\nchecks:\n";

/// Writes a spec to a temporary folder. The folder lives as long as the returned guard.
fn spec_file(body: &str) -> (tempfile::TempDir, String) {
    let dir = tempfile::tempdir().unwrap_or_else(|e| panic!("no temp dir: {e}"));
    let path = dir.path().join("acme-typo.yaml");
    std::fs::write(&path, body).unwrap_or_else(|e| panic!("cannot write: {e}"));
    let name = path.to_string_lossy().into_owned();
    (dir, name)
}

#[test]
fn acme_platform_exits_1_with_two_not_in_build_warnings() {
    let name = example("acme-platform.yaml");
    let ran = rdy(&["spec", "lint", &name]);
    assert_eq!(ran.code, 1, "{}", ran.stderr);
    assert!(ran.stdout.is_empty(), "text goes to stderr");
    let warnings: Vec<&str> = ran
        .stderr
        .lines()
        .filter(|l| l.contains(": warning: "))
        .collect();
    assert_eq!(warnings.len(), 2, "{}", ran.stderr);
    // The positions and words of 07 section C.8.
    assert!(
        warnings[0]
            .ends_with(":45:9: warning: gpu.cuda: this version of rdy has no gpu checks yet"),
        "{}",
        warnings[0]
    );
    assert!(
        warnings[1].ends_with(":50:9: warning: aws.iam: this version of rdy has no aws checks yet"),
        "{}",
        warnings[1]
    );
    assert!(
        ran.stderr.trim_end().ends_with(": 0 errors, 2 warnings"),
        "{}",
        ran.stderr
    );
}

#[test]
fn acme_platform_with_json_prints_a_lint_report_that_validates() {
    let name = example("acme-platform.yaml");
    let ran = rdy(&["spec", "lint", &name, "--json"]);
    assert_eq!(ran.code, 1);
    let doc = json(&ran);
    assert_valid(&validator("LintReport"), &doc);
    assert_eq!(doc["kind"], "Lint");
    assert_eq!(doc["errors"], 0);
    assert_eq!(doc["warnings"], 2);
    let findings = doc["findings"].as_array().map_or(&[][..], Vec::as_slice);
    assert_eq!(findings.len(), 2);
    assert_eq!(findings[0]["code"], "not_in_build");
    assert_eq!(findings[0]["key"], "gpu.cuda");
    assert_eq!(findings[0]["line"], 45);
    assert_eq!(findings[0]["column"], 9);
    assert_eq!(findings[1]["key"], "aws.iam");
    // The text report is still on stderr (07 section 1).
    assert!(ran.stderr.contains(": warning: gpu.cuda"), "{}", ran.stderr);
    assert!(ran.stdout.ends_with("}\n"));
}

#[test]
fn acme_quickstart_exits_0_and_names_only_checks_this_build_has() {
    let name = example("acme-quickstart.yaml");
    let ran = rdy(&["spec", "lint", &name]);
    assert_eq!(ran.code, 0, "{}", ran.stderr);
    assert!(ran.stderr.trim_end().ends_with(": 0 errors, 0 warnings"));
    let ran = rdy(&["spec", "lint", &name, "--json"]);
    let doc = json(&ran);
    assert_valid(&validator("LintReport"), &doc);
    assert_eq!(doc["findings"], Value::Array(Vec::new()));
}

#[test]
fn every_example_exits_0_or_1() {
    for name in [
        "acme-platform.yaml",
        "acme-quickstart.yaml",
        "acme-k8s-only.yaml",
        "acme-airgap-host.yaml",
        "acme-inference-gpu.yaml",
    ] {
        let path = example(name);
        let ran = rdy(&["spec", "lint", &path, "--json"]);
        assert!(ran.code <= 1, "{name}: exit {}: {}", ran.code, ran.stderr);
        let doc = json(&ran);
        assert_valid(&validator("LintReport"), &doc);
        assert_eq!(doc["errors"], 0, "{name}: {}", ran.stderr);
    }
}

#[test]
fn a_misspelled_field_exits_2_with_a_did_you_mean_and_its_line() {
    let (_dir, name) = spec_file(&format!("{HEAD}  - id: host.memory\n    mn: 32Gi\n"));
    let ran = rdy(&["spec", "lint", &name]);
    assert_eq!(ran.code, 2, "{}", ran.stderr);
    assert!(
        ran.stderr
            .contains(":7:5: error: unknown field 'mn' in host.memory\n"),
        "{}",
        ran.stderr
    );
    assert!(
        ran.stderr
            .contains("\n  fix: check the spelling (did you mean 'min'?)\n"),
        "{}",
        ran.stderr
    );
    assert!(ran.stderr.trim_end().ends_with(": 1 error, 0 warnings"));

    let ran = rdy(&["spec", "lint", &name, "--json"]);
    assert_eq!(ran.code, 2);
    let doc = json(&ran);
    assert_valid(&validator("LintReport"), &doc);
    assert_eq!(doc["errors"], 1);
    assert_eq!(doc["findings"][0]["code"], "unsupported_field");
    assert_eq!(doc["findings"][0]["line"], 7);
    assert_eq!(doc["findings"][0]["column"], 5);
}

#[test]
fn an_unknown_top_level_key_exits_2_as_a_finding_with_a_did_you_mean() {
    let (_dir, name) = spec_file(
        "apiVersion: rdy/v1\nkind: Readiness\nmetdata:\n  product: acme\nchecks:\n  - id: host.cpu\n    min: 4\n",
    );
    let ran = rdy(&["spec", "lint", &name, "--json"]);
    assert_eq!(ran.code, 2, "{}", ran.stderr);
    let doc = json(&ran);
    assert_valid(&validator("LintReport"), &doc);
    let f = &doc["findings"][0];
    assert_eq!(f["code"], "unknown_key");
    assert_eq!(
        (f["line"].as_u64(), f["column"].as_u64()),
        (Some(3), Some(1))
    );
    assert_eq!(f["key"], Value::Null);
    assert!(
        f["fix"]
            .as_str()
            .unwrap_or_default()
            .contains("did you mean 'metadata'?"),
        "{f}"
    );
}

#[test]
fn a_regex_that_does_not_compile_exits_2() {
    let (_dir, name) = spec_file(&format!(
        "{HEAD}  - id: net.tls_intercept\n    expected_issuer: \"(abc\"\n"
    ));
    let ran = rdy(&["spec", "lint", &name]);
    assert_eq!(ran.code, 2, "{}", ran.stderr);
    assert!(ran.stderr.contains("unclosed group"), "{}", ran.stderr);
    assert!(ran.stderr.contains(":7:22: error:"), "{}", ran.stderr);
}

#[test]
fn a_missing_file_exits_64_with_the_two_lines() {
    let ran = rdy(&["spec", "lint", "no-such-spec.yaml"]);
    assert_eq!(ran.code, 64);
    assert!(ran.stdout.is_empty());
    assert_eq!(
        ran.stderr,
        "error: cannot read no-such-spec.yaml: no such file\nfix: check the file name and the folder you are in\n"
    );
    let ran = rdy(&["spec", "lint", "no-such-spec.yaml", "--json"]);
    assert_eq!(ran.code, 64);
    assert_valid(&validator("ErrorOutput"), &json(&ran));
    assert_eq!(json(&ran)["error"]["code"], "spec_unreadable");
}

#[test]
fn a_folder_is_not_a_spec_file() {
    let dir = tempfile::tempdir().unwrap_or_else(|e| panic!("no temp dir: {e}"));
    let name = dir.path().to_string_lossy().into_owned();
    let ran = rdy(&["spec", "lint", &name]);
    assert_eq!(ran.code, 64, "{}", ran.stderr);
    assert!(ran.stderr.contains("not a regular file"), "{}", ran.stderr);
}

#[test]
fn a_file_over_the_size_limit_is_a_finding_and_is_not_read_in_full() {
    let (_dir, name) = spec_file(&"#".repeat(1024 * 1024 + 10));
    let ran = rdy(&["spec", "lint", &name, "--json"]);
    assert_eq!(ran.code, 2);
    let doc = json(&ran);
    assert_valid(&validator("LintReport"), &doc);
    assert_eq!(doc["findings"][0]["code"], "structure");
    assert_eq!(doc["findings"][0]["line"], Value::Null);
}

#[test]
fn hostile_text_in_the_file_never_reaches_the_terminal_raw() {
    // An escape sequence in a key and in a check id.
    let (_dir, name) = spec_file(&format!(
        "{HEAD}  - id: host.memory\n    \"m\\u001b[2Jn\": 32Gi\n  - id: \"host.\\u001b[31mx\"\n"
    ));
    let ran = rdy(&["spec", "lint", &name]);
    assert_eq!(ran.code, 2, "{}", ran.stderr);
    assert!(
        !ran.stderr.chars().any(|c| c.is_control() && c != '\n'),
        "{:?}",
        ran.stderr
    );
}

#[test]
fn no_signature_is_needed_and_none_is_read() {
    // The same file linted with and without a `.minisig` next to it gives the same report.
    let (dir, name) = spec_file(&format!("{HEAD}  - id: host.cpu\n    min: 4\n"));
    let plain = rdy(&["spec", "lint", &name, "--json"]);
    std::fs::write(format!("{name}.minisig"), "not a signature")
        .unwrap_or_else(|e| panic!("cannot write: {e}"));
    let with_sig = rdy(&["spec", "lint", &name, "--json"]);
    assert_eq!(plain.code, 0);
    assert_eq!(plain.stdout, with_sig.stdout);
    drop(dir);
}
