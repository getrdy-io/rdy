//! The generated JSON schemas against the repo's fixtures: the example specs, the samples in the plan,
//! the hostile cases of the two reviews of docs/plan/01-spec-format.md, and the files on disk.
//!
//! The expected outcome of each hostile case is the documented one: what the review asked for after
//! its findings were applied. A case the schema cannot express (a regex that matches the empty
//! string, a number outside the 1s to 60s timeout range) is listed as accepted, with the layer that
//! does check it. Each fixture is checked with a 2020-12 validator that also checks formats.

use std::error::Error;
use std::path::{Path, PathBuf};

use jsonschema::Validator;
use serde_json::{Value, json};

type TestResult<T = ()> = Result<T, Box<dyn Error>>;

fn repo_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../..")
}

/// A file as text with LF line endings, so a Windows checkout reads like a Unix one.
fn read(path: &Path) -> TestResult<String> {
    Ok(std::fs::read_to_string(path)?.replace("\r\n", "\n"))
}

fn schema_file(name: &str) -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("schema")
        .join(name)
}

fn schema(name: &str) -> TestResult<Value> {
    Ok(serde_json::from_str(&read(&schema_file(name))?)?)
}

fn build(schema: &Value) -> TestResult<Validator> {
    Ok(jsonschema::draft202012::options()
        .should_validate_formats(true)
        .build(schema)?)
}

/// A validator for the whole spec.
fn spec_validator() -> TestResult<Validator> {
    build(&schema("spec.v1.schema.json")?)
}

/// A validator for `$defs/<def>` of the spec or the result schema. Only the definitions are kept, so
/// the root keywords of the spec do not apply.
fn def_validator(file: &str, def: &str) -> TestResult<Validator> {
    let whole = schema(file)?;
    build(&json!({
        "$schema": "https://json-schema.org/draft/2020-12/schema",
        "$ref": format!("#/$defs/{def}"),
        "$defs": whole["$defs"],
    }))
}

fn result_validator() -> TestResult<Validator> {
    build(&schema("result.v1.schema.json")?)
}

fn errors(v: &Validator, instance: &Value) -> Vec<String> {
    v.iter_errors(instance)
        .map(|e| format!("{e} at {}", e.instance_path()))
        .collect()
}

fn assert_valid(v: &Validator, instance: &Value, what: &str) {
    let found = errors(v, instance);
    assert!(found.is_empty(), "{what} fails the schema: {found:#?}");
}

fn yaml(text: &str) -> TestResult<Value> {
    Ok(serde_saphyr::from_str::<Value>(text)?)
}

fn example(name: &str) -> TestResult<Value> {
    yaml(&read(&repo_root().join("examples/specs").join(name))?)
}

// ---- the files on disk ---------------------------------------------------------------------------

/// The committed files are what the generator writes. `cargo xtask schema --check` makes the same
/// comparison, so a plain `cargo test` also catches a type or doc comment that changed on its own.
#[test]
fn the_committed_files_are_what_the_types_generate() -> TestResult {
    assert_eq!(
        read(&schema_file("spec.v1.schema.json"))?,
        rdy_spec::schema::spec_schema_json(),
        "spec.v1.schema.json is stale. Run `cargo xtask schema`."
    );
    assert_eq!(
        read(&schema_file("result.v1.schema.json"))?,
        rdy_spec::schema::result_schema_json(),
        "result.v1.schema.json is stale. Run `cargo xtask schema`."
    );
    Ok(())
}

/// Both files build as draft 2020-12 schemas. Building compiles every `pattern`, so a regular
/// expression that ECMA 262 or Rust refuses fails here. The `file:` rule of `bundle.collect` once did.
#[test]
fn both_files_are_valid_2020_12_schemas_with_working_patterns() -> TestResult {
    for name in ["spec.v1.schema.json", "result.v1.schema.json"] {
        let file = schema(name)?;
        assert_eq!(
            file["$schema"], "https://json-schema.org/draft/2020-12/schema",
            "{name}"
        );
        assert!(
            jsonschema::draft202012::meta::validate(&file).is_ok(),
            "{name} is not a valid schema"
        );
        build(&file)?;
    }
    Ok(())
}

// ---- the fixtures in the repo ----------------------------------------------------------------------

#[test]
fn every_file_in_examples_specs_validates() -> TestResult {
    let v = spec_validator()?;
    let dir = repo_root().join("examples/specs");
    let mut seen = 0;
    for entry in std::fs::read_dir(&dir)? {
        let path = entry?.path();
        if path.extension().is_some_and(|e| e == "yaml") {
            let name = path
                .file_name()
                .map_or_else(String::new, |n| n.to_string_lossy().into_owned());
            assert_valid(&v, &yaml(&read(&path)?)?, &name);
            seen += 1;
        }
    }
    assert!(seen >= 5, "found {seen} example specs");
    Ok(())
}

#[test]
fn the_signed_fixture_spec_validates() -> TestResult {
    let v = spec_validator()?;
    let value = yaml(&read(
        &repo_root().join("tests/fixtures/signed/acme-platform.yaml"),
    )?)?;
    assert_valid(&v, &value, "tests/fixtures/signed/acme-platform.yaml");
    Ok(())
}

/// The spec in 01 section 7.1 is the example file, byte for byte.
#[test]
fn section_7_1_is_the_acme_platform_example() -> TestResult {
    let doc = read(&repo_root().join("docs/plan/01-spec-format.md"))?;
    let start = doc.find("\n### 7.1").ok_or("no 7.1")?;
    let block = &doc[start..];
    let open = block.find("```yaml\n").ok_or("no yaml block")? + "```yaml\n".len();
    let body = &block[open..];
    let close = body.find("\n```").ok_or("unclosed yaml block")?;
    let from_doc = format!("{}\n", &body[..close]);
    let from_file = read(&repo_root().join("examples/specs/acme-platform.yaml"))?;
    assert_eq!(from_doc, from_file);
    Ok(())
}

/// The first fenced `json` block after `heading`, up to the next heading of any level.
fn json_after(doc: &str, heading: &str) -> TestResult<Value> {
    let start = doc.find(heading).ok_or_else(|| format!("no {heading}"))? + heading.len();
    let section = &doc[start..];
    let end = section.find("\n#").unwrap_or(section.len());
    let section = &section[..end];
    let open = section.find("```json\n").ok_or("no json block")? + "```json\n".len();
    let body = &section[open..];
    let close = body.find("\n```").ok_or("unclosed json block")?;
    Ok(serde_json::from_str(&body[..close])?)
}

/// Applies the `add` and `replace` operations of a JSON Patch (RFC 6902), which is all B.2 uses.
fn apply_patch(mut doc: Value, patch: &Value) -> TestResult<Value> {
    for op in patch.as_array().ok_or("a patch is an array")? {
        let kind = op["op"].as_str().ok_or("op")?;
        let path = op["path"].as_str().ok_or("path")?;
        let (parent, key) = path.rsplit_once('/').ok_or("path has a parent")?;
        let target = doc.pointer_mut(parent).ok_or("parent exists")?;
        match (kind, target) {
            ("replace" | "add", Value::Object(map)) => {
                map.insert(key.to_owned(), op["value"].clone());
            }
            ("replace", Value::Array(items)) => {
                let slot = items.get_mut(key.parse::<usize>()?).ok_or("index")?;
                *slot = op["value"].clone();
            }
            _ => return Err(format!("unsupported patch operation {kind} at {path}").into()),
        }
    }
    Ok(doc)
}

/// The golden reports of the CLI plan (appendix B) and the objects of C.11 validate against their
/// definitions. B.2 is stored as a patch against B.1.
#[test]
fn the_golden_results_and_command_objects_of_the_cli_plan_validate() -> TestResult {
    let doc = read(&repo_root().join("docs/plan/07-cli-ux.md"))?;
    let report = result_validator()?;
    let b1 = json_after(&doc, "### B.1 READY (C.17)")?;
    assert_valid(&report, &b1, "B.1");
    let b2 = apply_patch(b1, &json_after(&doc, "### B.2 READY with warnings (C.18)")?)?;
    assert_valid(&report, &b2, "B.2");
    assert_valid(
        &report,
        &json_after(&doc, "### B.3 NOT READY (2.7)")?,
        "B.3",
    );

    // C.11: every json block, each against the definition its `kind` names. The Version object
    // has no `kind`, so it is found by its keys.
    let c11 = doc.find("### C.11").ok_or("no C.11")?;
    let end = doc[c11..].find("### C.12").map_or(doc.len(), |i| c11 + i);
    let mut rest = &doc[c11..end];
    let mut checked = Vec::new();
    while let Some(open) = rest.find("```json\n") {
        let body = &rest[open + "```json\n".len()..];
        let close = body.find("\n```").ok_or("unclosed block")?;
        let value: Value = serde_json::from_str(&body[..close])?;
        let def = match value.get("kind").and_then(Value::as_str) {
            Some("Error") => "ErrorOutput",
            Some("Lint") => "LintReport",
            Some("Verification") => "Verification",
            _ if value.get("rdy_spec").is_some() => "Version",
            other => return Err(format!("a C.11 block of kind {other:?}").into()),
        };
        assert_valid(&def_validator("result.v1.schema.json", def)?, &value, def);
        checked.push(def);
        rest = &body[close + 4..];
    }
    for def in ["ErrorOutput", "LintReport", "Verification", "Version"] {
        assert!(checked.contains(&def), "C.11 has no {def} sample");
    }
    Ok(())
}

/// Every golden result file under `tests/fixtures/results/` validates. The directory does not exist
/// yet, so this holds until the first golden is added, and then it checks that one and every later one.
#[test]
fn every_golden_result_file_validates() -> TestResult {
    let dir = repo_root().join("tests/fixtures/results");
    if !dir.is_dir() {
        return Ok(());
    }
    let v = result_validator()?;
    let mut stack = vec![dir];
    while let Some(dir) = stack.pop() {
        for entry in std::fs::read_dir(&dir)? {
            let path = entry?.path();
            if path.is_dir() {
                stack.push(path);
            } else if path.extension().is_some_and(|e| e == "json") {
                let value: Value = serde_json::from_str(&read(&path)?)?;
                assert_valid(&v, &value, &path.display().to_string());
            }
        }
    }
    Ok(())
}

// ---- hostile spec fixtures -----------------------------------------------------------------------

/// A spec with one extra check entry, built on the canonical example.
fn with_check(entry: Value) -> TestResult<Value> {
    let mut spec = example("acme-platform.yaml")?;
    spec["checks"]
        .as_array_mut()
        .ok_or("checks is an array")?
        .push(entry);
    Ok(spec)
}

/// Edits the canonical example in place.
fn edited(edit: impl FnOnce(&mut Value)) -> TestResult<Value> {
    let mut spec = example("acme-platform.yaml")?;
    edit(&mut spec);
    Ok(spec)
}

/// The cases of the security review (hostile cases, MF and SF items) and the CLI review (S4, S5 and the
/// example edits), each with the documented answer.
#[test]
fn hostile_spec_fixtures_give_the_documented_answer() -> TestResult {
    let v = spec_validator()?;
    let accepted_to_start = example("acme-platform.yaml")?;
    assert_valid(&v, &accepted_to_start, "the canonical example");

    let mut cases: Vec<(&str, Value, bool)> = vec![
        // Rejected: nothing a spec says can turn a feature on that the CLI does not offer.
        (
            "unknown top-level key upload",
            edited(|s| s["upload"] = json!({}))?,
            false,
        ),
        (
            "metadata.allow_unsigned",
            edited(|s| s["metadata"]["allow_unsigned"] = json!(true))?,
            false,
        ),
        (
            "bundle.upload",
            edited(|s| s["bundle"]["upload"] = json!(true))?,
            false,
        ),
        (
            "a typo in a parameter (mn for min)",
            with_check(json!({"id": "host.memory", "mn": "1Gi"}))?,
            false,
        ),
        (
            "a check with no id",
            with_check(json!({"min": "1Gi"}))?,
            false,
        ),
        (
            "a check entry that is not an object",
            with_check(json!("host.cpu"))?,
            false,
        ),
        (
            "a dotted product name",
            edited(|s| s["metadata"]["product"] = json!("acme.platform"))?,
            false,
        ),
        (
            "the removed needs alias",
            with_check(json!({"id": "k8s.storageclass", "needs": ["ReadWriteOnce"]}))?,
            false,
        ),
        (
            "net.egress via_proxy never",
            with_check(
                json!({"id": "net.egress", "endpoints": ["a.example:443"], "via_proxy": "never"}),
            )?,
            false,
        ),
        (
            "k8s.rbac can_i",
            with_check(json!({"id": "k8s.rbac", "can_i": ["get pods"]}))?,
            false,
        ),
        // Rejected after the review's fixes: a URL with credentials, a loose expiry, a path climb.
        (
            "a URL target with user info",
            with_check(
                json!({"id": "net.egress", "endpoints": ["https://user:pw@registry.acme.example/"]}),
            )?,
            false,
        ),
        (
            "expires: tomorrow",
            edited(|s| s["metadata"]["expires"] = json!("tomorrow"))?,
            false,
        ),
        (
            "collect file:../../etc/shadow",
            edited(|s| s["bundle"]["collect"] = json!(["file:../../etc/shadow"]))?,
            false,
        ),
        (
            "collect file: with a parent part in the middle",
            edited(|s| s["bundle"]["collect"] = json!(["file:/var/log/../shadow"]))?,
            false,
        ),
        (
            "collect file: with a NUL byte",
            edited(|s| s["bundle"]["collect"] = json!(["file:/var/log/a\u{0}b"]))?,
            false,
        ),
        (
            "collect k8s: other than events",
            edited(|s| s["bundle"]["collect"] = json!(["k8s:secrets"]))?,
            false,
        ),
        // A threshold the check cannot do without (CLI review S5).
        (
            "host.memory with no min",
            with_check(json!({"id": "host.memory"}))?,
            false,
        ),
        (
            "host.cpu with no threshold",
            with_check(json!({"id": "host.cpu"}))?,
            false,
        ),
        // Accepted: unknown ids are skipped by the run, not refused (ADR 0005, 0007).
        (
            "custom.exec with argv",
            with_check(json!({"id": "custom.exec", "argv": ["/bin/true"]}))?,
            true,
        ),
        (
            "an unreserved family",
            with_check(json!({"id": "upload.now"}))?,
            true,
        ),
        // Accepted here, refused by another layer.
        (
            "timeout 999d (the 1s to 60s range is checked by spec lint and at load)",
            with_check(json!({"id": "host.cpu", "min": 4, "timeout": "999d"}))?,
            true,
        ),
        (
            "timeout 90s (same)",
            with_check(json!({"id": "host.cpu", "min": 4, "timeout": "90s"}))?,
            true,
        ),
        (
            "a redact pattern that matches the empty string (checked when the pattern is compiled)",
            edited(|s| s["bundle"]["redact_patterns"] = json!([{"name": "empty", "regex": "x*"}]))?,
            true,
        ),
        (
            "a good file: collector",
            edited(|s| {
                s["bundle"]["collect"] =
                    json!(["file:/etc/acme/*.yaml", "journal:7d", "k8s:events"])
            })?,
            true,
        ),
    ];
    cases.push((
        "257 checks, one more than the limit",
        edited(|s| {
            s["checks"] = Value::Array((0..257).map(|_| json!({"id": "upload.now"})).collect());
        })?,
        false,
    ));
    for (what, spec, want) in cases {
        let found = errors(&v, &spec);
        assert_eq!(found.is_empty(), want, "{what}: {found:#?}");
    }
    Ok(())
}

// ---- hostile result fixtures ---------------------------------------------------------------------

fn report(name: &str) -> TestResult<Value> {
    let doc = read(&repo_root().join("docs/plan/01-spec-format.md"))?;
    json_after(&doc, name)
}

#[test]
fn hostile_result_fixtures_give_the_documented_answer() -> TestResult {
    let v = result_validator()?;
    let base = report("### 7.2 ")?;
    assert_valid(&v, &base, "7.2");

    let edited = |edit: &dyn Fn(&mut Value)| {
        let mut doc = base.clone();
        edit(&mut doc);
        doc
    };
    let cases: Vec<(&str, Value, bool)> = vec![
        // Rejected: the size caps of the security review (SEC-63).
        (
            "a 5 MiB message",
            edited(&|d| d["checks"][0]["message"] = json!("a".repeat(5 * 1024 * 1024))),
            false,
        ),
        (
            "a message of 1025 characters",
            edited(&|d| d["checks"][0]["message"] = json!("a".repeat(1025))),
            false,
        ),
        (
            "a message of 1024 characters",
            edited(&|d| d["checks"][0]["message"] = json!("a".repeat(1024))),
            true,
        ),
        (
            "a hostname over 4096 characters",
            edited(&|d| d["host"]["hostname"] = json!("h".repeat(4097))),
            false,
        ),
        (
            "5001 actions",
            edited(&|d| {
                let one = d["actions"][0].clone();
                d["actions"] = Value::Array(vec![one; 5001]);
            }),
            false,
        ),
        (
            "21 notes",
            edited(&|d| d["checks"][0]["notes"] = json!(vec!["n"; 21])),
            false,
        ),
        // Rejected: a document that contradicts itself.
        (
            "unsigned with allow_unsigned false",
            edited(&|d| d["signature"] = json!({"state": "unsigned"})),
            false,
        ),
        (
            "ready with two block checks",
            edited(&|d| {
                d["verdict"] = json!("ready");
                d["exit_code"] = json!(0);
            }),
            false,
        ),
        (
            "an exit code that is not the verdict's",
            edited(&|d| d["exit_code"] = json!(1)),
            false,
        ),
        (
            "exit code 70 (there is then no report)",
            edited(&|d| d["exit_code"] = json!(70)),
            false,
        ),
        (
            "a verified signature with no key fingerprint",
            edited(&|d| {
                if let Some(sig) = d["signature"].as_object_mut() {
                    sig.remove("key_fingerprint");
                }
            }),
            false,
        ),
        (
            "a skipped check with no skip_kind",
            edited(&|d| {
                if let Some(check) = d["checks"][6].as_object_mut() {
                    check.remove("skip_kind");
                }
            }),
            false,
        ),
        (
            "a closed value outside its set (verdict)",
            edited(&|d| d["verdict"] = json!("mostly_ready")),
            false,
        ),
        (
            "api_version rdy/v2",
            edited(&|d| d["api_version"] = json!("rdy/v2")),
            false,
        ),
        // Accepted: a newer producer.
        (
            "an unknown top-level field",
            edited(&|d| d["added_later"] = json!({"x": [1, 2]})),
            true,
        ),
        (
            "an unknown status",
            edited(&|d| d["checks"][0]["status"] = json!("quarantined")),
            true,
        ),
        (
            "an unknown bucket",
            edited(&|d| d["checks"][0]["bucket"] = json!("frozen")),
            true,
        ),
        (
            "an open value that is not snake_case",
            edited(&|d| d["checks"][0]["status"] = json!("Quarantined")),
            false,
        ),
    ];
    for (what, doc, want) in cases {
        let found = errors(&v, &doc);
        assert_eq!(found.is_empty(), want, "{what}: {found:#?}");
    }
    Ok(())
}
