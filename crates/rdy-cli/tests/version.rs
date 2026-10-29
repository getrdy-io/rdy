//! Runs the built `rdy` binary and checks the version line (ADR 0011, 07 section 4.3).

use std::path::Path;
use std::process::{Command, Output};

fn rdy(args: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_rdy"))
        .args(args)
        .output()
        .unwrap_or_else(|e| panic!("the rdy binary did not start: {e}"))
}

/// The 7-character commit of `HEAD` when this is a git checkout of the workspace, so the build had
/// a commit to embed. `None` for a packaged tree or a checkout that is not this workspace.
fn expected_commit() -> Option<String> {
    let dir = Path::new(env!("CARGO_MANIFEST_DIR"));
    if dir.join(".cargo_vcs_info.json").exists() {
        return None;
    }
    let git = |args: &[&str]| {
        let out = Command::new("git")
            .args(args)
            .current_dir(dir)
            .output()
            .ok()?;
        let text = String::from_utf8(out.stdout).ok()?;
        out.status.success().then(|| text.trim().to_string())
    };
    let top = Path::new(&git(&["rev-parse", "--show-toplevel"])?)
        .canonicalize()
        .ok()?;
    if top != dir.join("../..").canonicalize().ok()? {
        return None;
    }
    let full = git(&["rev-parse", "HEAD"])?;
    (full.len() >= 7).then(|| full[..7].to_string())
}

fn is_date(s: &str) -> bool {
    let b = s.as_bytes();
    b.len() == 10
        && b.iter().enumerate().all(|(i, c)| {
            if i == 4 || i == 7 {
                *c == b'-'
            } else {
                c.is_ascii_digit()
            }
        })
}

/// The line is `rdy <version>` and, when built from git, `rdy <version> (<commit7> <date>)`.
fn assert_version_line(line: &str) {
    let version = env!("CARGO_PKG_VERSION");
    let rest = line
        .strip_prefix("rdy ")
        .unwrap_or_else(|| panic!("line does not start with `rdy `: {line:?}"));
    let rest = rest
        .strip_prefix(version)
        .unwrap_or_else(|| panic!("line does not carry {version}: {line:?}"));
    let want = expected_commit();
    if rest.is_empty() {
        assert!(
            want.is_none(),
            "a git build must embed commit and date: {line:?}"
        );
        return;
    }
    let inner = rest
        .strip_prefix(" (")
        .and_then(|r| r.strip_suffix(')'))
        .unwrap_or_else(|| panic!("bad suffix after the version: {line:?}"));
    let (commit, date) = match inner.split_once(' ') {
        Some((commit, date)) => (commit, Some(date)),
        None => (inner, None),
    };
    assert!(
        commit.len() == 7 && commit.bytes().all(|c| c.is_ascii_hexdigit()),
        "commit is not 7 hex digits: {line:?}"
    );
    if let Some(want) = want {
        assert_eq!(commit, want, "commit is not HEAD: {line:?}");
        assert!(date.is_some(), "a git build must embed the date: {line:?}");
    }
    if let Some(date) = date {
        assert!(is_date(date), "date is not YYYY-MM-DD: {line:?}");
    }
}

fn assert_prints_version_line(args: &[&str]) {
    let out = rdy(args);
    assert!(out.status.success(), "rdy {args:?} failed: {out:?}");
    assert!(
        out.stderr.is_empty(),
        "rdy {args:?} wrote to stderr: {out:?}"
    );
    let stdout =
        String::from_utf8(out.stdout).unwrap_or_else(|e| panic!("stdout is not UTF-8: {e}"));
    let line = stdout
        .strip_suffix('\n')
        .unwrap_or_else(|| panic!("stdout does not end in a newline: {stdout:?}"));
    assert!(!line.contains('\n'), "want exactly one line: {stdout:?}");
    assert_version_line(line);
}

#[test]
fn version_command_prints_the_line() {
    assert_prints_version_line(&["version"]);
}

#[test]
fn long_version_flag_prints_the_line() {
    assert_prints_version_line(&["--version"]);
}

#[test]
fn short_version_flag_prints_the_line() {
    assert_prints_version_line(&["-V"]);
}

#[test]
fn flag_and_command_print_the_same_bytes() {
    assert_eq!(rdy(&["version"]).stdout, rdy(&["--version"]).stdout);
}

// ---- `rdy version --json` (07 sections 4.3 and C.11) -------------------------------------------

/// The keys of the top-level object of a JSON text, in the order they are written.
fn keys_in_order(json: &str) -> Vec<String> {
    struct Keys(Vec<String>);

    impl<'de> serde::Deserialize<'de> for Keys {
        fn deserialize<D: serde::Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
            struct Visit;
            impl<'de> serde::de::Visitor<'de> for Visit {
                type Value = Keys;
                fn expecting(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                    f.write_str("a JSON object")
                }
                fn visit_map<A: serde::de::MapAccess<'de>>(
                    self,
                    mut map: A,
                ) -> Result<Keys, A::Error> {
                    let mut keys = Vec::new();
                    while let Some((key, _)) = map.next_entry::<String, serde::de::IgnoredAny>()? {
                        keys.push(key);
                    }
                    Ok(Keys(keys))
                }
            }
            d.deserialize_map(Visit)
        }
    }

    match serde_json::from_str::<Keys>(json) {
        Ok(keys) => keys.0,
        Err(e) => panic!("not a JSON object: {e}"),
    }
}

/// The JSON block that follows the line "`rdy version --json`:" in appendix C.11 of the CLI plan.
fn c11_sample() -> String {
    let path = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../docs/plan/07-cli-ux.md");
    let doc = std::fs::read_to_string(&path)
        .unwrap_or_else(|e| panic!("cannot read {}: {e}", path.display()))
        .replace("\r\n", "\n");
    let after = doc
        .split("`rdy version --json`:\n\n```json\n")
        .nth(1)
        .unwrap_or_else(|| panic!("C.11 has no version sample"));
    match after.split_once("\n```") {
        Some((body, _)) => body.to_owned(),
        None => panic!("the version sample is not closed"),
    }
}

fn version_definition_validator() -> jsonschema::Validator {
    let path =
        Path::new(env!("CARGO_MANIFEST_DIR")).join("../rdy-spec/schema/result.v1.schema.json");
    let source = std::fs::read_to_string(&path)
        .unwrap_or_else(|e| panic!("cannot read {}: {e}", path.display()));
    let mut schema: serde_json::Value =
        serde_json::from_str(&source).unwrap_or_else(|e| panic!("schema is not JSON: {e}"));
    schema["$ref"] = serde_json::Value::String("#/$defs/Version".into());
    jsonschema::draft202012::options()
        .should_validate_formats(true)
        .build(&schema)
        .unwrap_or_else(|e| panic!("schema does not build: {e}"))
}

#[test]
fn version_json_has_the_fields_of_c11_in_the_same_order() {
    let out = rdy(&["version", "--json"]);
    assert!(out.status.success(), "{out:?}");
    assert!(out.stderr.is_empty(), "{out:?}");
    let stdout =
        String::from_utf8(out.stdout).unwrap_or_else(|e| panic!("stdout is not UTF-8: {e}"));
    assert!(stdout.ends_with("}\n"), "{stdout:?}");
    assert_eq!(keys_in_order(&stdout), keys_in_order(&c11_sample()));
}

#[test]
fn version_json_validates_against_the_version_definition() {
    let validator = version_definition_validator();
    let out = rdy(&["version", "--json"]);
    let doc: serde_json::Value =
        serde_json::from_slice(&out.stdout).unwrap_or_else(|e| panic!("stdout is not JSON: {e}"));
    let errors: Vec<String> = validator
        .iter_errors(&doc)
        .map(|e| format!("{e} at {}", e.instance_path()))
        .collect();
    assert!(errors.is_empty(), "{errors:#?}\n{doc}");
    // The documented sample is a valid object too, so the definition and the plan agree.
    let sample: serde_json::Value = serde_json::from_str(&c11_sample())
        .unwrap_or_else(|e| panic!("the C.11 sample is not JSON: {e}"));
    assert!(validator.is_valid(&sample));
}

#[test]
fn version_json_agrees_with_the_version_line() {
    let line_out = rdy(&["version"]);
    let line = String::from_utf8_lossy(&line_out.stdout)
        .trim_end()
        .to_owned();
    let out = rdy(&["version", "--json"]);
    let doc: serde_json::Value =
        serde_json::from_slice(&out.stdout).unwrap_or_else(|e| panic!("stdout is not JSON: {e}"));
    let text = |key: &str| doc[key].as_str().map(str::to_owned);
    assert_eq!(doc["name"], "rdy");
    assert_eq!(doc["api_version"], "rdy/v1");
    assert_eq!(text("version").as_deref(), Some(env!("CARGO_PKG_VERSION")));
    assert_eq!(text("rdy_spec").as_deref(), Some(rdy_spec::VERSION));
    assert!(
        text("target").is_some_and(|t| t.split('-').count() >= 3),
        "target is a triple: {doc}"
    );
    // The line is `rdy <version>` with ` (<commit> <date>)` after it when the build knows them.
    let suffix = match (text("commit"), text("date")) {
        (Some(commit), Some(date)) => format!(" ({commit} {date})"),
        (Some(commit), None) => format!(" ({commit})"),
        (None, _) => String::new(),
    };
    assert_eq!(line, format!("rdy {}{suffix}", env!("CARGO_PKG_VERSION")));
    if let Some(want) = expected_commit() {
        assert_eq!(text("commit"), Some(want), "a git build embeds HEAD");
        assert!(text("date").is_some(), "a git build embeds the date");
    }
}

#[test]
fn the_json_flag_does_not_change_the_other_forms() {
    assert_eq!(rdy(&["--version"]).stdout, rdy(&["version"]).stdout);
    let json = rdy(&["version", "--json"]);
    assert_ne!(json.stdout, rdy(&["version"]).stdout);
}
