//! Tests for `rdy_spec::parse_unverified`: the limits of ADR 0001 and the reviewer follow-ups of M1-017.
//!
//! Every refusal here is an `Err(SpecError)`. The CLI turns all of them into exit 64 (a spec content
//! error), so "exit 64 class" in the ticket means "an error with a line and column, never a panic".
//! Helpers in this file avoid `unwrap` and `expect` because clippy only allows them inside `#[test]`
//! functions.

use std::path::{Path, PathBuf};

use rdy_spec::{MAX_SPEC_BYTES, SpecError, parse_unverified};
use serde_json::Value;

/// A valid spec header. Entries start on line 7.
const HEAD: &str = "apiVersion: rdy/v1\nkind: Readiness\nmetadata:\n  product: acme\nchecks:\n";

fn repo_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../..")
}

fn read(path: &Path) -> Vec<u8> {
    match std::fs::read(path) {
        Ok(bytes) => bytes,
        Err(e) => panic!("cannot read {}: {e}", path.display()),
    }
}

fn spec_with_entry(entry: &str) -> String {
    format!("{HEAD}{entry}")
}

fn fail(yaml: &str) -> SpecError {
    match parse_unverified(yaml.as_bytes()) {
        Ok(_) => panic!("expected an error for:\n{yaml}"),
        Err(e) => e,
    }
}

fn fail_bytes(bytes: &[u8]) -> SpecError {
    match parse_unverified(bytes) {
        Ok(_) => panic!("expected an error"),
        Err(e) => e,
    }
}

fn pass(yaml: &str) -> rdy_spec::spec::Spec {
    match parse_unverified(yaml.as_bytes()) {
        Ok(spec) => spec,
        Err(e) => panic!("expected {yaml:?} to parse, got: {e} at {:?}", e.location()),
    }
}

/// The line and column of an error, or a panic when it has none.
fn place(e: &SpecError) -> (u32, u32) {
    match e.location() {
        Some(l) => (l.line, l.column),
        None => panic!("no location on {e:?}"),
    }
}

/// An error text that is safe to print: one line, no control characters, short.
fn assert_printable(e: &SpecError) {
    let text = e.to_string();
    assert!(!text.chars().any(char::is_control), "{text:?}");
    assert!(text.chars().count() < 400, "{} chars", text.chars().count());
    assert!(!e.hint().is_empty());
}

// ---- the example specs -------------------------------------------------------------------------

#[test]
fn every_example_spec_decodes_into_typed_values() {
    let dir = repo_root().join("examples/specs");
    let expected: [(&str, &str, usize, bool); 5] = [
        ("acme-airgap-host.yaml", "acme-edge", 9, true),
        ("acme-inference-gpu.yaml", "acme-inference", 6, true),
        ("acme-k8s-only.yaml", "acme-operator", 5, true),
        ("acme-platform.yaml", "acme-platform", 8, true),
        ("acme-quickstart.yaml", "acme-quickstart", 5, false),
    ];
    let on_disk = match std::fs::read_dir(&dir) {
        Ok(entries) => entries.filter_map(Result::ok).count(),
        Err(e) => panic!("cannot read {}: {e}", dir.display()),
    };
    assert_eq!(on_disk, expected.len(), "a new example needs a row here");
    for (file, product, checks, has_bundle) in expected {
        let bytes = read(&dir.join(file));
        let spec = match parse_unverified(&bytes) {
            Ok(s) => s,
            Err(e) => panic!("{file}: {e} at {:?}", e.location()),
        };
        assert_eq!(spec.metadata.product.as_str(), product, "{file}");
        assert_eq!(spec.checks.len(), checks, "{file}");
        assert_eq!(spec.bundle.is_some(), has_bundle, "{file}");
        assert!(spec.checks.iter().all(|c| c.check_id().is_ok()), "{file}");
    }
}

#[test]
fn example_values_keep_their_types_and_text() {
    let bytes = read(&repo_root().join("examples/specs/acme-platform.yaml"));
    let spec = match parse_unverified(&bytes) {
        Ok(s) => s,
        Err(e) => panic!("{e}"),
    };
    let by_id = |id: &str| match spec.checks.iter().find(|c| c.id == id) {
        Some(c) => c,
        None => panic!("no {id}"),
    };
    assert_eq!(by_id("host.cpu").params["min"], Value::from(8));
    assert_eq!(by_id("host.memory").params["min"], Value::from("32Gi"));
    // A quoted version keeps its text.
    assert_eq!(by_id("gpu.cuda").params["min"], Value::from("12.4"));
    assert_eq!(by_id("k8s.version").params["min"], Value::from("1.28"));
    assert_eq!(
        by_id("net.egress").params["endpoints"],
        serde_json::json!(["registry.acme.example:443", "license.acme.example:443"])
    );
    assert_eq!(spec.metadata.version.as_deref(), Some(">=4.2"));
}

// ---- size ---------------------------------------------------------------------------------------

#[test]
fn a_spec_of_exactly_one_mib_is_read() {
    let mut yaml = spec_with_entry("  - id: host.cpu\n    min: 8\n");
    let pad = MAX_SPEC_BYTES - yaml.len();
    // Comment lines keep the file valid. The last line has no newline so the size is exact.
    let filler = "#".repeat(pad - 1);
    yaml.push('\n');
    yaml.push_str(&filler);
    yaml.truncate(MAX_SPEC_BYTES);
    assert_eq!(yaml.len(), MAX_SPEC_BYTES);
    pass(&yaml);
}

#[test]
fn a_spec_one_byte_over_the_limit_is_refused_before_parsing() {
    let mut yaml = spec_with_entry("  - id: host.cpu\n    min: 8\n");
    yaml.push_str(&" ".repeat(MAX_SPEC_BYTES + 1 - yaml.len()));
    assert_eq!(yaml.len(), MAX_SPEC_BYTES + 1);
    let e = fail(&yaml);
    assert!(matches!(
        e,
        SpecError::TooLarge { size, limit } if size == MAX_SPEC_BYTES + 1 && limit == MAX_SPEC_BYTES
    ));
    assert_printable(&e);
}

#[test]
fn a_two_mib_file_is_refused_even_when_it_is_not_text() {
    // Not YAML and not UTF-8. The size check comes first, so neither matters.
    let e = fail_bytes(&vec![0xff; 2 * 1024 * 1024]);
    assert!(matches!(e, SpecError::TooLarge { .. }), "{e:?}");
    assert!(e.to_string().contains("2097152"), "{e}");
}

// ---- the fixtures of SEC-62 and the ADR 0001 limits -------------------------------------------------

#[test]
fn malformed_fixtures_give_their_documented_error_with_line_and_column() {
    type Check = fn(&SpecError) -> bool;
    let cases: [(&str, Check, (u32, u32)); 15] = [
        (
            "tag-binary.yaml",
            |e| matches!(e, SpecError::Tag { tag } if tag == "!!binary"),
            (8, 10),
        ),
        (
            "tag-custom.yaml",
            |e| matches!(e, SpecError::Tag { tag } if tag == "!custom"),
            (8, 10),
        ),
        (
            "directive-yaml-1-1.yaml",
            |e| matches!(e, SpecError::Directive),
            (1, 1),
        ),
        (
            "directive-tag.yaml",
            |e| matches!(e, SpecError::Directive),
            (1, 1),
        ),
        (
            "nan.yaml",
            |e| matches!(e, SpecError::NonFiniteNumber { text } if text == ".nan"),
            (8, 10),
        ),
        (
            "inf.yaml",
            |e| matches!(e, SpecError::NonFiniteNumber { text } if text == ".inf"),
            (8, 10),
        ),
        (
            "neg-inf.yaml",
            |e| matches!(e, SpecError::NonFiniteNumber { text } if text == "-.inf"),
            (8, 10),
        ),
        ("anchor.yaml", |e| matches!(e, SpecError::Anchor), (8, 10)),
        (
            "alias-unknown-anchor.yaml",
            |e| matches!(e, SpecError::Alias),
            (9, 10),
        ),
        (
            "duplicate-key-check.yaml",
            |e| matches!(e, SpecError::DuplicateKey { key } if key == "min"),
            (9, 5),
        ),
        (
            "duplicate-key-nested-param.yaml",
            |e| matches!(e, SpecError::DuplicateKey { key } if key == "target"),
            (11, 9),
        ),
        (
            "merge-key.yaml",
            |e| matches!(e, SpecError::MergeKey),
            (8, 5),
        ),
        (
            "two-documents.yaml",
            |e| matches!(e, SpecError::MultipleDocuments),
            (9, 1),
        ),
        (
            "unquoted-decimal-cuda.yaml",
            |e| matches!(e, SpecError::UnquotedDecimal { key: Some(k), text } if k == "min" && text == "12.10"),
            (8, 10),
        ),
        (
            "api-version-v2.yaml",
            |e| matches!(e, SpecError::UnsupportedApiVersion { found } if found == "rdy/v2"),
            (2, 13),
        ),
    ];
    let dir = repo_root().join("tests/fixtures/specs/malformed");
    for (file, is_expected, (line, column)) in cases {
        let bytes = read(&dir.join(file));
        let e = fail_bytes(&bytes);
        assert!(is_expected(e.kind()), "{file}: wrong error {e:?}");
        assert_eq!(place(&e), (line, column), "{file}: {e}");
        assert_printable(&e);
    }
}

#[test]
fn every_malformed_fixture_is_covered_by_the_table() {
    let dir = repo_root().join("tests/fixtures/specs/malformed");
    let count = match std::fs::read_dir(&dir) {
        Ok(entries) => entries.filter_map(Result::ok).count(),
        Err(e) => panic!("cannot read {}: {e}", dir.display()),
    };
    assert_eq!(count, 15, "a new fixture needs a row in the table");
}

// ---- anchors, aliases, merge keys, documents ----------------------------------------------------

#[test]
fn anchors_and_aliases_are_refused_wherever_they_sit() {
    // The entry starts on line 6 of the file, so a second line of the entry is line 7.
    let cases: [(&str, &str, bool, (u32, u32)); 6] = [
        (
            "anchor on a scalar",
            "  - id: host.cpu\n    min: &a 8\n",
            true,
            (7, 10),
        ),
        (
            "anchor on a map",
            "  - id: host.cpu\n    p: &a\n      x: 1\n",
            true,
            (7, 8),
        ),
        (
            "anchor on a list",
            "  - id: host.cpu\n    p: &a\n      - 1\n",
            true,
            (7, 8),
        ),
        (
            "anchor on a key",
            "  - id: host.cpu\n    &k min: 8\n",
            true,
            (7, 5),
        ),
        (
            "anchor on an entry",
            "  - &e\n    id: host.cpu\n",
            true,
            (6, 5),
        ),
        ("alias", "  - id: host.cpu\n    min: *a\n", false, (7, 10)),
    ];
    for (name, entry, is_anchor, at) in cases {
        let e = fail(&spec_with_entry(entry));
        if is_anchor {
            assert!(matches!(e.kind(), SpecError::Anchor), "{name}: {e:?}");
        } else {
            assert!(matches!(e.kind(), SpecError::Alias), "{name}: {e:?}");
        }
        assert_eq!(place(&e), at, "{name}: {e:?}");
    }
}

#[test]
fn an_anchor_and_its_alias_give_two_different_errors() {
    let yaml = spec_with_entry("  - id: host.cpu\n    a: &x 1\n    b: *x\n");
    let e = fail(&yaml);
    assert!(matches!(e.kind(), SpecError::Anchor), "{e:?}");
    assert_eq!(place(&e), (7, 8));
    let e = fail(&spec_with_entry("  - id: host.cpu\n    b: *x\n"));
    assert!(matches!(e.kind(), SpecError::Alias), "{e:?}");
    assert_eq!(place(&e), (7, 8));
}

#[test]
fn a_billion_laughs_file_is_refused_at_the_first_anchor() {
    let mut yaml = String::from(HEAD);
    yaml.push_str("  - id: host.cpu\n    a: &a [x, x, x, x, x, x, x, x, x]\n");
    yaml.push_str("    b: &b [*a, *a, *a, *a, *a, *a, *a, *a, *a]\n");
    yaml.push_str("    c: &c [*b, *b, *b, *b, *b, *b, *b, *b, *b]\n");
    let e = fail(&yaml);
    assert!(matches!(e.kind(), SpecError::Anchor), "{e:?}");
    assert_eq!(place(&e).0, 7);
}

#[test]
fn merge_keys_are_refused_in_block_and_flow_maps() {
    let e = fail(&spec_with_entry("  - id: host.cpu\n    <<: {min: 8}\n"));
    assert!(matches!(e.kind(), SpecError::MergeKey), "{e:?}");
    assert_eq!(place(&e), (7, 5));
    let e = fail(&spec_with_entry("  - {id: host.cpu, <<: {min: 8}}\n"));
    assert!(matches!(e.kind(), SpecError::MergeKey), "{e:?}");
    assert_eq!(place(&e).0, 6);
    // Quoted, it is only a key that happens to look like one.
    pass(&spec_with_entry("  - id: host.cpu\n    \"<<\": 1\n"));
}

#[test]
fn a_second_document_is_refused_however_it_starts() {
    let one = spec_with_entry("  - id: host.cpu\n    min: 8\n");
    for (name, tail, at) in [
        ("--- and a document", format!("---\n{one}"), (8, 1)),
        ("--- alone", "---\n".to_owned(), (8, 1)),
        ("... then ---", "...\n---\nkind: x\n".to_owned(), (9, 1)),
    ] {
        let e = fail(&format!("{one}{tail}"));
        assert!(
            matches!(e.kind(), SpecError::MultipleDocuments),
            "{name}: {e:?}"
        );
        assert_eq!(place(&e), at, "{name}");
    }
}

#[test]
fn an_empty_file_and_a_comment_only_file_have_no_document() {
    for yaml in ["", "\n\n", "# only a comment\n", "---\n"] {
        let e = fail(yaml);
        assert!(place(&e).0 >= 1, "{yaml:?}: {e:?}");
        assert_printable(&e);
    }
}

// ---- duplicate keys (reviewer follow-up) --------------------------------------------------------------

#[test]
fn a_duplicate_key_is_refused_at_every_depth() {
    let cases: [(&str, String, &str, (u32, u32)); 9] = [
        (
            "top level",
            format!("{HEAD}  - id: host.cpu\nkind: Readiness\n"),
            "kind",
            (7, 1),
        ),
        (
            "metadata",
            "apiVersion: rdy/v1\nkind: Readiness\nmetadata:\n  product: a\n  product: b\nchecks: []\n"
                .to_owned(),
            "product",
            (5, 3),
        ),
        (
            "common field of a check",
            spec_with_entry("  - id: host.cpu\n    severity: warn\n    severity: block\n"),
            "severity",
            (8, 5),
        ),
        (
            "the id of a check",
            spec_with_entry("  - id: host.cpu\n    id: host.memory\n"),
            "id",
            (7, 5),
        ),
        (
            "parameter of a check (flatten must not keep the last)",
            spec_with_entry("  - id: host.memory\n    min: 32Gi\n    min: 64Gi\n"),
            "min",
            (8, 5),
        ),
        (
            "map inside a parameter",
            spec_with_entry("  - id: host.lsm\n    selinux:\n      allow: a\n      allow: b\n"),
            "allow",
            (9, 7),
        ),
        (
            "list of maps inside a parameter",
            spec_with_entry(
                "  - id: net.egress\n    endpoints:\n      - target: a.example:443\n        target: b.example:443\n",
            ),
            "target",
            (9, 9),
        ),
        (
            "flow map inside a parameter",
            spec_with_entry("  - id: net.egress\n    endpoints: [{target: a, target: b}]\n"),
            "target",
            (7, 29),
        ),
        (
            "bundle pattern",
            format!(
                "{HEAD}  - id: host.cpu\nbundle:\n  redact_patterns:\n    - name: a\n      regex: b\n      name: c\n"
            ),
            "name",
            (11, 7),
        ),
    ];
    for (name, yaml, key, (line, column)) in cases {
        let e = fail(&yaml);
        assert!(
            matches!(e.kind(), SpecError::DuplicateKey { key: k } if k == key),
            "{name}: {e:?}"
        );
        assert_eq!(place(&e), (line, column), "{name}: {e}");
        assert_printable(&e);
    }
}

#[test]
fn equal_keys_in_different_maps_are_not_duplicates() {
    let yaml = spec_with_entry(
        "  - id: host.cpu\n    min: 8\n  - id: host.memory\n    min: 32Gi\n    p: {min: 1}\n    q: [{min: 1}, {min: 2}]\n",
    );
    let spec = pass(&yaml);
    assert_eq!(spec.checks.len(), 2);
}

#[test]
fn a_key_that_is_not_text_is_refused() {
    let e = fail(&spec_with_entry(
        "  - id: host.cpu\n    ? [a, b]\n    : c\n",
    ));
    assert!(matches!(e.kind(), SpecError::InvalidValue { .. }), "{e:?}");
    assert_eq!(place(&e).0, 7);
}

// ---- non-finite numbers (reviewer follow-up) -----------------------------------------------------------

#[test]
fn non_finite_numbers_are_refused_wherever_they_sit() {
    let spellings = [
        ".nan", ".NaN", ".NAN", ".inf", ".Inf", ".INF", "-.inf", "+.inf", "-.INF",
    ];
    for text in spellings {
        let places = [
            format!("  - id: host.cpu\n    min: {text}\n"),
            format!("  - id: host.cpu\n    p: [{text}]\n"),
            format!("  - id: host.cpu\n    p: {{a: {text}}}\n"),
            format!("  - id: host.cpu\n    {text}: 1\n"),
            format!("  - id: host.cpu\n    - {text}\n").replace("    - ", "    p:\n      - "),
        ];
        for entry in places {
            let e = fail(&spec_with_entry(&entry));
            assert!(
                matches!(e.kind(), SpecError::NonFiniteNumber { text: t } if t == text),
                "{text} in {entry:?}: {e:?}"
            );
            assert!(place(&e).0 >= 7);
            assert_printable(&e);
        }
    }
    // In the parts of the file that are typed rather than raw.
    let yaml = "apiVersion: rdy/v1\nkind: Readiness\nmetadata:\n  product: a\n  serial: .nan\nchecks: []\n";
    let e = fail(yaml);
    assert!(
        matches!(e.kind(), SpecError::NonFiniteNumber { .. }),
        "{e:?}"
    );
    assert_eq!(place(&e), (5, 11));
}

#[test]
fn a_decimal_too_large_for_a_float_counts_as_not_finite() {
    for text in ["1e999", "-1e999", "1.5e400", "1" /* control: finite */] {
        let entry = format!("  - id: host.cpu\n    min: {text}\n");
        if text == "1" {
            pass(&spec_with_entry(&entry));
            continue;
        }
        let e = fail(&spec_with_entry(&entry));
        assert!(
            matches!(e.kind(), SpecError::NonFiniteNumber { .. }),
            "{text}: {e:?}"
        );
    }
}

#[test]
fn text_that_only_looks_like_a_non_finite_number_is_text() {
    let yaml = spec_with_entry(concat!(
        "  - id: host.cpu\n",
        "    a: nan\n    b: inf\n    c: Infinity\n    d: NaN\n    e: \".nan\"\n    f: '.inf'\n",
        "    g: |\n      .nan\n",
    ));
    let spec = pass(&yaml);
    let p = &spec.checks[0].params;
    assert_eq!(p["a"], Value::from("nan"));
    assert_eq!(p["b"], Value::from("inf"));
    assert_eq!(p["c"], Value::from("Infinity"));
    assert_eq!(p["d"], Value::from("NaN"));
    assert_eq!(p["e"], Value::from(".nan"));
    assert_eq!(p["f"], Value::from(".inf"));
    assert_eq!(p["g"], Value::from(".nan\n"));
}

// ---- unquoted decimals ---------------------------------------------------------------------------------------

#[test]
fn a_quoted_version_keeps_its_text_and_an_unquoted_one_is_refused() {
    let spec = pass(&spec_with_entry("  - id: gpu.cuda\n    min: \"12.10\"\n"));
    assert_eq!(spec.checks[0].params["min"], Value::from("12.10"));
    let spec = pass(&spec_with_entry("  - id: gpu.cuda\n    min: '1.30'\n"));
    assert_eq!(spec.checks[0].params["min"], Value::from("1.30"));

    let e = fail(&spec_with_entry("  - id: gpu.cuda\n    min: 12.10\n"));
    assert!(
        matches!(e.kind(), SpecError::UnquotedDecimal { key: Some(k), text } if k == "min" && text == "12.10"),
        "{e:?}"
    );
    assert_eq!(place(&e), (7, 10));
    assert!(
        e.to_string().contains("min is written as the number 12.10"),
        "{e}"
    );
    assert!(e.hint().contains("quotes"), "{}", e.hint());
}

#[test]
fn every_unquoted_decimal_shape_is_refused() {
    for text in [
        "1.30", "0.5", ".5", "5.", "1e3", "1E3", "2.5e-3", "-1.5", "+1.5", "00.10",
    ] {
        let e = fail(&spec_with_entry(&format!(
            "  - id: gpu.cuda\n    min: {text}\n"
        )));
        assert!(
            matches!(e.kind(), SpecError::UnquotedDecimal { text: t, .. } if t == text),
            "{text}: {e:?}"
        );
    }
}

#[test]
fn a_decimal_in_a_list_names_the_key_it_belongs_to() {
    let e = fail(&spec_with_entry(
        "  - id: gpu.cuda\n    versions: [\"12.4\", 12.10]\n",
    ));
    assert!(
        matches!(e.kind(), SpecError::UnquotedDecimal { key: Some(k), .. } if k == "versions"),
        "{e:?}"
    );
    assert_eq!(place(&e), (7, 24));
}

#[test]
fn metadata_version_must_be_quoted_when_it_is_a_bare_decimal() {
    let yaml = "apiVersion: rdy/v1\nkind: Readiness\nmetadata:\n  product: a\n  version: 4.2\nchecks: []\n";
    let e = fail(yaml);
    assert!(
        matches!(e.kind(), SpecError::UnquotedDecimal { .. }),
        "{e:?}"
    );
    assert_eq!(place(&e), (5, 12));
}

#[test]
fn whole_numbers_and_dotted_versions_are_not_decimals() {
    let spec = pass(&spec_with_entry(
        "  - id: host.cpu\n    a: 8\n    b: 0x1F\n    c: 12.10.1\n    d: -3\n    e: 1.2.3-rc1\n    f: ~\n",
    ));
    let p = &spec.checks[0].params;
    assert_eq!(p["a"], Value::from(8));
    assert_eq!(p["b"], Value::from(31));
    assert_eq!(p["c"], Value::from("12.10.1"));
    assert_eq!(p["d"], Value::from(-3));
    assert_eq!(p["e"], Value::from("1.2.3-rc1"));
    assert_eq!(p["f"], Value::Null);
    // The extremes of i64 and u64 keep every digit.
    let spec = pass(&spec_with_entry(
        "  - id: host.cpu\n    a: 18446744073709551615\n    b: -9223372036854775808\n    c: 0\n    d: -0\n    e: +5\n",
    ));
    let p = &spec.checks[0].params;
    assert_eq!(p["a"], Value::from(u64::MAX));
    assert_eq!(p["b"], Value::from(i64::MIN));
    assert_eq!(p["c"], Value::from(0));
}

#[test]
fn whole_numbers_that_would_not_keep_their_text_are_refused_with_a_quote_hint() {
    let cases = [
        ("0755", (7, 8)),
        ("00", (7, 8)),
        ("-007", (7, 8)),
        ("+01", (7, 8)),
        ("18446744073709551616", (7, 8)),
        ("99999999999999999999999", (7, 8)),
        ("-9223372036854775809", (7, 8)),
    ];
    for (text, at) in cases {
        let e = fail(&spec_with_entry(&format!(
            "  - id: host.cpu\n    a: {text}\n"
        )));
        assert!(
            matches!(e.kind(), SpecError::UnquotedDecimal { key: Some(k), text: t } if k == "a" && t == text),
            "{text}: {e:?}"
        );
        assert_eq!(place(&e), at, "{text}");
        assert!(e.hint().contains("quotes"), "{}", e.hint());
        assert!(e.to_string().contains("Quote it"), "{e}");
    }
    // Quoted, they keep their text.
    let spec = pass(&spec_with_entry(
        "  - id: host.cpu\n    a: \"0755\"\n    b: '99999999999999999999999'\n",
    ));
    assert_eq!(spec.checks[0].params["a"], Value::from("0755"));
    assert_eq!(
        spec.checks[0].params["b"],
        Value::from("99999999999999999999999")
    );
}

#[test]
fn the_decimal_message_talks_about_versions_only_for_version_keys() {
    let e = fail(&spec_with_entry("  - id: gpu.cuda\n    min: 12.10\n"));
    assert_eq!(
        e.to_string(),
        "min is written as the number 12.10, but versions must be text"
    );
    let e = fail(&spec_with_entry("  - id: net.egress\n    port: 0443\n"));
    assert_eq!(
        e.to_string(),
        "port is written as the number 0443. Quote it to keep it as typed"
    );
}

// ---- YAML 1.2 core schema ----------------------------------------------------------------------------------------

#[test]
fn yes_no_on_off_are_text() {
    let spec = pass(&spec_with_entry(
        "  - id: host.memory\n    swap: off\n    a: yes\n    b: no\n    c: on\n    d: y\n    e: true\n",
    ));
    let p = &spec.checks[0].params;
    assert_eq!(p["swap"], Value::from("off"));
    assert_eq!(p["a"], Value::from("yes"));
    assert_eq!(p["b"], Value::from("no"));
    assert_eq!(p["c"], Value::from("on"));
    assert_eq!(p["d"], Value::from("y"));
    assert_eq!(p["e"], Value::Bool(true));
}

// ---- tags and directives -----------------------------------------------------------------------------------------------

#[test]
fn every_explicit_tag_is_refused() {
    for tag in [
        "!!str",
        "!!int",
        "!!binary",
        "!!float",
        "!!seq",
        "!!map",
        "!custom",
        "!<tag:x.example,2026:y>",
    ] {
        let e = fail(&spec_with_entry(&format!(
            "  - id: host.cpu\n    min: {tag} 8\n"
        )));
        assert!(matches!(e.kind(), SpecError::Tag { .. }), "{tag}: {e:?}");
        assert_eq!(place(&e), (7, 10), "{tag}");
    }
    let e = fail(&spec_with_entry("  - id: host.cpu\n    p: !!seq [1]\n"));
    assert!(matches!(e.kind(), SpecError::Tag { .. }), "{e:?}");
    let e = fail(&spec_with_entry("  - id: host.cpu\n    p: !!map {a: 1}\n"));
    assert!(matches!(e.kind(), SpecError::Tag { .. }), "{e:?}");
    let e = fail(&spec_with_entry("  - !!map\n    id: host.cpu\n"));
    assert!(matches!(e.kind(), SpecError::Tag { .. }), "{e:?}");
}

#[test]
fn directives_are_refused_even_after_comments() {
    for (head, line) in [
        ("%YAML 1.2\n---\n", 1),
        ("%YAML 1.1\n---\n", 1),
        ("# comment\n%YAML 1.2\n---\n", 2),
        ("%TAG ! tag:example.com,2026:\n---\n", 1),
        ("%FOO bar\n---\n", 1),
    ] {
        let e = fail(&format!("{head}{}", spec_with_entry("  - id: host.cpu\n")));
        assert!(matches!(e.kind(), SpecError::Directive), "{head:?}: {e:?}");
        assert_eq!(place(&e), (line, 1), "{head:?}");
    }
}

#[test]
fn an_explicit_document_start_without_a_directive_is_fine() {
    pass(&format!("---\n{}", spec_with_entry("  - id: host.cpu\n")));
}

// ---- apiVersion ------------------------------------------------------------------------------------------------------------

#[test]
fn a_later_api_version_asks_for_an_upgrade_and_ignores_the_rest_of_the_file() {
    for version in ["rdy/v2", "rdy/v3", "rdy/v10", "rdy/v99"] {
        let yaml = format!(
            "apiVersion: {version}\nkind: Readiness\nmetadata: {{product: a, new_thing: 1}}\nbrand_new: true\nchecks: []\n"
        );
        let e = fail(&yaml);
        assert!(
            matches!(e.kind(), SpecError::UnsupportedApiVersion { found } if found == version),
            "{version}: {e:?}"
        );
        assert_eq!(place(&e), (1, 13));
        assert!(e.to_string().contains(version), "{e}");
        assert_eq!(e.hint(), "install the latest rdy.");
    }
}

#[test]
fn once_the_file_says_rdy_v2_every_later_refusal_becomes_an_upgrade_message() {
    let later_problems = [
        "x: 1.5\n",
        "x: !foo 1\n",
        "x: &a 1\n",
        "x: *a\n",
        "x: .nan\n",
        "x: 0755\n",
        "x: 1\nx: 2\n",
        "<<: {a: 1}\n",
        "x: [\n",
        "metadata: 1\n---\nz: 1\n",
    ];
    for tail in later_problems {
        let e = fail(&format!("apiVersion: rdy/v2\n{tail}"));
        assert!(
            matches!(e.kind(), SpecError::UnsupportedApiVersion { found } if found == "rdy/v2"),
            "{tail:?}: {e:?}"
        );
        assert_eq!(place(&e), (1, 13), "{tail:?}");
        assert_eq!(e.hint(), "install the latest rdy.");
    }
    // A problem above the apiVersion line is reported first.
    let e = fail("x: 1.5\napiVersion: rdy/v2\n");
    assert!(
        matches!(e.kind(), SpecError::UnquotedDecimal { .. }),
        "{e:?}"
    );
    let e = fail("%YAML 1.2\n---\napiVersion: rdy/v2\n");
    assert!(matches!(e.kind(), SpecError::Directive), "{e:?}");
    // For rdy/v1 nothing changes.
    let e = fail("apiVersion: rdy/v1\nx: 1.5\n");
    assert!(
        matches!(e.kind(), SpecError::UnquotedDecimal { .. }),
        "{e:?}"
    );
}

#[test]
fn a_wrong_or_missing_api_version_is_refused_with_its_own_error() {
    let cases = [
        (
            "apiVersion: rdy/v1.1\nkind: Readiness\n",
            Some("rdy/v1.1"),
            (1, 13),
        ),
        (
            "apiVersion: rdy/v0\nkind: Readiness\n",
            Some("rdy/v0"),
            (1, 13),
        ),
        (
            "apiVersion: rdy/V2\nkind: Readiness\n",
            Some("rdy/V2"),
            (1, 13),
        ),
        ("apiVersion: v1\nkind: Readiness\n", Some("v1"), (1, 13)),
        (
            "apiVersion: other.io/v2\nkind: Readiness\n",
            Some("other.io/v2"),
            (1, 13),
        ),
        ("apiVersion: \"\"\nkind: Readiness\n", Some(""), (1, 13)),
        ("apiVersion: 1\nkind: Readiness\n", Some("1"), (1, 13)),
        (
            "apiVersion: rdy/v99999999999999\nkind: Readiness\n",
            Some("rdy/v99999999999999"),
            (1, 13),
        ),
        ("apiVersion: [rdy/v1]\nkind: Readiness\n", None, (1, 13)),
        ("apiVersion: {a: b}\nkind: Readiness\n", None, (1, 13)),
        ("apiVersion:\nkind: Readiness\n", Some("~"), (1, 11)),
        (
            "kind: Readiness\nmetadata: {product: a}\nchecks: []\n",
            None,
            (1, 1),
        ),
    ];
    for (yaml, found, at) in cases {
        let e = fail(yaml);
        assert!(
            matches!(e.kind(), SpecError::BadApiVersion { found: f } if f.as_deref() == found),
            "{yaml:?}: {e:?}"
        );
        assert_eq!(place(&e), at, "{yaml:?}");
        assert_eq!(e.hint(), "add 'apiVersion: rdy/v1' as the first line.");
    }
}

#[test]
fn a_quoted_api_version_is_the_same_as_a_plain_one() {
    pass("apiVersion: \"rdy/v1\"\nkind: Readiness\nmetadata: {product: a}\nchecks: []\n");
    pass("apiVersion: 'rdy/v1'\nkind: Readiness\nmetadata: {product: a}\nchecks: []\n");
}

// ---- typed errors from the second pass -----------------------------------------------------------------------------------

#[test]
fn errors_of_the_typed_read_carry_a_place_and_a_fix() {
    let base = |meta: &str, extra: &str| {
        format!(
            "apiVersion: rdy/v1\nkind: Readiness\nmetadata: {meta}\nchecks: [{{id: host.cpu}}]\n{extra}"
        )
    };
    let e = fail(&base("{product: a}", "metdata: {}\n"));
    assert!(
        matches!(e.kind(), SpecError::UnknownKey { key } if key == "metdata"),
        "{e:?}"
    );
    assert_eq!(place(&e), (5, 1));

    let e = fail(&base("{prodcut: a}", ""));
    assert!(
        matches!(e.kind(), SpecError::UnknownKey { key } if key == "prodcut"),
        "{e:?}"
    );

    let e = fail("apiVersion: rdy/v1\nkind: Readiness\nchecks: []\n");
    assert!(
        matches!(e.kind(), SpecError::MissingField { field } if field == "metadata"),
        "{e:?}"
    );

    let e = fail(&base("{product: Acme Platform}", ""));
    assert!(
        matches!(e.kind(), SpecError::InvalidProduct { value } if value == "Acme Platform"),
        "{e:?}"
    );
    assert_eq!(place(&e), (3, 21));

    let e = fail(&base("{product: a, serial: 9007199254740992}", ""));
    assert!(matches!(e.kind(), SpecError::InvalidSerial { .. }), "{e:?}");

    let e = fail("apiVersion: rdy/v1\nkind: Report\nmetadata: {product: a}\nchecks: []\n");
    assert!(matches!(e.kind(), SpecError::InvalidValue { .. }), "{e:?}");
    assert_eq!(place(&e), (2, 7));

    let e = fail(
        "apiVersion: rdy/v1\nkind: Readiness\nmetadata: {product: a}\nchecks: [{severity: warn}]\n",
    );
    assert!(
        matches!(e.kind(), SpecError::MissingField { field } if field == "id"),
        "{e:?}"
    );

    let e = fail("hello\n");
    assert!(matches!(e.kind(), SpecError::InvalidValue { .. }), "{e:?}");
    assert_eq!(place(&e), (1, 1));

    for e in [
        fail(&base("{product: a}", "metdata: {}\n")),
        fail(&base("{prodcut: a}", "")),
        fail("hello\n"),
    ] {
        assert_printable(&e);
    }
}

#[test]
fn a_bad_common_field_still_does_not_reject_the_file() {
    let spec = pass(&spec_with_entry(
        "  - id: host.cpu\n    severity: blok\n    os: [rhel]\n    timeout: 90\n    name: Data\n    mn: 3\n",
    ));
    assert_eq!(spec.checks.len(), 1);
    assert_eq!(spec.checks[0].params["mn"], Value::from(3));
}

// ---- syntax, depth and text safety --------------------------------------------------------------------------------------

#[test]
fn yaml_syntax_errors_carry_a_place() {
    for yaml in [
        "apiVersion: rdy/v1\n  bad: [\n",
        "apiVersion: rdy/v1\nkind: [Readiness\n",
        "a: 'unclosed\n",
        "a: \"bad \\q escape\"\n",
        "key: value\n\tbad: tab\n",
        "- a\nb: c\n",
        "a: b: c\n",
    ] {
        let e = fail(yaml);
        assert!(place(&e).0 >= 1, "{yaml:?}: {e:?}");
        assert_printable(&e);
    }
}

#[test]
fn nesting_of_64_levels_is_read_and_65_is_refused() {
    // The top-level map is level 1, `checks` is 2, and the entry is 3. Then `p` adds the rest.
    let flow = |n: usize| {
        spec_with_entry(&format!(
            "  - id: host.cpu\n    p: {}{}\n",
            "[".repeat(n),
            "]".repeat(n)
        ))
    };
    pass(&flow(61));
    let e = fail(&flow(62));
    assert!(
        matches!(e.kind(), SpecError::TooDeep { limit: 64 }),
        "{e:?}"
    );
    assert_eq!(place(&e).0, 7);

    let block = |n: usize| {
        let mut entry = String::from("  - id: host.cpu\n    p:\n");
        for i in 0..n {
            entry.push_str(&format!("{}k{i}:\n", " ".repeat(6 + i)));
        }
        entry.push_str(&format!("{}v: 1\n", " ".repeat(6 + n)));
        spec_with_entry(&entry)
    };
    // n nested maps below `p`, the innermost holding `v: 1`: depth 3 + n + 1 - 1.
    pass(&block(60));
    let e = fail(&block(62));
    assert!(matches!(e.kind(), SpecError::TooDeep { .. }), "{e:?}");

    let mut seq = String::from("  - id: host.cpu\n    p:\n");
    for i in 0..70 {
        seq.push_str(&format!("{}-\n", " ".repeat(6 + i)));
    }
    let e = fail(&spec_with_entry(&seq));
    assert!(
        matches!(
            e.kind(),
            SpecError::TooDeep { .. } | SpecError::Syntax { .. }
        ),
        "{e:?}"
    );
}

#[test]
fn a_megabyte_of_open_brackets_is_an_error_not_a_crash() {
    for open in ["[", "{a: ", "- ", "? [", "[{"] {
        let mut yaml = spec_with_entry("  - id: host.cpu\n    p: ");
        while yaml.len() < MAX_SPEC_BYTES - 8 {
            yaml.push_str(open);
        }
        let e = fail(&yaml);
        assert!(place(&e).0 >= 1, "{open:?}: {e:?}");
        assert_printable(&e);
    }
}

#[test]
fn a_valid_file_of_the_size_limit_is_not_refused_for_its_number_of_values() {
    // About 500,000 one-digit values fit in 1 MiB. The count caps are raised to cover that.
    let mut yaml = spec_with_entry("  - id: host.cpu\n    p: [");
    while yaml.len() < MAX_SPEC_BYTES - 8 {
        yaml.push_str("1,");
    }
    yaml.push_str("1]\n");
    assert!(yaml.len() <= MAX_SPEC_BYTES);
    let spec = pass(&yaml);
    assert!(matches!(&spec.checks[0].params["p"], Value::Array(a) if a.len() > 400_000));
    // The worst case for events: one empty value per two bytes.
    let mut yaml = spec_with_entry("  - id: host.cpu\n    p:\n");
    while yaml.len() < MAX_SPEC_BYTES - 8 {
        yaml.push_str("      -\n");
    }
    pass(&yaml);
}

#[test]
fn syntax_reasons_are_escaped_once() {
    // The reader quotes the bad character already escaped. A second pass would turn `\u{0}` into `\\u{0}`.
    let e = fail(&spec_with_entry("  - id: host.cpu\n    p: a\u{0}b\n"));
    let text = e.to_string();
    assert!(text.contains("\\u{0}"), "{text}");
    assert!(!text.contains("\\\\"), "{text}");
    assert_printable(&e);
}

#[test]
fn a_tab_error_points_at_the_tab() {
    let e = fail("apiVersion: rdy/v1\nmetadata:\n\tproduct: a\n");
    assert_eq!(place(&e), (3, 1), "{e:?}");
    // Tabs inside a line are fine.
    pass(&spec_with_entry(
        "  - id: host.cpu\n    a:\t1\n    b: [1,\t2]\n",
    ));
}

#[test]
fn invalid_utf8_is_refused_at_the_bad_byte() {
    let mut bytes = b"apiVersion: rdy/v1\nkind: Readiness\r\nmetadata: {product: \xe2\x82".to_vec();
    bytes.extend_from_slice(&[0xff, b'}', b'\n']);
    let e = fail_bytes(&bytes);
    assert!(matches!(e.kind(), SpecError::NotUtf8), "{e:?}");
    assert_eq!(place(&e), (3, 21));
    assert_printable(&e);
}

#[test]
fn columns_count_characters_and_lines_survive_crlf() {
    // Two emoji and an accented letter before the duplicate key: the column counts characters.
    let yaml =
        spec_with_entry("  - id: host.cpu\n    p: {\u{1f600}\u{e9}\u{1f600}: 1, a: 1, a: 2}\n");
    let e = fail(&yaml);
    assert!(matches!(e.kind(), SpecError::DuplicateKey { .. }), "{e:?}");
    assert_eq!(place(&e), (7, 23));

    let crlf = spec_with_entry("  - id: host.cpu\n    min: 8\n    min: 9\n").replace('\n', "\r\n");
    let e = fail(&crlf);
    assert_eq!(place(&e), (8, 5));
}

#[test]
fn echoed_text_is_escaped_and_capped() {
    let ansi = "\u{1b}[2J\u{1b}]0;pwned\u{7}";
    // Keys longer than 1024 characters are a syntax error of their own, so keys stay below that.
    let long = "k".repeat(1000);
    let huge = "h".repeat(10 * 1024);
    let dup = |key: &str| {
        spec_with_entry(&format!(
            "  - id: host.cpu\n    \"{key}\": 1\n    \"{key}\": 2\n"
        ))
    };
    let cases = [
        ("duplicate key", fail(&dup("\\e[2J\\e]0;pwned\\a"))),
        ("long duplicate key", fail(&dup(&long))),
        (
            "tag",
            fail(&spec_with_entry(&format!(
                "  - id: host.cpu\n    min: !<{huge}> 8\n"
            ))),
        ),
        (
            "unknown key",
            fail(&format!(
                "apiVersion: rdy/v1\nkind: Readiness\nmetadata: {{product: a}}\nchecks: []\n\"{long}\": 1\n"
            )),
        ),
        (
            "unknown key with escapes",
            fail(
                "apiVersion: rdy/v1\nkind: Readiness\nmetadata: {product: a}\nchecks: []\n\"\\e[2J\": 1\n",
            ),
        ),
        (
            "api version",
            fail(&format!("apiVersion: \"{huge}\"\nkind: Readiness\n")),
        ),
        (
            "api version with escapes",
            fail("apiVersion: \"\\e[31mrdy/v2\"\nkind: Readiness\n"),
        ),
        (
            "kind",
            fail("apiVersion: rdy/v1\nkind: \"\\e[31mred\"\nmetadata: {product: a}\nchecks: []\n"),
        ),
        (
            "product",
            fail(
                "apiVersion: rdy/v1\nkind: Readiness\nmetadata: {product: \"\\e[31m\"}\nchecks: []\n",
            ),
        ),
        (
            "decimal key",
            fail(&spec_with_entry(&format!(
                "  - id: host.cpu\n    \"{long}\": 1.5\n"
            ))),
        ),
        (
            "syntax error with a control character",
            fail(&spec_with_entry("  - id: host.cpu\n    p: a\u{1b}b\n")),
        ),
        (
            "missing field after an escape",
            fail("apiVersion: rdy/v1\nkind: Readiness\nmetadata: {product: a}\n"),
        ),
    ];
    for (name, e) in cases {
        assert_printable(&e);
        assert!(
            !e.to_string().contains(&long),
            "{name}: echoed the whole value"
        );
        assert!(
            !e.to_string().contains(ansi),
            "{name}: raw escape in {:?}",
            e.to_string()
        );
    }
    let e = fail(&dup("\\e[2J"));
    assert!(e.to_string().contains("\\u{1b}[2J"), "{e}");
    let e = fail(&dup(&long));
    assert!(
        e.to_string().contains(&format!("{}...", "k".repeat(64))),
        "{e}"
    );
}

// ---- no panic -----------------------------------------------------------------------------------------------------------------------

#[test]
fn no_prefix_of_an_example_spec_panics() {
    let bytes = read(&repo_root().join("examples/specs/acme-platform.yaml"));
    for end in 0..=bytes.len() {
        // Ok or Err, either is fine. A panic fails the test.
        let _ = parse_unverified(&bytes[..end]);
    }
}

#[test]
fn awkward_inputs_do_not_panic() {
    let inputs: [&[u8]; 14] = [
        b"",
        b"\0",
        b"\xef\xbb\xbf",
        b"\xef\xbb\xbfapiVersion: rdy/v1\n",
        b"---\n---\n---\n",
        b"%",
        b"&",
        b"*",
        b"!",
        b"!!",
        b"<<: 1\n",
        b"? \n: \n",
        b"\r\r\r\n\n",
        b"a: \"\\ud800\"\n",
    ];
    for input in inputs {
        let _ = parse_unverified(input);
    }
}

#[test]
fn a_byte_order_mark_is_accepted() {
    let mut bytes = b"\xef\xbb\xbf".to_vec();
    bytes.extend_from_slice(spec_with_entry("  - id: host.cpu\n    min: 8\n").as_bytes());
    assert!(parse_unverified(&bytes).is_ok());
}
