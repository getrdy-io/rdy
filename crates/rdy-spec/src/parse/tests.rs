//! Unit tests for the internals of the reader. The public behaviour is tested in `tests/parse.rs`.

use super::*;

const HEAD: &str = "apiVersion: rdy/v1\nkind: Readiness\nmetadata:\n  product: acme\nchecks:\n";

fn entry(body: &str) -> String {
    format!("{HEAD}  - id: host.cpu\n{body}")
}

#[test]
fn number_kind_follows_the_yaml_1_2_core_schema() {
    let decimal = Some(NumberKind::Decimal);
    let non_finite = Some(NumberKind::NonFinite);
    let table = [
        ("8", None),
        ("-8", None),
        ("0x1F", None),
        ("0o17", None),
        ("12.10.1", None),
        ("1.2.3", None),
        ("1e", None),
        ("e5", None),
        (".", None),
        ("-", None),
        ("+.", None),
        ("1_000.5", None),
        ("nan", None),
        ("inf", None),
        ("-inf", None),
        ("Infinity", None),
        ("NaN", None),
        ("..nan", None),
        ("", None),
        ("0", None),
        ("-0", None),
        ("+5", None),
        ("007", decimal),
        ("-007", decimal),
        ("18446744073709551615", None),
        ("18446744073709551616", decimal),
        ("-9223372036854775808", None),
        ("-9223372036854775809", decimal),
        ("12.10", decimal),
        ("1.", decimal),
        (".5", decimal),
        ("-.5", decimal),
        ("+0.5", decimal),
        ("1e3", decimal),
        ("1E+3", decimal),
        ("1.5e-3", decimal),
        ("0.0", decimal),
        (".nan", non_finite),
        (".NaN", non_finite),
        (".NAN", non_finite),
        ("-.inf", non_finite),
        ("+.INF", non_finite),
        ("1e400", non_finite),
        ("-1e400", non_finite),
    ];
    for (text, expected) in table {
        assert_eq!(number_kind(text), expected, "{text:?}");
    }
}

#[test]
fn later_versions_are_rdy_v_followed_by_a_number_above_one() {
    for yes in ["rdy/v2", "rdy/v3", "rdy/v10", "rdy/v002"] {
        assert!(is_later_version(yes), "{yes}");
    }
    for no in [
        "rdy/v1",
        "rdy/v0",
        "rdy/v",
        "rdy/v1.1",
        "rdy/V2",
        "rdy/v2a",
        "rdy/v-2",
        "v2",
        "",
        "rdy/v1234567890",
    ] {
        assert!(!is_later_version(no), "{no}");
    }
}

#[test]
fn locations_of_bad_bytes_count_lines_and_characters() {
    let bytes = b"ab\ncd\r\nef\rg\xff";
    assert_eq!(location_of_byte(bytes, 0), Location::new(1, 1));
    assert_eq!(location_of_byte(bytes, 2), Location::new(1, 3));
    assert_eq!(location_of_byte(bytes, 3), Location::new(2, 1));
    assert_eq!(location_of_byte(bytes, 9), Location::new(3, 3));
    assert_eq!(location_of_byte(bytes, 10), Location::new(4, 1));
    assert_eq!(location_of_byte(bytes, 11), Location::new(4, 2));
    // An offset past the end is clamped, and the bad byte then counts as one character.
    assert_eq!(location_of_byte(bytes, 999), Location::new(4, 3));
    assert_eq!(location_of_byte(b"", 0), Location::new(1, 1));
    assert_eq!(
        location_of_byte("\u{1f600}x".as_bytes(), 4),
        Location::new(1, 2)
    );
}

/// The guard runs first and catches these with better places. These cases call the second pass by
/// itself, so the limits also hold if the guard ever has a gap.
#[test]
fn the_typed_read_alone_refuses_duplicates_merge_keys_and_non_finite_numbers() {
    let cases = [
        ("duplicate in params", entry("    min: 4\n    min: 5\n")),
        (
            "duplicate in nested params",
            entry("    p:\n      - a: 1\n        a: 2\n"),
        ),
        ("duplicate in a flow map", entry("    p: {a: 1, a: 2}\n")),
        ("non-finite", entry("    min: .nan\n")),
        ("non-finite in a list", entry("    p: [1, .inf]\n")),
        ("overflow", entry("    min: 1e999\n")),
        ("merge key", entry("    <<: {min: 4}\n")),
        ("unknown tag", entry("    min: !custom 4\n")),
        ("anchor", entry("    min: &a 4\n")),
        ("alias", entry("    a: &a 4\n    b: *a\n")),
        ("second document", entry("    min: 4\n---\nkind: x\n")),
    ];
    for (name, yaml) in cases {
        assert!(
            typed_read(&yaml).is_err(),
            "{name} passed the typed read alone"
        );
    }
}

#[test]
fn the_typed_read_alone_keeps_the_text_of_quoted_values() {
    let Ok(spec) = typed_read(&entry("    min: \"12.10\"\n    swap: off\n")) else {
        panic!("the spec must read");
    };
    assert_eq!(spec.checks[0].params["min"], serde_json::json!("12.10"));
    assert_eq!(spec.checks[0].params["swap"], serde_json::json!("off"));
}

#[test]
fn the_reader_reports_the_problem_nearest_the_top() {
    let err = |yaml: String| match parse_bytes(yaml.as_bytes()) {
        Ok(_) => panic!("expected an error"),
        Err(e) => e,
    };
    // The duplicate key is on line 8 and the anchor on line 9. The duplicate comes first.
    let e = err(entry("    a: 1\n    a: 2\n    b: &x 3\n"));
    assert!(matches!(e.kind(), SpecError::DuplicateKey { .. }), "{e:?}");
    // The anchor comes first this time.
    let e = err(entry("    b: &x 3\n    a: 1\n    a: 2\n"));
    assert!(matches!(e.kind(), SpecError::Anchor), "{e:?}");
    // A directive always comes first.
    let e = err(format!("%YAML 1.2\n---\n{}", entry("    a: &x 3\n")));
    assert!(matches!(e.kind(), SpecError::Directive), "{e:?}");
}

#[test]
fn parse_unverified_returns_a_plain_spec_and_load_still_wants_a_signature() {
    let yaml = entry("    min: 8\n");
    let Ok(spec) = parse_unverified(yaml.as_bytes()) else {
        panic!("the spec must parse");
    };
    assert_eq!(spec.metadata.product.as_str(), "acme");
    // Nothing turns that `Spec` into a `LoadedSpec`. Only `load` can, and it wants a signature.
    let trust = crate::sig::TrustStore::new();
    assert_eq!(
        crate::load(
            yaml.as_bytes(),
            None,
            &trust,
            crate::sig::Policy::RequireSigned
        )
        .unwrap_err(),
        SpecError::Signature(crate::sig::SignatureError::Missing)
    );
}
