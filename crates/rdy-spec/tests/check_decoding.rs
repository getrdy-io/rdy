//! Tests for the second decoding step of check entries: `CheckSpec::decode_params` and
//! `Spec::decode_checks`, driven through `parse_unverified` so every error has a line and a column.
//!
//! Helpers avoid `unwrap` and `expect` because clippy only allows them inside `#[test]` functions.

use std::path::{Path, PathBuf};

use rdy_spec::check::{CheckParams, KNOWN_IDS, UnsupportedReason};
use rdy_spec::spec::Spec;
use rdy_spec::{SpecError, parse_unverified};

/// A valid spec header. Entries start on line 6.
const HEAD: &str = "apiVersion: rdy/v1\nkind: Readiness\nmetadata:\n  product: acme\nchecks:\n";

fn pass(yaml: &str) -> Spec {
    match parse_unverified(yaml.as_bytes()) {
        Ok(spec) => spec,
        Err(e) => panic!("expected {yaml:?} to parse, got: {e} at {:?}", e.location()),
    }
}

fn fail(yaml: &str) -> SpecError {
    match parse_unverified(yaml.as_bytes()) {
        Ok(_) => panic!("expected an error for:\n{yaml}"),
        Err(e) => e,
    }
}

fn decode(spec: &Spec) -> Vec<CheckParams> {
    match spec.decode_checks() {
        Ok(v) => v,
        Err(e) => panic!("expected the checks to decode, got: {e}"),
    }
}

fn place(e: &SpecError) -> (u32, u32) {
    match e.location() {
        Some(l) => (l.line, l.column),
        None => panic!("no location on {e:?}"),
    }
}

fn with_entries(entries: &str) -> String {
    format!("{HEAD}{entries}")
}

// ---- the exit test of the ticket ---------------------------------------------------------------

#[test]
fn gpu_cuda_decodes_to_unknown() {
    let spec = pass(&with_entries("  - id: gpu.cuda\n    min: \"12.4\"\n"));
    let decoded = decode(&spec);
    let CheckParams::Unknown { id, fields } = &decoded[0] else {
        panic!("gpu.cuda must be Unknown, got {:?}", decoded[0]);
    };
    assert_eq!(id, "gpu.cuda");
    assert_eq!(fields["min"], "12.4");
}

#[test]
fn host_memory_with_mn_decodes_to_unsupported_naming_mn() {
    let spec = pass(&with_entries(
        "  - id: host.memory\n    mn: 32Gi\n    severity: block\n",
    ));
    let decoded = decode(&spec);
    let CheckParams::Unsupported { id, reason, .. } = &decoded[0] else {
        panic!("must be Unsupported, got {:?}", decoded[0]);
    };
    assert_eq!(id, "host.memory");
    assert_eq!(
        *reason,
        UnsupportedReason::UnknownField { field: "mn".into() }
    );
    // The skipped check is still required.
    assert_eq!(
        spec.checks[0].effective_severity(),
        rdy_spec::spec::Severity::Block
    );
}

#[test]
fn a_missing_id_is_a_spec_error_with_line_and_column() {
    // Block style: the second entry has no id. The error points at where that entry starts.
    let e = fail(&with_entries(
        "  - id: host.cpu\n  - severity: warn\n    min: 4\n",
    ));
    assert!(
        matches!(e.kind(), SpecError::MissingCheckId { number: 2 }),
        "{e:?}"
    );
    assert_eq!(place(&e), (7, 5));
    assert_eq!(e.to_string(), "check 2 has no id");
    assert_eq!(e.hint(), "add an id such as 'id: host.memory'.");

    // Flow style.
    let e = fail(
        "apiVersion: rdy/v1\nkind: Readiness\nmetadata: {product: a}\nchecks: [{id: host.cpu}, {min: 4}]\n",
    );
    assert!(
        matches!(e.kind(), SpecError::MissingCheckId { number: 2 }),
        "{e:?}"
    );
    assert_eq!(place(&e), (4, 26));
}

#[test]
fn an_id_inside_a_parameter_is_not_the_id_of_the_entry() {
    let e = fail(&with_entries(
        "  - endpoints:\n      - id: nested\n    min: 1\n",
    ));
    assert!(
        matches!(e.kind(), SpecError::MissingCheckId { number: 1 }),
        "{e:?}"
    );
    assert_eq!(place(&e), (6, 5));
}

#[test]
fn a_non_text_id_still_rejects_the_file_with_a_place() {
    let e = fail(&with_entries("  - id: [host.cpu]\n"));
    assert!(e.location().is_some(), "{e:?}");
}

#[test]
fn a_duplicate_entry_key_is_a_spec_error_with_line_and_column() {
    let e = fail(&with_entries(
        "  - id: host.cpu\n  - id: host.disk\n    path: /a\n  - id: host.disk\n    path: /b\n",
    ));
    assert!(
        matches!(e.kind(), SpecError::DuplicateCheck { id, name: None } if id == "host.disk"),
        "{e:?}"
    );
    assert_eq!(place(&e), (9, 5));
    assert_eq!(e.to_string(), "two checks are named host.disk");

    let e = fail(&with_entries(
        "  - id: host.disk\n    name: data\n  - id: host.disk\n    name: data\n",
    ));
    assert!(
        matches!(e.kind(), SpecError::DuplicateCheck { name: Some(n), .. } if n == "data"),
        "{e:?}"
    );
    assert_eq!(place(&e), (8, 5));
}

#[test]
fn flow_style_entries_are_placed_too() {
    let e = fail(
        "apiVersion: rdy/v1\nkind: Readiness\nmetadata: {product: a}\nchecks: [{id: gpu.cuda}, {id: gpu.cuda}]\n",
    );
    assert!(
        matches!(e.kind(), SpecError::DuplicateCheck { .. }),
        "{e:?}"
    );
    assert_eq!(place(&e), (4, 26));
}

#[test]
fn a_name_makes_two_entries_with_one_id_fine() {
    let spec = pass(&with_entries(
        "  - id: host.disk\n    name: data\n  - id: host.disk\n    name: logs\n  - id: host.disk\n",
    ));
    assert_eq!(decode(&spec).len(), 3);
}

// ---- one bad check never fails the spec ----------------------------------------------------------

#[test]
fn one_bad_check_never_fails_the_whole_spec() {
    let spec = pass(&with_entries(
        "  - id: host.cpu\n    min: 4\n\
         \x20 - id: gpu.cuda\n    min: \"12.4\"\n\
         \x20 - id: host.memory\n    mn: 32Gi\n\
         \x20 - id: host.disk\n    severity: blok\n\
         \x20 - id: host.ports\n    timeout: 90s\n\
         \x20 - id: host.os\n    os: [rhel]\n\
         \x20 - id: memroy\n\
         \x20 - id: net.dns\n    names: [a.example]\n",
    ));
    let decoded = decode(&spec);
    assert_eq!(decoded.len(), 8);
    assert!(matches!(decoded[0], CheckParams::HostCpu(_)));
    assert!(matches!(decoded[1], CheckParams::Unknown { .. }));
    assert!(matches!(decoded[2], CheckParams::Unsupported { .. }));
    let fields = [("severity", 3), ("timeout", 4), ("os", 5)];
    for (field, index) in fields {
        let CheckParams::Unsupported { reason, .. } = &decoded[index] else {
            panic!("entry {index} must be Unsupported: {:?}", decoded[index]);
        };
        assert_eq!(*reason, UnsupportedReason::BadCommonField { field });
    }
    assert!(matches!(decoded[6], CheckParams::Unknown { .. }));
    // `names` is a real net.dns parameter, but this build has not got its struct yet, so it is refused
    // by name and not ignored.
    let CheckParams::Unsupported { reason, .. } = &decoded[7] else {
        panic!("net.dns: {:?}", decoded[7]);
    };
    assert_eq!(
        *reason,
        UnsupportedReason::UnknownField {
            field: "names".into()
        }
    );
}

/// 01 section 2.5 and ADR 0008: a key a known check does not have is never ignored, however it is
/// written, because ignoring a stricter threshold could turn a failing host into a passing one.
#[test]
fn an_unknown_field_is_never_dropped_whatever_its_value() {
    for value in [
        "1", "\"32Gi\"", "[a, b]", "{x: 1}", "true", "null", "~", "\"\"",
    ] {
        let spec = pass(&with_entries(&format!(
            "  - id: host.memory\n    min_resident: {value}\n"
        )));
        let decoded = decode(&spec);
        let CheckParams::Unsupported { reason, fields, .. } = &decoded[0] else {
            panic!("{value}: {:?}", decoded[0]);
        };
        assert_eq!(
            *reason,
            UnsupportedReason::UnknownField {
                field: "min_resident".into()
            },
            "{value}"
        );
        assert!(fields.contains_key("min_resident"), "{value}");
    }
}

#[test]
fn a_hostile_unknown_field_name_is_printable_in_the_reason() {
    let spec = pass(&with_entries(
        "  - id: host.memory\n    \"\\e[2Jboom\": 1\n",
    ));
    let decoded = decode(&spec);
    let CheckParams::Unsupported { reason, .. } = &decoded[0] else {
        panic!("{:?}", decoded[0]);
    };
    let text = reason.to_string();
    assert!(!text.chars().any(char::is_control), "{text:?}");
    assert!(text.contains("boom"), "{text}");
}

// ---- precedence of the errors -----------------------------------------------------------------

#[test]
fn a_structural_error_above_a_missing_id_is_reported_first() {
    let e = fail(
        "apiVersion: rdy/v1\nkind: Readiness\nmetdata: {}\nmetadata: {product: a}\nchecks: [{min: 4}]\n",
    );
    assert!(matches!(e.kind(), SpecError::UnknownKey { .. }), "{e:?}");
}

#[test]
fn an_error_inside_an_entry_is_not_hidden_by_the_entry_checks() {
    let e = fail(&with_entries("  - id: host.cpu\n    min: 12.10\n"));
    assert!(
        matches!(e.kind(), SpecError::UnquotedDecimal { .. }),
        "{e:?}"
    );
}

// ---- the examples -----------------------------------------------------------------------------

fn repo_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../..")
}

#[test]
fn every_example_spec_decodes_its_checks_without_an_error() {
    let dir = repo_root().join("examples/specs");
    let Ok(entries) = std::fs::read_dir(&dir) else {
        panic!("cannot read {}", dir.display());
    };
    let mut seen = 0;
    for item in entries.flatten() {
        let path = item.path();
        if path.extension().is_none_or(|e| e != "yaml") {
            continue;
        }
        let Ok(bytes) = std::fs::read(&path) else {
            panic!("cannot read {}", path.display());
        };
        let spec = match parse_unverified(&bytes) {
            Ok(s) => s,
            Err(e) => panic!("{}: {e} at {:?}", path.display(), e.location()),
        };
        let decoded = decode(&spec);
        assert_eq!(decoded.len(), spec.checks.len(), "{}", path.display());
        for (entry, params) in spec.checks.iter().zip(&decoded) {
            // Known ids are one of the 17. Everything else is Unknown. Nothing panics.
            let known = KNOWN_IDS.contains(&entry.id.as_str());
            assert_eq!(
                known,
                !matches!(params, CheckParams::Unknown { .. }),
                "{}: {}",
                path.display(),
                entry.id
            );
        }
        seen += 1;
    }
    assert_eq!(seen, 5);
}

#[test]
fn acme_platform_has_gpu_cuda_and_aws_iam_as_unknown() {
    let path = repo_root().join("examples/specs/acme-platform.yaml");
    let Ok(bytes) = std::fs::read(&path) else {
        panic!("cannot read {}", path.display());
    };
    let spec = pass(&String::from_utf8_lossy(&bytes));
    let decoded = decode(&spec);
    let unknown: Vec<&str> = decoded
        .iter()
        .filter(|p| matches!(p, CheckParams::Unknown { .. }))
        .map(CheckParams::id)
        .collect();
    assert_eq!(unknown, ["gpu.cuda", "aws.iam"]);
}

/// The host checks of the example specs all read: a vendor who copies an example gets a check that runs.
#[test]
fn every_host_check_in_the_examples_that_this_build_has_reads_fully() {
    let dir = repo_root().join("examples/specs");
    let Ok(entries) = std::fs::read_dir(&dir) else {
        panic!("cannot read {}", dir.display());
    };
    let mut host_checks = 0;
    for item in entries.flatten() {
        let path = item.path();
        if path.extension().is_none_or(|e| e != "yaml") {
            continue;
        }
        let Ok(bytes) = std::fs::read(&path) else {
            panic!("cannot read {}", path.display());
        };
        let spec = pass(&String::from_utf8_lossy(&bytes));
        for params in decode(&spec) {
            if params.id().starts_with("host.") && KNOWN_IDS.contains(&params.id()) {
                host_checks += 1;
                assert!(
                    !matches!(params, CheckParams::Unsupported { .. }),
                    "{}: {params:?}",
                    path.display()
                );
            }
        }
    }
    assert!(host_checks >= 10, "{host_checks}");
}

/// 01 section 2.5: `- id: host.memory` alone is skipped as `unsupported_spec`, with the reason
/// `no_threshold` for lint.
#[test]
fn a_bare_host_memory_has_no_threshold() {
    let spec = pass(&with_entries(
        "  - id: host.memory\n    severity: block\n    fix: Add RAM.\n",
    ));
    let decoded = decode(&spec);
    let CheckParams::Unsupported { id, reason, .. } = &decoded[0] else {
        panic!("{:?}", decoded[0]);
    };
    assert_eq!(id, "host.memory");
    assert_eq!(*reason, UnsupportedReason::NoThreshold { one_of: &["min"] });
}

/// A YAML key with no value (`min:`) is a bad value. It must not read as an absent threshold.
#[test]
fn a_host_key_with_no_value_is_a_bad_value() {
    let spec = pass(&with_entries("  - id: host.memory\n    min:\n"));
    let decoded = decode(&spec);
    let CheckParams::Unsupported { reason, .. } = &decoded[0] else {
        panic!("{:?}", decoded[0]);
    };
    assert!(
        matches!(reason, UnsupportedReason::BadValue { field: Some(f), .. } if f == "min"),
        "{reason:?}"
    );
}
