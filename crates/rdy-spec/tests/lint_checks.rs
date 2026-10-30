//! Tests for the lint rule on check entries: reserved ids warn, typos and unreadable entries are errors.
//!
//! Helpers avoid `unwrap` and `expect` because clippy only allows them inside `#[test]` functions.

use std::path::PathBuf;

use rdy_spec::check::{CheckParams, UnsupportedReason};
use rdy_spec::lint::{CheckLint, Level, LintCode};
use rdy_spec::parse_unverified;
use rdy_spec::reserved::UnknownKind;
use rdy_spec::spec::Spec;

const HEAD: &str = "apiVersion: rdy/v1\nkind: Readiness\nmetadata:\n  product: acme\nchecks:\n";

fn pass(entries: &str) -> Spec {
    let yaml = format!("{HEAD}{entries}");
    match parse_unverified(yaml.as_bytes()) {
        Ok(spec) => spec,
        Err(e) => panic!("expected the spec to parse, got: {e}"),
    }
}

fn one(entries: &str) -> CheckLint {
    let mut findings = pass(entries).lint_checks();
    assert_eq!(findings.len(), 1, "{findings:?}");
    findings.remove(0)
}

fn assert_error_with_fix(finding: &CheckLint, code: LintCode) {
    assert_eq!(finding.code, code, "{finding:?}");
    assert_eq!(finding.level, Level::Error, "{finding:?}");
    assert!(finding.blocks_signing());
    assert!(!finding.fix.is_empty());
    assert!(!finding.message.is_empty());
}

#[test]
fn host_virtualization_lints_as_not_in_build() {
    let f = one("  - id: host.virtualization\n");
    assert_eq!(f.code, LintCode::NotInBuild);
    assert_eq!(f.code.as_str(), "not_in_build");
    assert_eq!(f.level, Level::Warning);
    assert!(f.message.contains("host.virtualization"));
}

#[test]
fn a_gpu_cuda_entry_only_warns_and_does_not_block_signing() {
    let f = one("  - id: gpu.cuda\n    min: \"12.4\"\n    severity: warn\n");
    assert_eq!(f.code, LintCode::NotInBuild);
    assert_eq!(f.level, Level::Warning);
    assert!(!f.blocks_signing());
    assert!(!f.fix.is_empty());
}

#[test]
fn a_misspelled_id_is_an_unknown_check_error_with_a_fix() {
    let f = one("  - id: host.memroy\n    min: 32Gi\n");
    assert_error_with_fix(&f, LintCode::UnknownCheck);
    assert!(f.message.contains("host.memroy"));
    assert!(f.fix.contains("did you mean 'host.memory'?"), "{}", f.fix);
}

#[test]
fn an_unknown_id_far_from_every_reserved_id_names_the_id_in_the_fix() {
    let f = one("  - id: upload.now\n");
    assert!(f.fix.contains("upload.now"), "{}", f.fix);
    assert!(!f.fix.contains("did you mean"), "{}", f.fix);
}

#[test]
fn an_id_in_an_unreserved_family_is_an_unknown_check_error() {
    let f = one("  - id: upload.now\n");
    assert_error_with_fix(&f, LintCode::UnknownCheck);
}

#[test]
fn an_id_that_is_not_family_dot_name_is_an_unknown_check_error() {
    let f = one("  - id: Host.Memory\n");
    assert_error_with_fix(&f, LintCode::UnknownCheck);
}

#[test]
fn a_misspelled_field_is_an_unsupported_spec_error_with_a_fix() {
    let f = one("  - id: host.memory\n    mn: 32Gi\n");
    assert_error_with_fix(&f, LintCode::UnsupportedSpec);
    assert!(f.message.contains("mn"), "{}", f.message);
    assert!(f.fix.contains("did you mean 'min'?"), "{}", f.fix);
}

#[test]
fn a_field_far_from_every_key_of_the_check_names_the_field_in_the_fix() {
    let f = one("  - id: host.memory\n    min: 32Gi\n    colour: red\n");
    assert_error_with_fix(&f, LintCode::UnsupportedSpec);
    assert!(f.fix.contains("colour"), "{}", f.fix);
    assert!(!f.fix.contains("did you mean"), "{}", f.fix);
}

#[test]
fn a_misspelled_key_in_a_nested_block_names_its_path_and_the_near_key() {
    let f = one("  - id: host.ports\n    free:\n      - port: 80\n        bnid: loopback\n");
    assert_error_with_fix(&f, LintCode::UnsupportedSpec);
    assert!(f.message.contains("free[0].bnid"), "{}", f.message);
    assert!(f.fix.contains("did you mean 'bind'?"), "{}", f.fix);
}

#[test]
fn a_regex_field_that_does_not_compile_is_an_error() {
    let f = one("  - id: k8s.access\n    context_pattern: \"prod-(\"\n");
    assert_error_with_fix(&f, LintCode::UnsupportedSpec);
    assert!(f.message.contains("context_pattern"), "{}", f.message);
    let ok = pass("  - id: k8s.access\n    context_pattern: \"^prod-.*$\"\n");
    assert!(ok.lint_checks().is_empty());
}

#[test]
fn a_bad_value_is_an_unsupported_spec_error_with_a_fix() {
    let f = one("  - id: host.memory\n    min: 32G\n");
    assert_error_with_fix(&f, LintCode::UnsupportedSpec);
}

#[test]
fn a_bare_host_memory_is_a_no_threshold_error_naming_the_missing_key() {
    let f = one("  - id: host.memory\n");
    assert_eq!(f.code, LintCode::NoThreshold);
    assert_eq!(f.code.as_str(), "no_threshold");
    assert_eq!(f.level, Level::Error);
    assert!(f.blocks_signing());
    assert_eq!(
        f.message,
        "host.memory has no threshold, so it can only pass"
    );
    assert_eq!(f.fix, "add 'min: 8Gi'.");
}

#[test]
fn a_no_threshold_fix_puts_or_before_the_last_key_and_names_the_other_required_keys() {
    let f = one("  - id: host.cpu\n");
    assert_eq!(f.fix, "add 'min: 4'.");
    let f = one("  - id: host.ports\n");
    assert_eq!(f.fix, "add at least one of 'free', or 'udp_free'.");
    let f = one("  - id: host.disk\n");
    assert_eq!(f.code, LintCode::NoThreshold);
    assert_eq!(f.fix, "add 'min: 20Gi'; also add 'path'.");
}

#[test]
fn not_in_build_follows_the_wording_of_the_cli_design() {
    let f = one("  - id: gpu.cuda\n");
    assert_eq!(
        f.message,
        "gpu.cuda: this version of rdy has no gpu checks yet"
    );
    assert_eq!(
        f.fix,
        "customers will see this check as not run, and NOT READY while it is required. Keep it if that is what you want."
    );
    let f = one("  - id: host.virtualization\n");
    assert_eq!(
        f.message,
        "host.virtualization: this version of rdy does not have the check host.virtualization yet"
    );
}

#[test]
fn unsupported_messages_do_not_repeat_the_reason() {
    let f = one("  - id: host.memory\n    mn: 32Gi\n");
    assert_eq!(f.message, "unknown field 'mn' in host.memory");
}

#[test]
fn min_32g_is_a_bad_value_not_an_unknown_field() {
    let spec = pass("  - id: host.memory\n    min: 32G\n");
    let decoded = match spec.decode_checks() {
        Ok(d) => d,
        Err(e) => panic!("{e}"),
    };
    assert!(matches!(
        &decoded[0],
        CheckParams::Unsupported {
            reason: UnsupportedReason::BadValue { .. },
            ..
        }
    ));
}

#[test]
fn a_bad_common_field_is_an_unsupported_spec_error() {
    let f = one("  - id: host.cpu\n    min: 4\n    timeout: 90s\n");
    assert_error_with_fix(&f, LintCode::UnsupportedSpec);
    assert!(f.fix.contains("timeout"));
}

#[test]
fn a_clean_entry_has_no_finding() {
    assert!(
        pass("  - id: host.cpu\n    min: 4\n")
            .lint_checks()
            .is_empty()
    );
}

#[test]
fn findings_carry_the_entry_index() {
    let spec = pass(
        "  - id: host.cpu\n    min: 4\n  - id: host.virtualization\n  - id: host.cpu\n    min: 4\n    name: b\n  - id: x.y\n",
    );
    let indexes: Vec<usize> = spec.lint_checks().iter().map(|f| f.index).collect();
    assert_eq!(indexes, [1, 3]);
}

#[test]
fn hostile_text_is_escaped_in_the_message_and_the_fix() {
    let f = one("  - id: \"host.\\u001b[31mred\"\n");
    assert_eq!(f.code, LintCode::UnknownCheck);
    for text in [&f.message, &f.fix] {
        assert!(!text.chars().any(char::is_control), "{text:?}");
    }
}

#[test]
fn unknown_kind_follows_the_reserved_list() {
    let spec =
        pass("  - id: host.virtualization\n  - id: host.memroy\n  - id: host.cpu\n    min: 4\n");
    let decoded = match spec.decode_checks() {
        Ok(d) => d,
        Err(e) => panic!("{e}"),
    };
    let kinds: Vec<Option<UnknownKind>> = decoded.iter().map(CheckParams::unknown_kind).collect();
    assert_eq!(
        kinds,
        [
            Some(UnknownKind::NotInBuild),
            Some(UnknownKind::UnknownCheck),
            None
        ]
    );
}

#[test]
fn acme_platform_has_two_not_in_build_warnings() {
    let path =
        PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../examples/specs/acme-platform.yaml");
    let Ok(bytes) = std::fs::read(&path) else {
        panic!("cannot read {}", path.display());
    };
    let spec = match parse_unverified(&bytes) {
        Ok(s) => s,
        Err(e) => panic!("{e}"),
    };
    let findings = spec.lint_checks();
    // Whether the rest of the example is clean is the job of `rdy spec lint` (M1-031).
    let warnings = findings
        .iter()
        .filter(|f| (f.code, f.level) == (LintCode::NotInBuild, Level::Warning))
        .count();
    assert_eq!(warnings, 2, "{findings:?}");
}

/// M1-172: the 14 M1-late ids have parameter types, so they are no longer `not_in_build`. A bare entry
/// that needs a threshold is a `no_threshold` error with a fix, and a typo in a key is an error too.
#[test]
fn the_m1_late_ids_lint_as_known_checks() {
    for entry in [
        "  - id: host.firewall\n",
        "  - id: host.time_sync\n    ntp_servers: [ntp.acme.example]\n",
        "  - id: host.kernel\n    min: \"5.4\"\n",
        "  - id: net.registry\n    registries: [registry.acme.example]\n",
        "  - id: k8s.crds\n    crds:\n      - name: certificates.cert-manager.io\n",
    ] {
        assert!(pass(entry).lint_checks().is_empty(), "{entry}");
    }
    let f = one("  - id: host.kernel\n");
    assert_eq!(f.code, LintCode::NoThreshold);
    assert_eq!(f.fix, "add 'min: \"5.4\"'.");
    let f = one("  - id: host.sysctl\n");
    assert_eq!(f.code, LintCode::NoThreshold);
    assert_eq!(f.fix, "add at least one of 'expect', or 'limits'.");
    let f = one("  - id: net.registry\n");
    assert_eq!(f.fix, "add 'registries'.");
    let f = one("  - id: host.kernel\n    mn: \"5.4\"\n");
    assert_error_with_fix(&f, LintCode::UnsupportedSpec);
}
