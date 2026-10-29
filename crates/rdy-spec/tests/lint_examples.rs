//! The example specs are the first thing a vendor copies, so they must lint the way the docs say
//! (M1-031): no errors, a `fix` on every check, and only the warnings that are meant.
//!
//! Helpers avoid `unwrap` and `expect` because clippy only allows them inside `#[test]` functions.

use std::path::{Path, PathBuf};

use rdy_spec::check::KNOWN_IDS;
use rdy_spec::lint::{Level, lint_bytes};
use rdy_spec::parse_unverified;
use rdy_spec::spec::{Lenient, Severity, Spec};

fn dir() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../../examples/specs")
}

fn read(name: &str) -> Vec<u8> {
    let path = dir().join(name);
    match std::fs::read(&path) {
        Ok(bytes) => bytes,
        Err(e) => panic!("cannot read {}: {e}", path.display()),
    }
}

fn spec(name: &str) -> Spec {
    match parse_unverified(&read(name)) {
        Ok(spec) => spec,
        Err(e) => panic!("{name}: {e}"),
    }
}

fn examples() -> Vec<String> {
    let entries = match std::fs::read_dir(dir()) {
        Ok(entries) => entries,
        Err(e) => panic!("cannot read the examples: {e}"),
    };
    let mut names: Vec<String> = entries
        .flatten()
        .filter_map(|e| e.file_name().into_string().ok())
        .filter(|n| n.ends_with(".yaml"))
        .collect();
    names.sort();
    names
}

#[test]
fn there_are_five_examples() {
    assert_eq!(examples().len(), 5);
}

#[test]
fn no_example_has_a_lint_error() {
    for name in examples() {
        let report = lint_bytes(&name, &read(&name));
        assert_eq!(report.errors, 0, "{name}: {:#?}", report.findings);
        assert!(
            report.findings.iter().all(|f| f.level == Level::Warning),
            "{name}"
        );
    }
}

#[test]
fn every_block_and_warn_check_of_every_example_has_a_fix() {
    for name in examples() {
        for (index, check) in spec(&name).checks.iter().enumerate() {
            let severity = check.effective_severity();
            assert!(matches!(severity, Severity::Block | Severity::Warn));
            let has_fix =
                matches!(&check.fix, Some(Lenient::Valid(fix)) if !fix.as_str().is_empty());
            assert!(has_fix, "{name}: check {index} ({}) has no fix", check.id);
        }
    }
}

#[test]
fn acme_platform_has_exactly_two_not_in_build_warnings() {
    let report = lint_bytes("acme-platform.yaml", &read("acme-platform.yaml"));
    let codes: Vec<&str> = report.findings.iter().map(|f| f.code).collect();
    assert_eq!(codes, ["not_in_build", "not_in_build"]);
    let keys: Vec<Option<&str>> = report.findings.iter().map(|f| f.key.as_deref()).collect();
    assert_eq!(keys, [Some("gpu.cuda"), Some("aws.iam")]);
    assert_eq!((report.errors, report.warnings), (0, 2));
}

#[test]
fn acme_quickstart_is_clean_and_uses_only_checks_this_build_has() {
    let report = lint_bytes("acme-quickstart.yaml", &read("acme-quickstart.yaml"));
    assert!(report.findings.is_empty(), "{:#?}", report.findings);
    for check in &spec("acme-quickstart.yaml").checks {
        assert!(KNOWN_IDS.contains(&check.id.as_str()), "{}", check.id);
    }
}

#[test]
fn acme_inference_gpu_names_ids_from_the_catalog_only() {
    let spec = spec("acme-inference-gpu.yaml");
    assert!(spec.checks.iter().all(|c| c.id != "gpu.device_plugin"));
    assert!(spec.checks.iter().any(|c| c.id == "k8s.device_plugins"));
    // Every finding is the warning for an id the catalog reserves and this build lacks.
    let report = lint_bytes("acme-inference-gpu.yaml", &read("acme-inference-gpu.yaml"));
    assert!(report.findings.iter().all(|f| f.code == "not_in_build"));
}
