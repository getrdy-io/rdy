//! Unit tests of `k8s.namespace`: the pure parts, with no cluster and no mock. The fixture tests in
//! `tests.rs` run the whole check.

use std::collections::BTreeMap;

use k8s_openapi::api::authorization::v1::SubjectAccessReviewStatus;
use rdy_engine::check::Level;
use serde_json::json;

use super::amount::{Amount, show};
use super::fix::is_name;
use super::judge::{Answer, normalize, shown};
use super::objects::{LimitItem, Limits, MemoryLimits, Page, Quota};
use super::*;

fn params(spec: serde_json::Value) -> K8sNamespace {
    serde_json::from_value(spec).expect("the parameters parse")
}

fn nano(text: &str) -> i128 {
    Amount::parse(text).expect("an amount").nano()
}

#[test]
fn quantities_are_read_with_the_grammar_of_the_api() {
    for (text, units) in [
        ("0", 0),
        ("1", 1),
        ("16", 16),
        ("+16", 16),
        ("1k", 1_000),
        ("2G", 2_000_000_000),
        ("1Ki", 1024),
        ("64Gi", 64 * 1024 * 1024 * 1024),
        ("1e3", 1000),
        ("1E3", 1000),
        ("2e0", 2),
        ("12e-1", 1),
    ] {
        let amount = Amount::parse(text).unwrap_or_else(|| panic!("{text} reads"));
        if text == "12e-1" {
            // 1.2 rounds up to nano precision, not to a whole unit.
            assert_eq!(amount.nano(), 1_200_000_000);
        } else {
            assert_eq!(amount.nano(), units * 1_000_000_000, "{text}");
        }
    }
    assert_eq!(nano("500m"), 500_000_000);
    assert_eq!(nano("0.5"), 500_000_000);
    assert_eq!(nano(".5"), 500_000_000);
    assert_eq!(nano("5."), 5_000_000_000);
    assert_eq!(nano("100u"), 100_000);
    assert_eq!(nano("1n"), 1);
    // Below a nano-unit rounds up, so a tiny used amount is never read as zero.
    assert_eq!(nano("1e-12"), 1);
    assert_eq!(nano("0.0000000001"), 1);
    assert_eq!(nano("1.5Gi"), 1_610_612_736 * 1_000_000_000);
}

#[test]
fn text_that_is_not_a_quantity_is_none() {
    for text in [
        "",
        " ",
        "lots",
        "-1",
        "1 Gi",
        "1GB",
        "1gi",
        "1.2.3",
        ".",
        "e3",
        "1e",
        "1e+",
        "1eX",
        "1e1234",
        "Gi",
        "0x10",
        "١٢",
        "1Gi ",
        "1\n",
        "\u{1b}[2J1",
    ] {
        assert_eq!(Amount::parse(text), None, "{text:?}");
    }
    // Over the bounds: 49 characters, and 37 digits.
    assert_eq!(Amount::parse(&"1".repeat(49)), None);
    assert_eq!(Amount::parse(&"1".repeat(37)), None);
}

#[test]
fn a_huge_amount_saturates_and_never_panics() {
    let huge = Amount::parse("999999999999999999999999999999999999Ei").expect("reads");
    assert_eq!(huge.nano(), i128::MAX);
    let exp = Amount::parse("9e999").expect("reads");
    assert_eq!(exp.nano(), i128::MAX);
    assert!(Amount::parse("1e-999").expect("reads") < Amount::parse("1m").expect("reads"));
    assert_eq!(nano("0e999"), 0);
    // Saturated subtraction stays in range.
    assert_eq!(huge.minus(huge).nano(), 0);
    assert_eq!(Amount::from_bytes(0).minus(huge).nano(), -i128::MAX);
    assert_eq!(
        Amount::from_bytes(u64::MAX).nano(),
        i128::from(u64::MAX) * 1_000_000_000
    );
}

#[test]
fn amounts_are_shown_from_the_number() {
    let seen = |text: &str, bytes: bool| show(Amount::parse(text).expect("reads"), bytes);
    assert_eq!(seen("16", false), "16");
    assert_eq!(seen("500m", false), "500m");
    assert_eq!(seen("64Gi", true), "64Gi");
    assert_eq!(seen("1536Mi", true), "1536Mi");
    assert_eq!(seen("1500", true), "1500");
    assert_eq!(seen("2Ti", true), "2Ti");
    assert_eq!(seen("1n", false), "1n");
    assert_eq!(seen("0", true), "0");
    // A quantity below zero is shown as zero.
    let over = Amount::parse("1")
        .expect("reads")
        .minus(Amount::parse("3").expect("reads"));
    assert_eq!(show(over, false), "0");
    assert_eq!(show(over.at_least_zero(), false), "0");
}

#[test]
fn the_short_resource_names_are_the_requests_names() {
    assert_eq!(normalize("cpu"), "requests.cpu");
    assert_eq!(normalize("memory"), "requests.memory");
    assert_eq!(normalize("ephemeral-storage"), "requests.ephemeral-storage");
    assert_eq!(normalize("hugepages-2Mi"), "requests.hugepages-2Mi");
    assert_eq!(normalize("requests.cpu"), "requests.cpu");
    assert_eq!(normalize("limits.cpu"), "limits.cpu");
    assert_eq!(normalize("pods"), "pods");
    assert_eq!(normalize("count/jobs.batch"), "count/jobs.batch");
}

#[test]
fn only_a_name_shaped_text_goes_into_a_command() {
    for good in ["compute", "object-counts", "a.b-c", "x1"] {
        assert!(is_name(good), "{good}");
    }
    for bad in [
        "",
        "Compute",
        "-a",
        "a-",
        "a..b",
        "a b",
        "a`b",
        "a;b",
        "a$b",
        "\u{1b}[2J",
        &"a".repeat(254),
    ] {
        assert!(!is_name(bad), "{bad:?}");
    }
}

#[test]
fn text_from_the_server_is_made_safe() {
    assert_eq!(shown("plain"), "plain");
    assert!(!shown("a`b").contains('`'));
    assert!(!shown("\u{1b}[2J").contains('\u{1b}'));
    assert_eq!(shown(&"L".repeat(100)), format!("{}...", "L".repeat(64)));
}

#[test]
fn an_access_review_answer_is_sorted() {
    let status =
        |allowed: bool, denied: Option<bool>, error: Option<&str>| SubjectAccessReviewStatus {
            allowed,
            denied,
            evaluation_error: error.map(str::to_owned),
            reason: Some("why".to_owned()),
        };
    assert_eq!(
        super::judge::answer_of(&status(true, None, None)),
        Answer::Allowed
    );
    assert_eq!(
        super::judge::answer_of(&status(false, Some(true), Some("boom"))),
        Answer::NotAllowed("why".to_owned())
    );
    assert!(matches!(
        super::judge::answer_of(&status(false, None, Some("boom"))),
        Answer::Unknown(_)
    ));
    assert!(matches!(
        super::judge::answer_of(&status(false, None, Some(""))),
        Answer::NotAllowed(_)
    ));
}

fn quota(name: &str, hard: &[(&str, &str)], used: Option<&[(&str, &str)]>, scoped: bool) -> Quota {
    let map = |pairs: &[(&str, &str)]| -> BTreeMap<String, String> {
        pairs
            .iter()
            .map(|(k, v)| ((*k).to_owned(), (*v).to_owned()))
            .collect()
    };
    Quota {
        name: name.to_owned(),
        scopes: if scoped {
            vec!["Terminating".to_owned()]
        } else {
            Vec::new()
        },
        scoped,
        hard: map(hard),
        used: used.map(map),
    }
}

fn active(quotas: Vec<Quota>, limits: Vec<Limits>) -> Gathered {
    Gathered {
        namespace: Some("acme".to_owned()),
        ns: Some(Read::Ok(NsFacts {
            terminating: false,
            conditions: Vec::new(),
        })),
        quotas: Some(Read::Ok(Page {
            items: quotas,
            cut: false,
        })),
        limits: Some(Read::Ok(Page {
            items: limits,
            cut: false,
        })),
        create: None,
    }
}

fn clean(finding: &rdy_engine::check::Finding) {
    for text in finding.fix.iter().chain(&finding.notes) {
        if let Err(error) = rdy_engine::fixtext::check(text) {
            panic!("fix text breaks the allow-list: {error}\n{text}");
        }
    }
}

#[test]
fn a_quota_that_is_exactly_enough_passes_and_one_unit_short_blocks() {
    let spec = params(json!({"quota_needs": {"requests.cpu": 2}}));
    let exact = active(
        vec![quota(
            "q",
            &[("requests.cpu", "8")],
            Some(&[("requests.cpu", "6")]),
            false,
        )],
        Vec::new(),
    );
    assert_eq!(judge::judge(&spec, &exact).level, Level::Pass);
    let short = active(
        vec![quota(
            "q",
            &[("requests.cpu", "8")],
            Some(&[("requests.cpu", "7")]),
            false,
        )],
        Vec::new(),
    );
    let finding = judge::judge(&spec, &short);
    assert_eq!(finding.level, Level::Fail);
    clean(&finding);
    // Milli-CPU amounts compare exactly: 1500m left against 2 needed.
    let milli = active(
        vec![quota(
            "q",
            &[("requests.cpu", "8")],
            Some(&[("requests.cpu", "6500m")]),
            false,
        )],
        Vec::new(),
    );
    let finding = judge::judge(&spec, &milli);
    assert_eq!(finding.level, Level::Fail);
    assert!(
        finding.message.contains("leaves 1500m of requests.cpu"),
        "{}",
        finding.message
    );
}

#[test]
fn an_over_used_quota_leaves_zero() {
    let spec = params(json!({"quota_needs": {"pods": 1}}));
    let over = active(
        vec![quota(
            "q",
            &[("pods", "10")],
            Some(&[("pods", "12")]),
            false,
        )],
        Vec::new(),
    );
    let finding = judge::judge(&spec, &over);
    assert_eq!(finding.level, Level::Fail);
    assert!(
        finding.message.contains("leaves 0 of pods"),
        "{}",
        finding.message
    );
}

#[test]
fn a_quota_that_does_not_name_the_resource_does_not_limit_it() {
    let spec = params(json!({"quota_needs": {"requests.cpu": 100}}));
    let other = active(
        vec![quota(
            "q",
            &[("limits.cpu", "2"), ("pods", "5")],
            Some(&[("limits.cpu", "2")]),
            false,
        )],
        Vec::new(),
    );
    let finding = judge::judge(&spec, &other);
    assert_eq!(finding.level, Level::Pass);
    assert!(finding.partial.is_none());
}

#[test]
fn a_scoped_quota_never_blocks() {
    let spec = params(json!({"quota_needs": {"requests.cpu": 100}}));
    let scoped = active(
        vec![quota(
            "q",
            &[("requests.cpu", "1")],
            Some(&[("requests.cpu", "1")]),
            true,
        )],
        Vec::new(),
    );
    let finding = judge::judge(&spec, &scoped);
    assert_eq!(finding.level, Level::Pass);
    assert!(finding.partial.is_some());
}

#[test]
fn a_memory_need_is_judged_in_bytes_and_shown_in_binary_units() {
    let spec = params(json!({"quota_needs": {"requests.memory": "64Gi"}}));
    let tight = active(
        vec![quota(
            "q",
            &[("requests.memory", "100Gi")],
            Some(&[("requests.memory", "50Gi")]),
            false,
        )],
        Vec::new(),
    );
    let finding = judge::judge(&spec, &tight);
    assert_eq!(finding.level, Level::Fail);
    assert!(
        finding
            .message
            .contains("leaves 50Gi of requests.memory (100Gi allowed, 50Gi used)"),
        "{}",
        finding.message
    );
    // The server may write the same size in decimal bytes.
    let bytes = active(
        vec![quota(
            "q",
            &[("requests.memory", "107374182400")],
            Some(&[("requests.memory", "53687091200")]),
            false,
        )],
        Vec::new(),
    );
    let finding = judge::judge(&spec, &bytes);
    assert_eq!(finding.level, Level::Fail);
    assert!(
        finding.message.contains("leaves 50Gi"),
        "{}",
        finding.message
    );
}

fn limit(kind: &str, max: Option<&str>, default: Option<&str>) -> Limits {
    Limits {
        name: "r".to_owned(),
        items: vec![LimitItem {
            kind: kind.to_owned(),
            memory: MemoryLimits {
                max: max.map(str::to_owned),
                min: None,
                default: default.map(str::to_owned),
            },
        }],
    }
}

#[test]
fn only_container_and_pod_items_are_judged() {
    let spec = params(json!({"limit_needs": {"container_max_memory": "16Gi"}}));
    for kind in [
        "PersistentVolumeClaim",
        "Container ",
        "container",
        "Mystery",
    ] {
        let found = active(Vec::new(), vec![limit(kind, Some("1Gi"), None)]);
        assert_eq!(judge::judge(&spec, &found).level, Level::Pass, "{kind}");
    }
    for kind in ["Container", "Pod"] {
        let found = active(Vec::new(), vec![limit(kind, Some("1Gi"), None)]);
        assert_eq!(judge::judge(&spec, &found).level, Level::Fail, "{kind}");
    }
    // A max equal to the need is enough.
    let found = active(Vec::new(), vec![limit("Container", Some("16Gi"), None)]);
    assert_eq!(judge::judge(&spec, &found).level, Level::Pass);
}

#[test]
fn a_cut_namespace_list_never_blocks_and_never_passes_quietly() {
    let spec = params(json!({"quota_needs": {"pods": 1}}));
    let mut found = active(Vec::new(), Vec::new());
    found.quotas = Some(Read::Ok(Page {
        items: Vec::new(),
        cut: true,
    }));
    let finding = judge::judge(&spec, &found);
    assert_eq!(finding.level, Level::Pass);
    assert!(finding.partial.is_some());
}

#[test]
fn every_text_the_judgement_builds_passes_the_fix_text_audit() {
    let spec = params(json!({
        "quota_needs": {"requests.cpu": 100, "pods": 1000},
        "limit_needs": {"container_max_memory": "16Gi"}
    }));
    let found = active(
        vec![quota(
            "q",
            &[("requests.cpu", "1"), ("pods", "1")],
            Some(&[("requests.cpu", "0"), ("pods", "0")]),
            false,
        )],
        vec![limit("Container", Some("1Gi"), Some("1Gi"))],
    );
    let finding = judge::judge(&spec, &found);
    assert_eq!(finding.level, Level::Fail);
    clean(&finding);
    assert!(finding.fix.is_some_and(|fix| !fix.is_empty()));
}
