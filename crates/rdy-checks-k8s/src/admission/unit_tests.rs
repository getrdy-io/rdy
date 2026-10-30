//! Unit tests of `k8s.admission`: the pure parts, with no cluster and no mock. The fixture tests in
//! `tests.rs` run the whole check.

use std::collections::BTreeMap;

use rdy_engine::check::{Finding, Level};
use serde_json::{Value, json};

use super::engines::{self, Found, FoundGroup};
use super::judge::{Gathered, NsFacts, Openshift, judge, shown};
use super::level::{Label, Labels, Need, Standard, Version, need_of};
use super::scc::uid_range;
use super::*;

fn params(spec: Value) -> K8sAdmission {
    serde_json::from_value(spec).expect("the parameters parse")
}

fn labels(pairs: &[(&str, &str)]) -> Labels {
    let map: BTreeMap<String, String> = pairs
        .iter()
        .map(|(k, v)| ((*k).to_owned(), (*v).to_owned()))
        .collect();
    Labels::from_map(&map)
}

fn clean(finding: &Finding) {
    for text in finding.fix.iter().chain(&finding.notes) {
        if let Err(error) = rdy_engine::fixtext::check(text) {
            panic!("fix text breaks the allow-list: {error}\n{text}");
        }
    }
}

/// A gathered cluster with a readable namespace and nothing else found.
fn plain(facts: NsFacts) -> Gathered {
    Gathered {
        namespace: Some("acme".to_owned()),
        ns: Some(Read::Ok(facts)),
        groups: Read::Ok(()),
        openshift: Openshift::No,
        engines: Vec::new(),
        scc: None,
        rke2: false,
    }
}

fn facts(pairs: &[(&str, &str)]) -> NsFacts {
    NsFacts {
        labels: labels(pairs),
        uid_range: None,
        label_sync_off: false,
    }
}

// ---- the level the product needs ----------------------------------------------------------------------------

fn need(spec: Value) -> Option<Need> {
    need_of(&params(spec))
}

#[test]
fn the_level_comes_from_the_most_permissive_thing_the_spec_says() {
    let cases = [
        (json!({}), None),
        (json!({"namespace": "acme"}), None),
        (
            json!({"pod_security": "privileged"}),
            Some(Standard::Privileged),
        ),
        (
            json!({"pod_security": "baseline"}),
            Some(Standard::Baseline),
        ),
        (
            json!({"pod_security": "restricted"}),
            Some(Standard::Restricted),
        ),
        (json!({"uses": ["hostPath"]}), Some(Standard::Privileged)),
        (json!({"uses": ["hostNetwork"]}), Some(Standard::Privileged)),
        (json!({"uses": ["hostPID"]}), Some(Standard::Privileged)),
        (json!({"uses": ["privileged"]}), Some(Standard::Privileged)),
        (json!({"uses": ["runAsRoot"]}), Some(Standard::Baseline)),
        (
            json!({"uses": ["runAsRoot", "hostPath"]}),
            Some(Standard::Privileged),
        ),
        // The spec contradicts itself: the weaker need would be a wrong pass.
        (
            json!({"pod_security": "baseline", "uses": ["hostPath"]}),
            Some(Standard::Privileged),
        ),
        (
            json!({"pod_security": "privileged", "uses": ["runAsRoot"]}),
            Some(Standard::Privileged),
        ),
        (
            json!({"pod_security": "restricted", "uses": ["runAsRoot"]}),
            Some(Standard::Baseline),
        ),
    ];
    for (spec, want) in cases {
        assert_eq!(need(spec.clone()).map(|need| need.level), want, "{spec}");
    }
}

#[test]
fn the_reason_names_only_the_features_that_force_the_level() {
    let both = need(json!({"uses": ["runAsRoot", "hostPath", "privileged"]})).expect("a need");
    assert_eq!(both.level, Standard::Privileged);
    assert_eq!(both.because, ["hostPath volumes", "privileged containers"]);
    assert_eq!(both.uses, ["runAsRoot", "hostPath", "privileged"]);
    let stated =
        need(json!({"pod_security": "privileged", "uses": ["runAsRoot"]})).expect("a need");
    assert!(
        stated.because.is_empty(),
        "the level is the spec's own word"
    );
}

#[test]
fn levels_are_ordered_by_strictness() {
    assert!(Standard::Privileged < Standard::Baseline);
    assert!(Standard::Baseline < Standard::Restricted);
}

// ---- the labels ---------------------------------------------------------------------------------------------

#[test]
fn labels_are_read_the_way_the_admission_plugin_reads_them() {
    let p = "pod-security.kubernetes.io/";
    let l = labels(&[
        (&format!("{p}enforce"), "baseline"),
        (&format!("{p}audit"), "restricted"),
        (&format!("{p}warn"), "privileged"),
        (&format!("{p}enforce-version"), "v1.29"),
    ]);
    assert_eq!(l.enforce, Label::Valid(Standard::Baseline));
    assert_eq!(l.audit, Label::Valid(Standard::Restricted));
    assert_eq!(l.warn, Label::Valid(Standard::Privileged));
    assert_eq!(l.enforce_version, Version::Minor(29));
    // Case matters and so does every byte.
    for bad in [
        "Baseline",
        "BASELINE",
        " baseline",
        "baseline ",
        "",
        "strict",
        "baseline\n",
    ] {
        let l = labels(&[(&format!("{p}enforce"), bad)]);
        assert_eq!(l.enforce, Label::Invalid, "{bad:?}");
    }
    // A label of another prefix is not one of ours.
    let other = labels(&[("pod-security.example/enforce", "baseline")]);
    assert_eq!(other.enforce, Label::Absent);
    assert_eq!(labels(&[]).enforce, Label::Absent);
}

#[test]
fn the_version_label_is_latest_or_v1_n() {
    let p = "pod-security.kubernetes.io/enforce-version";
    let cases = [
        ("latest", Version::Latest),
        ("v1.0", Version::Minor(0)),
        ("v1.30", Version::Minor(30)),
        ("v1.030", Version::Invalid),
        ("v1.", Version::Invalid),
        ("v1.x", Version::Invalid),
        ("v2.1", Version::Invalid),
        ("1.30", Version::Invalid),
        ("v1.99999999999999999999", Version::Invalid),
        ("Latest", Version::Invalid),
    ];
    for (value, want) in cases {
        assert_eq!(labels(&[(p, value)]).enforce_version, want, "{value}");
    }
    assert_eq!(labels(&[]).enforce_version, Version::Absent);
    assert_eq!(Version::Minor(7).word().as_deref(), Some("v1.7"));
    assert_eq!(Version::Absent.word(), None);
}

#[test]
fn a_range_annotation_has_two_numbers() {
    assert_eq!(
        uid_range("1000680000/10000").as_deref(),
        Some("1000680000/10000")
    );
    assert_eq!(uid_range("1/1").as_deref(), Some("1/1"));
    for bad in [
        "",
        "1000680000",
        "1000680000/",
        "/10000",
        "1000680000/0",
        "a/b",
        "1/2/3",
        "-1/10",
        "1000680000/10000; rm",
        "12345678901/1",
        "1 /1",
        "1\u{1b}/1",
    ] {
        assert_eq!(uid_range(bad), None, "{bad:?}");
    }
}

// ---- engines ------------------------------------------------------------------------------------------------

#[test]
fn the_groups_of_an_engine_are_found_by_name() {
    let groups: Vec<(String, Option<String>)> = [
        "apps",
        "policies.kyverno.io",
        "constraints.gatekeeper.sh",
        "gatekeeper.sh",
        "x.kyverno.io",
    ]
    .iter()
    .map(|name| ((*name).to_owned(), Some("v1".to_owned())))
    .collect();
    assert_eq!(
        engines::served(&groups),
        [
            ("Kyverno", "policies.kyverno.io"),
            ("Gatekeeper", "constraints.gatekeeper.sh"),
        ]
    );
    assert!(engines::served(&[]).is_empty());
}

#[test]
fn kinds_are_sorted_without_repeats_and_cut_at_eight() {
    let (kinds, more) = engines::cut_kinds(
        ["b", "a", "", "b", "c", "d", "e", "f", "g", "h", "i", "j"]
            .iter()
            .map(|kind| (*kind).to_owned())
            .collect(),
    );
    assert_eq!(kinds, ["a", "b", "c", "d", "e", "f", "g", "h"]);
    assert_eq!(more, 2);
    assert_eq!(engines::cut_kinds(Vec::new()), (Vec::new(), 0));
}

#[test]
fn names_shaped_like_kinds_sort_ahead_of_hostile_ones() {
    let mut kinds: Vec<String> = ["A\u{202e}B", "`x`", "\u{1b}[2J", "AKind"]
        .iter()
        .map(|kind| (*kind).to_owned())
        .collect();
    kinds.extend((0..8).map(|n| format!("K8sCheck{n}")));
    let (shown_kinds, more) = engines::cut_kinds(kinds);
    assert_eq!(more, 4);
    assert!(
        shown_kinds
            .iter()
            .all(|kind| kind.bytes().all(|b| b.is_ascii_alphanumeric())),
        "{shown_kinds:?}"
    );
    assert_eq!(shown_kinds[0], "AKind");
}

#[test]
fn the_legacy_kyverno_kinds_are_found_before_the_cut() {
    assert!(engines::has_legacy_policies(&["Policy".to_owned()]));
    assert!(engines::has_legacy_policies(&[
        "PolicyException".to_owned(),
        "ClusterPolicy".to_owned()
    ]));
    assert!(!engines::has_legacy_policies(&[
        "PolicyException".to_owned(),
        "CleanupPolicy".to_owned()
    ]));
}

#[test]
fn a_server_text_is_made_safe_before_it_reaches_a_sentence() {
    assert_eq!(shown("ClusterPolicy"), "ClusterPolicy");
    assert_eq!(shown("a`b`"), "a'b'");
    assert_eq!(shown("x\u{1b}[31m"), "x\\x1b[31m");
    assert_eq!(shown("a\u{202e}b"), "a\\u{202e}b");
    let long = "a".repeat(200);
    let text = shown(&long);
    assert_eq!(text.len(), 67, "64 characters and an ellipsis");
    assert!(text.ends_with("..."));
}

// ---- judging, without a cluster -----------------------------------------------------------------------------

#[test]
fn a_cluster_that_says_nothing_found_passes() {
    let finding = judge(
        &params(json!({"pod_security": "restricted"})),
        need(json!({"pod_security": "restricted"})).as_ref(),
        &plain(facts(&[])),
    );
    assert_eq!(finding.level, Level::Pass, "{finding:?}");
    assert!(finding.partial.is_none());
    assert!(finding.fix.is_none());
    clean(&finding);
}

#[test]
fn the_worst_finding_is_the_message_and_the_rest_are_notes() {
    let mut gathered = plain(facts(&[(
        "pod-security.kubernetes.io/enforce",
        "restricted",
    )]));
    gathered.engines = vec![Found {
        engine: "Kyverno",
        groups: vec![FoundGroup {
            group: "kyverno.io",
            version: Some("v1".to_owned()),
            kinds: vec!["ClusterPolicy".to_owned()],
            more: 0,
            legacy_policies: true,
        }],
    }];
    let spec = json!({"uses": ["hostPath"]});
    let finding = judge(&params(spec.clone()), need(spec).as_ref(), &gathered);
    assert_eq!(finding.level, Level::Fail, "{finding:?}");
    assert!(
        finding
            .message
            .starts_with("Namespace acme enforces restricted"),
        "{}",
        finding.message
    );
    assert!(
        finding.message.ends_with("(and 1 more, see the notes)"),
        "{}",
        finding.message
    );
    assert!(
        finding
            .notes
            .iter()
            .any(|note| note.starts_with("Policy engine found: Kyverno (kyverno.io)")),
        "{finding:?}"
    );
    // Both fixes are there, the block first.
    let fix = finding.fix.clone().expect("a fix");
    let label = fix.find("kubectl label ns acme").expect("label fix");
    let list = fix
        .find("which Kyverno policies apply")
        .expect("engine fix");
    assert!(label < list, "{fix}");
    clean(&finding);
}

#[test]
fn an_unreadable_namespace_with_a_read_group_list_is_partial_with_one_grant() {
    let mut gathered = plain(facts(&[]));
    gathered.ns = Some(Read::Forbidden);
    let spec = json!({"pod_security": "baseline"});
    let finding = judge(&params(spec.clone()), need(spec).as_ref(), &gathered);
    assert_eq!(finding.level, Level::Pass);
    let partial = finding.partial.expect("partial");
    assert_eq!(partial.missing_grants, ["get namespaces"]);
    assert!(partial.missing.is_empty());
}

#[test]
fn every_unreadable_thing_is_listed_once_in_the_note() {
    let mut gathered = plain(facts(&[]));
    gathered.ns = Some(Read::Forbidden);
    gathered.groups = Read::Forbidden;
    gathered.openshift = Openshift::Unknown;
    let spec = json!({"pod_security": "baseline"});
    let finding = judge(&params(spec.clone()), need(spec).as_ref(), &gathered);
    let partial = finding.partial.clone().expect("partial");
    assert_eq!(partial.missing_grants, ["get namespaces", "get /apis"]);
    assert_eq!(
        partial.note.matches("were not read").count(),
        1,
        "{partial:?}"
    );
    assert!(partial.note.contains("not checked"), "{partial:?}");
    let fix = finding.fix.clone().expect("a fix");
    assert!(
        fix.contains("grant this identity: get namespaces, get /apis. Check each with `kubectl auth can-i get namespaces`, `kubectl auth can-i get /apis`."),
        "{fix}"
    );
    clean(&finding);
}

#[test]
fn a_group_list_that_ran_out_of_time_is_not_a_grant() {
    let mut gathered = plain(facts(&[]));
    gathered.groups = Read::OutOfTime;
    gathered.openshift = Openshift::Unknown;
    let finding = judge(&params(json!({})), None, &gathered);
    let partial = finding.partial.expect("partial");
    assert!(partial.missing_grants.is_empty());
    assert!(partial.note.contains("rdy ran out of time"), "{partial:?}");
}

#[test]
fn the_unread_namespace_other_than_forbidden_is_partial_without_a_grant() {
    for read in [Read::Unreadable(500), Read::Cut, Read::OutOfTime] {
        let mut gathered = plain(facts(&[]));
        gathered.ns = Some(read);
        let spec = json!({"pod_security": "baseline"});
        let finding = judge(&params(spec.clone()), need(spec).as_ref(), &gathered);
        let partial = finding.partial.expect("partial");
        assert!(partial.missing_grants.is_empty(), "{partial:?}");
        assert!(partial.note.contains("were not read"), "{partial:?}");
    }
}

#[test]
fn the_text_never_holds_the_spec_s_free_text_as_a_command_unchecked() {
    // The namespace is a Kubernetes name from the spec, which rdy-spec has already checked, so a fix that
    // names it passes the allow-list for any such name.
    for name in ["a", "acme-system", "a.b-c", "x1"] {
        let mut gathered = plain(facts(&[(
            "pod-security.kubernetes.io/enforce",
            "restricted",
        )]));
        gathered.namespace = Some(name.to_owned());
        let spec = json!({"uses": ["privileged"]});
        let finding = judge(&params(spec.clone()), need(spec).as_ref(), &gathered);
        clean(&finding);
        assert!(
            finding
                .fix
                .expect("a fix")
                .contains(&format!("kubectl label ns {name} ")),
        );
    }
}

#[test]
fn the_observed_value_is_complete_for_a_found_namespace() {
    let finding = judge(
        &params(json!({"pod_security": "baseline", "namespace": "acme"})),
        need(json!({"pod_security": "baseline"})).as_ref(),
        &plain(facts(&[("pod-security.kubernetes.io/enforce", "baseline")])),
    );
    assert_eq!(
        finding.observed,
        json!({
            "namespace": "acme",
            "namespace_read": "read",
            "pod_security": {"enforce": "baseline", "audit": "none", "warn": "none", "enforce_version": null},
            "need": {"level": "baseline", "uses": []},
            "openshift": false,
            "uid_range": null,
            "scc_on_cluster": null,
            "policy_engines": [],
        })
    );
    assert_eq!(
        finding.expected,
        json!({"needs_level": "baseline", "namespace": "acme", "scc": null})
    );
}
