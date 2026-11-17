//! Unit tests of `k8s.crds`: version reading, the Deployment projection, the verdict on one definition and
//! the fix texts.

use std::collections::BTreeMap;

use serde_json::json;

use super::fix;
use super::judge::{CrdRead, GroupState, Verdict, is_version, verdict};
use super::objects::{OperatorDeployment, Tag, Unread, image_tag, parse_tag, versions_of};
use super::split_name;

fn text(tag: &str) -> Option<String> {
    parse_tag(tag).map(|tag| tag.text())
}

#[test]
fn a_tag_is_read_as_two_to_four_numbers_and_an_optional_suffix() {
    for (tag, want) in [
        ("1.14.5", "1.14.5"),
        ("v1.14.5", "1.14.5"),
        ("1.14", "1.14"),
        ("1.14.5-ubi8", "1.14.5"),
        ("v1.14.5_debian", "1.14.5"),
        ("1.14.5+build.7", "1.14.5"),
        ("1.2.3.4", "1.2.3.4"),
        ("v1.15.0-rc.1", "1.15.0 (a pre-release)"),
        ("1.15.0-beta2", "1.15.0 (a pre-release)"),
        ("1.15.0-ALPHA", "1.15.0 (a pre-release)"),
        ("2.0.0-dev", "2.0.0 (a pre-release)"),
    ] {
        assert_eq!(text(tag).as_deref(), Some(want), "{tag}");
    }
}

#[test]
fn what_is_not_a_version_is_not_read_as_one() {
    for tag in [
        "",
        "latest",
        "main",
        "3",
        "20240101",
        "v3",
        "1.2.3.4.5",
        "1.14.5abc",
        "1..5",
        "1.14.",
        ".1.2",
        "1.14.5\u{1b}[2J",
        "sha-1234567",
        "99999999999.1",
    ] {
        assert_eq!(text(tag), None, "{tag:?}");
    }
    assert_eq!(text(&format!("1.{}", "9".repeat(300))), None);
}

#[test]
fn the_tag_of_an_image_is_after_the_last_colon_of_the_last_path_part() {
    for (image, want) in [
        (
            "registry.acme.example/acme/operator:v1.14.5",
            Some("v1.14.5"),
        ),
        ("registry.acme.example:5000/acme/operator:1.2", Some("1.2")),
        ("registry.acme.example:5000/acme/operator", None),
        ("operator", None),
        ("operator:1.2", Some("1.2")),
        ("registry.acme.example/acme/operator@sha256:abcd", None),
        (
            "registry.acme.example/acme/operator:1.2@sha256:abcd",
            Some("1.2"),
        ),
        ("", None),
    ] {
        assert_eq!(image_tag(image), want, "{image}");
    }
}

fn deployment(containers: serde_json::Value, label: Option<&str>) -> OperatorDeployment {
    let mut labels = json!({"app.kubernetes.io/name": "acme-operator"});
    if let Some(label) = label {
        labels["app.kubernetes.io/version"] = json!(label);
    }
    serde_json::from_value(json!({
        "metadata": {"name": "acme-operator", "namespace": "acme-system", "labels": labels},
        "spec": {"replicas": 2, "template": {"spec": {"containers": containers}}},
        "status": {"readyReplicas": 1},
    }))
    .expect("a Deployment")
}

#[test]
fn the_operator_container_is_the_one_named_like_the_deployment() {
    let d = deployment(
        json!([
            {"name": "proxy", "image": "registry.acme.example/proxy:v0.15.0"},
            {"name": "acme-operator", "image": "registry.acme.example/op:v1.14.5"},
        ]),
        None,
    );
    let v = versions_of(&d, "acme-operator");
    assert_eq!(v.best().map(Tag::text).as_deref(), Some("1.14.5"));
    assert!(!v.ambiguous);
}

#[test]
fn two_containers_with_the_same_version_agree() {
    let d = deployment(
        json!([
            {"name": "manager", "image": "registry.acme.example/op:v1.14.5"},
            {"name": "webhook", "image": "registry.acme.example/hook:v1.14.5"},
        ]),
        None,
    );
    let v = versions_of(&d, "acme-operator");
    assert_eq!(v.best().map(Tag::text).as_deref(), Some("1.14.5"));
    assert!(!v.ambiguous);
}

#[test]
fn two_containers_with_two_versions_are_ambiguous_and_the_label_decides() {
    let containers = json!([
        {"name": "manager", "image": "registry.acme.example/op:v1.14.5"},
        {"name": "proxy", "image": "registry.acme.example/proxy:v0.15.0"},
    ]);
    let v = versions_of(&deployment(containers.clone(), None), "acme-operator");
    assert!(v.ambiguous);
    assert!(v.best().is_none());
    let v = versions_of(&deployment(containers, Some("1.14.5")), "acme-operator");
    assert_eq!(v.best().map(Tag::text).as_deref(), Some("1.14.5"));
}

#[test]
fn a_deployment_keeps_only_what_the_check_reads() {
    let d: OperatorDeployment = serde_json::from_value(json!({
        "metadata": {
            "name": "acme-operator",
            "namespace": "acme-system",
            "labels": {
                "app.kubernetes.io/version": "1.14.5",
                "app.kubernetes.io/name": "MARKER-LABEL-0001",
            },
            "annotations": {
                "kubectl.kubernetes.io/last-applied-configuration": "MARKER-ANNOTATION-1",
            },
            "managedFields": [{"manager": "MARKER-MANAGED-2"}],
            "ownerReferences": [{"name": "MARKER-OWNER-3"}],
        },
        "spec": {
            "replicas": 3,
            "template": {"spec": {"containers": [{
                "name": "acme-operator",
                "image": "registry.acme.example/op:v1.14.5",
                "env": [{"name": "TOKEN", "value": "MARKER-ENV-4"}],
                "args": ["--token=MARKER-ARG-5"],
            }]}},
        },
        "status": {"readyReplicas": 2, "conditions": [{"message": "MARKER-STATUS-6"}]},
    }))
    .expect("a Deployment");
    assert_eq!((d.desired, d.ready), (3, 2));
    assert_eq!(d.label(), Some("1.14.5"));
    let shown = format!("{d:?}");
    for marker in [
        "MARKER-LABEL",
        "MARKER-ANNOTATION",
        "MARKER-MANAGED",
        "MARKER-OWNER",
        "MARKER-ENV",
        "MARKER-ARG",
        "MARKER-STATUS",
    ] {
        assert!(!shown.contains(marker), "{marker} is held: {shown}");
    }
    assert!(!shown.contains("annotations: Some"), "{shown}");
}

#[test]
fn replicas_default_to_one_and_ready_to_zero() {
    let d: OperatorDeployment =
        serde_json::from_value(json!({"metadata": {"name": "x"}})).expect("a Deployment");
    assert_eq!((d.desired, d.ready), (1, 0));
    assert!(d.containers.is_empty());
}

#[test]
fn an_api_version_has_the_shape_of_one() {
    for good in ["v1", "v2", "v1beta1", "v1alpha12", "v10"] {
        assert!(is_version(good), "{good}");
    }
    for bad in [
        "",
        "v",
        "1",
        "vbeta",
        "v1beta",
        "v1gamma1",
        "v1\u{1b}",
        "v1beta12345",
        "V1",
    ] {
        assert!(!is_version(bad), "{bad:?}");
    }
}

#[test]
fn a_name_is_split_at_its_first_dot() {
    assert_eq!(
        split_name("certificates.cert-manager.io"),
        Some(("certificates".to_owned(), "cert-manager.io".to_owned()))
    );
    assert_eq!(split_name("certificates"), None);
    assert_eq!(split_name(".io"), None);
    assert_eq!(split_name("a."), None);
}

fn read(wanted: &[&str], group: GroupState, listed: &[(&str, Result<bool, Unread>)]) -> CrdRead {
    CrdRead {
        name: "certificates.pki.acme.example".to_owned(),
        split: Some(("certificates".to_owned(), "pki.acme.example".to_owned())),
        wanted: wanted.iter().map(|v| (*v).to_owned()).collect(),
        group,
        listed: listed
            .iter()
            .map(|(v, got)| ((*v).to_owned(), *got))
            .collect(),
    }
}

fn served(versions: &[&str]) -> GroupState {
    GroupState::Served(versions.iter().map(|v| (*v).to_owned()).collect())
}

#[test]
fn the_verdict_on_one_definition() {
    let v1 = |got| ("v1", got);
    assert_eq!(
        verdict(&read(&["v1"], GroupState::Absent, &[])),
        Verdict::GroupMissing
    );
    assert_eq!(
        verdict(&read(&["v1"], served(&["v1"]), &[v1(Ok(true))])),
        Verdict::Served(vec!["v1".to_owned()])
    );
    assert_eq!(
        verdict(&read(&["v1"], served(&["v1"]), &[v1(Ok(false))])),
        Verdict::NotInGroup
    );
    assert_eq!(
        verdict(&read(
            &["v1"],
            served(&["v1", "v1beta1"]),
            &[v1(Ok(false)), ("v1beta1", Ok(true))]
        )),
        Verdict::VersionsMissing {
            missing: vec!["v1".to_owned()],
            served: vec!["v1beta1".to_owned()]
        }
    );
    assert_eq!(
        verdict(&read(
            &["v1"],
            served(&["v1"]),
            &[v1(Err(Unread::Forbidden))]
        )),
        Verdict::Unverified(Unread::Forbidden)
    );
    assert_eq!(
        verdict(&read(&["v1"], GroupState::Unread(Unread::Time), &[])),
        Verdict::Unverified(Unread::Time)
    );
    // A block stands even when another wanted version could not be read.
    assert!(matches!(
        verdict(&read(
            &["v1", "v2"],
            served(&["v1"]),
            &[v1(Err(Unread::Status(500)))]
        )),
        Verdict::VersionsMissing { .. }
    ));
    // Any version: the first one that lists it is enough, and a version that was not read is not a block.
    assert_eq!(
        verdict(&read(
            &[],
            served(&["v1", "v1beta1"]),
            &[v1(Err(Unread::Budget))]
        )),
        Verdict::Unverified(Unread::Budget)
    );
    assert_eq!(
        verdict(&read(
            &[],
            served(&["v1", "v1beta1"]),
            &[v1(Ok(false)), ("v1beta1", Ok(false))]
        )),
        Verdict::NotInGroup
    );
}

#[test]
fn every_fix_text_is_on_the_allow_list_and_has_no_em_dash() {
    let texts = [
        fix::install("cert-manager.io"),
        fix::install("pki.acme.example"),
        fix::upgrade("pki.acme.example"),
        fix::operator_missing("acme-system", "acme-operator"),
        fix::operator_not_ready("acme-system", "acme-operator", 0),
        fix::operator_not_ready("acme-system", "acme-operator", 2),
        fix::operator_old("acme-system", "acme-operator"),
        fix::check_version("acme-system", "acme-operator"),
        fix::crd_name().to_owned(),
        fix::grants(
            &["`kubectl auth can-i get /apis`".to_owned()],
            &["get /apis".to_owned()],
        ),
    ];
    for text in texts {
        if let Err(error) = rdy_engine::fixtext::check(&text) {
            panic!("{error}\n{text}");
        }
        assert!(!text.contains('\u{2014}'), "{text}");
    }
}

#[test]
fn the_cert_manager_fix_names_both_chart_flags_and_the_public_source() {
    let fix = fix::install("cert-manager.io");
    assert!(fix.starts_with(
        "The cert-manager CRDs are missing. Install the chart from your registry or mirror:"
    ));
    assert!(fix.contains("`helm install cert-manager <chart> -n cert-manager --create-namespace --set crds.enabled=true`"));
    assert!(fix.contains("older charts use `installCRDs=true`"));
    assert!(fix.contains("`helm repo add jetstack https://charts.jetstack.io`"));
    assert!(fix.contains("air-gapped"));
}

#[test]
fn the_unread_phrases() {
    let all: BTreeMap<String, Unread> = [
        ("forbidden", Unread::Forbidden),
        ("status", Unread::Status(500)),
        ("refused", Unread::Refused),
        ("time", Unread::Time),
        ("budget", Unread::Budget),
    ]
    .into_iter()
    .map(|(k, v)| (k.to_owned(), v))
    .collect();
    assert_eq!(all["status"].why(), "the server answered 500");
    for why in all.values() {
        assert!(!why.why().is_empty());
    }
}
