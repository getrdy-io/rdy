//! Unit tests of `k8s.storageclass`: the pure parts, with no cluster and no mock. The fixture tests in
//! `tests.rs` run the whole check.

use k8s_openapi::api::core::v1::PersistentVolumeClaim;
use k8s_openapi::api::storage::v1::StorageClass;
use k8s_openapi::jiff::Timestamp;
use rdy_engine::check::{Finding, Level};
use rdy_spec::check::AccessMode::{ReadOnlyMany, ReadWriteMany, ReadWriteOnce, ReadWriteOncePod};
use rdy_spec::check::{AccessMode, K8sStorageClass};
use serde_json::{Value, json};

use super::facts::{
    Binding, Class, Page, Read, Reclaim, Waiting, command_arg, pending_claims, token,
};
use super::judge::{
    Chosen, Classes, Evidence, Grant, How, Nodes, Object, Support, Unread, Verdict, judge_driver,
    judge_modes, judge_settings, judge_waiting, mode_support, select,
};
use super::*;
use crate::provisioners::Catalog;

fn catalog() -> &'static Catalog {
    Catalog::shipped().expect("the shipped table parses")
}

fn params(spec: Value) -> K8sStorageClass {
    serde_json::from_value(spec).expect("the parameters parse")
}

fn class(name: &str, provisioner: &str, default: bool, created: &str) -> Class {
    Class {
        name: name.to_owned(),
        provisioner: provisioner.to_owned(),
        default,
        created: Some(created.parse().expect("a time")),
        binding: Binding::WaitForFirstConsumer,
        expansion: false,
        reclaim: Reclaim::Delete,
    }
}

fn page(items: Vec<Class>, more: bool) -> Classes {
    Classes::Listed(Page { items, more })
}

fn clean(finding: &Finding) {
    for text in finding.fix.iter().chain(&finding.notes) {
        if let Err(error) = rdy_engine::fixtext::check(text) {
            panic!("fix text breaks the allow-list: {error}\n{text}");
        }
    }
}

// ---- small helpers ------------------------------------------------------------------------------------------

#[test]
fn a_server_text_is_made_safe_before_it_reaches_a_sentence_or_a_command() {
    let cases = [
        ("gp3", "gp3"),
        ("kubernetes.io/aws-ebs", "kubernetes.io/aws-ebs"),
        ("a b", "a?b"),
        ("`rm -rf /`", "?rm?-rf?/?"),
        ("x\u{1b}[31m", "x??31m"),
        ("a\u{202e}b", "a?b"),
        ("caf\u{e9}", "caf?"),
        ("", ""),
    ];
    for (input, want) in cases {
        assert_eq!(token(input), want, "{input:?}");
    }
    let long = "a".repeat(200);
    let shown = token(&long);
    assert_eq!(shown.len(), 67, "64 characters and an ellipsis");
    assert!(shown.ends_with("..."));
}

#[test]
fn only_an_untruncated_object_name_goes_into_a_command() {
    let long = "a".repeat(100);
    let edge = "a".repeat(64);
    for good in [
        "gp3",
        "managed-csi",
        "acme.fast-ssd",
        "a",
        "0",
        edge.as_str(),
    ] {
        assert_eq!(command_arg(good, "<class>"), good);
    }
    for bad in [
        "--server",
        "--insecure-skip-tls-verify",
        "-n",
        "gp3-",
        "GP3",
        "a_b",
        "a b",
        "a..b",
        ".a",
        "a.",
        "a/b",
        "",
        "x`;rm",
        long.as_str(),
        "a\u{e9}",
    ] {
        assert_eq!(command_arg(bad, "<class>"), "<class>", "{bad:?}");
    }
    // 64 characters is what `token` shows whole; one more is cut, so it never names a real object.
    assert_eq!(command_arg(&"a".repeat(65), "<claim>"), "<claim>");
}

#[test]
fn the_server_version_is_read_from_the_git_version_then_from_major_and_minor() {
    let read = |git: &str, major: &str, minor: &str| {
        server_minor(&ServerVersion {
            git_version: git.to_owned(),
            major: major.to_owned(),
            minor: minor.to_owned(),
            platform: String::new(),
        })
    };
    assert_eq!(read("v1.29.4-eks-abc123", "1", "29+"), Some((1, 29)));
    assert_eq!(read("v1.30.0+k3s1", "1", "30"), Some((1, 30)));
    assert_eq!(read("v1.27.8+3f8e0c1", "1", "27"), Some((1, 27)));
    assert_eq!(read("1.25.0", "1", "25"), Some((1, 25)));
    // The git version is garbage: major and minor, with the `+` some distributions add.
    assert_eq!(read("", "1", "29+"), Some((1, 29)));
    assert_eq!(read("dev", "1", "28"), Some((1, 28)));
    assert_eq!(read("dev", "", ""), None);
    assert_eq!(read("v1", "1", ""), None);
    assert_eq!(read("v.2", "x", "y"), None);
}

// ---- reading a class --------------------------------------------------------------------------------------------

fn object(value: Value) -> StorageClass {
    serde_json::from_value(value).expect("a StorageClass")
}

#[test]
fn a_class_is_read_with_the_defaults_the_api_server_uses() {
    let bare = Class::from_object(&object(json!({
        "metadata": {"name": "bare"}, "provisioner": "csi.acme.example"
    })))
    .expect("a class");
    assert!(!bare.default);
    assert_eq!(bare.binding, Binding::Immediate);
    assert_eq!(bare.reclaim, Reclaim::Delete);
    assert!(!bare.expansion);
    assert_eq!(bare.created, None);

    let full = Class::from_object(&object(json!({
        "metadata": {"name": "full", "creationTimestamp": "2026-01-01T00:00:00Z"},
        "provisioner": "csi.acme.example",
        "volumeBindingMode": "WaitForFirstConsumer",
        "reclaimPolicy": "Retain",
        "allowVolumeExpansion": true,
    })))
    .expect("a class");
    assert_eq!(full.binding, Binding::WaitForFirstConsumer);
    assert_eq!(full.reclaim, Reclaim::Retain);
    assert!(full.expansion);
    assert!(full.created.is_some());

    let odd = Class::from_object(&object(json!({
        "metadata": {"name": "odd"}, "provisioner": "x", "reclaimPolicy": "Recycle",
        "volumeBindingMode": "Something"
    })))
    .expect("a class");
    assert_eq!(odd.reclaim, Reclaim::Other);
    assert_eq!(odd.binding, Binding::Immediate);

    assert!(
        Class::from_object(&object(json!({"metadata": {}, "provisioner": "x"}))).is_none(),
        "a class with no name is dropped"
    );
}

#[test]
fn only_the_value_true_marks_a_default_in_either_annotation() {
    let default = |annotations: Value| {
        Class::from_object(&object(json!({
            "metadata": {"name": "c", "annotations": annotations}, "provisioner": "x"
        })))
        .expect("a class")
        .default
    };
    assert!(default(
        json!({"storageclass.kubernetes.io/is-default-class": "true"})
    ));
    assert!(default(
        json!({"storageclass.beta.kubernetes.io/is-default-class": "true"})
    ));
    assert!(!default(
        json!({"storageclass.kubernetes.io/is-default-class": "false"})
    ));
    assert!(!default(
        json!({"storageclass.kubernetes.io/is-default-class": "True"})
    ));
    assert!(!default(
        json!({"storageclass.kubernetes.io/is-default-class": ""})
    ));
    assert!(!default(json!({"other": "true"})));
}

// ---- choosing a class --------------------------------------------------------------------------------------------

fn selected(
    classes: &Classes,
    spec: Value,
    server: Option<(u64, u64)>,
) -> (Option<Chosen>, Finding) {
    let params = params(spec);
    let mut verdict = Verdict::new();
    let chosen = select(&mut verdict, &params, classes, server);
    (chosen, verdict.finish(&params))
}

#[test]
fn two_defaults_made_at_the_same_second_are_ordered_by_name() {
    let classes = page(
        vec![
            class("b", "csi.acme.example", true, "2026-01-01T00:00:00Z"),
            class("a", "csi.acme.example", true, "2026-01-01T00:00:00Z"),
            class("c", "csi.acme.example", true, "2025-12-31T00:00:00Z"),
        ],
        false,
    );
    let (chosen, finding) = selected(&classes, json!({}), Some((1, 30)));
    assert_eq!(chosen.expect("chosen").class.name, "a");
    assert_eq!(finding.level, Level::Warn);
    assert!(finding.message.contains("(a, b, c)"), "{}", finding.message);
}

#[test]
fn a_class_with_no_creation_time_is_the_oldest() {
    let mut old = class("old", "csi.acme.example", true, "2026-01-01T00:00:00Z");
    old.created = None;
    let new = class("new", "csi.acme.example", true, "2026-01-01T00:00:00Z");
    let (chosen, _) = selected(&page(vec![old, new], false), json!({}), Some((1, 30)));
    assert_eq!(chosen.expect("chosen").class.name, "new");
}

#[test]
fn a_named_class_ignores_which_classes_are_the_default() {
    let classes = page(
        vec![
            class("a", "csi.acme.example", true, "2026-01-01T00:00:00Z"),
            class("b", "csi.acme.example", true, "2026-01-02T00:00:00Z"),
            class("c", "csi.acme.example", false, "2026-01-03T00:00:00Z"),
        ],
        false,
    );
    let (chosen, finding) = selected(&classes, json!({"class": "c"}), Some((1, 25)));
    let chosen = chosen.expect("chosen");
    assert_eq!((chosen.class.name.as_str(), chosen.how), ("c", How::Named));
    // Two defaults do not matter when the product names its class.
    assert_eq!(finding.level, Level::Pass);
}

#[test]
fn nothing_chosen_when_the_class_list_could_not_be_read() {
    for (read, grant) in [
        (
            Read::Forbidden,
            Some("list storageclasses (storage.k8s.io)"),
        ),
        (Read::Unreadable(500), None),
        (Read::Missing, None),
    ] {
        let (chosen, finding) = selected(&Classes::NoList(read), json!({}), Some((1, 30)));
        assert!(chosen.is_none());
        assert_eq!(finding.level, Level::Warn);
        let wire: Vec<String> = finding
            .partial
            .as_ref()
            .map(|p| p.missing_grants.clone())
            .unwrap_or_default();
        assert_eq!(
            wire,
            grant.map(str::to_owned).into_iter().collect::<Vec<_>>()
        );
        clean(&finding);
    }
}

#[test]
fn a_hostile_class_name_never_becomes_a_flag_or_a_missing_object_in_a_command() {
    let long = "c".repeat(100);
    for name in ["--server", "--insecure-skip-tls-verify", long.as_str()] {
        // Two defaults: the fix unmarks the one that is not kept.
        let classes = page(
            vec![
                class("zz-keep", "csi.acme.example", true, "2026-03-01T00:00:00Z"),
                class(name, "csi.acme.example", true, "2026-01-01T00:00:00Z"),
            ],
            false,
        );
        let (_, finding) = selected(&classes, json!({}), Some((1, 30)));
        let fix = finding.fix.clone().expect("a fix");
        assert!(
            fix.contains("kubectl patch storageclass <class> -p"),
            "{fix}"
        );
        assert!(!fix.contains("--server"), "{fix}");
        assert!(!fix.contains("--insecure"), "{fix}");
        assert!(!fix.contains(&"c".repeat(65)), "{fix}");
        clean(&finding);

        // No default: the fix marks a class, and the class is a hostile one.
        let one = page(
            vec![class(
                name,
                "csi.acme.example",
                false,
                "2026-01-01T00:00:00Z",
            )],
            false,
        );
        let (_, finding) = selected(&one, json!({}), Some((1, 30)));
        let fix = finding.fix.clone().expect("a fix");
        assert!(
            fix.contains("kubectl patch storageclass <class> -p"),
            "{fix}"
        );
        assert!(!fix.contains("--server"), "{fix}");
    }
    // A real name still goes through.
    let one = page(
        vec![class(
            "managed-csi",
            "csi.acme.example",
            false,
            "2026-01-01T00:00:00Z",
        )],
        false,
    );
    let (_, finding) = selected(&one, json!({}), Some((1, 30)));
    assert!(
        finding
            .fix
            .expect("a fix")
            .contains("kubectl patch storageclass managed-csi -p")
    );
}

#[test]
fn a_hostile_name_in_the_other_fixes_is_a_placeholder_too() {
    let long = "d".repeat(100);
    for name in ["--server", long.as_str()] {
        let texts = [
            fix::rebind(name, "WaitForFirstConsumer"),
            fix::allow_expansion(name),
            fix::reclaim(name, "Retain"),
            fix::failing_claims(name, name),
            fix::unmark_defaults(&[name.to_owned()]),
            fix::mark_default(name),
        ];
        for text in texts {
            assert!(
                text.contains("<class>") || text.contains("<claim>"),
                "{text}"
            );
            assert!(
                !text.contains("--server") && !text.contains(&"d".repeat(65)),
                "{text}"
            );
            rdy_engine::fixtext::check(&text).expect("an allowed text");
        }
    }
    let claim = fix::failing_claims("--server", "--insecure-skip-tls-verify");
    assert!(
        claim.contains("`kubectl describe pvc <claim> -n <namespace>`"),
        "{claim}"
    );
    let grant = Grant::namespaced("list", "events", "--server");
    assert!(
        grant.can_i().contains("-n <namespace>"),
        "{}",
        grant.can_i()
    );
    assert!(!grant.can_i().contains("--server"));
    // The wire text still names what was meant, made safe.
    assert_eq!(grant.text(), "list events in --server");
}

#[test]
fn a_single_default_on_a_cut_list_is_not_a_clean_pass() {
    let classes = page(
        vec![class(
            "gp3",
            "csi.acme.example",
            true,
            "2026-01-01T00:00:00Z",
        )],
        true,
    );
    let (chosen, finding) = selected(&classes, json!({}), Some((1, 30)));
    assert_eq!(chosen.expect("chosen").class.name, "gp3");
    // A second default may sit on a page that was not read.
    let partial = finding.partial.expect("a partial");
    assert!(
        partial
            .note
            .contains("the storage classes after the first page"),
        "{partial:?}"
    );
    assert_eq!(finding.observed["classes_complete"], json!(false));

    // On a whole list the same class leaves no partial.
    let whole = page(
        vec![class(
            "gp3",
            "csi.acme.example",
            true,
            "2026-01-01T00:00:00Z",
        )],
        false,
    );
    let (_, finding) = selected(&whole, json!({}), Some((1, 30)));
    assert!(finding.partial.is_none());
}

#[test]
fn a_name_fetch_without_a_name_in_the_spec_is_not_verified_and_never_a_pass() {
    // The check never builds this pair; if it did, the answer is a warning, not a silent pass.
    let (chosen, finding) = selected(&Classes::ByName(Read::Missing), json!({}), Some((1, 30)));
    assert!(chosen.is_none());
    assert_eq!(finding.level, Level::Warn, "{finding:?}");
    assert!(
        finding.message.starts_with("Not verified:"),
        "{}",
        finding.message
    );
    let partial = finding.partial.expect("a partial");
    assert_eq!(
        partial.missing_grants,
        ["list storageclasses (storage.k8s.io)"]
    );
}

#[test]
fn a_hostile_class_name_cannot_reach_a_message_or_a_fix() {
    let hostile = "x`; rm -rf ~ #\n";
    let classes = page(
        vec![class(
            hostile,
            "csi.acme.example",
            false,
            "2026-01-01T00:00:00Z",
        )],
        false,
    );
    let (chosen, finding) = selected(&classes, json!({}), Some((1, 30)));
    assert!(chosen.is_none());
    let text = format!(
        "{} {}",
        finding.message,
        finding.fix.clone().unwrap_or_default()
    );
    assert!(!text.contains("rm -rf"), "{text}");
    assert!(!text.contains('\n'), "{text:?}");
    assert!(text.contains(&token(hostile)), "{text}");
    clean(&finding);

    let (_, missing) = selected(&classes, json!({"class": "nope"}), Some((1, 30)));
    assert!(!missing.message.contains('\n'));
    assert!(
        missing.message.contains(&token(hostile)),
        "{}",
        missing.message
    );
}

#[test]
fn many_classes_are_counted_and_not_all_listed() {
    let items: Vec<Class> = (0..8)
        .map(|n| {
            class(
                &format!("c{n}"),
                "csi.acme.example",
                false,
                "2026-01-01T00:00:00Z",
            )
        })
        .collect();
    let (_, finding) = selected(&page(items, false), json!({}), None);
    assert_eq!(
        finding.message,
        "No default storage class. The cluster has: c0, c1, c2, c3, c4 and 3 more"
    );
}

// ---- the driver ------------------------------------------------------------------------------------------------

fn chosen(provisioner: &str) -> Chosen {
    Chosen {
        class: class("gp3", provisioner, true, "2026-01-01T00:00:00Z"),
        how: How::Default,
    }
}

fn judged(provisioner: &str, evidence: Option<Evidence>, spec: Value) -> Finding {
    let params = params(spec);
    let chosen = chosen(provisioner);
    let (normalised, kind) = catalog().classify(&chosen.class.provisioner);
    let mut verdict = Verdict::new();
    judge_driver(&mut verdict, &chosen, &normalised, &kind, evidence.as_ref());
    judge_modes(&mut verdict, &params, &kind, normalised.name);
    judge_settings(&mut verdict, &params, &chosen.class, &kind);
    let finding = verdict.finish(&params);
    clean(&finding);
    finding
}

fn registered(with: usize, read: usize) -> Registered {
    Registered {
        with_driver: with,
        read,
    }
}

#[test]
fn too_little_time_is_a_warning_with_no_grant() {
    let evidence = Evidence {
        nodes: Nodes::Unknown(Unread::Time),
        object: Some(Object::Unknown(Unread::Time)),
    };
    let finding = judged("ebs.csi.aws.com", Some(evidence), json!({}));
    assert_eq!(finding.level, Level::Warn);
    assert!(
        finding
            .message
            .contains("was not read, the check ran out of time"),
        "{}",
        finding.message
    );
    let partial = finding.partial.expect("partial");
    assert!(partial.missing_grants.is_empty());
    assert!(finding.fix.expect("a fix").contains("kubectl get csinodes"));
}

#[test]
fn a_registered_driver_is_a_pass_whatever_the_weaker_list_says() {
    let evidence = Evidence {
        nodes: Nodes::Found(registered(1, 4)),
        object: None,
    };
    let finding = judged("ebs.csi.aws.com", Some(evidence), json!({}));
    assert_eq!(finding.level, Level::Pass);
    assert_eq!(
        finding.message,
        "Default class gp3 (ebs.csi.aws.com): driver registered on 1 node"
    );
    assert_eq!(finding.observed["csinodes_read"], 4);
}

#[test]
fn every_evidence_pair_has_one_outcome() {
    use Nodes::{Found, NotFound, Unknown};
    use Object::{Found as Declared, NotFound as Absent};
    let any = registered(0, 3);
    let table: &[(Nodes, Option<Object>, Level, bool)] = &[
        (Found(registered(2, 3)), None, Level::Pass, false),
        (Found(registered(2, 3)), Some(Absent), Level::Pass, false),
        (NotFound(any), Some(Declared), Level::Warn, false),
        (NotFound(any), Some(Absent), Level::Fail, false),
        (
            NotFound(any),
            Some(Object::Unknown(Unread::Forbidden)),
            Level::Warn,
            true,
        ),
        (
            NotFound(any),
            Some(Object::Unknown(Unread::Capped)),
            Level::Warn,
            true,
        ),
        (
            Unknown(Unread::Forbidden),
            Some(Declared),
            Level::Pass,
            true,
        ),
        (Unknown(Unread::Forbidden), Some(Absent), Level::Warn, true),
        (
            Unknown(Unread::Status(500)),
            Some(Declared),
            Level::Pass,
            true,
        ),
        (Unknown(Unread::Capped), Some(Declared), Level::Pass, true),
        (Unknown(Unread::Capped), Some(Absent), Level::Warn, true),
        (
            Unknown(Unread::Forbidden),
            Some(Object::Unknown(Unread::Forbidden)),
            Level::Warn,
            true,
        ),
        (Unknown(Unread::Time), None, Level::Warn, true),
    ];
    for (nodes, object, level, partial) in table {
        let finding = judged(
            "ebs.csi.aws.com",
            Some(Evidence {
                nodes: *nodes,
                object: *object,
            }),
            json!({}),
        );
        assert_eq!(
            (finding.level, finding.partial.is_some()),
            (*level, *partial),
            "{nodes:?} {object:?}: {finding:?}"
        );
    }
}

#[test]
fn a_block_on_a_missing_driver_names_the_fix_for_that_driver() {
    let absent = Evidence {
        nodes: Nodes::NotFound(registered(0, 2)),
        object: Some(Object::NotFound),
    };
    let fix = |driver: &str| judged(driver, Some(absent), json!({})).fix.expect("a fix");
    assert!(
        fix("ebs.csi.aws.com")
            .contains("eksctl create addon --cluster <cluster> --name aws-ebs-csi-driver")
    );
    assert!(fix("efs.csi.aws.com").contains("aws-efs-csi-driver"));
    let ebs = fix("ebs.csi.aws.com");
    assert!(
        ebs.contains(
            "--pod-identity-associations serviceAccount=ebs-csi-controller-sa,roleArn=<role-arn>"
        ),
        "{ebs}"
    );
    assert!(ebs.contains("AmazonEBSCSIDriverPolicyV2"), "{ebs}");
    let auto = fix::install_driver("ebs.csi.eks.amazonaws.com", "auto-ebs-sc");
    assert!(auto.contains("no add-on to install"), "{auto}");
    assert!(!auto.contains("eksctl create addon"), "{auto}");
    assert!(fix("pd.csi.storage.gke.io").contains("GKE Autopilot clusters always have it"));
    assert!(
        fix("pd.csi.storage.gke.io").contains("--update-addons=GcePersistentDiskCsiDriver=ENABLED")
    );
    assert!(
        fix("disk.csi.azure.com")
            .contains("az aks update -g <resource-group> -n <cluster> --enable-disk-driver")
    );
    assert!(fix("file.csi.azure.com").contains("--enable-file-driver"));
    assert!(fix("driver.longhorn.io").contains("Install the driver and its node plugin"));
    assert!(fix("kubernetes.io/vsphere-volume").contains("`csi.vsphere.vmware.com`"));
}

#[test]
fn a_driver_that_is_not_csi_asks_for_no_evidence() {
    for provisioner in [
        "rancher.io/local-path",
        "kubernetes.io/no-provisioner",
        "csi.acme.example",
    ] {
        let finding = judged(provisioner, None, json!({}));
        assert_eq!(finding.level, Level::Pass, "{provisioner}");
        assert!(
            finding.message.contains("driver not verified"),
            "{provisioner}"
        );
        assert!(finding.partial.is_none(), "{provisioner}");
    }
}

// ---- access modes --------------------------------------------------------------------------------------------------

fn support(provisioner: &'static str, mode: AccessMode) -> &'static str {
    let (normalised, kind) = catalog().classify(provisioner);
    match mode_support(&kind, normalised.name, mode) {
        Support::Yes => "yes",
        Support::No(_) => "no",
        Support::Unverified(_) => "unverified",
    }
}

#[test]
fn the_access_modes_of_every_driver_in_the_table() {
    let table: &[(&str, [&str; 4])] = &[
        // RWO, ROX, RWX, RWOP
        (
            "ebs.csi.aws.com",
            ["yes", "unverified", "unverified", "unverified"],
        ),
        (
            "kubernetes.io/aws-ebs",
            ["yes", "unverified", "unverified", "unverified"],
        ),
        // EKS Auto Mode is not confirmed as CSI: what it lists is served, the rest is not verified.
        (
            "ebs.csi.eks.amazonaws.com",
            ["yes", "unverified", "unverified", "unverified"],
        ),
        (
            "pd.csi.storage.gke.io",
            ["yes", "yes", "unverified", "unverified"],
        ),
        (
            "filestore.csi.storage.gke.io",
            ["yes", "yes", "yes", "unverified"],
        ),
        (
            "disk.csi.azure.com",
            ["yes", "unverified", "unverified", "unverified"],
        ),
        ("file.csi.azure.com", ["yes", "yes", "yes", "unverified"]),
        ("efs.csi.aws.com", ["yes", "yes", "yes", "unverified"]),
        ("nfs.csi.k8s.io", ["yes", "yes", "yes", "unverified"]),
        (
            "driver.longhorn.io",
            ["yes", "unverified", "yes", "unverified"],
        ),
        (
            "openshift-storage.cephfs.csi.ceph.com",
            ["yes", "yes", "yes", "unverified"],
        ),
        (
            "openshift-storage.rbd.csi.ceph.com",
            ["yes", "yes", "unverified", "unverified"],
        ),
        ("rancher.io/local-path", ["yes", "no", "no", "no"]),
        (
            "csi.vsphere.vmware.com",
            ["yes", "yes", "unverified", "unverified"],
        ),
        (
            "kubernetes.io/vsphere-volume",
            ["yes", "yes", "unverified", "unverified"],
        ),
        (
            "cinder.csi.openstack.org",
            ["yes", "unverified", "unverified", "unverified"],
        ),
        // Not in the table.
        ("kubernetes.io/portworx-volume", ["unverified"; 4]),
        ("kubernetes.io/no-provisioner", ["unverified"; 4]),
        ("csi.acme.example", ["unverified"; 4]),
    ];
    for (provisioner, want) in table {
        let got = [
            support(provisioner, ReadWriteOnce),
            support(provisioner, ReadOnlyMany),
            support(provisioner, ReadWriteMany),
            support(provisioner, ReadWriteOncePod),
        ];
        assert_eq!(&got, want, "{provisioner}");
    }
}

#[test]
fn a_mixed_request_blocks_on_any_mode_that_is_refused_and_lists_each_in_observed() {
    let finding = judged(
        "rancher.io/local-path",
        None,
        json!({"access_modes": ["ReadWriteOnce", "ReadWriteMany", "ReadWriteOncePod"], "binding": "WaitForFirstConsumer"}),
    );
    assert_eq!(finding.level, Level::Fail);
    assert_eq!(
        finding.observed["access_modes"],
        json!({"ReadWriteOnce": "served", "ReadWriteMany": "not served", "ReadWriteOncePod": "not served"})
    );
    assert_eq!(
        finding.message,
        "Class gp3 cannot serve ReadWriteMany: rancher.io/local-path serves ReadWriteOnce"
    );
    // The second refused mode is a note, not the message.
    assert!(
        finding
            .notes
            .iter()
            .any(|note| note.contains("Class gp3 cannot serve ReadWriteOncePod")),
        "{:?}",
        finding.notes
    );

    // A mode that is only not verified never fails: EKS Auto Mode is not confirmed as CSI.
    let auto = judged(
        "ebs.csi.eks.amazonaws.com",
        None,
        json!({"access_modes": ["ReadWriteOnce", "ReadWriteMany", "ReadWriteOncePod"], "binding": "WaitForFirstConsumer"}),
    );
    assert_eq!(auto.level, Level::Warn, "{auto:?}");
    assert_eq!(
        auto.observed["access_modes"],
        json!({"ReadWriteOnce": "served", "ReadWriteMany": "not verified", "ReadWriteOncePod": "not verified"})
    );
}

// ---- grants, claims, the finding -------------------------------------------------------------------------------

#[test]
fn a_grant_says_what_to_ask_for_and_how_to_check_it() {
    let nodes = Grant::cluster("list", "csinodes", "storage.k8s.io");
    assert_eq!(nodes.text(), "list csinodes (storage.k8s.io)");
    assert_eq!(
        nodes.can_i(),
        "`kubectl auth can-i list csinodes.storage.k8s.io`"
    );
    let events = Grant::namespaced("list", "events", "acme-system");
    assert_eq!(events.text(), "list events in acme-system");
    assert_eq!(
        events.can_i(),
        "`kubectl auth can-i list events -n acme-system`"
    );
    // A namespace from the server is made safe.
    assert_eq!(
        Grant::namespaced("list", "events", "a b").text(),
        "list events in a?b"
    );
}

fn claim(name: &str, phase: &str, created: &str, class: Option<&str>) -> PersistentVolumeClaim {
    let mut spec = json!({});
    if let Some(class) = class {
        spec["storageClassName"] = json!(class);
    }
    serde_json::from_value(json!({
        "metadata": {"name": name, "creationTimestamp": created},
        "spec": spec,
        "status": {"phase": phase},
    }))
    .expect("a claim")
}

#[test]
fn a_claim_counts_after_exactly_five_minutes_pending_on_the_class() {
    let now: Timestamp = "2026-06-01T12:00:00Z".parse().expect("a time");
    let claims = vec![
        claim("exact", "Pending", "2026-06-01T11:55:00Z", Some("gp3")),
        claim("early", "Pending", "2026-06-01T11:55:01Z", Some("gp3")),
        claim("bound", "Bound", "2026-06-01T10:00:00Z", Some("gp3")),
        claim("other", "Pending", "2026-06-01T10:00:00Z", Some("fast")),
        claim("unnamed", "Pending", "2026-06-01T10:00:00Z", None),
        claim("lost", "Lost", "2026-06-01T10:00:00Z", Some("gp3")),
    ];
    let names = |default: bool| -> Vec<String> {
        pending_claims(&claims, "gp3", default, now)
            .into_iter()
            .map(|(name, _)| name)
            .collect()
    };
    // A claim with no class uses the default class only.
    assert_eq!(names(true), ["exact", "unnamed"]);
    assert_eq!(names(false), ["exact"]);
    assert_eq!(
        pending_claims(&claims, "gp3", false, now),
        [("exact".to_owned(), 5)]
    );
}

#[test]
fn a_claim_with_no_phase_or_no_time_is_left_out() {
    let now: Timestamp = "2026-06-01T12:00:00Z".parse().expect("a time");
    let no_phase: PersistentVolumeClaim = serde_json::from_value(
        json!({"metadata": {"name": "a", "creationTimestamp": "2026-06-01T10:00:00Z"}}),
    )
    .expect("a claim");
    let no_time: PersistentVolumeClaim =
        serde_json::from_value(json!({"metadata": {"name": "b"}, "status": {"phase": "Pending"}}))
            .expect("a claim");
    assert!(pending_claims(&[no_phase, no_time], "gp3", true, now).is_empty());
}

#[test]
fn only_a_claim_whose_provisioning_failed_warns() {
    let waiting = |name: &str, failed: bool| Waiting {
        name: name.to_owned(),
        minutes: 9,
        failed,
    };
    let mut quiet = Verdict::new();
    judge_waiting(&mut quiet, "acme-system", &[waiting("a", false)]);
    assert_eq!(quiet.finish(&params(json!({}))).level, Level::Pass);

    let mut loud = Verdict::new();
    let local = chosen("rancher.io/local-path");
    let (normalised, kind) = catalog().classify(&local.class.provisioner);
    judge_driver(&mut loud, &local, &normalised, &kind, None);
    judge_waiting(
        &mut loud,
        "acme-system",
        &[waiting("a", true), waiting("b", false), waiting("c", true)],
    );
    let finding = loud.finish(&params(json!({})));
    assert_eq!(finding.level, Level::Warn);
    assert_eq!(
        finding.message,
        "2 claims in acme-system on class gp3 have been Pending for 5 minutes or more with a ProvisioningFailed event: a, c"
    );
    clean(&finding);
}

#[test]
fn the_finding_orders_fixes_by_severity_drops_duplicates_and_keeps_the_rest_as_notes() {
    let evidence = Evidence {
        nodes: Nodes::Found(registered(1, 1)),
        object: None,
    };
    // Immediate binding on a zonal driver (a warn), a missing mode (a fail) and an expansion warn.
    let mut class = chosen("rancher.io/local-path");
    class.class.binding = Binding::Immediate;
    let params = params(json!({"access_modes": ["ReadWriteMany"], "expansion": true}));
    let (normalised, kind) = catalog().classify(&class.class.provisioner);
    let mut verdict = Verdict::new();
    judge_driver(&mut verdict, &class, &normalised, &kind, Some(&evidence));
    judge_modes(&mut verdict, &params, &kind, normalised.name);
    judge_settings(&mut verdict, &params, &class.class, &kind);
    let finding = verdict.finish(&params);
    assert_eq!(finding.level, Level::Fail);
    assert!(
        finding
            .message
            .starts_with("Class gp3 cannot serve ReadWriteMany")
    );
    assert_eq!(finding.notes.len(), 2, "{:?}", finding.notes);
    let fix = finding.fix.clone().expect("a fix");
    let failing = fix.find("Create a class on").expect("the failing fix");
    let warning = fix
        .find("The binding mode of a class")
        .expect("a warning fix");
    assert!(failing < warning, "{fix}");
    clean(&finding);
}

#[test]
fn the_expected_value_holds_only_what_the_spec_set() {
    assert_eq!(Verdict::expected(&params(json!({}))), json!({}));
    assert_eq!(
        Verdict::expected(&params(json!({
            "class": "gp3", "access_modes": ["ReadWriteOnce", "ReadOnlyMany"], "binding": "any",
            "expansion": false, "reclaim_policy": "Delete"
        }))),
        json!({
            "class": "gp3", "access_modes": ["ReadWriteOnce", "ReadOnlyMany"],
            "expansion": false, "reclaim_policy": "Delete"
        })
    );
}

// ---- fix text ----------------------------------------------------------------------------------------------------

#[test]
fn every_fix_text_passes_the_allow_list_and_is_short() {
    let texts = [
        fix::mark_default("managed-csi"),
        fix::no_classes(),
        fix::create_class("fast"),
        fix::unmark_defaults(&["a".to_owned(), "b".to_owned()]),
        fix::grants(
            &["`kubectl auth can-i list csinodes.storage.k8s.io`".to_owned()],
            &["list csinodes (storage.k8s.io)".to_owned()],
        ),
        fix::by_hand().to_owned(),
        fix::install_driver("ebs.csi.aws.com", "gp2"),
        fix::install_driver("efs.csi.aws.com", "efs"),
        fix::install_driver("ebs.csi.eks.amazonaws.com", "auto-ebs-sc"),
        fix::install_driver("pd.csi.storage.gke.io", "standard-rwo"),
        fix::install_driver("disk.csi.azure.com", "managed-csi"),
        fix::install_driver("file.csi.azure.com", "azurefile-csi"),
        fix::install_driver("driver.longhorn.io", "longhorn"),
        fix::node_plugin("ebs.csi.aws.com"),
        fix::other_driver(ReadWriteMany),
        fix::other_driver(ReadWriteOncePod),
        fix::other_driver(ReadOnlyMany),
        fix::rebind("gp3", "WaitForFirstConsumer"),
        fix::allow_expansion("gp3"),
        fix::reclaim("gp3", "Retain"),
        fix::failing_claims("acme-system", "data-0"),
    ];
    for text in texts {
        if let Err(error) = rdy_engine::fixtext::check(&text) {
            panic!("{error}\n{text}");
        }
        assert!(text.len() <= 600, "{} characters: {text}", text.len());
        assert!(!text.contains('\u{2014}'), "{text}");
        assert!(text.ends_with('.'), "{text}");
    }
}
