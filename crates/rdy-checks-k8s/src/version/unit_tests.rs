//! Unit tests of the pure parts of `k8s.version`: version text, distribution evidence, the removed-API
//! table, the fix text, the error sorting and the judgement.

use std::cmp::Ordering;

use k8s_openapi::api::core::v1::Node;
use rdy_engine::check::{CheckError, Level};
use rdy_spec::check::{ApiRef, K8sVersion};
use serde_json::{Value, json};

use super::server::{Distro, NodeFacts, Reported, cloud, compare, detect, parse_openshift};
use super::{Gathered, Read, Served, apis, fix, judge, listed, read, shown};

fn parsed(text: &str) -> Reported {
    Reported::parse(text).unwrap_or_else(|| panic!("{text} parses"))
}

fn api(text: &str) -> ApiRef {
    serde_json::from_value(json!(text)).expect("an API reference")
}

fn params(spec: Value) -> K8sVersion {
    serde_json::from_value(spec).expect("parameters")
}

fn node(value: Value) -> NodeFacts {
    NodeFacts::from_node(&serde_json::from_value::<Node>(value).expect("a node"))
}

// ---- version text ---------------------------------------------------------------------------------------------

#[test]
fn git_versions_parse_with_their_suffix() {
    for (text, parts, suffix) in [
        ("v1.29.4-eks-abc123", vec![1, 29, 4], "-eks-abc123"),
        ("v1.29.4", vec![1, 29, 4], ""),
        ("v1.29.4+k3s1", vec![1, 29, 4], "+k3s1"),
        ("v1.29.4+rke2r1", vec![1, 29, 4], "+rke2r1"),
        ("v1.26.9-gke.1000", vec![1, 26, 9], "-gke.1000"),
        ("v1.30.0-alpha.1", vec![1, 30, 0], "-alpha.1"),
        ("v1.29", vec![1, 29], ""),
        ("1.29.4", vec![1, 29, 4], ""),
    ] {
        let got = parsed(text);
        assert_eq!(got.parts(), parts, "{text}");
        assert_eq!(got.suffix(), suffix, "{text}");
    }
    assert_eq!(parsed("v1.29.4-eks-abc123").dotted(), "1.29.4");
    assert_eq!(parsed("v1.29.4-eks-abc123").minor(), 29);
}

#[test]
fn text_that_is_not_a_version_does_not_parse() {
    let long = format!("v1.29.4-{}", "x".repeat(200));
    for text in [
        "",
        "v",
        "v1",
        "v1.",
        "v1.29.",
        "v1..29",
        "v1.29.4.5",
        "vx.y",
        "v1.2a",
        "v1.29.4 extra",
        "v1.29.4\u{1b}[2J",
        "acme-build-7",
        "v1.1234567.0",
        long.as_str(),
    ] {
        assert!(Reported::parse(text).is_none(), "{text:?}");
    }
}

#[test]
fn major_and_minor_are_the_fallback_and_a_plus_is_dropped() {
    let got = Reported::from_major_minor("1", "29+").expect("parses");
    assert_eq!(got.parts(), [1, 29]);
    assert!(Reported::from_major_minor("1", "x").is_none());
    assert!(Reported::from_major_minor("", "29").is_none());
}

#[test]
fn bounds_compare_over_the_parts_both_have() {
    let table = [
        (vec![1, 29, 4], vec![1, 28], Ordering::Greater),
        (vec![1, 28, 7], vec![1, 28], Ordering::Equal),
        (vec![1, 27, 9], vec![1, 28], Ordering::Less),
        (vec![1, 31, 5], vec![1, 31], Ordering::Equal),
        (vec![1, 28, 1], vec![1, 28, 3], Ordering::Less),
        (vec![1, 28], vec![1, 28, 3], Ordering::Equal),
        (vec![1, 9], vec![1, 10], Ordering::Less),
        (vec![1, 29], vec![2], Ordering::Less),
    ];
    for (have, bound, expected) in table {
        assert_eq!(
            compare(&have, &bound),
            expected,
            "{have:?} against {bound:?}"
        );
    }
}

#[test]
fn openshift_versions_parse() {
    assert_eq!(parse_openshift("4.14.9"), Some(vec![4, 14, 9]));
    assert_eq!(parse_openshift("4.15.0-rc.1"), Some(vec![4, 15, 0]));
    assert_eq!(parse_openshift("4.14"), Some(vec![4, 14]));
    for text in ["", "4", "four", "4.14.9.1.2", "4.x", "4.14 extra"] {
        assert_eq!(parse_openshift(text), None, "{text:?}");
    }
}

// ---- distributions --------------------------------------------------------------------------------------------

fn bare() -> NodeFacts {
    NodeFacts::default()
}

#[test]
fn suffixes_name_the_distribution() {
    for (text, expected) in [
        ("v1.29.4-eks-abc123", Distro::Eks),
        ("v1.26.9-gke.1000", Distro::Gke),
        ("v1.29.4+k3s1", Distro::K3s),
        ("v1.29.4+rke2r1", Distro::Rke2),
        ("v1.29.4", Distro::Vanilla),
        ("v1.30.0-alpha.1", Distro::Vanilla),
    ] {
        assert_eq!(detect(&parsed(text), false, &[]), expected, "{text}");
    }
}

#[test]
fn labels_name_a_distribution_the_version_does_not() {
    let plain = parsed("v1.29.4");
    let with = |change: &dyn Fn(&mut NodeFacts)| {
        let mut one = bare();
        change(&mut one);
        vec![one]
    };
    assert_eq!(
        detect(&plain, false, &with(&|n| n.aks_label = true)),
        Distro::Aks
    );
    assert_eq!(
        detect(&plain, false, &with(&|n| n.eks_label = true)),
        Distro::Eks
    );
    assert_eq!(
        detect(&plain, false, &with(&|n| n.gke_label = true)),
        Distro::Gke
    );
    assert_eq!(
        detect(&plain, false, &with(&|n| n.cloud = Some("kind"))),
        Distro::Kind
    );
    // A cloud provider id alone is a self-managed cluster, not a managed service.
    for cloud in ["aws", "gcp", "azure"] {
        assert_eq!(
            detect(&plain, false, &with(&|n| n.cloud = Some(cloud))),
            Distro::Vanilla
        );
    }
}

#[test]
fn the_openshift_group_beats_every_other_evidence() {
    let nodes = [NodeFacts {
        eks_label: true,
        cloud: Some("aws"),
        ..bare()
    }];
    assert_eq!(
        detect(&parsed("v1.27.8-eks-abc"), true, &nodes),
        Distro::OpenShift
    );
    // And a suffix beats a label: k3s on AWS machines is k3s.
    assert_eq!(detect(&parsed("v1.29.4+k3s1"), false, &nodes), Distro::K3s);
}

#[test]
fn the_cloud_is_reported_only_when_the_nodes_agree() {
    let on = |cloud| NodeFacts { cloud, ..bare() };
    assert_eq!(cloud(&[on(Some("aws")), on(Some("aws"))]), Some("aws"));
    assert_eq!(cloud(&[on(Some("aws")), on(None)]), Some("aws"));
    assert_eq!(cloud(&[on(Some("aws")), on(Some("azure"))]), None);
    assert_eq!(cloud(&[on(None)]), None);
    assert_eq!(cloud(&[]), None);
}

#[test]
fn a_node_keeps_only_the_facts_rdy_reads() {
    let facts = node(json!({
        "metadata": {"name": "acme-1", "labels": {"kubernetes.azure.com/cluster": "x", "type": "virtual-kubelet"}},
        "spec": {"providerID": "azure:///subscriptions/0/resourceGroups/acme"},
        "status": {"nodeInfo": {"machineID": "", "systemUUID": "", "bootID": "", "kernelVersion": "", "osImage": "",
            "containerRuntimeVersion": "", "kubeletVersion": "v1.29.4", "kubeProxyVersion": "", "operatingSystem": "linux", "architecture": "amd64"}}
    }));
    assert_eq!(facts.name, "acme-1");
    assert_eq!(facts.cloud, Some("azure"));
    assert!(facts.aks_label && !facts.eks_label && !facts.gke_label);
    assert!(facts.virtual_kubelet);
    assert_eq!(facts.kubelet.expect("a kubelet").dotted(), "1.29.4");

    // An unknown provider scheme is dropped, never copied.
    let other =
        node(json!({"metadata": {"name": "n"}, "spec": {"providerID": "acme-cloud://secret-id"}}));
    assert_eq!(other.cloud, None);
    assert!(other.kubelet.is_none());
    // The connector's version text marks a virtual kubelet without the label.
    let by_version = node(json!({
        "metadata": {"name": "n"},
        "status": {"nodeInfo": {"machineID": "", "systemUUID": "", "bootID": "", "kernelVersion": "", "osImage": "",
            "containerRuntimeVersion": "", "kubeletVersion": "v1.14.0-vk-azure-aci-v1.4.1", "kubeProxyVersion": "", "operatingSystem": "linux", "architecture": "amd64"}}
    }));
    assert!(by_version.virtual_kubelet);
}

// ---- removed APIs ---------------------------------------------------------------------------------------------

#[test]
fn a_removed_beta_names_the_minor_and_the_replacement() {
    for (reference, minor, removed, instead) in [
        (
            "autoscaling/v2beta2 HorizontalPodAutoscaler",
            29,
            26,
            "autoscaling/v2",
        ),
        (
            "autoscaling/v2beta1 HorizontalPodAutoscaler",
            25,
            25,
            "autoscaling/v2",
        ),
        ("policy/v1beta1 PodDisruptionBudget", 25, 25, "policy/v1"),
        ("batch/v1beta1 CronJob", 30, 25, "batch/v1"),
        (
            "flowcontrol.apiserver.k8s.io/v1beta3 FlowSchema",
            32,
            32,
            "flowcontrol.apiserver.k8s.io/v1",
        ),
        (
            "flowcontrol.apiserver.k8s.io/v1beta2 FlowSchema",
            29,
            29,
            "flowcontrol.apiserver.k8s.io/v1",
        ),
        (
            "networking.k8s.io/v1beta1 Ingress",
            29,
            22,
            "networking.k8s.io/v1",
        ),
        (
            "storage.k8s.io/v1beta1 CSIStorageCapacity",
            29,
            27,
            "storage.k8s.io/v1",
        ),
        (
            "storage.k8s.io/v1beta1 CSIDriver",
            29,
            22,
            "storage.k8s.io/v1",
        ),
    ] {
        let text = apis::why_missing(&api(reference), Some(minor));
        assert!(
            text.contains(&format!("was removed in Kubernetes 1.{removed}")),
            "{reference}: {text}"
        );
        assert!(
            text.contains(&format!("uses \"{instead}\"")),
            "{reference}: {text}"
        );
        assert!(
            text.contains(&format!("This cluster is 1.{minor}")),
            "{reference}: {text}"
        );
    }
}

#[test]
fn a_beta_that_is_not_yet_removed_gets_the_general_text() {
    // 1.25 still serves autoscaling/v2beta2, so a missing one is not "removed".
    let text = apis::why_missing(
        &api("autoscaling/v2beta2 HorizontalPodAutoscaler"),
        Some(25),
    );
    assert!(!text.contains("removed"), "{text}");
    assert!(
        text.contains("`kubectl api-versions` lists what the cluster serves"),
        "{text}"
    );
    assert!(text.contains("the group is \"autoscaling\""), "{text}");
    // Unknown minor: the same.
    let text = apis::why_missing(&api("autoscaling/v2beta2 HorizontalPodAutoscaler"), None);
    assert!(!text.contains("removed"), "{text}");
    // A CRD group.
    let text = apis::why_missing(&api("cert-manager.io/v1 Certificate"), Some(29));
    assert!(text.contains("install that"), "{text}");
    // The core group.
    assert!(apis::why_missing(&api("v1 Pod"), Some(29)).contains("too old"));
}

#[test]
fn an_api_reference_is_shown_as_the_spec_writes_it() {
    assert_eq!(apis::show(&api("v1 Pod")), "v1 Pod");
    assert_eq!(
        apis::show(&api("autoscaling/v2 HorizontalPodAutoscaler")),
        "autoscaling/v2 HorizontalPodAutoscaler"
    );
    assert_eq!(apis::group_version(&api("batch/v1 CronJob")), "batch/v1");
}

// ---- fix text -------------------------------------------------------------------------------------------------

#[test]
fn every_distribution_has_its_own_upgrade_command() {
    let have = parsed("v1.26.9");
    let need = [1, 29];
    for (distro, command) in [
        (
            Distro::Eks,
            "aws eks update-cluster-version --name <cluster> --kubernetes-version 1.27",
        ),
        (
            Distro::Gke,
            "gcloud container clusters upgrade <cluster> --master --cluster-version 1.29",
        ),
        (
            Distro::Aks,
            "az aks upgrade -g <resource-group> -n <cluster> --kubernetes-version 1.27",
        ),
        (Distro::OpenShift, "oc adm upgrade"),
        (Distro::K3s, "INSTALL_K3S_CHANNEL=v1.29"),
        (Distro::Rke2, "INSTALL_RKE2_CHANNEL=v1.29"),
        (
            Distro::Kind,
            "kind create cluster --image kindest/node:<tag for 1.29>",
        ),
        (Distro::Vanilla, "kubeadm upgrade plan"),
    ] {
        let text = fix::below_min(distro, &have, &need);
        assert!(
            text.starts_with("Cluster is 1.26.9, product needs 1.29 or newer."),
            "{text}"
        );
        assert!(text.contains(command), "{distro:?}: {text}");
        assert!(!text.contains('\u{2014}'), "no em dash");
    }
    let eks = fix::below_min(Distro::Eks, &have, &need);
    assert!(eks.contains("then repeat for 1.28, then 1.29"), "{eks}");
}

#[test]
fn the_steps_stay_inside_the_major_and_are_capped() {
    // A bound on another major has no steps: the text names the bound itself.
    let text = fix::below_min(Distro::Eks, &parsed("v1.20.1"), &[2, 0]);
    assert!(text.contains("--kubernetes-version 2.0"), "{text}");
    // A long climb lists six steps, not twenty.
    let text = fix::below_min(Distro::Eks, &parsed("v1.10.1"), &[1, 30]);
    assert!(
        text.contains(
            "then repeat for 1.12, then 1.13, then 1.14, then 1.15, then 1.16, and so on up to 1.30"
        ),
        "{text}"
    );
    assert!(!text.contains("1.17"), "{text}");
    // A bound with a patch keeps it in the sentence.
    let text = fix::below_min(Distro::Gke, &parsed("v1.26.9"), &[1, 28, 3]);
    assert!(text.contains("needs 1.28.3 or newer"), "{text}");
}

#[test]
fn the_other_fix_texts_name_the_bound() {
    let ocp = fix::below_openshift_min("4.12.5", &[4, 14, 2]);
    assert!(
        ocp.contains("OpenShift is 4.12.5, product needs 4.14.2 or newer."),
        "{ocp}"
    );
    assert!(ocp.contains("oc adm upgrade channel stable-4.14"), "{ocp}");
    let over = fix::above_max(&parsed("v1.32.1"), &[1, 31]);
    assert!(
        over.contains("Cluster is 1.32.1, newer than the 1.31"),
        "{over}"
    );
}

// ---- sorting errors -------------------------------------------------------------------------------------------

fn api_error(code: u16, reason: &str) -> kube::Error {
    let status: kube::core::Status = serde_json::from_value(
        json!({"status": "Failure", "code": code, "reason": reason, "message": "acme secret text"}),
    )
    .expect("a status");
    kube::Error::Api(Box::new(status))
}

#[test]
fn the_server_refusing_this_identity_is_an_answer_and_other_failures_fail_the_check() {
    assert_eq!(
        read(Err::<(), _>(api_error(403, "Forbidden")), |()| 1),
        Ok(Read::Forbidden)
    );
    assert_eq!(
        read(Err::<(), _>(api_error(404, "NotFound")), |()| 1),
        Ok(Read::Missing)
    );
    assert_eq!(
        read(Err::<(), _>(api_error(500, "InternalError")), |()| 1),
        Ok(Read::Unreadable(500))
    );
    assert_eq!(read(Ok::<_, kube::Error>(2), |n| n * 2), Ok(Read::Ok(4)));

    // A 401 is not an answer: the credentials stopped working, and the hint says so.
    let Err(CheckError::Failed { message, hint }) =
        read(Err::<(), _>(api_error(401, "Unauthorized")), |()| 1)
    else {
        panic!("a 401 fails the check");
    };
    assert!(hint.contains("Log in again"), "{hint}");
    assert!(
        !message.contains("acme secret text"),
        "the server's text is not copied: {message}"
    );
}

#[tokio::test]
async fn a_guard_refusal_of_the_path_shape_means_not_served_and_any_other_refusal_fails() {
    use k8s_openapi::api::core::v1::Secret;
    use kube::api::ListParams;

    let harness = crate::client::mock::Harness::load("checks/k8s.version/eks").expect("a fixture");
    let client = harness.client_for("k8s.version");
    // The core group has one version; any other is refused as a path shape before it is sent.
    let shape = client.core_resources("v2").await;
    assert_eq!(read(shape, |_| 1), Ok(Read::Missing));
    let shape = client.group_resources("autoscaling", "v1/../x").await;
    assert_eq!(read(shape, |_| 1), Ok(Read::Missing));
    // Any other refusal is a bug of rdy, and the hint says to report it.
    let secrets = client.all::<Secret>().list(&ListParams::default()).await;
    let Err(CheckError::Failed { hint, .. }) = read(secrets, |_| 1) else {
        panic!("any other refusal fails the check");
    };
    assert!(hint.contains("Report it"), "{hint}");
    assert!(harness.mock().seen().is_empty(), "nothing was sent");
}

// ---- judging --------------------------------------------------------------------------------------------------

fn gathered(git: &str) -> Gathered {
    Gathered {
        reported: git.to_owned(),
        server: Reported::parse(git),
        groups: Read::Ok(Vec::new()),
        cluster_version: None,
        nodes: Read::Ok((Vec::new(), false)),
        apis: Vec::new(),
    }
}

#[test]
fn hostile_text_from_the_server_is_escaped_and_cut() {
    assert_eq!(shown("v1.29.4"), "v1.29.4");
    assert_eq!(shown("a\u{1b}[2Jb"), "a\\x1b[2Jb");
    assert_eq!(shown("x\u{202e}y"), "x\\u{202e}y");
    let long = "z".repeat(200);
    let cut = shown(&long);
    assert_eq!(cut.len(), 64 + 3);
    assert!(cut.ends_with("..."));

    // A version that carries a control sequence cannot be read, and its message holds no control character.
    let finding = judge(
        &params(json!({"min": "1.28"})),
        &gathered("v1.29.4\u{1b}[2J"),
    );
    assert_eq!(finding.level, Level::Warn);
    assert!(
        finding.message.chars().all(|c| !c.is_control()),
        "{}",
        finding.message
    );
    assert!(finding.message.contains("\\x1b"));
    assert!(
        finding.observed["git_version"]
            .as_str()
            .expect("text")
            .contains("\\x1b")
    );
}

#[test]
fn a_hostile_node_name_is_escaped_in_the_skew_sentence() {
    let mut facts = gathered("v1.29.4");
    facts.nodes = Read::Ok((
        vec![NodeFacts {
            name: "evil\u{1b}[2J".to_owned(),
            kubelet: Reported::parse("v1.20.0"),
            ..bare()
        }],
        false,
    ));
    let finding = judge(&params(json!({"min": "1.20"})), &facts);
    assert_eq!(finding.level, Level::Warn);
    assert!(
        finding.message.chars().all(|c| !c.is_control()),
        "{}",
        finding.message
    );
    assert!(
        finding.message.contains("evil\\x1b[2J (1.20.0)"),
        "{}",
        finding.message
    );
}

#[test]
fn a_kubelet_on_another_major_is_left_out_of_the_skew() {
    let mut facts = gathered("v1.29.4");
    facts.nodes = Read::Ok((
        vec![NodeFacts {
            name: "n".to_owned(),
            kubelet: Reported::parse("v2.0.0"),
            ..bare()
        }],
        false,
    ));
    assert_eq!(
        judge(&params(json!({"min": "1.20"})), &facts).level,
        Level::Pass
    );
}

#[test]
fn an_unknown_discovery_state_is_partial_and_never_a_block() {
    let mut facts = gathered("v1.29.4");
    facts.apis = vec![(
        api("autoscaling/v2 HorizontalPodAutoscaler"),
        Served::Unknown("the server answered 503".to_owned()),
    )];
    let finding = judge(
        &params(json!({"apis": ["autoscaling/v2 HorizontalPodAutoscaler"]})),
        &facts,
    );
    assert_eq!(finding.level, Level::Pass);
    let partial = finding.partial.expect("partial");
    assert!(
        partial
            .note
            .contains("was not checked: the server answered 503"),
        "{}",
        partial.note
    );
    assert_eq!(finding.observed["apis"][0]["served"], Value::Null);
}

#[test]
fn a_group_list_that_could_not_be_read_is_noted() {
    let mut facts = gathered("v1.29.4");
    facts.groups = Read::Unreadable(503);
    facts.apis = vec![(api("v1 Pod"), Served::Yes)];
    let finding = judge(&params(json!({"apis": ["v1 Pod"]})), &facts);
    assert_eq!(finding.level, Level::Pass);
    assert!(
        finding
            .notes
            .iter()
            .any(|n| n.contains("the server answered 503")),
        "{:?}",
        finding.notes
    );
    assert_eq!(finding.message, "Server v1.29.4, 1 API served");
}

#[test]
fn discovery_stops_when_the_time_is_nearly_gone() {
    use std::time::Duration;
    assert!(super::out_of_time(Duration::ZERO));
    assert!(super::out_of_time(Duration::from_millis(499)));
    assert!(!super::out_of_time(Duration::from_millis(500)));
    assert!(!super::out_of_time(rdy_engine::check::MAX_TIMEOUT));
}

#[test]
fn long_lists_are_counted_not_printed() {
    let items: Vec<String> = ["a", "b", "c", "d", "e"]
        .iter()
        .map(|s| (*s).to_owned())
        .collect();
    assert_eq!(listed(&items), "a, b, c, and 2 more");
    assert_eq!(listed(&items[..3]), "a, b, c");
    assert_eq!(listed(&items[..1]), "a");
}

#[test]
fn a_cluster_version_is_read_from_desired_then_history() {
    let read = |value: Value| -> super::openshift::ClusterVersion {
        serde_json::from_value(value).expect("a cluster version")
    };
    let full = read(json!({
        "metadata": {"name": "version"},
        "status": {"desired": {"version": "4.14.9"}, "history": [{"state": "Partial", "version": "4.14.9"}]}
    }));
    assert_eq!(full.version(), Some("4.14.9"));
    assert!(full.updating());
    let history_only =
        read(json!({"status": {"history": [{"state": "Completed", "version": "4.13.1"}]}}));
    assert_eq!(history_only.version(), Some("4.13.1"));
    assert!(!history_only.updating());
    let empty = read(json!({}));
    assert_eq!(empty.version(), None);
    assert!(!empty.updating());
}

#[test]
fn every_fix_text_names_only_commands_on_the_allow_list() {
    let mut texts = vec![
        super::INFO.meta.remediation.to_owned(),
        fix::skew().to_owned(),
        fix::above_max(&parsed("v1.32.1"), &[1, 31]),
        fix::below_openshift_min("4.12.5", &[4, 14]),
    ];
    for distro in [
        Distro::Eks,
        Distro::Gke,
        Distro::Aks,
        Distro::OpenShift,
        Distro::K3s,
        Distro::Rke2,
        Distro::Kind,
        Distro::Vanilla,
    ] {
        texts.push(fix::below_min(distro, &parsed("v1.26.9"), &[1, 29]));
    }
    for reference in [
        "autoscaling/v2beta2 HorizontalPodAutoscaler",
        "cert-manager.io/v1 Certificate",
        "v1 Pod",
    ] {
        texts.push(apis::why_missing(&api(reference), Some(29)));
    }
    for text in texts {
        if let Err(error) = rdy_engine::fixtext::check(&text) {
            panic!("{error}: {text}");
        }
        assert!(!text.contains('\u{2014}'), "no em dash: {text}");
    }
}
