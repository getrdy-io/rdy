//! Unit tests of the cut-down objects and the fix helpers of `k8s.dns`.

use serde_json::json;

use super::fix::{is_name, object};
use super::objects::{
    DnsConfigMap, DnsDaemonSet, DnsDeployment, DnsPod, DnsService, Kind, MAX_COREFILE, Role,
    corefile_of, daemon_set_of, deployment_of, pod_of, service_of,
};

fn parse<T: serde::de::DeserializeOwned>(value: serde_json::Value) -> T {
    serde_json::from_value(value).expect("it parses")
}

#[test]
fn a_deployment_keeps_replicas_ready_and_container_names_and_nothing_else() {
    let object: DnsDeployment = parse(json!({
        "metadata": {"name": "coredns", "labels": {"k8s-app": "kube-dns"}},
        "spec": {
            "replicas": 3,
            "template": {"spec": {"containers": [
                {"name": "coredns", "env": [{"name": "A", "value": "ENV-VALUE"}], "args": ["x"]}
            ]}}
        },
        "status": {"readyReplicas": 2}
    }));
    // The type has no field for env or args, so there is nothing of them to keep.
    assert!(!format!("{object:?}").contains("ENV-VALUE"));
    let workload = deployment_of(object);
    assert_eq!(workload.kind, Kind::Deployment);
    assert_eq!((workload.desired, workload.ready), (3, 2));
    assert_eq!(workload.containers, ["coredns"]);
    assert_eq!(workload.role, Role::Cluster);
}

#[test]
fn a_deployment_with_no_replicas_wants_one_and_with_no_status_has_none_ready() {
    let object: DnsDeployment = parse(json!({"metadata": {"name": "x"}}));
    let workload = deployment_of(object);
    assert_eq!((workload.desired, workload.ready), (1, 0));
    assert_eq!(workload.role, Role::Other);
}

#[test]
fn a_daemon_set_is_read_by_its_status_counts_and_labels_pick_the_role() {
    let object: DnsDaemonSet = parse(json!({
        "metadata": {"name": "dns-default", "labels": {"dns.operator.openshift.io/owning-dns": "default"}},
        "status": {"desiredNumberScheduled": 6, "numberReady": 4}
    }));
    let workload = daemon_set_of(object);
    assert_eq!((workload.desired, workload.ready), (6, 4));
    assert_eq!(workload.role, Role::Cluster);
    let local: DnsDaemonSet = parse(json!({
        "metadata": {"name": "n", "labels": {"k8s-app": "node-local-dns"}},
        "spec": {"template": {"spec": {"containers": [{"name": "node-cache"}]}}}
    }));
    let local = daemon_set_of(local);
    assert_eq!(local.role, Role::NodeLocal);
    assert_eq!(local.desired, 0);
}

#[test]
fn a_kubedns_container_marks_kube_dns() {
    let object: DnsDeployment = parse(json!({
        "metadata": {"name": "kube-dns", "labels": {"k8s-app": "kube-dns"}},
        "spec": {"template": {"spec": {"containers": [{"name": "kubedns"}, {"name": "sidecar"}]}}}
    }));
    assert!(deployment_of(object).is_kube_dns());
}

#[test]
fn a_pod_keeps_only_crash_loop_containers_and_counts_back_from_now() {
    let object: DnsPod = parse(json!({
        "metadata": {"name": "p"},
        "spec": {"containers": [{"name": "c", "env": [{"name": "A", "value": "SPEC-VALUE"}]}]},
        "status": {"containerStatuses": [
            {"name": "ok", "restartCount": 20, "state": {"running": {}}},
            {"name": "bad", "restartCount": 3,
             "state": {"waiting": {"reason": "CrashLoopBackOff"}},
             "lastState": {"terminated": {"exitCode": 1, "reason": "Error", "finishedAt": "2026-11-17T11:58:00Z"}}},
            {"name": "waiting", "restartCount": 1, "state": {"waiting": {"reason": "ImagePullBackOff"}}}
        ]}
    }));
    assert!(!format!("{object:?}").contains("SPEC-VALUE"));
    let now = "2026-11-17T12:00:00Z"
        .parse::<k8s_openapi::jiff::Timestamp>()
        .expect("a time")
        .as_second();
    let pod = pod_of(object, now);
    assert_eq!(pod.restarts, 20);
    assert_eq!(pod.crashes.len(), 1);
    let crash = &pod.crashes[0];
    assert_eq!(crash.container, "bad");
    assert_eq!(crash.ended_ago, Some(120));
    assert_eq!(crash.reason.as_deref(), Some("Error"));
    assert_eq!(crash.exit_code, Some(1));
}

#[test]
fn a_pod_with_odd_fields_does_not_break_parsing() {
    let object: DnsPod = parse(json!({
        "metadata": {},
        "status": {"containerStatuses": [{"state": {"waiting": {}}, "lastState": {"terminated": {"finishedAt": null}}}]}
    }));
    let pod = pod_of(object, 0);
    assert!(pod.crashes.is_empty());
}

#[test]
fn a_configmap_keeps_the_corefile_key_only_and_cuts_a_huge_one_on_a_boundary() {
    let object: DnsConfigMap = parse(json!({
        "metadata": {"name": "coredns"},
        "data": {"Corefile": ".:53 {\n}\n", "other": "KEY-VALUE"}
    }));
    assert!(!format!("{object:?}").contains("KEY-VALUE"));
    assert_eq!(corefile_of(object).as_deref(), Some(".:53 {\n}\n"));

    let huge = "\u{e9}".repeat(MAX_COREFILE);
    let object: DnsConfigMap = parse(json!({"data": {"Corefile": huge}}));
    let text = corefile_of(object).expect("text");
    assert!(text.len() <= MAX_COREFILE);
    assert!(text.chars().all(|c| c == '\u{e9}'));

    let none: DnsConfigMap = parse(json!({"data": {"other": "x"}}));
    assert_eq!(corefile_of(none), None);
}

#[test]
fn only_names_in_the_shape_of_a_kubernetes_name_go_into_a_command() {
    assert!(is_name("rke2-coredns-rke2-coredns"));
    assert!(is_name("a.b-c"));
    for bad in ["", "-a", "a-", "A", "a b", "a`b", "a..b", "a;b", "a$(x)"] {
        assert!(!is_name(bad), "{bad}");
        assert_eq!(object(bad), "<name>");
    }
    assert!(!is_name(&"a".repeat(254)));
}

/// `kubectl apply` stores the whole applied object in this annotation: env values, every ConfigMap key.
fn annotated(kind_fields: serde_json::Value) -> serde_json::Value {
    let mut value = kind_fields;
    value["metadata"] = json!({
        "name": "x",
        "namespace": "kube-system",
        "labels": {"k8s-app": "kube-dns"},
        "annotations": {"kubectl.kubernetes.io/last-applied-configuration": "ENV-VALUE"},
        "managedFields": [{"manager": "ENV-VALUE"}],
    });
    value
}

#[test]
fn no_annotation_or_other_metadata_is_held() {
    let deployment: DnsDeployment = parse(annotated(json!({"spec": {"replicas": 2}})));
    assert!(!format!("{deployment:?}").contains("ENV-VALUE"));
    let daemon_set: DnsDaemonSet = parse(annotated(json!({"status": {"numberReady": 1}})));
    assert!(!format!("{daemon_set:?}").contains("ENV-VALUE"));
    let map: DnsConfigMap = parse(annotated(json!({"data": {"Corefile": ".:53 {\n}\n"}})));
    assert!(!format!("{map:?}").contains("ENV-VALUE"));
    let pod: DnsPod = parse(annotated(json!({"status": {"containerStatuses": []}})));
    assert!(!format!("{pod:?}").contains("ENV-VALUE"));
    assert!(pod.is_in("kube-system"));
    let service: DnsService = parse(annotated(json!({"spec": {"clusterIP": "10.0.0.10"}})));
    assert!(!format!("{service:?}").contains("ENV-VALUE"));
    // The labels survive, so the role of a workload is still read.
    assert_eq!(deployment_of(deployment).role, Role::Cluster);
}

#[test]
fn a_service_keeps_the_address_and_the_port_53_protocols_only() {
    let service: DnsService = parse(json!({
        "metadata": {"name": "kube-dns"},
        "spec": {
            "clusterIP": "10.0.0.10",
            "selector": {"a": "ENV-VALUE"},
            "ports": [
                {"name": "dns", "port": 53, "protocol": "UDP"},
                {"name": "metrics", "port": 9153, "protocol": "TCP"},
                {"port": 53}
            ]
        }
    }));
    assert!(!format!("{service:?}").contains("ENV-VALUE"));
    let parts = service_of(service);
    assert_eq!(parts.cluster_ip, "10.0.0.10");
    // A port with no protocol is TCP, the server's default.
    assert!(parts.udp_53 && parts.tcp_53);
}
