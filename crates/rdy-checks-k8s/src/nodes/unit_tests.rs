//! Unit tests of `k8s.nodes`: node facts, tolerations and the exclusion order, with no mock.

use k8s_openapi::api::core::v1::Node;
use rdy_spec::check::K8sNodes;
use serde_json::{Value, json};

use super::facts::{Excluded, NodeFacts, Platform, Resource, Taint, command_arg, shown, tolerates};
use super::fix;

fn node(value: Value) -> NodeFacts {
    let node: Node = serde_json::from_value(value).expect("a node");
    NodeFacts::from_node(&node)
}

fn params(value: Value) -> K8sNodes {
    serde_json::from_value(value).expect("parameters")
}

/// A Ready Linux amd64 node, with the top-level keys of `extra` replacing the defaults.
fn ready_node(extra: Value) -> NodeFacts {
    let mut base = json!({
        "metadata": {"name": "n1", "labels": {"kubernetes.io/os": "linux", "kubernetes.io/arch": "amd64"}},
        "spec": {},
        "status": {"conditions": [{"type": "Ready", "status": "True"}]}
    });
    if let (Some(base), Some(extra)) = (base.as_object_mut(), extra.as_object()) {
        for (key, value) in extra {
            base.insert(key.clone(), value.clone());
        }
    }
    node(base)
}

fn taint(key: &str, value: &str, effect: &str) -> Taint {
    Taint {
        key: key.to_owned(),
        value: value.to_owned(),
        effect: effect.to_owned(),
    }
}

fn toleration(value: Value) -> rdy_spec::check::Toleration {
    serde_json::from_value(value).expect("a toleration")
}

#[test]
fn a_toleration_follows_the_rules_of_kubernetes() {
    let gpu = taint("nvidia.com/gpu", "present", "NoSchedule");
    let cases = [
        // No key and `Exists`: every taint.
        (json!({"operator": "Exists"}), true),
        // A key with no operator is `Equal`, and the value is compared.
        (json!({"key": "nvidia.com/gpu", "value": "present"}), true),
        (json!({"key": "nvidia.com/gpu", "value": "absent"}), false),
        (json!({"key": "nvidia.com/gpu"}), false),
        (json!({"key": "nvidia.com/gpu", "operator": "Exists"}), true),
        (json!({"key": "other", "operator": "Exists"}), false),
        // An effect narrows it.
        (
            json!({"key": "nvidia.com/gpu", "operator": "Exists", "effect": "NoSchedule"}),
            true,
        ),
        (
            json!({"key": "nvidia.com/gpu", "operator": "Exists", "effect": "NoExecute"}),
            false,
        ),
    ];
    for (spec, expect) in cases {
        assert_eq!(tolerates(&toleration(spec.clone()), &gpu), expect, "{spec}");
    }
    // `Equal` with no value matches an empty taint value.
    let bare = taint("acme.example/dedicated", "", "NoExecute");
    assert!(tolerates(
        &toleration(json!({"key": "acme.example/dedicated"})),
        &bare
    ));
}

#[test]
fn the_first_reason_that_applies_is_the_reason() {
    let every = params(json!({"min_ready": 1}));
    // Fargate before anything: a Fargate node is also Linux and Ready.
    let fargate = ready_node(json!({
        "metadata": {"name": "f", "labels": {"eks.amazonaws.com/compute-type": "fargate", "kubernetes.io/os": "linux"}}
    }));
    assert_eq!(fargate.excluded(&every), Some(Excluded::Fargate));
    // A Windows node that is also NotReady is `not Linux`.
    let windows = node(json!({
        "metadata": {"name": "w", "labels": {"kubernetes.io/os": "windows"}},
        "status": {"conditions": [{"type": "Ready", "status": "False"}]}
    }));
    assert_eq!(windows.excluded(&every), Some(Excluded::NotLinux));
    // The OS comes from nodeInfo when the label is missing.
    let by_info = node(json!({
        "metadata": {"name": "w2"},
        "status": {
            "conditions": [{"type": "Ready", "status": "True"}],
            "nodeInfo": {"machineID": "", "systemUUID": "", "bootID": "", "kernelVersion": "", "osImage": "",
                "containerRuntimeVersion": "", "kubeletVersion": "", "kubeProxyVersion": "",
                "operatingSystem": "windows", "architecture": "amd64"}
        }
    }));
    assert_eq!(by_info.excluded(&every), Some(Excluded::NotLinux));
    // A node that says nothing about its OS counts.
    let silent = node(json!({
        "metadata": {"name": "s"},
        "status": {"conditions": [{"type": "Ready", "status": "True"}]}
    }));
    assert_eq!(silent.excluded(&every), None);
    // A node with no Ready condition is not ready.
    let unknown = node(json!({"metadata": {"name": "u", "labels": {"kubernetes.io/os": "linux"}}}));
    assert_eq!(unknown.excluded(&every), Some(Excluded::NotReady));
    // Cordoned before not ready.
    let both = node(json!({
        "metadata": {"name": "b"},
        "spec": {"unschedulable": true},
        "status": {"conditions": [{"type": "Ready", "status": "Unknown"}]}
    }));
    assert_eq!(both.excluded(&every), Some(Excluded::Cordoned));
}

#[test]
fn only_no_schedule_and_no_execute_taints_exclude() {
    let none = params(json!({"min_ready": 1}));
    for (effect, excluded) in [
        ("NoSchedule", true),
        ("NoExecute", true),
        ("PreferNoSchedule", false),
        ("Something", false),
    ] {
        let tainted = ready_node(json!({
            "spec": {"taints": [{"key": "k", "effect": effect}]}
        }));
        assert_eq!(
            tainted.excluded(&none) == Some(Excluded::Tainted),
            excluded,
            "{effect}"
        );
    }
    // One untolerated taint is enough, even when another is tolerated.
    let two = ready_node(json!({
        "spec": {"taints": [{"key": "a", "effect": "NoSchedule"}, {"key": "b", "effect": "NoSchedule"}]}
    }));
    let tolerates_a =
        params(json!({"min_ready": 1, "tolerations": [{"key": "a", "operator": "Exists"}]}));
    assert_eq!(two.excluded(&tolerates_a), Some(Excluded::Tainted));
}

#[test]
fn an_unknown_architecture_never_matches_an_arch_list() {
    let amd = params(json!({"min_ready": 1, "arch": ["amd64"]}));
    let unlabeled = node(json!({
        "metadata": {"name": "n"},
        "status": {"conditions": [{"type": "Ready", "status": "True"}]}
    }));
    assert_eq!(unlabeled.excluded(&amd), Some(Excluded::Arch));
    assert_eq!(ready_node(json!({})).excluded(&amd), None);
}

#[test]
fn allocatable_is_read_in_every_quantity_form_and_garbage_is_none() {
    let read = node(json!({
        "metadata": {"name": "n"},
        "status": {"allocatable": {
            "cpu": "7910m", "memory": "32Gi", "ephemeral-storage": "1e11", "pods": "NaN"
        }}
    }));
    let nano = |resource| read.allocatable.get(resource).map(|a| a.nano());
    assert_eq!(nano(Resource::Cpu), Some(7_910_000_000));
    assert_eq!(nano(Resource::Memory), Some(32 * (1 << 30) * 1_000_000_000));
    assert_eq!(
        nano(Resource::Ephemeral),
        Some(100_000_000_000 * 1_000_000_000)
    );
    assert_eq!(nano(Resource::Pods), None);
    assert_eq!(read.capacity.get(Resource::Cpu), None);
}

#[test]
fn a_name_that_is_not_an_object_name_never_reaches_a_command() {
    assert_eq!(
        command_arg("ip-10-0-1-2.ec2.internal", "<node>"),
        "ip-10-0-1-2.ec2.internal"
    );
    let long = "a".repeat(65);
    for bad in [
        "--all",
        "-n",
        "a b",
        "NODE",
        "",
        "a;b",
        "a$(x)",
        long.as_str(),
    ] {
        assert_eq!(command_arg(bad, "<node>"), "<node>", "{bad}");
    }
}

#[test]
fn shown_escapes_and_cuts() {
    assert_eq!(shown("evil\u{1b}[2J"), "evil\\x1b[2J");
    assert!(!shown("\u{202e}x").contains('\u{202e}'));
    let long = "a".repeat(100);
    assert_eq!(shown(&long), format!("{}...", "a".repeat(64)));
}

#[test]
fn the_pressure_conditions_that_are_true_are_kept_in_order() {
    let under = node(json!({
        "metadata": {"name": "n"},
        "status": {"conditions": [
            {"type": "PIDPressure", "status": "True"},
            {"type": "MemoryPressure", "status": "True"},
            {"type": "DiskPressure", "status": "False"},
            {"type": "NetworkUnavailable", "status": "True"}
        ]}
    }));
    assert_eq!(
        under.pressure,
        ["MemoryPressure", "PIDPressure", "NetworkUnavailable"]
    );
}

#[test]
fn the_scaler_hint_follows_labels_then_the_autopilot_prefix() {
    let labeled =
        |labels: Value, name: &str| node(json!({"metadata": {"name": name, "labels": labels}}));
    assert_eq!(
        labeled(json!({"karpenter.sh/nodepool": "x"}), "a").scaler_hint(),
        Some("Karpenter")
    );
    assert_eq!(
        labeled(json!({"eks.amazonaws.com/compute-type": "auto"}), "a").scaler_hint(),
        Some("EKS Auto Mode")
    );
    assert_eq!(
        labeled(json!({"eks.amazonaws.com/compute-type": "ec2"}), "a").scaler_hint(),
        None
    );
    assert_eq!(
        labeled(json!({}), "gk3-pool-1").scaler_hint(),
        Some("GKE Autopilot")
    );
    assert_eq!(labeled(json!({}), "acme").scaler_hint(), None);
}

#[test]
fn the_taints_of_the_node_lifecycle_never_exclude_but_a_cut_taint_list_does() {
    let none = params(json!({"min_ready": 1}));
    for key in [
        "node.kubernetes.io/memory-pressure",
        "node.kubernetes.io/disk-pressure",
        "node.kubernetes.io/pid-pressure",
        "node.kubernetes.io/network-unavailable",
        "node.kubernetes.io/not-ready",
        "node.kubernetes.io/unreachable",
        "node.kubernetes.io/unschedulable",
    ] {
        let node = ready_node(json!({"spec": {"taints": [{"key": key, "effect": "NoSchedule"}]}}));
        assert_eq!(node.excluded(&none), None, "{key}");
    }
    // An operator's taint under the same prefix is still a taint.
    let other = ready_node(json!({
        "spec": {"taints": [{"key": "node.kubernetes.io/acme", "effect": "NoSchedule"}]}
    }));
    assert_eq!(other.excluded(&none), Some(Excluded::Tainted));
    // More taints than rdy keeps: it cannot say the rest are harmless.
    let many: Vec<Value> = (0..65)
        .map(|i| json!({"key": "node.kubernetes.io/not-ready", "effect": "NoSchedule", "value": i.to_string()}))
        .collect();
    let cut = ready_node(json!({"spec": {"taints": many}}));
    assert_eq!(cut.excluded(&none), Some(Excluded::Tainted));
}

#[test]
fn a_zone_label_of_zero_is_not_a_zone() {
    let labeled = |zone: &str| {
        ready_node(json!({
            "metadata": {"name": "n", "labels": {"topology.kubernetes.io/zone": zone}}
        }))
    };
    assert_eq!(labeled("0").zone, None);
    assert_eq!(labeled("1").zone.as_deref(), Some("1"));
    assert_eq!(labeled("us-east-1a").zone.as_deref(), Some("us-east-1a"));
}

#[test]
fn the_platform_follows_labels_and_the_version_and_auto_mode_is_its_own() {
    let with = |labels: Value, kubelet: &str| {
        node(json!({
            "metadata": {"name": "n", "labels": labels},
            "status": {"nodeInfo": {"machineID": "", "systemUUID": "", "bootID": "", "kernelVersion": "", "osImage": "",
                "containerRuntimeVersion": "", "kubeletVersion": kubelet, "kubeProxyVersion": "",
                "operatingSystem": "linux", "architecture": "amd64"}}
        }))
        .platform()
    };
    assert_eq!(with(json!({}), "v1.29.4-eks-abc1234"), Platform::Eks);
    assert_eq!(
        with(json!({"eks.amazonaws.com/nodegroup": "g"}), "v1.29.4"),
        Platform::Eks
    );
    assert_eq!(
        with(json!({"eks.amazonaws.com/compute-type": "auto"}), "v1.29.4"),
        Platform::EksAuto
    );
    assert_eq!(with(json!({}), "v1.29.4-gke.1000"), Platform::Gke);
    assert_eq!(
        with(json!({"kubernetes.azure.com/cluster": "c"}), "v1.29.4"),
        Platform::Aks
    );
    assert_eq!(
        with(json!({"node.openshift.io/os_id": "rhcos"}), "v1.29.4+abc"),
        Platform::OpenShift
    );
    assert_eq!(with(json!({}), "v1.29.4"), Platform::Other);
}

#[test]
fn the_pod_limit_fix_names_the_platform_and_only_eks_gets_prefix_delegation() {
    for (platform, must) in [
        (Platform::Eks, "ENABLE_PREFIX_DELEGATION=true"),
        (Platform::EksAuto, "NodePool"),
        (Platform::Gke, "--max-pods-per-node"),
        (Platform::Aks, "az aks nodepool add"),
        (Platform::OpenShift, "KubeletConfig"),
        (Platform::Other, "maxPods"),
    ] {
        let text = fix::pod_limit(platform, "acme-node-1");
        assert!(text.contains(must), "{platform:?}: {text}");
        assert_eq!(
            text.contains("ENABLE_PREFIX_DELEGATION"),
            platform == Platform::Eks,
            "{platform:?}"
        );
        if let Err(error) = rdy_engine::fixtext::check(&text) {
            panic!("{platform:?}: {error}\n{text}");
        }
    }
}
