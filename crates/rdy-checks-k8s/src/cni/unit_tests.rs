//! Unit tests of `k8s.cni`: the table, the ranges, the cut-down objects and the naming rules.

use serde_json::json;

use super::cidr::Net;
use super::judge::{Named, Signal, cheap_signals, name_plugin, settled};
use super::objects::{
    CniDaemonSet, CniNode, CniPolicy, ENV_NETWORK_POLICY, Kubeadm, OcpNetwork, ServiceCidrV1,
};
use super::table::{Enforces, Table, TableError};
use super::{family_hint, service_subnet};

const MARKER: &str = "ENV-VALUE-MARKER-4f9c2a7e1b3d";

fn shipped() -> &'static Table {
    Table::shipped().expect("the shipped table parses")
}

// ---- the table --------------------------------------------------------------------------------------------

#[test]
fn the_shipped_table_parses_and_holds_the_plugins_of_03() {
    let table = shipped();
    let ids: Vec<&str> = table.entries().iter().map(|e| e.id.as_str()).collect();
    for id in [
        "calico",
        "cilium",
        "anetd",
        "canal",
        "azure-cns",
        "rke2-cilium",
        "aws-vpc-cni",
        "azure-npm",
        "flannel",
        "weave",
        "antrea",
        "kube-router",
        "kube-ovn",
        "ovn-kubernetes",
        "openshift-sdn",
    ] {
        assert!(ids.contains(&id), "{id}");
    }
}

#[test]
fn the_table_says_which_plugins_enforce() {
    let table = shipped();
    let enforces = |id: &str| table.by_id(id).expect(id).enforces;
    for id in [
        "calico",
        "cilium",
        "anetd",
        "canal",
        "antrea",
        "weave",
        "kube-router",
        "ovn-kubernetes",
    ] {
        assert_eq!(enforces(id), Enforces::Yes, "{id}");
    }
    assert_eq!(enforces("flannel"), Enforces::No);
    assert_eq!(enforces("aws-vpc-cni"), Enforces::Env);
}

#[test]
fn the_daemonsets_of_the_table_are_the_pairs_of_03() {
    let pairs: Vec<String> = shipped()
        .daemonsets()
        .map(|(ns, name, _)| format!("{ns}/{name}"))
        .collect();
    assert_eq!(pairs.len(), 16);
    for want in [
        "kube-system/calico-node",
        "kube-system/cilium",
        "kube-system/anetd",
        "kube-system/canal",
        "kube-system/rke2-canal",
        "kube-system/azure-cns",
        "kube-system/rke2-cilium",
        "kube-system/aws-node",
        "kube-system/azure-npm",
        "kube-system/kube-flannel-ds",
        "kube-system/weave-net",
        "kube-system/antrea-agent",
        "kube-system/kube-router",
        "kube-system/kube-ovn-cni",
        "calico-system/calico-node",
        "kube-flannel/kube-flannel-ds",
    ] {
        assert!(pairs.iter().any(|p| p == want), "{want}");
    }
}

#[test]
fn the_guard_allows_exactly_the_daemonsets_of_the_table() {
    use crate::client::guard::{ALLOWED, Access};
    let allowed: std::collections::BTreeSet<String> = ALLOWED
        .iter()
        .filter(|e| e.resource == "daemonsets" && e.checks.contains(&"k8s.cni"))
        .flat_map(|e| e.access.iter())
        // The entry is shared with k8s.dns, which lists DaemonSets by label: only the named pairs are ours.
        .filter_map(|a| match a {
            Access::GetIn { namespace, name } => Some(format!("{namespace}/{name}")),
            _ => None,
        })
        .collect();
    let table: std::collections::BTreeSet<String> = shipped()
        .daemonsets()
        .map(|(ns, name, _)| format!("{ns}/{name}"))
        .collect();
    assert_eq!(allowed, table);
}

fn entry(extra: &str) -> String {
    format!(
        "schema = 1\n[[cni]]\nid = \"x\"\nname = \"X\"\nfamily = \"x\"\nnode_reasons = []\ncrd_groups = []\nnetwork_types = []\ndaemonsets = []\nrole = \"full\"\nenforces = \"yes\"\npod_cidr = \"own\"\nsource = \"https://example.org/x\"\nverified = true\nchecked_on = \"2026-11-17\"\n{extra}"
    )
}

#[test]
fn the_parser_refuses_what_it_should() {
    let bad = |text: &str| Table::parse(text).expect_err(text);
    assert!(matches!(bad("schema = 2\n"), TableError::Form(_)));
    assert!(matches!(bad("not toml ["), TableError::Form(_)));
    // The same entry twice.
    let twice = format!("{}{}", entry(""), &entry("")["schema = 1\n".len()..]);
    assert!(matches!(bad(&twice), TableError::Entry { .. }));
    for (from, to) in [
        ("id = \"x\"", "id = \"X Y\""),
        (
            "source = \"https://example.org/x\"",
            "source = \"http://example.org/x\"",
        ),
        ("checked_on = \"2026-11-17\"", "checked_on = \"yesterday\""),
        ("verified = true", "verified = false"),
        ("daemonsets = []", "daemonsets = [\"no-slash\"]"),
        (
            "daemonsets = []",
            "daemonsets = [\"a/b\", \"a/c\", \"a/d\", \"a/e\", \"a/f\"]",
        ),
        ("crd_groups = []", "crd_groups = [\"Not A Group\"]"),
        ("node_reasons = []", "node_reasons = [\"has space\"]"),
        ("enforces = \"yes\"", "enforces = \"maybe\""),
    ] {
        let text = entry("").replace(from, to);
        assert!(Table::parse(&text).is_err(), "{to}");
    }
    // A DaemonSet named by two entries.
    let two = format!(
        "{}[[cni]]\nid = \"y\"\nname = \"Y\"\nfamily = \"y\"\nnode_reasons = []\ncrd_groups = []\nnetwork_types = []\ndaemonsets = [\"a/b\"]\nrole = \"full\"\nenforces = \"yes\"\npod_cidr = \"own\"\nsource = \"https://example.org/y\"\nverified = true\nchecked_on = \"2026-11-17\"\n",
        entry("").replace("daemonsets = []", "daemonsets = [\"a/b\"]")
    );
    assert!(matches!(bad(&two), TableError::Entry { .. }));
}

// ---- ranges -----------------------------------------------------------------------------------------------

#[test]
fn ranges_overlap_when_one_holds_the_other() {
    let net = |text: &str| Net::parse(text).expect(text);
    assert!(net("10.96.0.0/12").overlaps(net("10.0.0.0/8")));
    assert!(net("10.0.0.0/8").overlaps(net("10.96.0.0/12")));
    assert!(net("10.244.1.0/24").overlaps(net("10.244.1.0/24")));
    assert!(!net("10.96.0.0/12").overlaps(net("10.112.0.0/12")));
    assert!(!net("192.168.0.0/16").overlaps(net("10.0.0.0/8")));
    // The edges: /0 holds everything of its family, /32 and /128 hold one address.
    assert!(net("0.0.0.0/0").overlaps(net("203.0.113.9/32")));
    assert!(net("203.0.113.9/32").overlaps(net("203.0.113.0/24")));
    assert!(!net("203.0.113.9/32").overlaps(net("203.0.113.10/32")));
    assert!(net("::/0").overlaps(net("fd00::1/128")));
    assert!(!net("fd00::1/128").overlaps(net("fd00::2/128")));
    // Two families never overlap, not even /0 with /0.
    assert!(!net("0.0.0.0/0").overlaps(net("::/0")));
    // Bits past the prefix do not count.
    assert!(net("10.1.2.3/8").overlaps(net("10.200.0.0/16")));
}

#[test]
fn text_that_is_not_a_range_is_not_read() {
    for text in [
        "",
        "10.0.0.0",
        "10.0.0.0/",
        "/8",
        "10.0.0.0/33",
        "10.0.0.0/08",
        "10.0.0.0/8 ",
        "::ffff:10.0.0.1/104",
        "10.0.0/8",
        "fd00::/129",
        "10.0.0.0/8,10.1.0.0/16",
        "a.b.c.d/8",
        "10.0.0.0/-1",
    ] {
        assert_eq!(Net::parse(text), None, "{text:?}");
    }
    assert_eq!(
        Net::parse("fd00::/8").map(|n| n.to_string()).as_deref(),
        Some("fd00::/8")
    );
    assert_eq!(
        Net::parse("10.1.2.3/8").map(|n| n.to_string()).as_deref(),
        Some("10.0.0.0/8")
    );
}

#[test]
fn the_kubeadm_service_subnet_is_read_from_the_networking_block_only() {
    let doc = "apiVersion: kubeadm.k8s.io/v1beta3\nkind: ClusterConfiguration\nnetworking:\n  dnsDomain: cluster.local\n  podSubnet: 10.244.0.0/16\n  serviceSubnet: 10.96.0.0/12\nscheduler: {}\n";
    assert_eq!(service_subnet(doc), ["10.96.0.0/12"]);
    let dual = "networking:\n  serviceSubnet: \"10.96.0.0/12, fd00:96::/108\"\n";
    assert_eq!(service_subnet(dual), ["10.96.0.0/12", "fd00:96::/108"]);
    // A serviceSubnet elsewhere is not the one.
    assert!(service_subnet("etcd:\n  serviceSubnet: 10.1.0.0/16\n").is_empty());
    assert!(service_subnet("").is_empty());
    assert!(service_subnet("networking:\n  podSubnet: 10.244.0.0/16\n").is_empty());
}

// ---- the cut-down objects ---------------------------------------------------------------------------------

#[test]
fn a_node_keeps_the_condition_the_ranges_and_the_kubelet_version_only() {
    let node: CniNode = serde_json::from_value(json!({
        "metadata": {"name": "n1", "annotations": {"a": MARKER}, "labels": {"l": MARKER}},
        "spec": {"podCIDR": "10.244.0.0/24", "podCIDRs": ["10.244.0.0/24", "fd00::/64"], "taints": [{"key": MARKER}]},
        "status": {
            "conditions": [
                {"type": "Ready", "status": "True", "reason": "KubeletReady"},
                {"type": "NetworkUnavailable", "status": "False", "reason": "FlannelIsUp", "message": MARKER}
            ],
            "nodeInfo": {"kubeletVersion": "v1.30.2", "machineID": MARKER},
            "images": [{"names": [MARKER]}]
        }
    }))
    .expect("parses");
    assert!(!format!("{node:?}").contains(MARKER), "{node:?}");
    let facts = node.facts();
    assert_eq!(facts.name, "n1");
    assert_eq!(facts.reason.as_deref(), Some("FlannelIsUp"));
    assert!(!facts.unavailable);
    assert_eq!(facts.pod_cidrs, ["10.244.0.0/24", "fd00::/64"]);
    assert_eq!(facts.kubelet_version.as_deref(), Some("v1.30.2"));
}

#[test]
fn an_older_node_with_only_pod_cidr_still_gives_its_range() {
    let node: CniNode = serde_json::from_value(
        json!({"metadata": {"name": "n1"}, "spec": {"podCIDR": "10.244.0.0/24"}}),
    )
    .expect("parses");
    assert_eq!(node.facts().pod_cidrs, ["10.244.0.0/24"]);
    let bare: CniNode = serde_json::from_value(json!({})).expect("parses");
    assert_eq!(bare.facts().reason, None);
}

#[test]
fn a_daemonset_keeps_the_counts_and_one_env_value_and_nothing_of_the_rest() {
    let long = format!("{MARKER}-and-a-long-tail");
    let ds: CniDaemonSet = serde_json::from_value(json!({
        "metadata": {
            "name": "aws-node", "namespace": "kube-system",
            "labels": {"k8s-app": "aws-node"},
            "annotations": {"kubectl.kubernetes.io/last-applied-configuration": format!("{{\"env\":\"{MARKER}\"}}")}
        },
        "spec": {"template": {"spec": {"containers": [
            {"name": "aws-node", "args": [MARKER], "command": [MARKER], "env": [
                {"name": "SYNTHETIC_TOKEN", "value": long},
                {"name": "SHORT", "value": "1"},
                {"name": "NODE", "valueFrom": {"fieldRef": {"fieldPath": "spec.nodeName"}}},
                {"name": ENV_NETWORK_POLICY, "value": "true"}
            ]},
            {"name": "agent", "env": [{"name": ENV_NETWORK_POLICY, "value": "false"}]}
        ]}}},
        "status": {"desiredNumberScheduled": 4, "numberReady": 3}
    }))
    .expect("parses");
    assert!(!format!("{ds:?}").contains(MARKER), "{ds:?}");
    let facts = ds.facts();
    assert_eq!((facts.desired, facts.ready), (4, 3));
    assert_eq!(facts.network_policy_env.as_deref(), Some("true"));
}

#[test]
fn an_enable_network_policy_value_that_is_long_is_dropped() {
    let ds: CniDaemonSet = serde_json::from_value(json!({
        "spec": {"template": {"spec": {"containers": [{"name": "c", "env": [
            {"name": ENV_NETWORK_POLICY, "value": MARKER}
        ]}]}}}
    }))
    .expect("parses");
    assert_eq!(ds.facts().network_policy_env, None);
}

#[test]
fn a_daemonset_with_no_env_or_null_lists_parses() {
    for body in [
        json!({"spec": {"template": {"spec": {"containers": [{"name": "c"}]}}}}),
        json!({"spec": {"template": {"spec": {"containers": [{"name": "c", "env": null}]}}}}),
        json!({"spec": {"template": {"spec": {"containers": null}}}}),
        json!({"spec": null, "status": null}),
    ] {
        let ds: CniDaemonSet = serde_json::from_value(body).expect("parses");
        assert_eq!(ds.facts().network_policy_env, None);
    }
}

#[test]
fn a_policy_keeps_its_shape_and_none_of_its_labels_or_annotations() {
    let policy: CniPolicy = serde_json::from_value(json!({
        "metadata": {"name": "p", "labels": {"x": MARKER}, "annotations": {"kubectl.kubernetes.io/last-applied-configuration": MARKER}},
        "spec": {
            "podSelector": {"matchLabels": {"app": MARKER}},
            "policyTypes": ["Egress"],
            "egress": [{"to": [{"ipBlock": {"cidr": MARKER}}], "ports": [{"port": 443}]}, {}]
        }
    }))
    .expect("parses");
    assert!(!format!("{policy:?}").contains(MARKER), "{policy:?}");
    let facts = policy.facts();
    assert!(
        !facts.selects_all,
        "a selector with labels selects some pods"
    );
    assert!(facts.egress);
    assert_eq!(facts.egress_rules.len(), 2);
    assert!(facts.egress_rules[0].has_to && facts.egress_rules[0].has_ports);
    assert!(!facts.egress_rules[1].has_to && !facts.egress_rules[1].has_ports);
}

#[test]
fn the_policy_types_default_as_kubernetes_does() {
    let facts = |spec: serde_json::Value| {
        serde_json::from_value::<CniPolicy>(json!({"metadata": {"name": "p"}, "spec": spec}))
            .expect("parses")
            .facts()
    };
    // No policyTypes and no egress rules: ingress only.
    assert!(!facts(json!({"podSelector": {}})).egress);
    // No policyTypes and egress rules: both.
    assert!(facts(json!({"podSelector": {}, "egress": [{}]})).egress);
    assert!(facts(json!({"podSelector": {}, "policyTypes": ["Egress"]})).egress);
    assert!(!facts(json!({"podSelector": {}, "policyTypes": ["Ingress"]})).egress);
    // An empty selector, with an empty matchExpressions, still selects everything.
    assert!(facts(json!({"podSelector": {"matchLabels": {}, "matchExpressions": []}})).selects_all);
    assert!(
        !facts(json!({"podSelector": {"matchExpressions": [{"key": "a", "operator": "Exists"}]}}))
            .selects_all
    );
}

#[test]
fn a_configmap_keeps_the_cluster_configuration_key_only() {
    let map: Kubeadm = serde_json::from_value(json!({
        "metadata": {"name": "kubeadm-config", "annotations": {"a": MARKER}},
        "data": {"ClusterConfiguration": "networking:\n  serviceSubnet: 10.96.0.0/12\n", "ClusterStatus": MARKER, "other": MARKER},
        "binaryData": {"x": MARKER}
    }))
    .expect("parses");
    assert!(!format!("{map:?}").contains(MARKER), "{map:?}");
    assert_eq!(
        map.cluster_configuration().as_deref(),
        Some("networking:\n  serviceSubnet: 10.96.0.0/12\n")
    );
    let none: Kubeadm = serde_json::from_value(json!({"data": null})).expect("parses");
    assert_eq!(none.cluster_configuration(), None);
}

#[test]
fn a_cluster_configuration_over_the_cap_is_dropped() {
    let big = "x".repeat(super::objects::MAX_KUBEADM + 1);
    let map: Kubeadm =
        serde_json::from_value(json!({"data": {"ClusterConfiguration": big}})).expect("parses");
    assert_eq!(map.cluster_configuration(), None);
}

#[test]
fn a_service_cidr_and_the_openshift_network_keep_ranges_only() {
    let cidr: ServiceCidrV1 = serde_json::from_value(json!({
        "metadata": {"name": "kubernetes", "annotations": {"a": MARKER}},
        "spec": {"cidrs": ["10.96.0.0/12", "fd00::/108"]}
    }))
    .expect("parses");
    assert_eq!(cidr.cidrs(), ["10.96.0.0/12", "fd00::/108"]);
    let net: OcpNetwork = serde_json::from_value(json!({
        "metadata": {"name": "cluster", "annotations": {"a": MARKER}},
        "spec": {"externalIP": {"policy": MARKER}},
        "status": {"networkType": "OVNKubernetes", "clusterNetwork": [{"cidr": "10.128.0.0/14", "hostPrefix": 23}], "serviceNetwork": ["172.30.0.0/16"]}
    }))
    .expect("parses");
    assert!(!format!("{net:?}").contains(MARKER));
    let facts = net.facts();
    assert_eq!(facts.network_type.as_deref(), Some("OVNKubernetes"));
    assert_eq!(facts.pod_cidrs, ["10.128.0.0/14"]);
    assert_eq!(facts.service_cidrs, ["172.30.0.0/16"]);
}

#[test]
fn a_long_list_is_cut_while_it_is_read() {
    let many: Vec<String> = (0..500)
        .map(|i| format!("10.{}.{}.0/24", i / 256, i % 256))
        .collect();
    let node: CniNode =
        serde_json::from_value(json!({"spec": {"podCIDRs": many}})).expect("parses");
    assert_eq!(node.facts().pod_cidrs.len(), 64);
}

// ---- naming the plugin ------------------------------------------------------------------------------------

fn node_with(reason: Option<&str>, kubelet: &str) -> super::objects::NodeFacts {
    let conditions = reason
        .map(|r| json!([{"type": "NetworkUnavailable", "status": "False", "reason": r}]))
        .unwrap_or(json!([]));
    serde_json::from_value::<CniNode>(json!({
        "metadata": {"name": "n"},
        "status": {"conditions": conditions, "nodeInfo": {"kubeletVersion": kubelet}}
    }))
    .expect("parses")
    .facts()
}

fn named<'t>(table: &'t Table, nodes: &[super::objects::NodeFacts], groups: &[&str]) -> Named<'t> {
    let groups: Vec<String> = groups.iter().map(|g| (*g).to_owned()).collect();
    name_plugin(table, cheap_signals(table, nodes, &groups, None))
}

#[test]
fn flannel_with_calico_is_canal_and_either_alone_is_itself() {
    let table = shipped();
    let flannel = [node_with(Some("FlannelIsUp"), "v1.30.2")];
    let id = |n: Named<'_>| match n {
        Named::One(entry, _) => entry.id.clone(),
        other => format!("{other:?}"),
    };
    assert_eq!(id(named(table, &flannel, &[])), "flannel");
    assert_eq!(
        id(named(table, &flannel, &["crd.projectcalico.org"])),
        "canal"
    );
    assert_eq!(id(named(table, &[], &["crd.projectcalico.org"])), "calico");
    // Two other families are ambiguous.
    let two = named(table, &[], &["crd.projectcalico.org", "cilium.io"]);
    assert!(matches!(two, Named::Several(_)), "{two:?}");
    // Multus names nothing.
    assert!(matches!(
        named(table, &[], &["k8s.cni.cncf.io"]),
        Named::Nothing
    ));
    // No signal.
    assert!(matches!(
        named(table, &[node_with(Some("RouteCreated"), "v1.30.2")], &[]),
        Named::Nothing
    ));
}

#[test]
fn only_the_vpc_cni_needs_its_daemonset_after_a_cheap_signal() {
    let table = shipped();
    let nodes = [node_with(Some("CalicoIsUp"), "v1.30.2")];
    let signals = cheap_signals(table, &nodes, &[], None);
    assert!(settled(table, &signals));
    assert!(!settled(table, &[]));
    let aws = table.by_id("aws-vpc-cni").expect("aws");
    assert!(!settled(
        table,
        &[(aws, Signal::DaemonSet("kube-system/aws-node".to_owned()))]
    ));
}

#[test]
fn the_kubelet_version_orders_the_daemonset_reads_and_nothing_more() {
    let hint = |v: &str| family_hint(&[node_with(None, v)]);
    assert_eq!(hint("v1.30.4-eks-a737599"), Some("aws-vpc-cni"));
    assert_eq!(hint("v1.30.4-gke.1348000"), Some("cilium"));
    assert_eq!(hint("v1.30.4+rke2r1"), Some("canal"));
    assert_eq!(hint("v1.30.4"), None);
    assert_eq!(hint("v1.30.4+k3s1"), None);
}

#[test]
fn the_openshift_network_type_names_the_plugin() {
    let table = shipped();
    let signals = cheap_signals(
        table,
        &[],
        &["config.openshift.io".to_owned()],
        Some("OVNKubernetes"),
    );
    assert!(matches!(name_plugin(table, signals), Named::One(e, _) if e.id == "ovn-kubernetes"));
    let signals = cheap_signals(table, &[], &[], Some("OpenShiftSDN"));
    assert!(matches!(name_plugin(table, signals), Named::One(e, _) if e.id == "openshift-sdn"));
    assert!(cheap_signals(table, &[], &[], Some("SomethingElse")).is_empty());
}

#[test]
fn a_policy_plugin_on_top_of_a_base_plugin_is_the_policy_plugin() {
    let table = shipped();
    let id = |n: Named<'_>| match n {
        Named::One(entry, _) => entry.id.clone(),
        other => format!("{other:?}"),
    };
    let ds = |entry: &str, pair: &str| {
        (
            table.by_id(entry).expect(entry),
            Signal::DaemonSet(pair.to_owned()),
        )
    };
    let crd = |entry: &str, group: &str| {
        (
            table.by_id(entry).expect(entry),
            Signal::CrdGroup(group.to_owned()),
        )
    };
    // Calico over the VPC CNI (EKS), over Azure CNI (AKS), Cilium in chaining mode over the VPC CNI.
    let calico_aws = vec![
        crd("calico", "crd.projectcalico.org"),
        ds("aws-vpc-cni", "kube-system/aws-node"),
    ];
    assert_eq!(id(name_plugin(table, calico_aws)), "calico");
    let calico_azure = vec![
        crd("calico", "crd.projectcalico.org"),
        ds("azure-cns", "kube-system/azure-cns"),
    ];
    assert_eq!(id(name_plugin(table, calico_azure)), "calico");
    let cilium_aws = vec![
        crd("cilium", "cilium.io"),
        ds("aws-vpc-cni", "kube-system/aws-node"),
    ];
    assert_eq!(id(name_plugin(table, cilium_aws)), "cilium");
    // Azure CNI with the Azure network policy manager.
    let azure = vec![
        ds("azure-cns", "kube-system/azure-cns"),
        ds("azure-npm", "kube-system/azure-npm"),
    ];
    assert_eq!(id(name_plugin(table, azure)), "azure-npm");
    // Two policy plugins, or a policy plugin over a full plugin, are still ambiguous.
    let two = vec![
        crd("calico", "crd.projectcalico.org"),
        crd("cilium", "cilium.io"),
    ];
    assert!(matches!(name_plugin(table, two), Named::Several(_)));
    let full = vec![
        crd("calico", "crd.projectcalico.org"),
        crd("antrea", "crd.antrea.io"),
    ];
    assert!(matches!(name_plugin(table, full), Named::Several(_)));
    // A base plugin alone is itself.
    assert_eq!(
        id(name_plugin(
            table,
            vec![ds("azure-cns", "kube-system/azure-cns")]
        )),
        "azure-cns"
    );
}

#[test]
fn azure_cni_alone_does_not_enforce_and_the_table_says_where_names_are_verified() {
    let table = shipped();
    assert_eq!(
        table.by_id("azure-cns").expect("azure-cns").enforces,
        Enforces::No
    );
    for entry in table.entries() {
        assert_eq!(entry.verified, entry.checked_on.is_some(), "{}", entry.id);
    }
    assert!(table.by_id("flannel").expect("flannel").verified);
    assert!(table.by_id("aws-vpc-cni").expect("aws").verified);
    assert!(!table.by_id("calico").expect("calico").verified);
    assert!(table.by_id("rke2-calico").is_none());
}

#[test]
fn a_selector_with_labels_is_counted_and_its_keys_are_not_kept() {
    let policy: CniPolicy = serde_json::from_value(json!({
        "metadata": {"name": "p"},
        "spec": {"podSelector": {"matchLabels": {MARKER: "x"}}, "policyTypes": ["Egress"]}
    }))
    .expect("parses");
    assert!(!format!("{policy:?}").contains(MARKER), "{policy:?}");
    assert!(!policy.facts().selects_all);
}

#[test]
fn the_service_subnet_read_keeps_nothing_else_of_the_document() {
    let doc = format!(
        "apiServer:\n  extraArgs:\n    oidc-client-secret: {MARKER}\nnetworking:\n  serviceSubnet: 10.96.0.0/12\n"
    );
    let found = service_subnet(&doc);
    assert_eq!(found, ["10.96.0.0/12"]);
    assert!(!format!("{found:?}").contains(MARKER));
}
