//! Tests of the parameter structs of the 14 M1-late check ids (M1-172).
//!
//! Each struct has one fixture that sets every field and a rejected value for every field. The shared
//! checks in [`run_case_checks`] also prove that a key the struct does not have is refused by name and
//! that a key with no value is a bad value, so the format stays closed.

use serde_json::{Value, json};

use super::testkit::{Case, assert_printable, fields_match, run_case_checks, typed, why};
use super::*;
use crate::Version;

/// `n` distinct strings made by `make`, as a JSON list.
fn many(n: usize, make: impl Fn(usize) -> String) -> Vec<Value> {
    (0..n).map(|i| json!(make(i))).collect()
}

fn cases() -> Vec<Case> {
    let long_name = "a".repeat(254);
    let mut cases = host_cases();
    cases.extend(net_cases());
    cases.extend(k8s_cases(&long_name));
    cases
}

fn host_cases() -> Vec<Case> {
    let ports_257: Vec<Value> = (1..=257).map(|p| json!(p)).collect();
    let servers_9 = many(9, |i| format!("ntp{i}.acme.example"));
    let params_65: Value =
        Value::Object((0..65).map(|i| (format!("a.b{i}"), json!("1"))).collect());
    let distros_17: Value =
        Value::Object((0..17).map(|i| (format!("d{i}"), json!("5.4"))).collect());
    let modules_65 = many(65, |i| format!("mod{i}"));
    let controllers_33 = many(33, |i| format!("c{i}"));
    vec![
        Case {
            id: "host.firewall",
            full: json!({"open_inbound": [6443, 10250]}),
            bad: vec![
                ("open_inbound", json!([])),
                ("open_inbound", json!(6443)),
                ("open_inbound", json!([0])),
                ("open_inbound", json!([65536])),
                ("open_inbound", json!([6443, 6443])),
                ("open_inbound", json!(["6443"])),
                ("open_inbound", json!([1.5])),
                ("open_inbound", Value::Array(ports_257)),
            ],
            fields: HostFirewall::FIELDS,
        },
        Case {
            id: "host.time_sync",
            full: json!({
                "max_skew": "5s", "require_sync": true,
                "ntp_servers": ["ntp.acme.example", "10.0.0.1:1123", "[fd00:ec2::123]"]
            }),
            bad: vec![
                ("max_skew", json!("0s")),
                ("max_skew", json!("5")),
                ("max_skew", json!(5)),
                ("max_skew", json!("fast")),
                ("require_sync", json!("yes")),
                ("require_sync", json!(1)),
                ("ntp_servers", json!([])),
                ("ntp_servers", json!("ntp.acme.example")),
                ("ntp_servers", Value::Array(servers_9)),
                ("ntp_servers", json!([""])),
                ("ntp_servers", json!(["http://ntp.acme.example"])),
                ("ntp_servers", json!(["ntp.acme.example/x"])),
                ("ntp_servers", json!(["ntp.acme.example:0"])),
                ("ntp_servers", json!(["ntp.acme.example:99999"])),
                ("ntp_servers", json!(["ntp.acme.example:"])),
                ("ntp_servers", json!(["a b"])),
                ("ntp_servers", json!(["user:pw@ntp.acme.example"])),
                ("ntp_servers", json!(["2852039166"])),
                ("ntp_servers", json!(["0xa9.0xfe.0xa9.0xfe"])),
                ("ntp_servers", json!(["ntp.acme.example."])),
                ("ntp_servers", json!(["::ffff:10.0.0.1"])),
                ("ntp_servers", json!(["fd00::g"])),
                ("ntp_servers", json!(["[fd00::1"])),
                (
                    "ntp_servers",
                    json!([format!("{}.example", "a".repeat(300))]),
                ),
                ("ntp_servers", json!([7])),
                // The same server written twice, in different spellings.
                ("ntp_servers", json!(["a.example", "A.example"])),
                ("ntp_servers", json!(["fd00::1", "[fd00::1]:123"])),
                ("ntp_servers", json!(["a.example", "a.example:123"])),
            ],
            fields: HostTimeSync::FIELDS,
        },
        Case {
            id: "host.sysctl",
            full: json!({
                "expect": {
                    "vm.max_map_count": ">=262144",
                    "net.ipv4.ip_forward": 1,
                    "net/ipv4/conf/eth0.100/rp_filter": "2",
                    "net.ipv4.tcp_congestion_control": "bbr",
                    "fs.file-max": "<= 9999999"
                },
                "limits": {"nofile": ">=65536"}
            }),
            bad: vec![
                ("expect", json!({})),
                ("expect", json!([])),
                ("expect", json!("vm.max_map_count")),
                ("expect", params_65),
                ("expect", json!({"vm.max_map_count": ""})),
                ("expect", json!({"vm.max_map_count": ">5"})),
                ("expect", json!({"vm.max_map_count": "<5"})),
                ("expect", json!({"vm.max_map_count": ">="})),
                ("expect", json!({"vm.max_map_count": ">=abc"})),
                ("expect", json!({"vm.max_map_count": ">=  1"})),
                ("expect", json!({"vm.max_map_count": ">=1.5"})),
                ("expect", json!({"vm.max_map_count": "=5"})),
                ("expect", json!({"vm.max_map_count": "==5"})),
                ("expect", json!({"vm.max_map_count": " 5"})),
                ("expect", json!({"vm.max_map_count": "5 "})),
                ("expect", json!({"vm.max_map_count": 1.5})),
                ("expect", json!({"vm.max_map_count": true})),
                ("expect", json!({"vm.max_map_count": ["1"]})),
                ("expect", json!({"vm.max_map_count": "x".repeat(129)})),
                ("expect", json!({"vm.max_map_count": "a\u{1b}b"})),
                ("expect", json!({"": "1"})),
                ("expect", json!({"vm..x": "1"})),
                ("expect", json!({".vm": "1"})),
                ("expect", json!({"vm.": "1"})),
                ("expect", json!({"-vm.x": "1"})),
                ("expect", json!({"vm/../x": "1"})),
                ("expect", json!({"./x": "1"})),
                ("expect", json!({"/etc/passwd": "1"})),
                ("expect", json!({"a/b/": "1"})),
                ("expect", json!({"a//b": "1"})),
                ("expect", json!({"vm x": "1"})),
                ("expect", json!({"vm.x\u{202e}": "1"})),
                ("expect", json!({"a".repeat(129): "1"})),
                ("limits", json!({})),
                ("limits", json!([])),
                ("limits", json!("nofile")),
                ("limits", json!({"nofile": ""})),
                ("limits", json!({"nofile": ">=x"})),
                ("limits", json!({"nofile": true})),
                ("limits", json!({"open_files": ">=1"})),
            ],
            fields: HostSysctl::FIELDS,
        },
        Case {
            id: "host.container_runtime",
            full: json!({
                "runtime": ["docker", "containerd", "podman", "crio"], "min_version": "1.7",
                "cgroup_driver": "systemd", "storage_driver": "overlay2"
            }),
            bad: vec![
                ("runtime", json!([])),
                ("runtime", json!("docker")),
                ("runtime", json!(["docker", "docker"])),
                ("runtime", json!(["lxc"])),
                ("runtime", json!(["Docker"])),
                ("runtime", json!(["cri-o"])),
                ("runtime", json!([1])),
                ("min_version", json!("")),
                ("min_version", json!("latest")),
                ("min_version", json!(1.3)),
                ("min_version", json!("1.2.3.4.5")),
                ("min_version", json!(">=1.7")),
                ("cgroup_driver", json!("cgroupv2")),
                ("cgroup_driver", json!("Systemd")),
                ("cgroup_driver", json!(true)),
                ("storage_driver", json!("")),
                ("storage_driver", json!("Overlay2")),
                ("storage_driver", json!("x".repeat(33))),
                ("storage_driver", json!("over lay")),
                ("storage_driver", json!(5)),
            ],
            fields: HostContainerRuntime::FIELDS,
        },
        Case {
            id: "host.cgroups",
            full: json!({"version": "v2", "controllers": ["cpu", "memory", "io", "pids"]}),
            bad: vec![
                ("version", json!("v3")),
                ("version", json!("V2")),
                ("version", json!("hybrid")),
                ("version", json!(2)),
                ("version", json!(true)),
                ("controllers", json!([])),
                ("controllers", json!("cpu")),
                ("controllers", json!(["cpu", "cpu"])),
                ("controllers", json!([""])),
                ("controllers", json!(["CPU"])),
                ("controllers", json!(["cpu memory"])),
                ("controllers", json!(["x".repeat(33)])),
                ("controllers", json!([1])),
                ("controllers", Value::Array(controllers_33)),
            ],
            fields: HostCgroups::FIELDS,
        },
        Case {
            id: "host.kernel",
            full: json!({
                "min": "5.4", "distro_min": {"rhel": "4.18.0-305", "ubuntu": "5.15"},
                "modules": ["overlay", "br_netfilter", "xt_TCPMSS"], "btf": true
            }),
            bad: vec![
                ("min", json!("")),
                ("min", json!("latest")),
                ("min", json!(5.1)),
                ("min", json!("v5.4")),
                ("min", json!("5.4-")),
                ("min", json!("-305")),
                ("min", json!("5.4.x")),
                ("min", json!("4.18.0--305")),
                ("min", json!("4.18.0-305-1")),
                ("min", json!("4.18.0-305.el8")),
                ("min", json!("1.2.3.4.5")),
                ("min", json!("5.4 ")),
                ("min", json!(true)),
                ("distro_min", json!({})),
                ("distro_min", json!([])),
                ("distro_min", json!("rhel")),
                ("distro_min", json!({"RHEL": "4"})),
                ("distro_min", json!({"": "4"})),
                ("distro_min", json!({"r h": "4"})),
                ("distro_min", json!({"rhel": ""})),
                ("distro_min", json!({"rhel": "x"})),
                ("distro_min", json!({"rhel": 4.18})),
                ("distro_min", distros_17),
                ("modules", json!([])),
                ("modules", json!("overlay")),
                ("modules", json!(["overlay", "overlay"])),
                ("modules", json!([""])),
                ("modules", json!(["over lay"])),
                ("modules", json!(["overlay.ko"])),
                ("modules", json!(["x".repeat(65)])),
                ("modules", json!([1])),
                ("modules", Value::Array(modules_65)),
                ("btf", json!("yes")),
                ("btf", json!(1)),
            ],
            fields: HostKernel::FIELDS,
        },
    ]
}

fn net_cases() -> Vec<Case> {
    let registries_17 = many(17, |i| format!("r{i}.acme.example"));
    let hosts_9 = many(9, |i| format!("h{i}.acme.example"));
    let images_17 = many(17, |i| format!("acme/a{i}:1"));
    vec![
        Case {
            id: "net.registry",
            full: json!({"registries": [
                "registry.acme.example",
                {"host": "registry.acme.example:5000",
                 "hosts": ["auth.acme.example", "blobs.acme.example:443"],
                 "images": ["acme/agent:1.4", "library/nginx:1.27-alpine"], "optional": true}
            ]}),
            bad: vec![
                ("registries", json!([])),
                ("registries", json!("registry.acme.example")),
                ("registries", Value::Array(registries_17)),
                ("registries", json!([""])),
                ("registries", json!(["https://registry.acme.example"])),
                ("registries", json!(["registry.acme.example:0"])),
                ("registries", json!(["registry.acme.example."])),
                ("registries", json!(["a b"])),
                ("registries", json!(["user:pw@registry.acme.example"])),
                ("registries", json!([7])),
                ("registries", json!([{"optional": true}])),
                ("registries", json!([{"host": "a.example", "retries": 1}])),
                (
                    "registries",
                    json!([{"host": "a.example", "optional": "yes"}]),
                ),
                ("registries", json!([{"host": "a.example", "hosts": []}])),
                (
                    "registries",
                    json!([{"host": "a.example", "hosts": "b.example"}]),
                ),
                (
                    "registries",
                    json!([{"host": "a.example", "hosts": hosts_9}]),
                ),
                (
                    "registries",
                    json!([{"host": "a.example", "hosts": ["b.example", "b.example"]}]),
                ),
                (
                    "registries",
                    json!([{"host": "a.example", "hosts": ["https://b.example"]}]),
                ),
                ("registries", json!([{"host": "a.example", "images": []}])),
                (
                    "registries",
                    json!([{"host": "a.example", "images": images_17}]),
                ),
                (
                    "registries",
                    json!([{"host": "a.example", "images": ["a:1", "a:1"]}]),
                ),
                (
                    "registries",
                    json!([{"host": "a.example", "images": ["acme/agent"]}]),
                ),
                (
                    "registries",
                    json!([{"host": "a.example", "images": ["Acme/agent:1"]}]),
                ),
                (
                    "registries",
                    json!([{"host": "a.example", "images": ["acme/agent:"]}]),
                ),
                (
                    "registries",
                    json!([{"host": "a.example", "images": ["acme//agent:1"]}]),
                ),
                (
                    "registries",
                    json!([{"host": "a.example", "images": ["/acme:1"]}]),
                ),
                (
                    "registries",
                    json!([{"host": "a.example", "images": ["acme/-agent:1"]}]),
                ),
                (
                    "registries",
                    json!([{"host": "a.example", "images": ["acme/agent-:1"]}]),
                ),
                (
                    "registries",
                    json!([{"host": "a.example", "images": ["acme/agent:-1"]}]),
                ),
                (
                    "registries",
                    json!([{"host": "a.example", "images": ["acme/agent:."]}]),
                ),
                (
                    "registries",
                    json!([{"host": "a.example", "images": ["acme/a.-b:1"]}]),
                ),
                (
                    "registries",
                    json!([{"host": "a.example", "images": [format!("acme/agent:{}", "x".repeat(129))]}]),
                ),
                (
                    "registries",
                    json!([{"host": "a.example", "images": ["acme/agent@sha256:0123456789abcdef"]}]),
                ),
                ("registries", json!([{"host": "a.example", "images": [1]}])),
            ],
            fields: NetRegistry::FIELDS,
        },
        Case {
            id: "net.mtu",
            full: json!({"min_mtu": 1400, "overlay": "vxlan", "underlay": "ipv6"}),
            bad: vec![
                ("min_mtu", json!(0)),
                ("min_mtu", json!(67)),
                ("min_mtu", json!(65536)),
                ("min_mtu", json!(-1)),
                ("min_mtu", json!("1400")),
                ("min_mtu", json!(1400.5)),
                ("overlay", json!("gre")),
                ("overlay", json!("VXLAN")),
                ("overlay", json!(true)),
                ("underlay", json!("ipv5")),
                ("underlay", json!("IPv4")),
                ("underlay", json!(6)),
            ],
            fields: NetMtu::FIELDS,
        },
        Case {
            id: "net.bandwidth",
            full: json!({
                "url": "https://mirror.acme.example/sample.bin", "bytes": "10Mi",
                "min_mbps": 50, "recommended_mbps": 100.5
            }),
            bad: vec![
                ("url", json!("")),
                ("url", json!("mirror.acme.example:443")),
                ("url", json!("mirror.acme.example")),
                ("url", json!("ftp://mirror.acme.example/x")),
                ("url", json!("https://user:pw@mirror.acme.example/x")),
                ("url", json!("https://mirror.acme.example/x#frag")),
                ("url", json!("https://")),
                ("url", json!("https://a b.example/x")),
                ("url", json!(5)),
                ("bytes", json!("512Ki")),
                ("bytes", json!(1_048_575)),
                ("bytes", json!("101Mi")),
                ("bytes", json!("10G")),
                ("bytes", json!("ten")),
                ("bytes", json!(0)),
                ("bytes", json!(-1)),
                ("min_mbps", json!(0)),
                ("min_mbps", json!(-1)),
                ("min_mbps", json!(100_001)),
                ("min_mbps", json!("50")),
                ("min_mbps", json!(true)),
                ("recommended_mbps", json!(0)),
                ("recommended_mbps", json!(-0.5)),
                ("recommended_mbps", json!(100_000.5)),
                ("recommended_mbps", json!("fast")),
            ],
            fields: NetBandwidth::FIELDS,
        },
    ]
}

fn k8s_cases(long_name: &str) -> Vec<Case> {
    let quotas_33: Value =
        Value::Object((0..33).map(|i| (format!("count/r{i}"), json!(1))).collect());
    let crds_65: Vec<Value> = (0..65)
        .map(|i| json!({"name": format!("r{i}.acme.example")}))
        .collect();
    let operators_17: Vec<Value> = (0..17)
        .map(|i| json!({"namespace": format!("ns{i}"), "deployment": "op"}))
        .collect();
    let versions_17 = many(17, |i| format!("v{i}"));
    let egress_65 = many(65, |i| format!("h{i}.acme.example:443"));
    let cidrs_33 = many(33, |i| format!("10.{i}.0.0/16"));
    vec![
        Case {
            id: "k8s.namespace",
            full: json!({
                "namespace": "acme-system",
                "quota_needs": {"requests.cpu": 16, "requests.memory": "64Gi", "pods": 100,
                                "limits.cpu": "500m", "count/jobs.batch": 0.5},
                "limit_needs": {"container_max_memory": "16Gi"}
            }),
            bad: vec![
                ("namespace", json!("")),
                ("namespace", json!("Acme")),
                ("namespace", json!("-a")),
                ("namespace", json!("a_b")),
                ("namespace", json!(long_name)),
                ("namespace", json!(7)),
                ("quota_needs", json!({})),
                ("quota_needs", json!([])),
                ("quota_needs", json!("pods")),
                ("quota_needs", quotas_33),
                ("quota_needs", json!({"": 1})),
                ("quota_needs", json!({"requests cpu": 1})),
                ("quota_needs", json!({"a".repeat(254): 1})),
                ("quota_needs", json!({"pods": ""})),
                ("quota_needs", json!({"pods": "-1"})),
                ("quota_needs", json!({"pods": -1})),
                ("quota_needs", json!({"pods": "1 Gi"})),
                ("quota_needs", json!({"pods": "1K"})),
                ("quota_needs", json!({"pods": "1e3"})),
                ("quota_needs", json!({"pods": "1.5.2"})),
                ("quota_needs", json!({"pods": "."})),
                ("quota_needs", json!({"pods": "1."})),
                ("quota_needs", json!({"pods": "Gi"})),
                ("quota_needs", json!({"pods": true})),
                ("quota_needs", json!({"pods": [1]})),
                ("quota_needs", json!({"pods": 1e16})),
                ("quota_needs", json!({"pods": "1".repeat(21)})),
                ("limit_needs", json!({})),
                ("limit_needs", json!([])),
                ("limit_needs", json!("16Gi")),
                ("limit_needs", json!({"container_max_memory": ""})),
                ("limit_needs", json!({"container_max_memory": "16G"})),
                ("limit_needs", json!({"container_min_memory": "1Gi"})),
            ],
            fields: K8sNamespace::FIELDS,
        },
        Case {
            id: "k8s.dns",
            full: json!({"cluster_domain": "cluster.local"}),
            bad: vec![
                ("cluster_domain", json!("")),
                ("cluster_domain", json!("Cluster.Local")),
                ("cluster_domain", json!("cluster..local")),
                ("cluster_domain", json!(".local")),
                ("cluster_domain", json!("a_b.local")),
                ("cluster_domain", json!(long_name)),
                ("cluster_domain", json!(7)),
            ],
            fields: K8sDns::FIELDS,
        },
        Case {
            id: "k8s.ingress",
            full: json!({
                "controller": "k8s.io/ingress-nginx", "gateway_api": "required",
                "route": true, "loadbalancer": true
            }),
            bad: vec![
                ("controller", json!("")),
                ("controller", json!("x".repeat(254))),
                ("controller", json!("nginx ingress")),
                ("controller", json!("k8s.io/ingress-nginx\n")),
                ("controller", json!(5)),
                ("gateway_api", json!("yes")),
                ("gateway_api", json!("Required")),
                ("gateway_api", json!(true)),
                ("gateway_api", json!("")),
                ("route", json!("yes")),
                ("route", json!(1)),
                ("loadbalancer", json!("true")),
                ("loadbalancer", json!(0)),
            ],
            fields: K8sIngress::FIELDS,
        },
        Case {
            id: "k8s.crds",
            full: json!({
                "crds": [
                    {"name": "certificates.cert-manager.io", "versions": ["v1", "v1beta1"]},
                    {"name": "issuers.cert-manager.io"}
                ],
                "operators": [{"namespace": "cert-manager", "deployment": "cert-manager",
                               "min_version": "1.13"}]
            }),
            bad: vec![
                ("crds", json!([])),
                ("crds", json!("certificates.cert-manager.io")),
                ("crds", Value::Array(crds_65)),
                ("crds", json!(["certificates.cert-manager.io"])),
                ("crds", json!([{}])),
                ("crds", json!([{"name": "Bad"}])),
                ("crds", json!([{"name": "a.b", "retries": 1}])),
                ("crds", json!([{"name": "a.b", "versions": []}])),
                ("crds", json!([{"name": "a.b", "versions": ["1"]}])),
                ("crds", json!([{"name": "a.b", "versions": ["V1"]}])),
                ("crds", json!([{"name": "a.b", "versions": ["v"]}])),
                ("crds", json!([{"name": "a.b", "versions": ["v1", "v1"]}])),
                ("crds", json!([{"name": "a.b", "versions": versions_17}])),
                ("operators", json!([])),
                ("operators", json!("cert-manager")),
                ("operators", Value::Array(operators_17)),
                ("operators", json!([{"namespace": "cm"}])),
                ("operators", json!([{"deployment": "d"}])),
                (
                    "operators",
                    json!([{"namespace": "cm", "deployment": "d", "min_version": "x"}]),
                ),
                ("operators", json!([{"namespace": "CM", "deployment": "d"}])),
                (
                    "operators",
                    json!([{"namespace": "cm", "deployment": "d", "image": "x"}]),
                ),
            ],
            fields: K8sCrds::FIELDS,
        },
        Case {
            id: "k8s.cni",
            full: json!({
                "network_policy": "enforced",
                "needs_egress": ["db.acme.example:5432", "[fd00::1]:443"],
                "avoid_cidrs": ["10.0.0.0/8", "fd00::/8"]
            }),
            bad: vec![
                ("network_policy", json!("any")),
                ("network_policy", json!("Enforced")),
                ("network_policy", json!(true)),
                ("needs_egress", json!([])),
                ("needs_egress", json!("db.acme.example:5432")),
                ("needs_egress", json!(["db.acme.example"])),
                ("needs_egress", json!(["https://db.acme.example"])),
                ("needs_egress", json!(["http://db.acme.example:80/x"])),
                ("needs_egress", json!(["db.acme.example:0"])),
                (
                    "needs_egress",
                    json!(["db.acme.example:443", "db.acme.example:443"]),
                ),
                ("needs_egress", Value::Array(egress_65)),
                ("needs_egress", json!([1])),
                ("avoid_cidrs", json!([])),
                ("avoid_cidrs", json!("10.0.0.0/8")),
                ("avoid_cidrs", json!(["10.0.0.0"])),
                ("avoid_cidrs", json!(["10.0.0.0/33"])),
                ("avoid_cidrs", json!(["10.0.0.0/8", "10.0.0.0/8"])),
                ("avoid_cidrs", json!([""])),
                ("avoid_cidrs", Value::Array(cidrs_33)),
            ],
            fields: K8sCni::FIELDS,
        },
    ]
}

// ---- the fixture covers every field, every field has a rejecting case ----------------------------

#[test]
fn each_late_id_accepts_its_full_fixture_and_refuses_each_bad_value() {
    run_case_checks(&cases());
}

#[test]
fn the_cases_cover_every_m1_late_id() {
    let covered: Vec<&str> = cases().iter().map(|c| c.id).collect();
    let late = [
        "host.firewall",
        "host.time_sync",
        "host.sysctl",
        "host.container_runtime",
        "host.cgroups",
        "host.kernel",
        "net.registry",
        "net.mtu",
        "net.bandwidth",
        "k8s.namespace",
        "k8s.dns",
        "k8s.ingress",
        "k8s.crds",
        "k8s.cni",
    ];
    assert_eq!(covered, late);
    for id in late {
        assert!(KNOWN_IDS.contains(&id), "{id}");
        assert!(crate::reserved::is_reserved_id(id), "{id}");
    }
}

// ---- FIELDS cannot drift from the struct --------------------------------------------------------

#[test]
fn late_fields_match_the_structs() {
    fields_match::<HostFirewall>();
    fields_match::<HostTimeSync>();
    fields_match::<HostSysctl>();
    fields_match::<HostContainerRuntime>();
    fields_match::<HostCgroups>();
    fields_match::<HostKernel>();
    fields_match::<NetRegistry>();
    fields_match::<NetMtu>();
    fields_match::<NetBandwidth>();
    fields_match::<K8sNamespace>();
    fields_match::<K8sDns>();
    fields_match::<K8sIngress>();
    fields_match::<K8sCrds>();
    fields_match::<K8sCni>();
}

// ---- no threshold -------------------------------------------------------------------------------

#[test]
fn a_late_check_with_its_required_keys_missing_is_no_threshold() {
    let one_of: &[(&str, &[&str])] = &[
        ("host.sysctl", &["expect", "limits"]),
        ("host.kernel", &["min", "distro_min", "modules", "btf"]),
        ("net.registry", &["registries"]),
        ("net.bandwidth", &["url"]),
        ("k8s.crds", &["crds", "operators"]),
    ];
    for (id, keys) in one_of {
        assert_eq!(
            why(id, &json!({})),
            UnsupportedReason::NoThreshold {
                one_of: keys,
                and: vec![]
            },
            "{id}"
        );
    }
    // Options alone are not a threshold.
    assert!(matches!(
        why("net.bandwidth", &json!({"min_mbps": 5})),
        UnsupportedReason::NoThreshold { .. }
    ));
    assert_eq!(
        why("net.bandwidth", &json!({"min_mbps": 5})).to_string(),
        "has no threshold: add 'url'"
    );
    assert_eq!(
        why("host.sysctl", &json!({})).to_string(),
        "has no threshold: add at least one of 'expect', or 'limits'"
    );
}

#[test]
fn late_checks_that_need_no_threshold_decode_bare() {
    for id in [
        "host.firewall",
        "host.time_sync",
        "host.container_runtime",
        "host.cgroups",
        "net.mtu",
        "k8s.namespace",
        "k8s.dns",
        "k8s.ingress",
        "k8s.cni",
    ] {
        typed(id, &json!({}));
    }
}

#[test]
fn any_one_threshold_is_enough_for_a_one_of_late_check() {
    typed("host.sysctl", &json!({"limits": {"nofile": ">=65536"}}));
    typed("host.sysctl", &json!({"expect": {"vm.swappiness": "10"}}));
    for params in [
        json!({"min": "5.4"}),
        json!({"distro_min": {"rhel": "4.18.0-305"}}),
        json!({"modules": ["overlay"]}),
        json!({"btf": true}),
    ] {
        typed("host.kernel", &params);
    }
    typed("k8s.crds", &json!({"crds": [{"name": "a.example.io"}]}));
    typed(
        "k8s.crds",
        &json!({"operators": [{"namespace": "ns", "deployment": "op"}]}),
    );
}

// ---- what a good value reads as -----------------------------------------------------------------

#[test]
fn defaults_are_applied() {
    let CheckParams::HostTimeSync(t) = typed("host.time_sync", &json!({})) else {
        panic!("not HostTimeSync");
    };
    assert_eq!(t.max_skew, None);
    assert!(!t.require_sync);
    assert_eq!(t.ntp_servers, None);
    let CheckParams::HostCgroups(c) = typed("host.cgroups", &json!({})) else {
        panic!("not HostCgroups");
    };
    assert_eq!(c.version, CgroupVersion::Any);
    let CheckParams::NetMtu(m) = typed("net.mtu", &json!({})) else {
        panic!("not NetMtu");
    };
    assert_eq!(m.underlay, Underlay::Ipv4);
    let CheckParams::HostKernel(k) = typed("host.kernel", &json!({"min": "5.4"})) else {
        panic!("not HostKernel");
    };
    assert!(!k.btf);
    let CheckParams::K8sIngress(i) = typed("k8s.ingress", &json!({})) else {
        panic!("not K8sIngress");
    };
    assert!(!i.route && !i.loadbalancer);
    let CheckParams::NetRegistry(r) = typed("net.registry", &json!({"registries": ["a.example"]}))
    else {
        panic!("not NetRegistry");
    };
    assert!(!r.registries[0].optional);
    assert_eq!(r.registries[0].host.port(), None);
}

#[test]
fn ntp_servers_read_every_form_and_default_to_port_123() {
    let CheckParams::HostTimeSync(t) = typed(
        "host.time_sync",
        &json!({"ntp_servers": [
            "ntp.acme.example", "ntp2.acme.example:1123", "10.0.0.1", "fd00:ec2::123",
            "[fd00:ec2::124]", "[fd00:ec2::125]:1234", "NTP3.acme.example"
        ]}),
    ) else {
        panic!("not HostTimeSync");
    };
    let servers = t.ntp_servers.expect("servers");
    let shown: Vec<(String, u16)> = servers
        .iter()
        .map(|s| (s.host().to_string(), s.port()))
        .collect();
    assert_eq!(
        shown,
        [
            ("ntp.acme.example".to_owned(), 123),
            ("ntp2.acme.example".to_owned(), 1123),
            ("10.0.0.1".to_owned(), 123),
            ("[fd00:ec2::123]".to_owned(), 123),
            ("[fd00:ec2::124]".to_owned(), 123),
            ("[fd00:ec2::125]".to_owned(), 1234),
            ("ntp3.acme.example".to_owned(), 123),
        ]
    );
    // A link-local server parses. The egress policy refuses it at run time (INV-12), not the spec.
    typed(
        "host.time_sync",
        &json!({"ntp_servers": ["169.254.169.123", "fd00:ec2::123"]}),
    );
}

#[test]
fn a_ntp_server_does_not_echo_a_password() {
    let reason = why(
        "host.time_sync",
        &json!({"ntp_servers": ["user:secret-pw@ntp.acme.example"]}),
    );
    assert!(!reason.to_string().contains("secret-pw"), "{reason}");
}

#[test]
fn value_rules_read_a_comparison_or_a_plain_value() {
    let CheckParams::HostSysctl(s) = typed(
        "host.sysctl",
        &json!({"expect": {
            "a": ">=262144", "b": "<= 100", "c": 1, "d": "bbr", "e": "4096 87380 6291456",
            "f": ">=-1", "g": "1"
        }}),
    ) else {
        panic!("not HostSysctl");
    };
    let rules = s.expect.expect("expect");
    let read = |name: &str| {
        let rule = rules
            .iter()
            .find(|(k, _)| k.as_str() == name)
            .map(|(_, v)| v)
            .expect("a rule");
        (rule.compare, rule.value.clone(), rule.integer())
    };
    assert_eq!(
        read("a"),
        (Compare::AtLeast, "262144".to_owned(), Some(262_144))
    );
    assert_eq!(read("b"), (Compare::AtMost, "100".to_owned(), Some(100)));
    assert_eq!(read("c"), (Compare::Equal, "1".to_owned(), Some(1)));
    assert_eq!(read("d"), (Compare::Equal, "bbr".to_owned(), None));
    assert_eq!(read("e").2, None);
    assert_eq!(read("f"), (Compare::AtLeast, "-1".to_owned(), Some(-1)));
    assert_eq!(read("g"), (Compare::Equal, "1".to_owned(), Some(1)));
}

#[test]
fn a_sysctl_name_may_use_dots_or_slashes() {
    let CheckParams::HostSysctl(s) = typed(
        "host.sysctl",
        &json!({"expect": {
            "vm.max_map_count": "1", "net/ipv4/conf/eth0.100/rp_filter": "2", "kernel": "1",
            "net.ipv4.conf.br-1234.forwarding": "1"
        }}),
    ) else {
        panic!("not HostSysctl");
    };
    let names: Vec<&str> = s
        .expect
        .as_ref()
        .expect("expect")
        .keys()
        .map(SysctlName::as_str)
        .collect();
    assert_eq!(
        names,
        [
            "kernel",
            "net.ipv4.conf.br-1234.forwarding",
            "net/ipv4/conf/eth0.100/rp_filter",
            "vm.max_map_count"
        ]
    );
}

/// The check reads `/proc/sys/<name>`, so a name must never climb out of it.
#[test]
fn a_sysctl_name_cannot_climb_out_of_proc_sys() {
    for name in [
        "..", "../x", "a/../b", "a/./b", "/a", "a/", ".a", "a.", "a..b", "a b", "a\\b",
    ] {
        let reason = why("host.sysctl", &json!({"expect": {name: "1"}}));
        assert!(
            matches!(&reason, UnsupportedReason::BadValue { field: Some(f), .. } if f == "expect"),
            "{name}: {reason:?}"
        );
    }
}

#[test]
fn kernel_versions_keep_their_text_and_split_the_build() {
    let CheckParams::HostKernel(k) = typed(
        "host.kernel",
        &json!({"min": "5.10", "distro_min": {"rhel": "4.18.0-305", "ubuntu": 5, "sles": "5.14.21-150500.55.19"}}),
    ) else {
        // The last entry has a build part with two parts, so it reads.
        panic!("not HostKernel");
    };
    assert_eq!(k.min.as_ref().map(KernelVersion::as_str), Some("5.10"));
    let min = k.distro_min.expect("distro_min");
    let rhel = min
        .iter()
        .find(|(d, _)| d.as_str() == "rhel")
        .map(|(_, v)| v)
        .expect("rhel");
    assert_eq!(rhel.as_str(), "4.18.0-305");
    assert_eq!(rhel.base().components(), [4, 18, 0]);
    assert_eq!(rhel.build().map(Version::components), Some(&[305][..]));
    let ubuntu = min
        .iter()
        .find(|(d, _)| d.as_str() == "ubuntu")
        .map(|(_, v)| v)
        .expect("ubuntu");
    assert_eq!(ubuntu.as_str(), "5");
    assert_eq!(ubuntu.build(), None);
}

#[test]
fn an_unquoted_decimal_kernel_version_says_to_quote_it() {
    let reason = why("host.kernel", &json!({"min": 5.10}));
    let text = reason.to_string();
    assert!(text.contains("quote"), "{text}");
}

#[test]
fn image_references_split_into_repository_and_tag() {
    let CheckParams::NetRegistry(r) = typed(
        "net.registry",
        &json!({"registries": [{"host": "r.example", "images": [
            "acme/agent:1.4", "library/nginx:1.27-alpine", "a.b_c__d---e/f:_T-1.2", "x:1"
        ]}]}),
    ) else {
        panic!("not NetRegistry");
    };
    let images = r.registries[0].images.as_ref().expect("images");
    let shown: Vec<(&str, &str)> = images.iter().map(|i| (i.repository(), i.tag())).collect();
    assert_eq!(
        shown,
        [
            ("acme/agent", "1.4"),
            ("library/nginx", "1.27-alpine"),
            ("a.b_c__d---e/f", "_T-1.2"),
            ("x", "1"),
        ]
    );
}

#[test]
fn a_bare_registry_and_a_registry_object_read_the_same_way() {
    let CheckParams::NetRegistry(r) = typed(
        "net.registry",
        &json!({"registries": ["r.example:5000", {"host": "r.example:5000"}]}),
    ) else {
        panic!("not NetRegistry");
    };
    assert_eq!(r.registries[0], r.registries[1]);
    assert_eq!(r.registries[0].host.port(), Some(5000));
}

#[test]
fn quota_amounts_keep_their_text() {
    let CheckParams::K8sNamespace(n) = typed(
        "k8s.namespace",
        &json!({"quota_needs": {
            "a": 16, "b": 0.5, "c": "64Gi", "d": "500m", "e": ".5", "f": "1.5Gi", "g": "0",
            "h": "2E", "i": 1_000_000_000_000_000_u64
        }}),
    ) else {
        panic!("not K8sNamespace");
    };
    let amounts: Vec<&str> = n
        .quota_needs
        .as_ref()
        .expect("quota_needs")
        .values()
        .map(K8sQuantity::as_str)
        .collect();
    assert_eq!(
        amounts,
        [
            "16",
            "0.5",
            "64Gi",
            "500m",
            ".5",
            "1.5Gi",
            "0",
            "2E",
            "1000000000000000"
        ]
    );
}

#[test]
fn bandwidth_keeps_the_url_and_reads_the_sample_size() {
    let CheckParams::NetBandwidth(b) = typed(
        "net.bandwidth",
        &json!({"url": "https://mirror.acme.example:8443/s.bin?sig=abc", "bytes": "1Mi",
                "min_mbps": 0.5}),
    ) else {
        panic!("not NetBandwidth");
    };
    assert_eq!(b.url.target().port(), 8443);
    assert_eq!(b.url.target().host().to_string(), "mirror.acme.example");
    assert_eq!(b.bytes.map(SampleBytes::bytes), Some(1 << 20));
    assert_eq!(b.min_mbps.map(Mbps::get), Some(0.5));
    let CheckParams::NetBandwidth(b) = typed(
        "net.bandwidth",
        &json!({"url": "http://a.example/x", "bytes": 104_857_600}),
    ) else {
        panic!("not NetBandwidth");
    };
    assert_eq!(b.bytes.map(SampleBytes::bytes), Some(100 << 20));
    assert_eq!(b.recommended_mbps, None);
}

#[test]
fn a_bandwidth_url_does_not_echo_a_query_string() {
    let reason = why(
        "net.bandwidth",
        &json!({"url": "mirror.acme.example/x?token=hunter2"}),
    );
    assert!(!reason.to_string().contains("hunter2"), "{reason}");
    let reason = why(
        "net.bandwidth",
        &json!({"url": "https://u:secret-token@a.example/x?token=hunter2"}),
    );
    let text = reason.to_string();
    assert!(
        !text.contains("hunter2") && !text.contains("secret-token"),
        "{text}"
    );
}

#[test]
fn a_cni_egress_destination_is_a_host_and_port() {
    let CheckParams::K8sCni(c) = typed(
        "k8s.cni",
        &json!({"needs_egress": ["db.acme.example:5432", "10.1.2.3:443", "[fd00::1]:8443"]}),
    ) else {
        panic!("not K8sCni");
    };
    let shown: Vec<(String, u16)> = c
        .needs_egress
        .expect("needs_egress")
        .iter()
        .map(|h| (h.target().host().to_string(), h.target().port()))
        .collect();
    assert_eq!(
        shown,
        [
            ("db.acme.example".to_owned(), 5432),
            ("10.1.2.3".to_owned(), 443),
            ("[fd00::1]".to_owned(), 8443)
        ]
    );
}

#[test]
fn crds_and_operators_keep_their_fields() {
    let CheckParams::K8sCrds(c) = typed(
        "k8s.crds",
        &json!({"crds": [{"name": "certificates.cert-manager.io", "versions": ["v1", "v1beta1"]}],
                "operators": [{"namespace": "cert-manager", "deployment": "cert-manager",
                               "min_version": "v1.13.0"}]}),
    ) else {
        panic!("not K8sCrds");
    };
    let crds = c.crds.expect("crds");
    assert_eq!(crds[0].name.as_str(), "certificates.cert-manager.io");
    let versions: Vec<&str> = crds[0]
        .versions
        .as_ref()
        .expect("versions")
        .iter()
        .map(CrdVersion::as_str)
        .collect();
    assert_eq!(versions, ["v1", "v1beta1"]);
    let operators = c.operators.expect("operators");
    assert_eq!(operators[0].namespace.as_str(), "cert-manager");
    assert_eq!(
        operators[0].min_version.as_ref().map(Version::components),
        Some(&[1, 13, 0][..])
    );
}

// ---- hostile text and nested values -------------------------------------------------------------

#[test]
fn refused_text_is_escaped_in_the_reason() {
    for (id, params) in [
        (
            "host.time_sync",
            json!({"ntp_servers": ["a\u{1b}[2J.example"]}),
        ),
        ("host.sysctl", json!({"expect": {"a\u{1b}[2J": "1"}})),
        ("host.sysctl", json!({"expect": {"a": "\u{1b}[2J"}})),
        ("host.kernel", json!({"min": "\u{1b}[2J"})),
        ("host.kernel", json!({"distro_min": {"\u{1b}[2J": "5.4"}})),
        ("host.kernel", json!({"modules": ["\u{1b}[2J"]})),
        ("host.cgroups", json!({"controllers": ["\u{1b}[2J"]})),
        (
            "host.container_runtime",
            json!({"storage_driver": "\u{1b}[2J"}),
        ),
        (
            "net.registry",
            json!({"registries": ["a\u{1b}[2J.example"]}),
        ),
        (
            "net.registry",
            json!({"registries": [{"host": "a.example", "images": ["\u{1b}[2J:1"]}]}),
        ),
        (
            "net.bandwidth",
            json!({"url": "https://a\u{1b}[2J.example/x"}),
        ),
        ("k8s.namespace", json!({"quota_needs": {"a\u{1b}[2J": 1}})),
        (
            "k8s.namespace",
            json!({"quota_needs": {"pods": "\u{1b}[2J"}}),
        ),
        ("k8s.ingress", json!({"controller": "\u{1b}[2J"})),
        (
            "k8s.crds",
            json!({"crds": [{"name": "a", "versions": ["\u{1b}[2J"]}]}),
        ),
        (
            "k8s.cni",
            json!({"needs_egress": ["a\u{1b}[2J.example:443"]}),
        ),
    ] {
        assert_printable(&why(id, &params));
    }
}

#[test]
fn a_key_with_no_value_inside_a_late_value_is_a_bad_value() {
    for (id, params, field) in [
        (
            "host.sysctl",
            json!({"expect": {"vm.max_map_count": null}}),
            "expect",
        ),
        ("host.sysctl", json!({"limits": {"nofile": null}}), "limits"),
        (
            "host.kernel",
            json!({"distro_min": {"rhel": null}}),
            "distro_min",
        ),
        (
            "net.registry",
            json!({"registries": [{"host": "a.example", "hosts": null}]}),
            "registries",
        ),
        (
            "k8s.namespace",
            json!({"quota_needs": {"pods": null}}),
            "quota_needs",
        ),
        (
            "k8s.crds",
            json!({"crds": [{"name": "a.example.io", "versions": null}]}),
            "crds",
        ),
    ] {
        let reason = why(id, &params);
        assert!(
            matches!(&reason, UnsupportedReason::BadValue { field: Some(f), .. } if f == field),
            "{params}: {reason:?}"
        );
    }
}

/// A key the new type does not have is refused by name, also inside a block (01 section 2.5).
#[test]
fn an_unknown_key_in_a_late_check_is_named() {
    assert_eq!(
        why("host.kernel", &json!({"min": "5.4", "minimum": "5.4"})),
        UnsupportedReason::UnknownField {
            field: "minimum".into()
        }
    );
    let reason = why(
        "k8s.crds",
        &json!({"crds": [{"name": "a.example.io", "verions": ["v1"]}]}),
    );
    assert_eq!(
        reason,
        UnsupportedReason::UnknownNestedField {
            path: "crds[0].verions".into(),
            near: Some("versions".into())
        }
    );
}
