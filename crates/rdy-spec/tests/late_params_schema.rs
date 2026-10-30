//! The parameter structs of the 14 M1-late check ids against `schema/spec.v1.schema.json` (M1-172).
//!
//! For each entry, the JSON schema and `CheckSpec::decode_params` must agree: the schema accepts the
//! entry exactly when it decodes to a typed variant. So the schema, which writers of specs read, and
//! the structs, which rdy runs, cannot drift apart without this test failing.
//!
//! The decoder is stricter than the schema in a few places that a pattern cannot say: a host with a
//! trailing dot or a single-number IPv4 form, a time server written twice in two spellings, a sample
//! size outside 1 MiB to 100 MiB, and the length of a repository. Those entries are tested against the
//! decoder only, in the unit tests. Every other entry is in "both accept" or "both refuse".

use std::error::Error;
use std::path::Path;

use jsonschema::Validator;
use rdy_spec::check::CheckParams;
use rdy_spec::spec::CheckSpec;
use serde_json::{Value, json};

type TestResult<T = ()> = Result<T, Box<dyn Error>>;

fn check_validator() -> TestResult<Validator> {
    let text = std::fs::read_to_string(
        Path::new(env!("CARGO_MANIFEST_DIR")).join("schema/spec.v1.schema.json"),
    )?;
    let whole: Value = serde_json::from_str(&text)?;
    let schema = json!({
        "$schema": "https://json-schema.org/draft/2020-12/schema",
        "$ref": "#/$defs/Check",
        "$defs": whole["$defs"].clone(),
    });
    Ok(jsonschema::draft202012::options().build(&schema)?)
}

fn decodes(entry: &Value) -> TestResult<bool> {
    let spec: CheckSpec = serde_json::from_value(entry.clone())?;
    Ok(!matches!(
        spec.decode_params(),
        CheckParams::Unsupported { .. } | CheckParams::Unknown { .. }
    ))
}

fn agree(entries: &[Value], want: bool) -> TestResult {
    let validator = check_validator()?;
    for entry in entries {
        assert_eq!(validator.is_valid(entry), want, "schema, for {entry}");
        assert_eq!(decodes(entry)?, want, "decoder, for {entry}");
    }
    Ok(())
}

#[test]
fn host_entries_both_accept() -> TestResult {
    agree(
        &[
            json!({"id": "host.firewall"}),
            json!({"id": "host.firewall", "open_inbound": [6443, 10250]}),
            json!({"id": "host.firewall", "open_inbound": [1, 65535]}),
            json!({"id": "host.time_sync"}),
            json!({"id": "host.time_sync", "max_skew": "5s", "require_sync": true,
                "ntp_servers": ["ntp.acme.example", "ntp2.acme.example:1123", "10.0.0.1",
                    "fd00:ec2::123", "[fd00:ec2::124]", "[fd00:ec2::125]:1234"]}),
            json!({"id": "host.sysctl", "expect": {"vm.max_map_count": ">=262144"}}),
            json!({"id": "host.sysctl", "limits": {"nofile": ">=65536"}}),
            json!({"id": "host.sysctl",
                "expect": {"net.ipv4.ip_forward": 1, "net.ipv4.tcp_congestion_control": "bbr",
                    "net/ipv4/conf/eth0.100/rp_filter": "2", "fs.file-max": "<= 9999999",
                    "net.ipv4.tcp_rmem": "4096 87380 6291456", "kernel.perf_event_paranoid": ">=-1",
                    "a": "x"},
                "limits": {"nofile": 1048576}}),
            json!({"id": "host.container_runtime"}),
            json!({"id": "host.container_runtime", "runtime": ["docker", "containerd", "podman", "crio"],
                "min_version": "1.7", "cgroup_driver": "systemd", "storage_driver": "overlay2"}),
            json!({"id": "host.container_runtime", "min_version": 20, "cgroup_driver": "cgroupfs",
                "storage_driver": "fuse-overlayfs"}),
            json!({"id": "host.cgroups"}),
            json!({"id": "host.cgroups", "version": "v1"}),
            json!({"id": "host.cgroups", "version": "any", "controllers": ["cpu", "memory", "io", "pids"]}),
            json!({"id": "host.kernel", "min": "5.4"}),
            json!({"id": "host.kernel", "min": 5}),
            json!({"id": "host.kernel", "min": "4.18.0-305"}),
            json!({"id": "host.kernel", "min": "5.14.21-150500.55.19"}),
            json!({"id": "host.kernel", "distro_min": {"rhel": "4.18.0-305", "ubuntu": "5.15"}}),
            json!({"id": "host.kernel", "modules": ["overlay", "br_netfilter", "xt_TCPMSS"]}),
            json!({"id": "host.kernel", "btf": true}),
            json!({"id": "host.kernel", "btf": false}),
            json!({"id": "host.kernel", "min": "5.4", "distro_min": {"rhel": "4.18.0-305"},
                "modules": ["overlay"], "btf": true}),
        ],
        true,
    )
}

#[test]
fn host_entries_both_refuse() -> TestResult {
    agree(
        &[
            // a required threshold is missing
            json!({"id": "host.sysctl"}),
            json!({"id": "host.kernel"}),
            // empty lists and maps
            json!({"id": "host.firewall", "open_inbound": []}),
            json!({"id": "host.time_sync", "ntp_servers": []}),
            json!({"id": "host.sysctl", "expect": {}}),
            json!({"id": "host.sysctl", "limits": {}}),
            json!({"id": "host.container_runtime", "runtime": []}),
            json!({"id": "host.cgroups", "controllers": []}),
            json!({"id": "host.kernel", "distro_min": {}}),
            json!({"id": "host.kernel", "modules": []}),
            // unknown keys
            json!({"id": "host.firewall", "open_outbound": [80]}),
            json!({"id": "host.time_sync", "max_offset": "5s"}),
            json!({"id": "host.sysctl", "expect": {"a": "1"}, "values": {}}),
            json!({"id": "host.sysctl", "limits": {"nproc": ">=1"}}),
            json!({"id": "host.container_runtime", "driver": "systemd"}),
            json!({"id": "host.cgroups", "hybrid": true}),
            json!({"id": "host.kernel", "min": "5.4", "minimum": "5.4"}),
            // a key with no value
            json!({"id": "host.firewall", "open_inbound": null}),
            json!({"id": "host.sysctl", "expect": {"a": null}}),
            json!({"id": "host.kernel", "distro_min": {"rhel": null}}),
            // bad values
            json!({"id": "host.firewall", "open_inbound": [0]}),
            json!({"id": "host.firewall", "open_inbound": [65536]}),
            json!({"id": "host.firewall", "open_inbound": [6443, 6443]}),
            json!({"id": "host.firewall", "open_inbound": ["6443"]}),
            json!({"id": "host.firewall", "open_inbound": 6443}),
            json!({"id": "host.time_sync", "max_skew": "0s"}),
            json!({"id": "host.time_sync", "max_skew": 5}),
            json!({"id": "host.time_sync", "require_sync": "yes"}),
            json!({"id": "host.time_sync", "ntp_servers": ["http://ntp.acme.example"]}),
            json!({"id": "host.time_sync", "ntp_servers": ["ntp.acme.example:0"]}),
            json!({"id": "host.time_sync", "ntp_servers": ["ntp.acme.example:99999"]}),
            json!({"id": "host.time_sync", "ntp_servers": ["ntp.acme.example:"]}),
            json!({"id": "host.time_sync", "ntp_servers": ["a b"]}),
            json!({"id": "host.time_sync", "ntp_servers": ["user:pw@ntp.acme.example"]}),
            json!({"id": "host.time_sync", "ntp_servers": ["::ffff:10.0.0.1"]}),
            json!({"id": "host.time_sync", "ntp_servers": ["fd00::g"]}),
            json!({"id": "host.time_sync", "ntp_servers": ["[fd00::1"]}),
            json!({"id": "host.time_sync", "ntp_servers": [""]}),
            json!({"id": "host.time_sync", "ntp_servers": "ntp.acme.example"}),
            json!({"id": "host.time_sync", "ntp_servers": (0..9).map(|i| format!("n{i}.acme.example")).collect::<Vec<_>>()}),
            json!({"id": "host.sysctl", "expect": {"a": ""}}),
            json!({"id": "host.sysctl", "expect": {"a": ">5"}}),
            json!({"id": "host.sysctl", "expect": {"a": ">="}}),
            json!({"id": "host.sysctl", "expect": {"a": ">=abc"}}),
            json!({"id": "host.sysctl", "expect": {"a": ">=  1"}}),
            json!({"id": "host.sysctl", "expect": {"a": "=5"}}),
            json!({"id": "host.sysctl", "expect": {"a": " 5"}}),
            json!({"id": "host.sysctl", "expect": {"a": "5 "}}),
            json!({"id": "host.sysctl", "expect": {"a": 1.5}}),
            json!({"id": "host.sysctl", "expect": {"a": true}}),
            json!({"id": "host.sysctl", "expect": {"a": "x".repeat(129)}}),
            json!({"id": "host.sysctl", "expect": {"a": "b\u{1b}c"}}),
            json!({"id": "host.sysctl", "expect": {"": "1"}}),
            json!({"id": "host.sysctl", "expect": {"vm..x": "1"}}),
            json!({"id": "host.sysctl", "expect": {".vm": "1"}}),
            json!({"id": "host.sysctl", "expect": {"vm.": "1"}}),
            json!({"id": "host.sysctl", "expect": {"-vm.x": "1"}}),
            json!({"id": "host.sysctl", "expect": {"vm/../x": "1"}}),
            json!({"id": "host.sysctl", "expect": {"./x": "1"}}),
            json!({"id": "host.sysctl", "expect": {"/etc/passwd": "1"}}),
            json!({"id": "host.sysctl", "expect": {"a/b/": "1"}}),
            json!({"id": "host.sysctl", "expect": {"a//b": "1"}}),
            json!({"id": "host.sysctl", "expect": {"vm x": "1"}}),
            json!({"id": "host.sysctl", "expect": {"a".repeat(129): "1"}}),
            json!({"id": "host.sysctl", "limits": {"nofile": ">=x"}}),
            json!({"id": "host.container_runtime", "runtime": ["lxc"]}),
            json!({"id": "host.container_runtime", "runtime": ["Docker"]}),
            json!({"id": "host.container_runtime", "runtime": ["cri-o"]}),
            json!({"id": "host.container_runtime", "runtime": ["docker", "docker"]}),
            json!({"id": "host.container_runtime", "min_version": "latest"}),
            json!({"id": "host.container_runtime", "min_version": 1.3}),
            json!({"id": "host.container_runtime", "cgroup_driver": "cgroupv2"}),
            json!({"id": "host.container_runtime", "cgroup_driver": "Systemd"}),
            json!({"id": "host.container_runtime", "storage_driver": ""}),
            json!({"id": "host.container_runtime", "storage_driver": "Overlay2"}),
            json!({"id": "host.container_runtime", "storage_driver": "x".repeat(33)}),
            json!({"id": "host.cgroups", "version": "v3"}),
            json!({"id": "host.cgroups", "version": "V2"}),
            json!({"id": "host.cgroups", "version": "hybrid"}),
            json!({"id": "host.cgroups", "controllers": ["CPU"]}),
            json!({"id": "host.cgroups", "controllers": ["cpu", "cpu"]}),
            json!({"id": "host.cgroups", "controllers": [""]}),
            json!({"id": "host.kernel", "min": ""}),
            json!({"id": "host.kernel", "min": "latest"}),
            json!({"id": "host.kernel", "min": 5.1}),
            json!({"id": "host.kernel", "min": "v5.4"}),
            json!({"id": "host.kernel", "min": "5.4-"}),
            json!({"id": "host.kernel", "min": "-305"}),
            json!({"id": "host.kernel", "min": "5.4.x"}),
            json!({"id": "host.kernel", "min": "4.18.0--305"}),
            json!({"id": "host.kernel", "min": "4.18.0-305-1"}),
            json!({"id": "host.kernel", "min": "4.18.0-305.el8"}),
            json!({"id": "host.kernel", "min": "1.2.3.4.5"}),
            json!({"id": "host.kernel", "min": "1000000000"}),
            json!({"id": "host.kernel", "distro_min": {"RHEL": "4.18"}}),
            json!({"id": "host.kernel", "distro_min": {"rhel": ""}}),
            json!({"id": "host.kernel", "distro_min": {"rhel": "x"}}),
            json!({"id": "host.kernel", "distro_min": {"": "4.18"}}),
            json!({"id": "host.kernel", "modules": ["over lay"]}),
            json!({"id": "host.kernel", "modules": ["overlay.ko"]}),
            json!({"id": "host.kernel", "modules": ["overlay", "overlay"]}),
            json!({"id": "host.kernel", "modules": [""]}),
            json!({"id": "host.kernel", "modules": ["x".repeat(65)]}),
            json!({"id": "host.kernel", "btf": "yes"}),
        ],
        false,
    )
}

#[test]
fn net_entries_both_accept() -> TestResult {
    agree(
        &[
            json!({"id": "net.registry", "registries": ["registry.acme.example"]}),
            json!({"id": "net.registry", "registries": ["registry.acme.example:5000"]}),
            json!({"id": "net.registry", "registries": [
                {"host": "registry.acme.example"},
                {"host": "registry.acme.example:5000", "hosts": ["auth.acme.example", "blobs.acme.example:443"],
                 "images": ["acme/agent:1.4", "library/nginx:1.27-alpine", "a.b_c__d---e/f:_T-1.2", "x:1"],
                 "optional": true}]}),
            json!({"id": "net.mtu"}),
            json!({"id": "net.mtu", "min_mtu": 1400, "overlay": "vxlan", "underlay": "ipv6"}),
            json!({"id": "net.mtu", "min_mtu": 68, "overlay": "geneve"}),
            json!({"id": "net.mtu", "min_mtu": 65535, "overlay": "wireguard"}),
            json!({"id": "net.mtu", "overlay": "ipip", "underlay": "ipv4"}),
            json!({"id": "net.bandwidth", "url": "https://mirror.acme.example/sample.bin"}),
            json!({"id": "net.bandwidth", "url": "http://mirror.acme.example:8080/s.bin?sig=abc",
                "bytes": "10Mi", "min_mbps": 50, "recommended_mbps": 100.5}),
            json!({"id": "net.bandwidth", "url": "https://a.example/x", "bytes": 1_048_576,
                "min_mbps": 0.5}),
        ],
        true,
    )
}

#[test]
fn net_entries_both_refuse() -> TestResult {
    agree(
        &[
            // a required key is missing
            json!({"id": "net.registry"}),
            json!({"id": "net.bandwidth"}),
            json!({"id": "net.bandwidth", "min_mbps": 5}),
            // empty lists
            json!({"id": "net.registry", "registries": []}),
            json!({"id": "net.registry", "registries": [{"host": "a.example", "hosts": []}]}),
            json!({"id": "net.registry", "registries": [{"host": "a.example", "images": []}]}),
            // unknown keys
            json!({"id": "net.registry", "registries": ["a.example"], "mirrors": []}),
            json!({"id": "net.registry", "registries": [{"host": "a.example", "retries": 1}]}),
            json!({"id": "net.mtu", "mtu": 1400}),
            json!({"id": "net.bandwidth", "url": "https://a.example/x", "duration": "5s"}),
            // a key with no value
            json!({"id": "net.registry", "registries": null}),
            json!({"id": "net.registry", "registries": [{"host": "a.example", "hosts": null}]}),
            json!({"id": "net.mtu", "min_mtu": null}),
            json!({"id": "net.bandwidth", "url": null}),
            // bad values
            json!({"id": "net.registry", "registries": "a.example"}),
            json!({"id": "net.registry", "registries": [""]}),
            json!({"id": "net.registry", "registries": ["https://a.example"]}),
            json!({"id": "net.registry", "registries": ["a.example:0"]}),
            json!({"id": "net.registry", "registries": ["a.example:99999"]}),
            json!({"id": "net.registry", "registries": ["a b"]}),
            json!({"id": "net.registry", "registries": [{"optional": true}]}),
            json!({"id": "net.registry", "registries": [{"host": "a.example", "optional": "yes"}]}),
            json!({"id": "net.registry", "registries": [{"host": "a.example", "hosts": ["https://b.example"]}]}),
            json!({"id": "net.registry", "registries": [{"host": "a.example", "hosts": "b.example"}]}),
            json!({"id": "net.registry", "registries": [{"host": "a.example", "hosts": ["b.example", "b.example"]}]}),
            json!({"id": "net.registry", "registries": [{"host": "a.example", "images": ["acme/agent"]}]}),
            json!({"id": "net.registry", "registries": [{"host": "a.example", "images": ["Acme/agent:1"]}]}),
            json!({"id": "net.registry", "registries": [{"host": "a.example", "images": ["acme/agent:"]}]}),
            json!({"id": "net.registry", "registries": [{"host": "a.example", "images": ["acme//agent:1"]}]}),
            json!({"id": "net.registry", "registries": [{"host": "a.example", "images": ["/acme:1"]}]}),
            json!({"id": "net.registry", "registries": [{"host": "a.example", "images": ["acme/-agent:1"]}]}),
            json!({"id": "net.registry", "registries": [{"host": "a.example", "images": ["acme/agent-:1"]}]}),
            json!({"id": "net.registry", "registries": [{"host": "a.example", "images": ["acme/agent:-1"]}]}),
            json!({"id": "net.registry", "registries": [{"host": "a.example", "images": ["acme/agent:."]}]}),
            json!({"id": "net.registry", "registries": [{"host": "a.example", "images": ["acme/a.-b:1"]}]}),
            json!({"id": "net.registry", "registries": [{"host": "a.example", "images": ["acme/a._b:1"]}]}),
            json!({"id": "net.registry", "registries": [{"host": "a.example", "images": ["acme/agent@sha256:0123456789abcdef"]}]}),
            json!({"id": "net.registry", "registries": [{"host": "a.example", "images": ["a:1", "a:1"]}]}),
            json!({"id": "net.mtu", "min_mtu": 0}),
            json!({"id": "net.mtu", "min_mtu": 67}),
            json!({"id": "net.mtu", "min_mtu": 65536}),
            json!({"id": "net.mtu", "min_mtu": -1}),
            json!({"id": "net.mtu", "min_mtu": "1400"}),
            json!({"id": "net.mtu", "min_mtu": 1400.5}),
            json!({"id": "net.mtu", "overlay": "gre"}),
            json!({"id": "net.mtu", "overlay": "VXLAN"}),
            json!({"id": "net.mtu", "underlay": "ipv5"}),
            json!({"id": "net.bandwidth", "url": ""}),
            json!({"id": "net.bandwidth", "url": "mirror.acme.example:443"}),
            json!({"id": "net.bandwidth", "url": "mirror.acme.example"}),
            json!({"id": "net.bandwidth", "url": "ftp://mirror.acme.example/x"}),
            json!({"id": "net.bandwidth", "url": "https://user:pw@mirror.acme.example/x"}),
            json!({"id": "net.bandwidth", "url": "https://mirror.acme.example/x#frag"}),
            json!({"id": "net.bandwidth", "url": "https://"}),
            json!({"id": "net.bandwidth", "url": 5}),
            json!({"id": "net.bandwidth", "url": "https://a.example/x", "bytes": "10G"}),
            json!({"id": "net.bandwidth", "url": "https://a.example/x", "bytes": "ten"}),
            json!({"id": "net.bandwidth", "url": "https://a.example/x", "bytes": -1}),
            json!({"id": "net.bandwidth", "url": "https://a.example/x", "min_mbps": 0}),
            json!({"id": "net.bandwidth", "url": "https://a.example/x", "min_mbps": -1}),
            json!({"id": "net.bandwidth", "url": "https://a.example/x", "min_mbps": 100_001}),
            json!({"id": "net.bandwidth", "url": "https://a.example/x", "min_mbps": "50"}),
            json!({"id": "net.bandwidth", "url": "https://a.example/x", "recommended_mbps": 0}),
            json!({"id": "net.bandwidth", "url": "https://a.example/x", "recommended_mbps": true}),
        ],
        false,
    )
}

#[test]
fn k8s_entries_both_accept() -> TestResult {
    agree(
        &[
            json!({"id": "k8s.namespace"}),
            json!({"id": "k8s.namespace", "namespace": "acme-system"}),
            json!({"id": "k8s.namespace", "namespace": "acme-system",
                "quota_needs": {"requests.cpu": 16, "requests.memory": "64Gi", "pods": 100,
                    "persistentvolumeclaims": "10", "requests.storage": "500Gi", "limits.cpu": "500m",
                    "count/jobs.batch": 0.5, "a": ".5", "b": "1.5Gi", "c": "0", "d": "2E"},
                "limit_needs": {"container_max_memory": "16Gi"}}),
            json!({"id": "k8s.dns"}),
            json!({"id": "k8s.dns", "cluster_domain": "cluster.local"}),
            json!({"id": "k8s.ingress"}),
            json!({"id": "k8s.ingress", "controller": "any", "gateway_api": "optional"}),
            json!({"id": "k8s.ingress", "controller": "k8s.io/ingress-nginx", "gateway_api": "required",
                "route": true, "loadbalancer": true}),
            json!({"id": "k8s.crds", "crds": [{"name": "certificates.cert-manager.io"}]}),
            json!({"id": "k8s.crds", "crds": [{"name": "certificates.cert-manager.io",
                "versions": ["v1", "v1beta1", "v2alpha1"]}]}),
            json!({"id": "k8s.crds", "operators": [{"namespace": "cert-manager",
                "deployment": "cert-manager"}]}),
            json!({"id": "k8s.crds",
                "crds": [{"name": "issuers.cert-manager.io", "versions": ["v1"]}],
                "operators": [{"namespace": "cert-manager", "deployment": "cert-manager",
                    "min_version": "1.13"}]}),
            json!({"id": "k8s.cni"}),
            json!({"id": "k8s.cni", "network_policy": "enforced"}),
            json!({"id": "k8s.cni", "network_policy": "enforced",
                "needs_egress": ["db.acme.example:5432", "10.1.2.3:443", "[fd00::1]:8443"],
                "avoid_cidrs": ["10.0.0.0/8", "fd00::/8", "0.0.0.0/0"]}),
        ],
        true,
    )
}

#[test]
fn k8s_entries_both_refuse() -> TestResult {
    agree(
        &[
            // a required threshold is missing
            json!({"id": "k8s.crds"}),
            // empty lists and maps
            json!({"id": "k8s.namespace", "quota_needs": {}}),
            json!({"id": "k8s.namespace", "limit_needs": {}}),
            json!({"id": "k8s.crds", "crds": []}),
            json!({"id": "k8s.crds", "operators": []}),
            json!({"id": "k8s.crds", "crds": [{"name": "a.example", "versions": []}]}),
            json!({"id": "k8s.cni", "needs_egress": []}),
            json!({"id": "k8s.cni", "avoid_cidrs": []}),
            // unknown keys
            json!({"id": "k8s.namespace", "quota": {}}),
            json!({"id": "k8s.namespace", "limit_needs": {"container_min_memory": "1Gi"}}),
            json!({"id": "k8s.dns", "domain": "cluster.local"}),
            json!({"id": "k8s.ingress", "class": "nginx"}),
            json!({"id": "k8s.crds", "crds": [{"name": "a.example", "verions": ["v1"]}]}),
            json!({"id": "k8s.crds", "operators": [{"namespace": "n", "deployment": "d", "image": "x"}]}),
            json!({"id": "k8s.cni", "plugin": "calico"}),
            // a key with no value
            json!({"id": "k8s.namespace", "quota_needs": {"pods": null}}),
            json!({"id": "k8s.dns", "cluster_domain": null}),
            json!({"id": "k8s.crds", "crds": [{"name": "a.example", "versions": null}]}),
            json!({"id": "k8s.cni", "network_policy": null}),
            // bad values
            json!({"id": "k8s.namespace", "namespace": "Acme"}),
            json!({"id": "k8s.namespace", "namespace": ""}),
            json!({"id": "k8s.namespace", "quota_needs": {"": 1}}),
            json!({"id": "k8s.namespace", "quota_needs": {"requests cpu": 1}}),
            json!({"id": "k8s.namespace", "quota_needs": {"pods": ""}}),
            json!({"id": "k8s.namespace", "quota_needs": {"pods": "-1"}}),
            json!({"id": "k8s.namespace", "quota_needs": {"pods": -1}}),
            json!({"id": "k8s.namespace", "quota_needs": {"pods": "1 Gi"}}),
            json!({"id": "k8s.namespace", "quota_needs": {"pods": "1K"}}),
            json!({"id": "k8s.namespace", "quota_needs": {"pods": "1e3"}}),
            json!({"id": "k8s.namespace", "quota_needs": {"pods": "1.5.2"}}),
            json!({"id": "k8s.namespace", "quota_needs": {"pods": "."}}),
            json!({"id": "k8s.namespace", "quota_needs": {"pods": "1."}}),
            json!({"id": "k8s.namespace", "quota_needs": {"pods": "Gi"}}),
            json!({"id": "k8s.namespace", "quota_needs": {"pods": true}}),
            json!({"id": "k8s.namespace", "quota_needs": {"pods": 1e16}}),
            json!({"id": "k8s.namespace", "limit_needs": {"container_max_memory": "16G"}}),
            json!({"id": "k8s.namespace", "limit_needs": {"container_max_memory": ""}}),
            json!({"id": "k8s.dns", "cluster_domain": ""}),
            json!({"id": "k8s.dns", "cluster_domain": "Cluster.Local"}),
            json!({"id": "k8s.dns", "cluster_domain": "cluster..local"}),
            json!({"id": "k8s.dns", "cluster_domain": "a_b.local"}),
            json!({"id": "k8s.ingress", "controller": ""}),
            json!({"id": "k8s.ingress", "controller": "nginx ingress"}),
            json!({"id": "k8s.ingress", "controller": "x".repeat(254)}),
            json!({"id": "k8s.ingress", "gateway_api": "yes"}),
            json!({"id": "k8s.ingress", "gateway_api": "Required"}),
            json!({"id": "k8s.ingress", "route": "yes"}),
            json!({"id": "k8s.ingress", "loadbalancer": 1}),
            json!({"id": "k8s.crds", "crds": ["a.example"]}),
            json!({"id": "k8s.crds", "crds": [{}]}),
            json!({"id": "k8s.crds", "crds": [{"name": "Bad"}]}),
            json!({"id": "k8s.crds", "crds": [{"name": "a.example", "versions": ["1"]}]}),
            json!({"id": "k8s.crds", "crds": [{"name": "a.example", "versions": ["V1"]}]}),
            json!({"id": "k8s.crds", "crds": [{"name": "a.example", "versions": ["v"]}]}),
            json!({"id": "k8s.crds", "crds": [{"name": "a.example", "versions": ["v1", "v1"]}]}),
            json!({"id": "k8s.crds", "operators": [{"namespace": "n"}]}),
            json!({"id": "k8s.crds", "operators": [{"deployment": "d"}]}),
            json!({"id": "k8s.crds", "operators": [{"namespace": "n", "deployment": "d", "min_version": "x"}]}),
            json!({"id": "k8s.crds", "operators": [{"namespace": "N", "deployment": "d"}]}),
            json!({"id": "k8s.cni", "network_policy": "any"}),
            json!({"id": "k8s.cni", "network_policy": "Enforced"}),
            json!({"id": "k8s.cni", "needs_egress": ["db.acme.example"]}),
            json!({"id": "k8s.cni", "needs_egress": ["https://db.acme.example"]}),
            json!({"id": "k8s.cni", "needs_egress": ["db.acme.example:0"]}),
            json!({"id": "k8s.cni", "needs_egress": ["db.acme.example:443", "db.acme.example:443"]}),
            json!({"id": "k8s.cni", "avoid_cidrs": ["10.0.0.0"]}),
            json!({"id": "k8s.cni", "avoid_cidrs": ["10.0.0.0/33"]}),
            json!({"id": "k8s.cni", "avoid_cidrs": ["10.0.0.0/8", "10.0.0.0/8"]}),
            json!({"id": "k8s.cni", "avoid_cidrs": [""]}),
        ],
        false,
    )
}

/// The airgap example names three of the 14 ids. They validate per check and decode to typed values, so
/// they are no longer `not_in_build`.
#[test]
fn the_airgap_example_decodes_its_late_checks() -> TestResult {
    let validator = check_validator()?;
    let path =
        Path::new(env!("CARGO_MANIFEST_DIR")).join("../../examples/specs/acme-airgap-host.yaml");
    let bytes = std::fs::read(&path)?;
    let spec = rdy_spec::parse_unverified(&bytes)?;
    let mut seen = Vec::new();
    for check in &spec.checks {
        let id = check.id.as_str();
        if ["host.kernel", "host.cgroups", "host.time_sync"].contains(&id) {
            let entry = serde_json::to_value(check)?;
            assert!(validator.is_valid(&entry), "schema, for {entry}");
            assert!(decodes(&entry)?, "decoder, for {entry}");
            seen.push(id.to_owned());
        }
    }
    assert_eq!(seen, ["host.kernel", "host.cgroups", "host.time_sync"]);
    Ok(())
}
