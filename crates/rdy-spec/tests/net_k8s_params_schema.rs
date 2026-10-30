//! The net and k8s parameter structs against `schema/spec.v1.schema.json`.
//!
//! For each entry, the JSON schema and `CheckSpec::decode_params` must agree: the schema accepts the
//! entry exactly when it decodes to a typed variant. So the schema, which writers of specs read, and
//! the structs, which rdy runs, cannot drift apart without this test failing.
//!
//! The decoder is stricter than the schema in a few places that a pattern cannot say: a `Target` or TLS
//! host with a trailing dot or a single-number IPv4 form, an IPv6 range that is not an address (`:::/8`),
//! and a CPU amount with a fraction of a millicore (the schema description says at most three decimals).
//! Those entries are tested against the decoder only, in the unit tests. Every other entry is in
//! "both accept" or "both refuse".

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
    let defs = whole["$defs"].clone();
    let schema = json!({
        "$schema": "https://json-schema.org/draft/2020-12/schema",
        "$ref": "#/$defs/Check",
        "$defs": defs,
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

const PIN: &str = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";

#[test]
fn net_entries_both_accept() -> TestResult {
    agree(
        &[
            json!({"id": "net.egress", "endpoints": ["registry.acme.example:443"]}),
            json!({"id": "net.egress", "endpoints": ["[2001:db8::1]:443", "http://a.example:8080/health"],
                "via_proxy": "direct", "trust": "bundled", "max_latency": "500ms"}),
            json!({"id": "net.egress", "endpoints": [
                {"target": "a.example:443"},
                {"target": "https://a.example/x", "optional": true, "expect_status": [200, 401],
                 "method": "GET", "via_proxy": "proxy_only", "tls": false}]}),
            json!({"id": "net.proxy"}),
            json!({"id": "net.proxy", "required_no_proxy": [".svc", "10.0.0.0/8"], "daemons_need_proxy": true}),
            json!({"id": "net.tls_intercept"}),
            json!({"id": "net.tls_intercept", "hosts": ["a.example", "b.example:8443"],
                "expected_issuer": "^Acme", "pin_sha256": [PIN], "forbid_interception": true}),
            json!({"id": "net.tls_intercept", "hosts": ["10.1.2.3:65535"]}),
            json!({"id": "net.dns", "names": ["a.example"]}),
            json!({"id": "net.dns", "names": ["localhost", "a-b.example", "xn--bcher-kva.example", "A1.b2.example"]}),
            json!({"id": "net.dns", "names": [{"name": "a.example", "expect_in":
                ["10.255.255.255/32", "255.255.255.255/32", "1.2.3.4/0", "::/0", "fd00::/128", "2001:db8::/32"]}]}),
            json!({"id": "net.dns", "names": ["a.example",
                {"name": "db.example", "expect_in": ["10.0.0.0/8", "fd00::/8", "0.0.0.0/0"],
                 "expect_public": false}], "max_latency": "250ms"}),
        ],
        true,
    )
}

#[test]
fn net_entries_both_refuse() -> TestResult {
    agree(
        &[
            // a required key is missing
            json!({"id": "net.egress"}),
            json!({"id": "net.egress", "via_proxy": "direct"}),
            json!({"id": "net.dns"}),
            json!({"id": "net.dns", "max_latency": "1s"}),
            // empty lists
            json!({"id": "net.egress", "endpoints": []}),
            json!({"id": "net.dns", "names": []}),
            json!({"id": "net.tls_intercept", "hosts": []}),
            json!({"id": "net.tls_intercept", "pin_sha256": []}),
            json!({"id": "net.egress", "endpoints": [{"target": "a.example:443", "expect_status": []}]}),
            json!({"id": "net.dns", "names": [{"name": "a.example", "expect_in": []}]}),
            // unknown keys
            json!({"id": "net.egress", "endpoints": ["a.example:443"], "retries": 3}),
            json!({"id": "net.egress", "endpoints": [{"target": "a.example:443", "retries": 3}]}),
            json!({"id": "net.proxy", "proxy": "http://p.example:3128"}),
            json!({"id": "net.tls_intercept", "issuer": "x"}),
            json!({"id": "net.dns", "names": [{"name": "a.example", "type": "A"}]}),
            // a key with no value, at any depth
            json!({"id": "net.egress", "endpoints": null}),
            json!({"id": "net.egress", "endpoints": [{"target": "a.example:443", "optional": null}]}),
            json!({"id": "net.proxy", "daemons_need_proxy": null}),
            json!({"id": "net.dns", "names": [{"name": "a.example", "expect_in": null}]}),
            // bad values
            json!({"id": "net.egress", "endpoints": "a.example:443"}),
            json!({"id": "net.egress", "endpoints": ["a.example"]}),
            json!({"id": "net.egress", "endpoints": ["a.example:0"]}),
            json!({"id": "net.egress", "endpoints": ["a.example:65536"]}),
            json!({"id": "net.egress", "endpoints": ["https://u:p@a.example/"]}),
            json!({"id": "net.egress", "endpoints": [{"optional": true}]}),
            json!({"id": "net.egress", "endpoints": [{"target": "a.example:443", "method": "POST"}]}),
            json!({"id": "net.egress", "endpoints": [{"target": "a.example:443", "expect_status": [99]}]}),
            json!({"id": "net.egress", "endpoints": [{"target": "a.example:443", "expect_status": [600]}]}),
            json!({"id": "net.egress", "endpoints": [{"target": "a.example:443", "expect_status": [200, 200]}]}),
            json!({"id": "net.egress", "endpoints": [{"target": "a.example:443", "via_proxy": "never"}]}),
            json!({"id": "net.egress", "endpoints": [{"target": "a.example:443", "tls": "yes"}]}),
            json!({"id": "net.egress", "endpoints": ["a.example:443"], "via_proxy": "never"}),
            json!({"id": "net.egress", "endpoints": ["a.example:443"], "trust": "os"}),
            json!({"id": "net.egress", "endpoints": ["a.example:443"], "max_latency": "0s"}),
            json!({"id": "net.egress", "endpoints": ["a.example:443"], "max_latency": 2}),
            json!({"id": "net.proxy", "required_no_proxy": [""]}),
            json!({"id": "net.proxy", "required_no_proxy": ".svc"}),
            json!({"id": "net.proxy", "daemons_need_proxy": "yes"}),
            json!({"id": "net.tls_intercept", "hosts": ["a.example:0"]}),
            json!({"id": "net.tls_intercept", "hosts": ["a.example:99999"]}),
            json!({"id": "net.tls_intercept", "hosts": ["a.example:"]}),
            json!({"id": "net.tls_intercept", "hosts": ["a b"]}),
            json!({"id": "net.tls_intercept", "hosts": ["https://a.example"]}),
            json!({"id": "net.tls_intercept", "hosts": [""]}),
            json!({"id": "net.tls_intercept", "expected_issuer": ""}),
            json!({"id": "net.tls_intercept", "pin_sha256": ["abc"]}),
            json!({"id": "net.tls_intercept", "pin_sha256": [PIN.to_uppercase()]}),
            json!({"id": "net.tls_intercept", "forbid_interception": "yes"}),
            json!({"id": "net.dns", "names": [""]}),
            json!({"id": "net.dns", "names": ["a b"]}),
            json!({"id": "net.dns", "names": ["a_b.example"]}),
            json!({"id": "net.dns", "names": [{"expect_public": true}]}),
            json!({"id": "net.dns", "names": [{"name": "a.example", "expect_in": ["10.0.0.0"]}]}),
            json!({"id": "net.dns", "names": [{"name": "a.example", "expect_in": ["10.0.0.300/8"]}]}),
            json!({"id": "net.dns", "names": [{"name": "a.example", "expect_in": ["256.0.0.0/8"]}]}),
            json!({"id": "net.dns", "names": [{"name": "a.example", "expect_in": ["10.0.0.0/33"]}]}),
            json!({"id": "net.dns", "names": [{"name": "a.example", "expect_in": [":::/8"]}]}),
            json!({"id": "net.dns", "names": [{"name": "a.example", "expect_in": ["10.0.0.0/08"]}]}),
            json!({"id": "net.dns", "names": [{"name": "a.example", "expect_in": ["10.0.0.0/8/8"]}]}),
            json!({"id": "net.dns", "names": [{"name": "a.example", "expect_in": ["::1/129"]}]}),
            json!({"id": "net.dns", "names": ["-s"]}),
            json!({"id": "net.dns", "names": ["--x"]}),
            json!({"id": "net.dns", "names": ["-a.example"]}),
            json!({"id": "net.dns", "names": ["a-.example"]}),
            json!({"id": "net.dns", "names": ["a..example"]}),
            json!({"id": "net.dns", "names": ["a.example."]}),
            json!({"id": "net.dns", "names": ["2852039166"]}),
            json!({"id": "net.dns", "names": ["0xa9.0xfe.0xa9.0xfe"]}),
            json!({"id": "net.dns", "names": ["10.0.0.1"]}),
            json!({"id": "net.dns", "names": [{"name": "-s"}]}),
            json!({"id": "net.dns", "names": [format!("{}.example", "a".repeat(64))]}),
            json!({"id": "net.dns", "names": [{"name": "a.example", "expect_in": ["a.example/8"]}]}),
            json!({"id": "net.dns", "names": [{"name": "a.example", "expect_public": "yes"}]}),
            json!({"id": "net.dns", "names": ["a.example"], "max_latency": "fast"}),
        ],
        false,
    )
}

#[test]
fn k8s_entries_both_accept() -> TestResult {
    agree(
        &[
            json!({"id": "k8s.access"}),
            json!({"id": "k8s.access", "context_pattern": "^prod-", "server_pattern": "^https://",
                "max_latency": "3s"}),
            json!({"id": "k8s.storageclass"}),
            json!({"id": "k8s.storageclass", "class": "fast-ssd",
                "access_modes": ["ReadWriteOnce", "ReadOnlyMany", "ReadWriteMany", "ReadWriteOncePod"],
                "binding": "WaitForFirstConsumer", "expansion": false, "reclaim_policy": "Delete"}),
            json!({"id": "k8s.storageclass", "binding": "any"}),
            json!({"id": "k8s.rbac", "can": ["create namespaces"]}),
            json!({"id": "k8s.rbac", "can": ["get /healthz", "get /logs/*", {"verb": "get", "path": "/metrics"}],
                "as": "system:serviceaccount:acme-system:installer"}),
            json!({"id": "k8s.rbac", "can": ["get pods/log", "create clusterroles.rbac.authorization.k8s.io",
                "get deployments.apps/status", "list *", "* *"], "namespace": "acme"}),
            json!({"id": "k8s.rbac", "can": [{"verb": "get", "resource": "pods"},
                {"verb": "get", "group": "", "resource": "pods", "subresource": "log",
                 "namespace": "acme", "name": "web-0"},
                {"verb": "create", "group": "rbac.authorization.k8s.io", "resource": "clusterroles"}]}),
            json!({"id": "k8s.admission"}),
            json!({"id": "k8s.admission", "pod_security": "restricted",
                "uses": ["hostPath", "hostNetwork", "hostPID", "privileged", "runAsRoot"],
                "namespace": "acme", "scc": "restricted-v2"}),
            json!({"id": "k8s.admission", "uses": []}),
            json!({"id": "k8s.nodes", "min_ready": 3}),
            json!({"id": "k8s.nodes", "per_node": {"memory": "28Gi"}}),
            json!({"id": "k8s.nodes", "free": {"pods": 100}, "min_zones": 2}),
            json!({"id": "k8s.nodes", "min_ready": 3, "min_zones": 3,
                "per_node": {"cpu": 7, "memory": "28Gi", "ephemeral": "100Gi", "pods": 30},
                "free": {"cpu": "16", "memory": "64Gi"}, "arch": ["amd64", "arm64", "x86_64", "aarch64"],
                "selector": {"node-role.kubernetes.io/worker": ""},
                "tolerations": [{"key": "gpu", "operator": "Exists", "effect": "NoSchedule"},
                    {"key": "dedicated", "operator": "Equal", "value": "acme", "effect": "NoExecute"},
                    {"operator": "Exists"}]}),
            json!({"id": "k8s.nodes", "min_ready": 1, "per_node": {"cpu": 0.5}}),
            json!({"id": "k8s.nodes", "min_ready": 1, "per_node": {"cpu": "500m"}}),
            json!({"id": "k8s.nodes", "min_ready": 1, "per_node": {"cpu": 1000000}}),
            json!({"id": "k8s.nodes", "min_ready": 1, "per_node": {"cpu": "1000000"}}),
            json!({"id": "k8s.nodes", "min_ready": 1, "per_node": {"cpu": "1000000000m"}}),
            json!({"id": "k8s.nodes", "min_ready": 1, "per_node": {"cpu": 1.234}}),
            json!({"id": "k8s.nodes", "min_ready": 1, "selector": {"a.example/b_c": "V-1.x", "k": ""}}),
            json!({"id": "k8s.nodes", "min_ready": 1,
                "selector": {"a-b.c1.example/x": "v", format!("{}/y", vec!["a"; 126].join(".")): "v"}}),
            json!({"id": "k8s.nodes", "min_ready": 1, "tolerations": [{"operator": "Exists"},
                {"operator": "Exists", "value": ""}, {"key": "k"}, {"key": "k", "value": "v"},
                {"key": "a.example/k", "operator": "Equal", "value": "v", "effect": "NoExecute"}]}),
            json!({"id": "k8s.nodes", "min_ready": 4_294_967_295_u64}),
            json!({"id": "k8s.version", "min": "1.27"}),
            json!({"id": "k8s.version", "max": 1}),
            json!({"id": "k8s.version", "openshift_min": "4.14"}),
            json!({"id": "k8s.version", "apis": ["networking.k8s.io/v1 Ingress", "v1 Pod",
                "autoscaling/v2beta2 HorizontalPodAutoscaler"]}),
            json!({"id": "k8s.version", "min": "1.27", "max": "v1.31", "openshift_min": "4.14",
                "apis": ["batch/v1 CronJob"], "over_max": "block"}),
        ],
        true,
    )
}

#[test]
fn k8s_entries_both_refuse() -> TestResult {
    agree(
        &[
            // a required key or group is missing
            json!({"id": "k8s.rbac"}),
            json!({"id": "k8s.rbac", "namespace": "acme"}),
            json!({"id": "k8s.nodes"}),
            json!({"id": "k8s.nodes", "min_zones": 2, "arch": ["amd64"], "selector": {"a": "b"}}),
            json!({"id": "k8s.version"}),
            json!({"id": "k8s.version", "over_max": "block"}),
            // empty lists and objects that stand for a threshold
            json!({"id": "k8s.rbac", "can": []}),
            json!({"id": "k8s.version", "apis": []}),
            json!({"id": "k8s.nodes", "min_ready": 1, "arch": []}),
            json!({"id": "k8s.nodes", "per_node": {}}),
            json!({"id": "k8s.nodes", "free": {}}),
            json!({"id": "k8s.storageclass", "access_modes": []}),
            // unknown keys, including the ones 01 removed or does not have in M1
            json!({"id": "k8s.storageclass", "needs": ["ReadWriteMany"]}),
            json!({"id": "k8s.admission", "dry_run": true}),
            json!({"id": "k8s.admission", "probe_pod": true}),
            json!({"id": "k8s.admission", "needs_pod_security": "baseline"}),
            json!({"id": "k8s.version", "min": "1.27", "max_severity": "block"}),
            json!({"id": "k8s.access", "context": "prod"}),
            json!({"id": "k8s.nodes", "min_ready": 1, "per_node": {"disk": "1Gi"}}),
            json!({"id": "k8s.nodes", "min_ready": 1, "tolerations": [{"tolerationSeconds": 60}]}),
            json!({"id": "k8s.rbac", "can": [{"verb": "get", "resource": "pods", "as": "bob"}]}),
            json!({"id": "k8s.rbac", "can": [{"verb": "get", "path": "/healthz", "name": "x"}]}),
            // a key with no value, at any depth
            json!({"id": "k8s.rbac", "can": null}),
            json!({"id": "k8s.nodes", "min_ready": 1, "per_node": {"cpu": null}}),
            json!({"id": "k8s.nodes", "min_ready": 1, "selector": {"a": null}}),
            json!({"id": "k8s.version", "apis": [null]}),
            // bad values
            json!({"id": "k8s.access", "context_pattern": ""}),
            json!({"id": "k8s.access", "max_latency": "0s"}),
            json!({"id": "k8s.storageclass", "class": "Fast"}),
            json!({"id": "k8s.storageclass", "class": "-fast"}),
            json!({"id": "k8s.storageclass", "class": "fast-"}),
            json!({"id": "k8s.storageclass", "access_modes": ["RWO"]}),
            json!({"id": "k8s.storageclass", "access_modes": ["ReadWriteOnce", "ReadWriteOnce"]}),
            json!({"id": "k8s.storageclass", "binding": "wait"}),
            json!({"id": "k8s.storageclass", "expansion": "yes"}),
            json!({"id": "k8s.storageclass", "reclaim_policy": "Recycle"}),
            json!({"id": "k8s.rbac", "can": "create namespaces"}),
            json!({"id": "k8s.rbac", "can": ["create"]}),
            json!({"id": "k8s.rbac", "can": ["Create namespaces"]}),
            json!({"id": "k8s.rbac", "can": ["create namespaces."]}),
            json!({"id": "k8s.rbac", "can": ["get pods/"]}),
            json!({"id": "k8s.rbac", "can": ["get pods/Log"]}),
            json!({"id": "k8s.rbac", "can": ["create namespaces extra"]}),
            json!({"id": "k8s.rbac", "can": [{"verb": "get"}]}),
            json!({"id": "k8s.rbac", "can": [{"resource": "pods"}]}),
            json!({"id": "k8s.rbac", "can": [{"verb": "GET", "resource": "pods"}]}),
            json!({"id": "k8s.rbac", "can": [{"verb": "get", "resource": "pods", "group": "Apps"}]}),
            json!({"id": "k8s.rbac", "can": [{"verb": "get", "resource": "pods", "namespace": "Acme"}]}),
            json!({"id": "k8s.rbac", "can": ["get pods"], "namespace": "Acme"}),
            json!({"id": "k8s.rbac", "can": ["get /healthz"], "as": ""}),
            json!({"id": "k8s.rbac", "can": ["get /healthz"], "as": "caf\u{e9}"}),
            json!({"id": "k8s.rbac", "can": ["get healthz/"]}),
            json!({"id": "k8s.rbac", "can": ["get /a//b"]}),
            json!({"id": "k8s.rbac", "can": [{"verb": "get", "path": "healthz"}]}),
            json!({"id": "k8s.admission", "pod_security": "strict"}),
            json!({"id": "k8s.admission", "uses": ["hostIPC"]}),
            json!({"id": "k8s.admission", "uses": ["hostPath", "hostPath"]}),
            json!({"id": "k8s.admission", "scc": "Restricted V2"}),
            json!({"id": "k8s.admission", "namespace": ""}),
            json!({"id": "k8s.nodes", "min_ready": 0}),
            json!({"id": "k8s.nodes", "min_ready": "3"}),
            json!({"id": "k8s.nodes", "min_ready": 4_294_967_296_u64}),
            json!({"id": "k8s.nodes", "min_ready": 1, "min_zones": 0}),
            json!({"id": "k8s.nodes", "per_node": {"cpu": 0}}),
            json!({"id": "k8s.nodes", "per_node": {"cpu": "0"}}),
            json!({"id": "k8s.nodes", "per_node": {"cpu": "0m"}}),
            json!({"id": "k8s.nodes", "per_node": {"cpu": "4 cores"}}),
            json!({"id": "k8s.nodes", "per_node": {"cpu": -1}}),
            json!({"id": "k8s.nodes", "per_node": {"cpu": 0.0001}}),
            json!({"id": "k8s.nodes", "per_node": {"cpu": 1_000_001}}),
            json!({"id": "k8s.nodes", "per_node": {"memory": "28G"}}),
            json!({"id": "k8s.nodes", "per_node": {"pods": 0}}),
            json!({"id": "k8s.nodes", "free": {"pods": "many"}}),
            json!({"id": "k8s.nodes", "min_ready": 1, "arch": ["sparc"]}),
            json!({"id": "k8s.nodes", "min_ready": 1, "arch": ["amd64", "amd64"]}),
            json!({"id": "k8s.nodes", "min_ready": 1, "selector": {"a": 1}}),
            json!({"id": "k8s.nodes", "min_ready": 1, "selector": {"": "x"}}),
            json!({"id": "k8s.nodes", "min_ready": 1, "selector": {"k": "x".repeat(64)}}),
            json!({"id": "k8s.nodes", "min_ready": 1, "selector": {"a..b/x": "v"}}),
            json!({"id": "k8s.nodes", "min_ready": 1, "selector": {"a-.b/x": "v"}}),
            json!({"id": "k8s.nodes", "min_ready": 1, "selector": {"a.-b/x": "v"}}),
            json!({"id": "k8s.nodes", "min_ready": 1, "selector": {".a/x": "v"}}),
            json!({"id": "k8s.nodes", "min_ready": 1, "selector": {"a./x": "v"}}),
            json!({"id": "k8s.nodes", "min_ready": 1,
                "selector": {format!("{}.b/x", "a".repeat(64)): "v"}}),
            json!({"id": "k8s.nodes", "min_ready": 1,
                "selector": {format!("{}/x", vec!["a"; 128].join(".")): "v"}}),
            json!({"id": "k8s.nodes", "min_ready": 1, "tolerations": [{"operator": "Maybe"}]}),
            json!({"id": "k8s.nodes", "min_ready": 1, "tolerations": [{}]}),
            json!({"id": "k8s.nodes", "min_ready": 1, "tolerations": [{"operator": "Equal"}]}),
            json!({"id": "k8s.nodes", "min_ready": 1, "tolerations": [{"effect": "NoSchedule"}]}),
            json!({"id": "k8s.nodes", "min_ready": 1, "tolerations": [{"value": "x"}]}),
            json!({"id": "k8s.nodes", "min_ready": 1, "tolerations": [{"operator": "Exists", "value": "x"}]}),
            json!({"id": "k8s.nodes", "min_ready": 1, "tolerations": [{"key": "a\u{202e}b"}]}),
            json!({"id": "k8s.nodes", "min_ready": 1, "tolerations": [{"key": "k", "value": "-v"}]}),
            json!({"id": "k8s.nodes", "min_ready": 1, "selector": {"-a": "x"}}),
            json!({"id": "k8s.nodes", "min_ready": 1, "selector": {"a/b/c": "x"}}),
            json!({"id": "k8s.nodes", "min_ready": 1, "selector": {"A.Example/b": "x"}}),
            json!({"id": "k8s.nodes", "min_ready": 1, "selector": {"k": "-x"}}),
            json!({"id": "k8s.nodes", "min_ready": 1, "selector": {"a\u{202e}b": "x"}}),
            json!({"id": "k8s.nodes", "min_ready": 1, "selector": {"k": "x\u{202e}"}}),
            json!({"id": "k8s.nodes", "per_node": {"cpu": "1000001"}}),
            json!({"id": "k8s.nodes", "per_node": {"cpu": "1000000001m"}}),
            json!({"id": "k8s.nodes", "min_ready": 1, "tolerations": [{"effect": "Never"}]}),
            json!({"id": "k8s.nodes", "min_ready": 1, "tolerations": [{"key": ""}]}),
            json!({"id": "k8s.nodes", "min_ready": 1, "tolerations": ["gpu"]}),
            json!({"id": "k8s.version", "min": "latest"}),
            json!({"id": "k8s.version", "min": 1.3}),
            json!({"id": "k8s.version", "min": "1.2.3.4.5"}),
            json!({"id": "k8s.version", "max": ""}),
            json!({"id": "k8s.version", "openshift_min": "4.x"}),
            json!({"id": "k8s.version", "apis": ["Ingress"]}),
            json!({"id": "k8s.version", "apis": ["networking.k8s.io/v1"]}),
            json!({"id": "k8s.version", "apis": ["v1 pod"]}),
            json!({"id": "k8s.version", "apis": ["v1  Pod"]}),
            json!({"id": "k8s.version", "apis": ["Networking/v1 Ingress"]}),
            json!({"id": "k8s.version", "min": "1.27", "over_max": "error"}),
        ],
        false,
    )
}

/// The schema and the decoder also agree on the two example specs the ticket names.
#[test]
fn the_two_example_specs_validate_per_check() -> TestResult {
    let validator = check_validator()?;
    for name in ["acme-platform.yaml", "acme-k8s-only.yaml"] {
        let path = Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../examples/specs")
            .join(name);
        let bytes = std::fs::read(&path)?;
        let spec = rdy_spec::parse_unverified(&bytes)?;
        for check in &spec.checks {
            let entry = serde_json::to_value(check)?;
            let id = check.id.as_str();
            if id.starts_with("net.") || id.starts_with("k8s.") {
                assert!(validator.is_valid(&entry), "{name}: schema, for {entry}");
                assert!(decodes(&entry)?, "{name}: decoder, for {entry}");
            }
        }
    }
    Ok(())
}
