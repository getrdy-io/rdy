//! M1-025 through the public API: the net and k8s ids of the example specs decode to typed values, and
//! YAML written the way a vendor writes it reaches the right outcome.
//!
//! Helpers avoid `unwrap` and `expect` because clippy only allows them inside `#[test]` functions.

use std::path::{Path, PathBuf};

use rdy_spec::check::{CheckParams, UnsupportedReason, ViaProxy};
use rdy_spec::parse_unverified;
use rdy_spec::spec::Spec;

const HEAD: &str = "apiVersion: rdy/v1\nkind: Readiness\nmetadata:\n  product: acme\nchecks:\n";

fn repo_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../..")
}

fn parse(yaml: &str) -> Spec {
    match parse_unverified(yaml.as_bytes()) {
        Ok(spec) => spec,
        Err(e) => panic!("expected {yaml:?} to parse, got: {e} at {:?}", e.location()),
    }
}

fn example(name: &str) -> Spec {
    let path = repo_root().join("examples/specs").join(name);
    let Ok(bytes) = std::fs::read(&path) else {
        panic!("cannot read {}", path.display());
    };
    match parse_unverified(&bytes) {
        Ok(spec) => spec,
        Err(e) => panic!("{name}: {e} at {:?}", e.location()),
    }
}

fn decode(spec: &Spec) -> Vec<CheckParams> {
    match spec.decode_checks() {
        Ok(v) => v,
        Err(e) => panic!("expected the checks to decode, got: {e}"),
    }
}

fn one(entry: &str) -> CheckParams {
    let spec = parse(&format!("{HEAD}{entry}"));
    let mut decoded = decode(&spec);
    assert_eq!(decoded.len(), 1);
    decoded.remove(0)
}

fn reason(params: &CheckParams) -> &UnsupportedReason {
    match params {
        CheckParams::Unsupported { reason, .. } => reason,
        other => panic!("expected Unsupported, got {other:?}"),
    }
}

// ---- the exit test of the ticket ---------------------------------------------------------------

#[test]
fn acme_platform_decodes_its_net_and_k8s_checks_to_typed_values() {
    let decoded = decode(&example("acme-platform.yaml"));
    let by_id = |id: &str| decoded.iter().find(|p| p.id() == id);
    let Some(CheckParams::NetEgress(egress)) = by_id("net.egress") else {
        panic!("net.egress is not typed: {:?}", by_id("net.egress"));
    };
    assert_eq!(egress.endpoints.len(), 2);
    assert_eq!(egress.via_proxy, ViaProxy::Auto);
    let Some(CheckParams::K8sVersion(version)) = by_id("k8s.version") else {
        panic!("k8s.version is not typed: {:?}", by_id("k8s.version"));
    };
    assert_eq!(
        version.min.as_ref().map(|v| v.components().to_vec()),
        Some(vec![1, 28])
    );
    let Some(CheckParams::K8sStorageClass(class)) = by_id("k8s.storageclass") else {
        panic!(
            "k8s.storageclass is not typed: {:?}",
            by_id("k8s.storageclass")
        );
    };
    assert_eq!(class.access_modes.as_ref().map(|m| m.len()), Some(1));
}

#[test]
fn acme_k8s_only_decodes_every_check_to_a_typed_value() {
    let decoded = decode(&example("acme-k8s-only.yaml"));
    let ids: Vec<&str> = decoded.iter().map(CheckParams::id).collect();
    assert_eq!(
        ids,
        [
            "k8s.version",
            "k8s.nodes",
            "k8s.storageclass",
            "k8s.rbac",
            "k8s.admission"
        ]
    );
    for params in &decoded {
        assert!(
            !matches!(
                params,
                CheckParams::Unknown { .. } | CheckParams::Unsupported { .. }
            ),
            "{params:?}"
        );
    }
    let CheckParams::K8sNodes(nodes) = &decoded[1] else {
        panic!("not K8sNodes");
    };
    let per_node = nodes.per_node.as_ref();
    assert_eq!(
        per_node.and_then(|p| p.cpu).map(|c| c.millicores()),
        Some(4000)
    );
    let CheckParams::K8sRbac(rbac) = &decoded[3] else {
        panic!("not K8sRbac");
    };
    assert_eq!(rbac.can.len(), 3);
}

#[test]
fn needs_on_k8s_storageclass_is_unsupported() {
    let params = one("  - id: k8s.storageclass\n    needs: [ReadWriteMany]\n");
    assert_eq!(
        *reason(&params),
        UnsupportedReason::UnknownField {
            field: "needs".into()
        }
    );
}

/// Every net and k8s check in every example spec reads fully, so a vendor who copies one gets a check
/// that runs.
#[test]
fn every_net_and_k8s_check_in_the_examples_reads_fully() {
    let dir = repo_root().join("examples/specs");
    let Ok(entries) = std::fs::read_dir(&dir) else {
        panic!("cannot read {}", dir.display());
    };
    let mut seen = 0;
    for item in entries.flatten() {
        let path = item.path();
        let Some(name) = path.file_name().and_then(|n| n.to_str()) else {
            continue;
        };
        if !name.ends_with(".yaml") {
            continue;
        }
        for params in decode(&example(name)) {
            if params.id().starts_with("net.") || params.id().starts_with("k8s.") {
                seen += 1;
                assert!(
                    !matches!(params, CheckParams::Unsupported { .. }),
                    "{name}: {params:?}"
                );
            }
        }
    }
    assert!(seen >= 10, "{seen}");
}

// ---- YAML written the way a vendor writes it ----------------------------------------------------

/// 01 section 2.5: `- id: net.egress` alone is skipped as `unsupported_spec`, with `no_threshold`.
#[test]
fn a_bare_net_egress_or_k8s_rbac_has_no_threshold() {
    for (entry, key) in [
        ("  - id: net.egress\n    severity: block\n", "endpoints"),
        ("  - id: net.dns\n", "names"),
        ("  - id: k8s.rbac\n", "can"),
    ] {
        let params = one(entry);
        let UnsupportedReason::NoThreshold { one_of, and } = reason(&params) else {
            panic!("{entry}: {params:?}");
        };
        assert_eq!(*one_of, [key], "{entry}");
        assert!(and.is_empty());
    }
}

#[test]
fn a_yaml_key_with_no_value_is_a_bad_value_at_any_depth() {
    for (entry, field) in [
        ("  - id: net.egress\n    endpoints:\n", "endpoints"),
        (
            "  - id: net.egress\n    endpoints:\n      - target: a.example:443\n        optional:\n",
            "endpoints",
        ),
        (
            "  - id: k8s.nodes\n    min_ready: 1\n    per_node:\n      cpu:\n",
            "per_node",
        ),
        ("  - id: k8s.version\n    min:\n", "min"),
    ] {
        let params = one(entry);
        assert!(
            matches!(reason(&params), UnsupportedReason::BadValue { field: Some(f), .. } if f == field),
            "{entry}: {params:?}"
        );
    }
}

#[test]
fn an_unquoted_cpu_and_a_quoted_one_read_the_same() {
    let CheckParams::K8sNodes(a) = one("  - id: k8s.nodes\n    per_node: {cpu: 4}\n") else {
        panic!("not K8sNodes");
    };
    let CheckParams::K8sNodes(b) = one("  - id: k8s.nodes\n    per_node: {cpu: \"4\"}\n") else {
        panic!("not K8sNodes");
    };
    assert_eq!(a.per_node, b.per_node);
}

#[test]
fn a_yaml_toleration_and_selector_read() {
    let params = one("  - id: k8s.nodes
    min_ready: 2
    selector:
      node-role.kubernetes.io/worker: \"\"
    tolerations:
      - {key: gpu, operator: Exists, effect: NoSchedule}
");
    let CheckParams::K8sNodes(nodes) = params else {
        panic!("not K8sNodes");
    };
    assert_eq!(nodes.selector.map(|s| s.labels().len()), Some(1));
    assert_eq!(nodes.tolerations.map(|t| t.len()), Some(1));
}
