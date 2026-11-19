//! `examples/rbac/rdy-readonly.yaml` and the guard's allowlist say the same thing (SEC-24).
//!
//! The role is the second line behind the guard. If the two drift, either rdy asks for something the
//! role does not grant (a check fails with 403 on a cluster that uses the role) or the role grants
//! something rdy never reads. Both directions are tested. The role is three files: the main one, the
//! optional OpenShift DNS Role (`rdy-readonly-openshift-dns.yaml`, M1-162) and the optional operator template
//! (`rdy-readonly-operator.yaml`, M1-164), which are read together with it.

#![allow(clippy::expect_used)]
// This test reads the example role file from the repository, which the lint wall bans in the rest of
// this crate (INV-07). This file is on the allowlist of tests/lint-wall/tests/allow_grep.rs. A test of a
// check does not belong here: use the probe.
#![allow(clippy::disallowed_methods)]

use std::collections::BTreeSet;
use std::path::Path;

use rdy_checks_k8s::client::guard::{ALLOWED, Access, Only};
use serde_json::Value;

/// The example files, under `examples/rbac/`.
const FILES: [&str; 3] = [
    "rdy-readonly.yaml",
    "rdy-readonly-openshift-dns.yaml",
    // The optional operator template, which holds the Role of the `k8s.crds` read.
    "rdy-readonly-operator.yaml",
];

/// The documents of the example files, parsed.
fn documents() -> Vec<Value> {
    let mut out = Vec::new();
    for file in FILES {
        let path = Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../examples/rbac")
            .join(file);
        let text = std::fs::read_to_string(path).expect("the example file exists");
        out.extend(
            text.split("\n---\n")
                .map(|doc| serde_saphyr::from_str::<Value>(doc).expect("valid YAML")),
        );
    }
    out
}

/// `group/resource verb` for every rule of the documents of `kind`, and the namespace of the role.
fn grants(docs: &[Value], kind: &str) -> BTreeSet<(Option<String>, String)> {
    let mut out = BTreeSet::new();
    for doc in docs.iter().filter(|d| d["kind"] == kind) {
        let namespace = doc["metadata"]["namespace"].as_str().map(str::to_owned);
        for rule in doc["rules"].as_array().expect("rules") {
            let strings = |key: &str| -> Vec<String> {
                rule[key]
                    .as_array()
                    .expect(key)
                    .iter()
                    .map(|v| v.as_str().expect("string").to_owned())
                    .collect()
            };
            let names: Vec<String> = if rule["resourceNames"].is_null() {
                Vec::new()
            } else {
                strings("resourceNames")
            };
            for group in strings("apiGroups") {
                for resource in strings("resources") {
                    for verb in strings("verbs") {
                        let base = format!("{group}/{resource} {verb}");
                        if names.is_empty() {
                            out.insert((namespace.clone(), base));
                        } else {
                            for name in &names {
                                out.insert((namespace.clone(), format!("{base} name={name}")));
                            }
                        }
                    }
                }
            }
        }
    }
    out
}

/// What the guard's table needs, as `(namespace, "group/resource verb")`.
fn needed() -> BTreeSet<(Option<String>, String)> {
    let mut out = BTreeSet::new();
    for entry in ALLOWED {
        for access in entry.access {
            let (verb, namespace, name) = match access {
                Access::List => ("list", None, String::new()),
                Access::Get(Only::Any) => ("get", None, String::new()),
                // A get of one name is granted by name, so the role cannot read any other object.
                Access::Get(Only::Name(name)) => ("get", None, format!(" name={name}")),
                // A get of a named object in a namespace the spec names: the optional operator template,
                // a Role of one namespace and one name.
                Access::GetInNamespace(Only::Any) => (
                    "get",
                    Some("<operator-namespace>".to_owned()),
                    " name=<operator-deployment>".to_owned(),
                ),
                Access::GetInNamespace(Only::Name(ns)) => {
                    ("get", Some((*ns).to_owned()), String::new())
                }
                Access::ListInNamespace(Only::Any) => ("list", None, String::new()),
                Access::ListInNamespace(Only::Name(ns)) => {
                    ("list", Some((*ns).to_owned()), String::new())
                }
                // One object of one namespace: a Role of that namespace, granted by name.
                Access::GetIn { namespace, name } => (
                    "get",
                    Some((*namespace).to_owned()),
                    format!(" name={name}"),
                ),
            };
            out.insert((
                namespace,
                format!("{}/{} {verb}{name}", entry.group, entry.resource),
            ));
        }
    }
    out
}

/// The three reviews, which the guard allows as the only POSTs.
fn reviews() -> BTreeSet<(Option<String>, String)> {
    [
        "authentication.k8s.io/selfsubjectreviews create",
        "authorization.k8s.io/selfsubjectaccessreviews create",
        "authorization.k8s.io/selfsubjectrulesreviews create",
    ]
    .into_iter()
    .map(|grant| (None, grant.to_owned()))
    .collect()
}

#[test]
fn the_role_grants_exactly_what_the_guard_allows_and_the_three_reviews() {
    let docs = documents();
    let mut granted = grants(&docs, "ClusterRole");
    granted.extend(grants(&docs, "Role"));

    let mut expected = needed();
    expected.extend(reviews());
    assert_eq!(granted, expected);
}

#[test]
fn the_role_never_writes_reads_secrets_or_uses_a_wildcard() {
    let docs = documents();
    let text = serde_json::to_string(&docs).expect("json");
    assert!(!text.contains("secrets"), "the role must not name Secrets");
    // The one wildcard is the list of every Gatekeeper constraint kind (ADR 0042). Anything else with a `*`
    // fails.
    let without_gatekeeper = text.replace(
        r#"{"apiGroups":["constraints.gatekeeper.sh"],"resources":["*"],"verbs":["list"]}"#,
        "",
    );
    let rule = r#"{"apiGroups":["constraints.gatekeeper.sh"],"resources":["*"],"verbs":["list"]}"#;
    assert_eq!(
        text.matches(rule).count(),
        1,
        "the Gatekeeper rule is there, once"
    );
    assert!(
        !without_gatekeeper.contains('*'),
        "the role must not use a wildcard but the Gatekeeper constraints rule"
    );
    for kind in ["ClusterRole", "Role"] {
        for (_, grant) in grants(&docs, kind) {
            let verb = grant.split(' ').nth(1).expect("verb");
            assert!(matches!(verb, "get" | "list" | "create"), "{grant}");
            if verb == "create" {
                assert!(
                    grant.contains("selfsubject") && grant.contains("reviews"),
                    "create is only for the self reviews: {grant}"
                );
            }
        }
    }
}

#[test]
fn every_binding_points_at_a_role_in_the_file() {
    let docs = documents();
    let roles: BTreeSet<(String, String)> = docs
        .iter()
        .filter(|d| d["kind"] == "ClusterRole" || d["kind"] == "Role")
        .map(|d| {
            (
                d["kind"].as_str().expect("kind").to_owned(),
                d["metadata"]["name"].as_str().expect("name").to_owned(),
            )
        })
        .collect();
    let bindings: Vec<&Value> = docs
        .iter()
        .filter(|d| d["kind"] == "ClusterRoleBinding" || d["kind"] == "RoleBinding")
        .collect();
    assert_eq!(bindings.len(), 4);
    for binding in bindings {
        let role = (
            binding["roleRef"]["kind"]
                .as_str()
                .expect("kind")
                .to_owned(),
            binding["roleRef"]["name"]
                .as_str()
                .expect("name")
                .to_owned(),
        );
        assert!(roles.contains(&role), "{role:?}");
        // Only the rdy service account, never a group such as system:authenticated.
        let subjects = binding["subjects"].as_array().expect("subjects");
        assert!(subjects.iter().all(|s| s["kind"] == "ServiceAccount"));
    }
}
