//! `examples/rbac/rdy-readonly.yaml` and the guard's allowlist say the same thing (SEC-24).
//!
//! The role is the second line behind the guard. If the two drift, either rdy asks for something the
//! role does not grant (a check fails with 403 on a cluster that uses the role) or the role grants
//! something rdy never reads. Both directions are tested.

#![allow(clippy::expect_used)]

use std::collections::BTreeSet;
use std::path::Path;

use rdy_checks_k8s::client::guard::{ALLOWED, Access, Only};
use serde_json::Value;

/// The documents of the example, parsed.
fn documents() -> Vec<Value> {
    let path = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../examples/rbac/rdy-readonly.yaml");
    let text = std::fs::read_to_string(path).expect("examples/rbac/rdy-readonly.yaml exists");
    text.split("\n---\n")
        .map(|doc| serde_saphyr::from_str::<Value>(doc).expect("valid YAML"))
        .collect()
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
            for group in strings("apiGroups") {
                for resource in strings("resources") {
                    for verb in strings("verbs") {
                        out.insert((namespace.clone(), format!("{group}/{resource} {verb}")));
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
            let (verb, namespace) = match access {
                Access::List => ("list", None),
                Access::Get(_) => ("get", None),
                Access::ListInNamespace(Only::Any) => ("list", None),
                Access::ListInNamespace(Only::Name(ns)) => ("list", Some((*ns).to_owned())),
            };
            out.insert((
                namespace,
                format!("{}/{} {verb}", entry.group, entry.resource),
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
    assert!(!text.contains('*'), "the role must not use a wildcard");
    for kind in ["ClusterRole", "Role"] {
        for (_, grant) in grants(&docs, kind) {
            let verb = grant.rsplit(' ').next().expect("verb");
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
    assert_eq!(bindings.len(), 2);
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
