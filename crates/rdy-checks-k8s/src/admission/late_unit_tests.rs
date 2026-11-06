//! Unit tests of the M1-160 half of `k8s.admission`: matching, the policy readers and the judgement of
//! webhooks and policies, with no cluster and no mock. The fixture tests are in `tests/late.rs`.

use std::collections::BTreeMap;

use k8s_openapi::api::admissionregistration::v1::{MatchResources, NamedRuleWithOperations};
use k8s_openapi::apimachinery::pkg::apis::meta::v1::{LabelSelector, LabelSelectorRequirement};
use rdy_engine::check::Level;
use serde_json::{Value, json};

use super::judge::judge;
use super::matching::{self, Applies, NsLabels, Rule};
use super::policies::{self, ApiKind, PolicyFact, PolicyList, PolicyRead};
use super::unit_tests::{clean, facts, need, params, plain};
use super::vap;
use super::webhooks::{
    Backend, BackendState, ConfigKind, ReadGrant, ServiceRead, Webhook, safe_name,
};
use super::*;

fn pod_rule() -> Rule {
    Rule {
        operations: vec!["CREATE".to_owned()],
        groups: vec![String::new()],
        versions: vec!["v1".to_owned()],
        resources: vec!["pods".to_owned()],
        scope: Some("Namespaced".to_owned()),
        names: false,
    }
}

fn labels(pairs: &[(&str, &str)]) -> NsLabels {
    Some(
        pairs
            .iter()
            .map(|(k, v)| ((*k).to_owned(), (*v).to_owned()))
            .collect::<BTreeMap<_, _>>(),
    )
}

fn selector(match_labels: &[(&str, &str)], expressions: &[(&str, &str, &[&str])]) -> LabelSelector {
    LabelSelector {
        match_labels: (!match_labels.is_empty()).then(|| {
            match_labels
                .iter()
                .map(|(k, v)| ((*k).to_owned(), (*v).to_owned()))
                .collect()
        }),
        match_expressions: (!expressions.is_empty()).then(|| {
            expressions
                .iter()
                .map(|(key, op, values)| LabelSelectorRequirement {
                    key: (*key).to_owned(),
                    operator: (*op).to_owned(),
                    values: (!values.is_empty())
                        .then(|| values.iter().map(|v| (*v).to_owned()).collect()),
                })
                .collect()
        }),
    }
}

fn hook(name: &str) -> Webhook {
    Webhook {
        kind: ConfigKind::Validating,
        config: "acme-validating".to_owned(),
        name: name.to_owned(),
        fail: true,
        backend: Backend::Service {
            namespace: "acme-hooks".to_owned(),
            name: "hooks".to_owned(),
        },
        rules: vec![pod_rule()],
        namespace_selector: None,
        object_selector: false,
        conditions: false,
    }
}

// ---- matching ---------------------------------------------------------------------------------------------

#[test]
fn a_rule_matches_the_creation_of_a_pod_and_nothing_near_it() {
    assert!(pod_rule().matches_pod_create());
    let with = |edit: &dyn Fn(&mut Rule)| {
        let mut rule = pod_rule();
        edit(&mut rule);
        rule.matches_pod_create()
    };
    // Wildcards that include a pod.
    assert!(with(&|r| r.resources = vec!["*".to_owned()]));
    assert!(with(&|r| r.resources = vec!["*/*".to_owned()]));
    assert!(with(&|r| r.operations = vec!["*".to_owned()]));
    assert!(with(&|r| r.groups = vec!["*".to_owned()]));
    assert!(with(&|r| r.versions = vec!["*".to_owned()]));
    assert!(with(&|r| r.scope = None));
    assert!(with(&|r| r.scope = Some("*".to_owned())));
    // Near misses.
    assert!(!with(&|r| r.resources = vec!["pods/*".to_owned()]));
    assert!(!with(&|r| r.resources = vec!["pods/exec".to_owned()]));
    assert!(!with(&|r| r.resources = vec!["deployments".to_owned()]));
    assert!(!with(
        &|r| r.operations = vec!["UPDATE".to_owned(), "DELETE".to_owned()]
    ));
    assert!(!with(&|r| r.groups = vec!["apps".to_owned()]));
    assert!(!with(&|r| r.versions = vec!["v1beta1".to_owned()]));
    assert!(!with(&|r| r.scope = Some("Cluster".to_owned())));
    assert!(!with(&|r| r.names = true));
    assert!(!with(&|r| r.operations.clear()));
}

#[test]
fn a_namespace_selector_is_judged_on_the_labels_and_unknown_labels_are_maybe() {
    let known = labels(&[("team", "acme"), ("env", "prod")]);
    let none: NsLabels = None;
    assert_eq!(matching::selects(None, &known), Applies::Yes);
    assert_eq!(
        matching::selects(Some(&LabelSelector::default()), &none),
        Applies::Yes
    );
    let cases: [(LabelSelector, Applies); 9] = [
        (selector(&[("team", "acme")], &[]), Applies::Yes),
        (selector(&[("team", "other")], &[]), Applies::No),
        (
            selector(&[], &[("env", "In", &["prod", "dev"])]),
            Applies::Yes,
        ),
        (selector(&[], &[("env", "In", &["dev"])]), Applies::No),
        (selector(&[], &[("env", "NotIn", &["prod"])]), Applies::No),
        (selector(&[], &[("zone", "NotIn", &["a"])]), Applies::Yes),
        (selector(&[], &[("env", "Exists", &[])]), Applies::Yes),
        (
            selector(&[], &[("zone", "DoesNotExist", &[])]),
            Applies::Yes,
        ),
        (selector(&[], &[("env", "Gt", &["1"])]), Applies::Maybe),
    ];
    for (selector, want) in cases {
        assert_eq!(
            matching::selects(Some(&selector), &known),
            want,
            "{selector:?}"
        );
        // Unknown labels: any non-empty selector is a maybe.
        assert_eq!(matching::selects(Some(&selector), &none), Applies::Maybe);
    }
}

#[test]
fn applies_combine_the_way_the_words_say() {
    use Applies::{Maybe, No, Yes};
    assert_eq!(Yes.and(Maybe), Maybe);
    assert_eq!(Maybe.and(No), No);
    assert_eq!(No.or(Maybe), Maybe);
    assert_eq!(Maybe.or(Yes), Yes);
    assert_eq!(Yes.capped(true), Maybe);
    assert_eq!(No.capped(true), No);
    assert_eq!(Yes.capped(false), Yes);
}

fn match_resources(value: Value) -> MatchResources {
    serde_json::from_value(value).expect("match resources")
}

#[test]
fn policy_constraints_and_binding_resources_are_read_differently() {
    let pods = json!({"resourceRules": [{"apiGroups": [""], "apiVersions": ["v1"], "operations": ["CREATE"], "resources": ["pods"]}]});
    let known = labels(&[("team", "acme")]);
    // A policy must name rules; a binding that names none does not narrow.
    assert_eq!(matching::match_resources(None, &known, false), Applies::No);
    assert_eq!(matching::match_resources(None, &known, true), Applies::Yes);
    let empty = match_resources(json!({}));
    assert_eq!(
        matching::match_resources(Some(&empty), &known, false),
        Applies::No
    );
    assert_eq!(
        matching::match_resources(Some(&empty), &known, true),
        Applies::Yes
    );
    let pods_rules = match_resources(pods.clone());
    assert_eq!(
        matching::match_resources(Some(&pods_rules), &known, false),
        Applies::Yes
    );
    // An exclusion wins.
    let mut excluded = pods.clone();
    excluded["excludeResourceRules"] = pods["resourceRules"].clone();
    let excluded = match_resources(excluded);
    assert_eq!(
        matching::match_resources(Some(&excluded), &known, false),
        Applies::No
    );
    // An objectSelector matches on the labels of the pod, which are not known.
    let mut by_label = pods.clone();
    by_label["objectSelector"] = json!({"matchLabels": {"inject": "true"}});
    let by_label = match_resources(by_label);
    assert_eq!(
        matching::match_resources(Some(&by_label), &known, false),
        Applies::Maybe
    );
    // A namespace selector that does not match.
    let mut other = pods;
    other["namespaceSelector"] = json!({"matchLabels": {"team": "other"}});
    let other = match_resources(other);
    assert_eq!(
        matching::match_resources(Some(&other), &known, false),
        Applies::No
    );
    let rule: NamedRuleWithOperations =
        serde_json::from_value(json!({"resourceNames": ["x"], "operations": ["CREATE"], "apiGroups": [""], "apiVersions": ["v1"], "resources": ["pods"]})).expect("rule");
    assert!(!Rule::from(&rule).matches_pod_create());
}

#[test]
fn a_webhook_applies_by_rules_and_selectors_and_is_read_only_when_it_fails_closed() {
    let known = labels(&[("team", "acme")]);
    let mut h = hook("a");
    assert_eq!(h.applies(&known), Applies::Yes);
    assert_eq!(h.service_to_read(&known), Some(("acme-hooks", "hooks")));
    h.conditions = true;
    assert_eq!(h.applies(&known), Applies::Maybe);
    assert!(
        h.service_to_read(&known).is_some(),
        "a maybe still needs its backend read"
    );
    h.conditions = false;
    h.namespace_selector = Some(selector(&[("team", "other")], &[]));
    assert_eq!(h.applies(&known), Applies::No);
    assert!(h.service_to_read(&known).is_none());
    // The namespace labels are not known: maybe.
    assert_eq!(h.applies(&None), Applies::Maybe);
    h.namespace_selector = None;
    h.fail = false;
    assert!(
        h.service_to_read(&known).is_none(),
        "a webhook that fails open is never read"
    );
    h.fail = true;
    h.rules[0].resources = vec!["deployments".to_owned()];
    assert_eq!(h.applies(&known), Applies::No);
    assert!(safe_name("acme-hooks") && safe_name("a.b-c"));
    assert!(!safe_name("") && !safe_name("A") && !safe_name("a`b") && !safe_name("a/b"));
    assert!(!safe_name(&"a".repeat(254)));
}

// ---- judging a webhook ------------------------------------------------------------------------------------

fn gathered_with(hook: Webhook, state: BackendState) -> Gathered {
    let mut gathered = plain(facts(&[
        ("pod-security.kubernetes.io/enforce", "baseline"),
        ("team", "acme"),
    ]));
    let (namespace, name) = match &hook.backend {
        Backend::Service { namespace, name } => (namespace.clone(), name.clone()),
        _ => (String::new(), String::new()),
    };
    gathered.webhooks.validating = Read::Ok(Listed {
        items: vec![hook],
        cut: false,
    });
    gathered.webhooks.services = vec![ServiceRead {
        namespace,
        name,
        state,
    }];
    gathered
}

fn judged(gathered: &Gathered) -> rdy_engine::check::Finding {
    let spec = json!({"pod_security": "baseline"});
    let finding = judge(&params(spec.clone()), need(spec).as_ref(), gathered);
    clean(&finding);
    finding
}

#[test]
fn unread_namespace_labels_turn_a_block_into_a_warning() {
    let mut h = hook("a");
    h.namespace_selector = Some(selector(&[("team", "acme")], &[]));
    let mut gathered = gathered_with(h, BackendState::NoReady { total: 0 });
    // The selector matches the labels read, so it blocks.
    assert_eq!(judged(&gathered).level, Level::Fail);
    // The namespace could not be read: the selector cannot be evaluated.
    gathered.ns = Some(Read::Forbidden);
    let finding = judged(&gathered);
    assert_eq!(finding.level, Level::Warn, "{finding:?}");
    assert!(
        finding
            .message
            .contains("unless the namespace labels, which were not read, exempt them"),
        "{}",
        finding.message
    );
}

#[test]
fn hostile_names_never_reach_a_command_or_a_sentence_raw() {
    let mut h = hook("evil\u{1b}[2J`name`");
    h.config = "cfg`; rm -rf /`".to_owned();
    let gathered = gathered_with(h.clone(), BackendState::NoReady { total: 0 });
    let finding = judged(&gathered);
    assert_eq!(finding.level, Level::Fail);
    let everything = format!(
        "{}\n{}\n{}",
        finding.message,
        finding.fix.clone().unwrap_or_default(),
        finding.observed
    );
    assert!(!everything.contains('\u{1b}'), "{everything:?}");
    assert!(!everything.contains("rm -rf /`"), "{everything:?}");
    // The configuration name is not a Kubernetes name, so the command takes a placeholder.
    let fix = finding.fix.expect("a fix");
    assert!(
        fix.contains("`kubectl get validatingwebhookconfigurations <configuration>`"),
        "{fix}"
    );
    // A Service name that is not a Kubernetes name is never put in a path or a command.
    let mut h = hook("a");
    h.backend = Backend::Service {
        namespace: "acme-hooks".to_owned(),
        name: "svc`x".to_owned(),
    };
    let finding = judged(&gathered_with(h, BackendState::BadName));
    assert_eq!(finding.level, Level::Pass);
    assert!(finding.partial.is_some());
    assert!(!finding.fix.unwrap_or_default().contains("svc`x"));
}

#[test]
fn a_ready_backend_and_a_webhook_that_fails_open_say_nothing() {
    let finding = judged(&gathered_with(hook("a"), BackendState::Ready(2)));
    assert_eq!(finding.level, Level::Pass);
    assert!(finding.partial.is_none());
    let mut h = hook("b");
    h.fail = false;
    let finding = judged(&gathered_with(h, BackendState::NoReady { total: 0 }));
    assert_eq!(finding.level, Level::Pass);
    assert!(finding.partial.is_none());
}

#[test]
fn a_read_that_failed_names_the_grant_only_when_the_identity_was_refused() {
    let unread = |why: &str, grant| BackendState::Unread {
        why: why.to_owned(),
        grant,
    };
    let finding = judged(&gathered_with(
        hook("a"),
        unread("the server answered 500", None),
    ));
    let partial = finding.partial.expect("partial");
    assert!(partial.missing_grants.is_empty());
    assert!(partial.note.contains("the server answered 500"));
    let finding = judged(&gathered_with(
        hook("a"),
        unread(
            "the identity may not read it",
            Some(ReadGrant::EndpointSlices),
        ),
    ));
    assert_eq!(
        finding.partial.expect("partial").missing_grants,
        ["list endpointslices.discovery.k8s.io"]
    );
}

#[test]
fn a_cut_webhook_list_is_said() {
    let mut gathered = plain(facts(&[]));
    gathered.webhooks.validating = Read::Ok(Listed {
        items: Vec::new(),
        cut: true,
    });
    let finding = judged(&gathered);
    // A cut list is partial: a webhook on the next page is not evaluated (R4).
    assert!(
        finding
            .partial
            .expect("partial")
            .note
            .contains("only the first 500 validating webhook configurations were read"),
    );
}

// ---- engine policies --------------------------------------------------------------------------------------

fn list(group: &'static str, version: &str, kind: &str, plural: &str) -> PolicyList {
    PolicyList {
        engine: if group.contains("gatekeeper") {
            "Gatekeeper"
        } else {
            "Kyverno"
        },
        group,
        version: version.to_owned(),
        plural: plural.to_owned(),
        kind: kind.to_owned(),
    }
}

fn fact_of(list: &PolicyList, data: Value, ns_labels: &NsLabels) -> PolicyFact {
    policies::fact(list, "p", &data, ns_labels, Some("acme-system"))
}

#[test]
fn a_kyverno_cluster_policy_rejects_by_its_action_and_applies_by_its_filters() {
    let l = list("kyverno.io", "v1", "ClusterPolicy", "clusterpolicies");
    let known = labels(&[("team", "acme")]);
    let policy = |action: &str, resources: Value| {
        json!({"spec": {"validationFailureAction": action, "rules": [
            {"name": "r", "match": {"any": [{"resources": resources}]}, "validate": {"message": "m"}}
        ]}})
    };
    let fact = |data| fact_of(&l, data, &known);
    assert_eq!(
        fact(policy("Enforce", json!({"kinds": ["Pod"]}))).applies,
        Applies::Yes
    );
    assert!(fact(policy("Enforce", json!({"kinds": ["Pod"]}))).enforcing);
    // The older spelling in lower case, and the kind with a version.
    assert!(fact(policy("enforce", json!({"kinds": ["v1/Pod"]}))).enforcing);
    let audit = fact(policy("Audit", json!({"kinds": ["Pod"]})));
    assert!(!audit.enforcing);
    assert_eq!(audit.applies, Applies::No);
    assert_eq!(
        fact(policy("Enforce", json!({"kinds": ["Deployment"]}))).applies,
        Applies::No
    );
    assert_eq!(
        fact(policy("Enforce", json!({"kinds": ["*"]}))).applies,
        Applies::Yes
    );
    assert_eq!(
        fact(policy(
            "Enforce",
            json!({"kinds": ["Pod"], "namespaces": ["acme-*"]})
        ))
        .applies,
        Applies::Yes
    );
    assert_eq!(
        fact(policy(
            "Enforce",
            json!({"kinds": ["Pod"], "namespaces": ["prod", "stage-?"]})
        ))
        .applies,
        Applies::No
    );
    assert_eq!(
        fact(policy(
            "Enforce",
            json!({"kinds": ["Pod"], "operations": ["UPDATE"]})
        ))
        .applies,
        Applies::No
    );
    assert_eq!(
        fact(policy(
            "Enforce",
            json!({"kinds": ["Pod"], "namespaceSelector": {"matchLabels": {"team": "other"}}})
        ))
        .applies,
        Applies::No
    );
    // A pod label selector cannot be judged.
    assert_eq!(
        fact(policy(
            "Enforce",
            json!({"kinds": ["Pod"], "selector": {"matchLabels": {"a": "b"}}})
        ))
        .applies,
        Applies::Maybe
    );
    // The rule's own action wins over the policy's, in both directions.
    let rule_level = json!({"spec": {"validationFailureAction": "Audit", "rules": [
        {"name": "r", "match": {"resources": {"kinds": ["Pod"]}}, "validate": {"failureAction": "Enforce"}}
    ]}});
    assert!(fact(rule_level).enforcing);
    let rule_audit = json!({"spec": {"validationFailureAction": "Enforce", "rules": [
        {"name": "r", "match": {"resources": {"kinds": ["Pod"]}}, "validate": {"failureAction": "Audit"}}
    ]}});
    assert!(!fact(rule_audit).enforcing);
    // A policy with only a mutate rule rejects nothing.
    let mutate = json!({"spec": {"validationFailureAction": "Enforce", "rules": [
        {"name": "r", "match": {"resources": {"kinds": ["Pod"]}}, "mutate": {}}
    ]}});
    assert!(!fact(mutate).enforcing);
    // `all` is an AND and `any` an OR.
    let all = json!({"spec": {"validationFailureAction": "Enforce", "rules": [
        {"name": "r", "match": {"all": [{"resources": {"kinds": ["Pod"]}}, {"resources": {"kinds": ["Pod"], "namespaces": ["other"]}}]}, "validate": {}}
    ]}});
    assert_eq!(fact(all).applies, Applies::No);
    // Nothing in the object: not a policy.
    assert!(!fact(json!({})).enforcing);
}

#[test]
fn a_kyverno_cel_policy_rejects_on_deny() {
    let l = list(
        "policies.kyverno.io",
        "v1",
        "ValidatingPolicy",
        "validatingpolicies",
    );
    let known = labels(&[]);
    let rules = json!({"resourceRules": [{"apiGroups": [""], "apiVersions": ["v1"], "operations": ["CREATE"], "resources": ["pods"]}]});
    let deny = fact_of(
        &l,
        json!({"spec": {"validationActions": ["Deny"], "matchConstraints": rules}}),
        &known,
    );
    assert!(deny.enforcing);
    assert_eq!(deny.applies, Applies::Yes);
    let warn = fact_of(
        &l,
        json!({"spec": {"validationActions": ["Warn"], "matchConstraints": rules}}),
        &known,
    );
    assert!(!warn.enforcing);
    let other = json!({"resourceRules": [{"apiGroups": ["apps"], "apiVersions": ["v1"], "operations": ["CREATE"], "resources": ["deployments"]}]});
    assert_eq!(
        fact_of(
            &l,
            json!({"spec": {"validationActions": ["Deny"], "matchConstraints": other}}),
            &known
        )
        .applies,
        Applies::No
    );
    // No constraints we can read: maybe. matchConditions: maybe.
    assert_eq!(
        fact_of(&l, json!({"spec": {"validationActions": ["Deny"]}}), &known).applies,
        Applies::Maybe
    );
    assert_eq!(
        fact_of(&l, json!({"spec": {"validationActions": ["Deny"], "matchConstraints": rules, "matchConditions": [{"name": "c", "expression": "true"}]}}), &known).applies,
        Applies::Maybe
    );
}

#[test]
fn a_gatekeeper_constraint_rejects_unless_it_is_dry_run_or_warn() {
    let l = list(
        "constraints.gatekeeper.sh",
        "v1beta1",
        "K8sRequiredLabels",
        "k8srequiredlabels",
    );
    let known = labels(&[("team", "acme")]);
    let fact = |spec: Value| fact_of(&l, json!({"spec": spec}), &known);
    // `deny` is the default.
    let default = fact(json!({}));
    assert!(default.enforcing);
    assert_eq!(default.applies, Applies::Yes);
    assert!(fact(json!({"enforcementAction": "deny"})).enforcing);
    assert!(!fact(json!({"enforcementAction": "dryrun"})).enforcing);
    assert!(!fact(json!({"enforcementAction": "warn"})).enforcing);
    assert!(fact(json!({"enforcementAction": "scoped", "scopedEnforcementActions": [{"action": "deny", "enforcementPoints": [{"name": "validation.gatekeeper.sh"}]}]})).enforcing);
    assert!(
        !fact(
            json!({"enforcementAction": "scoped", "scopedEnforcementActions": [{"action": "warn"}]})
        )
        .enforcing
    );
    // Match: kinds, namespaces, exclusions, selectors and scope.
    let m = |m: Value| fact(json!({"match": m}));
    assert_eq!(
        m(json!({"kinds": [{"apiGroups": [""], "kinds": ["Pod"]}]})).applies,
        Applies::Yes
    );
    assert_eq!(
        m(json!({"kinds": [{"apiGroups": ["*"], "kinds": ["*"]}]})).applies,
        Applies::Yes
    );
    assert_eq!(
        m(json!({"kinds": [{"apiGroups": ["apps"], "kinds": ["Deployment"]}]})).applies,
        Applies::No
    );
    assert_eq!(m(json!({"namespaces": ["acme-*"]})).applies, Applies::Yes);
    assert_eq!(m(json!({"namespaces": ["other"]})).applies, Applies::No);
    assert_eq!(
        m(json!({"excludedNamespaces": ["acme-system"]})).applies,
        Applies::No
    );
    assert_eq!(m(json!({"scope": "Cluster"})).applies, Applies::No);
    assert_eq!(
        m(json!({"namespaceSelector": {"matchLabels": {"team": "other"}}})).applies,
        Applies::No
    );
    assert_eq!(
        m(json!({"labelSelector": {"matchLabels": {"a": "b"}}})).applies,
        Applies::Maybe
    );
}

#[test]
fn a_glob_matches_the_way_the_engines_write_namespaces() {
    for (pattern, text, want) in [
        ("acme-system", "acme-system", true),
        ("acme-*", "acme-system", true),
        ("*-system", "acme-system", true),
        ("a*m*m", "acme-system", true),
        ("*", "", true),
        ("acme-?", "acme-1", true),
        ("acme-?", "acme-12", false),
        ("acme", "acme-system", false),
        ("", "x", false),
        ("x*", "acme", false),
    ] {
        assert_eq!(policies::glob(pattern, text), want, "{pattern} {text}");
    }
}

fn kind(kind: &str, plural: &str, namespaced: bool) -> ApiKind {
    ApiKind {
        plural: plural.to_owned(),
        kind: kind.to_owned(),
        namespaced,
    }
}

#[test]
fn the_lists_follow_the_kinds_that_discovery_showed() {
    // A kyverno.io group that serves only PolicyException and the cleanup kinds lists no policy.
    let v2 = [
        kind("PolicyException", "policyexceptions", true),
        kind("CleanupPolicy", "cleanuppolicies", true),
    ];
    assert!(policies::plan("kyverno.io", "v2", &v2).is_empty());
    assert!(policies::plan("kyverno.io", "v1", &v2).is_empty());
    // ClusterPolicy in v1 is listed; the namespaced Policy is not.
    let v1 = [
        kind("ClusterPolicy", "clusterpolicies", false),
        kind("Policy", "policies", true),
    ];
    let planned = policies::plan("kyverno.io", "v1", &v1);
    assert_eq!(planned.len(), 1);
    assert_eq!(planned[0].plural, "clusterpolicies");
    // The path is built from a version the table knows.
    assert!(policies::plan("kyverno.io", "v2beta1", &v1).is_empty());
    let cel = [
        kind("ValidatingPolicy", "validatingpolicies", false),
        kind("MutatingPolicy", "mutatingpolicies", false),
        kind("ImageValidatingPolicy", "imagevalidatingpolicies", false),
    ];
    assert_eq!(policies::plan("policies.kyverno.io", "v1", &cel).len(), 2);
    assert_eq!(
        policies::plan("policies.kyverno.io", "v1beta1", &cel).len(),
        2
    );
    assert_eq!(
        policies::plan("policies.kyverno.io", "v1alpha1", &cel).len(),
        2
    );
    assert!(policies::plan("policies.kyverno.io", "v2", &cel).is_empty());
    // Templates are not constraints.
    assert!(
        policies::plan(
            "templates.gatekeeper.sh",
            "v1",
            &[kind("ConstraintTemplate", "constrainttemplates", false)]
        )
        .is_empty()
    );
}

#[test]
fn gatekeeper_lists_are_capped_and_a_hostile_kind_comes_last() {
    let mut kinds: Vec<ApiKind> = (0..10)
        .map(|n| {
            kind(
                &format!("K8sCheck{n:02}"),
                &format!("k8scheck{n:02}"),
                false,
            )
        })
        .collect();
    kinds.push(kind("Evil\u{1b}Kind", "aaaevil", false));
    kinds.push(kind("Namespaced", "namespacedkind", true));
    kinds.push(kind("Bad", "bad`plural", false));
    let planned = policies::plan("constraints.gatekeeper.sh", "v1beta1", &kinds);
    let plurals: Vec<&str> = planned.iter().map(|l| l.plural.as_str()).collect();
    // The planner lists every kind, real ones first; the reader applies the cap and counts the rest.
    assert_eq!(plurals.len(), 11, "{plurals:?}");
    assert_eq!(plurals[0], "k8scheck00");
    assert_eq!(plurals[9], "k8scheck09");
    assert_eq!(plurals[10], "aaaevil");
    assert!(policies::plan("constraints.gatekeeper.sh", "v1alpha1", &kinds).is_empty());
}

#[test]
fn the_policy_part_names_blockers_cuts_the_list_and_cleans_hostile_names() {
    let l = list("kyverno.io", "v1", "ClusterPolicy", "clusterpolicies");
    let mut items: Vec<PolicyFact> = (0..12)
        .map(|n| PolicyFact {
            name: format!("policy-{n:02}"),
            kind: "ClusterPolicy".to_owned(),
            enforcing: true,
            applies: if n == 0 { Applies::Maybe } else { Applies::Yes },
        })
        .collect();
    items.push(PolicyFact {
        name: "evil\u{1b}[2J`x`".to_owned(),
        kind: "ClusterPolicy".to_owned(),
        enforcing: false,
        applies: Applies::No,
    });
    let mut gathered = plain(facts(&[("pod-security.kubernetes.io/enforce", "baseline")]));
    gathered.engine_policies.reads.push(PolicyRead {
        list: l,
        result: Read::Ok(Listed { items, cut: false }),
    });
    let finding = judged(&gathered);
    let notes = finding.notes.join("\n");
    assert!(
        notes.contains("Kyverno ClusterPolicy policy-00 (may apply)"),
        "{notes}"
    );
    assert!(notes.contains("and 4 more"), "{notes}");
    assert!(notes.contains("(12 of 13 read reject)"), "{notes}");
    // The audit-only hostile policy is counted and never named.
    assert!(!notes.contains('\u{1b}'));
    assert_eq!(
        finding.observed["engine_policies"][0]["enforcing"]
            .as_array()
            .map(Vec::len),
        Some(8)
    );
}

#[test]
fn engine_lists_that_are_skipped_are_said() {
    let mut gathered = plain(facts(&[]));
    gathered.engine_policies.skipped = 3;
    gathered.engine_policies.reads.push(PolicyRead {
        list: list("kyverno.io", "v1", "ClusterPolicy", "clusterpolicies"),
        result: Read::Ok(Listed::default()),
    });
    let finding = judged(&gathered);
    let notes = finding.notes.join("\n");
    assert!(
        finding
            .partial
            .expect("partial")
            .note
            .contains("so 3 more were not listed and their policies are not evaluated")
    );
    assert!(notes.contains("none that rejects can apply"), "{notes}");
}

// ---- K1, K3, K5, K6 ---------------------------------------------------------------------------------------

#[test]
fn a_scoped_gatekeeper_deny_rejects_only_at_the_admission_point() {
    let l = list(
        "constraints.gatekeeper.sh",
        "v1beta1",
        "K8sRequiredLabels",
        "k8srequiredlabels",
    );
    let known = labels(&[]);
    let scoped = |points: Value| {
        let mut entry = json!({"action": "deny"});
        if !points.is_null() {
            entry["enforcementPoints"] = points;
        }
        fact_of(
            &l,
            json!({"spec": {"enforcementAction": "scoped", "scopedEnforcementActions": [entry]}}),
            &known,
        )
        .enforcing
    };
    assert!(scoped(json!([{"name": "validation.gatekeeper.sh"}])));
    assert!(scoped(json!([{"name": "*"}])));
    // No points listed is the default.
    assert!(scoped(Value::Null));
    assert!(scoped(json!([])));
    assert!(!scoped(json!([{"name": "audit"}])));
    assert!(!scoped(json!([{"name": "gator.gatekeeper.sh"}])));
}

#[test]
fn kyverno_exclusions_overrides_names_and_switches_make_a_policy_a_maybe() {
    let l = list("kyverno.io", "v1", "ClusterPolicy", "clusterpolicies");
    let known = labels(&[]);
    let base = |extra_spec: Value, extra_rule: Value| {
        let mut spec = json!({"validationFailureAction": "Enforce", "rules": [
            {"name": "r", "match": {"any": [{"resources": {"kinds": ["Pod"]}}]}, "validate": {}}
        ]});
        for (k, v) in extra_spec.as_object().into_iter().flatten() {
            spec[k] = v.clone();
        }
        for (k, v) in extra_rule.as_object().into_iter().flatten() {
            spec["rules"][0][k] = v.clone();
        }
        fact_of(&l, json!({"spec": spec}), &known)
    };
    assert_eq!(base(json!({}), json!({})).applies, Applies::Yes);
    let exclude = json!({"exclude": {"any": [{"resources": {"namespaces": ["kube-system"]}}]}});
    assert_eq!(base(json!({}), exclude).applies, Applies::Maybe);
    let named = json!({"match": {"any": [{"resources": {"kinds": ["Pod"], "names": ["web-*"]}}]}});
    assert_eq!(base(json!({}), named).applies, Applies::Maybe);
    let off = json!({"evaluation": {"admission": {"enabled": false}}});
    assert_eq!(base(off, json!({})).applies, Applies::Maybe);
    // Overrides can flip Audit to Enforce in a namespace.
    let flipped = base(
        json!({"validationFailureAction": "Audit", "validationFailureActionOverrides": [{"action": "Enforce", "namespaces": ["acme-*"]}]}),
        json!({}),
    );
    assert!(flipped.enforcing);
    assert_eq!(flipped.applies, Applies::Maybe);
    let audit_only = base(
        json!({"validationFailureAction": "Audit", "validationFailureActionOverrides": [{"action": "Audit", "namespaces": ["x"]}]}),
        json!({}),
    );
    assert!(!audit_only.enforcing);
}

#[test]
fn gatekeeper_name_and_ignore_label_make_a_constraint_a_maybe() {
    let l = list(
        "constraints.gatekeeper.sh",
        "v1beta1",
        "K8sRequiredLabels",
        "k8srequiredlabels",
    );
    let named = fact_of(
        &l,
        json!({"spec": {"match": {"name": "web-*"}}}),
        &labels(&[]),
    );
    assert_eq!(named.applies, Applies::Maybe);
    let ignored = fact_of(
        &l,
        json!({"spec": {}}),
        &labels(&[("admission.gatekeeper.sh/ignore", "no-self-managing")]),
    );
    assert_eq!(ignored.applies, Applies::Maybe);
}

fn vap_found(policy_validations: bool, cut: bool, binding_policy: &str) -> vap::Policies {
    let constraints: MatchResources = serde_json::from_value(json!({"resourceRules": [
        {"apiGroups": [""], "apiVersions": ["v1"], "operations": ["CREATE"], "resources": ["pods"]}
    ]}))
    .expect("constraints");
    vap::Policies {
        policies: Read::Ok(Listed {
            items: vec![vap::Policy {
                name: "p".to_owned(),
                constraints: Some(constraints),
                conditions: false,
                validations: policy_validations,
            }],
            cut,
        }),
        bindings: Some(Read::Ok(Listed {
            items: vec![vap::Binding {
                name: "b".to_owned(),
                policy: binding_policy.to_owned(),
                deny: true,
                resources: None,
            }],
            cut: false,
        })),
    }
}

#[test]
fn a_policy_with_no_validations_cannot_reject_and_a_binding_off_the_page_is_kept() {
    let denying =
        |found: &vap::Policies| vap::judge(found, &labels(&[]), Some("acme")).issues.len();
    assert_eq!(denying(&vap_found(true, false, "p")), 1);
    // No validations: audit annotations only, nothing to reject with.
    assert_eq!(denying(&vap_found(false, false, "p")), 0);
    // The policy of the binding is not on the page that was read: a maybe, and the cut is partial.
    let off_page = vap_found(true, true, "elsewhere");
    let part = vap::judge(&off_page, &labels(&[]), Some("acme"));
    assert_eq!(part.issues.len(), 1);
    assert!(part.issues[0].message.contains("(may apply)"));
    assert!(!part.unverified.is_empty());
    // Not cut and the policy is missing: a binding to nothing rejects nothing.
    assert_eq!(denying(&vap_found(true, false, "elsewhere")), 0);
}
