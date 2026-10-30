//! Unit tests of `k8s.rbac`: the asks, the reading of a review status, the judgement and the fix text,
//! without a cluster.

use k8s_openapi::api::authorization::v1::SubjectAccessReviewStatus;
use rdy_engine::check::Level;
use rdy_spec::check::K8sRbac;
use serde_json::{Value, json};

use super::ask::{Ask, Asks, MAX_REVIEWS, Target, impersonation_ask};
use super::judge::{Answer, Gathered, Identity, Impersonation, NamespaceState, Why, judge, shown};
use super::{answer_of, fix};

fn params(spec: Value) -> K8sRbac {
    serde_json::from_value(spec).expect("the parameters parse")
}

fn describe(asks: &[Ask]) -> Vec<String> {
    asks.iter().map(Ask::describe).collect()
}

// ---- the asks --------------------------------------------------------------------------------------------------

#[test]
fn the_entry_namespace_goes_onto_resource_items_that_name_none() {
    let asks = Asks::from_params(&params(json!({
        "can": ["create deployments.apps", {"verb": "get", "resource": "pods", "namespace": "other"}, "get /healthz"],
        "namespace": "acme"
    })));
    assert_eq!(
        describe(&asks.spec),
        [
            "create deployments.apps in acme",
            "get pods in other",
            "get /healthz"
        ]
    );
}

#[test]
fn describe_writes_group_subresource_name_and_namespace() {
    let asks = Asks::from_params(&params(json!({"can": [
        {"verb": "get", "group": "apps", "resource": "deployments", "subresource": "status", "namespace": "acme", "name": "web"},
        "list *",
        "* *"
    ]})));
    assert_eq!(
        describe(&asks.spec),
        ["get deployments.apps/status web in acme", "list *", "* *"]
    );
}

#[test]
fn a_repeated_item_is_one_ask() {
    let asks = Asks::from_params(&params(json!({"can": [
        "create namespaces",
        {"verb": "create", "resource": "namespaces"},
        "create namespaces"
    ]})));
    assert_eq!(describe(&asks.spec), ["create namespaces"]);
}

#[test]
fn roles_and_bindings_add_escalate_and_bind() {
    let asks = Asks::from_params(&params(json!({"can": [
        "create clusterroles.rbac.authorization.k8s.io",
        "patch roles.rbac.authorization.k8s.io",
        "update clusterrolebindings.rbac.authorization.k8s.io",
        {"verb": "create", "group": "rbac.authorization.k8s.io", "resource": "rolebindings", "namespace": "acme"}
    ]})));
    assert_eq!(
        describe(&asks.implied),
        [
            "escalate clusterroles.rbac.authorization.k8s.io",
            "escalate roles.rbac.authorization.k8s.io",
            "bind clusterroles.rbac.authorization.k8s.io",
            "bind roles.rbac.authorization.k8s.io in acme",
        ]
    );
    assert!(asks.implied.iter().all(|ask| ask.implied));
    assert!(asks.spec.iter().all(|ask| !ask.implied));
}

#[test]
fn only_a_verb_that_writes_adds_an_implied_ask() {
    for verb in ["get", "list", "watch", "delete", "escalate", "bind"] {
        let asks = Asks::from_params(&params(json!({"can": [
            format!("{verb} clusterroles.rbac.authorization.k8s.io")
        ]})));
        assert!(asks.implied.is_empty(), "{verb}");
    }
    for verb in ["create", "update", "patch", "*"] {
        let asks = Asks::from_params(&params(json!({"can": [
            format!("{verb} clusterroles.rbac.authorization.k8s.io")
        ]})));
        assert_eq!(asks.implied.len(), 1, "{verb}");
    }
}

#[test]
fn another_group_or_a_subresource_adds_nothing() {
    let asks = Asks::from_params(&params(json!({"can": [
        "create clusterroles.example.com",
        "create clusterroles.rbac.authorization.k8s.io/status",
        "create /healthz"
    ]})));
    assert!(asks.implied.is_empty());
}

#[test]
fn an_implied_ask_that_the_spec_already_lists_is_not_added_twice() {
    let asks = Asks::from_params(&params(json!({"can": [
        "create clusterroles.rbac.authorization.k8s.io",
        "escalate clusterroles.rbac.authorization.k8s.io",
        "update clusterroles.rbac.authorization.k8s.io"
    ]})));
    assert!(asks.implied.is_empty());
    assert_eq!(asks.spec.len(), 3);
    let two = Asks::from_params(&params(json!({"can": [
        "create clusterroles.rbac.authorization.k8s.io",
        "update clusterroles.rbac.authorization.k8s.io"
    ]})));
    assert_eq!(two.implied.len(), 1, "one escalate for two writers");
}

#[test]
fn implied_asks_past_the_cap_are_dropped_and_counted() {
    let mut can: Vec<Value> = (0..98).map(|i| json!(format!("get r{i}"))).collect();
    can.push(json!("create clusterroles.rbac.authorization.k8s.io"));
    can.push(json!(
        "create clusterrolebindings.rbac.authorization.k8s.io"
    ));
    let asks = Asks::from_params(&params(json!({"can": can})));
    assert_eq!(asks.spec.len(), 100);
    assert!(asks.implied.is_empty());
    assert_eq!(asks.dropped, 2);

    let can: Vec<Value> = (0..98).map(|i| json!(format!("get r{i}"))).collect();
    let mut can = can;
    can.push(json!("create clusterroles.rbac.authorization.k8s.io"));
    let asks = Asks::from_params(&params(json!({"can": can})));
    assert_eq!(asks.spec.len() + asks.implied.len(), MAX_REVIEWS);
    assert_eq!(asks.implied.len(), 1);
    assert_eq!(asks.dropped, 0);
}

#[test]
fn a_review_leaves_out_the_core_group_and_empty_fields() {
    let asks = Asks::from_params(&params(json!({"can": [
        "create namespaces",
        {"verb": "get", "group": "apps", "resource": "deployments", "subresource": "status", "namespace": "acme", "name": "web"},
        "get /healthz"
    ]})));
    let body = |ask: &Ask| serde_json::to_value(ask.review()).expect("serializes");
    assert_eq!(
        body(&asks.spec[0])["spec"],
        json!({"resourceAttributes": {"verb": "create", "resource": "namespaces"}})
    );
    assert_eq!(
        body(&asks.spec[1])["spec"],
        json!({"resourceAttributes": {"verb": "get", "group": "apps", "resource": "deployments",
            "subresource": "status", "namespace": "acme", "name": "web"}})
    );
    assert_eq!(
        body(&asks.spec[2])["spec"],
        json!({"nonResourceAttributes": {"verb": "get", "path": "/healthz"}})
    );
    // A typed review has no status to send.
    assert!(body(&asks.spec[0]).get("status").is_none());
}

#[test]
fn the_impersonation_question_is_about_the_service_account_or_the_user() {
    let sa = impersonation_ask("system:serviceaccount:acme-system:installer");
    assert_eq!(
        sa.describe(),
        "impersonate serviceaccounts installer in acme-system"
    );
    assert!(matches!(
        &sa.target,
        Target::Resource { group, resource, .. } if group.is_empty() && resource == "serviceaccounts"
    ));
    let user = impersonation_ask("acme-installer");
    assert_eq!(user.describe(), "impersonate users acme-installer");
}

// ---- reading a status ------------------------------------------------------------------------------------------

fn status(
    allowed: bool,
    denied: Option<bool>,
    error: Option<&str>,
    reason: Option<&str>,
) -> SubjectAccessReviewStatus {
    SubjectAccessReviewStatus {
        allowed,
        denied,
        evaluation_error: error.map(str::to_owned),
        reason: reason.map(str::to_owned),
    }
}

#[test]
fn a_status_is_allowed_denied_unclear_or_not_allowed() {
    assert_eq!(
        answer_of(&status(true, None, None, Some("ok"))),
        Answer::Allowed
    );
    // A yes wins over an evaluation error: some authorizer allowed it.
    assert_eq!(
        answer_of(&status(true, None, Some("webhook down"), None)),
        Answer::Allowed
    );
    assert_eq!(
        answer_of(&status(false, Some(true), None, Some("no"))),
        Answer::Denied {
            reason: "no".to_owned()
        }
    );
    // An explicit deny wins over an evaluation error.
    assert_eq!(
        answer_of(&status(false, Some(true), Some("boom"), None)),
        Answer::Denied {
            reason: String::new()
        }
    );
    assert_eq!(
        answer_of(&status(false, None, Some("boom"), None)),
        Answer::Unclear {
            reason: "boom".to_owned()
        }
    );
    assert_eq!(
        answer_of(&status(false, Some(false), Some(""), None)),
        Answer::NotAllowed {
            reason: String::new()
        }
    );
    assert_eq!(
        answer_of(&status(false, None, None, Some("RBAC: nothing matched"))),
        Answer::NotAllowed {
            reason: "RBAC: nothing matched".to_owned()
        }
    );
}

#[test]
fn text_from_the_server_is_escaped_without_backticks_and_cut() {
    assert_eq!(shown("a\u{1b}[2Jb", 50), "a\\x1b[2Jb");
    assert_eq!(shown("run `rm -rf /`", 50), "run 'rm -rf /'");
    assert_eq!(shown("abcdef", 3), "abc...");
    assert_eq!(shown("abc", 3), "abc");
    assert_eq!(shown("a\u{202e}b", 50), "a\\u{202e}b");
}

// ---- judging ---------------------------------------------------------------------------------------------------

fn gathered(spec: Vec<(Ask, Answer)>, implied: Vec<(Ask, Answer)>) -> Gathered {
    Gathered {
        identity: Identity::Verified {
            user: "acme-installer".to_owned(),
            groups: vec!["system:authenticated".to_owned()],
        },
        as_user: None,
        impersonation: Impersonation::NotUsed,
        spec,
        implied,
        dropped: 0,
        rules: None,
        namespaces: Vec::new(),
        sent: 0,
    }
}

fn ask(text: &str) -> Ask {
    let spec = params(json!({"can": [text]}));
    Asks::from_params(&spec).spec.remove(0)
}

fn no() -> Answer {
    Answer::NotAllowed {
        reason: String::new(),
    }
}

#[test]
fn a_missing_permission_outranks_an_unclear_one_and_a_denied_escalate() {
    let spec = params(
        json!({"can": ["create namespaces", "list nodes", "create clusterroles.rbac.authorization.k8s.io"]}),
    );
    let g = gathered(
        vec![
            (ask("create namespaces"), no()),
            (
                ask("list nodes"),
                Answer::Unclear {
                    reason: "x".to_owned(),
                },
            ),
            (
                ask("create clusterroles.rbac.authorization.k8s.io"),
                Answer::Allowed,
            ),
        ],
        vec![(ask("escalate clusterroles.rbac.authorization.k8s.io"), no())],
    );
    let finding = judge(&spec, &g);
    assert_eq!(finding.level, Level::Fail);
    assert_eq!(
        finding.message,
        "`acme-installer` cannot `create namespaces`: not allowed"
    );
    // The warnings are still said, in the notes.
    assert_eq!(finding.notes.len(), 4, "{:?}", finding.notes);
}

#[test]
fn unclear_answers_warn_and_only_unclear_ones() {
    let spec = params(json!({"can": ["create namespaces", "list nodes"]}));
    let g = gathered(
        vec![
            (ask("create namespaces"), Answer::Allowed),
            (
                ask("list nodes"),
                Answer::Unclear {
                    reason: "x".to_owned(),
                },
            ),
        ],
        Vec::new(),
    );
    assert_eq!(judge(&spec, &g).level, Level::Warn);
}

#[test]
fn a_list_of_many_missing_items_names_three_and_counts_the_rest() {
    let items: Vec<String> = (0..6).map(|i| format!("create r{i}")).collect();
    let spec = params(json!({"can": items}));
    let g = gathered(
        items.iter().map(|text| (ask(text), no())).collect(),
        Vec::new(),
    );
    let finding = judge(&spec, &g);
    assert_eq!(
        finding.message,
        "6 of 6 permissions are missing for `acme-installer`: `create r0` (not allowed); `create r1` (not allowed); `create r2` (not allowed); and 3 more"
    );
    assert_eq!(
        finding.notes.len(),
        7,
        "one note per item and the audit note"
    );
}

#[test]
fn gaps_are_grouped_by_reason_with_a_grant_when_a_grant_would_help() {
    let spec = params(json!({"can": ["a x", "b x", "c x"]}));
    let g = gathered(
        vec![
            (ask("a x"), Answer::Allowed),
            (ask("b x"), Answer::NotEvaluated(Why::Forbidden)),
            (ask("c x"), Answer::NotEvaluated(Why::OutOfTime)),
        ],
        Vec::new(),
    );
    let finding = judge(&spec, &g);
    assert_eq!(finding.level, Level::Pass);
    assert_eq!(
        finding.message,
        "`acme-installer` can do the 1 permissions that were evaluated"
    );
    let partial = finding.partial.expect("partial");
    assert_eq!(
        partial.note,
        "1 permission was not evaluated: the identity may not create access reviews; 1 permission was not evaluated: rdy ran out of time"
    );
    assert_eq!(
        partial.missing_grants,
        ["create selfsubjectaccessreviews.authorization.k8s.io"]
    );
}

#[test]
fn a_missing_permission_and_a_gap_give_a_block_with_a_partial() {
    let spec = params(json!({"can": ["a x", "b x"]}));
    let g = gathered(
        vec![
            (ask("a x"), no()),
            (ask("b x"), Answer::NotEvaluated(Why::OutOfTime)),
        ],
        Vec::new(),
    );
    let finding = judge(&spec, &g);
    assert_eq!(finding.level, Level::Fail);
    assert!(finding.partial.is_some());
}

#[test]
fn the_tested_user_is_the_subject_when_the_spec_has_as() {
    let spec = params(json!({"can": ["a x"], "as": "acme-user"}));
    let mut g = gathered(vec![(ask("a x"), no())], Vec::new());
    g.as_user = Some("acme-user".to_owned());
    g.impersonation = Impersonation::Allowed;
    assert_eq!(
        judge(&spec, &g).message,
        "`acme-user` cannot `a x`: not allowed"
    );
}

#[test]
fn namespaces_of_denied_items_are_listed_once_in_order() {
    let g = gathered(
        vec![
            (ask("get pods"), Answer::Allowed),
            (
                ask_in("get pods", "b"),
                Answer::NotAllowed {
                    reason: String::new(),
                },
            ),
            (ask_in("get nodes", "a"), no()),
            (ask_in("get secrets", "b"), no()),
        ],
        Vec::new(),
    );
    assert_eq!(g.denied_namespaces(), ["b", "a"]);
    assert_eq!(g.rules_namespace(None).as_deref(), Some("b"));
    let entry: rdy_spec::check::K8sName = serde_json::from_value(json!("entry")).expect("a name");
    assert_eq!(g.rules_namespace(Some(&entry)).as_deref(), Some("entry"));
    let _ = NamespaceState::Exists;
}

fn ask_in(text: &str, namespace: &str) -> Ask {
    let spec = params(json!({"can": [text], "namespace": namespace}));
    Asks::from_params(&spec).spec.remove(0)
}

// ---- the fix ---------------------------------------------------------------------------------------------------

fn who(user: &str) -> fix::Who {
    let g = gathered(Vec::new(), Vec::new());
    let mut g = g;
    g.identity = Identity::Verified {
        user: user.to_owned(),
        groups: Vec::new(),
    };
    fix::Who::of(&g)
}

fn fix_for(grantable: &[Ask], denied: &[Ask], user: &str) -> String {
    fix::text(&fix::Context {
        who: who(user),
        grantable: grantable.iter().collect(),
        denied: denied.iter().collect(),
        implied: Vec::new(),
        unclear: Vec::new(),
        missing_namespaces: Vec::new(),
    })
}

#[test]
fn a_cluster_item_gets_a_clusterrole_and_a_namespaced_item_gets_a_role() {
    let text = fix_for(&[ask("create namespaces")], &[], "acme-installer");
    assert!(
        text.contains("`kubectl create clusterrole rdy-installer --verb=create --resource=namespaces`, then `kubectl create clusterrolebinding rdy-installer --clusterrole=rdy-installer --user=acme-installer`"),
        "{text}"
    );
    let text = fix_for(
        &[ask_in("get pods/log", "acme")],
        &[],
        "system:serviceaccount:acme:installer",
    );
    assert!(
        text.contains("`kubectl create role rdy-installer -n acme --verb=get --resource=pods/log`, then `kubectl create rolebinding rdy-installer -n acme --role=rdy-installer --serviceaccount=acme:installer`"),
        "{text}"
    );
}

#[test]
fn a_wildcard_is_quoted_and_a_name_is_passed() {
    let text = fix_for(&[ask("* *")], &[], "bob");
    assert!(text.contains("--verb='*' --resource='*'"), "{text}");
    let named = Asks::from_params(&params(json!({"can": [
        {"verb": "get", "resource": "configmaps", "namespace": "acme", "name": "cfg"}
    ]})))
    .spec
    .remove(0);
    let text = fix_for(&[named], &[], "bob");
    assert!(
        text.contains("--resource=configmaps --resource-name=cfg"),
        "{text}"
    );
}

#[test]
fn a_user_name_with_odd_characters_never_reaches_a_command() {
    for user in ["bob smith", "a;b", "a$(x)", "a`b`", "'q'", "a\nb", ""] {
        let text = fix_for(&[ask("create namespaces")], &[], user);
        assert!(text.contains("--user=<user>"), "{user:?}: {text}");
    }
    let text = fix_for(&[ask("create namespaces")], &[], "bob@acme.example");
    assert!(text.contains("--user=bob@acme.example"), "{text}");
}

#[test]
fn a_denied_item_is_not_something_a_role_grants() {
    let text = fix_for(&[], &[ask("list pods")], "bob");
    assert!(!text.contains("kubectl create"), "{text}");
    assert!(!text.contains("cluster-admin"), "{text}");
    assert!(
        text.contains("`list pods` was refused by an authorizer other than RBAC"),
        "{text}"
    );
}
