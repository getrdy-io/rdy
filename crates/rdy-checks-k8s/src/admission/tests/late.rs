//! Fixture tests of the M1-160 half of `k8s.admission`: admission webhooks, `ValidatingAdmissionPolicy` and the
//! engines' own policies, over the same mock harness with the guard in front.

use super::*;

const VW: &str = "/apis/admissionregistration.k8s.io/v1/validatingwebhookconfigurations";
const MW: &str = "/apis/admissionregistration.k8s.io/v1/mutatingwebhookconfigurations";
const VAP: &str = "/apis/admissionregistration.k8s.io/v1/validatingadmissionpolicies";
const VAPB: &str = "/apis/admissionregistration.k8s.io/v1/validatingadmissionpolicybindings";
const SERVICE: &str = "/api/v1/namespaces/acme-hooks/services";
const SLICES: &str = "/apis/discovery.k8s.io/v1/namespaces/acme-hooks/endpointslices";

fn spec() -> Value {
    json!({"pod_security": "baseline"})
}

// ---- webhooks ---------------------------------------------------------------------------------------------

#[tokio::test]
async fn a_fail_webhook_with_an_empty_endpointslice_blocks() {
    let rig = rig("webhook-fail-empty");
    let finding = rig.finding(spec()).await;
    assert_eq!(finding.level, Level::Fail, "{finding:?}");
    assert_eq!(
        finding.message,
        "validating webhook pods.acme-hooks.example of acme-validating fails closed and Service hooks in namespace acme-hooks has no endpoint, so the API server rejects every pod create in namespace acme-system"
    );
    let fix = finding.fix.clone().expect("a fix");
    assert!(
        fix.contains(
            "`kubectl get endpointslices -n acme-hooks -l kubernetes.io/service-name=hooks`"
        ),
        "{fix}"
    );
    assert!(fix.contains("`kubectl get pods -n acme-hooks`"), "{fix}");
    assert!(
        fix.contains("`kubectl get validatingwebhookconfigurations acme-validating`"),
        "{fix}"
    );
    assert!(finding.partial.is_none());
    let applying = &finding.observed["webhooks"]["applying"][0];
    assert_eq!(applying["failure_policy"], "Fail");
    assert_eq!(applying["applies"], "yes");
    assert_eq!(applying["backend"], "service");
    assert_eq!(applying["ready_endpoints"], 0);
    // The Service is read first, then its slices, after the lists of the configurations.
    let paths = rig.every_path();
    let at = |wanted: &str| paths.iter().position(|path| path == wanted).expect(wanted);
    assert!(at(VW) < at(MW) && at(MW) < at(SERVICE) && at(SERVICE) < at(SLICES));
    // The engine turns the finding into a block, or a warn on a warn-severity entry.
    assert_eq!(engine(&rig, finding.clone(), None).status, Status::Block);
    assert_eq!(engine(&rig, finding, Some("warn")).status, Status::Warn);
    rig.audit();
}

#[tokio::test]
async fn a_webhook_with_no_failure_policy_fails_closed() {
    // `failurePolicy` defaults to Fail in admissionregistration.k8s.io/v1.
    let rig = rig("webhook-default-fail");
    let finding = rig.finding(spec()).await;
    assert_eq!(finding.level, Level::Fail, "{finding:?}");
    assert_eq!(
        finding.observed["webhooks"]["applying"][0]["failure_policy"],
        "Fail"
    );
    rig.audit();
}

#[tokio::test]
async fn ready_unset_means_ready_and_one_ready_endpoint_is_enough() {
    let rig = rig("webhook-ready");
    let finding = rig.finding(spec()).await;
    assert_eq!(finding.level, Level::Pass, "{finding:?}");
    assert!(finding.partial.is_none());
    // One endpoint says ready, one leaves `ready` unset and one says false.
    assert_eq!(
        finding.observed["webhooks"]["applying"][0]["ready_endpoints"],
        2
    );
    assert!(
        notes(&finding).contains(
            "rdy read 1 validating and 0 mutating webhooks. 1 can apply to a pod create in namespace acme-system."
        ),
        "{finding:?}"
    );
    rig.audit();
}

#[tokio::test]
async fn endpoints_that_are_all_not_ready_block() {
    let rig = rig("webhook-not-ready");
    let finding = rig.finding(spec()).await;
    assert_eq!(finding.level, Level::Fail, "{finding:?}");
    assert!(
        finding
            .message
            .contains("Service hooks in namespace acme-hooks has 2 endpoints and none is ready"),
        "{}",
        finding.message
    );
    rig.audit();
}

#[tokio::test]
async fn a_mutating_webhook_blocks_the_same_way() {
    let rig = rig("webhook-mutating");
    let finding = rig.finding(spec()).await;
    assert_eq!(finding.level, Level::Fail, "{finding:?}");
    assert!(
        finding.message.starts_with(
            "mutating webhook inject.acme-hooks.example of acme-mutating fails closed"
        ),
        "{}",
        finding.message
    );
    let fix = finding.fix.expect("a fix");
    assert!(
        fix.contains("`kubectl get mutatingwebhookconfigurations acme-mutating`"),
        "{fix}"
    );
    rig.audit();
}

#[tokio::test]
async fn a_service_that_does_not_exist_blocks_and_its_slices_are_not_asked() {
    let rig = rig("webhook-service-missing");
    let finding = rig.finding(spec()).await;
    assert_eq!(finding.level, Level::Fail, "{finding:?}");
    assert!(
        finding
            .message
            .contains("Service hooks in namespace acme-hooks does not exist"),
        "{}",
        finding.message
    );
    assert!(!rig.every_path().iter().any(|path| path == SLICES));
    rig.audit();
}

#[tokio::test]
async fn match_conditions_make_the_empty_backend_a_warning_that_says_not_evaluated() {
    let rig = rig("webhook-match-conditions");
    let finding = rig.finding(spec()).await;
    assert_eq!(finding.level, Level::Warn, "{finding:?}");
    assert!(
        finding.message.contains(
            "it rejects the product's pods unless its matchConditions exempt them, and rdy did not evaluate that"
        ),
        "{}",
        finding.message
    );
    assert_eq!(
        finding.observed["webhooks"]["applying"][0]["applies"],
        "maybe"
    );
    assert_eq!(engine(&rig, finding, None).status, Status::Warn);
    rig.audit();
}

#[tokio::test]
async fn an_object_selector_makes_the_empty_backend_a_warning_too() {
    let rig = rig("webhook-object-selector");
    let finding = rig.finding(spec()).await;
    assert_eq!(finding.level, Level::Warn, "{finding:?}");
    assert!(
        finding
            .message
            .contains("unless its objectSelector exempt them"),
        "{}",
        finding.message
    );
    rig.audit();
}

#[tokio::test]
async fn a_url_webhook_is_an_external_backend_not_verified() {
    let rig = rig("webhook-url");
    let finding = rig.finding(spec()).await;
    assert_eq!(finding.level, Level::Pass, "{finding:?}");
    let partial = finding.partial.clone().expect("partial");
    assert!(
        partial.note.contains(
            "validating webhook pods.acme-hooks.example of acme-validating sends requests to a URL outside the cluster and fails closed: external backend, not verified"
        ),
        "{partial:?}"
    );
    // Nothing about the URL, and no Service or slice read.
    assert!(!format!("{finding:?}").contains("hooks.example.invalid"));
    assert!(
        rig.every_path()
            .iter()
            .all(|path| path != SERVICE && path != SLICES)
    );
    assert_eq!(
        finding.observed["webhooks"]["applying"][0]["backend"],
        "url"
    );
    assert_eq!(engine(&rig, finding, None).status, Status::Warn);
    rig.audit();
}

#[tokio::test]
async fn an_external_name_service_is_not_verified() {
    let rig = rig("webhook-external-name");
    let finding = rig.finding(spec()).await;
    assert_eq!(finding.level, Level::Pass, "{finding:?}");
    assert!(
        finding
            .partial
            .expect("partial")
            .note
            .contains("is of type ExternalName: external backend, not verified")
    );
    assert!(!rig.every_path().iter().any(|path| path == SLICES));
    rig.audit();
}

#[tokio::test]
async fn a_webhook_that_fails_open_is_listed_and_never_judged() {
    let rig = rig("webhook-ignore");
    let finding = rig.finding(spec()).await;
    assert_eq!(finding.level, Level::Pass, "{finding:?}");
    assert!(finding.partial.is_none());
    assert_eq!(
        finding.observed["webhooks"]["applying"][0]["failure_policy"],
        "Ignore"
    );
    assert!(!rig.every_path().iter().any(|path| path == SERVICE));
    rig.audit();
}

#[tokio::test]
async fn webhooks_that_do_not_match_a_pod_create_here_are_not_judged() {
    // Another namespace, deployments only, update only and a pod subresource: none applies.
    let rig = rig("webhook-not-matching");
    let finding = rig.finding(spec()).await;
    assert_eq!(finding.level, Level::Pass, "{finding:?}");
    assert!(finding.partial.is_none());
    assert_eq!(finding.observed["webhooks"]["applying"], json!([]));
    assert_eq!(finding.observed["webhooks"]["validating"], 4);
    assert!(
        rig.every_path()
            .iter()
            .all(|path| path != SERVICE && path != SLICES)
    );
    rig.audit();
}

#[tokio::test]
async fn forbidden_webhook_lists_give_partial_with_both_grants() {
    let rig = rig("webhooks-forbidden");
    let finding = rig.finding(spec()).await;
    assert_eq!(finding.level, Level::Pass, "{finding:?}");
    assert_eq!(
        grants(&finding),
        [
            "list validatingwebhookconfigurations.admissionregistration.k8s.io",
            "list mutatingwebhookconfigurations.admissionregistration.k8s.io"
        ]
    );
    let partial = finding.partial.clone().expect("partial");
    assert!(
        partial
            .note
            .contains("validating webhooks were not evaluated: the list could not be read (the identity may not read it)"),
        "{partial:?}"
    );
    let fix = finding.fix.clone().expect("a fix");
    assert!(
        fix.contains(
            "`kubectl auth can-i list validatingwebhookconfigurations.admissionregistration.k8s.io`"
        ),
        "{fix}"
    );
    assert_eq!(finding.observed["webhooks"]["validating"], Value::Null);
    let result = engine(&rig, finding, None);
    assert_eq!(result.status, Status::Warn);
    assert_eq!(result.partial.expect("partial").missing_grants.len(), 2);
    rig.audit();
}

#[tokio::test]
async fn forbidden_endpoint_slices_are_not_evaluated_and_never_a_block() {
    let rig = rig("webhook-slices-forbidden");
    let finding = rig.finding(spec()).await;
    assert_eq!(finding.level, Level::Pass, "{finding:?}");
    assert_eq!(grants(&finding), ["list endpointslices.discovery.k8s.io"]);
    assert!(
        finding
            .partial
            .expect("partial")
            .note
            .contains("fails closed, and its endpoints were not read (the identity may not read it): not evaluated")
    );
    rig.audit();
}

#[tokio::test]
async fn forbidden_services_are_not_evaluated_and_never_a_block() {
    let rig = rig("webhook-services-forbidden");
    let finding = rig.finding(spec()).await;
    assert_eq!(finding.level, Level::Pass, "{finding:?}");
    assert_eq!(grants(&finding), ["list services"]);
    assert!(!rig.every_path().iter().any(|path| path == SLICES));
    rig.audit();
}

#[tokio::test]
async fn at_most_eight_services_are_read() {
    let rig = rig("webhook-many-services");
    let finding = rig.finding(spec()).await;
    let paths = rig.every_path();
    let services = paths.iter().filter(|p| p.ends_with("/services")).count();
    let slices = paths
        .iter()
        .filter(|p| p.ends_with("/endpointslices"))
        .count();
    assert_eq!((services, slices), (8, 8), "{paths:?}");
    // The two left are said, not guessed at.
    let partial = finding.partial.expect("partial");
    assert_eq!(
        partial
            .note
            .matches("its endpoints were not read: not evaluated")
            .count(),
        2,
        "{}",
        partial.note
    );
    rig.audit();
}

// ---- ValidatingAdmissionPolicy ----------------------------------------------------------------------------

#[tokio::test]
async fn a_denying_binding_that_matches_pods_warns_by_name() {
    let rig = rig("vap-deny");
    let finding = rig.finding(spec()).await;
    assert_eq!(finding.level, Level::Warn, "{finding:?}");
    assert_eq!(
        finding.message,
        "ValidatingAdmissionPolicy bindings that deny can reject the product's pods in namespace acme-system: require-labels-acme of policy require-labels. The CEL expressions were not evaluated"
    );
    let fix = finding.fix.clone().expect("a fix");
    assert!(
        fix.contains("`kubectl get validatingadmissionpolicies,validatingadmissionpolicybindings`"),
        "{fix}"
    );
    assert_eq!(
        finding.observed["validating_admission_policies"]["denying"][0]["binding"],
        "require-labels-acme"
    );
    let paths = rig.every_path();
    assert!(paths.iter().any(|p| p == VAP) && paths.iter().any(|p| p == VAPB));
    rig.audit();
}

#[tokio::test]
async fn bindings_that_only_warn_or_do_not_match_reject_nothing() {
    for case in ["vap-warn-only", "vap-not-matching", "vap-other-namespace"] {
        let rig = rig(case);
        let finding = rig.finding(spec()).await;
        assert_eq!(finding.level, Level::Pass, "{case}: {finding:?}");
        assert!(finding.partial.is_none(), "{case}");
        assert_eq!(
            finding.observed["validating_admission_policies"]["denying"],
            json!([]),
            "{case}"
        );
        rig.audit();
    }
}

#[tokio::test]
async fn a_cluster_that_does_not_serve_the_policy_api_has_none() {
    let rig = rig("vap-not-served");
    let finding = rig.finding(spec()).await;
    assert_eq!(finding.level, Level::Pass, "{finding:?}");
    assert!(finding.partial.is_none());
    assert!(
        notes(&finding).contains("does not serve ValidatingAdmissionPolicy"),
        "{finding:?}"
    );
    assert!(!rig.every_path().iter().any(|p| p == VAPB));
    rig.audit();
}

#[tokio::test]
async fn forbidden_policy_lists_give_partial_with_the_grant() {
    let rig = rig("vap-forbidden");
    let finding = rig.finding(spec()).await;
    assert_eq!(finding.level, Level::Pass, "{finding:?}");
    assert_eq!(
        grants(&finding),
        ["list validatingadmissionpolicies.admissionregistration.k8s.io"]
    );
    rig.audit();

    let second = self::rig("vap-bindings-forbidden");
    let finding = second.finding(spec()).await;
    assert_eq!(finding.level, Level::Pass, "{finding:?}");
    assert_eq!(
        grants(&finding),
        ["list validatingadmissionpolicybindings.admissionregistration.k8s.io"]
    );
    second.audit();
}

// ---- the engines' own policies ----------------------------------------------------------------------------

#[tokio::test]
async fn the_policies_of_both_engines_are_named() {
    let rig = rig("engine-policies");
    let finding = rig.finding(spec()).await;
    assert_eq!(finding.level, Level::Warn, "{finding:?}");
    let notes = notes(&finding);
    // A Kyverno ClusterPolicy and two Gatekeeper constraint kinds, each named.
    for named in [
        "Kyverno ClusterPolicy require-owner",
        "Kyverno ClusterPolicy rule-level-enforce",
        "Kyverno ValidatingPolicy no-host-network",
        "Gatekeeper K8sAllowedRepos repos-acme",
        "Gatekeeper K8sRequiredLabels labels-everywhere",
    ] {
        assert!(notes.contains(named), "{named}: {notes}");
    }
    // Audit-only, dry-run and warn-only policies, and the ones that do not match a pod here, are not.
    for left_out in [
        "audit-only",
        "deployments-only",
        "other-namespace",
        "repos-dryrun",
        "labels-other",
        "warn-only",
    ] {
        assert!(!notes.contains(left_out), "{left_out}: {notes}");
    }
    assert!(notes.contains("Their rules were not evaluated."), "{notes}");
    let lists = finding.observed["engine_policies"]
        .as_array()
        .expect("lists");
    assert_eq!(lists.len(), 4);
    assert!(lists.iter().all(|list| list["list"] == "read"));
    // The four policy lists, each a plain GET of one page.
    let paths = rig.every_path();
    for path in [
        "/apis/kyverno.io/v1/clusterpolicies",
        "/apis/policies.kyverno.io/v1/validatingpolicies",
        "/apis/constraints.gatekeeper.sh/v1beta1/k8sallowedrepos",
        "/apis/constraints.gatekeeper.sh/v1beta1/k8srequiredlabels",
    ] {
        assert!(paths.iter().any(|p| p == path), "{path}: {paths:?}");
    }
    assert!(finding.partial.is_none());
    rig.audit();
}

#[tokio::test]
async fn forbidden_policy_lists_of_the_engines_are_partial_and_never_a_block() {
    let rig = rig("engine-policies-forbidden");
    let finding = rig.finding(spec()).await;
    // The engine is still found, so the level is the engine's warn.
    assert_eq!(finding.level, Level::Warn, "{finding:?}");
    assert_eq!(
        grants(&finding),
        [
            "list clusterpolicies.kyverno.io",
            "list validatingpolicies.policies.kyverno.io",
            "list constraints.gatekeeper.sh"
        ]
    );
    let partial = finding.partial.clone().expect("partial");
    assert!(
        partial
            .note
            .contains("Kyverno ClusterPolicy policies were not evaluated: the list could not be read (the identity may not read it)"),
        "{partial:?}"
    );
    let fix = finding.fix.clone().expect("a fix");
    assert!(
        fix.contains("`kubectl auth can-i list k8sallowedrepos.constraints.gatekeeper.sh`"),
        "{fix}"
    );
    rig.audit();
}

#[tokio::test]
async fn a_kyverno_group_that_serves_only_policy_exceptions_lists_no_policy() {
    let rig = rig("kyverno-exception-only");
    let finding = rig.finding(spec()).await;
    assert_eq!(finding.level, Level::Warn, "{finding:?}");
    // `/apis/kyverno.io/v2` is discovery (three parts). A list would have four.
    let paths = rig.every_path();
    assert!(
        !paths
            .iter()
            .any(|path| path.starts_with("/apis/kyverno.io/") && path.matches('/').count() == 4),
        "{paths:?}"
    );
    assert_eq!(finding.observed["engine_policies"], json!([]));
    rig.audit();
}

#[tokio::test]
async fn an_engine_whose_kinds_could_not_be_read_lists_no_policy() {
    let rig = rig("engine-forbidden");
    let finding = rig.finding(spec()).await;
    assert_eq!(finding.observed["engine_policies"], json!([]));
    // The preferred version was forbidden: v1 of kyverno.io is not asked, so the fixture holds no file for it.
    assert!(
        !rig.every_path()
            .iter()
            .any(|path| path == "/apis/kyverno.io/v1"),
        "{:?}",
        rig.every_path()
    );
    rig.audit();
}

#[tokio::test]
async fn at_most_six_constraint_kinds_are_listed_and_real_kinds_come_first() {
    let rig = rig("many-kinds");
    let finding = rig.finding(spec()).await;
    let lists: Vec<String> = rig
        .every_path()
        .into_iter()
        .filter(|path| path.starts_with("/apis/constraints.gatekeeper.sh/v1beta1/"))
        .collect();
    assert_eq!(lists.len(), 6, "{lists:?}");
    // The hostile kinds (plurals evil1 to evil4) sort after the twelve real ones.
    assert!(
        lists.iter().all(|path| path.contains("k8scheck")),
        "{lists:?}"
    );
    assert!(
        finding.observed["engine_policies"]
            .as_array()
            .expect("lists")
            .len()
            == 6
    );
    rig.audit();
}

// ---- the guard test ---------------------------------------------------------------------------------------

#[tokio::test]
async fn across_the_fixture_set_the_check_makes_no_call_that_is_not_a_get() {
    // The exit test of M1-160: the only non-GET calls are the three review kinds, and this check asks for
    // none, so the set is empty. Every cluster of the folder is run and every request is looked at.
    const REVIEWS: [&str; 3] = [
        "/apis/authorization.k8s.io/v1/selfsubjectaccessreviews",
        "/apis/authorization.k8s.io/v1/selfsubjectrulesreviews",
        "/apis/authentication.k8s.io/v1/selfsubjectreviews",
    ];
    let cases = rdy_engine::testing::fixture_cases("k8s.admission");
    assert!(cases.len() >= 50, "the cases were found: {cases:?}");
    let mut late = 0;
    for case in cases.iter().map(String::as_str) {
        let rig = rig(case);
        let spec = if case == "no-namespace" {
            json!({"pod_security": "baseline"})
        } else {
            json!({"pod_security": "baseline", "scc": "anyuid"})
        };
        if case == "no-namespace" {
            rig.finding_in(spec, None).await;
        } else {
            rig.finding(spec).await;
        }
        for (method, path) in rig.requests() {
            assert!(
                method == "GET" || REVIEWS.contains(&path.as_str()),
                "{case}: {method} {path}"
            );
            late += usize::from(is_late_read(&path));
        }
        rig.audit();
    }
    // The new reads really ran across the set.
    assert!(late > 100, "{late}");
}
