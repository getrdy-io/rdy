//! Tests of the request-info parser, the resource allowlist, the `Impersonate-*` value rule, the decoded
//! query values and the citation of `ALLOWED` by the checks (M1-104).
//!
//! The first tests send each case of the exit test through the real layer in front of the mock: the
//! request is refused, the mock sees nothing, and the log has one denied entry with the check id.

use std::collections::BTreeSet;

use super::super::rules::{RequestInfo, request_info};
use super::*;

// ---- helpers ---------------------------------------------------------------------------------------------

/// Sends `sent`, and asserts the guard refused it with `rule`, that nothing reached the server, and that
/// the log gained exactly one denied `kube` entry for the rig's check, `method` and `path` (no query string).
async fn refused_and_logged(rig: &Rig, sent: Request<Body>, path: &str, rule: &str) {
    let before = rig.log().len();
    let method = sent.method().to_string();
    let verdict = rig.send(sent).await;
    assert_eq!(verdict, Err(rule), "{method} {path}");
    assert_eq!(rig.mock.seen(), Vec::<String>::new(), "{method} {path}");
    let log = rig.log();
    assert_eq!(log.len(), before + 1, "{method} {path}: one entry");
    let entry = log.last().expect("an entry");
    assert_eq!(entry.kind, ActionKind::Kube);
    assert_eq!(entry.outcome, ActionOutcome::Denied, "{method} {path}");
    assert_eq!(entry.check, rig.check, "{method} {path}");
    assert_eq!(field(entry, "rule"), Some(rule), "{method} {path}");
    assert_eq!(field(entry, "method"), Some(method.as_str()));
    assert_eq!(field(entry, "path"), Some(path), "{method} {path}");
}

fn get(uri: &str, headers: &[(&str, &str)]) -> Request<Body> {
    request(Method::GET, uri, headers, Vec::new())
}

// ---- the exit test cases, each refused and logged ----------------------------------------------------------

#[tokio::test]
async fn percent_encoded_secrets_is_refused_and_logged() {
    let rig = Rig::new();
    for path in [
        "/api/v1/%73ecrets",
        "/api/v1/namespaces/app/%73ecrets",
        "/api/v1/namespaces/app/%73ecrets/token",
        "/api/v1/namespaces/%73ecrets",
        "/api/%76%31/secrets",
        "/api/v1/namespaces/app/%2573ecrets",
        "/api/v1/namespaces/app/secret%73",
        "/api/v1/%53ecrets",
        "/%61pi/v1/nodes",
    ] {
        refused_and_logged(&rig, get(path, &[]), path, RULE_PATH_SHAPE).await;
    }
    // The raw word in the same places is refused as Secrets.
    for path in [
        "/api/v1/secrets",
        "/api/v1/namespaces/app/secrets",
        "/api/v1/namespaces/app/secrets/token",
    ] {
        refused_and_logged(&rig, get(path, &[]), path, RULE_SECRETS).await;
    }
    // The query is never decoded into the path, and `%73ecrets` in a value is only a value.
    assert_eq!(
        rig.get("/api/v1/nodes?labelSelector=%73ecrets").await,
        Ok(StatusCode::OK)
    );
}

#[tokio::test]
async fn secrets_in_every_segment_position_is_refused_and_logged() {
    let rig = Rig::new();
    for path in [
        "/secrets",
        "/secrets/v1/nodes",
        "/api/secrets",
        "/api/secrets/nodes",
        "/api/v1/secrets",
        "/api/v1/secrets/token",
        "/api/v1/secrets/token/status",
        "/api/v1/nodes/secrets",
        "/api/v1/nodes/secrets/status",
        "/api/v1/nodes/n1/secrets",
        "/api/v1/namespaces/secrets/pods",
        "/api/v1/namespaces/secrets/persistentvolumeclaims",
        "/api/v1/namespaces/secrets/secrets",
        "/api/v1/namespaces/secrets/finalize",
        "/api/v1/namespaces/secrets/status",
        "/api/v1/namespaces/app/secrets",
        "/api/v1/namespaces/app/secrets/token",
        "/api/v1/namespaces/app/pods/secrets",
        "/api/v1/namespaces/app/pods/p/secrets",
        "/api/v1/namespaces/secrets/extra/segments/here",
        "/apis/secrets",
        "/apis/secrets/v1",
        "/apis/secrets/v1/nodes",
        "/apis/storage.k8s.io/secrets",
        "/apis/storage.k8s.io/v1/secrets",
        "/apis/storage.k8s.io/v1/storageclasses/secrets",
        "/apis/storage.k8s.io/v1/storageclasses/x/secrets",
        "/apis/apps/v1/namespaces/secrets/deployments",
        "/apis/apps/v1/namespaces/kube-system/deployments/secrets",
        "/version/secrets",
        "/api/v1/watch/secrets",
        "/api/v1/watch/namespaces/app/secrets",
    ] {
        refused_and_logged(&rig, get(path, &[]), path, RULE_SECRETS).await;
    }
    // The word is a whole segment. A longer name is a different name.
    for path in [
        "/api/v1/namespaces/secretsx",
        "/api/v1/namespaces/xsecrets",
        "/api/v1/namespaces/my-secrets",
    ] {
        assert_eq!(rig.get(path).await, Ok(StatusCode::OK), "{path}");
    }
}

#[tokio::test]
async fn a_namespace_called_secrets_is_a_get_of_a_namespace() {
    let rig = Rig::new();
    assert_eq!(
        rig.get("/api/v1/namespaces/secrets").await,
        Ok(StatusCode::OK)
    );
    assert_eq!(
        rig.get("/api/v1/namespaces/secrets?&limit=5").await,
        Ok(StatusCode::OK)
    );
    assert_eq!(
        rig.mock.seen(),
        [
            "GET /api/v1/namespaces/secrets",
            "GET /api/v1/namespaces/secrets?&limit=5"
        ]
    );
    let log = rig.log();
    assert_eq!(log.len(), 2);
    assert!(log.iter().all(|a| a.outcome == ActionOutcome::Ok));
    assert_eq!(field(&log[0], "path"), Some("/api/v1/namespaces/secrets"));

    // That one path is the whole exception: no other verb, no subresource, no other group or version.
    let write = |method: Method| request(method, "/api/v1/namespaces/secrets", &[], b"{}".to_vec());
    let rig = Rig::new();
    for method in [Method::DELETE, Method::PUT, Method::PATCH] {
        refused_and_logged(
            &rig,
            write(method),
            "/api/v1/namespaces/secrets",
            RULE_METHOD,
        )
        .await;
    }
    refused_and_logged(
        &rig,
        write(Method::POST),
        "/api/v1/namespaces/secrets",
        RULE_SECRETS,
    )
    .await;
    for path in [
        "/api/v2/namespaces/secrets",
        "/apis/apps/v1/namespaces/secrets",
        "/api/v1/namespaces/secrets/",
    ] {
        assert!(rig.get(path).await.is_err(), "{path}");
    }
    assert_eq!(rig.mock.seen(), Vec::<String>::new());
}

#[tokio::test]
async fn namespace_subresources_are_refused_and_logged() {
    let rig = Rig::new();
    for path in [
        "/api/v1/namespaces/x/finalize",
        "/api/v1/namespaces/x/status",
        "/api/v1/namespaces/finalize/finalize",
        "/api/v1/namespaces/x/finalize/more",
    ] {
        refused_and_logged(&rig, get(path, &[]), path, RULE_SUBRESOURCE).await;
    }
    // A namespace that is called `finalize` or `status` is still only a namespace.
    let rig = Rig::new();
    for path in ["/api/v1/namespaces/finalize", "/api/v1/namespaces/status"] {
        assert_eq!(rig.get(path).await, Ok(StatusCode::OK), "{path}");
    }
    // The same word one level down is a resource the table does not list, not a namespace subresource.
    let rig = Rig::new();
    refused_and_logged(
        &rig,
        get("/api/v1/namespaces/x/pods/finalize", &[]),
        "/api/v1/namespaces/x/pods/finalize",
        RULE_NOT_ALLOWED,
    )
    .await;
}

#[tokio::test]
async fn every_subresource_is_refused_and_logged() {
    let rig = Rig::new();
    for path in [
        "/api/v1/namespaces/app/pods/p/exec",
        "/api/v1/namespaces/app/pods/p/attach",
        "/api/v1/namespaces/app/pods/p/portforward",
        "/api/v1/namespaces/app/pods/p/log",
        "/api/v1/namespaces/app/pods/p/proxy/x",
        "/api/v1/namespaces/app/pods/p/status",
        "/api/v1/nodes/n1/proxy",
        "/api/v1/nodes/n1/status",
        "/apis/apps/v1/namespaces/kube-system/deployments/d/scale",
        "/apis/storage.k8s.io/v1/storageclasses/gp2/status",
        "/apis/config.openshift.io/v1/clusterversions/version/status",
    ] {
        refused_and_logged(&rig, get(path, &[]), path, RULE_SUBRESOURCE).await;
    }
}

#[tokio::test]
async fn a_get_of_pods_exec_with_upgrade_is_refused_and_logged() {
    let rig = Rig::new();
    let path = "/api/v1/namespaces/app/pods/p/exec";
    let query = "?command=id&stdout=true&stdin=true&tty=true";
    for headers in [
        &[("connection", "Upgrade"), ("upgrade", "SPDY/3.1")][..],
        &[("connection", "Upgrade"), ("upgrade", "websocket")][..],
        &[("upgrade", "SPDY/3.1")][..],
        &[("connection", "keep-alive, Upgrade")][..],
    ] {
        let sent = get(&format!("{path}{query}"), headers);
        refused_and_logged(&rig, sent, path, RULE_UPGRADE).await;
    }
    // Without the headers the path is refused on its own.
    refused_and_logged(&rig, get(path, &[]), path, RULE_SUBRESOURCE).await;
    // With the real exec query the query keys are refused first. Either way it does not leave.
    refused_and_logged(&rig, get(&format!("{path}{query}"), &[]), path, RULE_QUERY).await;
}

#[tokio::test]
async fn a_dry_run_post_is_refused_and_logged() {
    let rig = Rig::new();
    let pod = || {
        request(
            Method::POST,
            "/api/v1/namespaces/app/pods?dryRun=All",
            &[],
            b"{}".to_vec(),
        )
    };
    refused_and_logged(&rig, pod(), "/api/v1/namespaces/app/pods", RULE_POST_TARGET).await;
    for path in [
        "/apis/authorization.k8s.io/v1/selfsubjectaccessreviews",
        "/apis/authorization.k8s.io/v1/selfsubjectrulesreviews",
    ] {
        let sent = request(
            Method::POST,
            &format!("{path}?dryRun=All"),
            &[],
            SSAR_BODY.to_vec(),
        );
        refused_and_logged(&rig, sent, path, RULE_POST_QUERY).await;
    }
    let sent = request(
        Method::POST,
        "/apis/authentication.k8s.io/v1/selfsubjectreviews?dryRun=All",
        &[],
        SELF_SUBJECT_REVIEW_BODY.to_vec(),
    );
    refused_and_logged(
        &rig,
        sent,
        "/apis/authentication.k8s.io/v1/selfsubjectreviews",
        RULE_POST_QUERY,
    )
    .await;
    // A dry run is a query key, so a GET with one is refused too.
    refused_and_logged(
        &rig,
        get("/api/v1/nodes?dryRun=All", &[]),
        "/api/v1/nodes",
        RULE_QUERY,
    )
    .await;
}

#[tokio::test]
async fn impersonate_user_on_a_get_is_refused_and_logged() {
    let rig = Rig::new();
    let path = "/api/v1/nodes";
    for name in [
        "Impersonate-User",
        "Impersonate-Group",
        "Impersonate-Uid",
        "Impersonate-Extra-Scopes",
    ] {
        let sent = get(path, &[(name, "system:serviceaccount:app:installer")]);
        refused_and_logged(&rig, sent, path, RULE_IMPERSONATE).await;
        let entry = rig.log().pop().expect("entry");
        assert_eq!(field(&entry, "header"), Some(name.to_lowercase().as_str()));
    }
    // A guard built with an `as:` user still refuses it on a GET, on a list and on the identity review.
    let rig = Rig::impersonating("system:serviceaccount:app:installer");
    let user = [("Impersonate-User", "system:serviceaccount:app:installer")];
    for (sent, path) in [
        (get("/api/v1/nodes", &user), "/api/v1/nodes"),
        (get("/version", &user), "/version"),
        (
            request(
                Method::POST,
                "/apis/authentication.k8s.io/v1/selfsubjectreviews",
                &user,
                SELF_SUBJECT_REVIEW_BODY.to_vec(),
            ),
            "/apis/authentication.k8s.io/v1/selfsubjectreviews",
        ),
    ] {
        refused_and_logged(&rig, sent, path, RULE_IMPERSONATE).await;
        let entry = rig.log().pop().expect("entry");
        assert_eq!(field(&entry, "header"), Some("impersonate-user"), "{path}");
    }
    assert_eq!(rig.mock.seen(), Vec::<String>::new());
}

#[tokio::test]
async fn an_unlisted_resource_is_refused_and_logged() {
    let rig = Rig::new();
    for path in [
        "/api/v1/configmaps",
        "/api/v1/namespaces/app/configmaps",
        "/api/v1/namespaces/app/serviceaccounts",
        "/api/v1/serviceaccounts",
        "/api/v1/persistentvolumes",
        "/api/v1/services",
        "/api/v1/namespaces",
        "/api/v1/nodes/n1",
        "/api/v1/namespaces/app/pods",
        "/apis/rbac.authorization.k8s.io/v1/clusterroles",
        "/apis/rbac.authorization.k8s.io/v1/clusterrolebindings",
        "/apis/apps/v1/statefulsets",
        "/apis/apps/v1/namespaces/default/deployments",
        "/apis/batch/v1/jobs",
        "/apis/admissionregistration.k8s.io/v1/validatingwebhookconfigurations",
        "/apis/apiextensions.k8s.io/v1/customresourcedefinitions",
        "/healthz",
        "/openapi/v2",
        "/metrics",
        "/logs/kube-apiserver.log",
    ] {
        refused_and_logged(&rig, get(path, &[]), path, RULE_NOT_ALLOWED).await;
    }
}

// ---- the request-info parser -------------------------------------------------------------------------------

fn info(uri: &str) -> Result<RequestInfo<'static>, &'static str> {
    let segments: Vec<&'static str> = uri
        .strip_prefix('/')
        .expect("a path")
        .split('/')
        .map(|s| &*Box::leak(s.to_owned().into_boxed_str()))
        .collect();
    request_info(&segments)
}

fn parts(
    uri: &str,
) -> (
    &'static str,
    &'static str,
    Option<&'static str>,
    &'static str,
    Option<&'static str>,
    Option<String>,
) {
    let info = info(uri).expect("a resource path");
    (
        info.group,
        info.version,
        info.namespace,
        info.resource,
        info.name,
        info.subresource,
    )
}

#[test]
fn the_parser_reads_a_path_as_the_api_server_does_except_for_two_deliberate_differences() {
    // The rows follow the cases of `TestGetAPIRequestInfo` in the API server's `requestinfo_test.go`
    // (k8s.io/apiserver, pkg/endpoints/request), for the paths a GET can take. There are two deliberate
    // differences, and neither changes a verdict:
    // - For `/api/v1/namespaces/x` the server sets the namespace to `x`. This parser leaves it `None`.
    // - The server keeps one subresource part. This parser joins the whole tail (`proxy/a/b`).
    // (path, group, version, namespace, resource, name, subresource)
    type Row = (
        &'static str,
        &'static str,
        &'static str,
        Option<&'static str>,
        &'static str,
        Option<&'static str>,
        Option<&'static str>,
    );
    let rows: [Row; 25] = [
        ("/api/v1/nodes", "", "v1", None, "nodes", None, None),
        (
            "/api/v1/nodes/n1",
            "",
            "v1",
            None,
            "nodes",
            Some("n1"),
            None,
        ),
        (
            "/api/v1/nodes/n1/proxy",
            "",
            "v1",
            None,
            "nodes",
            Some("n1"),
            Some("proxy"),
        ),
        (
            "/api/v1/namespaces",
            "",
            "v1",
            None,
            "namespaces",
            None,
            None,
        ),
        (
            "/api/v1/namespaces/x",
            "",
            "v1",
            None,
            "namespaces",
            Some("x"),
            None,
        ),
        (
            "/api/v1/namespaces/x/finalize",
            "",
            "v1",
            None,
            "namespaces",
            Some("x"),
            Some("finalize"),
        ),
        (
            "/api/v1/namespaces/x/status",
            "",
            "v1",
            None,
            "namespaces",
            Some("x"),
            Some("status"),
        ),
        (
            "/api/v1/namespaces/x/pods",
            "",
            "v1",
            Some("x"),
            "pods",
            None,
            None,
        ),
        (
            "/api/v1/namespaces/x/pods/p",
            "",
            "v1",
            Some("x"),
            "pods",
            Some("p"),
            None,
        ),
        (
            "/api/v1/namespaces/x/pods/p/exec",
            "",
            "v1",
            Some("x"),
            "pods",
            Some("p"),
            Some("exec"),
        ),
        (
            "/api/v1/namespaces/x/pods/p/proxy/a/b",
            "",
            "v1",
            Some("x"),
            "pods",
            Some("p"),
            Some("proxy/a/b"),
        ),
        // A namespace called `status` or `finalize`, and one in the resource position.
        (
            "/api/v1/namespaces/finalize",
            "",
            "v1",
            None,
            "namespaces",
            Some("finalize"),
            None,
        ),
        (
            "/api/v1/namespaces/x/namespaces/y",
            "",
            "v1",
            Some("x"),
            "namespaces",
            Some("y"),
            None,
        ),
        (
            "/apis/apps/v1/namespaces/kube-system/deployments",
            "apps",
            "v1",
            Some("kube-system"),
            "deployments",
            None,
            None,
        ),
        (
            "/apis/apps/v1/deployments",
            "apps",
            "v1",
            None,
            "deployments",
            None,
            None,
        ),
        (
            "/apis/storage.k8s.io/v1/storageclasses/gp2",
            "storage.k8s.io",
            "v1",
            None,
            "storageclasses",
            Some("gp2"),
            None,
        ),
        (
            "/apis/config.openshift.io/v1/clusterversions/version/status",
            "config.openshift.io",
            "v1",
            None,
            "clusterversions",
            Some("version"),
            Some("status"),
        ),
        // The version is whatever the path says. The table decides if it is listed.
        ("/api/v9/nodes", "", "v9", None, "nodes", None, None),
        // More rows from the upstream test.
        ("/api/v1/pods", "", "v1", None, "pods", None, None),
        (
            "/api/v1/namespaces/other/pods",
            "",
            "v1",
            Some("other"),
            "pods",
            None,
            None,
        ),
        (
            "/api/v1/namespaces/other/pods/foo/status",
            "",
            "v1",
            Some("other"),
            "pods",
            Some("foo"),
            Some("status"),
        ),
        (
            "/api/v1/namespaces/other/pods/foo/binding",
            "",
            "v1",
            Some("other"),
            "pods",
            Some("foo"),
            Some("binding"),
        ),
        (
            "/apis/apps/v1/namespaces/other/deployments/foo/scale",
            "apps",
            "v1",
            Some("other"),
            "deployments",
            Some("foo"),
            Some("scale"),
        ),
        (
            "/apis/extensions/v1beta1/namespaces/other/ingresses/foo/status",
            "extensions",
            "v1beta1",
            Some("other"),
            "ingresses",
            Some("foo"),
            Some("status"),
        ),
        (
            "/api/v1/nodes/foo/status",
            "",
            "v1",
            None,
            "nodes",
            Some("foo"),
            Some("status"),
        ),
    ];
    for (uri, group, version, namespace, resource, name, sub) in rows {
        assert_eq!(
            parts(uri),
            (
                group,
                version,
                namespace,
                resource,
                name,
                sub.map(str::to_owned)
            ),
            "{uri}"
        );
    }
}

#[test]
fn the_parser_refuses_what_is_not_a_resource_path() {
    for uri in [
        "/version",
        "/healthz",
        "/apis",
        "/apis/apps",
        "/apis/apps/v1",
        "/api",
        "/api/v1",
        // The legacy forms of a watch and a proxy.
        "/api/v1/watch/nodes",
        "/api/v1/watch/namespaces/x/pods",
        "/api/v1/proxy/nodes/n1",
        "/api/v1/proxy/namespaces/other/pods/foo",
        "/api/v1/watch/namespaces/other/pods/foo",
        "/apis/apps/v1/watch/namespaces/kube-system/deployments",
    ] {
        assert_eq!(info(uri), Err(RULE_NOT_ALLOWED), "{uri}");
    }
    // `watch` alone is a resource called `watch`, and the table does not list it.
    assert_eq!(judge_get("/api/v1/watch"), Err(RULE_NOT_ALLOWED));
    for uri in [
        "/api/v1/watch/nodes",
        "/api/v1/watch/namespaces/x/pods",
        "/api/v1/proxy/namespaces/x",
        "/apis/storage.k8s.io/v1/watch/storageclasses",
        "/apis/storage.k8s.io/v1/proxy/storageclasses/gp2",
    ] {
        assert_eq!(judge_get(uri), Err(RULE_NOT_ALLOWED), "{uri}");
    }
}

#[test]
fn the_table_judges_the_parsed_parts_not_the_text() {
    // A namespaced resource under a name that looks like a cluster path, and the other way round.
    for (uri, verdict) in [
        ("/api/v1/namespaces/x/namespaces/y", Err(RULE_NOT_ALLOWED)),
        ("/api/v1/namespaces/x/nodes", Err(RULE_NOT_ALLOWED)),
        ("/api/v1/nodes/namespaces/x", Err(RULE_SUBRESOURCE)),
        (
            "/apis/storage.k8s.io/v1/namespaces/x/storageclasses",
            Err(RULE_NOT_ALLOWED),
        ),
        (
            "/apis/storage.k8s.io/v1/namespaces/x/csinodes",
            Err(RULE_NOT_ALLOWED),
        ),
        ("/apis/apps/v1/namespaces/kube-system/deployments", Ok(())),
        (
            "/apis/apps/v1/namespaces/kube-system/deployments/d",
            Err(RULE_NOT_ALLOWED),
        ),
        ("/api/v1/namespaces/x", Ok(())),
        ("/api/v1/namespaces/x/persistentvolumeclaims", Ok(())),
        ("/api/v1/nodes", Ok(())),
        ("/apis/storage.k8s.io/v1/storageclasses/gp2", Ok(())),
    ] {
        assert_eq!(judge_get(uri), verdict, "{uri}");
    }
}

// ---- Impersonate-* ------------------------------------------------------------------------------------------

const AS_SA: &str = "system:serviceaccount:app:installer";
const SSAR_PATH: &str = "/apis/authorization.k8s.io/v1/selfsubjectaccessreviews";
const SSRR_PATH: &str = "/apis/authorization.k8s.io/v1/selfsubjectrulesreviews";

fn review(path: &str, headers: &[(&str, &str)]) -> Request<Body> {
    request(Method::POST, path, headers, SSAR_BODY.to_vec())
}

#[tokio::test]
async fn impersonate_user_with_the_spec_value_passes_on_the_two_access_reviews() {
    let rig = Rig::impersonating(AS_SA);
    for path in [SSAR_PATH, SSRR_PATH] {
        let sent = review(path, &[("Impersonate-User", AS_SA)]);
        assert_eq!(rig.send(sent).await, Ok(StatusCode::OK), "{path}");
    }
    // A review without the header goes as before.
    assert_eq!(rig.send(review(SSAR_PATH, &[])).await, Ok(StatusCode::OK));
    assert_eq!(
        rig.mock.seen(),
        [
            format!("POST {SSAR_PATH}"),
            format!("POST {SSRR_PATH}"),
            format!("POST {SSAR_PATH}"),
        ]
    );
    // Only the two header-carrying requests reached the server with the user.
    assert_eq!(rig.mock.impersonated(), [AS_SA, AS_SA]);
    let log = rig.log();
    assert_eq!(log.len(), 3);
    assert!(log.iter().all(|a| a.outcome == ActionOutcome::Ok));
}

#[tokio::test]
async fn any_other_impersonate_header_or_value_is_refused_on_the_access_reviews() {
    let rig = Rig::impersonating(AS_SA);
    let canary = "system:serviceaccount:canary-ns:canary-sa";
    let cases: [(&[(&str, &str)], &str); 8] = [
        // A different user, a prefix, an extension, other case, a surrounding space.
        (&[("Impersonate-User", canary)], "impersonate-user"),
        (
            &[("Impersonate-User", "system:serviceaccount:app:install")],
            "impersonate-user",
        ),
        (
            &[("Impersonate-User", "system:serviceaccount:app:installer2")],
            "impersonate-user",
        ),
        (
            &[("Impersonate-User", "System:ServiceAccount:app:installer")],
            "impersonate-user",
        ),
        // The group, uid and extra headers never pass, even beside the right user.
        (
            &[
                ("Impersonate-User", AS_SA),
                ("Impersonate-Group", "system:masters"),
            ],
            "impersonate-group",
        ),
        (
            &[("Impersonate-User", AS_SA), ("Impersonate-Uid", "0")],
            "impersonate-uid",
        ),
        (
            &[
                ("Impersonate-User", AS_SA),
                ("Impersonate-Extra-Scopes", "x"),
            ],
            "impersonate-extra-scopes",
        ),
        // Group without a user.
        (
            &[("Impersonate-Group", "system:masters")],
            "impersonate-group",
        ),
    ];
    for (headers, name) in cases {
        for path in [SSAR_PATH, SSRR_PATH] {
            let before = rig.log().len();
            assert_eq!(
                rig.send(review(path, headers)).await,
                Err(RULE_IMPERSONATE),
                "{headers:?}"
            );
            let log = rig.log();
            assert_eq!(log.len(), before + 1);
            let entry = &log[before];
            assert_eq!(entry.outcome, ActionOutcome::Denied);
            assert_eq!(field(entry, "header"), Some(name), "{headers:?}");
        }
    }
    // Two values for the header, even if one is right.
    let mut two = review(SSAR_PATH, &[("Impersonate-User", AS_SA)]);
    two.headers_mut()
        .append("impersonate-user", canary.parse().expect("value"));
    assert_eq!(rig.send(two).await, Err(RULE_IMPERSONATE));
    assert_eq!(rig.mock.seen(), Vec::<String>::new());
    // The log names the header and never holds a value.
    let all = serde_json::to_string(&rig.log()).expect("json");
    assert!(!all.contains("canary"), "{all}");
    assert!(!all.contains("installer"), "{all}");
}

#[tokio::test]
async fn impersonation_is_refused_when_the_guard_has_no_user() {
    // `guarded_service` has no `as:` value, so even a review POST cannot impersonate.
    let rig = Rig::new();
    for path in [SSAR_PATH, SSRR_PATH] {
        let sent = review(path, &[("Impersonate-User", AS_SA)]);
        assert_eq!(rig.send(sent).await, Err(RULE_IMPERSONATE), "{path}");
    }
    assert_eq!(rig.mock.seen(), Vec::<String>::new());
}

#[tokio::test]
async fn the_header_value_rule_does_not_loosen_the_other_rules_on_a_review() {
    let rig = Rig::impersonating(AS_SA);
    let user = [("Impersonate-User", AS_SA)];
    // A query string, another header, a streamed body and another target are still refused.
    let with_query = request(
        Method::POST,
        &format!("{SSAR_PATH}?dryRun=All"),
        &user,
        SSAR_BODY.to_vec(),
    );
    assert_eq!(rig.send(with_query).await, Err(RULE_POST_QUERY));
    let other_header = review(
        SSAR_PATH,
        &[("Impersonate-User", AS_SA), ("X-Remote-User", "admin")],
    );
    assert_eq!(rig.send(other_header).await, Err(RULE_HEADER));
    let other_target = request(
        Method::POST,
        "/api/v1/namespaces/app/pods",
        &user,
        b"{}".to_vec(),
    );
    assert_eq!(rig.send(other_target).await, Err(RULE_IMPERSONATE));
    let secrets = request(
        Method::POST,
        "/api/v1/namespaces/app/secrets",
        &user,
        b"{}".to_vec(),
    );
    assert_eq!(rig.send(secrets).await, Err(RULE_IMPERSONATE));
    assert_eq!(rig.mock.seen(), Vec::<String>::new());
}

#[test]
fn an_as_value_is_checked_once() {
    let long = "u".repeat(253);
    for good in [
        AS_SA,
        "system:serviceaccount:default:default",
        "system:serviceaccount:kube-system:a.b-c",
        "jane@example.com",
        "kube:admin",
        "CN=jane doe",
        "j",
        long.as_str(),
    ] {
        assert_eq!(
            ImpersonateAs::new(good).as_ref().map(ImpersonateAs::as_str),
            Ok(good),
            "{good}"
        );
    }
    let too_long = "u".repeat(254);
    let long_label = format!("system:serviceaccount:{}:sa", "n".repeat(64));
    let ok_label = format!("system:serviceaccount:{}:sa", "n".repeat(63));
    assert!(ImpersonateAs::new(&ok_label).is_ok());
    let bad: [(&str, ImpersonateError); 26] = [
        ("", ImpersonateError::Empty),
        (&too_long, ImpersonateError::TooLong),
        ("a\nb", ImpersonateError::BadCharacter),
        (
            "a\r\nImpersonate-Group: system:masters",
            ImpersonateError::BadCharacter,
        ),
        ("a\0b", ImpersonateError::BadCharacter),
        ("a\tb", ImpersonateError::BadCharacter),
        ("a\u{7f}b", ImpersonateError::BadCharacter),
        ("a\u{85}b", ImpersonateError::BadCharacter),
        // Only the bytes 0x20 to 0x7E: a non-ASCII letter, a bidirectional override and a zero-width
        // space are refused, so the user a report shows cannot be spoofed.
        ("j\u{f6}s\u{e9}", ImpersonateError::BadCharacter),
        ("\u{202E}x", ImpersonateError::BadCharacter),
        ("a\u{200B}b", ImpersonateError::BadCharacter),
        ("\u{ff1a}", ImpersonateError::BadCharacter),
        (" jane", ImpersonateError::BadCharacter),
        ("jane ", ImpersonateError::BadCharacter),
        ("jane\t", ImpersonateError::BadCharacter),
        (
            "system:serviceaccount:",
            ImpersonateError::BadServiceAccount,
        ),
        (
            "system:serviceaccount:app",
            ImpersonateError::BadServiceAccount,
        ),
        (
            "system:serviceaccount:app:",
            ImpersonateError::BadServiceAccount,
        ),
        (
            "system:serviceaccount::sa",
            ImpersonateError::BadServiceAccount,
        ),
        (
            "system:serviceaccount:App:sa",
            ImpersonateError::BadServiceAccount,
        ),
        (
            "system:serviceaccount:a.b:sa",
            ImpersonateError::BadServiceAccount,
        ),
        (
            "system:serviceaccount:app:sa:extra",
            ImpersonateError::BadServiceAccount,
        ),
        (
            "system:serviceaccount:app:Sa",
            ImpersonateError::BadServiceAccount,
        ),
        (
            "system:serviceaccount:app:-sa",
            ImpersonateError::BadServiceAccount,
        ),
        (
            "system:serviceaccount:ap_p:sa",
            ImpersonateError::BadServiceAccount,
        ),
        (&long_label, ImpersonateError::BadServiceAccount),
    ];
    for (value, error) in bad {
        assert_eq!(ImpersonateAs::new(value), Err(error), "{value:?}");
    }
    // The error text has a fix hint and holds no part of the value.
    let shown = ImpersonateAs::new("system:serviceaccount:canary")
        .expect_err("bad")
        .to_string();
    assert!(
        shown.contains("Fix:") && !shown.contains("canary"),
        "{shown}"
    );
    let debug = format!("{:?}", ImpersonateAs::new("canary-user").expect("ok"));
    assert!(!debug.contains("canary"), "{debug}");
}

// ---- decoded query values ----------------------------------------------------------------------------------

#[test]
fn decoded_selector_and_token_values_are_checked() {
    let nodes = "/api/v1/nodes";
    for query in [
        "labelSelector=app%3Dweb",
        "labelSelector=app%3Dweb%2Ctier%21%3Ddb",
        "labelSelector=env+in+%28a%2Cb%29",
        "labelSelector=%21canary",
        "labelSelector=example.com%2Fkey%3Dv1",
        "labelSelector=",
        "fieldSelector=metadata.name%3Dn1",
        "fieldSelector=spec.nodeName%3Dip-10-0-0-1.ec2.internal",
        "fieldSelector=involvedObject.name%3Da%3Ab",
        "fieldSelector=",
        "continue=eyJ2IjoibWV0YS5rOHMuaW8vdjEifQ",
        "continue=ab-_cd%3D%3D",
        "continue=ab%2Bcd%2F",
        "continue=",
        "limit=500&continue=abc&labelSelector=a%3Db&fieldSelector=metadata.name%3Dn",
    ] {
        assert_eq!(judge_get(&format!("{nodes}?{query}")), Ok(()), "{query}");
    }
    for query in [
        // A decoded `&`, `=` chain, `;`, quote, brace, NUL, newline, tab, backslash and `%`.
        "labelSelector=a%26limit%3D1",
        "labelSelector=a%3Bb",
        "labelSelector=a%22b",
        "labelSelector=%7Ba%7D",
        "labelSelector=a%00b",
        "labelSelector=a%0Ab",
        "labelSelector=a%09b",
        "labelSelector=a%5Cb",
        "labelSelector=a%25b",
        "labelSelector=a%2573",
        "labelSelector=a%ffb",
        "labelSelector=%C3%A9",
        "fieldSelector=metadata.name%3Dn1%26fieldSelector%3Dx",
        "fieldSelector=metadata.name%3Dn1%0A",
        "fieldSelector=metadata.name%3Dn1%00",
        "fieldSelector=metadata.name%3D%22n1%22",
        "fieldSelector=metadata.name%3Dn+1",
        "fieldSelector=metadata.name%3D%25",
        "fieldSelector=metadata.name%3Dn1%3B",
        // A term without a key or an operator, or with a lone `!`.
        "fieldSelector=metadata.name",
        "fieldSelector=%3Dn1",
        "fieldSelector=a%21b%3Dc",
        "fieldSelector=a%3Db%2C%2Cc%3Dd",
        "fieldSelector=%2C",
        "fieldSelector=a%3Db%2C",
        "continue=a%00",
        "continue=a%25",
        "continue=a+b",
        "continue=a%20b",
        "continue=a%7Cb",
        "continue=a%26b",
        "continue=a%22",
        "continue=a%5C",
        "continue=%C3%A9",
        // A key twice, in any pair.
        "limit=5&limit=6",
        "labelSelector=a&labelSelector=b",
        "continue=a&continue=b",
        "fieldSelector=a%3Db&fieldSelector=a%3Db",
    ] {
        assert_eq!(
            judge_get(&format!("{nodes}?{query}")),
            Err(RULE_QUERY),
            "{query}"
        );
    }
    // A value over the size limit, decoded.
    let long = "a".repeat(4097);
    for key in ["labelSelector", "continue"] {
        assert_eq!(judge_get(&format!("{nodes}?{key}={long}")), Err(RULE_QUERY));
    }
    let long = "a".repeat(4096);
    assert_eq!(judge_get(&format!("{nodes}?continue={long}")), Ok(()));
}

#[test]
fn the_selector_a_list_needs_is_still_checked_after_the_value_rules() {
    // The terms of a required field selector still count after decoding, and a bad extra term refuses
    // the whole selector instead of hiding behind the good one.
    let pods = "/api/v1/pods";
    assert_eq!(
        judge_get(&format!("{pods}?fieldSelector=status.phase%21%3DFailed")),
        Ok(())
    );
    assert_eq!(
        judge_get(&format!(
            "{pods}?fieldSelector=status.phase%21%3DFailed%2Cx"
        )),
        Err(RULE_QUERY)
    );
    assert_eq!(
        judge_get(&format!("{pods}?fieldSelector=status.phase%21%3DFailed%0A")),
        Err(RULE_QUERY)
    );
}

// ---- the citation of ALLOWED by the checks -------------------------------------------------------------------

/// Check ids that `ALLOWED` cites and that no `CheckInfo` exists for yet. A check ticket removes its id
/// when it registers its info in `crate::registry::infos`; the test fails if an id is in both places or
/// in neither. M1-115 requires this list to be empty.
const NOT_BUILT_YET: &[&str] = &[
    "k8s.admission",
    "k8s.nodes",
    "k8s.rbac",
    "k8s.storageclass",
    "k8s.version",
];

/// The ids `ALLOWED` cites that no info in `infos` has.
fn uncited<'a>(
    infos: impl IntoIterator<Item = &'a rdy_engine::check::CheckInfo>,
) -> BTreeSet<&'static str> {
    let built: BTreeSet<&str> = infos.into_iter().map(|info| info.id).collect();
    ALLOWED
        .iter()
        .flat_map(|entry| entry.checks.iter().copied())
        .filter(|id| !built.contains(id))
        .collect()
}

#[test]
fn every_allowed_entry_is_cited_by_a_check_that_exists_or_is_still_to_be_built() {
    let registered = crate::registry::infos();
    let missing = uncited(registered.iter().copied());
    let pending: BTreeSet<&str> = NOT_BUILT_YET.iter().copied().collect();
    // Every id without a registered CheckInfo is on the pending list, and the list holds nothing else.
    // An id in both places fails (it is pending but has an info); an id in neither fails (it is missing).
    assert_eq!(
        missing, pending,
        "ALLOWED cites a check that is not registered in crate::registry::infos and not on NOT_BUILT_YET, \
         or NOT_BUILT_YET names a check that is registered; when a k8s check lands, register its info and \
         remove its id from NOT_BUILT_YET"
    );
    // The registered infos are k8s checks.
    assert!(registered.iter().all(|info| info.family == "k8s"));
}

#[test]
fn the_citation_check_bites() {
    use rdy_engine::check::{CheckInfo, CheckMeta, OsSupport, Support};
    // A synthetic info per id: with all of them nothing is missing, and with one gone that id is.
    let info = |id: &'static str| {
        &*Box::leak(Box::new(CheckInfo {
            id,
            family: "k8s",
            summary: "synthetic",
            meta: CheckMeta {
                title: "Synthetic",
                remediation: "Nothing to fix.",
            },
            needs: &[],
            wants: &[],
            default_timeout: None,
            os: OsSupport {
                linux: Support::Full,
                macos: Support::Full,
                windows: Support::Full,
            },
            reads: &[],
            statfs: &[],
            env: &[],
            commands: &[],
            peers: &[],
        }))
    };
    let all: Vec<&CheckInfo> = NOT_BUILT_YET.iter().map(|id| info(id)).collect();
    assert!(uncited(all.iter().copied()).is_empty());
    let without: Vec<&CheckInfo> = all
        .iter()
        .copied()
        .filter(|info| info.id != "k8s.nodes")
        .collect();
    assert_eq!(uncited(without), BTreeSet::from(["k8s.nodes"]));
    // An id that is both registered and pending leaves the missing set short of the pending list, so the
    // test above fails on it.
    let both = [info("k8s.version")];
    let missing = uncited(all.iter().copied().chain(both));
    assert!(missing.is_empty());
    let pending: BTreeSet<&str> = NOT_BUILT_YET.iter().copied().collect();
    assert_ne!(missing, pending);
    // An info for a check that ALLOWED does not cite is not an error.
    let extra = [info("k8s.access")];
    assert_eq!(uncited(extra).len(), NOT_BUILT_YET.len());
}

#[test]
fn every_cited_check_id_is_a_check_in_the_catalog() {
    // The ids are not typos: each one is a heading of 03-check-catalog.md.
    // Embedded, not read at run time: a check crate may not read files (M1-044).
    let catalog = include_str!("../../../../../../docs/plan/03-check-catalog.md");
    let ids: BTreeSet<&str> = ALLOWED
        .iter()
        .flat_map(|entry| entry.checks.iter().copied())
        .collect();
    assert!(!ids.is_empty());
    for id in ids {
        let heading = format!("### {id} ");
        assert!(
            catalog.lines().any(|line| line.starts_with(&heading)),
            "{id} is not a heading in 03-check-catalog.md"
        );
    }
}
