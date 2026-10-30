//! Tests of `k8s.access`: the fixtures under `tests/fixtures/checks/k8s.access/`, the connection facts of
//! synthetic kubeconfigs (token, client certificate, plugin, `proxy-url`, environment proxy, Rancher path
//! prefix, no credentials) and the failures of the connection attempt.
//!
//! A case with an `api/` directory runs the real check code over the kube mock harness (M1-105): the guard
//! sits in front of the mock, and the harness audits every recorded request against `ALLOWED` when it is
//! dropped (INV-14). A case that fails before any request builds the failure from the same mapping
//! production uses (`from_kube_error`), so the words are the real ones.

use std::io::ErrorKind;
use std::sync::Arc;
use std::time::Duration;

use rdy_engine::check::{Check, CheckError, CheckOutcome, Finding, Level, Need, Os};
use rdy_engine::probe::Probe;
use rdy_engine::testing::{Replay, TestRun, assert_within_manifest};
use rdy_spec::check::CheckParams;
use rdy_spec::spec::CheckSpec;
use serde_json::{Value, json};

use super::*;
use crate::client::guard::SELF_SUBJECT_REVIEW_BODY;
use crate::client::mock::Harness;
use crate::client::testkit::{
    facts, kubeconfig, network_error, network_error_kind, test_ca_pem, timeout_error,
};
use crate::client::{Credential, Env, ProxyRule};

/// 2026-10-30 00:00:00 UTC.
const NOW: i64 = 1_793_318_400;
const SERVER: &str = "https://k8s.acme.example:6443";

/// A JWT whose `exp` is `NOW + 3 days`, and one that ended 100 s before `NOW`.
const JWT_IN_3_DAYS: &str = "eyJhbGciOiJSUzI1NiJ9.eyJleHAiOjE3OTM1Nzc2MDB9.c2ln";
const JWT_EXPIRED: &str = "eyJhbGciOiJSUzI1NiJ9.eyJleHAiOjE3OTMzMTgzMDB9.c2ln";
/// A JWT whose `exp` is `NOW + 7 days` exactly, and one second short of it.
const JWT_IN_7_DAYS: &str = "eyJhbGciOiJSUzI1NiJ9.eyJleHAiOjE3OTM5MjMyMDB9.c2ln";
const JWT_IN_7_DAYS_LESS_1S: &str = "eyJhbGciOiJSUzI1NiJ9.eyJleHAiOjE3OTM5MjMxOTl9.c2ln";

fn env() -> Env {
    Env::empty().with_now(NOW)
}

// ---- building the check -------------------------------------------------------------------------------------

fn params(extra: &Value) -> K8sAccess {
    let mut entry = json!({"id": "k8s.access"});
    for (key, value) in extra.as_object().expect("an object") {
        entry[key] = value.clone();
    }
    let entry: CheckSpec = serde_json::from_value(entry).expect("a check entry");
    match entry.decode_params() {
        CheckParams::K8sAccess(params) => params,
        other => panic!("not k8s.access: {other:?}"),
    }
}

/// The attempt of a test run: the facts, the outcome and, when there is a fixture, the mock behind the
/// client.
struct TestDial {
    facts: Option<ConnectionFacts>,
    outcome: DialOutcome,
    harness: Option<Harness>,
}

impl Dial for TestDial {
    fn facts(&self) -> Option<&ConnectionFacts> {
        self.facts.as_ref()
    }

    fn outcome(&self) -> &DialOutcome {
        &self.outcome
    }

    fn read_only(&self, probe: &Probe) -> Option<ReadOnlyClient> {
        match (&self.outcome, &self.harness) {
            (DialOutcome::Reached { .. }, Some(harness)) => Some(harness.client(probe)),
            _ => None,
        }
    }
}

/// What one run produced.
struct Ran {
    outcome: CheckOutcome,
    dial: Arc<TestDial>,
    run: TestRun,
}

impl Ran {
    fn finding(&self) -> &Finding {
        self.outcome.as_ref().expect("a finding")
    }

    fn observed(&self, key: &str) -> &Value {
        &self.finding().observed[key]
    }

    fn mock(&self) -> &crate::client::mock::Mock {
        self.dial.harness.as_ref().expect("a harness").mock()
    }

    fn notes(&self) -> String {
        self.finding().notes.join("\n")
    }

    fn fix(&self) -> &str {
        self.finding().fix.as_deref().expect("a fix")
    }

    /// Every text of the finding in one string.
    fn text(&self) -> String {
        let f = self.finding();
        format!(
            "{}\n{}\n{}\n{}\n{}",
            f.message,
            f.fix.as_deref().unwrap_or(""),
            f.notes.join("\n"),
            f.observed,
            f.expected
        )
    }
}

fn runtime() -> tokio::runtime::Runtime {
    tokio::runtime::Builder::new_current_thread()
        .enable_time()
        .build()
        .expect("a runtime")
}

/// Runs the check on `dial`. Every run is also held to what the check declares and to the fix text lists.
fn run_dial(dial: TestDial, run: TestRun, spec: &Value) -> Ran {
    let dial = Arc::new(dial);
    let check = AccessCheck::new(&params(spec), dial.clone()).expect("a check");
    let ctx = run.context_for(&INFO, "k8s.access", Os::Linux, []);
    let outcome = runtime().block_on(check.run(&ctx));
    let ran = Ran { outcome, dial, run };
    assert_within_manifest("k8s.access", &INFO, &ran.run.action_log());
    if let Ok(finding) = &ran.outcome {
        if let Some(fix) = &finding.fix
            && let Err(error) = rdy_engine::fixtext::check(fix)
        {
            panic!("the fix text names something off the lists: {error}\n{fix}");
        }
        for text in finding
            .message
            .lines()
            .chain(finding.notes.iter().map(String::as_str))
        {
            assert!(!text.contains('\u{1b}'), "{text:?}");
        }
    }
    ran
}

/// Runs the check over the fixture `case` with the attempt made over the mock, as `connect` makes it.
/// `latency` replaces the measured time, which would be a few microseconds.
fn run_case(case: &str, facts: ConnectionFacts, latency: Duration, spec: &Value) -> Ran {
    let harness = Harness::load(&format!("checks/k8s.access/{case}")).expect("the fixture loads");
    // As production builds the client: the requests record the proxy the facts name.
    let harness = match facts.proxy().proxy() {
        Some(origin) => harness.via_proxy(origin),
        None => harness,
    };
    let run = harness.run().clone();
    let attempt = runtime().block_on(harness.attempt(&facts));
    let outcome = match attempt {
        Ok((version, _)) => DialOutcome::Reached { version, latency },
        Err(error) => DialOutcome::Failed(error),
    };
    let dial = TestDial {
        facts: Some(facts),
        outcome,
        harness: Some(harness),
    };
    run_dial(dial, run, spec)
}

/// Runs the check on an attempt that never reached the cluster.
fn run_outcome(facts: Option<ConnectionFacts>, outcome: DialOutcome, spec: &Value) -> Ran {
    run_dial(
        TestDial {
            facts,
            outcome,
            harness: None,
        },
        TestRun::new(Replay::new()),
        spec,
    )
}

fn good(case: &str, facts: ConnectionFacts) -> Ran {
    run_case(case, facts, Duration::from_millis(120), &json!({}))
}

// ---- synthetic kubeconfigs ----------------------------------------------------------------------------------

const TOKEN_USER: &str = "\n    token: opaque-token-1\n";
const NO_USER: &str = " {}\n";
const AWS_USER: &str = "\n    exec:\n      apiVersion: client.authentication.k8s.io/v1\n      command: /usr/local/bin/aws\n      args: [\"eks\", \"get-token\", \"--cluster-name\", \"acme-prod\"]\n";
const GKE_USER: &str = "\n    exec:\n      apiVersion: client.authentication.k8s.io/v1\n      command: gke-gcloud-auth-plugin\n";
const AKS_USER: &str = "\n    exec:\n      apiVersion: client.authentication.k8s.io/v1\n      command: kubelogin\n      args: [\"get-token\", \"--login\", \"azurecli\"]\n";

fn token_facts() -> ConnectionFacts {
    facts(
        &kubeconfig("acme-prod", SERVER, "", TOKEN_USER),
        &[],
        &env(),
    )
}

fn eks_facts() -> ConnectionFacts {
    facts(
        &kubeconfig(
            "arn:aws:eks:us-east-1:111122223333:cluster/acme-prod",
            "https://ABCDEF0123.gr7.us-east-1.eks.amazonaws.com",
            "",
            AWS_USER,
        ),
        &[],
        &env(),
    )
}

fn user_facts(user: &str) -> ConnectionFacts {
    facts(&kubeconfig("acme-prod", SERVER, "", user), &[], &env())
}

fn has(text: &str, part: &str) -> bool {
    text.contains(part)
}

// ---- a good cluster -----------------------------------------------------------------------------------------

#[test]
fn a_good_cluster_passes_and_shows_who_rdy_is() {
    let ran = good("good", token_facts());
    let f = ran.finding();
    assert_eq!(f.level, Level::Pass);
    assert_eq!(
        f.message,
        "Connected to https://k8s.acme.example:6443 as jane@acme.example, Kubernetes v1.29.4-eks-abc123, 120 ms."
    );
    assert!(f.fix.is_none());
    assert!(f.partial.is_none());
    assert_eq!(f.observed["identity"]["username"], "jane@acme.example");
    assert_eq!(
        f.observed["identity"]["groups"],
        json!(["acme-platform-admins", "system:authenticated"])
    );
    assert_eq!(f.observed["identity"]["verified"], true);
    assert_eq!(f.observed["version"], "v1.29.4-eks-abc123");
    assert_eq!(f.observed["latency_ms"], 120);
    assert_eq!(f.observed["context"], "acme-prod");
    assert_eq!(f.observed["source"], "--kubeconfig");
    assert_eq!(f.observed["proxy"]["rule"], "none");
    assert_eq!(f.observed["tls_verification"], "bundled_roots");
    assert_eq!(f.observed["discovery"]["core_versions"], json!(["v1"]));
    assert_eq!(f.observed["discovery"]["group_count"], 3);
    let notes = ran.notes();
    assert!(
        has(
            &notes,
            "Identity: jane@acme.example; groups: acme-platform-admins, system:authenticated"
        ),
        "{notes}"
    );
    assert!(
        has(&notes, "Discovery: /api serves v1; /apis lists 3 groups."),
        "{notes}"
    );
    assert!(
        has(
            &notes,
            "Route to the API server: direct, no proxy configured."
        ),
        "{notes}"
    );
    assert!(
        has(&notes, "Kubernetes v1.29.4-eks-abc123 on linux/amd64"),
        "{notes}"
    );
    ran.dial
        .harness
        .as_ref()
        .expect("harness")
        .audit()
        .expect("INV-14");
}

#[test]
fn the_identity_review_is_the_raw_route_with_the_fixed_body() {
    let ran = good("good", token_facts());
    let seen = ran.mock().seen();
    let posts: Vec<_> = seen
        .iter()
        .filter(|request| request.method == http::Method::POST)
        .collect();
    assert_eq!(posts.len(), 1, "{seen:?}");
    assert_eq!(
        posts[0].uri.path(),
        "/apis/authentication.k8s.io/v1/selfsubjectreviews"
    );
    assert_eq!(posts[0].body, SELF_SUBJECT_REVIEW_BODY);
    // A typed value would carry a `metadata` member.
    assert!(!String::from_utf8_lossy(&posts[0].body).contains("metadata"));
    // Discovery is named exactly, and nothing else is read.
    let lines: Vec<String> = seen.iter().map(crate::client::mock::Seen::line).collect();
    assert_eq!(
        lines,
        [
            "GET /version",
            "POST /apis/authentication.k8s.io/v1/selfsubjectreviews",
            "GET /api",
            "GET /apis",
        ]
    );
}

#[test]
fn every_request_is_logged_under_the_check_and_the_version_under_the_run() {
    let ran = good("good", token_facts());
    let log = ran.run.action_log();
    let kube: Vec<(Option<&str>, String)> = log
        .actions
        .iter()
        .filter(|entry| entry.kind == rdy_spec::result::ActionKind::Kube)
        .map(|entry| {
            (
                entry.check.as_deref(),
                format!(
                    "{} {}",
                    entry.fields["method"].as_str().unwrap_or(""),
                    entry.fields["path"].as_str().unwrap_or("")
                ),
            )
        })
        .collect();
    assert_eq!(
        kube,
        [
            (None, "GET /version".to_owned()),
            (
                Some("k8s.access"),
                "POST /apis/authentication.k8s.io/v1/selfsubjectreviews".to_owned()
            ),
            (Some("k8s.access"), "GET /api".to_owned()),
            (Some("k8s.access"), "GET /apis".to_owned()),
        ]
    );
}

#[test]
fn a_user_with_many_groups_lists_ten_and_counts_the_rest() {
    let ran = good("many-groups", token_facts());
    let notes = ran.notes();
    assert!(
        has(&notes, "acme-dir-group-000, acme-dir-group-001"),
        "{notes}"
    );
    assert!(has(&notes, "acme-dir-group-009 and 111 more"), "{notes}");
    assert!(!has(&notes, "acme-dir-group-010"), "{notes}");
    assert_eq!(ran.observed("identity")["group_count"], 121);
    assert!(
        ran.observed("identity")["groups"]
            .as_array()
            .expect("a list")
            .len()
            <= 20
    );
}

#[test]
fn names_from_the_server_cannot_move_the_cursor() {
    let ran = good("hostile-names", token_facts());
    let text = ran.text();
    assert!(!text.contains('\u{1b}'), "{text:?}");
    assert!(!text.contains('\u{202e}'), "{text:?}");
    assert!(
        has(&ran.finding().message, "jane\\x1b[2J@acme.example"),
        "{}",
        ran.finding().message
    );
}

// ---- 401, 403 and the identity ------------------------------------------------------------------------------

#[test]
fn a_401_on_version_blocks_with_the_login_fix() {
    let ran = good("unauthorized", token_facts());
    let f = ran.finding();
    assert_eq!(f.level, Level::Fail);
    assert_eq!(
        f.message,
        "the cluster at https://k8s.acme.example:6443 did not accept the credentials (401)"
    );
    assert_eq!(f.observed["state"], "unauthorized");
    assert!(
        has(
            ran.fix(),
            "Log in again the way you did when you made this kubeconfig"
        ),
        "{}",
        ran.fix()
    );
}

#[test]
fn a_401_on_eks_after_a_good_token_says_the_principal_is_not_mapped() {
    let ran = good("unauthorized", eks_facts());
    let fix = ran.fix();
    assert!(
        has(
            fix,
            "`aws eks update-kubeconfig --name acme-prod --region us-east-1`"
        ),
        "{fix}"
    );
    assert!(has(fix, "`aws sso login --profile <profile>`"), "{fix}");
    assert!(
        has(fix, "the IAM principal is not mapped to the cluster"),
        "{fix}"
    );
    assert!(
        has(
            fix,
            "`aws eks create-access-entry --cluster-name acme-prod --principal-arn <principal-arn>`"
        ),
        "{fix}"
    );
    assert!(
        has(fix, "Only the cluster creator is admin by default."),
        "{fix}"
    );
    assert!(
        has(&ran.notes(), "runs `aws` to get credentials"),
        "{}",
        ran.notes()
    );
}

#[test]
fn a_401_names_the_right_login_per_provider() {
    let gke = facts(
        &kubeconfig(
            "gke_acme-proj_europe-west1_acme-prod",
            "https://203.0.113.9",
            "",
            GKE_USER,
        ),
        &[],
        &env(),
    );
    let fix = good("unauthorized", gke).fix().to_owned();
    assert!(
        has(
            &fix,
            "`gcloud container clusters get-credentials acme-prod --location europe-west1 --project acme-proj`"
        ),
        "{fix}"
    );
    assert!(has(&fix, "`gke-gcloud-auth-plugin`"), "{fix}");
    let aks = facts(
        &kubeconfig(
            "acme-aks",
            "https://acme-aks-dns-1a2b3c.hcp.westeurope.azmk8s.io:443",
            "",
            AKS_USER,
        ),
        &[],
        &env(),
    );
    let fix = good("unauthorized", aks).fix().to_owned();
    assert!(
        has(
            &fix,
            "`az aks get-credentials -g <resource-group> -n acme-aks`"
        ),
        "{fix}"
    );
    assert!(
        has(&fix, "`kubelogin convert-kubeconfig -l azurecli`"),
        "{fix}"
    );
    let oc = facts(
        &kubeconfig(
            "acme-ns/api-ocp-acme-example:6443/jane",
            "https://api.ocp.acme.example:6443",
            "",
            TOKEN_USER,
        ),
        &[],
        &env(),
    );
    let fix = good("unauthorized", oc).fix().to_owned();
    assert!(
        has(&fix, "`oc login https://api.ocp.acme.example:6443`"),
        "{fix}"
    );
}

#[test]
fn a_403_on_the_identity_review_blocks_and_points_at_system_basic_user() {
    let ran = good("forbidden-review", token_facts());
    let f = ran.finding();
    assert_eq!(f.level, Level::Fail);
    assert_eq!(
        f.message,
        "The API server refused to say who rdy is (403 on the identity review)."
    );
    assert!(has(ran.fix(), "system:basic-user"), "{}", ran.fix());
    assert!(
        has(
            ran.fix(),
            "`kubectl get clusterrolebinding system:basic-user -o yaml`"
        ),
        "{}",
        ran.fix()
    );
    // Discovery is not asked after a refusal.
    assert!(
        ran.mock()
            .seen()
            .iter()
            .all(|request| request.uri.path() != "/api"),
        "{:?}",
        ran.mock().seen()
    );
}

#[test]
fn a_403_with_no_credentials_in_the_kubeconfig_says_so() {
    let ran = good("forbidden-review", user_facts(NO_USER));
    assert_eq!(
        ran.finding().message,
        "The kubeconfig has no credentials, so the server treats rdy as anonymous and refuses it (403)."
    );
    assert!(
        has(ran.fix(), "The kubeconfig user has no credentials"),
        "{}",
        ran.fix()
    );
}

#[test]
fn an_anonymous_kubeconfig_warns() {
    let ran = good("anonymous", user_facts(NO_USER));
    let f = ran.finding();
    assert_eq!(f.level, Level::Warn);
    assert_eq!(f.message, "rdy is connected as system:anonymous.");
    assert!(
        has(
            ran.fix(),
            "The kubeconfig user has no token, client certificate or credential plugin."
        ),
        "{}",
        ran.fix()
    );
    assert!(
        has(&ran.notes(), "The kubeconfig user has no credentials."),
        "{}",
        ran.notes()
    );
    assert_eq!(f.observed["credentials"], json!([]));
}

#[test]
fn anonymous_with_a_token_in_the_kubeconfig_says_the_token_was_not_accepted() {
    let ran = good("anonymous", token_facts());
    assert_eq!(ran.finding().level, Level::Warn);
    // The server answers 401 for a credential it rejects and never falls back to anonymous, so anonymous
    // with a token in the file means no credential was sent.
    assert!(has(ran.fix(), "saw no credentials"), "{}", ran.fix());
    assert!(has(ran.fix(), "none were sent"), "{}", ran.fix());
    assert!(!has(ran.fix(), "fell back"), "{}", ran.fix());
}

#[test]
fn a_server_without_selfsubjectreview_is_a_partial_pass_with_the_user_not_verified() {
    let ran = good("old-server", token_facts());
    let f = ran.finding();
    assert_eq!(f.level, Level::Pass);
    assert!(
        has(&f.message, "Who rdy is could not be shown."),
        "{}",
        f.message
    );
    let partial = f.partial.as_ref().expect("partial");
    // The fixture is a 1.27 server, which serves the review only as v1beta1.
    assert!(has(&partial.note, "1.27"), "{}", partial.note);
    assert!(has(&partial.note, "v1beta1"), "{}", partial.note);
    assert_eq!(f.observed["identity"], json!({"verified": false}));
    assert!(
        has(&ran.notes(), "Identity: not verified."),
        "{}",
        ran.notes()
    );
    // One cheap access review, and nothing else was posted.
    let posts: Vec<String> = ran
        .mock()
        .seen()
        .iter()
        .filter(|request| request.method == http::Method::POST)
        .map(|request| request.uri.path().to_owned())
        .collect();
    assert_eq!(
        posts,
        [
            "/apis/authentication.k8s.io/v1/selfsubjectreviews",
            "/apis/authorization.k8s.io/v1/selfsubjectaccessreviews",
        ]
    );
}

#[test]
fn a_refused_discovery_is_a_note_not_a_failure() {
    let ran = good("discovery-denied", token_facts());
    assert_eq!(ran.finding().level, Level::Pass);
    let notes = ran.notes();
    assert!(
        has(&notes, "Discovery: GET /api was refused (403)."),
        "{notes}"
    );
    assert!(
        has(&notes, "Discovery: GET /apis was refused (403)."),
        "{notes}"
    );
    assert_eq!(ran.observed("discovery")["core_versions"], Value::Null);
}

#[test]
fn an_identity_review_that_errors_or_says_nothing_warns() {
    let ran = good("review-error", token_facts());
    assert_eq!(ran.finding().level, Level::Warn);
    assert!(
        has(&ran.finding().message, "answered with status 500"),
        "{}",
        ran.finding().message
    );
    let ran = good("review-silent", token_facts());
    assert_eq!(ran.finding().level, Level::Warn);
    assert!(
        has(&ran.finding().message, "answered without a user"),
        "{}",
        ran.finding().message
    );
}

// ---- credentials that end -----------------------------------------------------------------------------------

#[test]
fn a_token_that_ends_inside_seven_days_warns_and_at_seven_days_does_not() {
    let user = |token: &str| format!("\n    token: {token}\n");
    let ran = good("good", user_facts(&user(JWT_IN_3_DAYS)));
    assert_eq!(ran.finding().level, Level::Warn);
    assert_eq!(
        ran.finding().message,
        "The token in the kubeconfig ends in 3 days."
    );
    assert!(
        has(ran.fix(), "Log in again the way you did"),
        "{}",
        ran.fix()
    );
    // The boundary is strict: 7 days exactly is not a warning, one second less is.
    let at = good("good", user_facts(&user(JWT_IN_7_DAYS)));
    assert_eq!(at.finding().level, Level::Pass, "{}", at.finding().message);
    let short = good("good", user_facts(&user(JWT_IN_7_DAYS_LESS_1S)));
    assert_eq!(short.finding().level, Level::Warn);
}

#[test]
fn an_expired_token_blocks_and_explains_a_401() {
    let user = format!("\n    token: {JWT_EXPIRED}\n");
    let ran = good("unauthorized", user_facts(&user));
    let f = ran.finding();
    assert_eq!(f.level, Level::Fail);
    assert_eq!(f.message, "The token in the kubeconfig ended 1 minute ago.");
}

#[test]
fn an_opaque_token_and_a_plugin_get_no_expiry_warning() {
    let ran = good("good", token_facts());
    assert!(
        has(
            &ran.notes(),
            "has no known expiry (it is not a JWT with an exp claim)"
        ),
        "{}",
        ran.notes()
    );
    let ran = good("good", eks_facts());
    assert_eq!(ran.finding().level, Level::Pass);
    let notes = ran.notes();
    assert!(
        has(
            &notes,
            "They are short-lived and refreshed by `aws`, so no expiry is checked."
        ),
        "{notes}"
    );
    assert_eq!(
        ran.observed("credentials"),
        &json!([{"kind": "exec_plugin", "binary": "aws"}])
    );
}

#[test]
fn an_expired_client_certificate_blocks_with_a_renewal_fix() {
    let key = rcgen::KeyPair::generate().expect("key");
    let mut cert_params =
        rcgen::CertificateParams::new(vec!["admin.acme.example".to_owned()]).expect("params");
    cert_params.not_before = rcgen::date_time_ymd(2020, 1, 1);
    cert_params.not_after = rcgen::date_time_ymd(2026, 10, 1);
    let cert = cert_params.self_signed(&key).expect("cert").pem();
    let yaml = kubeconfig(
        "acme-prod",
        SERVER,
        "",
        "\n    client-certificate: client.crt\n    client-key: client.key\n",
    );
    let facts = facts(
        &yaml,
        &[("client.crt", &cert), ("client.key", &key.serialize_pem())],
        &env(),
    );
    // Both the server's 401 and the ended certificate are true. The certificate is the reason.
    let ran = good("unauthorized", facts);
    let f = ran.finding();
    assert_eq!(f.level, Level::Fail);
    assert_eq!(
        f.message,
        "The client certificate in the kubeconfig ended 29 days ago."
    );
    assert!(
        has(
            ran.fix(),
            "Ask the cluster admin for a new client certificate"
        ),
        "{}",
        ran.fix()
    );
    assert!(
        has(ran.fix(), "kubeadm certs renew admin.conf"),
        "{}",
        ran.fix()
    );
}

// ---- the server certificate ---------------------------------------------------------------------------------

#[test]
fn an_unknown_issuer_blocks_and_the_hint_depends_on_the_kubeconfig_ca() {
    // No CA in the kubeconfig: rdy trusts only its bundled roots (ADR 0031 decision 9).
    let without = token_facts();
    let error = network_error("invalid peer certificate: UnknownIssuer", &without);
    let ran = run_outcome(Some(without), DialOutcome::Failed(error), &json!({}));
    let f = ran.finding();
    assert_eq!(f.level, Level::Fail);
    assert!(has(&f.message, "(UnknownIssuer)"), "{}", f.message);
    assert!(
        has(ran.fix(), "names no certificate authority"),
        "{}",
        ran.fix()
    );
    assert!(has(ran.fix(), "not this machine's store"), "{}", ran.fix());
    // A CA that does not match: a proxy that re-signs TLS is the other suspect.
    let with = facts(
        &kubeconfig(
            "acme-prod",
            SERVER,
            "    certificate-authority: ca.pem\n",
            TOKEN_USER,
        ),
        &[("ca.pem", &test_ca_pem())],
        &env(),
    );
    let error = network_error("invalid peer certificate: UnknownIssuer", &with);
    let ran = run_outcome(Some(with), DialOutcome::Failed(error), &json!({}));
    assert!(
        has(ran.fix(), "does not match this server"),
        "{}",
        ran.fix()
    );
    assert!(has(ran.fix(), "net.tls_intercept"), "{}", ran.fix());
}

#[test]
fn an_expired_server_certificate_blocks_with_the_admin_fix() {
    let facts = token_facts();
    let error = network_error("invalid peer certificate: Expired", &facts);
    let ran = run_outcome(Some(facts), DialOutcome::Failed(error), &json!({}));
    assert_eq!(ran.finding().level, Level::Fail);
    assert!(
        has(&ran.finding().message, "(Expired)"),
        "{}",
        ran.finding().message
    );
    assert!(
        has(ran.fix(), "The API server's certificate has expired."),
        "{}",
        ran.fix()
    );
}

#[test]
fn a_certificate_for_another_name_and_a_clock_behind_get_their_own_fix() {
    let facts = token_facts();
    let error = network_error(
        "invalid peer certificate: certificate not valid for name \"k8s.acme.example\"",
        &facts,
    );
    let ran = run_outcome(Some(token_facts()), DialOutcome::Failed(error), &json!({}));
    assert!(has(ran.fix(), "`tls-server-name`"), "{}", ran.fix());
    let error = network_error("invalid peer certificate: NotValidYet", &facts);
    let ran = run_outcome(Some(token_facts()), DialOutcome::Failed(error), &json!({}));
    assert!(has(ran.fix(), "`timedatectl`"), "{}", ran.fix());
}

#[test]
fn insecure_skip_tls_verify_warns() {
    let facts = facts(
        &kubeconfig(
            "acme-prod",
            SERVER,
            "    insecure-skip-tls-verify: true\n",
            TOKEN_USER,
        ),
        &[],
        &env(),
    );
    let ran = good("good", facts);
    let f = ran.finding();
    assert_eq!(f.level, Level::Warn);
    assert!(
        has(&f.message, "TLS verification is off in the kubeconfig"),
        "{}",
        f.message
    );
    assert!(
        has(
            ran.fix(),
            "--certificate-authority=<ca-file> --embed-certs=true --insecure-skip-tls-verify=false"
        ),
        "{}",
        ran.fix()
    );
    assert_eq!(f.observed["tls_verification"], "off");
}

// ---- no reply -----------------------------------------------------------------------------------------------

#[test]
fn a_private_endpoint_gets_the_provider_specific_fix() {
    let eks = eks_facts();
    let error = network_error_kind(ErrorKind::ConnectionRefused, "tcp connect error", &eks);
    let ran = run_outcome(Some(eks), DialOutcome::Failed(error), &json!({}));
    assert_eq!(ran.finding().level, Level::Fail);
    assert!(
        has(&ran.finding().message, "the connection was refused"),
        "{}",
        ran.finding().message
    );
    let fix = ran.fix();
    assert!(
        has(
            fix,
            "No reply from https://ABCDEF0123.gr7.us-east-1.eks.amazonaws.com."
        ),
        "{fix}"
    );
    assert!(
        has(fix, "`endpointPublicAccess` and `publicAccessCidrs`"),
        "{fix}"
    );
    assert!(!has(fix, "master authorized networks"), "{fix}");
    assert!(has(fix, "Run rdy from a host inside the network"), "{fix}");
    // Without a known provider all three are named.
    let plain = token_facts();
    let error = timeout_error(&plain);
    let ran = run_outcome(Some(plain), DialOutcome::Failed(error), &json!({}));
    let fix = ran.fix();
    assert!(
        has(fix, "EKS:")
            && has(fix, "GKE:")
            && has(fix, "AKS: check `--api-server-authorized-ip-ranges`"),
        "{fix}"
    );
}

#[test]
fn a_name_that_does_not_resolve_says_so() {
    let facts = token_facts();
    let error = network_error("dns error: failed to lookup address information", &facts);
    let ran = run_outcome(Some(facts), DialOutcome::Failed(error), &json!({}));
    assert!(
        has(
            ran.fix(),
            "The server name does not resolve from this machine."
        ),
        "{}",
        ran.fix()
    );
}

// ---- the proxy ----------------------------------------------------------------------------------------------

fn proxy_facts(cluster_extra: &str, env: &Env) -> ConnectionFacts {
    facts(
        &kubeconfig("acme-prod", SERVER, cluster_extra, TOKEN_USER),
        &[],
        env,
    )
}

#[test]
fn a_kubeconfig_proxy_url_is_reported_as_the_rule_that_applied() {
    let facts = proxy_facts(
        "    proxy-url: http://svc:PROXY-CANARY-5@proxy.acme.example:3128\n",
        &env(),
    );
    assert_eq!(facts.proxy().rule(), &ProxyRule::KubeconfigProxyUrl);
    let ran = good("good", facts);
    assert_eq!(ran.observed("proxy")["rule"], "kubeconfig_proxy_url");
    assert_eq!(
        ran.observed("proxy")["proxy"],
        "http://proxy.acme.example:3128"
    );
    let notes = ran.notes();
    assert!(
        has(
            &notes,
            "Route to the API server: through the proxy http://proxy.acme.example:3128 (proxy-url in the kubeconfig)."
        ),
        "{notes}"
    );
    // The password is nowhere in the finding.
    assert!(!ran.text().contains("PROXY-CANARY"), "{}", ran.text());
    assert!(!ran.text().contains("svc:"), "{}", ran.text());
}

#[test]
fn an_environment_only_proxy_is_reported_with_the_variable() {
    let env = env().with_https_proxy("http://proxy.acme.example:3128");
    let ran = good("good", proxy_facts("", &env));
    assert_eq!(ran.observed("proxy")["rule"], "environment");
    assert!(
        has(
            &ran.notes(),
            "through the proxy http://proxy.acme.example:3128 (HTTPS_PROXY)"
        ),
        "{}",
        ran.notes()
    );
}

#[test]
fn no_proxy_covering_the_host_is_reported_as_direct() {
    let env = env()
        .with_https_proxy("http://proxy.acme.example:3128")
        .with_no_proxy(".acme.example");
    let ran = good("good", proxy_facts("", &env));
    assert_eq!(ran.observed("proxy")["rule"], "bypassed");
    assert!(
        has(
            &ran.notes(),
            "directly, although HTTPS_PROXY is set (NO_PROXY entry \".acme.example\" covers the API host)"
        ),
        "{}",
        ran.notes()
    );
}

#[test]
fn a_proxy_that_refuses_the_tunnel_blocks_with_the_proxy_in_the_fix() {
    let facts = proxy_facts("    proxy-url: http://proxy.acme.example:3128\n", &env());
    let error = network_error("tunnel error: unsuccessful", &facts);
    let ran = run_outcome(Some(facts), DialOutcome::Failed(error), &json!({}));
    assert_eq!(ran.finding().level, Level::Fail);
    assert!(
        has(
            &ran.finding().message,
            "the proxy refused to open a tunnel to the API server"
        ),
        "{}",
        ran.finding().message
    );
    assert!(
        has(
            ran.fix(),
            "The proxy refused the CONNECT to the API server."
        ),
        "{}",
        ran.fix()
    );
    assert_eq!(ran.observed("proxy")["rule"], "kubeconfig_proxy_url");
}

#[test]
fn a_proxy_that_wants_credentials_says_where_to_put_them() {
    let facts = proxy_facts("    proxy-url: http://proxy.acme.example:3128\n", &env());
    let error = network_error("tunnel error: proxy authorization required", &facts);
    let ran = run_outcome(Some(facts), DialOutcome::Failed(error), &json!({}));
    assert!(
        has(ran.fix(), "`http://user:password@host:port`"),
        "{}",
        ran.fix()
    );
}

#[test]
fn a_timeout_through_a_proxy_names_the_proxy_route() {
    let facts = proxy_facts("    proxy-url: http://proxy.acme.example:3128\n", &env());
    let error = timeout_error(&facts);
    let ran = run_outcome(Some(facts), DialOutcome::Failed(error), &json!({}));
    assert!(
        has(
            ran.fix(),
            "The request went through the proxy http://proxy.acme.example:3128 (proxy-url in the kubeconfig): check that the proxy allows CONNECT"
        ),
        "{}",
        ran.fix()
    );
}

#[test]
fn a_rancher_path_prefix_is_kept_in_the_report() {
    let facts = facts(
        &kubeconfig(
            "acme-rancher",
            "https://rancher.acme.example/k8s/clusters/c-m-abc12",
            "",
            TOKEN_USER,
        ),
        &[],
        &env(),
    );
    let ran = good("good", facts);
    assert_eq!(
        ran.observed("server"),
        "https://rancher.acme.example/k8s/clusters/c-m-abc12"
    );
    assert!(
        has(
            &ran.finding().message,
            "https://rancher.acme.example/k8s/clusters/c-m-abc12"
        ),
        "{}",
        ran.finding().message
    );
}

// ---- the credential plugin ----------------------------------------------------------------------------------

#[test]
fn a_plugin_that_needs_a_login_is_reported_as_timed_out_with_the_login_to_run() {
    let ran = run_outcome(
        Some(user_facts(AWS_USER)),
        DialOutcome::TimedOut,
        &json!({}),
    );
    let f = ran.finding();
    assert_eq!(f.level, Level::Fail);
    assert_eq!(
        f.message,
        "The credential plugin `aws` did not answer in time. It may need an interactive login."
    );
    assert!(
        has(ran.fix(), "`aws sso login --profile <profile>`"),
        "{}",
        ran.fix()
    );
    assert!(
        has(
            ran.fix(),
            "Without a terminal on stdin and stderr rdy runs `aws` non-interactively"
        ),
        "{}",
        ran.fix()
    );
    assert_eq!(f.observed["state"], "timed_out");
    for (user, login) in [(GKE_USER, "`gcloud auth login`"), (AKS_USER, "`az login`")] {
        let ran = run_outcome(Some(user_facts(user)), DialOutcome::TimedOut, &json!({}));
        assert!(has(ran.fix(), login), "{}", ran.fix());
    }
}

#[test]
fn a_timeout_with_no_plugin_is_a_slow_network_and_one_with_no_config_is_a_slow_read() {
    let ran = run_outcome(Some(token_facts()), DialOutcome::TimedOut, &json!({}));
    assert_eq!(
        ran.finding().message,
        "No answer from https://k8s.acme.example:6443 in time."
    );
    assert!(has(ran.fix(), "No reply from"), "{}", ran.fix());
    let ran = run_outcome(None, DialOutcome::TimedOut, &json!({}));
    assert_eq!(
        ran.finding().message,
        "Reading the kubeconfig took too long."
    );
    assert!(has(ran.fix(), "slow network mount"), "{}", ran.fix());
}

#[test]
fn a_failed_plugin_gets_the_error_hint_and_the_login() {
    let facts = eks_facts();
    let error = KubeError::PluginFailed {
        plugin: "aws".to_owned(),
        exit_code: Some(255),
    };
    let ran = run_outcome(Some(facts), DialOutcome::Failed(error), &json!({}));
    assert_eq!(
        ran.finding().message,
        "the credential plugin aws failed with exit code 255"
    );
    assert!(
        has(
            ran.fix(),
            "Run the same plugin command yourself to see why it fails."
        ),
        "{}",
        ran.fix()
    );
    assert!(
        has(ran.fix(), "`aws sso login --profile <profile>`"),
        "{}",
        ran.fix()
    );
    assert_eq!(ran.observed("state"), "plugin_failed");
}

#[test]
fn every_plugin_failure_class_blocks_with_the_command_to_run() {
    // The classes of 03: it did not start, it failed, it gave nothing usable, it waited for a login.
    let classes = [
        KubeError::PluginNotStarted {
            plugin: "aws".to_owned(),
            reason: "no such command",
        },
        KubeError::PluginFailed {
            plugin: "aws".to_owned(),
            exit_code: None,
        },
        KubeError::PluginOutputInvalid {
            plugin: "aws".to_owned(),
        },
    ];
    for error in classes {
        let shown = error.to_string();
        let ran = run_outcome(Some(eks_facts()), DialOutcome::Failed(error), &json!({}));
        assert_eq!(ran.finding().level, Level::Fail, "{shown}");
        assert_eq!(ran.finding().message, shown);
        assert_eq!(ran.observed("state"), "plugin_failed", "{shown}");
        assert!(!ran.fix().is_empty(), "{shown}");
    }
    let ran = run_outcome(
        Some(eks_facts()),
        DialOutcome::Failed(KubeError::PluginNotStarted {
            plugin: "aws".to_owned(),
            reason: "no such command",
        }),
        &json!({}),
    );
    assert!(
        has(ran.fix(), "Install the plugin and put it on PATH"),
        "{}",
        ran.fix()
    );
}

#[test]
fn a_403_or_another_status_on_version_keeps_the_error_hint() {
    let forbidden = KubeError::Forbidden {
        server: SERVER.to_owned(),
    };
    let hint = forbidden.hint();
    let ran = run_outcome(
        Some(token_facts()),
        DialOutcome::Failed(forbidden),
        &json!({}),
    );
    assert_eq!(ran.finding().level, Level::Fail);
    assert_eq!(ran.observed("state"), "forbidden");
    assert_eq!(ran.fix(), hint);
    for error in [
        KubeError::BadAnswer {
            server: SERVER.to_owned(),
        },
        KubeError::Api {
            server: SERVER.to_owned(),
            code: 502,
            reason: "BadGateway".to_owned(),
        },
    ] {
        let hint = error.hint();
        let ran = run_outcome(Some(token_facts()), DialOutcome::Failed(error), &json!({}));
        assert_eq!(ran.fix(), hint);
        assert!(
            has(ran.fix(), "server address in the kubeconfig"),
            "{}",
            ran.fix()
        );
    }
}

#[test]
fn a_missing_gke_plugin_says_how_to_install_it() {
    let facts = user_facts(GKE_USER);
    let error = KubeError::PluginNotStarted {
        plugin: "gke-gcloud-auth-plugin".to_owned(),
        reason: "no such command",
    };
    let ran = run_outcome(Some(facts), DialOutcome::Failed(error), &json!({}));
    assert!(
        has(
            ran.fix(),
            "`gcloud components install gke-gcloud-auth-plugin`"
        ),
        "{}",
        ran.fix()
    );
}

// ---- no kubeconfig and no network ---------------------------------------------------------------------------

#[test]
fn no_kubeconfig_blocks_with_the_flag_and_the_distribution_files() {
    let ran = run_outcome(
        None,
        DialOutcome::Failed(KubeError::NoKubeconfig),
        &json!({}),
    );
    let f = ran.finding();
    assert_eq!(f.level, Level::Fail);
    assert_eq!(f.message, "no kubeconfig found");
    assert_eq!(f.observed["state"], "no_kubeconfig");
    assert!(
        has(ran.fix(), "Pass --kubeconfig <file> or set KUBECONFIG."),
        "{}",
        ran.fix()
    );
    if cfg!(target_os = "linux") {
        assert!(has(ran.fix(), "/etc/rancher/k3s/k3s.yaml"), "{}", ran.fix());
        assert!(has(ran.fix(), "chmod 600"), "{}", ran.fix());
    }
}

#[test]
fn an_unreadable_root_only_kubeconfig_gets_the_k3s_text() {
    let error = KubeError::KubeconfigUnreadable {
        path: "/etc/rancher/k3s/k3s.yaml".to_owned(),
        reason: "permission denied",
    };
    let ran = run_outcome(None, DialOutcome::Failed(error), &json!({}));
    if cfg!(target_os = "linux") {
        assert!(
            has(ran.fix(), "copy one to ~/.kube/config and chmod 600 it"),
            "{}",
            ran.fix()
        );
    }
}

#[test]
fn an_unsupported_proxy_scheme_blocks_with_the_proxy_hint() {
    let error = KubeError::ProxyUnsupported {
        proxy: "socks5://proxy.acme.example:1080".to_owned(),
        origin: "the proxy-url in the kubeconfig",
    };
    let ran = run_outcome(None, DialOutcome::Failed(error), &json!({}));
    assert_eq!(ran.observed("state"), "proxy_unsupported");
    assert!(
        has(ran.fix(), "http:// proxy through a CONNECT tunnel"),
        "{}",
        ran.fix()
    );
}

#[test]
fn with_no_network_the_check_is_skipped_as_a_missing_network() {
    let ran = run_outcome(None, DialOutcome::NoNetwork, &json!({}));
    assert_eq!(
        ran.outcome.as_ref().expect_err("a skip"),
        &CheckError::MissingNeed(Need::Network)
    );
}

// ---- the spec's thresholds ----------------------------------------------------------------------------------

#[test]
fn a_version_slower_than_two_seconds_warns_by_default() {
    let slow =
        |ms: u64, spec: &Value| run_case("good", token_facts(), Duration::from_millis(ms), spec);
    assert_eq!(slow(2000, &json!({})).finding().level, Level::Pass);
    let ran = slow(2001, &json!({}));
    assert_eq!(ran.finding().level, Level::Warn);
    assert_eq!(
        ran.finding().message,
        "GET /version took 2001 ms, above the 2000 ms limit."
    );
    assert!(
        has(ran.fix(), "raise `max_latency` in the spec"),
        "{}",
        ran.fix()
    );
    // The spec moves the limit.
    assert_eq!(
        slow(2500, &json!({"max_latency": "5s"})).finding().level,
        Level::Pass
    );
    assert_eq!(
        slow(500, &json!({"max_latency": "400ms"})).finding().level,
        Level::Warn
    );
    assert_eq!(ran.finding().expected["max_latency_ms"], 2000);
    assert_eq!(
        slow(1, &json!({"max_latency": "5s"})).finding().expected["max_latency_ms"],
        5000
    );
}

#[test]
fn a_context_or_server_that_does_not_match_its_pattern_blocks() {
    let spec =
        json!({"context_pattern": "^acme-prod-", "server_pattern": "^https://.*\\.acme\\.example"});
    // The context `acme-prod` has no trailing dash, so it does not match. The server matches.
    let ran = run_case("good", token_facts(), Duration::from_millis(10), &spec);
    let f = ran.finding();
    assert_eq!(f.level, Level::Fail);
    assert_eq!(
        f.message,
        "The kube context is acme-prod, which does not match the pattern ^acme-prod- in the spec."
    );
    assert!(has(ran.fix(), "`--kube-context <name>`"), "{}", ran.fix());
    assert!(
        has(ran.fix(), "`kubectl config get-contexts`"),
        "{}",
        ran.fix()
    );
    assert_eq!(f.expected["context_pattern"], "^acme-prod-");

    let spec = json!({"server_pattern": "^https://.*\\.corp\\.example"});
    let ran = run_case("good", token_facts(), Duration::from_millis(10), &spec);
    assert_eq!(ran.finding().level, Level::Fail);
    assert_eq!(
        ran.finding().message,
        "The API server is https://k8s.acme.example:6443, which does not match the pattern ^https://.*\\.corp\\.example in the spec."
    );
    assert!(has(ran.fix(), "`--kubeconfig <file>`"), "{}", ran.fix());
}

#[test]
fn matching_patterns_pass_and_a_second_problem_is_a_note() {
    let spec = json!({"context_pattern": "^acme-", "server_pattern": "^https://k8s\\."});
    let ran = run_case("good", token_facts(), Duration::from_millis(10), &spec);
    assert_eq!(ran.finding().level, Level::Pass);
    // Two problems: the first is the message, the other is an "Also:" note, and both fixes are given once.
    let spec = json!({"context_pattern": "^nope-", "server_pattern": "^nope"});
    let ran = run_case(
        "anonymous",
        user_facts(NO_USER),
        Duration::from_millis(10),
        &spec,
    );
    let f = ran.finding();
    assert_eq!(f.level, Level::Fail);
    assert!(has(&f.message, "The kube context is"), "{}", f.message);
    assert_eq!(
        f.notes
            .iter()
            .filter(|note| note.starts_with("Also: "))
            .count(),
        2,
        "{:?}",
        f.notes
    );
}

#[test]
fn a_pattern_that_does_not_compile_refuses_to_build() {
    let dial = Arc::new(TestDial {
        facts: None,
        outcome: DialOutcome::NoNetwork,
        harness: None,
    });
    let error = AccessCheck::new(&params(&json!({"context_pattern": "("})), dial)
        .expect_err("an open group");
    assert_eq!(error.field(), "context_pattern");
    assert!(
        error
            .to_string()
            .starts_with("k8s.access context_pattern is not a pattern rdy can use")
    );
}

// ---- the declaration ----------------------------------------------------------------------------------------

#[test]
fn the_check_is_registered_and_needs_the_network_but_not_a_cluster() {
    let info = crate::registry::infos()
        .iter()
        .find(|info| info.id == "k8s.access")
        .expect("k8s.access is registered");
    assert_eq!(info.family, "k8s");
    // 02: no `KubeContext` need, because this check reports why the attempt failed. The network need is
    // the one the check itself returns when the run forbids the network.
    assert_eq!(info.needs, &[Need::Network]);
    assert!(info.wants.is_empty());
    assert_eq!(info.default_timeout, Some(Duration::from_secs(10)));
    assert!(info.reads.is_empty() && info.commands.is_empty() && info.env.is_empty());
    assert_eq!(
        info.peers,
        &[
            rdy_engine::check::PeerClass::KubeApi,
            rdy_engine::check::PeerClass::Proxy
        ]
    );
    assert!(
        rdy_engine::fixtext::check(info.meta.remediation).is_ok(),
        "{}",
        info.meta.remediation
    );
    assert_eq!(info.meta.title, "Cluster access");
}

#[test]
fn the_credential_kind_is_the_same_in_facts_and_json() {
    // A token credential is a token in the report.
    let ran = good(
        "good",
        user_facts(&format!("\n    token: {JWT_IN_3_DAYS}\n")),
    );
    assert_eq!(
        ran.observed("credentials"),
        &json!([{"kind": "token", "expires_in_seconds": 3 * 86_400}])
    );
    let _ = Credential::Password;
}

// ---- fix round 1 of PR #130 ---------------------------------------------------------------------------------

/// The `via_proxy` value of every `kube` entry of the run, in order.
fn kube_via(ran: &Ran) -> Vec<Value> {
    ran.run
        .action_log()
        .actions
        .iter()
        .filter(|entry| entry.kind == rdy_spec::result::ActionKind::Kube)
        .map(|entry| entry.fields["via_proxy"].clone())
        .collect()
}

#[test]
fn every_kube_entry_names_the_proxy_it_went_through() {
    // INV-07: the proxy hop is recorded. The origin has no user info.
    let facts = proxy_facts(
        "    proxy-url: http://svc:VIA-CANARY-8@proxy.acme.example:3128\n",
        &env(),
    );
    let ran = good("good", facts);
    let via = kube_via(&ran);
    assert_eq!(via.len(), 4, "{via:?}");
    assert!(
        via.iter()
            .all(|value| value == "http://proxy.acme.example:3128"),
        "{via:?}"
    );
    let logged = serde_json::to_string(&ran.run.action_log().actions).expect("json");
    assert!(
        !logged.contains("VIA-CANARY") && !logged.contains("svc:"),
        "{logged}"
    );
    // An environment proxy is recorded the same way.
    let with_env = env().with_https_proxy("http://env-proxy.acme.example:3128");
    let ran = good("good", proxy_facts("", &with_env));
    assert!(
        kube_via(&ran)
            .iter()
            .all(|value| value == "http://env-proxy.acme.example:3128")
    );
    // A direct request has `via_proxy: null`, as a `connect` entry does.
    let ran = good("good", token_facts());
    assert!(
        kube_via(&ran).iter().all(Value::is_null),
        "{:?}",
        kube_via(&ran)
    );
    // A proxy that NO_PROXY exempts is not in the path.
    let env = env()
        .with_https_proxy("http://proxy.acme.example:3128")
        .with_no_proxy(".acme.example");
    let ran = good("good", proxy_facts("", &env));
    assert!(kube_via(&ran).iter().all(Value::is_null));
}

#[test]
fn an_ended_token_the_server_accepted_warns_about_the_clock_and_does_not_block() {
    let user = format!("\n    token: {JWT_EXPIRED}\n");
    let ran = good("good", user_facts(&user));
    let f = ran.finding();
    assert_eq!(f.level, Level::Warn, "{}", f.message);
    assert_eq!(
        f.message,
        "The token in the kubeconfig ended 1 minute ago by this machine's clock, yet the server did not reject it (no 401). The clock is probably wrong."
    );
    assert!(has(ran.fix(), "`timedatectl`"), "{}", ran.fix());
    assert_eq!(f.observed["identity"]["verified"], true);
    // The run reached the cluster and read who rdy is: it is not the failed-attempt path.
    assert_eq!(f.observed["state"], "connected");
}

#[test]
fn a_client_certificate_that_ended_but_was_accepted_also_warns_about_the_clock() {
    let key = rcgen::KeyPair::generate().expect("key");
    let mut cert_params =
        rcgen::CertificateParams::new(vec!["admin.acme.example".to_owned()]).expect("params");
    cert_params.not_before = rcgen::date_time_ymd(2020, 1, 1);
    cert_params.not_after = rcgen::date_time_ymd(2026, 10, 1);
    let cert = cert_params.self_signed(&key).expect("cert").pem();
    let yaml = kubeconfig(
        "acme-prod",
        SERVER,
        "",
        "\n    client-certificate: client.crt\n    client-key: client.key\n",
    );
    let facts = facts(
        &yaml,
        &[("client.crt", &cert), ("client.key", &key.serialize_pem())],
        &env(),
    );
    let ran = good("good", facts);
    assert_eq!(ran.finding().level, Level::Warn);
    assert!(
        has(
            &ran.finding().message,
            "client certificate in the kubeconfig ended 29 days ago"
        ),
        "{}",
        ran.finding().message
    );
    assert!(has(ran.fix(), "`timedatectl`"), "{}", ran.fix());
}

#[test]
fn hostile_api_versions_are_escaped_and_capped_at_sixteen() {
    let ran = good("hostile-names", token_facts());
    let text = ran.text();
    for bad in ['\u{1b}', '\u{7}', '\u{9b}'] {
        assert!(!text.contains(bad), "{bad:?} in {text:?}");
    }
    let versions = ran.observed("discovery")["core_versions"]
        .as_array()
        .expect("a list")
        .clone();
    assert_eq!(versions.len(), 16, "{versions:?}");
    assert_eq!(versions[0], "v1");
    assert_eq!(versions[1], "v2\\x1b[31mevil\\x1b]0;pwn\\x07");
    let notes = ran.notes();
    assert!(
        has(&notes, "v1, v2\\x1b[31mevil\\x1b]0;pwn\\x07, v3"),
        "{notes}"
    );
    assert!(has(&notes, "v16 and 4 more; /apis lists"), "{notes}");
    assert!(!has(&notes, "v17"), "{notes}");
}

#[test]
fn a_404_on_the_identity_review_of_a_new_server_says_the_route_is_not_served() {
    let ran = good("route-missing", token_facts());
    let f = ran.finding();
    assert_eq!(f.level, Level::Pass);
    let partial = f.partial.as_ref().expect("partial");
    assert!(has(&partial.note, "is not served"), "{}", partial.note);
    assert!(has(&partial.note, "1.28 or later"), "{}", partial.note);
    assert!(!has(&partial.note, "older than 1.28"), "{}", partial.note);
    let notes = ran.notes();
    assert!(
        has(
            &notes,
            "The identity review route (authentication.k8s.io/v1 selfsubjectreviews) is not served by this server, although it is 1.28 or later."
        ),
        "{notes}"
    );
    assert!(has(&notes, "gateway"), "{notes}");
    assert!(!has(&notes, "older than"), "{notes}");
    assert_eq!(f.observed["identity"], json!({"verified": false}));
}

#[test]
fn a_1_27_server_is_named_with_its_v1beta1_route() {
    let ran = good("old-server", token_facts());
    let notes = ran.notes();
    assert!(
        has(
            &notes,
            "The server is 1.27, which serves the identity review only as authentication.k8s.io/v1beta1"
        ),
        "{notes}"
    );
    assert!(has(&notes, "1.27 is out of support"), "{notes}");
}

#[test]
fn tls_verification_off_behind_a_proxy_warns_that_the_proxy_can_read_the_token() {
    let env = env().with_https_proxy("http://proxy.acme.example:3128");
    let facts = facts(
        &kubeconfig(
            "acme-prod",
            SERVER,
            "    insecure-skip-tls-verify: true\n",
            TOKEN_USER,
        ),
        &[],
        &env,
    );
    let ran = good("good", facts);
    assert_eq!(ran.finding().level, Level::Warn);
    assert!(
        has(
            &ran.finding().message,
            "A proxy is in the path, and it can read the credentials rdy sends."
        ),
        "{}",
        ran.finding().message
    );
}

#[test]
fn a_rancher_cluster_gets_the_rancher_login_not_the_generic_one() {
    let facts = facts(
        &kubeconfig(
            "acme-rancher",
            "https://rancher.acme.example/k8s/clusters/c-m-abc12",
            "",
            TOKEN_USER,
        ),
        &[],
        &env(),
    );
    let ran = good("unauthorized", facts);
    assert_eq!(ran.finding().level, Level::Fail);
    assert!(has(ran.fix(), "Download KubeConfig"), "{}", ran.fix());
    assert!(
        has(
            ran.fix(),
            "`rancher login <rancher-url> --token <bearer-token>`"
        ),
        "{}",
        ran.fix()
    );
    assert!(!has(ran.fix(), "the way you did"), "{}", ran.fix());
}

#[test]
fn the_none_fixture_is_the_run_of_an_attempt_that_never_reached_a_cluster() {
    let fixture = rdy_engine::testing::Fixture::load(
        &rdy_engine::testing::fixtures_dir(),
        "checks/k8s.access/none",
    )
    .expect("the fixture loads");
    let run = TestRun::for_fixture(&fixture);
    let ran = run_dial(
        TestDial {
            facts: None,
            outcome: DialOutcome::Failed(KubeError::NoKubeconfig),
            harness: None,
        },
        run,
        &json!({}),
    );
    assert_eq!(ran.finding().level, Level::Fail);
    assert_eq!(ran.finding().message, "no kubeconfig found");
    // The fixture sends no request: its log holds no `kube` entry.
    assert!(kube_via(&ran).is_empty());
}

#[test]
fn a_proxy_url_on_a_plain_server_blocks_with_its_own_state() {
    let error = KubeError::ProxyPlainServer {
        proxy: "http://proxy.acme.example:3128".to_owned(),
        origin: "the proxy-url in the kubeconfig",
    };
    let ran = run_outcome(None, DialOutcome::Failed(error), &json!({}));
    assert_eq!(ran.finding().level, Level::Fail);
    assert_eq!(ran.finding().observed["state"], "proxy_unsupported");
    assert!(has(ran.fix(), "--kubeconfig"), "{}", ran.fix());
}

#[test]
fn a_client_certificate_alert_is_not_blamed_on_the_server_certificate() {
    let facts = token_facts();
    let error = network_error("received fatal alert: CertificateExpired", &facts);
    let ran = run_outcome(Some(facts), DialOutcome::Failed(error), &json!({}));
    assert_eq!(ran.finding().level, Level::Fail);
    assert!(
        has(
            &ran.finding().message,
            "rejected the client certificate as expired"
        ),
        "{}",
        ran.finding().message
    );
    assert!(
        has(
            ran.fix(),
            "rejected the client certificate in the kubeconfig as expired"
        ),
        "{}",
        ran.fix()
    );
    assert!(
        !has(ran.fix(), "API server's certificate has expired"),
        "{}",
        ran.fix()
    );
    // A server certificate that really expired keeps its own words.
    let facts = token_facts();
    let error = network_error("invalid peer certificate: Expired", &facts);
    let ran = run_outcome(Some(facts), DialOutcome::Failed(error), &json!({}));
    assert!(
        has(ran.fix(), "API server's certificate has expired"),
        "{}",
        ran.fix()
    );
}
