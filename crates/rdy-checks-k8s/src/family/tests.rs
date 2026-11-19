//! Tests of the k8s family that need no server: its list, and what the holder says for an error.

use rdy_engine::family::Family;

use super::*;
use crate::client::testkit;

#[test]
fn the_family_reads_its_check_list_from_the_registry_and_names_what_it_does_not_build() {
    let family = K8sFamily::new();
    let listed: Vec<&str> = family.checks().iter().map(|info| info.id).collect();
    let registered: Vec<&str> = registry::infos().iter().map(|info| info.id).collect();
    assert_eq!(
        listed, registered,
        "one list, so no check runs unregistered"
    );
    // Every id it does not build is one it lists, so the planner can skip it as not in the build.
    for id in family.not_built() {
        assert!(listed.contains(id), "{id} is not listed");
    }
    // What it builds is what is listed and not skipped.
    let built: Vec<&&str> = listed
        .iter()
        .filter(|id| !family.not_built().contains(id))
        .collect();
    // M1-175: the family builds every check of the crate, so the planner skips none as not in the build.
    assert!(family.not_built().is_empty());
    assert_eq!(built.len(), listed.len());
    assert_eq!(listed.len(), 8);
}

fn api_error(code: u16) -> kube::Error {
    kube::Error::Api(Box::new(
        kube::core::Status::failure("x", "Reason").with_code(code),
    ))
}

#[test]
fn the_holder_sorts_an_error_with_what_the_connection_knows() {
    // Before an attempt it knows nothing: the generic words.
    let holder = Holder::new(None);
    assert!(
        matches!(holder.map_error(&api_error(401)), KubeError::Unauthorized { server } if server == "the API server")
    );
    // After one that loaded a config it names the server.
    let facts = testkit::facts(
        &testkit::kubeconfig("acme-prod", "https://k8s.acme.example:6443", "", " {}\n"),
        &[],
        &Env::empty(),
    );
    holder.settle(Dialed::timed_out(Some(facts)));
    let mapped = holder.map_error(&api_error(403));
    assert!(
        matches!(&mapped, KubeError::Forbidden { server } if server == "https://k8s.acme.example:6443"),
        "{mapped:?}"
    );
}

// ---- M1-175: every check is built from its parameters, on the kube mock harness ---------------------------------

use std::sync::Arc;

use rdy_engine::check::Os;
use rdy_engine::outcome::map_outcome;
use rdy_engine::probe::Probe;
use rdy_engine::testing::{Fixture, TestRun, fixtures_dir};
use rdy_spec::result::Status;

use crate::client::mock::Harness;

/// A cluster over the mock, as the fixture tests of each check make one.
struct Fixtured {
    harness: Harness,
}

impl Cluster for Fixtured {
    fn server_version(&self) -> &ServerVersion {
        static VERSION: OnceLock<ServerVersion> = OnceLock::new();
        VERSION.get_or_init(|| ServerVersion {
            git_version: "v1.29.4".to_owned(),
            major: "1".to_owned(),
            minor: "29".to_owned(),
            platform: "linux/amd64".to_owned(),
        })
    }

    fn read_only(&self, probe: &Probe) -> ReadOnlyClient {
        self.harness.client(probe)
    }

    fn read_only_as(
        &self,
        _probe: &Probe,
        _user: ImpersonateAs,
    ) -> Result<ReadOnlyClient, ImpersonationError> {
        Err(ImpersonationError::Conflict)
    }
}

/// A spec that holds every k8s id of this build, and the fixture whose cluster answers that entry.
const ENTRIES: [(&str, &str, &str); 7] = [
    (
        "k8s.version",
        "checks/k8s.version/kind",
        "    min: \"1.28\"\n",
    ),
    (
        "k8s.storageclass",
        "checks/k8s.storageclass/k3s-local-path",
        "",
    ),
    (
        "k8s.rbac",
        "checks/k8s.rbac/all-allowed",
        "    can: [\"create deployments.apps\", \"get pods/log\", \"get /healthz\"]\n    namespace: acme-system\n",
    ),
    (
        "k8s.nodes",
        "checks/k8s.nodes/healthy",
        "    min_ready: 3\n",
    ),
    (
        "k8s.admission",
        "checks/k8s.admission/restricted",
        "    uses: [runAsRoot]\n    namespace: acme-system\n",
    ),
    (
        "k8s.namespace",
        "checks/k8s.namespace/active-plain",
        "    namespace: acme-system\n",
    ),
    ("k8s.dns", "checks/k8s.dns/kubeadm-ok", ""),
];

fn family_spec() -> Spec {
    let mut text = String::from(
        "apiVersion: rdy/v1\nkind: Readiness\nmetadata:\n  product: acme\nchecks:\n  - id: k8s.access\n",
    );
    for (id, _, params) in ENTRIES {
        text.push_str(&format!("  - id: {id}\n{params}"));
    }
    rdy_spec::parse_unverified(text.as_bytes())
        .unwrap_or_else(|error| panic!("the spec parses: {error}"))
}

#[test]
fn the_family_builds_every_k8s_id_of_a_spec_and_none_is_unsupported() {
    let spec = family_spec();
    let family = K8sFamily::new();
    let with_namespace = K8sFamily::new().with_namespace(
        serde_json::from_value(serde_json::json!("acme-system")).expect("a namespace"),
    );
    assert_eq!(spec.checks.len(), 8);
    for entry in &spec.checks {
        for family in [&family, &with_namespace] {
            let built = family
                .build(entry, entry.decode_params(), &spec)
                .unwrap_or_else(|error| panic!("{} is not built: {error}", entry.id));
            assert_eq!(built.check.info().id, entry.id);
            assert!(!family.not_built().contains(&entry.id.as_str()));
        }
    }
}

#[tokio::test]
async fn every_built_check_runs_over_the_mock_and_passes_the_inv_14_audit() {
    let spec = family_spec();
    for (id, case, _) in ENTRIES {
        let entry = spec
            .checks
            .iter()
            .find(|entry| entry.id == id)
            .unwrap_or_else(|| panic!("no entry for {id}"));
        let fixture = Fixture::load(&fixtures_dir(), case).expect("the fixture loads");
        let harness =
            Harness::new(TestRun::for_fixture(&fixture), fixture.replay()).expect("a mock");
        let cluster = Arc::new(Fixtured { harness });
        let built = crate::family::build_check(entry.decode_params(), None, cluster.clone())
            .unwrap_or_else(|error| panic!("{id} is not built: {error}"));
        let info = built.check.info();
        let ctx = cluster
            .harness
            .run()
            .context_for(info, id, Os::Linux, [Need::KubeContext]);
        let outcome = built.check.run(&ctx).await;
        let result = map_outcome(info, entry, &ctx, outcome, 0, 0);
        assert_eq!(result.id, id);
        assert_ne!(result.status, Status::Skipped, "{id}: {result:?}");
        assert_ne!(result.status, Status::Error, "{id}: {result:?}");
        // INV-14: every request the check sent passes the guard rules and is logged under a cited id.
        cluster
            .harness
            .audit()
            .unwrap_or_else(|violations| panic!("{id}: INV-14: {violations:?}"));
    }
}

#[tokio::test]
async fn the_family_namespace_reaches_k8s_storageclass_and_its_claim_evidence_is_read() {
    let namespace: K8sName =
        serde_json::from_value(serde_json::json!("acme-system")).expect("a namespace");
    let fixture = Fixture::load(&fixtures_dir(), "checks/k8s.storageclass/pending-failed")
        .expect("the fixture loads");
    let harness = Harness::new(TestRun::for_fixture(&fixture), fixture.replay()).expect("a mock");
    let cluster = Arc::new(Fixtured { harness });
    let spec = family_spec();
    let entry = spec
        .checks
        .iter()
        .find(|entry| entry.id == "k8s.storageclass")
        .expect("an entry");
    let built =
        crate::family::build_check(entry.decode_params(), Some(&namespace), cluster.clone())
            .expect("built");
    let ctx = cluster.harness.run().context_for(
        built.check.info(),
        "k8s.storageclass",
        Os::Linux,
        [Need::KubeContext],
    );
    // The check reads the real clock here, so the claim made two minutes ago in the fixture is old too.
    let finding = built.check.run(&ctx).await.expect("the check ran");
    assert!(
        finding
            .message
            .contains("claims in acme-system on class gp3")
            && finding.message.contains("data-db-0"),
        "{}",
        finding.message
    );
    cluster.harness.audit().expect("INV-14 audit is clean");
}
