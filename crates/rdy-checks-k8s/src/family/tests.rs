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
    assert_eq!(built, [&"k8s.access", &"k8s.version"]);
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
