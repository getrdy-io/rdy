//! A scripted cluster for the env harness (M1-185). Only with the `testing` feature, which the shipped
//! binary never enables: CI checks the binary's feature graph for it, and a release build with it does not
//! compile.
//!
//! [`ScriptedCluster`] serves the `api/` files of a fixture environment in process, with the read-only
//! guard in front of it, and hands a [`K8sFamily`] built over it to the run in place of a kubeconfig and a
//! socket. The shipped family has no constructor that takes a mock: the one that does is this feature's.
//!
//! After the run, [`ScriptedCluster::audit`] proves INV-14 over it, the same audit the check tests run (see
//! `client::mock`): every request the mock saw passes the guard's rules and pairs with one sent entry of
//! the run's action log, cited by the check that sent it, and the fixture answered every request.

// A release build with the feature does not compile, the same rule as the `testing` feature of rdy-engine. A
// debug build is allowed so `cargo test` and `cargo clippy --features testing` work. CI also keeps the
// feature out of the binary's feature graph.
#[cfg(all(not(test), not(debug_assertions)))]
compile_error!("the `testing` feature of rdy-checks-k8s must not be enabled in a release build");

use rdy_engine::testing::Replay;
use rdy_spec::result::Action;

use crate::client::mock::{Mock, audit};
use crate::family::K8sFamily;

/// The `api/` files of an environment did not make a cluster.
#[derive(Debug, thiserror::Error)]
#[error(
    "the `api/` files of the environment do not make a cluster: {0}. Fix: correct the file the message names"
)]
pub struct ScriptError(String);

/// A cluster served from the `api/` files of a fixture, in process. Clones share state.
#[derive(Debug, Clone)]
pub struct ScriptedCluster {
    mock: Mock,
}

impl ScriptedCluster {
    /// Builds the cluster from the `api/` records of `replay`. A `Replay` with none serves a cluster that
    /// answers nothing, and every request is unanswered.
    ///
    /// # Errors
    ///
    /// [`ScriptError`] for a query that cannot be decoded, two files that record one request, or a
    /// malformed `api/reviews.json`.
    pub fn new(replay: &Replay) -> Result<Self, ScriptError> {
        Mock::new(replay)
            .map(|mock| Self { mock })
            .map_err(|error| ScriptError(error.to_string()))
    }

    /// A family that reads this cluster and no kubeconfig. Its probe makes the attempt the real one makes,
    /// from the cluster line on, and every request goes through the read-only guard.
    #[must_use]
    pub fn family(&self) -> K8sFamily {
        K8sFamily::over_mock(self.mock.clone())
    }

    /// `METHOD path?query` of every request that reached the cluster, in arrival order.
    #[must_use]
    pub fn requests(&self) -> Vec<String> {
        self.mock.seen().iter().map(|seen| seen.line()).collect()
    }

    /// Audits the run (INV-14) against `actions`, the action log of its report. One sentence per
    /// violation. Empty is clean.
    #[must_use]
    pub fn audit(&self, actions: &[Action]) -> Vec<String> {
        audit(&self.mock.seen(), actions, &self.mock.unrecorded(), None)
    }
}

#[cfg(test)]
mod tests;
