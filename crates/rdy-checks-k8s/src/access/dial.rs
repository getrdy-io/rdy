//! How a run's attempt to reach the cluster ended, as `k8s.access` reads it.
//!
//! Every other k8s check needs the `kube_context` need and is skipped when the attempt failed. `k8s.access`
//! is the check that says *why* it failed (02: it has no hard need and reports the probe outcome as a
//! block with its fix). So it does not take a handle to a connected cluster, which exists only on
//! success. It takes a [`Dial`]: the facts the config gave, how the attempt ended, and a way to get a
//! read-only client when it worked.
//!
//! The family probe (M1-107) makes the attempt once per run, lazily, under the 10 s timer, and wraps what
//! it got in a [`Dialed`]. This crate only reads it.
//!
//! **Order.** Building `k8s.access` does no I/O, so it is handed a `Dial` that is filled before it runs:
//! the family probe makes the attempt whenever the plan holds any k8s check (`k8s.access` included, even
//! when it is the only one), then runs the checks. A `Dial` is read only after that family probe is done.
//! [`Dial::outcome`] is synchronous and never waits.

use std::time::Duration;

use rdy_engine::probe::Probe;

use crate::client::{Connected, ConnectionFacts, KubeError, ReadOnlyClient, ServerVersion};

/// How the attempt to reach the cluster ended.
#[derive(Debug)]
#[non_exhaustive]
pub enum DialOutcome {
    /// `GET /version` answered.
    Reached {
        /// What it said.
        version: ServerVersion,
        /// How long the request took.
        latency: Duration,
    },
    /// Loading the config, building the client or the first request failed.
    Failed(KubeError),
    /// The attempt did not finish inside the family's timer. With a credential plugin in the kubeconfig
    /// the likely cause is a login that waits for a person (ADR 0031 decision 7).
    TimedOut,
    /// The run does not allow the network (`--no-network`), so no client was built.
    NoNetwork,
}

/// The run's attempt to reach the cluster.
///
/// Read it only after the family probe has made the attempt: every method is synchronous and returns
/// what is there now. Before the attempt there is nothing to report, so a holder is not created (or its
/// methods are not called) until the attempt has ended.
pub trait Dial: Send + Sync + 'static {
    /// What the config said about the connection. `None` when no config loaded.
    fn facts(&self) -> Option<&ConnectionFacts>;

    /// How the attempt ended.
    fn outcome(&self) -> &DialOutcome;

    /// The read-only client for one check, bound to its own probe. `Some` only when the attempt reached
    /// the cluster.
    fn read_only(&self, probe: &Probe) -> Option<ReadOnlyClient>;
}

/// The attempt of a run, as the family probe holds it.
pub struct Dialed {
    facts: Option<ConnectionFacts>,
    outcome: DialOutcome,
    connected: Option<Connected>,
}

impl std::fmt::Debug for Dialed {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Dialed")
            .field("facts", &self.facts)
            .field("outcome", &self.outcome)
            .finish_non_exhaustive()
    }
}

impl Dialed {
    /// The attempt reached the cluster.
    #[must_use]
    pub fn reached(connected: Connected) -> Self {
        Self {
            facts: Some(connected.facts().clone()),
            outcome: DialOutcome::Reached {
                version: connected.server_version().clone(),
                latency: connected.version_latency(),
            },
            connected: Some(connected),
        }
    }

    /// The attempt failed. `facts` is `Loaded::facts()` taken before `connect`, or `None` when the config
    /// did not load.
    #[must_use]
    pub fn failed(facts: Option<ConnectionFacts>, error: KubeError) -> Self {
        Self {
            facts,
            outcome: DialOutcome::Failed(error),
            connected: None,
        }
    }

    /// The family's timer fired before the attempt finished.
    #[must_use]
    pub fn timed_out(facts: Option<ConnectionFacts>) -> Self {
        Self {
            facts,
            outcome: DialOutcome::TimedOut,
            connected: None,
        }
    }

    /// The run does not allow the network, so no attempt was made.
    #[must_use]
    pub fn no_network() -> Self {
        Self {
            facts: None,
            outcome: DialOutcome::NoNetwork,
            connected: None,
        }
    }
}

impl Dialed {
    /// The connected cluster, when the attempt reached it. The family probe (M1-107) uses it to hand the
    /// same connection to the other k8s checks, so one holder serves `k8s.access` and the `Cluster` the
    /// rest read.
    #[must_use]
    pub fn connected(&self) -> Option<&Connected> {
        self.connected.as_ref()
    }
}

impl Dial for Dialed {
    fn facts(&self) -> Option<&ConnectionFacts> {
        self.facts.as_ref()
    }

    fn outcome(&self) -> &DialOutcome {
        &self.outcome
    }

    fn read_only(&self, probe: &Probe) -> Option<ReadOnlyClient> {
        self.connected
            .as_ref()
            .map(|connected| connected.read_only(probe))
    }
}
