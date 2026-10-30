//! What a k8s check gets from the cluster the run is connected to.
//!
//! A check never sees the connection. It sees a [`Cluster`]: the answer of the run's `GET /version` and
//! a way to get its own [`ReadOnlyClient`] from its own probe. The production implementation is
//! [`Connected`]. The fixture tests implement it over the kube mock harness, so a check runs the same code
//! in both.

use std::sync::Arc;

use rdy_engine::probe::Probe;

use crate::client::{Connected, ReadOnlyClient, ServerVersion};

/// The connected cluster, as a k8s check sees it.
///
/// M1-107 implements it for whatever holds the lazy connection of a run.
pub trait Cluster: Send + Sync + 'static {
    /// What the run's `GET /version` said. The run asked once, so the checks do not ask again.
    fn server_version(&self) -> &ServerVersion;

    /// The read-only client for one check. `probe` is the check's own probe (`CheckContext::probe`): every
    /// request the client sends is logged under that check's id and goes through the guard (INV-14).
    fn read_only(&self, probe: &Probe) -> ReadOnlyClient;
}

impl Cluster for Connected {
    fn server_version(&self) -> &ServerVersion {
        Connected::server_version(self)
    }

    fn read_only(&self, probe: &Probe) -> ReadOnlyClient {
        Connected::read_only(self, probe)
    }
}

impl<T: Cluster + ?Sized> Cluster for Arc<T> {
    fn server_version(&self) -> &ServerVersion {
        (**self).server_version()
    }

    fn read_only(&self, probe: &Probe) -> ReadOnlyClient {
        (**self).read_only(probe)
    }
}
