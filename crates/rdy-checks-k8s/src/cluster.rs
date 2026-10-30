//! The seam between a k8s check and the connection.
//!
//! This is the shape PR #127 (M1-106) also gives the checks, so the two merge into one trait: a check holds
//! an `Arc<dyn Cluster>`, and the fixture tests implement the trait over the mock harness. M1-107 owns the
//! production wiring. If #127 lands first, its `cluster.rs` replaces this file and nothing else changes.

use rdy_engine::probe::Probe;

use crate::client::{Connected, KubeError, ReadOnlyClient, ServerVersion, from_kube_error};

/// What a check may ask of the cluster it runs against.
pub trait Cluster: Send + Sync + 'static {
    /// The `GET /version` answer the run got when it connected.
    fn server_version(&self) -> &ServerVersion;

    /// A guarded read-only client that logs under the check that owns `probe`.
    fn read_only(&self, probe: &Probe) -> ReadOnlyClient;

    /// Sorts a request error. The default has no connection details for the hint.
    fn map_error(&self, error: &kube::Error) -> KubeError {
        from_kube_error(error, "the API server", None, false, false)
    }
}

impl Cluster for Connected {
    fn server_version(&self) -> &ServerVersion {
        Connected::server_version(self)
    }

    fn read_only(&self, probe: &Probe) -> ReadOnlyClient {
        Connected::read_only(self, probe)
    }
}
