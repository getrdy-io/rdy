//! What a k8s check gets from the cluster the run is connected to.
//!
//! A check never sees the connection. It sees a [`Cluster`]: the answer of the run's `GET /version` and
//! a way to get its own [`ReadOnlyClient`] from its own probe. The production implementation is
//! [`Connected`]. The fixture tests implement it over the kube mock harness, so a check runs the same code
//! in both.

use std::sync::Arc;

use rdy_engine::probe::Probe;

use crate::client::{
    Connected, ImpersonateAs, ImpersonationError, KubeError, ReadOnlyClient, ServerVersion,
    from_kube_error,
};

/// The connected cluster, as a k8s check sees it.
///
/// M1-107 implements it for whatever holds the lazy connection of a run.
pub trait Cluster: Send + Sync + 'static {
    /// What the run's `GET /version` said. The run asked once, so the checks do not ask again.
    fn server_version(&self) -> &ServerVersion;

    /// The read-only client for one check. `probe` is the check's own probe (`CheckContext::probe`): every
    /// request the client sends is logged under that check's id and goes through the guard (INV-14).
    fn read_only(&self, probe: &Probe) -> ReadOnlyClient;

    /// Like [`Cluster::read_only`], and the access review POSTs carry `Impersonate-User: <user>` (the spec's
    /// `as:` of `k8s.rbac`). Every request of this client is logged as the check's own.
    ///
    /// # Errors
    ///
    /// [`ImpersonationError::Conflict`] when the kubeconfig user already impersonates. There is no
    /// default: an implementor must say how it impersonates, so a spec `as:` can never be answered with a
    /// refusal that blames the kubeconfig by mistake.
    fn read_only_as(
        &self,
        probe: &Probe,
        user: ImpersonateAs,
    ) -> Result<ReadOnlyClient, ImpersonationError>;

    /// True when the cluster facts say the cluster is OpenShift, so a fix can name `oc` commands. The
    /// default knows nothing and says no; M1-107's holder of the cluster facts answers it.
    fn is_openshift(&self) -> bool {
        false
    }

    /// Sorts an error of a request of this cluster, with what the connection knows: the server, the
    /// credential plugin, whether a proxy is in the path and the CA setting, so the fix hint can name them (02, "Errors").
    ///
    /// The default knows none of that. A test double may keep it.
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

    fn read_only_as(
        &self,
        probe: &Probe,
        user: ImpersonateAs,
    ) -> Result<ReadOnlyClient, ImpersonationError> {
        Connected::read_only_as(self, probe, user)
    }

    fn map_error(&self, error: &kube::Error) -> KubeError {
        Connected::map_error(self, error)
    }
}

impl<T: Cluster + ?Sized> Cluster for Arc<T> {
    fn server_version(&self) -> &ServerVersion {
        (**self).server_version()
    }

    fn read_only(&self, probe: &Probe) -> ReadOnlyClient {
        (**self).read_only(probe)
    }

    fn read_only_as(
        &self,
        probe: &Probe,
        user: ImpersonateAs,
    ) -> Result<ReadOnlyClient, ImpersonationError> {
        (**self).read_only_as(probe, user)
    }

    fn is_openshift(&self) -> bool {
        (**self).is_openshift()
    }

    fn map_error(&self, error: &kube::Error) -> KubeError {
        (**self).map_error(error)
    }
}
