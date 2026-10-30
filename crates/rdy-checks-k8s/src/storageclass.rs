//! `k8s.storageclass`: a usable default storage class, a driver behind it, and the access modes the
//! product needs (03 section 4).
//!
//! What it reads, all read-only and all through the guard:
//!
//! - the `StorageClass` list (the first page of 500), or the one class by name when the spec names a class
//!   and the identity may not list;
//! - for a class on a CSI driver (the provisioner after the in-tree map, so `kubernetes.io/aws-ebs` is
//!   looked up as `ebs.csi.aws.com`): the `CSINode` list, the strongest evidence that a node registered the
//!   driver, and only when no node did, the `CSIDriver` list;
//! - when the family names a target namespace: the `Namespace` by name (a list in a namespace that does
//!   not exist is empty, so the check asks first), the `PersistentVolumeClaim` list there, and, only when
//!   a claim has been `Pending` for 5 minutes, the claim `Event` list (reason `ProvisioningFailed`).
//!
//! Nothing is created. No canary claim is made.
//!
//! How the rules of 03 apply, and where this build differs from the catalog text:
//!
//! - The provisioner table is `data/provisioners.toml` ([`crate::provisioners`]). A provisioner that is not CSI, is not
//!   in the table, or is `kubernetes.io/no-provisioner` is "not CSI or unknown, driver not verified" and
//!   never blocks on driver grounds.
//! - Evidence is a `CSINode` that lists the driver on at least one node. 03 says "schedulable node", but
//!   `CSINode` does not say, and the guard does not let this check read `Node` objects, so a cordoned node
//!   counts.
//! - Unreadable data is never a block and never a pass. `CSINode` forbidden leaves the `CSIDriver` object
//!   as the only evidence: found is a pass that the engine shows as "not verified", not found is a warn.
//!   The grants that would complete the answer are in `partial.missing_grants`.
//! - The zone count is not read (it belongs to the family facts of M1-107), so `Immediate` binding on a
//!   zonal or node-local driver is a warn that says "if the nodes span more than one zone".
//! - The pending claims are evidence of broken provisioning: a claim on the judged class that has been
//!   `Pending` for 5 minutes with a `ProvisioningFailed` event is a warn. `WaitForFirstConsumer` waits are
//!   normal and are not one.

use std::sync::Arc;
use std::time::Duration;

use k8s_openapi::api::core::v1::{Event, Namespace, PersistentVolumeClaim};
use k8s_openapi::api::storage::v1::{CSIDriver, CSINode, StorageClass};
use k8s_openapi::jiff::Timestamp;
use kube::api::ListParams;
use rdy_engine::check::{
    BoxFuture, Check, CheckContext, CheckError, CheckInfo, CheckMeta, CheckOutcome, Need,
    OsSupport, Support,
};
use rdy_spec::check::{K8sName, K8sStorageClass};

use crate::client::{KubeError, ReadOnlyClient, ServerVersion};
use crate::cluster::Cluster;

mod facts;
mod fix;
mod judge;

#[cfg(test)]
mod tests;
#[cfg(test)]
mod unit_tests;

use crate::provisioners::Catalog;
use facts::{Class, Page, Read, Registered, pending_claims, with_failures};
use judge::{
    Classes, Evidence, Nodes, Object, Unread, Verdict, judge_driver, judge_modes, judge_settings,
    judge_waiting, needs_evidence, select,
};

/// The most objects one list asks for. A longer list is read as its first page and the rest is "not read".
const PAGE: u32 = 500;

/// Below this much time left, the optional reads are skipped.
const MIN_LEFT: Duration = Duration::from_millis(500);

/// The static facts about `k8s.storageclass` (03 section 4).
pub(crate) static INFO: CheckInfo = CheckInfo {
    id: "k8s.storageclass",
    family: "k8s",
    summary: "Default class, CSI driver registered, binding mode, access modes",
    meta: CheckMeta {
        title: "Storage class",
        remediation: "Mark one StorageClass as the default: `kubectl patch storageclass <name> -p '{\"metadata\":{\"annotations\":{\"storageclass.kubernetes.io/is-default-class\":\"true\"}}}'`. Install the CSI driver behind it (EKS: `eksctl create addon --name aws-ebs-csi-driver`; GKE and AKS ship one, enable it). For ReadWriteMany pick a shared file system class such as NFS, EFS or Azure Files.",
    },
    needs: &[Need::KubeContext],
    wants: &[],
    default_timeout: Some(Duration::from_secs(30)),
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
};

/// `k8s.storageclass`, built from its spec entry.
pub struct StorageClassCheck {
    params: K8sStorageClass,
    namespace: Option<K8sName>,
    cluster: Arc<dyn Cluster>,
    now: Option<Timestamp>,
}

impl std::fmt::Debug for StorageClassCheck {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("StorageClassCheck")
            .field("params", &self.params)
            .field("namespace", &self.namespace)
            .finish_non_exhaustive()
    }
}

impl StorageClassCheck {
    /// The check for `params`, reading `cluster`.
    ///
    /// `namespace` is the target namespace of the k8s block of the spec. With it the check also looks for
    /// claims that wait on the class there. Without it, it does not.
    #[must_use]
    pub fn new(
        params: K8sStorageClass,
        namespace: Option<K8sName>,
        cluster: Arc<dyn Cluster>,
    ) -> Self {
        Self {
            params,
            namespace,
            cluster,
            now: None,
        }
    }

    /// Fixes the time the age of a claim is measured at. Tests use it; a run uses the clock.
    #[cfg(test)]
    fn at(mut self, now: Timestamp) -> Self {
        self.now = Some(now);
        self
    }

    /// The static facts, for a family that lists its checks.
    #[must_use]
    pub fn info() -> &'static CheckInfo {
        &INFO
    }
}

impl Check for StorageClassCheck {
    fn info(&self) -> &'static CheckInfo {
        &INFO
    }

    fn run<'a>(&'a self, ctx: &'a CheckContext) -> BoxFuture<'a, CheckOutcome> {
        Box::pin(self.execute(ctx))
    }
}

// ---- reading the cluster --------------------------------------------------------------------------------------

/// How a failed request becomes a [`KubeError`]: `Cluster::map_error`, which knows the connection.
type Mapper<'a> = &'a (dyn Fn(&kube::Error) -> KubeError + Sync);

/// Sorts the result of one request. A refusal for this identity, a missing object and another status of the
/// server are answers. Anything else (the network, the credentials, the guard) fails the check.
fn sort<T, U>(
    mapper: Mapper<'_>,
    result: Result<T, kube::Error>,
    map: impl FnOnce(T) -> U,
) -> Result<Read<U>, CheckError> {
    match result {
        Ok(value) => Ok(Read::Ok(map(value))),
        Err(error) => match mapper(&error) {
            KubeError::Forbidden { .. } => Ok(Read::Forbidden),
            KubeError::Api { code: 404, .. } => Ok(Read::Missing),
            KubeError::Api { code, .. } => Ok(Read::Unreadable(code)),
            other => Err(CheckError::Failed {
                message: other.to_string(),
                hint: other.hint(),
            }),
        },
    }
}

/// The page of a list: its objects and whether the server had more.
fn page_of<K: Clone, U>(list: kube::core::ObjectList<K>, map: impl Fn(K) -> Option<U>) -> Page<U> {
    let more = list
        .metadata
        .continue_
        .as_deref()
        .is_some_and(|token| !token.is_empty());
    Page {
        items: list.items.into_iter().filter_map(map).collect(),
        more,
    }
}

fn first_page() -> ListParams {
    ListParams::default().limit(PAGE)
}

/// The Kubernetes version as (major, minor), from `gitVersion` or, failing that, `major` and `minor`
/// (some distributions write `29+`).
fn server_minor(version: &ServerVersion) -> Option<(u64, u64)> {
    fn leading(text: &str) -> Option<u64> {
        let digits: String = text.chars().take_while(char::is_ascii_digit).collect();
        digits.parse().ok()
    }
    let from_git = {
        let mut parts = version.git_version.trim_start_matches('v').split('.');
        let major = parts.next().and_then(leading);
        let minor = parts.next().and_then(leading);
        major.zip(minor)
    };
    from_git.or_else(|| leading(&version.major).zip(leading(&version.minor)))
}

/// True when too little of the check's time is left to ask the cluster another question.
fn out_of_time(ctx: &CheckContext) -> bool {
    ctx.remaining() < MIN_LEFT
}

impl StorageClassCheck {
    async fn execute(&self, ctx: &CheckContext) -> CheckOutcome {
        let catalog = Catalog::shipped().map_err(|error| CheckError::Failed {
            message: error.to_string(),
            hint: "Use a build of rdy that ships a valid provisioner table.".to_owned(),
        })?;
        let client = self.cluster.read_only(ctx.probe());
        let mapper = |error: &kube::Error| self.cluster.map_error(error);
        let server = server_minor(self.cluster.server_version());

        let mut verdict = Verdict::new();
        let classes = self.read_classes(&client, &mapper).await?;
        if let Some(chosen) = select(&mut verdict, &self.params, &classes, server) {
            let (normalised, kind) = catalog.classify(&chosen.class.provisioner);
            let evidence = if needs_evidence(&kind) {
                Some(
                    self.read_evidence(&client, &mapper, ctx, normalised.name)
                        .await?,
                )
            } else {
                None
            };
            judge_driver(&mut verdict, &chosen, &normalised, &kind, evidence.as_ref());
            judge_modes(&mut verdict, &self.params, &kind, normalised.name);
            judge_settings(&mut verdict, &self.params, &chosen.class, &kind);
            if let Some(namespace) = &self.namespace {
                self.read_waiting(
                    &client,
                    &mapper,
                    ctx,
                    &mut verdict,
                    namespace,
                    &chosen.class,
                )
                .await?;
            }
        }
        Ok(verdict.finish(&self.params))
    }

    /// The classes: the first page of the list, or the one class by name when the list is refused.
    async fn read_classes(
        &self,
        client: &ReadOnlyClient,
        mapper: Mapper<'_>,
    ) -> Result<Classes, CheckError> {
        let api = client.all::<StorageClass>();
        let listed = sort(mapper, api.list(&first_page()).await, |list| {
            page_of(list, |object| Class::from_object(&object))
        })?;
        Ok(match (listed, &self.params.class) {
            (Read::Ok(page), _) => Classes::Listed(page),
            (Read::Forbidden, Some(name)) => {
                let got = sort(mapper, api.get(name.as_str()).await, |object| {
                    Class::from_object(&object)
                })?;
                Classes::ByName(match got {
                    Read::Ok(Some(class)) => Read::Ok(class),
                    // A class with no name cannot be the one asked for by name.
                    Read::Ok(None) => Read::Unreadable(200),
                    Read::Forbidden => Read::Forbidden,
                    Read::Missing => Read::Missing,
                    Read::Unreadable(code) => Read::Unreadable(code),
                })
            }
            (Read::Forbidden, None) => Classes::NoList(Read::Forbidden),
            (Read::Missing, _) => Classes::NoList(Read::Missing),
            (Read::Unreadable(code), _) => Classes::NoList(Read::Unreadable(code)),
        })
    }

    /// The `CSINode` list, and the `CSIDriver` list when no node lists the driver.
    async fn read_evidence(
        &self,
        client: &ReadOnlyClient,
        mapper: Mapper<'_>,
        ctx: &CheckContext,
        driver: &str,
    ) -> Result<Evidence, CheckError> {
        if out_of_time(ctx) {
            return Ok(Evidence {
                nodes: Nodes::Unknown(Unread::Time),
                object: Some(Object::Unknown(Unread::Time)),
            });
        }
        let nodes = sort(
            mapper,
            client.all::<CSINode>().list(&first_page()).await,
            |list| page_of(list, Some),
        )?;
        let nodes = match nodes {
            Read::Ok(page) => {
                let registered = Registered::count(&page, driver);
                if registered.with_driver > 0 {
                    Nodes::Found(registered)
                } else if page.more {
                    Nodes::Unknown(Unread::Capped)
                } else {
                    Nodes::NotFound(registered)
                }
            }
            Read::Forbidden => Nodes::Unknown(Unread::Forbidden),
            Read::Missing => Nodes::Unknown(Unread::Status(404)),
            Read::Unreadable(code) => Nodes::Unknown(Unread::Status(code)),
        };
        if matches!(nodes, Nodes::Found(_)) {
            return Ok(Evidence {
                nodes,
                object: None,
            });
        }
        if out_of_time(ctx) {
            return Ok(Evidence {
                nodes,
                object: Some(Object::Unknown(Unread::Time)),
            });
        }
        let objects = sort(
            mapper,
            client.all::<CSIDriver>().list(&first_page()).await,
            |list| {
                let found = list
                    .items
                    .iter()
                    .any(|object| object.metadata.name.as_deref() == Some(driver));
                let more = list
                    .metadata
                    .continue_
                    .as_deref()
                    .is_some_and(|token| !token.is_empty());
                (found, more)
            },
        )?;
        let object = match objects {
            Read::Ok((true, _)) => Object::Found,
            Read::Ok((false, true)) => Object::Unknown(Unread::Capped),
            Read::Ok((false, false)) => Object::NotFound,
            Read::Forbidden => Object::Unknown(Unread::Forbidden),
            Read::Missing => Object::Unknown(Unread::Status(404)),
            Read::Unreadable(code) => Object::Unknown(Unread::Status(code)),
        };
        Ok(Evidence {
            nodes,
            object: Some(object),
        })
    }

    /// The claims in the target namespace that wait on the class, and their `ProvisioningFailed` events.
    async fn read_waiting(
        &self,
        client: &ReadOnlyClient,
        mapper: Mapper<'_>,
        ctx: &CheckContext,
        verdict: &mut Verdict,
        namespace: &K8sName,
        class: &Class,
    ) -> Result<(), CheckError> {
        let ns = namespace.as_str();
        if out_of_time(ctx) {
            verdict.claims_unread(ns, &Unread::Time);
            return Ok(());
        }
        // A list in a namespace that does not exist is empty, not an error, so ask first. The answer
        // only settles "does it exist": a refusal or another status does not stop the claim list.
        let exists = sort(mapper, client.all::<Namespace>().get(ns).await, |_| ())?;
        if exists == Read::Missing {
            verdict.namespace_missing(ns);
            return Ok(());
        }
        let claims = sort(
            mapper,
            client
                .namespaced::<PersistentVolumeClaim>(ns)
                .list(&first_page())
                .await,
            |list| page_of(list, Some),
        )?;
        let page = match claims {
            Read::Ok(page) => page,
            Read::Forbidden => {
                verdict.claims_unread(ns, &Unread::Forbidden);
                return Ok(());
            }
            Read::Missing => {
                verdict.claims_unread(ns, &Unread::Status(404));
                return Ok(());
            }
            Read::Unreadable(code) => {
                verdict.claims_unread(ns, &Unread::Status(code));
                return Ok(());
            }
        };
        if page.more {
            verdict.unread("the claims after the first page", None);
        }
        let now = self.now.unwrap_or_else(Timestamp::now);
        let waiting = pending_claims(&page.items, &class.name, class.default, now);
        if waiting.is_empty() {
            judge_waiting(verdict, ns, &[]);
            return Ok(());
        }
        let events = if out_of_time(ctx) {
            Read::Unreadable(0)
        } else {
            sort(
                mapper,
                client
                    .namespaced::<Event>(ns)
                    .list(&first_page().fields("involvedObject.kind=PersistentVolumeClaim"))
                    .await,
                |list| page_of(list, Some),
            )?
        };
        let events = match events {
            Read::Ok(page) => {
                if page.more {
                    verdict.unread("the claim events after the first page", None);
                }
                page.items
            }
            Read::Forbidden => {
                verdict.events_forbidden(ns);
                Vec::new()
            }
            Read::Missing | Read::Unreadable(_) => {
                verdict.unread("the claim events", None);
                Vec::new()
            }
        };
        judge_waiting(verdict, ns, &with_failures(waiting, &events));
        Ok(())
    }
}
