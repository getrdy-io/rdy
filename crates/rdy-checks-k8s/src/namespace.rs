//! `k8s.namespace`: the install namespace exists (or can be created), is not being deleted, has quota and
//! limit range headroom for the product (03 section 4, M1-late: M1-161).
//!
//! What it reads, all read-only and all through the guard:
//!
//! - the target `Namespace` by name: its phase (`Terminating`) and its deletion conditions. The namespace is
//!   the spec's `namespace`, else the family's;
//! - the `ResourceQuota` list of the namespace, first page of 500: `hard` and `used` of each quota, and
//!   whether it is scoped (`scopes` or `scopeSelector`);
//! - the `LimitRange` list of the namespace, first page of 500: the memory `max`, `default` and `min` of
//!   the `Container` and `Pod` items;
//! - only when the namespace does not exist: `GET /apis` (does the cluster serve `project.openshift.io`?)
//!   and one `SelfSubjectAccessReview`, `create namespaces`, or on OpenShift `create projectrequests`
//!   in `project.openshift.io`.
//!
//! That is five requests at most. Nothing is created.
//!
//! How the rules of 03 apply:
//!
//! - A namespace that is `Terminating` blocks. Its quotas and limit ranges are not read.
//! - A namespace that is missing and that the identity may not create blocks. One it may create passes with
//!   a note, since a new namespace has no quota and no limit range of its own yet.
//! - A quota resource named in `quota_needs` blocks when an **unscoped** quota has less left (`hard` minus
//!   `used`) than the product needs. A quota with `scopes` or a `scopeSelector` applies only to the pods it
//!   selects, so it is listed as "not evaluated" and the result is partial. Every quota applies, so the
//!   tightest unscoped one decides. `cpu` and `requests.cpu` are the same quota resource, and so are
//!   `memory`, `ephemeral-storage` and `hugepages-*` with their `requests.` forms.
//! - `limit_needs.container_max_memory` blocks when a `Container` or `Pod` item of a limit range has a
//!   memory `max` below it. A `Container` default limit below it is a note: a container with a request and
//!   no limit gets the default as its limit, and a request above its limit is rejected. The spec does not
//!   say whether the product sets limits, so this is not the block that 03 names, and it would turn most
//!   clusters (a default limit of 512Mi is common) into a warning.
//!
//! Anything the identity may not read is not evaluated, never a block: a namespace it may not get (grant
//! `get namespaces`), quotas or limit ranges it may not list (grants `list resourcequotas` and
//! `list limitranges`). A grant missing for a list the spec has no need for is only a note.
//!
//! Not read: OpenShift `ClusterResourceQuota`, quotas of other namespaces, and priority-class quotas.

use std::sync::Arc;
use std::time::Duration;

use k8s_openapi::api::authorization::v1::{
    ResourceAttributes, SelfSubjectAccessReview, SelfSubjectAccessReviewSpec,
};
use k8s_openapi::api::core::v1::{LimitRange, Namespace, ResourceQuota};
use kube::api::{ListParams, ObjectMeta, PostParams};
use rdy_engine::check::{
    BoxFuture, Check, CheckContext, CheckError, CheckInfo, CheckMeta, CheckOutcome, Need,
    OsSupport, Support,
};
use rdy_spec::check::{K8sName, K8sNamespace};

use crate::client::guard::{RULE_PATH_SHAPE, RULE_SECRETS};
use crate::client::{KubeError, ReadOnlyClient};
use crate::cluster::Cluster;

mod amount;
mod fix;
mod judge;
mod objects;

#[cfg(test)]
mod tests;
#[cfg(test)]
mod unit_tests;

use judge::{Answer, Create, Gathered, NsFacts, Via};
use objects::{Limits, Page, Quota, limits_of, quota_of};

/// The most objects one list asks for. A longer list is read as its first page and the rest is "not read".
const PAGE: u32 = 500;

/// Below this much time left, the optional reads are skipped.
const MIN_LEFT: Duration = Duration::from_millis(500);

/// The API group that only OpenShift serves for projects.
const PROJECT_GROUP: &str = "project.openshift.io";

/// The static facts about `k8s.namespace` (03 section 4).
pub(crate) static INFO: CheckInfo = CheckInfo {
    id: "k8s.namespace",
    family: "k8s",
    summary: "Install namespace exists or can be created, is not terminating, has quota and limit range room",
    meta: CheckMeta {
        title: "Namespace",
        remediation: "Ask the platform team for a namespace the product can install into. Create it with `kubectl create namespace <namespace>` (on OpenShift `oc new-project <namespace>`) and give the install identity the admin role in it. If a quota is too small, raise it with `kubectl edit resourcequota <name> -n <namespace>`. If a limit range caps containers too low, raise its max with `kubectl edit limitrange <name> -n <namespace>`.",
    },
    needs: &[Need::KubeContext],
    wants: &[],
    default_timeout: Some(Duration::from_secs(15)),
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

/// `k8s.namespace`, built from its spec entry.
pub struct NamespaceCheck {
    params: K8sNamespace,
    namespace: Option<K8sName>,
    cluster: Arc<dyn Cluster>,
}

impl std::fmt::Debug for NamespaceCheck {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("NamespaceCheck")
            .field("params", &self.params)
            .field("namespace", &self.namespace)
            .finish_non_exhaustive()
    }
}

impl NamespaceCheck {
    /// The check for `params`, reading `cluster`.
    ///
    /// `namespace` is the target namespace of the k8s block of the spec. The entry's own `namespace` wins
    /// over it. With neither, nothing can be read and the result says so.
    #[must_use]
    pub fn new(
        params: K8sNamespace,
        namespace: Option<K8sName>,
        cluster: Arc<dyn Cluster>,
    ) -> Self {
        Self {
            params,
            namespace,
            cluster,
        }
    }

    /// The static facts, for a family that lists its checks.
    #[must_use]
    pub fn info() -> &'static CheckInfo {
        &INFO
    }
}

impl Check for NamespaceCheck {
    fn info(&self) -> &'static CheckInfo {
        &INFO
    }

    fn run<'a>(&'a self, ctx: &'a CheckContext) -> BoxFuture<'a, CheckOutcome> {
        Box::pin(async move {
            let gathered = self.gather(ctx).await?;
            Ok(judge::judge(&self.params, &gathered))
        })
    }
}

// ---- reading the cluster --------------------------------------------------------------------------------------

/// The answer to a read the server may refuse.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum Read<T> {
    Ok(T),
    /// 403: the identity may not read it.
    Forbidden,
    /// 404: it does not exist here.
    Missing,
    /// Any other status of the server.
    Unreadable(u16),
    /// The guard refused the path. The only path it refuses that rdy builds is a list in a namespace that
    /// is called `secrets`.
    Refused,
    /// The check ran out of time before it asked.
    OutOfTime,
}

impl<T> Read<T> {
    /// Why the read gave nothing, as a phrase.
    pub(crate) fn why(&self) -> String {
        match self {
            Self::Ok(_) => "it was read".to_owned(),
            Self::Forbidden => "the identity may not read it".to_owned(),
            Self::Missing => "the server does not have it".to_owned(),
            Self::Unreadable(code) => format!("the server answered {code}"),
            Self::Refused => "rdy never reads a path through a namespace called secrets".to_owned(),
            Self::OutOfTime => "rdy ran out of time".to_owned(),
        }
    }
}

/// How a failed request becomes a [`KubeError`]: `Cluster::map_error`, which knows the connection.
type Mapper<'a> = &'a (dyn Fn(&kube::Error) -> KubeError + Sync);

/// Sorts the result of one request. A refusal for this identity, a missing object and another status of the
/// server are answers. The guard's refusal of a path through a namespace called `secrets` is one too.
/// Anything else (the network, the credentials) fails the check.
fn read<T, U>(
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
            KubeError::Refused { rule, .. } if rule == RULE_SECRETS || rule == RULE_PATH_SHAPE => {
                Ok(Read::Refused)
            }
            other => Err(CheckError::Failed {
                message: other.to_string(),
                hint: other.hint(),
            }),
        },
    }
}

/// True when too little of the check's time is left to ask the cluster another question.
fn out_of_time(ctx: &CheckContext) -> bool {
    ctx.remaining() < MIN_LEFT
}

impl NamespaceCheck {
    async fn gather(&self, ctx: &CheckContext) -> Result<Gathered, CheckError> {
        let client = self.cluster.read_only(ctx.probe());
        let mapper = |error: &kube::Error| self.cluster.map_error(error);
        let Some(name) = self
            .params
            .namespace
            .as_ref()
            .or(self.namespace.as_ref())
            .map(|name| name.as_str().to_owned())
        else {
            return Ok(Gathered::unnamed());
        };

        let ns = read_namespace(&mapper, &client, &name).await?;
        // A namespace that does not exist, or is going away, has nothing worth listing. One the identity
        // may not read could still have quotas it may list, so those are asked.
        let list = match &ns {
            Read::Ok(facts) => !facts.terminating,
            Read::Missing => false,
            _ => true,
        };
        let quotas = if list {
            Some(if out_of_time(ctx) {
                Read::OutOfTime
            } else {
                read_quotas(&mapper, &client, &name).await?
            })
        } else {
            None
        };
        let limits = if list {
            Some(if out_of_time(ctx) {
                Read::OutOfTime
            } else {
                read_limits(&mapper, &client, &name).await?
            })
        } else {
            None
        };
        let create = if matches!(ns, Read::Missing) {
            Some(read_create(&mapper, &client, ctx).await?)
        } else {
            None
        };
        Ok(Gathered {
            namespace: Some(name),
            ns: Some(ns),
            quotas,
            limits,
            create,
        })
    }
}

/// `GET` of the namespace: is it going away?
async fn read_namespace(
    mapper: Mapper<'_>,
    client: &ReadOnlyClient,
    name: &str,
) -> Result<Read<NsFacts>, CheckError> {
    read(
        mapper,
        client.all::<Namespace>().get(name).await,
        |namespace| {
            let phase_terminating = namespace
                .status
                .as_ref()
                .and_then(|status| status.phase.as_deref())
                == Some("Terminating");
            let conditions = namespace
                .status
                .and_then(|status| status.conditions)
                .unwrap_or_default()
                .into_iter()
                .filter(|condition| condition.status == "True")
                .map(|condition| condition.type_)
                .collect();
            NsFacts {
                terminating: phase_terminating || namespace.metadata.deletion_timestamp.is_some(),
                conditions,
            }
        },
    )
}

/// The quota list of the namespace, first page.
async fn read_quotas(
    mapper: Mapper<'_>,
    client: &ReadOnlyClient,
    name: &str,
) -> Result<Read<Page<Quota>>, CheckError> {
    read(
        mapper,
        client
            .namespaced::<ResourceQuota>(name)
            .list(&ListParams::default().limit(PAGE))
            .await,
        |list| {
            let cut = has_more(&list.metadata);
            let mut quotas: Vec<Quota> = list.items.into_iter().map(quota_of).collect();
            quotas.sort_by(|a, b| a.name.cmp(&b.name));
            Page { items: quotas, cut }
        },
    )
}

/// The limit range list of the namespace, first page.
async fn read_limits(
    mapper: Mapper<'_>,
    client: &ReadOnlyClient,
    name: &str,
) -> Result<Read<Page<Limits>>, CheckError> {
    read(
        mapper,
        client
            .namespaced::<LimitRange>(name)
            .list(&ListParams::default().limit(PAGE))
            .await,
        |list| {
            let cut = has_more(&list.metadata);
            let mut ranges: Vec<Limits> = list.items.into_iter().map(limits_of).collect();
            ranges.sort_by(|a, b| a.name.cmp(&b.name));
            Page { items: ranges, cut }
        },
    )
}

/// True when a list says there is a next page.
fn has_more(meta: &k8s_openapi::apimachinery::pkg::apis::meta::v1::ListMeta) -> bool {
    meta.continue_
        .as_deref()
        .is_some_and(|token| !token.is_empty())
}

/// Can the identity create the namespace? On OpenShift the question is `create projectrequests`.
async fn read_create(
    mapper: Mapper<'_>,
    client: &ReadOnlyClient,
    ctx: &CheckContext,
) -> Result<Create, CheckError> {
    let projects: Read<bool> = if out_of_time(ctx) {
        Read::OutOfTime
    } else {
        read(mapper, client.api_groups().await, |list| {
            list.groups.iter().any(|group| group.name == PROJECT_GROUP)
        })?
    };
    let via = match projects {
        Read::Ok(true) => Via::ProjectRequests,
        Read::Ok(false) => Via::Namespaces { sure: true },
        _ => Via::Namespaces { sure: false },
    };
    if out_of_time(ctx) {
        return Ok(Create {
            via,
            answer: Answer::Unknown(Read::<()>::OutOfTime.why()),
        });
    }
    let (group, resource) = match via {
        Via::ProjectRequests => (Some(PROJECT_GROUP.to_owned()), "projectrequests"),
        Via::Namespaces { .. } => (None, "namespaces"),
    };
    let review = SelfSubjectAccessReview {
        metadata: ObjectMeta::default(),
        spec: SelfSubjectAccessReviewSpec {
            resource_attributes: Some(ResourceAttributes {
                verb: Some("create".to_owned()),
                group,
                resource: Some(resource.to_owned()),
                ..ResourceAttributes::default()
            }),
            non_resource_attributes: None,
        },
        status: None,
    };
    let answer = match client
        .all::<SelfSubjectAccessReview>()
        .create(&PostParams::default(), &review)
        .await
    {
        Ok(done) => match done.status {
            Some(status) => judge::answer_of(&status),
            None => Answer::Unknown("the server sent no status".to_owned()),
        },
        Err(error) => match mapper(&error) {
            KubeError::Forbidden { .. } => Answer::Unknown(Read::<()>::Forbidden.why()),
            KubeError::Api { code, .. } => Answer::Unknown(Read::<()>::Unreadable(code).why()),
            other => {
                return Err(CheckError::Failed {
                    message: other.to_string(),
                    hint: other.hint(),
                });
            }
        },
    };
    Ok(Create { via, answer })
}
